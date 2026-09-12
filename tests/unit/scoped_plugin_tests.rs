//! Proxy-scoped PluginConfig assembly must match Edge's stored associations.

use gitforgeops::config::assembler::normalize_proxy_plugin_associations;
use gitforgeops::config::schema::{GatewayConfig, Proxy, Resource};
use gitforgeops::config::{apply_overlay, assemble};
use gitforgeops::diff::resource_diff::{compute_diff, compute_diff_with_ownership, DiffAction};
use gitforgeops::diff::security::{audit_security, security_blockers};
use gitforgeops::policy::{evaluate_policies, PolicyConfig};
use serde_json::json;

fn resource(namespace: &str, kind: &str, spec: serde_json::Value) -> (String, Resource) {
    (
        namespace.to_string(),
        serde_json::from_value(json!({"kind": kind, "spec": spec})).unwrap(),
    )
}

fn proxy(associations: &[&str]) -> (String, Resource) {
    let plugins: Vec<_> = associations
        .iter()
        .map(|id| json!({"plugin_config_id": id}))
        .collect();
    resource(
        "team-alpha",
        "Proxy",
        json!({
            "id": "api",
            "listen_path": "/api",
            "backend_host": "api.internal",
            "backend_port": 443,
            "plugins": plugins,
        }),
    )
}

fn plugin(id: &str, scope: &str, proxy_id: Option<&str>) -> (String, Resource) {
    resource(
        "team-alpha",
        "PluginConfig",
        json!({
            "id": id,
            "plugin_name": "key_auth",
            "scope": scope,
            "proxy_id": proxy_id,
            "config": {},
        }),
    )
}

fn association_ids(proxy: &Proxy) -> Vec<&str> {
    proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect()
}

#[test]
fn scoped_config_without_explicit_association_converges_to_live_backup() {
    let desired = assemble(vec![proxy(&[]), plugin("auth", "proxy", Some("api"))])
        .unwrap()
        .gateway;
    // Deserialize the live wire shape directly: never assemble the live side,
    // which would hide a missing stored association from the comparison.
    let actual: GatewayConfig = serde_json::from_value(json!({
        "proxies": [{
            "id": "api",
            "namespace": "team-alpha",
            "listen_path": "/api",
            "backend_host": "api.internal",
            "backend_port": 443,
            "backend_scheme": "https",
            "plugins": [{"plugin_config_id": "auth"}],
            "created_at": "2026-09-11T12:00:00Z",
            "updated_at": "2026-09-11T12:00:00Z",
        }],
        "plugin_configs": [{
            "id": "auth",
            "namespace": "team-alpha",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "api",
            "enabled": true,
            "config": {},
        }],
    }))
    .unwrap();

    assert_eq!(association_ids(&desired.proxies[0]), vec!["auth"]);
    assert!(compute_diff(&desired, &actual).is_empty());
    let shared = compute_diff_with_ownership(&desired, &actual, Some(&Default::default()));
    assert!(shared.diffs.is_empty());
    assert!(shared.unmanaged.is_empty());
    // The same assembled proxy is serialized for export and API writes.
    let payload = serde_json::to_value(&desired.proxies[0]).unwrap();
    assert_eq!(payload["plugins"], json!([{"plugin_config_id": "auth"}]));
    let exported: GatewayConfig =
        serde_yaml::from_str(&serde_yaml::to_string(&desired).unwrap()).unwrap();
    assert!(compute_diff(&exported, &actual).is_empty());

    let mut missing_live_association = actual;
    missing_live_association.proxies[0].plugins.clear();
    let drift = compute_diff(&desired, &missing_live_association);
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].action, DiffAction::Modify);
    assert_eq!(drift[0].details[0].field, "plugins");
}

#[test]
fn explicit_and_derived_associations_are_deduplicated_without_losing_entries() {
    let config = assemble(vec![
        proxy(&["z-auth", "group", "z-auth", "group"]),
        plugin("z-auth", "proxy", Some("api")),
        plugin("b-auth", "proxy", Some("api")),
        plugin("a-auth", "proxy", Some("api")),
        plugin("group", "proxy_group", None),
    ])
    .unwrap()
    .gateway;

    assert_eq!(
        association_ids(&config.proxies[0]),
        vec!["z-auth", "group", "a-auth", "b-auth"]
    );
    assert!(security_blockers(&audit_security(&config)).is_empty());
}

#[test]
fn association_comparison_is_a_set_without_changing_export_order() {
    let desired = assemble(vec![
        proxy(&["b"]),
        plugin("a", "proxy", Some("api")),
        plugin("b", "proxy", Some("api")),
    ])
    .unwrap()
    .gateway;
    let mut live = desired.clone();
    live.proxies[0].plugins.reverse();
    assert!(compute_diff(&desired, &live).is_empty());
    let shared = compute_diff_with_ownership(&desired, &live, Some(&Default::default()));
    assert!(shared.diffs.is_empty());
    assert!(shared.unmanaged.is_empty());

    let exported = gitforgeops::apply::render_file_yaml(&desired).unwrap();
    let exported: GatewayConfig = serde_yaml::from_str(&exported).unwrap();
    assert_eq!(association_ids(&exported.proxies[0]), vec!["b", "a"]);
    assert_eq!(association_ids(&desired.proxies[0]), vec!["b", "a"]);
    assert!(compute_diff(&exported, &live).is_empty());

    live.proxies[0].plugins.pop();
    let missing = compute_diff(&desired, &live);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].details[0].field, "plugins");
    let extra = compute_diff(&live, &desired);
    assert_eq!(extra.len(), 1);
    assert_eq!(extra[0].details[0].field, "plugins");
}

#[test]
fn opaque_plugin_arrays_remain_order_sensitive() {
    let mut desired = assemble(vec![proxy(&[]), plugin("auth", "proxy", Some("api"))])
        .unwrap()
        .gateway;
    desired.plugin_configs[0].config = json!({
        "plugins": [{"plugin_config_id": "a"}, {"plugin_config_id": "b"}],
    });
    let mut live = desired.clone();
    live.plugin_configs[0].config["plugins"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let drift = compute_diff(&desired, &live);
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].kind, "PluginConfig");
    assert_eq!(drift[0].details[0].field, "config");
}

#[test]
fn derived_order_is_independent_of_resource_order_and_normalization_is_idempotent() {
    let resources = vec![
        proxy(&[]),
        plugin("z-auth", "proxy", Some("api")),
        plugin("a-auth", "proxy", Some("api")),
        plugin("m-auth", "proxy", Some("api")),
    ];
    let mut reversed = resources.clone();
    reversed.reverse();
    let first = assemble(resources).unwrap().gateway;
    let mut second = assemble(reversed).unwrap().gateway;

    assert_eq!(
        association_ids(&first.proxies[0]),
        vec!["a-auth", "m-auth", "z-auth"]
    );
    assert!(compute_diff(&first, &second).is_empty());
    let before = serde_json::to_value(&second).unwrap();
    normalize_proxy_plugin_associations(&mut second);
    assert_eq!(serde_json::to_value(&second).unwrap(), before);
}

#[test]
fn derivation_uses_effective_namespaces_and_does_not_cross_same_id_proxies() {
    let config = assemble(vec![
        proxy(&[]),
        resource("team-beta", "Proxy", json!({"id": "api"})),
        resource(
            "source-directory",
            "Proxy",
            json!({"id": "api", "namespace": "team-gamma"}),
        ),
        plugin("alpha-auth", "proxy", Some("api")),
        resource(
            "another-directory",
            "PluginConfig",
            json!({
                "id": "gamma-auth",
                "namespace": "team-gamma",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "api",
            }),
        ),
        plugin("other-proxy", "proxy", Some("absent")),
        plugin("no-target", "proxy", None),
    ])
    .unwrap()
    .gateway;

    assert_eq!(association_ids(&config.proxies[0]), vec!["alpha-auth"]);
    assert!(config.proxies[1].plugins.is_empty());
    assert_eq!(association_ids(&config.proxies[2]), vec!["gamma-auth"]);
    let findings = audit_security(&config);
    let unauthenticated: Vec<_> = findings
        .iter()
        .filter(|finding| finding.message.contains("No auth plugin"))
        .map(|finding| finding.namespace.as_str())
        .collect();
    assert_eq!(unauthenticated, vec!["team-beta"]);
}

#[test]
fn derived_keyauth_satisfies_security_and_require_auth_policy() {
    let config = assemble(vec![proxy(&[]), plugin("auth", "proxy", Some("api"))])
        .unwrap()
        .gateway;
    assert!(audit_security(&config).is_empty());

    let mut policy = PolicyConfig::default();
    policy.policies.require_auth_plugin.enabled = true;
    assert!(evaluate_policies(&config, &policy).is_empty());

    let mut disabled = config;
    disabled.plugin_configs[0].enabled = false;
    assert!(audit_security(&disabled)
        .iter()
        .any(|finding| finding.message.contains("No auth plugin")));
    assert_eq!(evaluate_policies(&disabled, &policy).len(), 1);
}

#[test]
fn disabled_scoped_configs_are_still_attached_but_never_count_as_auth() {
    let mut auth = plugin("auth", "proxy", Some("api"));
    if let Resource::PluginConfig { spec } = &mut auth.1 {
        spec.enabled = false;
    }
    let config = assemble(vec![proxy(&[]), auth]).unwrap().gateway;

    assert_eq!(association_ids(&config.proxies[0]), vec!["auth"]);
    assert!(audit_security(&config)
        .iter()
        .any(|finding| finding.message.contains("No auth plugin")));
}

#[test]
fn global_and_proxy_group_configs_are_not_auto_attached() {
    for scope in ["global", "proxy_group"] {
        let config = assemble(vec![proxy(&[]), plugin("auth", scope, None)])
            .unwrap()
            .gateway;
        assert!(config.proxies[0].plugins.is_empty());
        let findings = audit_security(&config);
        assert!(security_blockers(&findings).is_empty());
        assert_eq!(
            findings
                .iter()
                .any(|finding| finding.message.contains("No auth plugin")),
            scope == "proxy_group"
        );
    }
}

#[test]
fn mismatched_explicit_associations_remain_visible_and_block_apply() {
    for (scope, proxy_id) in [
        ("proxy", Some("other")),
        ("proxy", None),
        ("global", None),
        ("global", Some("api")),
        ("proxy_group", Some("api")),
    ] {
        for enabled in [true, false] {
            let mut auth = plugin("auth", scope, proxy_id);
            if let Resource::PluginConfig { spec } = &mut auth.1 {
                spec.enabled = enabled;
            }
            let config = assemble(vec![
                proxy(&["auth"]),
                resource("team-alpha", "Proxy", json!({"id": "other"})),
                auth,
            ])
            .unwrap()
            .gateway;
            assert_eq!(association_ids(&config.proxies[0]), vec!["auth"]);
            let findings = audit_security(&config);
            let blockers = security_blockers(&findings);
            assert_eq!(blockers.len(), 1, "{scope} {proxy_id:?}: {findings:?}");
            assert_eq!(blockers[0].severity, "error");
            assert_eq!(blockers[0].id, "api");
            assert_eq!(blockers[0].namespace, "team-alpha");
            assert!(blockers[0]
                .message
                .contains("invalid plugin association auth"));
            if scope == "proxy" {
                assert!(findings.iter().any(|finding| {
                    finding.id == "api" && finding.message.contains("No auth plugin")
                }));
            }
        }
    }
}

#[test]
fn explicit_reference_cannot_resolve_a_plugin_in_another_namespace() {
    let mut auth = plugin("auth", "proxy", Some("api"));
    auth.0 = "team-beta".to_string();
    let config = assemble(vec![proxy(&["auth"]), auth]).unwrap().gateway;
    let findings = audit_security(&config);
    let blockers = security_blockers(&findings);
    assert_eq!(blockers.len(), 1);
    assert!(blockers[0]
        .message
        .contains("no PluginConfig with that ID exists in this namespace"));
    assert!(findings
        .iter()
        .any(|finding| finding.message.contains("No auth plugin")));
}

#[test]
fn derivation_uses_the_overlaid_plugin_target() {
    let mut resources = vec![
        proxy(&[]),
        resource("team-alpha", "Proxy", json!({"id": "other"})),
        plugin("auth", "proxy", Some("api")),
    ];
    let overlay = tempfile::tempdir().unwrap();
    let plugins = overlay.path().join("team-alpha/plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::write(
        plugins.join("auth.yaml"),
        "kind: PluginConfig\nspec:\n  id: auth\n  proxy_id: other\n",
    )
    .unwrap();
    apply_overlay(&mut resources, overlay.path()).unwrap();
    let config = assemble(resources).unwrap().gateway;
    assert!(config.proxies[0].plugins.is_empty());
    assert_eq!(association_ids(&config.proxies[1]), vec!["auth"]);
}
