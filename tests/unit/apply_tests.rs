use gitforgeops::apply::{apply_file, spec_owned_skip_messages, ApplyResult};
use gitforgeops::config::schema::{GatewayConfig, Proxy};
use gitforgeops::diff::SpecOwnedResource;

#[test]
fn apply_result_into_result_rejects_partial_failure() {
    let result = ApplyResult {
        created: 1,
        updated: 2,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Proxy proxy-a update: 500".to_string()],
        ..Default::default()
    };

    let error = result.into_result().unwrap_err();
    let msg = error.to_string();
    assert!(msg.contains("Apply failed after partial success"));
    assert!(msg.contains("Proxy proxy-a update: 500"));
    // The successful-counts portion of the message is what cmd_apply
    // surfaces via the deferred-propagation path: state.record/save
    // runs first, then this error propagates to the CLI. The counts
    // tell operators exactly which portion landed in state.
    assert!(msg.contains("1 created"), "expected created count: {msg}");
    assert!(msg.contains("2 updated"), "expected updated count: {msg}");
    assert!(msg.contains("1 failed"), "expected failed count: {msg}");
}

#[test]
fn apply_result_into_result_propagates_via_err_for_deferred_pattern() {
    // cmd_apply now uses `raw.into_result().err()` to capture the
    // partial-failure error AFTER state.record/state.save runs. This
    // documents that pattern: into_result returns Err on partial
    // failure (even when created+updated > 0), and `.err()` yields
    // Some(error) for deferred propagation.
    let partial = ApplyResult {
        created: 3,
        updated: 0,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Consumer alice create: 500".to_string()],
        ..Default::default()
    };
    assert!(
        partial.into_result().err().is_some(),
        "partial failure must yield Some(err) so deferred propagation triggers"
    );

    // Pure success path: into_result returns Ok, .err() yields None →
    // deferred-propagation block is a no-op.
    let success = ApplyResult {
        created: 5,
        updated: 0,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec![],
        ..Default::default()
    };
    assert!(
        success.into_result().err().is_none(),
        "clean apply must yield None — deferred propagation must not fire"
    );
}

#[test]
fn apply_file_creates_parent_dirs_and_writes_yaml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nested/resources.yaml");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            extra: Default::default(),
            id: "p1".to_string(),
            name: None,
            namespace: "ferrum".to_string(),
            hosts: vec![],
            listen_path: Some("/p1".to_string()),
            backend_scheme: Some(gitforgeops::config::schema::BackendScheme::Http),
            backend_host: "localhost".to_string(),
            backend_port: 8080,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5000,
            backend_read_timeout_ms: 30000,
            backend_write_timeout_ms: 30000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: Default::default(),
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            upstream_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: Default::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            udp_max_response_amplification_factor: None,
            tcp_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            pool_max_requests_per_connection: None,
            upstream_subset: None,
            api_spec_id: None,
            websocket_idle_timeout_seconds: None,
            stream_proxy_protocol: None,
            backend_proxy_protocol: None,
            stream_match: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..GatewayConfig::default()
    };

    apply_file(&config, path.to_str().unwrap()).unwrap();

    let written = std::fs::read_to_string(path).unwrap();
    assert!(written.contains("p1"));
    assert!(written.contains("proxies:"));
}

// --- Apply ordering ----------------------------------------------------------

use gitforgeops::apply::{
    exclusive_prune_denominator, format_prune_percentage, large_prune_exceeds_threshold,
    operation_rank, order_diffs, pending_create_assertion_diffs, preserve_spec_owned_graph,
    stale_view_block, validate_no_desired_spec_tags,
};
use gitforgeops::diff::resource_diff::{state_key, DiffAction, ResourceDiff};

fn diff(action: DiffAction, kind: &str, id: &str) -> ResourceDiff {
    ResourceDiff {
        action,
        kind: kind.to_string(),
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }
}

fn issued(diffs: Vec<ResourceDiff>) -> Vec<String> {
    order_diffs(diffs)
        .into_iter()
        .map(|d| format!("{:?} {} {}", d.action, d.kind, d.id))
        .collect()
}

#[test]
fn adds_follow_the_dependency_graph() {
    // The old kind-major order issued the Proxy add before the Upstream add,
    // and the gateway rejected it: "upstream_id '…' does not exist in
    // namespace '…'".
    let order = issued(vec![
        diff(DiffAction::Add, "Proxy", "p1"),
        diff(DiffAction::Add, "PluginConfig", "pc1"),
        diff(DiffAction::Add, "Upstream", "u1"),
        diff(DiffAction::Add, "Consumer", "c1"),
    ]);

    assert_eq!(
        order,
        vec![
            "Add Upstream u1",
            "Add Consumer c1",
            "Add Proxy p1",
            "Add PluginConfig pc1",
        ]
    );
}

#[test]
fn deletes_run_in_reverse_dependency_order() {
    let order = issued(vec![
        diff(DiffAction::Delete, "Upstream", "u1"),
        diff(DiffAction::Delete, "Proxy", "p1"),
        diff(DiffAction::Delete, "PluginConfig", "pc1"),
        diff(DiffAction::Delete, "Consumer", "c1"),
    ]);

    assert_eq!(
        order,
        vec![
            "Delete PluginConfig pc1",
            "Delete Proxy p1",
            "Delete Upstream u1",
            "Delete Consumer c1",
        ]
    );
}

#[test]
fn a_mixed_diff_applies_writes_before_deletes() {
    // Deleting an upstream only succeeds once nothing references it, so the
    // proxy modify that drops the reference has to land first.
    let order = issued(vec![
        diff(DiffAction::Delete, "Upstream", "old-upstream"),
        diff(DiffAction::Add, "Proxy", "new-proxy"),
        diff(DiffAction::Modify, "Proxy", "moved-proxy"),
        diff(DiffAction::Add, "Upstream", "new-upstream"),
        diff(DiffAction::Delete, "PluginConfig", "stale-pc"),
        diff(DiffAction::Modify, "PluginConfig", "kept-pc"),
    ]);

    assert_eq!(
        order,
        vec![
            "Add Upstream new-upstream",
            "Add Proxy new-proxy",
            "Modify Proxy moved-proxy",
            "Modify PluginConfig kept-pc",
            "Delete PluginConfig stale-pc",
            "Delete Upstream old-upstream",
        ]
    );
}

#[test]
fn ordering_is_stable_within_a_rank() {
    // Same rank ⇒ original (deterministic) diff order is preserved, so
    // repeated runs issue identical request sequences.
    let order = issued(vec![
        diff(DiffAction::Add, "Upstream", "u-b"),
        diff(DiffAction::Add, "Consumer", "c-a"),
        diff(DiffAction::Add, "Upstream", "u-a"),
    ]);
    assert_eq!(
        order,
        vec!["Add Upstream u-b", "Add Consumer c-a", "Add Upstream u-a"]
    );
}

#[test]
fn every_write_rank_precedes_every_delete_rank() {
    for kind in ["Upstream", "Consumer", "Proxy", "PluginConfig"] {
        let write = operation_rank(&DiffAction::Add, kind);
        let modify = operation_rank(&DiffAction::Modify, kind);
        assert_eq!(write, modify, "Add and Modify share a rank for {kind}");
        for other in ["Upstream", "Consumer", "Proxy", "PluginConfig"] {
            assert!(
                write < operation_rank(&DiffAction::Delete, other),
                "{kind} write must precede {other} delete"
            );
        }
    }
}

#[test]
fn unknown_kinds_get_a_defined_rank() {
    // Forward compatibility: a resource kind this build doesn't know about
    // must still sort deterministically rather than panicking or vanishing.
    let order = issued(vec![
        diff(DiffAction::Add, "FutureKind", "x"),
        diff(DiffAction::Add, "Upstream", "u1"),
    ]);
    assert_eq!(order, vec!["Add Upstream u1", "Add FutureKind x"]);
}

// --- Stale gateway view ------------------------------------------------------

#[test]
fn fresh_view_is_not_blocked() {
    assert!(stale_view_block(false).is_none());
}

#[test]
fn large_prune_threshold_uses_an_exact_ratio() {
    assert!(large_prune_exceeds_threshold(1, 200, 0));
    assert!(large_prune_exceeds_threshold(26, 101, 25));
    assert!(!large_prune_exceeds_threshold(25, 100, 25));
    assert!(!large_prune_exceeds_threshold(0, 0, 0));
    assert!(!large_prune_exceeds_threshold(0, usize::MAX, 0));

    // The comparison widens before multiplication, so large platform values
    // cannot overflow and silently weaken the guard.
    assert!(!large_prune_exceeds_threshold(usize::MAX, usize::MAX, 100));
    assert!(large_prune_exceeds_threshold(usize::MAX, usize::MAX, 99));
    assert_eq!(format_prune_percentage(26, 101), "25.74");
    assert_eq!(format_prune_percentage(0, 0), "0.00");
}

#[test]
fn large_prune_decision_matches_an_independent_reference_across_a_small_domain() {
    // The reference is deliberately computed a different way from the
    // implementation: reduce deletes/denominator and threshold/100 to lowest
    // terms and cross-multiply the reduced fractions. Restating the
    // implementation's own expression here would have asserted nothing.
    fn gcd(mut a: u128, mut b: u128) -> u128 {
        while b != 0 {
            let t = a % b;
            a = b;
            b = t;
        }
        a.max(1)
    }
    /// `deletes/denominator > threshold/100`, via reduced fractions.
    fn exceeds(deletes: u128, denominator: u128, threshold: u128) -> bool {
        if denominator == 0 {
            return false;
        }
        let (ln, ld) = {
            let g = gcd(deletes, denominator);
            (deletes / g, denominator / g)
        };
        let (rn, rd) = {
            let g = gcd(threshold, 100);
            (threshold / g, 100 / g)
        };
        ln * rd > rn * ld
    }

    for denominator in 0_usize..=250 {
        for deletes in 0_usize..=denominator {
            for threshold in 0_u8..=100 {
                let reference = exceeds(deletes as u128, denominator as u128, threshold as u128);
                assert_eq!(
                    large_prune_exceeds_threshold(deletes, denominator, threshold),
                    reference,
                    "deletes={deletes}, denominator={denominator}, threshold={threshold}"
                );
            }
        }
    }

    // Spot-check the reference itself against hand-computed answers, so a bug
    // in the reference cannot silently agree with a bug in the implementation.
    assert!(exceeds(1, 3, 33));
    assert!(!exceeds(1, 4, 25));
    assert!(!exceeds(0, 10, 0));
    assert!(exceeds(1, 10, 0));
}

// --- Full-replace API-spec graph preservation -------------------------------

fn proxy(id: &str, namespace: &str, api_spec_id: Option<&str>) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "api_spec_id": api_spec_id,
    }))
    .expect("proxy fixture")
}

fn plugin_config(
    id: &str,
    namespace: &str,
    proxy_id: &str,
    api_spec_id: Option<&str>,
) -> gitforgeops::config::schema::PluginConfig {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "plugin_name": "cors",
        "config": {},
        "scope": "proxy",
        "proxy_id": proxy_id,
        "api_spec_id": api_spec_id,
    }))
    .expect("plugin fixture")
}

fn spec_extras(ids: &[&str]) -> gitforgeops::http_client::BackupExtras {
    spec_extras_hashed(&ids.iter().map(|id| (*id, "sha-1")).collect::<Vec<_>>())
}

/// `spec_extras` with an explicit `content_hash` per spec, so a test can make
/// one document differ between two `/backup` reads the way a concurrent
/// `PUT /api-specs/{id}` would.
fn spec_extras_hashed(specs: &[(&str, &str)]) -> gitforgeops::http_client::BackupExtras {
    gitforgeops::http_client::BackupExtras {
        api_specs: Some(serde_json::json!({
            "section_version": "2",
            "items": specs.iter().map(|(id, content_hash)| serde_json::json!({
                "id": id,
                "namespace": "team-alpha",
                "proxy_id": "spec-proxy",
                "content_hash": content_hash,
            })).collect::<Vec<_>>(),
        })),
        gateway_trust_bundles: Some(serde_json::json!([{"revision": 7}])),
        unsupported_sections: Vec::new(),
    }
}

/// [`backup_body`] with the opaque sections `GatewayConfig` does not model
/// spliced back in, for the freshness re-read that reads `api_specs`.
fn backup_body_with_extras(
    config: &GatewayConfig,
    extras: &gitforgeops::http_client::BackupExtras,
) -> String {
    let mut body = serde_json::to_value(config).expect("config serializes");
    if let Some(map) = body.as_object_mut() {
        if let Some(api_specs) = extras.api_specs.as_ref() {
            map.insert("api_specs".to_string(), api_specs.clone());
        }
        if let Some(bundles) = extras.gateway_trust_bundles.as_ref() {
            map.insert("gateway_trust_bundles".to_string(), bundles.clone());
        }
    }
    serde_json::to_string(&body).expect("backup body")
}

/// Repo-owned desired rows plus the live spec-owned graph they must be
/// restored alongside: one API spec `spec-a` owning proxy `spec-proxy`,
/// upstream `spec-upstream` and plugin config `spec-plugin`.
fn spec_owned_graph() -> (GatewayConfig, GatewayConfig) {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let mut spec_upstream = upstream("spec-upstream", "team-alpha");
    spec_upstream.api_spec_id = Some("spec-a".to_string());
    let mut spec_proxy = proxy("spec-proxy", "team-alpha", Some("spec-a"));
    spec_proxy
        .plugins
        .push(gitforgeops::config::schema::PluginAssociation {
            plugin_config_id: "spec-plugin".to_string(),
        });
    let actual = GatewayConfig {
        proxies: vec![spec_proxy],
        upstreams: vec![spec_upstream],
        plugin_configs: vec![plugin_config(
            "spec-plugin",
            "team-alpha",
            "spec-proxy",
            Some("spec-a"),
        )],
        ..Default::default()
    };
    (desired, actual)
}

#[test]
fn merging_the_spec_owned_graph_keeps_repo_rows_authoritative() {
    let (desired, actual) = spec_owned_graph();

    let merged =
        preserve_spec_owned_graph(&desired, &actual, &spec_extras(&["spec-a"]), "team-alpha")
            .expect("complete graph should merge");

    assert_eq!(merged.proxies.len(), 1);
    assert_eq!(merged.plugin_configs.len(), 1);
    assert_eq!(merged.upstreams.len(), 2);
    assert_eq!(merged.upstreams[0].id, "repo-upstream");
    assert_eq!(merged.upstreams[1].id, "spec-upstream");
    assert_eq!(merged.upstreams[1].api_spec_id.as_deref(), Some("spec-a"));
}

#[test]
fn full_replace_rejects_repo_collision_with_spec_owned_row() {
    let desired = GatewayConfig {
        proxies: vec![proxy("shared-id", "team-alpha", None)],
        ..Default::default()
    };
    let actual = GatewayConfig {
        proxies: vec![proxy("shared-id", "team-alpha", Some("spec-a"))],
        ..Default::default()
    };

    let error =
        preserve_spec_owned_graph(&desired, &actual, &spec_extras(&["spec-a"]), "team-alpha")
            .unwrap_err()
            .to_string();
    assert!(error.contains("conflicts"), "{error}");
    assert!(error.contains("shared-id"), "{error}");
    assert!(error.contains("spec-a"), "{error}");
}

#[test]
fn every_api_strategy_rejects_repository_authored_spec_ownership_tags() {
    let desired = GatewayConfig {
        proxies: vec![proxy("forged-owner", "team-alpha", Some("spec-a"))],
        ..Default::default()
    };

    let error = validate_no_desired_spec_tags(&desired)
        .unwrap_err()
        .to_string();
    assert!(error.contains("forged-owner"), "{error}");
    assert!(error.contains("admin-generated"), "{error}");
}

#[test]
fn interactive_preview_includes_pending_create_ownership_assertions() {
    let desired_upstream = upstream("pending-upstream", "team-alpha");
    let desired = GatewayConfig {
        upstreams: vec![desired_upstream.clone()],
        ..Default::default()
    };
    let actual = GatewayConfig {
        upstreams: vec![desired_upstream],
        ..Default::default()
    };
    let pending =
        std::collections::BTreeSet::from([state_key("team-alpha", "Upstream", "pending-upstream")]);

    let assertions = pending_create_assertion_diffs(&desired, &actual, &pending, "team-alpha");

    assert_eq!(assertions.len(), 1);
    assert!(matches!(assertions[0].action, DiffAction::Modify));
    assert_eq!(assertions[0].kind, "Upstream");
    assert_eq!(assertions[0].id, "pending-upstream");
}

#[test]
fn full_replace_rejects_incomplete_spec_ownership_graph() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig::default();
    let error =
        preserve_spec_owned_graph(&desired, &actual, &spec_extras(&["spec-a"]), "team-alpha")
            .unwrap_err()
            .to_string();
    assert!(
        error.contains("no tagged") || error.contains("owning proxy"),
        "{error}"
    );
    assert!(error.contains("spec-a"), "{error}");
}

#[test]
fn full_replace_rejects_a_tagged_proxy_that_is_not_the_declared_owner() {
    let actual = GatewayConfig {
        proxies: vec![proxy("wrong-proxy", "team-alpha", Some("spec-a"))],
        ..Default::default()
    };

    let error = preserve_spec_owned_graph(
        &GatewayConfig::default(),
        &actual,
        &spec_extras(&["spec-a"]),
        "team-alpha",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("spec-proxy"), "{error}");
    assert!(error.contains("exactly one"), "{error}");
}

#[test]
fn full_replace_rejects_spec_owned_rows_from_another_namespace() {
    let actual = GatewayConfig {
        proxies: vec![proxy("spec-proxy", "foreign", Some("spec-a"))],
        ..Default::default()
    };

    let error = preserve_spec_owned_graph(
        &GatewayConfig::default(),
        &actual,
        &spec_extras(&["spec-a"]),
        "team-alpha",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("foreign"), "{error}");
    assert!(error.contains("team-alpha"), "{error}");
}

#[test]
fn exclusive_prune_denominator_excludes_unconfirmed_spec_owned_rows() {
    let actual = GatewayConfig {
        proxies: vec![
            proxy("manual-proxy", "team-alpha", None),
            proxy("spec-proxy", "team-alpha", Some("spec-a")),
        ],
        upstreams: vec![upstream("manual-upstream", "team-alpha"), {
            let mut value = upstream("spec-upstream", "team-alpha");
            value.api_spec_id = Some("spec-a".to_string());
            value
        }],
        plugin_configs: vec![
            plugin_config("manual-plugin", "team-alpha", "manual-proxy", None),
            plugin_config("spec-plugin", "team-alpha", "spec-proxy", Some("spec-a")),
        ],
        ..Default::default()
    };

    assert_eq!(exclusive_prune_denominator(&actual, false), 3);
    assert_eq!(exclusive_prune_denominator(&actual, true), 6);
}

// --- Spec-owned skip messages ------------------------------------------------

fn spec_owned(id: &str, declared_in_repo: bool, pruned: bool) -> SpecOwnedResource {
    SpecOwnedResource {
        kind: "Proxy".to_string(),
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        api_spec_id: "spec-7".to_string(),
        declared_in_repo,
        pruned,
    }
}

#[test]
fn spec_owned_skip_message_names_the_owning_spec() {
    let messages = spec_owned_skip_messages(&[spec_owned("from-spec", false, false)]);

    assert_eq!(messages.len(), 1);
    assert!(
        messages[0].contains("skipping Proxy `from-spec`"),
        "{}",
        messages[0]
    );
    assert!(messages[0].contains("spec-7"), "{}", messages[0]);
    assert!(
        messages[0].contains("--confirm-api-spec-deletion"),
        "the skip message must say how to override it: {}",
        messages[0]
    );
}

#[test]
fn spec_owned_skip_message_flags_repo_conflict() {
    let messages = spec_owned_skip_messages(&[spec_owned("shared-id", true, false)]);

    assert!(messages[0].starts_with("conflict:"), "{}", messages[0]);
    assert!(
        messages[0].contains("this repo also declares it"),
        "{}",
        messages[0]
    );
    assert!(
        !messages[0].contains("--confirm-api-spec-deletion"),
        "a conflict is not fixed by the deletion flag: {}",
        messages[0]
    );
}

#[test]
fn spec_owned_skip_message_announces_confirmed_deletion() {
    let messages = spec_owned_skip_messages(&[spec_owned("from-spec", false, true)]);

    assert!(
        messages[0].contains("deleting Proxy `from-spec`"),
        "{}",
        messages[0]
    );
    assert!(
        messages[0].contains("--confirm-api-spec-deletion"),
        "{}",
        messages[0]
    );
}

#[test]
fn spec_owned_skip_messages_is_empty_without_spec_owned_resources() {
    assert!(spec_owned_skip_messages(&[]).is_empty());
}

#[test]
fn apply_result_reports_spec_owned_skips() {
    let result = ApplyResult {
        created: 1,
        spec_owned_skipped: 2,
        ..Default::default()
    };
    let ok = result.into_result().expect("no errors means Ok");
    assert_eq!(ok.spec_owned_skipped, 2);
}

// --- Fatal stops -------------------------------------------------------------

#[test]
fn a_fatal_stop_still_yields_an_error_with_the_partial_counts() {
    // The fatal error rides on the result instead of being returned as Err, so
    // cmd_apply can persist state for the ops that landed first. into_result
    // is what turns it back into a non-zero exit.
    let result = ApplyResult {
        created: 4,
        updated: 1,
        fatal_error: Some(
            "[team-b] gateway admin API is read-only, refusing to apply: ...".to_string(),
        ),
        ..Default::default()
    };

    let msg = result.into_result().unwrap_err().to_string();
    assert!(msg.contains("Apply stopped"), "{msg}");
    assert!(msg.contains("read-only"), "{msg}");
    assert!(
        msg.contains("4 created"),
        "the operator must see what landed before the stop: {msg}"
    );
}

#[test]
fn a_fatal_stop_alongside_per_resource_failures_reports_both() {
    let result = ApplyResult {
        created: 2,
        errors: vec!["Proxy p9 create: 409 duplicate".to_string()],
        fatal_error: Some("[team-b] gateway admin API is read-only".to_string()),
        ..Default::default()
    };

    let msg = result.into_result().unwrap_err().to_string();
    assert!(msg.contains("Apply stopped"), "{msg}");
    assert!(msg.contains("Proxy p9 create"), "{msg}");
    assert!(msg.contains("1 failed"), "{msg}");
}

#[test]
fn a_clean_result_has_no_fatal_error() {
    let result = ApplyResult {
        created: 3,
        ..Default::default()
    };
    assert!(result.fatal_error.is_none());
    assert!(result.into_result().is_ok());
}

// --- All-404 delete warning --------------------------------------------------

#[test]
fn every_delete_404ing_is_called_out() {
    let warning = all_deletes_missing_warning("team-alpha", 3, 3).expect("should warn");
    assert!(warning.contains("[team-alpha]"), "{warning}");
    assert!(
        warning.contains("all 3 delete(s) returned 404"),
        "{warning}"
    );
    assert!(warning.contains("FERRUM_GATEWAY_URL"), "{warning}");
    assert!(
        warning.contains("state entries were still removed"),
        "the operator has to know the next run will not retry them: {warning}"
    );
}

#[test]
fn a_single_tolerated_404_stays_silent() {
    // The gateway cascades deletes server-side, so one follow-up delete
    // finding nothing is routine and must not become noise.
    assert!(all_deletes_missing_warning("team-alpha", 3, 1).is_none());
    assert!(all_deletes_missing_warning("team-alpha", 2, 0).is_none());
    // Nothing was deleted at all — there is no signal here either way.
    assert!(all_deletes_missing_warning("team-alpha", 0, 0).is_none());
}

// --- apply_api against a stub gateway ----------------------------------------

use gitforgeops::apply::{all_deletes_missing_warning, apply_api, ApplyOptions};
use gitforgeops::config::env::{EnvConfig, GatewayMode};
use gitforgeops::config::schema::Upstream;
use gitforgeops::diff::OwnershipScope;
use gitforgeops::http_client::AdminClient;
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// Canned-response gateway on a loopback socket, matched by the first route
/// whose needle appears anywhere in the request (line, headers, or body).
///
/// Reads the full request including its body, so routes can key on a payload —
/// which is how "fail this one resource, accept the others" is expressed.
fn spawn_stub_gateway(routes: Vec<(&'static str, u16, &'static str)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = routes.clone();
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                let (status, body) = routes
                    .iter()
                    .find(|(needle, _, _)| request.contains(needle))
                    .map(|(_, status, body)| (*status, *body))
                    .unwrap_or((200, "{}"));
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    format!("http://{addr}")
}

/// Owned-response variant that records every request and can attach response
/// headers (notably `X-Data-Source: cached`).
type RecordingRoute = (String, u16, String, Vec<(String, String)>);

fn spawn_recording_gateway(routes: Vec<RecordingRoute>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = routes.clone();
            let requests = Arc::clone(&thread_requests);
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                requests.lock().unwrap().push(request.clone());
                let (status, body, headers) = routes
                    .iter()
                    .find(|(needle, _, _, _)| request.contains(needle))
                    .map(|(_, status, body, headers)| (*status, body.as_str(), headers.as_slice()))
                    .unwrap_or((200, "{}", &[]));
                let headers = headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>();
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\n{headers}content-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    (format!("http://{addr}"), requests)
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let mut buf = [0_u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw).to_string();
        let Some(header_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let content_length = text
            .to_ascii_lowercase()
            .split("\r\n")
            .find_map(|line| {
                line.strip_prefix("content-length:")
                    .map(str::trim)
                    .map(String::from)
            })
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if raw.len() >= header_end + 4 + content_length {
            return Some(text);
        }
    }
}

/// Namespace scope every test client is built with.
///
/// `AdminClient::new_scoped` is the only public constructor, so tests declare
/// a scope like production call sites do. The stub gateways ignore the token,
/// but this keeps the tests honest about the constructor's contract.
const TEST_NAMESPACES: [&str; 5] = ["team-alpha", "team-a", "team-b", "ferrum", "alpha"];

fn stub_client(url: String) -> AdminClient {
    stub_client_with_retries(url, 0)
}

fn stub_client_with_retries(url: String, gateway_max_retries: u32) -> AdminClient {
    let env = EnvConfig {
        gateway_url: Some(url),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        gateway_mode: GatewayMode::Api,
        gateway_max_retries,
        ..EnvConfig::default()
    };
    AdminClient::new_scoped(&env, TEST_NAMESPACES).unwrap()
}

fn upstream(id: &str, namespace: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream fixture")
}

const HEALTHY: &str = r#"{"status":"ok","mode":"database","admin_writes_enabled":true}"#;

fn empty_actuals(namespaces: &[&str]) -> BTreeMap<String, GatewayConfig> {
    namespaces
        .iter()
        .map(|ns| (ns.to_string(), GatewayConfig::default()))
        .collect()
}

#[tokio::test]
async fn full_replace_rejects_unknown_backup_sections_before_preflight_or_mutation() {
    let client = stub_client("http://127.0.0.1:9".to_string());
    let namespaces = ["team-alpha".to_string()];
    let actuals = empty_actuals(&["team-alpha"]);
    let extras = BTreeMap::from([(
        "team-alpha".to_string(),
        gitforgeops::http_client::BackupExtras {
            unsupported_sections: vec!["future_security_policy".to_string()],
            ..Default::default()
        },
    )]);
    let options = ApplyOptions {
        strategy: gitforgeops::config::ApplyStrategy::FullReplace,
        ..Default::default()
    };

    let error = apply_api(
        &GatewayConfig::default(),
        &client,
        &namespaces,
        OwnershipScope::Exclusive,
        Some(&actuals),
        Some(&extras),
        &options,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        gitforgeops::error::Error::UnsupportedBackupSections(_)
    ));
    assert!(error.to_string().contains("future_security_policy"));
}

#[tokio::test]
async fn a_rejected_batch_chunk_falls_back_to_named_per_resource_creates() {
    // The old behaviour returned one opaque "POST /batch: {e}" and abandoned
    // every remaining resource. `/batch` is all-or-nothing per chunk, so
    // nothing landed — replaying the chunk per resource names the resource the
    // gateway actually objected to and still creates the rest.
    let url = spawn_stub_gateway(vec![
        ("GET /health", 200, HEALTHY),
        ("POST /batch", 400, r#"{"error":"batch rejected"}"#),
        (r#""id":"u2""#, 409, r#"{"error":"duplicate id"}"#),
        ("POST /upstreams", 201, "{}"),
    ]);
    let client = stub_client_with_retries(url, 3);

    let desired = GatewayConfig {
        upstreams: vec![
            upstream("u1", "team-alpha"),
            upstream("u2", "team-alpha"),
            upstream("u3", "team-alpha"),
        ],
        ..Default::default()
    };

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a per-resource failure is not fatal");

    assert_eq!(result.created, 2, "the healthy resources still land");
    assert_eq!(result.errors.len(), 1, "got {:?}", result.errors);
    assert!(
        result.errors[0].contains("Upstream u2 create"),
        "the failing resource must be named: {:?}",
        result.errors
    );
    // Order follows the diff, which is not id-sorted; the *set* is what
    // matters for the state update.
    let mut created: Vec<&str> = result
        .applied_incremental
        .iter()
        .map(|op| op.id.as_str())
        .collect();
    created.sort_unstable();
    assert_eq!(created, vec!["u1", "u3"]);
    assert!(result.fatal_error.is_none());
}

#[tokio::test]
async fn ambiguous_batch_is_not_replayed_and_is_recovered_from_authoritative_backup() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let backup = serde_json::to_string(&desired).unwrap();
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /batch".into(),
            503,
            r#"{"error":"upstream response lost"}"#.into(),
            vec![],
        ),
        ("GET /backup".into(), 200, backup, vec![]),
    ]);
    let client = stub_client_with_retries(url, 3);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("reconciliation should prove the committed chunk");

    assert_eq!(result.created, 1);
    assert_eq!(result.applied_incremental.len(), 1);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.fatal_error.is_none(), "{:?}", result.fatal_error);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("POST /batch"))
            .count(),
        1,
        "the ambiguous POST must never be retried"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("POST /upstreams"))
            .count(),
        0,
        "an ambiguous batch must not fall back to individual creates"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("PUT /upstreams/u1"))
            .count(),
        1,
        "exact readback still needs an idempotent ownership assertion"
    );
}

#[tokio::test]
async fn ambiguous_create_is_sent_once_and_recovered_from_authoritative_backup() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let backup = serde_json::to_string(&desired).unwrap();
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("POST /batch".into(), 501, "{}".into(), vec![]),
        (
            "POST /upstreams".into(),
            502,
            r#"{"error":"response lost after commit"}"#.into(),
            vec![],
        ),
        ("GET /backup".into(), 200, backup, vec![]),
    ]);
    let client = stub_client_with_retries(url, 3);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("reconciliation should prove the committed create");

    assert_eq!(result.created, 1);
    assert_eq!(result.applied_incremental.len(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("POST /upstreams"))
            .count(),
        1,
        "the ambiguous create must never be retried"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("PUT /upstreams/u1"))
            .count(),
        1,
        "exact readback still needs an idempotent ownership assertion"
    );
}

#[tokio::test]
async fn pending_exact_row_gets_an_idempotent_ownership_assertion() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("PUT /upstreams/u1".into(), 200, "{}".into(), vec![]),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            desired.clone(),
        )])),
        None,
        &ApplyOptions {
            pending_create_assertions: std::collections::BTreeSet::from([state_key(
                "team-alpha",
                "Upstream",
                "u1",
            )]),
            ..Default::default()
        },
    )
    .await
    .expect("ownership assertion should succeed");

    assert_eq!(result.updated, 1);
    assert_eq!(result.applied_incremental.len(), 1);
    assert!(matches!(
        result.applied_incremental[0].action,
        DiffAction::Modify
    ));
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("PUT /upstreams/u1"))
            .count(),
        1
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("POST /upstreams")),
        "the uncertain create must not be replayed"
    );
}

#[tokio::test]
async fn a_create_proven_uncommitted_is_an_ordinary_error_and_later_namespaces_still_apply() {
    // The gateway told us, authoritatively, that nothing landed. That is an
    // ordinary per-resource failure — retryable next run — not a reason to
    // abandon every namespace after it.
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "ferrum"), upstream("u2", "team-b")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        // Authoritative and empty: the create provably did not commit.
        (
            "GET /backup".into(),
            200,
            serde_json::to_string(&GatewayConfig::default()).unwrap(),
            vec![],
        ),
        ("POST /batch".into(), 501, "{}".into(), vec![]),
        (
            "x-ferrum-namespace: ferrum".into(),
            502,
            r#"{"error":"bad gateway"}"#.into(),
            vec![],
        ),
        ("POST /upstreams".into(), 201, "{}".into(), vec![]),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["ferrum".to_string(), "team-b".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum", "team-b"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a proven no-op is not fatal");

    assert!(result.fatal_error.is_none(), "{:?}", result.fatal_error);
    assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    assert!(
        result.errors[0].contains("[ferrum] Upstream u1 create"),
        "{:?}",
        result.errors
    );
    assert!(
        result.errors[0].contains("did not commit"),
        "{:?}",
        result.errors
    );
    assert_eq!(result.created, 1, "team-b must still be reconciled");
    assert_eq!(
        result
            .applied_incremental
            .iter()
            .map(|op| op.id.as_str())
            .collect::<Vec<_>>(),
        vec!["u2"]
    );

    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("POST /upstreams")
                && request.contains("x-ferrum-namespace: ferrum"))
            .count(),
        1,
        "the ambiguous create must never be retried"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("PUT /upstreams/u1")),
        "nothing landed, so there is no ownership to assert"
    );
}

#[tokio::test]
async fn a_create_whose_readback_finds_a_different_row_still_stops_the_run() {
    // Something holds the identity, but not what we sent. That could be a
    // partially applied write or another writer; either way no automatic
    // recovery is safe.
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "ferrum"), upstream("u2", "team-b")],
        ..Default::default()
    };
    let mut foreign = upstream("u1", "ferrum");
    foreign.targets.clear();
    let live = GatewayConfig {
        upstreams: vec![foreign],
        ..Default::default()
    };
    let (url, _requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            serde_json::to_string(&live).unwrap(),
            vec![],
        ),
        ("POST /batch".into(), 501, "{}".into(), vec![]),
        (
            "POST /upstreams".into(),
            502,
            r#"{"error":"bad gateway"}"#.into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["ferrum".to_string(), "team-b".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum", "team-b"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("the stop rides on the result");

    let fatal = result.fatal_error.expect("an unprovable outcome is fatal");
    assert!(fatal.contains("[ferrum]"), "{fatal}");
    assert!(fatal.contains("not the resource we sent"), "{fatal}");
    assert_eq!(result.created, 0);
}

#[tokio::test]
async fn committed_but_not_live_create_is_failed_without_reconciliation_success() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("POST /batch".into(), 501, "{}".into(), vec![]),
        (
            "POST /upstreams".into(),
            503,
            r#"{"error":"reload timed out","applied":false,"reason":"reload_timeout"}"#.into(),
            vec![],
        ),
    ]);
    let client = stub_client_with_retries(url, 3);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("run-stopping failure is returned in the aggregate");

    assert_eq!(result.created, 0);
    assert!(
        result
            .fatal_error
            .as_deref()
            .is_some_and(|error| error.contains("write committed, awaiting reload")),
        "{:?}",
        result.fatal_error
    );
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("POST /upstreams"))
            .count(),
        1
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("GET /backup")),
        "applied:false is a known failure, not proof that the desired resource is live"
    );
}

#[tokio::test]
async fn cached_backup_blocks_all_apply_mutations_before_the_first_write() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            serde_json::to_string(&GatewayConfig::default()).unwrap(),
            vec![("X-Data-Source".into(), "cached".into())],
        ),
    ]);
    let client = stub_client(url);
    let snapshot = client
        .get_backup_snapshot("team-alpha")
        .await
        .expect("cached backup itself remains readable");
    assert!(snapshot.cached);

    let error = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            snapshot.config,
        )])),
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            snapshot.extras,
        )])),
        &ApplyOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, gitforgeops::error::Error::StaleGatewayView(_)),
        "{error:?}"
    );
    // The wording is the operator's only clue about why an apply that looks
    // routine refused, so assert it where it is actually produced.
    let message = error.to_string();
    assert!(message.contains("X-Data-Source: cached"), "{message}");
    assert!(message.contains("API-spec ownership metadata"), "{message}");
    assert!(
        message.contains("--allow-large-prune") && message.contains("does not bypass"),
        "the one override an operator would reach for must be ruled out: {message}"
    );
    let requests = requests.lock().unwrap();
    assert!(
        requests.iter().all(|request| {
            !request.contains("POST ") && !request.contains("PUT ") && !request.contains("DELETE ")
        }),
        "no mutation may be sent from cached ownership data: {requests:?}"
    );
}

#[tokio::test]
async fn full_replace_preserves_the_complete_spec_owned_resource_graph() {
    // Issue #71. `/restore` validates the ownership graph as one unit: an
    // `api_specs` document whose owning proxy is missing, or a tagged row
    // whose spec is missing, is a 400 before anything is deleted. So the body
    // has to carry the repo's desired rows AND the live spec-owned rows AND
    // the live `api_specs` section. Restore never re-extracts resources from
    // the documents, so nothing is duplicated by carrying both.
    let (desired, actual) = spec_owned_graph();
    let extras = spec_extras(&["spec-a"]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
        // The freshness re-read immediately before the restore. Unchanged,
        // so the payload is still an accurate description of the namespace.
        (
            "GET /backup".into(),
            200,
            backup_body_with_extras(&actual, &extras),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([("team-alpha".to_string(), actual)])),
        Some(&BTreeMap::from([("team-alpha".to_string(), extras)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("a namespace with API specs must be restorable");

    assert_eq!(
        result.created, 1,
        "only the repo-owned row counts as applied; preserved spec rows are not this repo's"
    );
    assert_eq!(result.fully_replaced_namespaces, vec!["team-alpha"]);

    let restore = requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| request.contains("POST /restore?confirm=true"))
        .cloned()
        .expect("restore request");
    let body: serde_json::Value =
        serde_json::from_str(restore.split_once("\r\n\r\n").expect("request body").1)
            .expect("restore body is JSON");

    assert!(
        !restore.contains("confirm_api_spec_deletion"),
        "preservation must not use the destructive opt-in: {restore}"
    );

    let ids = |section: &str| {
        body[section]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|value| value["id"].as_str().map(str::to_string))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids("upstreams"), vec!["repo-upstream", "spec-upstream"]);
    assert_eq!(ids("proxies"), vec!["spec-proxy"]);
    assert_eq!(ids("plugin_configs"), vec!["spec-plugin"]);

    // Every tagged row names a spec that is present in `api_specs.items`, and
    // that spec's owning proxy is present and carries the tag — the exact two
    // directions ferrum-edge's restore validator checks.
    assert_eq!(body["api_specs"]["items"][0]["id"], "spec-a");
    assert_eq!(body["api_specs"]["items"][0]["proxy_id"], "spec-proxy");
    for section in ["proxies", "upstreams", "plugin_configs"] {
        for row in body[section].as_array().into_iter().flatten() {
            if let Some(tag) = row["api_spec_id"].as_str() {
                assert_eq!(tag, "spec-a", "{section}: {row}");
            }
        }
    }

    assert!(
        !restore.contains("gateway_trust_bundles"),
        "an absent trust section preserves the live roots: {restore}"
    );

    // The spec section is only safe to replay because it was re-read directly
    // before the POST; a payload built minutes earlier is not evidence.
    let ordered = requests.lock().unwrap().clone();
    let backup_at = ordered
        .iter()
        .position(|request| request.contains("GET /backup"))
        .expect("freshness re-read");
    let restore_at = ordered
        .iter()
        .position(|request| request.contains("POST /restore"))
        .expect("restore");
    assert!(
        backup_at < restore_at,
        "the spec snapshot must be re-verified before the restore: {ordered:?}"
    );
}

/// A spec rewritten between the payload being built and the POST must abort
/// the restore. `/restore` deletes every spec in the namespace and re-creates
/// exactly what the payload carries, so proceeding would roll the newer
/// document back to the one this run happened to read first.
#[tokio::test]
async fn full_replace_aborts_when_a_spec_changed_since_the_payload_was_built() {
    let (desired, actual) = spec_owned_graph();
    let prepared = spec_extras_hashed(&[("spec-a", "sha-1")]);
    let live = spec_extras_hashed(&[("spec-a", "sha-2")]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            backup_body_with_extras(&actual, &live),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([("team-alpha".to_string(), actual)])),
        Some(&BTreeMap::from([("team-alpha".to_string(), prepared)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("the abort is namespace-scoped, not a whole-run stop");

    // Namespace-scoped: recorded so the run still exits non-zero through
    // `into_result`, without taking every other namespace out of the apply.
    assert!(result.fully_replaced_namespaces.is_empty());
    let rendered = result.errors.join("\n");
    assert!(rendered.contains("`spec-a` was modified"), "{rendered}");
    assert!(result.into_result().is_err(), "the run must not exit green");
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("POST /restore")),
        "a stale spec snapshot must never be replayed"
    );
}

/// A spec created after the payload was built is the more destructive half of
/// the same race: it is absent from `api_specs.items`, and a non-empty section
/// makes the gateway delete every spec the payload does not name — without
/// consulting `confirm_api_spec_deletion`, which it only reads when the
/// section is absent entirely.
#[tokio::test]
async fn full_replace_aborts_when_a_spec_was_created_since_the_payload_was_built() {
    let (desired, actual) = spec_owned_graph();
    let prepared = spec_extras(&["spec-a"]);
    let live = spec_extras(&["spec-a", "spec-b"]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            backup_body_with_extras(&actual, &live),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([("team-alpha".to_string(), actual)])),
        Some(&BTreeMap::from([("team-alpha".to_string(), prepared)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("the abort is namespace-scoped, not a whole-run stop");

    // Namespace-scoped: recorded so the run still exits non-zero through
    // `into_result`, without taking every other namespace out of the apply.
    assert!(result.fully_replaced_namespaces.is_empty());
    let rendered = result.errors.join("\n");
    assert!(rendered.contains("`spec-b` was created"), "{rendered}");
    assert!(result.into_result().is_err(), "the run must not exit green");
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("POST /restore")),
        "a snapshot that no longer describes the namespace must not be replayed"
    );
}

/// A namespace with no API specs sends no `api_specs` section, so there is
/// nothing to replay and no reason to pay for the extra round-trip. The
/// gateway's own existing-spec `409` covers a spec created mid-run here.
#[tokio::test]
async fn full_replace_without_api_specs_does_not_re_read_the_backup() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            gitforgeops::http_client::BackupExtras::default(),
        )])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("a namespace with no specs restores");

    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("GET /backup")),
        "no spec section travels, so nothing needs re-verifying"
    );
}

#[tokio::test]
async fn full_replace_refuses_an_incomplete_spec_owned_graph_before_mutating() {
    // The preservation path is only safe while the graph can be proven whole.
    // A spec document whose tagged rows are missing from the same
    // authoritative backup means the view is incomplete, not that the rows
    // should be deleted.
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let error = apply_api(
        &GatewayConfig::default(),
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            spec_extras(&["spec-a"]),
        )])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("spec-a"), "{error}");
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("POST /restore")),
        "an unprovable graph must never reach /restore"
    );
}

#[tokio::test]
async fn confirmed_spec_deletion_leaves_live_trust_bundles_untouched() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let extras = spec_extras(&["spec-a"]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true&confirm_api_spec_deletion=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            GatewayConfig::default(),
        )])),
        Some(&BTreeMap::from([("team-alpha".to_string(), extras)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            confirm_api_spec_deletion: true,
            ..Default::default()
        },
    )
    .await
    .expect("confirmed full replace should succeed");

    assert_eq!(result.created, 1);
    let restore = requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| {
            request.contains("POST /restore?confirm=true&confirm_api_spec_deletion=true")
        })
        .cloned()
        .expect("confirmed restore request");
    assert!(restore.contains("repo-upstream"), "{restore}");
    assert!(!restore.contains("gateway_trust_bundles"), "{restore}");
    assert!(!restore.contains("api_specs"), "{restore}");
    assert!(!restore.contains("spec-proxy"), "{restore}");
}

#[tokio::test]
async fn empty_spec_snapshot_omits_api_specs_and_trust_to_close_lost_update_races() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let extras = gitforgeops::http_client::BackupExtras {
        api_specs: Some(serde_json::json!({"section_version": "2", "items": []})),
        gateway_trust_bundles: Some(serde_json::json!([{"revision": 7}])),
        unsupported_sections: Vec::new(),
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            GatewayConfig::default(),
        )])),
        Some(&BTreeMap::from([("team-alpha".to_string(), extras)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("empty spec snapshot is safe to restore");

    assert_eq!(result.created, 1);
    let restore = requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| request.contains("POST /restore?confirm=true"))
        .cloned()
        .expect("restore request");
    assert!(restore.contains("repo-upstream"), "{restore}");
    assert!(!restore.contains("api_specs"), "{restore}");
    assert!(!restore.contains("gateway_trust_bundles"), "{restore}");
}

#[tokio::test]
async fn later_namespace_restore_validation_fails_before_any_namespace_is_mutated() {
    let (url, requests) = spawn_recording_gateway(vec![]);
    let client = stub_client(url);
    let namespaces = vec!["alpha".to_string(), "beta".to_string()];
    let actuals = empty_actuals(&["alpha", "beta"]);
    let extras = BTreeMap::from([
        (
            "alpha".to_string(),
            gitforgeops::http_client::BackupExtras {
                api_specs: Some(serde_json::json!({
                    "section_version": "2",
                    "items": []
                })),
                ..Default::default()
            },
        ),
        (
            "beta".to_string(),
            gitforgeops::http_client::BackupExtras {
                api_specs: Some(serde_json::json!({"section_version": "2"})),
                ..Default::default()
            },
        ),
    ]);

    let error = apply_api(
        &GatewayConfig::default(),
        &client,
        &namespaces,
        OwnershipScope::Exclusive,
        Some(&actuals),
        Some(&extras),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("items"), "{error}");
    assert!(
        requests.lock().unwrap().is_empty(),
        "alpha must not restore before beta's deterministic error"
    );
}

#[tokio::test]
async fn a_spec_owned_conflict_blocks_only_the_conflicting_namespace() {
    // Two owners writing one row is a correctness problem in *that* namespace.
    // Stopping every other namespace turned one team's mis-declared proxy into
    // an outage for everybody sharing the environment, so the block is scoped
    // and reported as a per-namespace error — the run still exits non-zero.
    let desired_proxy = proxy("shared", "alpha", None);
    let mut spec_proxy = desired_proxy.clone();
    spec_proxy.api_spec_id = Some("spec-a".to_string());
    let desired = GatewayConfig {
        proxies: vec![desired_proxy],
        upstreams: vec![upstream("unrelated", "beta")],
        ..Default::default()
    };
    let actuals = BTreeMap::from([
        (
            "alpha".to_string(),
            GatewayConfig {
                proxies: vec![spec_proxy],
                ..Default::default()
            },
        ),
        ("beta".to_string(), GatewayConfig::default()),
    ]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /batch".into(),
            200,
            r#"{"created":{"upstreams":1}}"#.into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["alpha".to_string(), "beta".to_string()],
        OwnershipScope::Exclusive,
        Some(&actuals),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("the conflict rides on the result as a per-namespace error");

    assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    assert!(
        result.errors[0].starts_with("[alpha]"),
        "{:?}",
        result.errors
    );
    assert!(
        result.errors[0].contains("API-spec-owned"),
        "{:?}",
        result.errors
    );
    assert!(result.fatal_error.is_none(), "{:?}", result.fatal_error);

    assert_eq!(result.created, 1, "beta still reconciles");
    assert_eq!(
        result
            .applied_incremental
            .iter()
            .map(|op| op.namespace.as_str())
            .collect::<Vec<_>>(),
        vec!["beta"],
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("x-ferrum-namespace: alpha")),
        "nothing may be written to the conflicting namespace"
    );

    // ...and the run is still a failure.
    assert!(result.into_result().is_err());
}

#[tokio::test]
async fn three_xx_batch_response_never_records_an_applied_operation() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("POST /batch".into(), 304, "{}".into(), vec![]),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("nonfatal namespace error is aggregated");

    assert_eq!(result.created, 0);
    assert!(result.applied_incremental.is_empty());
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(
        result
            .fatal_error
            .as_deref()
            .is_some_and(|error| error.contains("304")),
        "{:?}",
        result.fatal_error
    );
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("POST /batch"))
            .count(),
        1
    );
}

#[tokio::test]
async fn bare_restore_403_is_refined_to_a_run_stopping_read_only_error() {
    let read_only_health = r#"{"status":"ok","mode":"file","admin_writes_enabled":false}"#;
    let (url, requests) = spawn_recording_gateway(vec![
        (
            "POST /restore?confirm=true".into(),
            403,
            r#"{"error":"forbidden"}"#.into(),
            vec![],
        ),
        ("GET /health".into(), 200, read_only_health.into(), vec![]),
    ]);
    let client = stub_client(url);

    let error = client
        .post_restore(
            &GatewayConfig::default(),
            "team-a",
            &Default::default(),
            false,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(error, gitforgeops::error::Error::GatewayReadOnly(_)),
        "{error:?}"
    );
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("POST /restore"))
            .count(),
        1,
        "restore must not be replayed"
    );
}

#[tokio::test]
async fn a_read_only_plane_stops_the_run_but_keeps_earlier_namespaces_recorded() {
    // The whole point of F1/F2: namespace ferrum applied cleanly, team-b hit a
    // read-only admin plane. Returning Err here threw away ferrum's applied
    // ops, so cmd_apply persisted nothing and the next run re-derived those
    // resources as unmanaged. The ops survive; the error rides on the result.
    let url = spawn_stub_gateway(vec![
        ("GET /health", 200, HEALTHY),
        // Force the per-resource path so the read-only 403 comes from a
        // single-resource create, the way it does mid-namespace.
        ("POST /batch", 501, "{}"),
        (
            "x-ferrum-namespace: team-b",
            403,
            r#"{"error":"Admin API is in read-only mode"}"#,
        ),
        ("POST /upstreams", 201, "{}"),
    ]);
    let client = stub_client(url);

    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "ferrum"), upstream("u2", "team-b")],
        ..Default::default()
    };

    let result = apply_api(
        &desired,
        &client,
        &["ferrum".to_string(), "team-b".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum", "team-b"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a fatal stop is reported on the result, not as Err");

    assert_eq!(result.created, 1);
    assert_eq!(
        result
            .applied_incremental
            .iter()
            .map(|op| op.id.as_str())
            .collect::<Vec<_>>(),
        vec!["u1"],
        "the namespace that succeeded must still be recordable in state"
    );
    let fatal = result.fatal_error.clone().expect("read-only is fatal");
    assert!(fatal.contains("[team-b]"), "{fatal}");
    assert!(fatal.contains("read-only"), "{fatal}");

    // ...and it is still a failed run.
    assert!(result.into_result().is_err());
}

#[tokio::test]
async fn a_read_only_plane_at_the_first_namespace_stops_immediately() {
    // Nothing landed, but the run must still stop rather than collecting the
    // same 403 once per remaining namespace.
    let url = spawn_stub_gateway(vec![
        ("GET /health", 200, HEALTHY),
        ("POST /batch", 501, "{}"),
        (
            "POST /upstreams",
            403,
            r#"{"error":"Admin API is in read-only mode"}"#,
        ),
    ]);
    let client = stub_client(url);

    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "ferrum"), upstream("u2", "team-b")],
        ..Default::default()
    };

    let result = apply_api(
        &desired,
        &client,
        &["ferrum".to_string(), "team-b".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum", "team-b"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("reported on the result");

    assert_eq!(result.created, 0);
    let fatal = result.fatal_error.expect("read-only is fatal");
    assert!(fatal.contains("[ferrum]"), "stopped at the first: {fatal}");
}

#[tokio::test]
async fn a_read_only_preflight_fails_before_any_mutation() {
    // Unchanged behaviour: the up-front GET /health verdict is a hard Err,
    // because nothing has been applied and there is no partial state to save.
    let url = spawn_stub_gateway(vec![(
        "GET /health",
        200,
        r#"{"status":"degraded","mode":"database","admin_writes_enabled":false}"#,
    )]);
    let client = stub_client(url);

    let err = apply_api(
        &GatewayConfig::default(),
        &client,
        &["ferrum".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, gitforgeops::error::Error::GatewayReadOnly(_)));
}

// --- Shared-mode adoption of already-matching rows (issue #129) ---------------

use gitforgeops::apply::{adoption_candidates, adoption_summary_line, AdoptionCandidate};
use gitforgeops::config::schema::Consumer;
use gitforgeops::state::StateFile;
use std::collections::{BTreeSet, HashSet};

fn consumer(id: &str, namespace: &str) -> Consumer {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "username": id,
        "namespace": namespace,
    }))
    .expect("consumer fixture")
}

/// `apply_api` reads timestamps back through serde, so fixtures shared between
/// the desired document and the stubbed backup have to be byte-identical.
fn backup_body(config: &GatewayConfig) -> String {
    serde_json::to_string(config).expect("backup body")
}

fn ledger_of(ops: &[gitforgeops::apply::AppliedOp], desired: &GatewayConfig) -> StateFile {
    let mut state = StateFile::default();
    for op in ops {
        state.record_op(op, desired).expect("record adopted op");
    }
    state
}

fn candidate_ids(candidates: &[AdoptionCandidate]) -> Vec<String> {
    candidates
        .iter()
        .map(|c| format!("{} {}", c.kind, c.id))
        .collect()
}

#[tokio::test]
async fn already_matching_rows_are_adopted_and_a_later_removal_is_pruned() {
    // Issue #129's reproduction. Two consumers imported from the gateway match
    // it exactly, so the diff is empty and — before adoption — nothing ever
    // recorded ownership. The ledger stayed `{}`, `old` sat outside the
    // shared-mode delete fence, and removing it from the repo pruned nothing.
    let live = GatewayConfig {
        consumers: vec![
            consumer("old", "team-alpha"),
            consumer("keep", "team-alpha"),
        ],
        ..Default::default()
    };
    let desired = live.clone();

    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("GET /backup".into(), 200, backup_body(&live), vec![]),
    ]);
    let client = stub_client(url);
    let empty_fence: HashSet<String> = HashSet::new();

    let first = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Shared {
            previously_managed: &empty_fence,
        },
        Some(&BTreeMap::from([("team-alpha".to_string(), live.clone())])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("an all-matching apply is a clean run");

    assert_eq!(
        (first.created, first.updated, first.deleted),
        (0, 0, 0),
        "adoption changes no gateway configuration"
    );
    assert_eq!(first.adopted.len(), 2, "{:?}", first.adopted);
    assert!(first.adoption_skipped.is_empty(), "{first:?}");

    {
        let requests = requests.lock().expect("recorded requests");
        for id in ["old", "keep"] {
            assert_eq!(
                requests
                    .iter()
                    .filter(|r| r.contains(&format!("PUT /consumers/{id}")))
                    .count(),
                1,
                "each adopted row is claimed with exactly one idempotent PUT: {requests:?}"
            );
        }
        assert!(
            requests
                .iter()
                .all(|r| !r.contains("POST /consumers") && !r.contains("DELETE /consumers")),
            "adoption creates and deletes nothing: {requests:?}"
        );
    }

    // The ledger the next run reads.
    let state = ledger_of(&first.adopted, &desired);
    let managed = state.previously_managed_keys();
    assert_eq!(managed.len(), 2, "{managed:?}");
    assert!(managed.contains(&state_key("team-alpha", "Consumer", "old")));
    assert!(managed.contains(&state_key("team-alpha", "Consumer", "keep")));

    // Remove `old` from the repository. It is now inside the delete fence, so
    // the second apply prunes it — and the large-prune guard has a denominator
    // (the managed set) to measure the deletion against instead of the empty
    // set that made it a no-op.
    let desired_without_old = GatewayConfig {
        consumers: vec![consumer("keep", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("GET /backup".into(), 200, backup_body(&live), vec![]),
    ]);
    let client = stub_client(url);

    let second = apply_api(
        &desired_without_old,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Shared {
            previously_managed: &managed,
        },
        Some(&BTreeMap::from([("team-alpha".to_string(), live.clone())])),
        None,
        &ApplyOptions {
            managed_ledger: managed.iter().cloned().collect(),
            ..Default::default()
        },
    )
    .await
    .expect("the prune is an ordinary shared-mode delete");

    assert_eq!(second.deleted, 1);
    assert_eq!(second.unmanaged_skipped, 0);
    assert!(
        second.adopted.is_empty(),
        "`keep` is already in the ledger and must not be re-adopted: {:?}",
        second.adopted
    );
    let requests = requests.lock().expect("recorded requests");
    assert!(
        requests.iter().any(|r| r.contains("DELETE /consumers/old")),
        "{requests:?}"
    );
    assert!(
        requests.iter().all(|r| !r.contains("PUT /consumers/keep")),
        "a second run must not re-issue the ownership PUT: {requests:?}"
    );
}

#[tokio::test]
async fn a_row_that_changed_between_diff_and_assertion_is_skipped_and_reported() {
    // The adoption PUT overwrites the row. If an administrator edited it after
    // this run's diff, claiming ownership would silently revert their change,
    // so the confirmation read has to disagree loudly instead.
    let desired = GatewayConfig {
        consumers: vec![consumer("c1", "team-alpha")],
        ..Default::default()
    };
    let mut edited = consumer("c1", "team-alpha");
    edited.username = "edited-by-an-admin".to_string();
    let confirmation = GatewayConfig {
        consumers: vec![edited],
        ..Default::default()
    };

    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            backup_body(&confirmation),
            vec![],
        ),
    ]);
    let client = stub_client(url);
    let empty_fence: HashSet<String> = HashSet::new();

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Shared {
            previously_managed: &empty_fence,
        },
        // The diff ran against a view in which the row still matched.
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            desired.clone(),
        )])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a skipped adoption is not a failure");

    assert!(result.adopted.is_empty(), "{:?}", result.adopted);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert_eq!(result.adoption_skipped.len(), 1, "{result:?}");
    let message = &result.adoption_skipped[0];
    assert!(message.contains("Consumer `c1`"), "{message}");
    assert!(
        message.contains("changed between this run's diff and the ownership assertion"),
        "{message}"
    );
    let requests = requests.lock().expect("recorded requests");
    assert!(
        requests.iter().all(|r| !r.contains("PUT /consumers/c1")),
        "the admin's edit must not be overwritten: {requests:?}"
    );
}

#[test]
fn spec_owned_rows_are_never_adopted() {
    // The `/api-specs` importer owns these rows in both ownership modes.
    // Adopting one would put a resource the repo must never delete inside the
    // delete fence — and the live tag is the only thing that says so, since a
    // repository declaration may never carry `api_spec_id` at all.
    let desired = GatewayConfig {
        proxies: vec![proxy("p1", "team-alpha", None)],
        plugin_configs: vec![plugin_config("pc1", "team-alpha", "p1", None)],
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let mut spec_owned_upstream = upstream("u1", "team-alpha");
    spec_owned_upstream.api_spec_id = Some("spec-a".to_string());
    let actual = GatewayConfig {
        proxies: vec![proxy("p1", "team-alpha", Some("spec-a"))],
        plugin_configs: vec![plugin_config("pc1", "team-alpha", "p1", Some("spec-a"))],
        upstreams: vec![spec_owned_upstream],
        ..Default::default()
    };

    let candidates = adoption_candidates(&desired, &actual, &BTreeSet::new(), &BTreeSet::new());
    assert!(
        candidates.is_empty(),
        "no spec-owned row may be adopted: {:?}",
        candidate_ids(&candidates)
    );

    // Control: the identical rows without the ownership tag are adoptable, so
    // the exclusion above is the tag and not an unrelated mismatch.
    let untagged = GatewayConfig {
        proxies: vec![proxy("p1", "team-alpha", None)],
        plugin_configs: vec![plugin_config("pc1", "team-alpha", "p1", None)],
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let candidates = adoption_candidates(&desired, &untagged, &BTreeSet::new(), &BTreeSet::new());
    assert_eq!(
        candidate_ids(&candidates),
        vec!["Upstream u1", "Proxy p1", "PluginConfig pc1"]
    );
}

#[test]
fn adoption_skips_ledger_entries_and_rows_an_operation_already_covers() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha"), upstream("u2", "team-alpha")],
        consumers: vec![consumer("c1", "team-alpha")],
        ..Default::default()
    };
    let actual = desired.clone();

    let managed = BTreeSet::from([state_key("team-alpha", "Upstream", "u1")]);
    let handled = BTreeSet::from([state_key("team-alpha", "Consumer", "c1")]);
    let candidates = adoption_candidates(&desired, &actual, &managed, &handled);
    assert_eq!(candidate_ids(&candidates), vec!["Upstream u2"]);
}

#[test]
fn a_row_absent_or_different_live_is_not_an_adoption_candidate() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha"), upstream("u2", "team-alpha")],
        ..Default::default()
    };
    let mut different = upstream("u1", "team-alpha");
    different.targets.clear();
    let actual = GatewayConfig {
        upstreams: vec![different],
        ..Default::default()
    };

    // `u1` differs (ordinary Modify), `u2` is absent (ordinary Add).
    let candidates = adoption_candidates(&desired, &actual, &BTreeSet::new(), &BTreeSet::new());
    assert!(candidates.is_empty(), "{:?}", candidate_ids(&candidates));
}

#[tokio::test]
async fn a_cached_backup_blocks_adoption() {
    // A cached backup clears `api_spec_id` tags, so it cannot prove a row is
    // not spec-owned — the same reason it blocks every other mutation.
    let desired = GatewayConfig {
        consumers: vec![consumer("c1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            backup_body(&desired),
            vec![("X-Data-Source".into(), "cached".into())],
        ),
    ]);
    let client = stub_client(url);
    let empty_fence: HashSet<String> = HashSet::new();

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Shared {
            previously_managed: &empty_fence,
        },
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            desired.clone(),
        )])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("the run itself is clean; only the claim is withheld");

    assert!(result.adopted.is_empty(), "{:?}", result.adopted);
    assert_eq!(result.adoption_skipped.len(), 1, "{result:?}");
    let message = &result.adoption_skipped[0];
    assert!(message.contains("X-Data-Source: cached"), "{message}");
    let requests = requests.lock().expect("recorded requests");
    assert!(
        requests
            .iter()
            .all(|r| !r.contains("PUT ") && !r.contains("POST ") && !r.contains("DELETE ")),
        "nothing may be claimed from a cached view: {requests:?}"
    );
}

#[tokio::test]
async fn exclusive_mode_records_adoption_without_a_put() {
    // Exclusive ownership is already authoritative for the namespace, so there
    // is nothing to assert. The ledger entry is still written, so the fence is
    // correct if the environment is later switched to `shared`.
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) =
        spawn_recording_gateway(vec![("GET /health".into(), 200, HEALTHY.into(), vec![])]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            desired.clone(),
        )])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("exclusive adoption never touches the gateway");

    assert_eq!(result.adopted.len(), 1);
    assert_eq!(result.adopted[0].id, "u1");
    assert!(result.adoption_skipped.is_empty(), "{result:?}");
    let requests = requests.lock().expect("recorded requests");
    assert!(
        requests.iter().all(|r| r.contains("GET /health")),
        "exclusive adoption issues no confirmation read and no PUT: {requests:?}"
    );
}

#[tokio::test]
async fn a_failed_adoption_put_is_reported_and_not_recorded() {
    // Ownership is recorded only after the gateway acknowledges the claim.
    // Silently continuing would leave the row outside the fence with nothing
    // on screen saying so — which is exactly the failure mode being fixed.
    let desired = GatewayConfig {
        consumers: vec![consumer("c1", "team-alpha")],
        ..Default::default()
    };
    let (url, _requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("GET /backup".into(), 200, backup_body(&desired), vec![]),
        (
            "PUT /consumers/c1".into(),
            500,
            r#"{"error":"boom"}"#.into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);
    let empty_fence: HashSet<String> = HashSet::new();

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Shared {
            previously_managed: &empty_fence,
        },
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            desired.clone(),
        )])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a failed claim is an ordinary per-resource failure");

    assert!(result.adopted.is_empty(), "{:?}", result.adopted);
    assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    assert!(
        result.errors[0].contains("Consumer c1 adopt"),
        "{:?}",
        result.errors
    );
    assert!(
        result.into_result().is_err(),
        "an unclaimed row must not report a clean apply"
    );
}

#[test]
fn adoption_summary_line_is_silent_when_nothing_was_adopted() {
    assert_eq!(adoption_summary_line(0), None);
    assert_eq!(
        adoption_summary_line(3).as_deref(),
        Some("Adopted 3 already-matching resource(s) into the ledger")
    );
}
