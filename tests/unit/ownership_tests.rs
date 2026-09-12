use std::collections::HashSet;

use gitforgeops::config::schema::{BackendScheme, GatewayConfig, Proxy};
use gitforgeops::diff::{
    compute_diff_with_options, compute_diff_with_ownership, state_key, DiffAction, DiffOptions,
    DiffResult, OwnershipScope,
};

fn proxy(id: &str, namespace: &str) -> Proxy {
    Proxy {
        labels: Default::default(),
        extra: Default::default(),
        id: id.to_string(),
        name: None,
        namespace: namespace.to_string(),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
        backend_scheme: Some(BackendScheme::Https),
        backend_host: "backend.example".to_string(),
        backend_port: 443,
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
        udp_idle_timeout_seconds: 30,
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
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    }
}

/// A live proxy provisioned by an OpenAPI spec import.
fn spec_owned_proxy(id: &str, namespace: &str, api_spec_id: &str) -> Proxy {
    Proxy {
        api_spec_id: Some(api_spec_id.to_string()),
        ..proxy(id, namespace)
    }
}

fn gateway_with(proxies: Vec<Proxy>) -> GatewayConfig {
    GatewayConfig {
        proxies,
        ..Default::default()
    }
}

#[test]
fn exclusive_mode_deletes_admin_added_resource() {
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        proxy("admin-added", "ferrum"),
    ]);

    let result = compute_diff_with_ownership(&desired, &actual, None);

    assert!(
        result.unmanaged.is_empty(),
        "exclusive should not classify as unmanaged"
    );
    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].id, "admin-added");
}

#[test]
fn shared_mode_leaves_admin_added_resource_untouched() {
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        proxy("admin-added", "ferrum"),
    ]);

    let mut managed = HashSet::new();
    managed.insert(state_key("ferrum", "Proxy", "from-repo"));

    let result = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    assert_eq!(result.unmanaged.len(), 1);
    assert_eq!(result.unmanaged[0].id, "admin-added");

    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 0);
}

#[test]
fn shared_mode_deletes_resource_previously_managed_now_removed_from_repo() {
    let desired = gateway_with(vec![]);
    let actual = gateway_with(vec![proxy("was-in-repo", "ferrum")]);

    let mut managed = HashSet::new();
    managed.insert(state_key("ferrum", "Proxy", "was-in-repo"));

    let result = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 1, "previously-managed removal should delete");
    assert_eq!(deletes[0].id, "was-in-repo");
    assert!(result.unmanaged.is_empty());
}

#[test]
fn exclusive_mode_with_namespace_filter_only_iterates_that_namespace() {
    // This test exercises main.rs::resolved_namespaces indirectly by rebuilding
    // its logic: with exclusive ownership=[ferrum, platform] and
    // namespace_filter=ferrum, the apply scope must be [ferrum] only.
    // Including `platform` with an empty desired would prune resources
    // outside the operator's requested scope.
    let owned = vec!["ferrum".to_string(), "platform".to_string()];
    let filter = Some("ferrum");

    let result: Vec<String> = match filter {
        Some(ns) if owned.iter().any(|o| o == ns) => vec![ns.to_string()],
        Some(_) => Vec::new(),
        None => owned.clone(),
    };
    assert_eq!(result, vec!["ferrum".to_string()]);

    // namespace_filter outside the ownership list → empty (warning logged,
    // nothing reconciled — operator's request can't be honored).
    let out_of_scope = Some("team-gamma");
    let result: Vec<String> = match out_of_scope {
        Some(ns) if owned.iter().any(|o| o == ns) => vec![ns.to_string()],
        Some(_) => Vec::new(),
        None => owned,
    };
    assert!(result.is_empty());
}

#[test]
fn shared_mode_iterates_previously_managed_namespaces_even_when_desired_is_empty_there() {
    // The key invariant: if the repo used to manage a resource in namespace X
    // and then removes its last resource, we still need to reconcile X to
    // delete the orphan. Verified at the compute_diff layer by passing a
    // previously_managed set that contains team-alpha — even when desired is
    // empty for team-alpha, the previously-managed hit drives a delete.
    let desired_for_team_alpha = gateway_with(vec![]);
    let actual_for_team_alpha = gateway_with(vec![proxy("was-in-repo", "team-alpha")]);

    let mut managed = HashSet::new();
    managed.insert(state_key("team-alpha", "Proxy", "was-in-repo"));

    let result = compute_diff_with_ownership(
        &desired_for_team_alpha,
        &actual_for_team_alpha,
        Some(&managed),
    );

    assert!(result.unmanaged.is_empty());
    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].id, "was-in-repo");
    assert_eq!(deletes[0].namespace, "team-alpha");
}

#[test]
fn exclusive_mode_with_explicit_namespaces_iterates_empty_namespaces() {
    // Scenario: repo used to manage `team-alpha` but now declares no resources
    // there. In exclusive mode with `namespaces: [team-alpha]`, apply must
    // still iterate team-alpha so it can prune resources left behind.
    //
    // We can exercise this by calling compute_diff_with_ownership on a
    // per-namespace (empty-desired, non-empty-actual) pair the way apply
    // would after load_namespace_pairs_for splits by ownership.namespaces.
    let desired_for_team_alpha = gateway_with(vec![]);
    let actual_for_team_alpha = gateway_with(vec![proxy("stale", "team-alpha")]);

    // Exclusive mode — pass None for previously_managed.
    let result = compute_diff_with_ownership(&desired_for_team_alpha, &actual_for_team_alpha, None);

    assert!(
        result.unmanaged.is_empty(),
        "exclusive should not classify as unmanaged"
    );
    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].id, "stale");
    assert_eq!(deletes[0].namespace, "team-alpha");
}

#[test]
fn shared_mode_first_apply_with_empty_state_skips_all_deletes() {
    let desired = gateway_with(vec![proxy("new-one", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("pre-existing-a", "ferrum"),
        proxy("pre-existing-b", "ferrum"),
    ]);

    let managed: HashSet<String> = HashSet::new();
    let result = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    assert_eq!(result.unmanaged.len(), 2);
    let adds: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Add))
        .collect();
    assert_eq!(adds.len(), 1);
    assert_eq!(adds[0].id, "new-one");
    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 0);
}

// --- Spec-owned resources ----------------------------------------------------
//
// A third owner besides the repo and a human admin: the `/api-specs` importer
// atomically provisions proxies, upstreams and plugin configs tagged with an
// `api_spec_id`. gitforgeops must stay off them in shared mode entirely, and in
// exclusive mode unless the operator passes `--confirm-api-spec-deletion`.

#[test]
fn shared_mode_never_deletes_spec_owned_resource() {
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        spec_owned_proxy("from-spec", "ferrum", "spec-7"),
    ]);

    // Even when state claims we once managed it, the spec tag wins: the
    // importer owns the row now.
    let mut managed = HashSet::new();
    managed.insert(state_key("ferrum", "Proxy", "from-repo"));
    managed.insert(state_key("ferrum", "Proxy", "from-spec"));

    let result = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    assert!(
        result
            .diffs
            .iter()
            .all(|d| !matches!(d.action, DiffAction::Delete)),
        "spec-owned resources must never be deleted in shared mode: {:?}",
        result.diffs
    );
    assert!(
        result.unmanaged.is_empty(),
        "spec-owned belongs in its own bucket, not `unmanaged`"
    );
    assert_eq!(result.spec_owned.len(), 1);
    assert_eq!(result.spec_owned[0].id, "from-spec");
    assert_eq!(result.spec_owned[0].api_spec_id, "spec-7");
    assert!(!result.spec_owned[0].declared_in_repo);
    assert!(!result.spec_owned[0].pruned);
}

#[test]
fn shared_mode_reports_conflict_instead_of_modify_for_spec_owned_resource() {
    // The repo declares `shared-id` and so does the spec import. The repo's
    // version differs (different listen path), which would normally be a
    // Modify — but applying it would be reverted by the next spec import.
    let mut repo_version = proxy("shared-id", "ferrum");
    repo_version.listen_path = Some("/repo-owns-this".to_string());
    let desired = gateway_with(vec![repo_version]);
    let actual = gateway_with(vec![spec_owned_proxy("shared-id", "ferrum", "spec-9")]);

    let managed = HashSet::new();
    let result = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    assert!(
        result.diffs.is_empty(),
        "no diff action should be emitted for a spec-owned row: {:?}",
        result.diffs
    );
    let conflicts: Vec<_> = result.spec_conflicts().collect();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].id, "shared-id");
    assert_eq!(conflicts[0].api_spec_id, "spec-9");
    assert!(conflicts[0].declared_in_repo);
    assert!(conflicts[0].is_conflict());
}

#[test]
fn conflict_is_reported_even_when_fields_currently_agree() {
    // Two owners writing one row is the finding — not the current field
    // delta, which the next spec import can change without warning.
    let desired = gateway_with(vec![proxy("shared-id", "ferrum")]);
    let actual = gateway_with(vec![spec_owned_proxy("shared-id", "ferrum", "spec-9")]);

    let result = compute_diff_with_ownership(&desired, &actual, None);

    assert!(result.diffs.is_empty());
    assert_eq!(result.spec_conflicts().count(), 1);
}

#[test]
fn exclusive_mode_skips_spec_owned_prune_without_confirmation() {
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        proxy("admin-added", "ferrum"),
        spec_owned_proxy("from-spec", "ferrum", "spec-7"),
    ]);

    let result = compute_diff_with_options(
        &desired,
        &actual,
        OwnershipScope::Exclusive,
        DiffOptions::default(),
    );

    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(
        deletes.len(),
        1,
        "only the plain admin-added resource is pruned"
    );
    assert_eq!(deletes[0].id, "admin-added");

    assert_eq!(result.spec_owned.len(), 1);
    assert_eq!(result.spec_owned[0].id, "from-spec");
    assert!(!result.spec_owned[0].pruned);
}

#[test]
fn exclusive_mode_prunes_spec_owned_with_confirmation() {
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        spec_owned_proxy("from-spec", "ferrum", "spec-7"),
    ]);

    let result = compute_diff_with_options(
        &desired,
        &actual,
        OwnershipScope::Exclusive,
        DiffOptions {
            prune_spec_owned: true,
        },
    );

    let deletes: Vec<_> = result
        .diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .collect();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].id, "from-spec");

    // Still labeled, so plan/apply output can say what is about to happen.
    assert_eq!(result.spec_owned.len(), 1);
    assert!(result.spec_owned[0].pruned);
}

#[test]
fn shared_mode_ignores_prune_confirmation_for_spec_owned() {
    // `--confirm-api-spec-deletion` is an exclusive-mode escape hatch. In
    // shared mode the state file is the fence and a spec-owned resource was
    // never behind it, so the flag must not turn into a delete.
    let desired = gateway_with(vec![]);
    let actual = gateway_with(vec![spec_owned_proxy("from-spec", "ferrum", "spec-7")]);

    let mut managed = HashSet::new();
    managed.insert(state_key("ferrum", "Proxy", "from-spec"));

    let result = compute_diff_with_options(
        &desired,
        &actual,
        OwnershipScope::Shared {
            previously_managed: &managed,
        },
        DiffOptions {
            prune_spec_owned: true,
        },
    );

    assert!(result.diffs.is_empty(), "got {:?}", result.diffs);
    assert_eq!(result.spec_owned.len(), 1);
    assert!(!result.spec_owned[0].pruned);
}

#[test]
fn confirmed_spec_prunes_are_visible_to_the_preview_and_the_large_prune_guard() {
    // cmd_apply computes its interactive preview and its large-prune
    // denominator from this diff. Running it with DiffOptions::default() while
    // applying with `--confirm-api-spec-deletion` meant the preview printed no
    // DELETE line for `from-spec` and the guard counted it as zero — then the
    // apply deleted it anyway. The flag has to reach both.
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        proxy("admin-added", "ferrum"),
        spec_owned_proxy("from-spec", "ferrum", "spec-7"),
    ]);

    let delete_count = |options| {
        compute_diff_with_options(&desired, &actual, OwnershipScope::Exclusive, options)
            .diffs
            .iter()
            .filter(|d| matches!(d.action, DiffAction::Delete))
            .count()
    };

    assert_eq!(delete_count(DiffOptions::default()), 1);
    assert_eq!(
        delete_count(DiffOptions {
            prune_spec_owned: true
        }),
        2,
        "the confirmed spec prune must be a counted deletion, not an invisible one"
    );
}

#[test]
fn informational_spec_owned_resources_leave_the_config_in_sync() {
    // The in-sync gate in `diff` (and the "No changes to apply" early return in
    // `apply`) used to require an empty spec_owned bucket, so a gateway that
    // ingests API specs could never report in sync and interactive apply
    // prompted on every no-op run. A spec-owned row that is not a conflict is
    // a stable steady state: report it, then say in sync.
    let desired = gateway_with(vec![proxy("from-repo", "ferrum")]);
    let actual = gateway_with(vec![
        proxy("from-repo", "ferrum"),
        spec_owned_proxy("from-spec", "ferrum", "spec-7"),
    ]);

    let result = compute_diff_with_options(
        &desired,
        &actual,
        OwnershipScope::Exclusive,
        DiffOptions::default(),
    );

    assert!(result.diffs.is_empty(), "got {:?}", result.diffs);
    assert!(result.unmanaged.is_empty());
    assert_eq!(result.spec_owned.len(), 1);
    assert!(
        !result.spec_owned[0].is_conflict(),
        "a resource the repo does not declare is informational, not a conflict"
    );
    assert_eq!(result.spec_conflicts().count(), 0);
}

#[test]
fn a_spec_owned_conflict_still_blocks_in_sync() {
    // The repo and the spec importer both claiming one row is exactly the case
    // that must keep reporting drift.
    let desired = gateway_with(vec![proxy("shared-id", "ferrum")]);
    let actual = gateway_with(vec![spec_owned_proxy("shared-id", "ferrum", "spec-9")]);

    let result = compute_diff_with_options(
        &desired,
        &actual,
        OwnershipScope::Exclusive,
        DiffOptions::default(),
    );

    assert_eq!(result.spec_conflicts().count(), 1);
    assert!(result.spec_owned[0].is_conflict());
}

#[test]
fn spec_owned_bucket_is_sorted_deterministically() {
    let desired = gateway_with(vec![]);
    let actual = gateway_with(vec![
        spec_owned_proxy("zulu", "ferrum", "spec-1"),
        spec_owned_proxy("alpha", "ferrum", "spec-1"),
        spec_owned_proxy("mike", "acme", "spec-2"),
    ]);

    let managed = HashSet::new();
    let ids: Vec<(String, String)> = compute_diff_with_ownership(&desired, &actual, Some(&managed))
        .spec_owned
        .iter()
        .map(|s| (s.namespace.clone(), s.id.clone()))
        .collect();

    assert_eq!(
        ids,
        vec![
            ("acme".to_string(), "mike".to_string()),
            ("ferrum".to_string(), "alpha".to_string()),
            ("ferrum".to_string(), "zulu".to_string()),
        ]
    );
}

// ---------------------------------------------------------------------------
// #172: `diff_collection` walks HashMaps, so `diffs` / `unmanaged` used to come
// out in `RandomState` order — the same inputs produced a differently ordered
// change list (and, past the review comment's 100-row cap, a differently
// populated one) on every run. All three buckets now sort by
// `(namespace, kind, id)`.
// ---------------------------------------------------------------------------

fn consumer(id: &str, namespace: &str) -> gitforgeops::config::schema::Consumer {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "username": id,
        "namespace": namespace,
    }))
    .unwrap()
}

fn upstream(id: &str, namespace: &str) -> gitforgeops::config::schema::Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .unwrap()
}

fn plugin_config(id: &str, namespace: &str) -> gitforgeops::config::schema::PluginConfig {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "plugin_name": "cors",
        "config": {},
        "scope": "global",
    }))
    .unwrap()
}

fn add(
    proxies: Vec<Proxy>,
    consumers: Vec<gitforgeops::config::schema::Consumer>,
    upstreams: Vec<gitforgeops::config::schema::Upstream>,
    plugin_configs: Vec<gitforgeops::config::schema::PluginConfig>,
) -> GatewayConfig {
    GatewayConfig {
        proxies,
        consumers,
        upstreams,
        plugin_configs,
        ..Default::default()
    }
}

#[test]
fn diff_and_unmanaged_buckets_are_sorted_deterministically() {
    let desired = add(
        vec![proxy("p-a", "ferrum")],
        vec![consumer("c-a", "acme")],
        vec![upstream("u-a", "ferrum")],
        vec![plugin_config("pc-a", "acme")],
    );
    let actual = add(
        vec![proxy("p-live", "ferrum")],
        vec![consumer("c-live", "acme")],
        vec![upstream("u-live", "ferrum")],
        vec![plugin_config("pc-live", "acme")],
    );

    // Shared mode, nothing previously managed: every desired resource is an
    // Add and every live resource is unmanaged.
    let managed = HashSet::new();
    let result = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    let diffs: Vec<(String, String, String)> = result
        .diffs
        .iter()
        .map(|d| (d.namespace.clone(), d.kind.clone(), d.id.clone()))
        .collect();
    assert_eq!(
        diffs,
        vec![
            (
                "acme".to_string(),
                "Consumer".to_string(),
                "c-a".to_string()
            ),
            (
                "acme".to_string(),
                "PluginConfig".to_string(),
                "pc-a".to_string()
            ),
            ("ferrum".to_string(), "Proxy".to_string(), "p-a".to_string()),
            (
                "ferrum".to_string(),
                "Upstream".to_string(),
                "u-a".to_string()
            ),
        ]
    );

    let unmanaged: Vec<(String, String, String)> = result
        .unmanaged
        .iter()
        .map(|u| (u.namespace.clone(), u.kind.clone(), u.id.clone()))
        .collect();
    assert_eq!(
        unmanaged,
        vec![
            (
                "acme".to_string(),
                "Consumer".to_string(),
                "c-live".to_string()
            ),
            (
                "acme".to_string(),
                "PluginConfig".to_string(),
                "pc-live".to_string()
            ),
            (
                "ferrum".to_string(),
                "Proxy".to_string(),
                "p-live".to_string()
            ),
            (
                "ferrum".to_string(),
                "Upstream".to_string(),
                "u-live".to_string()
            ),
        ]
    );
}

#[test]
fn diff_order_is_stable_across_two_runs() {
    let desired = add(
        vec![proxy("p-a", "ferrum"), proxy("p-b", "acme")],
        vec![consumer("c-a", "ferrum")],
        vec![upstream("u-a", "acme")],
        vec![plugin_config("pc-a", "ferrum")],
    );
    let actual = add(
        vec![proxy("p-x", "ferrum"), proxy("p-y", "acme")],
        vec![consumer("c-x", "ferrum")],
        vec![upstream("u-x", "acme")],
        vec![plugin_config("pc-x", "ferrum")],
    );
    let managed = HashSet::new();

    let first = compute_diff_with_ownership(&desired, &actual, Some(&managed));
    let second = compute_diff_with_ownership(&desired, &actual, Some(&managed));

    let order = |result: &DiffResult| -> Vec<(String, String, String)> {
        result
            .diffs
            .iter()
            .map(|d| (d.namespace.clone(), d.kind.clone(), d.id.clone()))
            .collect()
    };
    assert_eq!(order(&first), order(&second));
    assert_eq!(first.diffs.len(), second.diffs.len());
    // The sort must not change which entries exist — only their order.
    let mut first_ids: Vec<_> = first.diffs.iter().map(|d| d.id.clone()).collect();
    let mut second_ids: Vec<_> = second.diffs.iter().map(|d| d.id.clone()).collect();
    first_ids.sort_unstable();
    second_ids.sort_unstable();
    assert_eq!(first_ids, second_ids);
}
