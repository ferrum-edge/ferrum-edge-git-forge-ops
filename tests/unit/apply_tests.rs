use gitforgeops::apply::{apply_file, ApplyResult};
use gitforgeops::config::schema::{GatewayConfig, Proxy};

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

use gitforgeops::apply::{operation_rank, order_diffs, stale_view_block};
use gitforgeops::diff::resource_diff::{DiffAction, ResourceDiff};

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
fn stale_view_blocks_prunes_from_a_cached_backup() {
    // During a config-database outage /backup falls back to the in-memory
    // snapshot; resources created since then read as "should be deleted".
    let block = stale_view_block(true, 3, false).expect("should block");
    assert!(block.contains("X-Data-Source: cached"), "{block}");
    assert!(block.contains("3 computed deletion"), "{block}");
    assert!(block.contains("--allow-large-prune"), "{block}");
}

#[test]
fn stale_view_allows_a_pure_write_apply() {
    // No deletes means nothing can be wrongly pruned, so a cached view is
    // merely a warning.
    assert!(stale_view_block(true, 0, false).is_none());
}

#[test]
fn stale_view_is_overridable_and_inert_on_a_fresh_view() {
    assert!(stale_view_block(true, 5, true).is_none());
    assert!(stale_view_block(false, 5, false).is_none());
}
