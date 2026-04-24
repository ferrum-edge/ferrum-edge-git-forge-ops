use std::collections::HashSet;

use gitforgeops::config::schema::{BackendProtocol, GatewayConfig, Proxy};
use gitforgeops::diff::{compute_diff_with_ownership, state_key, DiffAction};

fn proxy(id: &str, namespace: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: None,
        namespace: namespace.to_string(),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
        backend_protocol: BackendProtocol::Https,
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
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
