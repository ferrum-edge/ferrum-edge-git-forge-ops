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
            backend_protocol: gitforgeops::config::schema::BackendProtocol::Http,
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
