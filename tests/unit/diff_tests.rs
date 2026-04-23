use gitforgeops::config::schema::*;
use gitforgeops::diff::{
    best_practice::check_best_practices, breaking::detect_breaking_changes,
    resource_diff::compute_diff, resource_diff::DiffAction, security::audit_security,
};

fn make_proxy(id: &str, listen_path: &str, host: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: None,
        namespace: "ferrum".to_string(),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_protocol: BackendProtocol::Http,
        backend_host: host.to_string(),
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
        auth_mode: AuthMode::default(),
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
        response_body_mode: ResponseBodyMode::default(),
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
    }
}

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.to_string(),
        username: username.to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: std::collections::HashMap::new(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_upstream(id: &str, target_count: usize) -> Upstream {
    let targets: Vec<UpstreamTarget> = (0..target_count)
        .map(|i| UpstreamTarget {
            host: format!("host-{i}.internal"),
            port: 8080,
            weight: 1,
            tags: std::collections::HashMap::new(),
            path: None,
        })
        .collect();
    Upstream {
        id: id.to_string(),
        name: None,
        namespace: "ferrum".to_string(),
        targets,
        algorithm: LoadBalancerAlgorithm::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn diff_detects_added_proxy() {
    let desired = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "localhost")],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig::default();

    let diffs = compute_diff(&desired, &actual);
    assert_eq!(diffs.len(), 1);
    assert!(matches!(diffs[0].action, DiffAction::Add));
    assert_eq!(diffs[0].id, "p1");
}

#[test]
fn diff_detects_deleted_proxy() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "localhost")],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual);
    assert_eq!(diffs.len(), 1);
    assert!(matches!(diffs[0].action, DiffAction::Delete));
}

#[test]
fn diff_detects_modified_proxy() {
    let desired = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "new-host")],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "old-host")],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual);
    assert_eq!(diffs.len(), 1);
    assert!(matches!(diffs[0].action, DiffAction::Modify));
}

#[test]
fn diff_identical_configs_empty() {
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "localhost")],
        ..GatewayConfig::default()
    };
    let diffs = compute_diff(&config, &config);
    assert!(diffs.is_empty());
}

#[test]
fn breaking_detects_deleted_proxy() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "localhost")],
        ..GatewayConfig::default()
    };
    let diffs = compute_diff(&desired, &actual);
    let breaking = detect_breaking_changes(&diffs, &desired, &actual);
    assert!(!breaking.is_empty());
    assert!(breaking[0].reason.to_lowercase().contains("delet"));
}

#[test]
fn breaking_detects_listen_path_change() {
    let desired = GatewayConfig {
        proxies: vec![make_proxy("p1", "/new-path", "localhost")],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        proxies: vec![make_proxy("p1", "/old-path", "localhost")],
        ..GatewayConfig::default()
    };
    let diffs = compute_diff(&desired, &actual);
    let breaking = detect_breaking_changes(&diffs, &desired, &actual);
    assert!(!breaking.is_empty());
    assert!(breaking[0].reason.to_lowercase().contains("listen_path"));
}

#[test]
fn security_detects_literal_credential() {
    let mut creds = std::collections::HashMap::new();
    creds.insert(
        "keyauth".to_string(),
        serde_json::json!({"key": "literal-secret-key"}),
    );
    let config = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds,
            ..make_consumer("c1", "alice")
        }],
        ..GatewayConfig::default()
    };
    let findings = audit_security(&config);
    assert!(!findings.is_empty());
    assert!(findings[0].message.to_lowercase().contains("credential"));
}

#[test]
fn security_passes_template_credential() {
    let mut creds = std::collections::HashMap::new();
    creds.insert(
        "keyauth".to_string(),
        serde_json::json!({"key": "${API_KEY}"}),
    );
    let config = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds,
            ..make_consumer("c1", "alice")
        }],
        ..GatewayConfig::default()
    };
    let findings = audit_security(&config);
    let cred_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.message.to_lowercase().contains("credential"))
        .collect();
    assert!(cred_findings.is_empty());
}

#[test]
fn security_detects_tls_verify_disabled() {
    let mut proxy = make_proxy("p1", "/api", "localhost");
    proxy.backend_tls_verify_server_cert = false;
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    let findings = audit_security(&config);
    assert!(!findings.is_empty());
    assert!(findings
        .iter()
        .any(|f| f.message.to_lowercase().contains("tls")));
}

#[test]
fn best_practice_flags_single_target_upstream() {
    let config = GatewayConfig {
        upstreams: vec![make_upstream("u1", 1)],
        ..GatewayConfig::default()
    };
    let checks = check_best_practices(&config);
    assert!(checks.iter().any(|c| c.message.contains("target")));
}

#[test]
fn best_practice_flags_no_health_checks() {
    let config = GatewayConfig {
        upstreams: vec![make_upstream("u1", 2)],
        ..GatewayConfig::default()
    };
    let checks = check_best_practices(&config);
    assert!(checks.iter().any(|c| c.message.contains("health")));
}

#[test]
fn best_practice_flags_high_timeout() {
    let mut proxy = make_proxy("p1", "/api", "localhost");
    proxy.backend_read_timeout_ms = 120000;
    let config = GatewayConfig {
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };
    let checks = check_best_practices(&config);
    assert!(checks.iter().any(|c| c.message.contains("timeout")));
}
