use gitforgeops::config::schema::*;
use gitforgeops::diff::{
    best_practice::check_best_practices, breaking::detect_breaking_changes,
    resource_diff::compute_diff, resource_diff::compute_diff_with_scope, resource_diff::state_key,
    resource_diff::DiffAction, resource_diff::OwnershipScope, security::audit_security,
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

fn make_plugin_config(
    id: &str,
    namespace: &str,
    plugin_name: &str,
    scope: PluginScope,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config: serde_json::json!({}),
        scope,
        proxy_id: None,
        enabled: true,
        priority_override: None,
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
fn diff_treats_same_id_in_different_namespaces_as_distinct() {
    let mut desired_proxy = make_proxy("shared-id", "/api", "localhost");
    desired_proxy.namespace = "team-alpha".to_string();

    let mut actual_proxy = make_proxy("shared-id", "/api", "localhost");
    actual_proxy.namespace = "ferrum".to_string();

    let desired = GatewayConfig {
        proxies: vec![desired_proxy],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        proxies: vec![actual_proxy],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual);
    assert_eq!(diffs.len(), 2);
    assert!(diffs
        .iter()
        .any(|diff| matches!(diff.action, DiffAction::Add) && diff.namespace == "team-alpha"));
    assert!(diffs
        .iter()
        .any(|diff| matches!(diff.action, DiffAction::Delete) && diff.namespace == "ferrum"));
}

#[test]
fn shared_diff_honors_managed_state_keys() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        proxies: vec![make_proxy("managed", "/api", "localhost")],
        ..GatewayConfig::default()
    };
    let mut previously_managed = std::collections::HashSet::new();
    previously_managed.insert(state_key("ferrum", "Proxy", "managed"));

    let result = compute_diff_with_scope(
        &desired,
        &actual,
        OwnershipScope::Shared {
            previously_managed: &previously_managed,
        },
    );

    assert_eq!(result.diffs.len(), 1);
    assert!(matches!(result.diffs[0].action, DiffAction::Delete));
    assert!(result.unmanaged.is_empty());
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
fn breaking_auth_plugin_deletion_scoped_by_namespace() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        plugin_configs: vec![
            make_plugin_config("plugin-shared", "team-alpha", "keyauth", PluginScope::Proxy),
            make_plugin_config(
                "plugin-shared",
                "team-beta",
                "rate_limiting",
                PluginScope::Proxy,
            ),
        ],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual);
    let breaking = detect_breaking_changes(&diffs, &desired, &actual);

    // Only the team-alpha deletion should be flagged as breaking — the
    // team-beta plugin with the same id is rate_limiting, not auth.
    let auth_breaking: Vec<_> = breaking
        .iter()
        .filter(|bc| bc.kind == "PluginConfig" && bc.reason.contains("Auth"))
        .collect();
    assert_eq!(
        auth_breaking.len(),
        1,
        "expected exactly one auth-plugin breaking change, got {breaking:?}"
    );
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
fn security_detects_nested_literal_credential() {
    let mut creds = std::collections::HashMap::new();
    creds.insert(
        "keyauth".to_string(),
        serde_json::json!({"outer": {"inner": "literal-secret-key"}}),
    );
    let config = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds,
            ..make_consumer("c1", "alice")
        }],
        ..GatewayConfig::default()
    };

    let findings = audit_security(&config);
    assert!(findings
        .iter()
        .any(|f| f.message.contains("keyauth.outer.inner")));
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
fn security_audit_must_run_pre_resolve_or_flags_resolved_values_as_literals() {
    // Regression guard: audit_security classifies any string that doesn't
    // start with `${` as a literal credential. If the caller (cmd_plan,
    // cmd_review) runs audit AFTER resolve_secrets, legitimate placeholders
    // have been replaced with real values and the auditor spuriously flags
    // them as literal credentials — drowning real findings in noise.
    //
    // This test verifies the invariant by simulating both orderings.

    // Pre-resolve: placeholder in the config. Audit sees a ${...} string.
    let mut creds_pre = std::collections::HashMap::new();
    creds_pre.insert(
        "keyauth".to_string(),
        serde_json::json!({"key": "${gh-env-secret:alloc=require}"}),
    );
    let config_pre = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds_pre,
            ..make_consumer("c1", "alice")
        }],
        ..GatewayConfig::default()
    };
    let findings_pre = audit_security(&config_pre);
    let literal_pre: Vec<_> = findings_pre
        .iter()
        .filter(|f| f.message.contains("Literal credential"))
        .collect();
    assert!(
        literal_pre.is_empty(),
        "pre-resolve: placeholder must not be flagged as literal"
    );

    // Post-resolve (simulated): the placeholder has been replaced with a real
    // value. Audit now incorrectly sees a "literal" credential. This is the
    // behavior we want to AVOID by auditing before resolve.
    let mut creds_post = std::collections::HashMap::new();
    creds_post.insert(
        "keyauth".to_string(),
        serde_json::json!({"key": "real-random-value"}),
    );
    let config_post = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds_post,
            ..make_consumer("c1", "alice")
        }],
        ..GatewayConfig::default()
    };
    let findings_post = audit_security(&config_post);
    let literal_post: Vec<_> = findings_post
        .iter()
        .filter(|f| f.message.contains("Literal credential"))
        .collect();
    assert_eq!(
        literal_post.len(),
        1,
        "post-resolve: resolved value IS flagged as literal — this is why cmd_plan/cmd_review must audit before resolve"
    );
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
fn security_respects_global_auth_plugin() {
    let mut proxy = make_proxy("p1", "/api", "localhost");
    proxy.namespace = "team-alpha".to_string();

    let config = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![make_plugin_config(
            "global-auth",
            "team-alpha",
            "key_auth",
            PluginScope::Global,
        )],
        ..GatewayConfig::default()
    };

    let findings = audit_security(&config);
    assert!(!findings
        .iter()
        .any(|f| f.message.contains("No auth plugin")));
}

#[test]
fn security_ignores_disabled_auth_plugin() {
    let mut proxy = make_proxy("p1", "/api", "localhost");
    proxy.namespace = "team-alpha".to_string();

    let mut disabled_auth =
        make_plugin_config("global-auth", "team-alpha", "key_auth", PluginScope::Global);
    disabled_auth.enabled = false;

    let config = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![disabled_auth],
        ..GatewayConfig::default()
    };

    let findings = audit_security(&config);
    assert!(findings
        .iter()
        .any(|f| f.message.contains("No auth plugin")));
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

#[test]
fn best_practice_respects_global_plugins() {
    let mut proxy = make_proxy("p1", "/api", "localhost");
    proxy.namespace = "team-alpha".to_string();

    let config = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![
            make_plugin_config(
                "global-rate-limit",
                "team-alpha",
                "rate_limiting",
                PluginScope::Global,
            ),
            make_plugin_config(
                "global-logging",
                "team-alpha",
                "request_logging",
                PluginScope::Global,
            ),
        ],
        ..GatewayConfig::default()
    };

    let checks = check_best_practices(&config);
    assert!(!checks
        .iter()
        .any(|check| check.message.contains("rate_limiting")));
    assert!(!checks.iter().any(|check| check.message.contains("logging")));
}
