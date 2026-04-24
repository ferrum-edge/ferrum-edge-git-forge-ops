use gitforgeops::config::schema::{BackendProtocol, GatewayConfig, Proxy};
use gitforgeops::policy::config::{
    BackendSchemeRuleConfig, ForbidTlsVerifyDisabledRuleConfig, PolicyConfig, PolicyRules,
    TimeoutBand, TimeoutBandsRuleConfig,
};
use gitforgeops::policy::{evaluate_policies, Severity};

fn proxy(id: &str, protocol: BackendProtocol, read_timeout: u64, tls_verify: bool) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: None,
        namespace: "ferrum".to_string(),
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_protocol: protocol,
        backend_host: "b.example".to_string(),
        backend_port: 443,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: read_timeout,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: tls_verify,
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

#[test]
fn disabled_policy_produces_no_findings() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Http, 120_000, true)],
        ..Default::default()
    };
    let policies = PolicyConfig::default();
    let findings = evaluate_policies(&cfg, &policies);
    assert!(findings.is_empty());
}

#[test]
fn timeout_band_upper_bound_triggers_error() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("slow-one", BackendProtocol::Https, 120_000, true)],
        ..Default::default()
    };
    let policies = PolicyConfig {
        version: 1,
        policies: PolicyRules {
            proxy_timeout_bands: TimeoutBandsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                read_timeout_ms: TimeoutBand {
                    min: Some(1000),
                    max: Some(60_000),
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Error);
    assert!(findings[0].message.contains("60000"));
    assert!(findings[0].is_blocking());
}

#[test]
fn backend_scheme_policy_flags_http() {
    let cfg = GatewayConfig {
        proxies: vec![
            proxy("secure", BackendProtocol::Https, 30_000, true),
            proxy("insecure", BackendProtocol::Http, 30_000, true),
        ],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            backend_scheme: BackendSchemeRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_protocols: vec!["https".to_string(), "wss".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "insecure");
    assert!(findings[0].is_blocking());
}

#[test]
fn forbid_tls_verify_disabled_triggers_on_false() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("risky", BackendProtocol::Https, 30_000, false)],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            forbid_tls_verify_disabled: ForbidTlsVerifyDisabledRuleConfig {
                enabled: true,
                severity: Severity::Warning,
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Warning);
    assert!(!findings[0].is_blocking()); // warning does not block
}

#[test]
fn parse_next_link_extracts_next_page_url() {
    // Verifies the Link header parser used by override pagination.
    use gitforgeops::policy::github_override::parse_next_link;

    let header = r#"<https://api.github.com/repos/x/y/issues/1/events?page=2>; rel="next", <https://api.github.com/repos/x/y/issues/1/events?page=5>; rel="last""#;
    assert_eq!(
        parse_next_link(header).as_deref(),
        Some("https://api.github.com/repos/x/y/issues/1/events?page=2")
    );

    // Last page: only `prev` + `first`, no `next`.
    let last_page = r#"<...?page=4>; rel="prev", <...?page=1>; rel="first""#;
    assert_eq!(parse_next_link(last_page), None);
}

#[test]
fn override_config_permission_rank_is_monotonic() {
    use gitforgeops::policy::config::OverrideConfig;

    let cfg = OverrideConfig {
        require_label: "x".to_string(),
        required_permission: "write".to_string(),
    };

    assert!(cfg.is_sufficient("admin"));
    assert!(cfg.is_sufficient("maintain"));
    assert!(cfg.is_sufficient("write"));
    assert!(!cfg.is_sufficient("triage"));
    assert!(!cfg.is_sufficient("read"));
    assert!(!cfg.is_sufficient("none"));
}
