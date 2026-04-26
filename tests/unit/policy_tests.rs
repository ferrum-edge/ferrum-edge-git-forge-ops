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
fn require_auth_plugin_ignores_disabled_plugins() {
    use gitforgeops::config::schema::{PluginConfig, PluginScope};

    // Proxy exists; an auth plugin exists in the same namespace at Global
    // scope but has enabled=false. The policy must still fire — disabled
    // plugins don't actually authenticate traffic.
    let p = proxy("p1", BackendProtocol::Https, 30_000, true);
    let disabled_auth = PluginConfig {
        id: "jwt-disabled".to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: "jwt".to_string(),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        config: Default::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let cfg = GatewayConfig {
        proxies: vec![p],
        plugin_configs: vec![disabled_auth],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            require_auth_plugin: gitforgeops::policy::config::RequireAuthPluginRuleConfig {
                enabled: true,
                severity: Severity::Error,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(
        findings.len(),
        1,
        "disabled auth plugin must not satisfy require_auth_plugin"
    );
    assert_eq!(findings[0].rule_id, "require_auth_plugin");

    // Same setup but plugin enabled — policy should be satisfied.
    let enabled_auth = PluginConfig {
        id: "jwt-on".to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: "jwt".to_string(),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        config: Default::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let cfg2 = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Https, 30_000, true)],
        plugin_configs: vec![enabled_auth],
        ..Default::default()
    };
    let findings2 = evaluate_policies(&cfg2, &policies);
    assert!(findings2.is_empty(), "enabled auth plugin should satisfy");
}

#[test]
fn require_auth_plugin_uses_explicit_allowlist() {
    // Regression: the old substring match on "auth" accepted
    // unrelated plugin names that merely contained the substring
    // (e.g. `body_size_audit`, `fake-auth-bypass`) and excluded `jwt`
    // — whose canonical id doesn't include the substring. The
    // allowlist fixes both directions.
    use gitforgeops::config::schema::{PluginConfig, PluginScope};

    let make_plugin = |id: &str, name: &str| PluginConfig {
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: name.to_string(),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        config: Default::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let policies = PolicyConfig {
        policies: PolicyRules {
            require_auth_plugin: gitforgeops::policy::config::RequireAuthPluginRuleConfig {
                enabled: true,
                severity: Severity::Error,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    // Case 1: `jwt` is on the default allowlist — proxy passes.
    let cfg_jwt = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("jwt-1", "jwt")],
        ..Default::default()
    };
    assert!(
        evaluate_policies(&cfg_jwt, &policies).is_empty(),
        "jwt should satisfy require_auth_plugin under default allowlist"
    );

    // Case 2: `basic-auth` is on the default allowlist — proxy passes.
    let cfg_basic = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("ba-1", "basic-auth")],
        ..Default::default()
    };
    assert!(
        evaluate_policies(&cfg_basic, &policies).is_empty(),
        "basic-auth should satisfy under default allowlist"
    );

    // Case 3: plugin name containing `auth` substring but not on the
    // allowlist (e.g. an audit plugin) — policy must STILL fire.
    let cfg_substring = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("audit-1", "body_size_audit")],
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg_substring, &policies);
    assert_eq!(
        findings.len(),
        1,
        "substring-only match must not satisfy the rule under the allowlist"
    );

    // Case 4: custom allowlist lets an org approve a non-default name.
    let custom_policies = PolicyConfig {
        policies: PolicyRules {
            require_auth_plugin: gitforgeops::policy::config::RequireAuthPluginRuleConfig {
                enabled: true,
                severity: Severity::Error,
                auth_plugin_names: vec!["company_sso".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let cfg_custom = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("sso-1", "company_sso")],
        ..Default::default()
    };
    assert!(
        evaluate_policies(&cfg_custom, &custom_policies).is_empty(),
        "custom allowlist entry should satisfy the rule"
    );
    // With the custom allowlist, `jwt` is no longer accepted.
    let cfg_custom_jwt = GatewayConfig {
        proxies: vec![proxy("p1", BackendProtocol::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("jwt-1", "jwt")],
        ..Default::default()
    };
    assert_eq!(
        evaluate_policies(&cfg_custom_jwt, &custom_policies).len(),
        1,
        "custom allowlist should not fall back to defaults"
    );
}

#[test]
fn forbid_tls_verify_disabled_covers_upstreams() {
    // Regression guard: the rule used to scan proxies only. Upstream
    // carries the same field, and a proxy can delegate to an upstream —
    // proxy-only scan lets an upstream set tls_verify=false and bypass.
    use gitforgeops::config::schema::{LoadBalancerAlgorithm, Upstream};
    let upstream_insecure = Upstream {
        id: "api-pool".to_string(),
        name: None,
        namespace: "ferrum".to_string(),
        targets: vec![],
        algorithm: LoadBalancerAlgorithm::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: false, // <-- the violation
        backend_tls_server_ca_cert_path: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let cfg = GatewayConfig {
        upstreams: vec![upstream_insecure],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            forbid_tls_verify_disabled: ForbidTlsVerifyDisabledRuleConfig {
                enabled: true,
                severity: Severity::Error,
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "Upstream");
    assert_eq!(findings[0].id, "api-pool");
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
    // Unknown actual permission fails closed — don't treat "none" or a
    // typoed response as if it were "read" (rank 0) and silently satisfy.
    assert!(!cfg.is_sufficient("none"));
    assert!(!cfg.is_sufficient("owner"));
}

#[test]
fn override_is_sufficient_fails_closed_on_unknown_required_permission() {
    // Defense in depth: even if validate_overrides is bypassed, a
    // misspelled required_permission must not silently admit every
    // labeler — which would happen if unknown values resolved to rank 0.
    use gitforgeops::policy::config::OverrideConfig;

    let cfg = OverrideConfig {
        require_label: "x".to_string(),
        required_permission: "admn".to_string(), // typo
    };

    assert!(!cfg.is_sufficient("admin"));
    assert!(!cfg.is_sufficient("maintain"));
    assert!(!cfg.is_sufficient("write"));
    assert!(!cfg.is_sufficient("read"));
}

#[test]
fn policy_config_load_rejects_invalid_override_permission() {
    use gitforgeops::policy::config::load_policies_from_path;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
version: 1
overrides:
  require_label: gitforgeops/policy-override
  required_permission: admn
"#
    )
    .unwrap();

    let err = load_policies_from_path(file.path()).unwrap_err();
    assert!(
        err.to_string().contains("admn"),
        "expected rejection of misspelled permission, got: {err}"
    );
    assert!(err.to_string().contains("admin"));
}
