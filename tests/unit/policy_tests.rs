use gitforgeops::config::schema::{
    BackendScheme, GatewayConfig, LoadBalancerAlgorithm, PluginAssociation, PluginConfig,
    PluginScope, Proxy, Upstream, UpstreamTarget,
};
use gitforgeops::policy::config::{
    AllowedBackendDomainsRuleConfig, AllowedProxyPluginsRuleConfig, BackendSchemeRuleConfig,
    ForbidTlsVerifyDisabledRuleConfig, PolicyConfig, PolicyRules, TimeoutBand,
    TimeoutBandsRuleConfig,
};
use gitforgeops::policy::{evaluate_policies, Severity};

fn proxy(id: &str, protocol: BackendScheme, read_timeout: u64, tls_verify: bool) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: None,
        namespace: "ferrum".to_string(),
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(protocol),
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
        pool_max_requests_per_connection: None,
        upstream_subset: None,
        api_spec_id: None,
        websocket_idle_timeout_seconds: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn plugin_config(id: &str, plugin_name: &str, namespace: &str) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: namespace.to_string(),
        plugin_name: plugin_name.to_string(),
        scope: PluginScope::Proxy,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        config: Default::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn upstream(id: &str, targets: Vec<UpstreamTarget>) -> Upstream {
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
        subsets: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: vec![],
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn target(host: &str) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port: 443,
        weight: 1,
        tags: Default::default(),
        locality: None,
        path: None,
    }
}

#[test]
fn disabled_policy_produces_no_findings() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("p1", BackendScheme::Http, 120_000, true)],
        ..Default::default()
    };
    let policies = PolicyConfig::default();
    let findings = evaluate_policies(&cfg, &policies);
    assert!(findings.is_empty());
}

#[test]
fn timeout_band_upper_bound_triggers_error() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("slow-one", BackendScheme::Https, 120_000, true)],
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
            proxy("secure", BackendScheme::Https, 30_000, true),
            proxy("insecure", BackendScheme::Http, 30_000, true),
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
fn allowed_proxy_plugins_flags_disallowed_associations() {
    let mut p = proxy("p1", BackendScheme::Https, 30_000, true);
    p.plugins = vec![
        PluginAssociation {
            plugin_config_id: "plugin-keyauth".to_string(),
        },
        PluginAssociation {
            plugin_config_id: "plugin-transform".to_string(),
        },
    ];

    let cfg = GatewayConfig {
        proxies: vec![p],
        plugin_configs: vec![
            plugin_config("plugin-keyauth", "key_auth", "ferrum"),
            plugin_config("plugin-transform", "request_transformer", "ferrum"),
        ],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_proxy_plugins: AllowedProxyPluginsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_plugin_names: vec!["KEY_AUTH".to_string(), "rate_limiting".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "allowed_proxy_plugins");
    assert_eq!(findings[0].id, "p1");
    assert!(findings[0].message.contains("plugin-transform"));
    assert!(findings[0].message.contains("request_transformer"));
}

#[test]
fn allowed_proxy_plugins_flags_unresolved_associations() {
    let mut p = proxy("p1", BackendScheme::Https, 30_000, true);
    p.plugins = vec![PluginAssociation {
        plugin_config_id: "plugin-other-namespace".to_string(),
    }];

    let cfg = GatewayConfig {
        proxies: vec![p],
        plugin_configs: vec![plugin_config(
            "plugin-other-namespace",
            "request_transformer",
            "team-alpha",
        )],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_proxy_plugins: AllowedProxyPluginsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_plugin_names: vec!["request_transformer".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "allowed_proxy_plugins");
    assert!(findings[0].message.contains("could not be resolved"));
    assert!(findings[0].message.contains("plugin-other-namespace"));
}

#[test]
fn allowed_backend_domains_checks_proxies_and_upstream_targets() {
    let mut exact_proxy = proxy("exact", BackendScheme::Https, 30_000, true);
    exact_proxy.backend_host = "API.Internal.Example.COM.".to_string();
    let mut disallowed_proxy = proxy("disallowed-proxy", BackendScheme::Https, 30_000, true);
    disallowed_proxy.backend_host = "api.evil.example".to_string();

    let cfg = GatewayConfig {
        proxies: vec![exact_proxy, disallowed_proxy],
        upstreams: vec![upstream(
            "api-pool",
            vec![
                target("blue.svc.cluster.local"),
                target("deep.team.prod.example.com"),
                target("db.other.example"),
            ],
        )],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec![
                    "api.internal.example.com".to_string(),
                    "*.svc.cluster.local".to_string(),
                    "*.prod.example.com".to_string(),
                ],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .any(|f| f.kind == "Proxy" && f.id == "disallowed-proxy"));
    assert!(findings.iter().any(|f| f.kind == "Upstream"
        && f.id == "api-pool"
        && f.message.contains("db.other.example")));
    assert!(!findings
        .iter()
        .any(|f| f.message.contains("blue.svc.cluster.local")));
    assert!(!findings
        .iter()
        .any(|f| f.message.contains("deep.team.prod.example.com")));
}

#[test]
fn allowed_backend_domains_skips_proxy_backend_host_when_upstream_is_used() {
    let mut p = proxy("upstream-backed", BackendScheme::Https, 30_000, true);
    p.backend_host = "placeholder.invalid".to_string();
    p.upstream_id = Some("api-pool".to_string());

    let cfg = GatewayConfig {
        proxies: vec![p],
        upstreams: vec![upstream("api-pool", vec![target("blue.svc.cluster.local")])],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec!["*.svc.cluster.local".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert!(
        findings.is_empty(),
        "upstream-backed proxy backend_host should not be checked: {findings:?}"
    );
}

#[test]
fn allowed_backend_domains_checks_proxy_backend_host_when_upstream_id_is_unresolved() {
    let mut p = proxy("missing-upstream", BackendScheme::Https, 30_000, true);
    p.backend_host = "attacker.invalid".to_string();
    p.upstream_id = Some("missing".to_string());

    let cfg = GatewayConfig {
        proxies: vec![p],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec!["*.svc.cluster.local".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "allowed_backend_domains");
    assert_eq!(findings[0].kind, "Proxy");
    assert_eq!(findings[0].id, "missing-upstream");
}

#[test]
fn allowed_backend_domains_checks_proxy_backend_host_when_upstream_id_is_empty() {
    let mut p = proxy("empty-upstream", BackendScheme::Https, 30_000, true);
    p.backend_host = "attacker.invalid".to_string();
    p.upstream_id = Some("   ".to_string());

    let cfg = GatewayConfig {
        proxies: vec![p],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec!["*.svc.cluster.local".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "allowed_backend_domains");
    assert_eq!(findings[0].kind, "Proxy");
    assert_eq!(findings[0].id, "empty-upstream");
}

#[test]
fn allowed_backend_domains_does_not_resolve_upstream_from_another_namespace() {
    let mut p = proxy("cross-namespace", BackendScheme::Https, 30_000, true);
    p.backend_host = "attacker.invalid".to_string();
    p.upstream_id = Some("api-pool".to_string());

    let mut other_namespace_upstream = upstream("api-pool", vec![target("blue.svc.cluster.local")]);
    other_namespace_upstream.namespace = "other".to_string();

    let cfg = GatewayConfig {
        proxies: vec![p],
        upstreams: vec![other_namespace_upstream],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec!["*.svc.cluster.local".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "Proxy");
    assert_eq!(findings[0].id, "cross-namespace");
}

#[test]
fn allowed_backend_domains_wildcard_does_not_match_root_domain() {
    let mut p = proxy("root", BackendScheme::Https, 30_000, true);
    p.backend_host = "example.com".to_string();
    let cfg = GatewayConfig {
        proxies: vec![p],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec!["*.example.com".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let findings = evaluate_policies(&cfg, &policies);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "allowed_backend_domains");
}

#[test]
fn allowed_backend_domains_matches_ip_literals_exactly() {
    let mut p = proxy("loopback", BackendScheme::Https, 30_000, true);
    p.backend_host = "[::1]".to_string();
    let cfg = GatewayConfig {
        proxies: vec![p],
        ..Default::default()
    };
    let policies = PolicyConfig {
        policies: PolicyRules {
            allowed_backend_domains: AllowedBackendDomainsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                allowed_domains: vec!["[::1]".to_string()],
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(evaluate_policies(&cfg, &policies).is_empty());
}

#[test]
fn require_auth_plugin_ignores_disabled_plugins() {
    // Proxy exists; an auth plugin exists in the same namespace at Global
    // scope but has enabled=false. The policy must still fire — disabled
    // plugins don't actually authenticate traffic.
    let p = proxy("p1", BackendScheme::Https, 30_000, true);
    let disabled_auth = PluginConfig {
        id: "jwt-disabled".to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: "jwt".to_string(),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
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
        trigger: None,
        api_spec_id: None,
        config: Default::default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let cfg2 = GatewayConfig {
        proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![enabled_auth],
        ..Default::default()
    };
    let findings2 = evaluate_policies(&cfg2, &policies);
    assert!(findings2.is_empty(), "enabled auth plugin should satisfy");
}

#[test]
fn require_auth_plugin_uses_explicit_allowlist() {
    // The allowlist accepts canonical auth plugin ids such as `jwt` and
    // rejects unrelated plugin names that merely contain auth-like
    // substrings (e.g. `body_size_audit`, `fake-auth-bypass`).
    use gitforgeops::config::schema::{PluginConfig, PluginScope};

    let make_plugin = |id: &str, name: &str| PluginConfig {
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: name.to_string(),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
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
        proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("jwt-1", "jwt")],
        ..Default::default()
    };
    assert!(
        evaluate_policies(&cfg_jwt, &policies).is_empty(),
        "jwt should satisfy require_auth_plugin under default allowlist"
    );

    // Case 2: `basic-auth` is on the default allowlist — proxy passes.
    let cfg_basic = GatewayConfig {
        proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
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
        proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
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
        proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![make_plugin("sso-1", "company_sso")],
        ..Default::default()
    };
    assert!(
        evaluate_policies(&cfg_custom, &custom_policies).is_empty(),
        "custom allowlist entry should satisfy the rule"
    );
    // With the custom allowlist, `jwt` is no longer accepted.
    let cfg_custom_jwt = GatewayConfig {
        proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
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
        subsets: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: vec![],
        api_spec_id: None,
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
        proxies: vec![proxy("risky", BackendScheme::Https, 30_000, false)],
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
fn override_pagination_cap_fails_closed_when_more_pages_exist() {
    use gitforgeops::policy::github_override::hit_pagination_safety_cap;

    assert!(!hit_pagination_safety_cap(0, true));
    assert!(!hit_pagination_safety_cap(19, false));
    assert!(hit_pagination_safety_cap(19, true));
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

// ---------------------------------------------------------------------------
// Plugin catalog + scope merge
// ---------------------------------------------------------------------------

fn catalog_plugin(
    id: &str,
    name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    config: serde_json::Value,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        plugin_name: name.to_string(),
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        config,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn attach(mut p: Proxy, plugin_ids: &[&str]) -> Proxy {
    p.plugins = plugin_ids
        .iter()
        .map(|id| PluginAssociation {
            plugin_config_id: (*id).to_string(),
        })
        .collect();
    p
}

#[test]
fn catalog_holds_the_full_builtin_registry() {
    use gitforgeops::plugin_catalog::{is_builtin, is_reserved, is_retired, BUILTIN_PLUGINS};

    assert_eq!(
        BUILTIN_PLUGINS.len(),
        82,
        "the gateway registers exactly 82 built-in plugins"
    );
    // Names that used to be spelled differently (or not at all) in this repo.
    for name in [
        "jwt_auth",
        "jwks_auth",
        "oauth2_introspection",
        "oidc_relying_party",
        "soap_ws_security",
        "spiffe_identity",
        "ai_semantic_firewall",
        "mcp_gateway",
        "udp_rate_limiting",
    ] {
        assert!(is_builtin(name), "{name} must be in the catalog");
    }
    // The short spellings that were previously hardcoded are NOT plugins.
    for name in ["jwt", "oauth2", "oidc", "request_logging"] {
        assert!(!is_builtin(name), "{name} is not a gateway plugin");
    }
    assert!(is_retired("oauth2_auth"));
    assert!(is_retired("semantic_ai_firewall"));
    assert!(is_reserved("__mesh_bpf_metrics"));
}

#[test]
fn default_auth_plugin_names_cover_every_builtin_authenticator() {
    use gitforgeops::plugin_catalog::AUTH_PLUGIN_NAMES;
    use gitforgeops::policy::config::{default_auth_plugin_names, is_default_auth_plugin_name};

    let defaults = default_auth_plugin_names();
    assert_eq!(AUTH_PLUGIN_NAMES.len(), 11);
    for name in AUTH_PLUGIN_NAMES {
        assert!(
            defaults.iter().any(|d| d == name),
            "{name} missing from the default auth allowlist"
        );
        assert!(is_default_auth_plugin_name(name));
    }
    // A proxy protected only by jwt_auth used to be reported unauthenticated.
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
    for name in AUTH_PLUGIN_NAMES {
        let cfg = GatewayConfig {
            proxies: vec![proxy("p1", BackendScheme::Https, 30_000, true)],
            plugin_configs: vec![catalog_plugin(
                "auth-1",
                name,
                PluginScope::Global,
                None,
                serde_json::json!({}),
            )],
            ..Default::default()
        };
        assert!(
            evaluate_policies(&cfg, &policies).is_empty(),
            "{name} should satisfy require_auth_plugin"
        );
    }
}

#[test]
fn effective_plugins_scoped_instance_replaces_the_global() {
    use gitforgeops::plugin_catalog::effective_plugins;

    let p = attach(
        proxy("p1", BackendScheme::Https, 30_000, true),
        &["rl-proxy"],
    );
    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![
            catalog_plugin(
                "rl-global",
                "rate_limiting",
                PluginScope::Global,
                None,
                serde_json::json!({}),
            ),
            catalog_plugin(
                "rl-proxy",
                "rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                serde_json::json!({}),
            ),
        ],
        ..Default::default()
    };

    let effective = effective_plugins(&cfg, &p);
    let ids: Vec<&str> = effective.iter().map(|pl| pl.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["rl-proxy"],
        "the scoped instance replaces the same-name global"
    );
}

#[test]
fn effective_plugins_keeps_the_global_for_other_plugin_names() {
    use gitforgeops::plugin_catalog::effective_plugins;

    let p = attach(
        proxy("p1", BackendScheme::Https, 30_000, true),
        &["cors-proxy"],
    );
    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![
            catalog_plugin(
                "rl-global",
                "rate_limiting",
                PluginScope::Global,
                None,
                serde_json::json!({}),
            ),
            catalog_plugin(
                "cors-proxy",
                "cors",
                PluginScope::Proxy,
                Some("p1"),
                serde_json::json!({}),
            ),
        ],
        ..Default::default()
    };

    let ids: Vec<&str> = effective_plugins(&cfg, &p)
        .iter()
        .map(|pl| pl.id.as_str())
        .collect();
    // cors (priority 100) sorts before rate_limiting (2900).
    assert_eq!(ids, vec!["cors-proxy", "rl-global"]);
}

#[test]
fn effective_plugins_excludes_disabled_instances() {
    use gitforgeops::plugin_catalog::effective_plugins;

    let p = proxy("p1", BackendScheme::Https, 30_000, true);
    let mut disabled = catalog_plugin(
        "auth-global",
        "jwt_auth",
        PluginScope::Global,
        None,
        serde_json::json!({}),
    );
    disabled.enabled = false;
    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![disabled],
        ..Default::default()
    };

    assert!(
        effective_plugins(&cfg, &p).is_empty(),
        "a disabled plugin is skipped by the gateway on every request"
    );
}

#[test]
fn effective_plugins_keeps_every_size_limiting_instance() {
    use gitforgeops::plugin_catalog::effective_plugins;

    // Size limits are conjunctive: a looser scoped instance must not be able
    // to displace a stricter global one.
    let p = attach(
        proxy("p1", BackendScheme::Https, 30_000, true),
        &["size-proxy"],
    );
    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![
            catalog_plugin(
                "size-global",
                "request_size_limiting",
                PluginScope::Global,
                None,
                serde_json::json!({}),
            ),
            catalog_plugin(
                "size-proxy",
                "request_size_limiting",
                PluginScope::Proxy,
                Some("p1"),
                serde_json::json!({}),
            ),
        ],
        ..Default::default()
    };

    let ids: Vec<&str> = effective_plugins(&cfg, &p)
        .iter()
        .map(|pl| pl.id.as_str())
        .collect();
    assert_eq!(ids.len(), 2, "both size-limit instances stay effective");
    assert!(ids.contains(&"size-global"));
}

#[test]
fn effective_plugins_sorts_by_priority_override() {
    use gitforgeops::plugin_catalog::{effective_plugins, effective_priority};

    let p = proxy("p1", BackendScheme::Https, 30_000, true);
    let mut late_cors = catalog_plugin(
        "cors-1",
        "cors",
        PluginScope::Global,
        None,
        serde_json::json!({}),
    );
    late_cors.priority_override = Some(9500);
    let logging = catalog_plugin(
        "log-1",
        "http_logging",
        PluginScope::Global,
        None,
        serde_json::json!({}),
    );
    assert_eq!(effective_priority(&logging), 9100);
    assert_eq!(effective_priority(&late_cors), 9500);

    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![late_cors, logging],
        ..Default::default()
    };
    let ids: Vec<&str> = effective_plugins(&cfg, &p)
        .iter()
        .map(|pl| pl.id.as_str())
        .collect();
    assert_eq!(ids, vec!["log-1", "cors-1"]);
}

// ---------------------------------------------------------------------------
// waf_enforcement
// ---------------------------------------------------------------------------

fn waf_policies(min_paranoia: Option<u8>) -> PolicyConfig {
    PolicyConfig {
        policies: PolicyRules {
            waf_enforcement: gitforgeops::policy::config::WafEnforcementRuleConfig {
                enabled: true,
                severity: Severity::Error,
                min_paranoia_level: min_paranoia,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn waf_config(config: serde_json::Value) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: vec![catalog_plugin(
            "waf-1",
            "waf",
            PluginScope::Global,
            None,
            config,
        )],
        ..Default::default()
    }
}

#[test]
fn waf_enforcement_flags_monitor_mode() {
    let cfg = waf_config(serde_json::json!({"mode": "monitor"}));
    let findings = evaluate_policies(&cfg, &waf_policies(None));
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("mode: monitor"));
    assert!(findings[0].message.contains("waf-1"));
    assert!(findings[0].message.contains("ferrum"));
    assert!(findings[0].is_blocking());
}

#[test]
fn waf_enforcement_flags_enforce_mode_with_only_monitor_rules() {
    // The built-in rule pack ships every rule at monitor, so `mode: enforce`
    // on its own rejects nothing.
    let cfg = waf_config(serde_json::json!({"mode": "enforce"}));
    let findings = evaluate_policies(&cfg, &waf_policies(None));
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("monitor-only"));
}

#[test]
fn waf_enforcement_accepts_a_promoted_rule_pack() {
    for promotion in [
        serde_json::json!({"mode": "enforce", "default_rule_action": "enforce"}),
        serde_json::json!({"mode": "enforce", "rule_modes": {"FE-SQLI-001": "enforce"}}),
        serde_json::json!({"mode": "enforce", "rule_overrides": {"FE-XSS-001": {"action": "enforce"}}}),
        serde_json::json!({"mode": "enforce", "custom_rules": [{"id": "x", "action": "block"}]}),
    ] {
        let cfg = waf_config(promotion.clone());
        assert!(
            evaluate_policies(&cfg, &waf_policies(None)).is_empty(),
            "expected no finding for {promotion}"
        );
    }
}

#[test]
fn waf_enforcement_checks_paranoia_level_and_body_skip() {
    let cfg = waf_config(serde_json::json!({
        "mode": "enforce",
        "default_rule_action": "enforce",
        "paranoia_level": 1,
        "on_body_too_large": "skip",
    }));
    let findings = evaluate_policies(&cfg, &waf_policies(Some(2)));
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .any(|f| f.message.contains("paranoia_level 1")));
    assert!(findings
        .iter()
        .any(|f| f.message.contains("on_body_too_large: skip")));
}

#[test]
fn waf_enforcement_ignores_disabled_instances() {
    let mut plugin = catalog_plugin(
        "waf-1",
        "waf",
        PluginScope::Global,
        None,
        serde_json::json!({"mode": "monitor"}),
    );
    plugin.enabled = false;
    let cfg = GatewayConfig {
        plugin_configs: vec![plugin],
        ..Default::default()
    };
    assert!(evaluate_policies(&cfg, &waf_policies(None)).is_empty());
}

// ---------------------------------------------------------------------------
// require_ai_guardrails
// ---------------------------------------------------------------------------

fn ai_policies() -> PolicyConfig {
    PolicyConfig {
        policies: PolicyRules {
            require_ai_guardrails: gitforgeops::policy::config::RequireAiGuardrailsRuleConfig {
                enabled: true,
                severity: Severity::Error,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn require_ai_guardrails_flags_an_unguarded_ai_route() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("llm", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![catalog_plugin(
            "mcp-1",
            "mcp_gateway",
            PluginScope::Global,
            None,
            serde_json::json!({}),
        )],
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &ai_policies());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("no content guardrail"));
    assert!(findings[0].message.contains("llm"));
}

#[test]
fn require_ai_guardrails_accepts_an_enforcing_guardrail() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("llm", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![
            catalog_plugin(
                "mcp-1",
                "mcp_gateway",
                PluginScope::Global,
                None,
                serde_json::json!({}),
            ),
            catalog_plugin(
                "shield-1",
                "ai_prompt_shield",
                PluginScope::Global,
                None,
                serde_json::json!({}),
            ),
        ],
        ..Default::default()
    };
    assert!(evaluate_policies(&cfg, &ai_policies()).is_empty());
}

#[test]
fn require_ai_guardrails_rejects_a_dry_run_guardrail() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("llm", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![
            catalog_plugin(
                "mcp-1",
                "mcp_gateway",
                PluginScope::Global,
                None,
                serde_json::json!({}),
            ),
            catalog_plugin(
                "fw-1",
                "ai_semantic_firewall",
                PluginScope::Global,
                None,
                serde_json::json!({"mode": "dry_run"}),
            ),
        ],
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &ai_policies());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("mode: dry_run"));
}

#[test]
fn require_ai_guardrails_ignores_non_ai_routes() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("plain", BackendScheme::Https, 30_000, true)],
        plugin_configs: vec![catalog_plugin(
            "rl-1",
            "rate_limiting",
            PluginScope::Global,
            None,
            serde_json::json!({}),
        )],
        ..Default::default()
    };
    assert!(evaluate_policies(&cfg, &ai_policies()).is_empty());
}

// ---------------------------------------------------------------------------
// rate_limit_completeness
// ---------------------------------------------------------------------------

fn rate_limit_policies() -> PolicyConfig {
    PolicyConfig {
        policies: PolicyRules {
            rate_limit_completeness: gitforgeops::policy::config::RateLimitCompletenessRuleConfig {
                enabled: true,
                severity: Severity::Error,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn rate_limit_config(name: &str, config: serde_json::Value) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: vec![catalog_plugin(
            "rl-1",
            name,
            PluginScope::Global,
            None,
            config,
        )],
        ..Default::default()
    }
}

#[test]
fn rate_limit_completeness_detects_the_removed_top_level_fields() {
    let cfg = rate_limit_config(
        "rate_limiting",
        serde_json::json!({"requests_per_second": 10, "window_seconds": 60}),
    );
    let findings = evaluate_policies(&cfg, &rate_limit_policies());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("requests_per_second"));
    assert!(findings[0].message.contains("top level"));
}

#[test]
fn rate_limit_completeness_flags_missing_and_empty_limits() {
    for config in [
        serde_json::json!({"limit_by": "ip"}),
        serde_json::json!({"limits": []}),
    ] {
        let cfg = rate_limit_config("rate_limiting", config.clone());
        let findings = evaluate_policies(&cfg, &rate_limit_policies());
        assert_eq!(findings.len(), 1, "for {config}");
        assert!(findings[0].message.contains("limits"));
    }
}

#[test]
fn rate_limit_completeness_requires_a_default_scope_and_a_budget() {
    let cfg = rate_limit_config(
        "rate_limiting",
        serde_json::json!({"limits": [{"scope": "consumers", "consumers": ["a"]}]}),
    );
    let findings = evaluate_policies(&cfg, &rate_limit_policies());
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .any(|f| f.message.contains("scope: default")));
    assert!(findings.iter().any(|f| f.message.contains("no budget")));
}

#[test]
fn rate_limit_completeness_accepts_a_complete_config() {
    let cfg = rate_limit_config(
        "rate_limiting",
        serde_json::json!({
            "limit_by": "consumer",
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}],
        }),
    );
    assert!(evaluate_policies(&cfg, &rate_limit_policies()).is_empty());
}

#[test]
fn rate_limit_completeness_covers_ai_rate_limiter_and_redis_fallback() {
    let cfg = rate_limit_config(
        "ai_rate_limiter",
        serde_json::json!({"redis_failure_policy": "local_fallback"}),
    );
    let findings = evaluate_policies(&cfg, &rate_limit_policies());
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|f| f.message.contains("token_limit")));
    assert!(findings
        .iter()
        .any(|f| f.message.contains("local_fallback")));

    let ok = rate_limit_config(
        "ai_rate_limiter",
        serde_json::json!({"token_limit": 10_000}),
    );
    assert!(evaluate_policies(&ok, &rate_limit_policies()).is_empty());
}

// ---------------------------------------------------------------------------
// plugin_name_is_known
// ---------------------------------------------------------------------------

fn known_name_policies(extra: Vec<String>) -> PolicyConfig {
    PolicyConfig {
        policies: PolicyRules {
            plugin_name_is_known: gitforgeops::policy::config::PluginNameIsKnownRuleConfig {
                enabled: true,
                severity: Severity::Warning,
                allowed_extra_plugin_names: extra,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn named_plugin_config(name: &str) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: vec![catalog_plugin(
            "pl-1",
            name,
            PluginScope::Global,
            None,
            serde_json::json!({}),
        )],
        ..Default::default()
    }
}

#[test]
fn plugin_name_is_known_errors_on_retired_names() {
    for name in ["oauth2_auth", "semantic_ai_firewall"] {
        let cfg = named_plugin_config(name);
        let findings = evaluate_policies(&cfg, &known_name_policies(vec![]));
        assert_eq!(findings.len(), 1, "for {name}");
        // Severity is forced to error even though the rule is configured at
        // warning: the gateway will not load the config at all.
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("retired"));
    }
}

#[test]
fn plugin_name_is_known_errors_on_the_reserved_mesh_plugin() {
    let cfg = named_plugin_config("__mesh_bpf_metrics");
    let findings = evaluate_policies(&cfg, &known_name_policies(vec![]));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Error);
    assert!(findings[0].message.contains("reserved"));
}

#[test]
fn plugin_name_is_known_warns_on_unknown_names_and_accepts_declared_customs() {
    let cfg = named_plugin_config("company_sso");
    let findings = evaluate_policies(&cfg, &known_name_policies(vec![]));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Warning);
    assert!(!findings[0].is_blocking());

    let declared = known_name_policies(vec!["company_sso".to_string()]);
    assert!(evaluate_policies(&cfg, &declared).is_empty());
}

#[test]
fn plugin_name_is_known_accepts_every_builtin() {
    use gitforgeops::plugin_catalog::BUILTIN_PLUGINS;

    for builtin in BUILTIN_PLUGINS {
        if builtin.name == "__mesh_bpf_metrics" {
            continue; // reserved — covered by its own test
        }
        let cfg = named_plugin_config(builtin.name);
        assert!(
            evaluate_policies(&cfg, &known_name_policies(vec![])).is_empty(),
            "{} should be accepted",
            builtin.name
        );
    }
}

// ---------------------------------------------------------------------------
// priority_override_range
// ---------------------------------------------------------------------------

fn priority_policies() -> PolicyConfig {
    PolicyConfig {
        policies: PolicyRules {
            priority_override_range: gitforgeops::policy::config::PriorityOverrideRangeRuleConfig {
                enabled: true,
                severity: Severity::Error,
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn priority_override_range_flags_values_above_the_gateway_maximum() {
    let mut plugin = catalog_plugin(
        "pl-1",
        "cors",
        PluginScope::Global,
        None,
        serde_json::json!({}),
    );
    plugin.priority_override = Some(60_000);
    let cfg = GatewayConfig {
        plugin_configs: vec![plugin],
        ..Default::default()
    };
    let findings = evaluate_policies(&cfg, &priority_policies());
    assert_eq!(findings.len(), 1);
    assert!(findings[0].message.contains("60000"));
    assert!(findings[0].message.contains("10000"));
}

#[test]
fn priority_override_range_accepts_in_range_and_unset_values() {
    for value in [None, Some(0), Some(9000), Some(10_000)] {
        let mut plugin = catalog_plugin(
            "pl-1",
            "cors",
            PluginScope::Global,
            None,
            serde_json::json!({}),
        );
        plugin.priority_override = value;
        let cfg = GatewayConfig {
            plugin_configs: vec![plugin],
            ..Default::default()
        };
        assert!(
            evaluate_policies(&cfg, &priority_policies()).is_empty(),
            "priority_override {value:?} is within range"
        );
    }
}

#[test]
fn shipped_policy_example_parses_and_keeps_every_rule_opt_in() {
    use gitforgeops::policy::config::load_policies_from_path;
    use std::path::Path;

    let loaded = load_policies_from_path(Path::new(".gitforgeops/policies.example.yaml"))
        .expect("the shipped example must parse")
        .expect("the shipped example must exist");

    // The new rules are opt-in, so a repo that copies the example verbatim
    // does not suddenly start blocking applies.
    assert!(!loaded.policies.waf_enforcement.enabled);
    assert!(!loaded.policies.require_ai_guardrails.enabled);
    assert!(!loaded.policies.rate_limit_completeness.enabled);
    assert!(!loaded.policies.plugin_name_is_known.enabled);
    assert!(!loaded.policies.priority_override_range.enabled);

    // And its documented plugin names are real gateway plugins.
    for name in &loaded.policies.allowed_proxy_plugins.allowed_plugin_names {
        assert!(
            gitforgeops::plugin_catalog::is_builtin(name),
            "allowed_proxy_plugins lists {name}, which is not a gateway plugin"
        );
    }
    for name in &loaded.policies.require_auth_plugin.auth_plugin_names {
        assert!(
            gitforgeops::plugin_catalog::is_auth_plugin(name),
            "auth_plugin_names lists {name}, which is not a gateway auth plugin"
        );
    }
}
