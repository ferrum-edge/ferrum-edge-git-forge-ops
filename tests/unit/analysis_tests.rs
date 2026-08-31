//! Security-audit and best-practice analysis (`src/diff/security.rs`,
//! `src/diff/best_practice.rs`). The literal-credential and scope-resolution
//! regressions live in `diff_tests.rs`; this file covers the plugin-config and
//! schema-field checks added on top of them.

use gitforgeops::config::schema::{
    BackendScheme, GatewayConfig, HealthCheckConfig, PassiveHealthCheck, PluginAssociation,
    PluginConfig, PluginScope, PluginTrigger, Proxy, ServiceDiscoveryConfig, Upstream,
};
use gitforgeops::diff::best_practice::check_best_practices;
use gitforgeops::diff::security::{audit_security, audit_security_with_policy};
use gitforgeops::policy::config::{PolicyConfig, PolicyRules, RequireAuthPluginRuleConfig};

/// Fixtures go through serde rather than struct literals: every field these
/// tests do not care about has a `#[serde(default)]`, so this stays readable
/// and does not need updating each time the schema mirror grows a field.
fn from_json<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).expect("fixture must deserialize")
}

fn proxy(id: &str, scheme: Option<BackendScheme>) -> Proxy {
    let mut value = serde_json::json!({
        "id": id,
        "namespace": "ferrum",
        "listen_path": "/api",
        "backend_host": "backend.internal",
        "backend_port": 443,
    });
    if let Some(scheme) = scheme {
        value["backend_scheme"] = serde_json::json!(scheme.as_str());
    }
    from_json(value)
}

fn plugin(id: &str, name: &str, config: serde_json::Value) -> PluginConfig {
    from_json(serde_json::json!({
        "id": id,
        "namespace": "ferrum",
        "plugin_name": name,
        "scope": "global",
        "enabled": true,
        "config": config,
    }))
}

fn upstream(id: &str, target_count: usize) -> Upstream {
    let targets: Vec<serde_json::Value> = (0..target_count)
        .map(|i| serde_json::json!({"host": format!("host-{i}.internal"), "port": 8080}))
        .collect();
    from_json(serde_json::json!({
        "id": id,
        "namespace": "ferrum",
        "targets": targets,
    }))
}

fn plugins_only(configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: configs,
        ..Default::default()
    }
}

fn messages(config: &GatewayConfig) -> Vec<String> {
    audit_security(config)
        .into_iter()
        .map(|f| f.message)
        .collect()
}

fn any_message(config: &GatewayConfig, needle: &str) -> bool {
    messages(config).iter().any(|m| m.contains(needle))
}

// ---------------------------------------------------------------------------
// Scheme-aware TLS verification
// ---------------------------------------------------------------------------

#[test]
fn tls_verify_check_is_scheme_aware() {
    // The gateway rejects `backend_tls_verify_server_cert: false` on plaintext
    // schemes outright, so flagging them here is misleading noise.
    for scheme in [BackendScheme::Http, BackendScheme::Tcp, BackendScheme::Udp] {
        let mut p = proxy("p1", Some(scheme));
        p.backend_tls_verify_server_cert = false;
        let cfg = GatewayConfig {
            proxies: vec![p],
            ..Default::default()
        };
        assert!(
            !any_message(&cfg, "backend_tls_verify_server_cert"),
            "{scheme:?} carries no server certificate to verify"
        );
    }

    for scheme in [
        BackendScheme::Https,
        BackendScheme::Tcps,
        BackendScheme::Dtls,
    ] {
        let mut p = proxy("p1", Some(scheme));
        p.backend_tls_verify_server_cert = false;
        let cfg = GatewayConfig {
            proxies: vec![p],
            ..Default::default()
        };
        assert!(
            any_message(&cfg, "backend_tls_verify_server_cert: false"),
            "{scheme:?} negotiates TLS, so the flag is meaningful"
        );
    }
}

#[test]
fn absent_backend_scheme_is_treated_as_https() {
    // `backend_scheme: None` means the gateway defaults to https — reading it
    // as plaintext would silently drop the check.
    let mut p = proxy("p1", None);
    p.backend_tls_verify_server_cert = false;
    let cfg = GatewayConfig {
        proxies: vec![p],
        ..Default::default()
    };
    assert!(any_message(&cfg, "backend_tls_verify_server_cert: false"));
}

#[test]
fn security_audit_scans_upstreams_too() {
    let mut up = upstream("pool", 2);
    up.backend_tls_verify_server_cert = false;
    let cfg = GatewayConfig {
        upstreams: vec![up],
        ..Default::default()
    };
    let findings = audit_security(&cfg);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, "Upstream");
    assert_eq!(findings[0].namespace, "ferrum");
}

// ---------------------------------------------------------------------------
// New proxy-field findings
// ---------------------------------------------------------------------------

#[test]
fn stream_proxy_protocol_and_passthrough_are_flagged() {
    let mut p = proxy("p1", Some(BackendScheme::Tcps));
    p.stream_proxy_protocol = Some(true);
    p.passthrough = true;
    let cfg = GatewayConfig {
        proxies: vec![p],
        ..Default::default()
    };
    assert!(any_message(&cfg, "stream_proxy_protocol: true"));
    assert!(any_message(&cfg, "passthrough: true"));

    let clean = GatewayConfig {
        proxies: vec![proxy("p2", Some(BackendScheme::Tcps))],
        ..Default::default()
    };
    assert!(!any_message(&clean, "stream_proxy_protocol"));
    assert!(!any_message(&clean, "passthrough"));
}

#[test]
fn auth_plugin_with_a_trigger_is_reported_as_conditional() {
    let mut auth = plugin("jwt-1", "jwt_auth", serde_json::json!({}));
    auth.trigger = Some(from_json::<PluginTrigger>(serde_json::json!({
        "when": {"match": {"path": {"prefix": ["/private"]}}},
    })));
    let cfg = GatewayConfig {
        proxies: vec![proxy("p1", Some(BackendScheme::Https))],
        plugin_configs: vec![auth],
        ..Default::default()
    };
    let msgs = messages(&cfg);
    assert!(
        msgs.iter().any(|m| m.contains("carries a trigger")),
        "expected a conditional-auth finding, got {msgs:?}"
    );
    // ... and the proxy is not reported as unauthenticated, because the
    // plugin is attached — just conditionally.
    assert!(!msgs.iter().any(|m| m.contains("No auth plugin")));
}

// ---------------------------------------------------------------------------
// Plugin name and configuration findings
// ---------------------------------------------------------------------------

#[test]
fn retired_plugin_names_are_errors_and_unknown_names_are_warnings() {
    let cfg = plugins_only(vec![plugin("p-1", "oauth2_auth", serde_json::json!({}))]);
    let findings = audit_security(&cfg);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, "error");
    assert!(findings[0].message.contains("retired"));
    assert!(findings[0].message.contains("oauth2_introspection"));

    let cfg = plugins_only(vec![plugin("p-1", "rate_limitting", serde_json::json!({}))]);
    let findings = audit_security(&cfg);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, "warning");
    assert!(findings[0].message.contains("not a built-in plugin"));

    let cfg = plugins_only(vec![plugin("p-1", "rate_limiting", serde_json::json!({}))]);
    assert!(audit_security(&cfg).is_empty());
}

#[test]
fn waf_that_blocks_nothing_is_reported() {
    let monitor = plugins_only(vec![plugin(
        "waf-1",
        "waf",
        serde_json::json!({"mode": "monitor"}),
    )]);
    assert!(any_message(&monitor, "mode: monitor"));

    let enforce_only = plugins_only(vec![plugin(
        "waf-1",
        "waf",
        serde_json::json!({"mode": "enforce"}),
    )]);
    assert!(any_message(&enforce_only, "monitor-only"));

    let promoted = plugins_only(vec![plugin(
        "waf-1",
        "waf",
        serde_json::json!({"mode": "enforce", "default_rule_action": "enforce"}),
    )]);
    assert!(audit_security(&promoted).is_empty());
}

#[test]
fn non_enforcing_validators_and_ai_guards_are_reported() {
    let cfg = plugins_only(vec![
        plugin(
            "ov-1",
            "openapi_validator",
            serde_json::json!({"enforcement_mode": "log_only"}),
        ),
        plugin(
            "fw-1",
            "ai_semantic_firewall",
            serde_json::json!({"mode": "dry_run"}),
        ),
        plugin(
            "tg-1",
            "ai_tool_governor",
            serde_json::json!({"mode": "dry_run"}),
        ),
    ]);
    assert!(any_message(&cfg, "enforcement_mode: log_only"));
    assert_eq!(
        messages(&cfg)
            .iter()
            .filter(|m| m.contains("mode: dry_run"))
            .count(),
        2
    );
}

#[test]
fn cors_wildcard_origin_is_reported_in_both_spellings() {
    for origins in [
        serde_json::json!(["*"]),
        serde_json::json!([{"exact": "*"}]),
        serde_json::json!([{"exact": ["https://app.example.com", "*"]}]),
    ] {
        let cfg = plugins_only(vec![plugin(
            "cors-1",
            "cors",
            serde_json::json!({"allowed_origins": origins}),
        )]);
        assert!(
            any_message(&cfg, "allowed_origins containing"),
            "expected a wildcard finding for {origins}"
        );
    }

    let credentials = plugins_only(vec![plugin(
        "cors-1",
        "cors",
        serde_json::json!({"allowed_origins": ["*"], "allow_credentials": true}),
    )]);
    assert!(any_message(&credentials, "silently drops the credentials"));

    let explicit = plugins_only(vec![plugin(
        "cors-1",
        "cors",
        serde_json::json!({"allowed_origins": ["https://app.example.com"]}),
    )]);
    assert!(audit_security(&explicit).is_empty());
}

#[test]
fn insecure_auth_plugin_settings_are_reported() {
    let cfg = plugins_only(vec![
        plugin(
            "ldap-1",
            "ldap_auth",
            serde_json::json!({"allow_plaintext": true}),
        ),
        plugin(
            "oidc-1",
            "oidc_relying_party",
            serde_json::json!({"session": {"secure": false}}),
        ),
        plugin(
            "hmac-1",
            "hmac_auth",
            serde_json::json!({"allow_unsafe_replayable_v1": true}),
        ),
    ]);
    assert!(any_message(&cfg, "allow_plaintext: true"));
    assert!(any_message(&cfg, "session.secure: false"));
    assert!(any_message(&cfg, "allow_unsafe_replayable_v1: true"));
    assert!(audit_security(&cfg).iter().all(|f| f.severity == "error"));
}

#[test]
fn fail_open_escape_hatches_are_reported() {
    let cfg = plugins_only(vec![
        plugin(
            "rl-1",
            "rate_limiting",
            serde_json::json!({"redis_failure_policy": "local_fallback"}),
        ),
        plugin(
            "guard-1",
            "ai_request_guard",
            serde_json::json!({"fail_on_uninspectable_body": false}),
        ),
    ]);
    assert!(any_message(&cfg, "redis_failure_policy: local_fallback"));
    assert!(any_message(&cfg, "fail_on_uninspectable_body: false"));
}

#[test]
fn disabled_plugins_skip_configuration_checks_but_not_name_checks() {
    let mut monitor_waf = plugin("waf-1", "waf", serde_json::json!({"mode": "monitor"}));
    monitor_waf.enabled = false;
    let cfg = plugins_only(vec![monitor_waf]);
    assert!(audit_security(&cfg).is_empty());

    let mut retired = plugin("p-1", "semantic_ai_firewall", serde_json::json!({}));
    retired.enabled = false;
    let cfg = plugins_only(vec![retired]);
    // The name alone is a fatal load error for the whole config.
    assert_eq!(audit_security(&cfg).len(), 1);
}

// ---------------------------------------------------------------------------
// Policy-driven auth allowlist
// ---------------------------------------------------------------------------

#[test]
fn security_audit_honours_the_configured_auth_allowlist() {
    let policy = PolicyConfig {
        policies: PolicyRules {
            require_auth_plugin: RequireAuthPluginRuleConfig {
                auth_plugin_names: vec!["company_sso".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let cfg = GatewayConfig {
        proxies: vec![proxy("p1", Some(BackendScheme::Https))],
        plugin_configs: vec![plugin("sso-1", "company_sso", serde_json::json!({}))],
        ..Default::default()
    };

    // Without the policy, `company_sso` is not an authenticator.
    assert!(audit_security(&cfg)
        .iter()
        .any(|f| f.message.contains("No auth plugin")));
    // With it, the proxy is considered authenticated.
    assert!(!audit_security_with_policy(&cfg, Some(&policy))
        .iter()
        .any(|f| f.message.contains("No auth plugin")));

    // And a built-in authenticator no longer counts once the operator has
    // narrowed the list.
    let builtin = GatewayConfig {
        proxies: vec![proxy("p1", Some(BackendScheme::Https))],
        plugin_configs: vec![plugin("jwt-1", "jwt_auth", serde_json::json!({}))],
        ..Default::default()
    };
    assert!(audit_security_with_policy(&builtin, Some(&policy))
        .iter()
        .any(|f| f.message.contains("No auth plugin")));
}

// ---------------------------------------------------------------------------
// Best practices
// ---------------------------------------------------------------------------

fn bp_messages(config: &GatewayConfig) -> Vec<String> {
    check_best_practices(config)
        .into_iter()
        .map(|f| f.message)
        .collect()
}

fn bp_any(config: &GatewayConfig, needle: &str) -> bool {
    bp_messages(config).iter().any(|m| m.contains(needle))
}

#[test]
fn rate_limit_recommendation_matches_the_proxy_protocol() {
    let udp = GatewayConfig {
        proxies: vec![proxy("stream", Some(BackendScheme::Udp))],
        ..Default::default()
    };
    assert!(bp_any(&udp, "attach udp_rate_limiting"));

    let tcp = GatewayConfig {
        proxies: vec![proxy("stream", Some(BackendScheme::Tcp))],
        ..Default::default()
    };
    assert!(bp_any(&tcp, "attach tcp_connection_throttle"));

    let http = GatewayConfig {
        proxies: vec![proxy("api", Some(BackendScheme::Https))],
        ..Default::default()
    };
    assert!(bp_any(&http, "attach rate_limiting"));
}

#[test]
fn rate_limit_check_accepts_the_whole_family() {
    // The old exact-match on `rate_limiting` reported a websocket proxy
    // guarded by `ws_rate_limiting` as unlimited.
    for name in [
        "rate_limiting",
        "ws_rate_limiting",
        "udp_rate_limiting",
        "ai_rate_limiter",
        "graphql",
    ] {
        let cfg = GatewayConfig {
            proxies: vec![proxy("api", Some(BackendScheme::Https))],
            plugin_configs: vec![plugin("rl-1", name, serde_json::json!({}))],
            ..Default::default()
        };
        assert!(
            !bp_any(&cfg, "No rate-limit plugin"),
            "{name} should satisfy the rate-limit check"
        );
    }
}

#[test]
fn observability_check_uses_the_explicit_plugin_set() {
    // `contains("logging")` missed these three entirely.
    for name in ["otel_tracing", "prometheus_metrics", "transaction_debugger"] {
        let cfg = GatewayConfig {
            proxies: vec![proxy("api", Some(BackendScheme::Https))],
            plugin_configs: vec![plugin("obs-1", name, serde_json::json!({}))],
            ..Default::default()
        };
        assert!(
            !bp_any(&cfg, "No observability plugin"),
            "{name} should satisfy the observability check"
        );
    }

    // ... and a disabled logger does not.
    let mut disabled = plugin("obs-1", "http_logging", serde_json::json!({}));
    disabled.enabled = false;
    let cfg = GatewayConfig {
        proxies: vec![proxy("api", Some(BackendScheme::Https))],
        plugin_configs: vec![disabled],
        ..Default::default()
    };
    assert!(bp_any(&cfg, "No observability plugin"));
}

#[test]
fn ai_routes_get_ai_specific_recommendations() {
    let cfg = GatewayConfig {
        proxies: vec![proxy("llm", Some(BackendScheme::Https))],
        plugin_configs: vec![plugin("mcp-1", "mcp_gateway", serde_json::json!({}))],
        ..Default::default()
    };
    assert!(bp_any(&cfg, "without ai_token_metrics"));
    assert!(bp_any(&cfg, "without ai_rate_limiter"));
    assert!(bp_any(&cfg, "no prompt guardrail"));

    let guarded = GatewayConfig {
        proxies: vec![proxy("llm", Some(BackendScheme::Https))],
        plugin_configs: vec![
            plugin("mcp-1", "mcp_gateway", serde_json::json!({})),
            plugin("shield-1", "ai_prompt_shield", serde_json::json!({})),
            plugin("tok-1", "ai_token_metrics", serde_json::json!({})),
            plugin("rl-1", "ai_rate_limiter", serde_json::json!({})),
        ],
        ..Default::default()
    };
    assert!(!bp_any(&guarded, "ai_token_metrics"));
    assert!(!bp_any(&guarded, "prompt guardrail"));
}

#[test]
fn http_proxies_are_nudged_toward_compression_and_security_headers() {
    let https = GatewayConfig {
        proxies: vec![proxy("api", Some(BackendScheme::Https))],
        ..Default::default()
    };
    assert!(bp_any(&https, "without a compression plugin"));
    assert!(bp_any(&https, "without a security_headers plugin"));

    // Stream proxies get neither — there is no HTTP response to hardening.
    let tcp = GatewayConfig {
        proxies: vec![proxy("stream", Some(BackendScheme::Tcp))],
        ..Default::default()
    };
    assert!(!bp_any(&tcp, "compression"));
    assert!(!bp_any(&tcp, "security_headers"));
}

#[test]
fn duplicate_plugin_instances_without_priority_override_are_flagged() {
    let mut p = proxy("api", Some(BackendScheme::Https));
    p.plugins = vec![
        PluginAssociation {
            plugin_config_id: "rt-1".to_string(),
        },
        PluginAssociation {
            plugin_config_id: "rt-2".to_string(),
        },
    ];
    let mut first = plugin("rt-1", "request_transformer", serde_json::json!({}));
    first.scope = PluginScope::Proxy;
    first.proxy_id = Some("api".to_string());
    let mut second = plugin("rt-2", "request_transformer", serde_json::json!({}));
    second.scope = PluginScope::Proxy;
    second.proxy_id = Some("api".to_string());

    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![first.clone(), second.clone()],
        ..Default::default()
    };
    assert!(bp_any(&cfg, "none sets priority_override"));

    // An explicit ordering resolves it.
    let mut ordered_first = first;
    ordered_first.priority_override = Some(3000);
    let mut ordered_second = second;
    ordered_second.priority_override = Some(3001);
    let ordered = GatewayConfig {
        proxies: vec![p],
        plugin_configs: vec![ordered_first, ordered_second],
        ..Default::default()
    };
    assert!(!bp_any(&ordered, "priority_override"));
}

#[test]
fn zero_target_upstreams_are_caught() {
    // The old `== 1` comparison let an upstream with no targets through.
    let cfg = GatewayConfig {
        upstreams: vec![upstream("empty", 0)],
        ..Default::default()
    };
    assert!(bp_any(&cfg, "has 0 target(s)"));

    let ok = GatewayConfig {
        upstreams: vec![Upstream {
            health_checks: Some(from_json::<HealthCheckConfig>(serde_json::json!({}))),
            ..upstream("pair", 2)
        }],
        ..Default::default()
    };
    assert!(!bp_any(&ok, "target(s)"));
}

#[test]
fn unbounded_ejection_and_stale_discovery_are_flagged() {
    let uncapped: PassiveHealthCheck = from_json(serde_json::json!({}));
    assert!(uncapped.max_ejection_percent.is_none());
    let cfg = GatewayConfig {
        upstreams: vec![Upstream {
            health_checks: Some(from_json::<HealthCheckConfig>(
                serde_json::json!({"passive": {}}),
            )),
            service_discovery: Some(from_json::<ServiceDiscoveryConfig>(serde_json::json!({
                "provider": "dns_sd",
                "max_stale_seconds": 0,
                "stale_policy": "retain",
            }))),
            ..upstream("pool", 3)
        }],
        ..Default::default()
    };
    assert!(bp_any(&cfg, "max_ejection_percent unset"));
    assert!(bp_any(&cfg, "stale_policy: retain"));
    assert!(bp_any(&cfg, "max_stale_seconds: 0"));

    let capped = GatewayConfig {
        upstreams: vec![Upstream {
            health_checks: Some(from_json::<HealthCheckConfig>(serde_json::json!({
                "passive": {"max_ejection_percent": 50},
            }))),
            ..upstream("pool", 3)
        }],
        ..Default::default()
    };
    assert!(!bp_any(&capped, "max_ejection_percent"));
}

#[test]
fn duplicate_chargeback_instances_are_flagged() {
    // The gateway's /charges registry is a process singleton, so two effective
    // instances double-count one transaction.
    let mut p = proxy("api", Some(BackendScheme::Https));
    p.plugins = vec![PluginAssociation {
        plugin_config_id: "cb-scoped".to_string(),
    }];
    let mut scoped = plugin("cb-scoped", "api_chargeback", serde_json::json!({}));
    scoped.scope = PluginScope::Proxy;
    scoped.proxy_id = Some("api".to_string());

    // A scoped instance normally replaces the same-name global, so the only
    // way to reach two is a second scoped instance.
    let mut second = plugin("cb-scoped-2", "api_chargeback", serde_json::json!({}));
    second.scope = PluginScope::Proxy;
    second.proxy_id = Some("api".to_string());
    p.plugins.push(PluginAssociation {
        plugin_config_id: "cb-scoped-2".to_string(),
    });

    let cfg = GatewayConfig {
        proxies: vec![p.clone()],
        plugin_configs: vec![scoped.clone(), second],
        ..Default::default()
    };
    assert!(bp_any(&cfg, "effective api_chargeback instances"));

    // One global plus one scoped merges down to one — no finding.
    let mut single = p;
    single.plugins = vec![PluginAssociation {
        plugin_config_id: "cb-scoped".to_string(),
    }];
    let merged = GatewayConfig {
        proxies: vec![single],
        plugin_configs: vec![
            plugin("cb-global", "api_chargeback", serde_json::json!({})),
            scoped,
        ],
        ..Default::default()
    };
    assert!(!bp_any(&merged, "effective api_chargeback instances"));
}
