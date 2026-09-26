use gitforgeops::config::schema::*;
use gitforgeops::diff::resource_diff::{
    compute_diff, compute_diff_with_scope, state_key, DiffAction, OwnershipScope,
};
use gitforgeops::diff::{
    best_practice::check_best_practices, breaking::detect_breaking_changes,
    is_sensitive_diff_field, security::audit_security,
};

fn mask_without_bundle(desired: &GatewayConfig, actual: &mut GatewayConfig) {
    let mut resolved = desired.clone();
    let report = gitforgeops::secrets::resolve_secrets_with_mode(
        &mut resolved,
        &gitforgeops::secrets::CredentialBundle::default(),
        gitforgeops::config::GatewayMode::Api,
    )
    .unwrap();
    gitforgeops::diff::mask_indeterminate_secret_values(&resolved, actual, &report);
}

fn make_proxy(id: &str, listen_path: &str, host: &str) -> Proxy {
    Proxy {
        labels: Default::default(),
        extra: Default::default(),
        id: id.to_string(),
        name: None,
        namespace: "ferrum".to_string(),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
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

fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        labels: Default::default(),
        extra: Default::default(),
        id: id.to_string(),
        username: username.to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: std::collections::BTreeMap::new(),
        acl_groups: vec![],
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    }
}

#[test]
fn credential_indeterminate_review_masks_only_matching_consumer_values() {
    let mut desired_consumer = make_consumer("app", "expected-name");
    desired_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "${gh-env-secret:alloc=require}"}]),
    );
    let desired = GatewayConfig {
        consumers: vec![desired_consumer],
        ..GatewayConfig::default()
    };

    let mut live_consumer = make_consumer("app", "different-live-name");
    live_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "live-secret"}]),
    );
    let mut actual = GatewayConfig {
        consumers: vec![live_consumer],
        ..GatewayConfig::default()
    };

    mask_without_bundle(&desired, &mut actual);
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1, "{:?}", diffs);
    assert_eq!(diffs[0].kind, "Consumer");
    assert!(
        diffs[0]
            .details
            .iter()
            .any(|change| change.field.contains("username")),
        "{:?}",
        diffs[0].details
    );
    assert!(
        diffs[0]
            .details
            .iter()
            .all(|change| !change.field.contains("credentials")),
        "{:?}",
        diffs[0].details
    );
}

#[test]
fn unresolved_secret_masking_matches_large_consumer_fixture() {
    const CONSUMER_COUNT: usize = 2_048;
    let mut desired_consumers = Vec::with_capacity(CONSUMER_COUNT);
    let mut live_consumers = Vec::with_capacity(CONSUMER_COUNT + 1);
    for index in 0..CONSUMER_COUNT {
        let id = format!("consumer-{index:05}");
        let mut desired_consumer = make_consumer(&id, &id);
        desired_consumer.credentials.insert(
            "keyauth".to_string(),
            serde_json::json!([{"key": "${gh-env-secret:alloc=require}"}]),
        );
        desired_consumers.push(desired_consumer);

        let mut live_consumer = make_consumer(&id, &id);
        live_consumer.credentials.insert(
            "keyauth".to_string(),
            serde_json::json!([{"key": format!("live-secret-{index:05}")}]),
        );
        live_consumers.push(live_consumer);
    }
    let mut unmatched_live = make_consumer("live-only", "live-only");
    unmatched_live.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "live-only-secret"}]),
    );
    live_consumers.push(unmatched_live);

    let desired = GatewayConfig {
        consumers: desired_consumers,
        ..GatewayConfig::default()
    };
    let mut actual = GatewayConfig {
        consumers: live_consumers,
        ..GatewayConfig::default()
    };

    mask_without_bundle(&desired, &mut actual);

    let placeholder = "${gh-env-secret:alloc=require}";
    assert_eq!(actual.consumers.len(), CONSUMER_COUNT + 1);
    for (index, consumer) in actual.consumers.iter().take(CONSUMER_COUNT).enumerate() {
        assert_eq!(consumer.id, format!("consumer-{index:05}"));
        assert_eq!(
            consumer.credentials["keyauth"][0]["key"],
            placeholder,
            "consumer {} was not masked",
            consumer.id
        );
    }
    assert_eq!(
        actual.consumers[CONSUMER_COUNT].credentials["keyauth"][0]["key"],
        "live-only-secret",
        "unmatched live resources must remain visible"
    );
}

#[test]
fn credential_indeterminate_review_keeps_known_literal_values_comparable() {
    let mut desired_consumer = make_consumer("app", "app");
    desired_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "known-desired-value"}]),
    );
    let desired = GatewayConfig {
        consumers: vec![desired_consumer],
        ..GatewayConfig::default()
    };

    let mut live_consumer = make_consumer("app", "app");
    live_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "different-live-value"}]),
    );
    let mut actual = GatewayConfig {
        consumers: vec![live_consumer],
        ..GatewayConfig::default()
    };

    mask_without_bundle(&desired, &mut actual);
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1, "{:?}", diffs);
    assert!(
        diffs[0]
            .details
            .iter()
            .any(|change| change.field.contains("credentials")),
        "{:?}",
        diffs[0].details
    );
}

#[test]
fn placeholder_syntax_without_unresolved_provenance_does_not_authorize_masking() {
    let mut consumer = make_consumer("app", "app");
    consumer.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "${gh-env-secret:alloc=require}"}]),
    );
    let mut plugin = make_plugin_config("app", "ferrum", "otel_tracing", PluginScope::Global);
    plugin.config = serde_json::json!({"authorization": "${gh-env-secret:alloc=require}"});
    let desired = GatewayConfig {
        consumers: vec![consumer],
        plugin_configs: vec![plugin],
        upstreams: vec![upstream_with_consul(
            "app",
            "https://consul.test:8501",
            Some("${gh-env-secret:alloc=require}"),
        )],
        ..GatewayConfig::default()
    };
    let mut actual = desired.clone();
    actual.consumers[0].credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "synthetic-live-key"}]),
    );
    actual.plugin_configs[0].config = serde_json::json!({"authorization": "synthetic-live-key"});
    actual.upstreams[0] = upstream_with_consul(
        "app",
        "https://consul.test:8501",
        Some("synthetic-live-key"),
    );
    let before = serde_json::to_value(&actual).unwrap();
    gitforgeops::diff::mask_indeterminate_secret_values(
        &desired,
        &mut actual,
        &gitforgeops::secrets::ResolveReport::default(),
    );
    assert_eq!(serde_json::to_value(&actual).unwrap(), before);
    assert_eq!(compute_diff(&desired, &actual).unwrap().len(), 3);
}

#[test]
fn credential_indeterminate_review_masks_only_placeholder_leaves() {
    let mut desired_consumer = make_consumer("app", "app");
    desired_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([
            {"key": "${gh-env-secret:alloc=require}", "label": "desired-label"}
        ]),
    );
    let desired = GatewayConfig {
        consumers: vec![desired_consumer],
        ..GatewayConfig::default()
    };

    let mut live_consumer = make_consumer("app", "app");
    live_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([
            {"key": "live-secret", "label": "changed-label"},
            {"key": "unexpected-extra-live-secret"}
        ]),
    );
    let mut actual = GatewayConfig {
        consumers: vec![live_consumer],
        ..GatewayConfig::default()
    };

    mask_without_bundle(&desired, &mut actual);
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1, "{:?}", diffs);
    assert!(
        diffs[0]
            .details
            .iter()
            .any(|change| change.field == "credentials"),
        "literal and extra live credential data must remain comparable: {:?}",
        diffs[0].details
    );
}

/// F7: `diff` needs the same masking `plan` and `review` already do. Without
/// it, a repo with no credential bundle reports the identical spurious change
/// on every run — the desired side is a placeholder, the live side is the real
/// value (or `[REDACTED]`) — and `drift-check.yml --exit-on-drift` can never
/// go green no matter what anyone commits.
#[test]
fn unmasked_broker_controlled_leaves_are_permanent_false_drift() {
    let mut desired_consumer = make_consumer("app", "app");
    desired_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "${gh-env-secret:alloc=generate}"}]),
    );
    let mut desired_plugin =
        make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
    desired_plugin.config = serde_json::json!({
        "authorization": "${gh-env-secret:alloc=require}"
    });
    let desired = GatewayConfig {
        consumers: vec![desired_consumer],
        plugin_configs: vec![desired_plugin],
        ..GatewayConfig::default()
    };

    let mut live_consumer = make_consumer("app", "app");
    live_consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "[REDACTED]"}]),
    );
    let mut live_plugin = make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
    live_plugin.config = serde_json::json!({"authorization": "Bearer live-secret"});
    let mut actual = GatewayConfig {
        consumers: vec![live_consumer],
        plugin_configs: vec![live_plugin],
        ..GatewayConfig::default()
    };

    // What `diff` reported before it masked: two changes nobody made.
    assert_eq!(compute_diff(&desired, &actual).unwrap().len(), 2);

    mask_without_bundle(&desired, &mut actual);

    assert!(
        compute_diff(&desired, &actual).unwrap().is_empty(),
        "{:?}",
        compute_diff(&desired, &actual).unwrap()
    );
}

#[test]
fn plugin_config_placeholder_leaves_are_masked_without_hiding_siblings() {
    let mut desired_plugin =
        make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
    desired_plugin.config = serde_json::json!({
        "authorization": "${gh-env-secret:alloc=require}",
        "protocol": "grpc"
    });
    let desired = GatewayConfig {
        plugin_configs: vec![desired_plugin],
        ..GatewayConfig::default()
    };

    let mut live_plugin = make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
    live_plugin.config = serde_json::json!({
        "authorization": "Bearer live-secret",
        "protocol": "http/protobuf"
    });
    let mut actual = GatewayConfig {
        plugin_configs: vec![live_plugin],
        ..GatewayConfig::default()
    };

    mask_without_bundle(&desired, &mut actual);
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1, "{:?}", diffs);
    assert_eq!(diffs[0].details.len(), 1, "{:?}", diffs[0].details);
    assert_eq!(diffs[0].details[0].field, "config");
    assert!(is_sensitive_diff_field("PluginConfig", "config"));
    assert!(is_sensitive_diff_field("Consumer", "credentials"));
    assert!(!is_sensitive_diff_field("PluginConfig", "plugin_name"));
}

fn make_plugin_config(
    id: &str,
    namespace: &str,
    plugin_name: &str,
    scope: PluginScope,
) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        extra: Default::default(),
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: namespace.to_string(),
        config: serde_json::json!({}),
        scope,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    }
}

fn make_upstream(id: &str, target_count: usize) -> Upstream {
    let targets: Vec<UpstreamTarget> = (0..target_count)
        .map(|i| UpstreamTarget {
            host: format!("host-{i}.internal"),
            port: 8080,
            weight: 1,
            tags: std::collections::BTreeMap::new(),
            locality: None,
            path: None,
        })
        .collect();
    Upstream {
        labels: Default::default(),
        extra: Default::default(),
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
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    }
}

#[test]
fn diff_detects_added_proxy() {
    let desired = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "localhost")],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig::default();

    let diffs = compute_diff(&desired, &actual).unwrap();
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

    let diffs = compute_diff(&desired, &actual).unwrap();
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

    let diffs = compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1);
    assert!(matches!(diffs[0].action, DiffAction::Modify));
}

#[test]
fn diff_identical_configs_empty() {
    let config = GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", "localhost")],
        ..GatewayConfig::default()
    };
    let diffs = compute_diff(&config, &config).unwrap();
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

    let diffs = compute_diff(&desired, &actual).unwrap();
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
    )
    .unwrap();

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
    let diffs = compute_diff(&desired, &actual).unwrap();
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
    let diffs = compute_diff(&desired, &actual).unwrap();
    let breaking = detect_breaking_changes(&diffs, &desired, &actual);
    assert!(!breaking.is_empty());
    assert!(breaking[0].reason.to_lowercase().contains("listen_path"));
}

/// Runs `desired` vs `actual` through diff + breaking detection where the two
/// proxies differ only in whatever `mutate` changes.
fn breaking_reasons_for_proxy_change(mutate: impl Fn(&mut Proxy)) -> Vec<String> {
    let actual_proxy = make_proxy("p1", "/api", "localhost");
    let mut desired_proxy = actual_proxy.clone();
    mutate(&mut desired_proxy);

    let desired = GatewayConfig {
        proxies: vec![desired_proxy],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        proxies: vec![actual_proxy],
        ..GatewayConfig::default()
    };
    let diffs = compute_diff(&desired, &actual).unwrap();
    detect_breaking_changes(&diffs, &desired, &actual)
        .into_iter()
        .map(|bc| bc.reason)
        .collect()
}

#[test]
fn breaking_detects_backend_scheme_change() {
    let reasons = breaking_reasons_for_proxy_change(|p| {
        p.backend_scheme = Some(BackendScheme::Https);
    });
    assert!(
        reasons.iter().any(|r| r.contains("backend_scheme")),
        "expected a backend_scheme breaking change, got {reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r.contains("backend_protocol")),
        "the pre-rename field name must not appear in messages: {reasons:?}"
    );
}

/// A live DB-backed gateway always reports a resolved scheme, so the desired
/// side (which assembly normalizes the same way) must compare equal. Before
/// this, a schemeless repo proxy read as `None != Some(https)` and every PR
/// touching it carried a phantom "backend_scheme changed" banner that no edit
/// could clear.
#[test]
fn schemeless_desired_proxy_is_not_a_breaking_change_against_a_resolved_live_scheme() {
    let mut actual_proxy = make_proxy("p1", "/api", "localhost");
    actual_proxy.backend_scheme = Some(BackendScheme::Https); // as returned by /backup
    let mut desired_proxy = actual_proxy.clone();
    desired_proxy.backend_scheme = None; // as authored, before normalization

    let desired = GatewayConfig {
        proxies: vec![desired_proxy],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        proxies: vec![actual_proxy],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual).unwrap();
    let reasons: Vec<String> = detect_breaking_changes(&diffs, &desired, &actual)
        .into_iter()
        .map(|bc| bc.reason)
        .collect();

    assert!(
        !reasons.iter().any(|r| r.contains("backend_scheme")),
        "an absent scheme resolves to https, so nothing changed: {reasons:?}"
    );
}

/// The end-to-end shape of the same bug: assemble the desired config (which
/// resolves the scheme) and diff it against what the gateway reports. There
/// must be no Modify at all — this is the drift that never converged.
#[test]
fn assembled_schemeless_proxy_diffs_clean_against_a_resolved_live_gateway() {
    use gitforgeops::config::assemble;

    let resource: Resource = serde_yaml::from_str(
        "kind: Proxy\nspec:\n  id: p1\n  listen_path: /api\n  backend_host: localhost\n  backend_port: 8080\n",
    )
    .unwrap();
    let desired = assemble(vec![("ferrum".to_string(), resource)])
        .expect("assemble")
        .gateway;

    // What `GET /backup` returns for that proxy: same fields, scheme resolved.
    let mut live_proxy = desired.proxies[0].clone();
    live_proxy.backend_scheme = Some(BackendScheme::Https);
    let actual = GatewayConfig {
        proxies: vec![live_proxy],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual).unwrap();
    assert!(
        diffs.is_empty(),
        "assembled desired config must converge with the live gateway: {diffs:?}"
    );
}

#[test]
fn breaking_detects_upstream_subset_change() {
    let reasons = breaking_reasons_for_proxy_change(|p| {
        p.upstream_id = Some("pool-a".to_string());
        p.upstream_subset = Some("canary".to_string());
    });
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("upstream_subset") && r.contains("reroute")),
        "expected an upstream_subset breaking change, got {reasons:?}"
    );
}

#[test]
fn breaking_detects_listen_port_change() {
    let reasons = breaking_reasons_for_proxy_change(|p| {
        p.backend_scheme = Some(BackendScheme::Tcp);
        p.listen_port = Some(15432);
    });
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("listen_port") && r.contains("listener")),
        "expected a listen_port breaking change, got {reasons:?}"
    );
}

#[test]
fn breaking_detects_frontend_tls_flip() {
    let reasons = breaking_reasons_for_proxy_change(|p| p.frontend_tls = true);
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("frontend_tls") && r.contains("false -> true")),
        "expected a frontend_tls breaking change naming the direction, got {reasons:?}"
    );
}

#[test]
fn breaking_detects_passthrough_flip() {
    let reasons = breaking_reasons_for_proxy_change(|p| p.passthrough = true);
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("passthrough") && r.contains("false -> true")),
        "expected a passthrough breaking change naming the direction, got {reasons:?}"
    );
}

#[test]
fn breaking_ignores_non_breaking_proxy_edit() {
    // A pure timeout bump is a modify, but nothing about it is breaking.
    let reasons = breaking_reasons_for_proxy_change(|p| p.backend_read_timeout_ms = 45_000);
    assert!(
        reasons.is_empty(),
        "timeout change should not be breaking, got {reasons:?}"
    );
}

#[test]
fn breaking_auth_plugin_deletion_scoped_by_namespace() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        plugin_configs: vec![
            make_plugin_config("plugin-shared", "team-alpha", "jwt", PluginScope::Proxy),
            make_plugin_config(
                "plugin-shared",
                "team-beta",
                "fake-auth-bypass",
                PluginScope::Proxy,
            ),
        ],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual).unwrap();
    let breaking = detect_breaking_changes(&diffs, &desired, &actual);

    // Only the team-alpha deletion should be flagged as breaking — the
    // team-beta plugin with the same id contains "auth" in its name but is
    // not on the auth allowlist.
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

/// A policy whose `require_auth_plugin.auth_plugin_names` allowlist is `names`.
fn auth_policy(names: &[&str]) -> gitforgeops::policy::PolicyConfig {
    use gitforgeops::policy::config::{PolicyConfig, PolicyRules, RequireAuthPluginRuleConfig};

    PolicyConfig {
        policies: PolicyRules {
            require_auth_plugin: RequireAuthPluginRuleConfig {
                auth_plugin_names: names.iter().map(|name| name.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Runs `desired` vs `actual` plugin configs through diff + breaking detection
/// and returns the PluginConfig breaking reasons.
fn plugin_breaking_reasons(
    desired: Vec<PluginConfig>,
    actual: Vec<PluginConfig>,
    policy: Option<&gitforgeops::policy::PolicyConfig>,
) -> Vec<String> {
    let desired = GatewayConfig {
        plugin_configs: desired,
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        plugin_configs: actual,
        ..GatewayConfig::default()
    };
    let diffs = compute_diff(&desired, &actual).unwrap();
    gitforgeops::diff::detect_breaking_changes_with_policy(&diffs, &desired, &actual, policy)
        .into_iter()
        .filter(|bc| bc.kind == "PluginConfig")
        .map(|bc| bc.reason)
        .collect()
}

/// Runs a single plugin config through a Modify where only `mutate` differs.
fn plugin_modify_reasons(
    actual_plugin: PluginConfig,
    mutate: impl Fn(&mut PluginConfig),
    policy: Option<&gitforgeops::policy::PolicyConfig>,
) -> Vec<String> {
    let mut desired_plugin = actual_plugin.clone();
    mutate(&mut desired_plugin);
    plugin_breaking_reasons(vec![desired_plugin], vec![actual_plugin], policy)
}

#[test]
fn breaking_without_policy_falls_back_to_builtin_auth_names() {
    let actual = GatewayConfig {
        plugin_configs: vec![
            make_plugin_config("auth", "ferrum", "key_auth", PluginScope::Global),
            make_plugin_config("custom", "ferrum", "acme_auth", PluginScope::Global),
        ],
        ..GatewayConfig::default()
    };
    let desired = GatewayConfig::default();
    let diffs = compute_diff(&desired, &actual).unwrap();

    let default_breaking = detect_breaking_changes(&diffs, &desired, &actual);
    let no_policy_breaking =
        gitforgeops::diff::detect_breaking_changes_with_policy(&diffs, &desired, &actual, None);

    // Without a policy only the built-in authenticator counts; an unlisted
    // custom name is not an authenticator.
    for breaking in [default_breaking, no_policy_breaking] {
        let entries: Vec<(&str, &str)> = breaking
            .iter()
            .map(|bc| (bc.id.as_str(), bc.reason.as_str()))
            .collect();
        assert_eq!(entries, vec![("auth", "Auth plugin deleted")]);
    }
}

#[test]
fn breaking_detects_configured_custom_auth_plugin_deletion() {
    let policy = auth_policy(&["acme_auth"]);
    let sso = make_plugin_config("sso", "ferrum", "acme_auth", PluginScope::Global);
    let reasons = plugin_breaking_reasons(vec![], vec![sso], Some(&policy));
    assert_eq!(reasons, vec!["Auth plugin deleted".to_string()]);
}

#[test]
fn breaking_auth_classification_follows_the_policy_allowlist_case_insensitively() {
    // The configured allowlist replaces the defaults, exactly as it does for
    // `require_auth_plugin` and the security audit.
    let policy = auth_policy(&["ACME_AUTH"]);
    let reasons = plugin_breaking_reasons(
        vec![],
        vec![
            make_plugin_config("sso", "ferrum", "acme_auth", PluginScope::Global),
            make_plugin_config("keys", "ferrum", "key_auth", PluginScope::Global),
        ],
        Some(&policy),
    );
    assert_eq!(reasons, vec!["Auth plugin deleted".to_string()]);
}

#[test]
fn breaking_detects_builtin_auth_plugin_disabled() {
    let reasons = plugin_modify_reasons(
        make_plugin_config("auth", "ferrum", "key_auth", PluginScope::Global),
        |p| p.enabled = false,
        None,
    );
    assert_eq!(
        reasons.len(),
        1,
        "expected one breaking entry, got {reasons:?}"
    );
    assert!(
        reasons[0].contains("Auth plugin disabled") && reasons[0].contains("true -> false"),
        "expected a disabled-authenticator entry, got {reasons:?}"
    );
}

#[test]
fn breaking_detects_configured_custom_auth_plugin_disabled() {
    let policy = auth_policy(&["acme_auth"]);
    let reasons = plugin_modify_reasons(
        make_plugin_config("sso", "ferrum", "acme_auth", PluginScope::Global),
        |p| p.enabled = false,
        Some(&policy),
    );
    assert!(
        reasons.iter().any(|r| r.contains("Auth plugin disabled")),
        "expected a disabled-authenticator entry, got {reasons:?}"
    );
}

#[test]
fn breaking_detects_auth_plugin_name_change() {
    let reasons = plugin_modify_reasons(
        make_plugin_config("auth", "ferrum", "key_auth", PluginScope::Global),
        |p| p.plugin_name = "rate_limiting".to_string(),
        None,
    );
    assert_eq!(
        reasons.len(),
        1,
        "expected one breaking entry, got {reasons:?}"
    );
    assert!(
        reasons[0].contains("plugin_name changed")
            && reasons[0].contains("key_auth -> rate_limiting"),
        "expected a plugin_name change naming the direction, got {reasons:?}"
    );
}

#[test]
fn breaking_ignores_benign_plugin_config_modifications() {
    // A non-auth plugin being disabled or renamed does not strand clients.
    let reasons = plugin_modify_reasons(
        make_plugin_config("limits", "ferrum", "rate_limiting", PluginScope::Global),
        |p| {
            p.enabled = false;
            p.config = serde_json::json!({"requests_per_second": 10});
        },
        None,
    );
    assert!(
        reasons.is_empty(),
        "non-auth modify is not breaking: {reasons:?}"
    );

    // An auth plugin that stays enabled under the same name is not breaking
    // when only its settings change.
    let reasons = plugin_modify_reasons(
        make_plugin_config("auth", "ferrum", "key_auth", PluginScope::Global),
        |p| {
            p.priority_override = Some(1100);
            p.config = serde_json::json!({"key_location": "header:x-api-key"});
        },
        None,
    );
    assert!(
        reasons.is_empty(),
        "auth settings edit is not breaking: {reasons:?}"
    );

    // Re-enabling or renaming an authenticator that was already disabled
    // live cannot strand anything that currently authenticates.
    let mut disabled = make_plugin_config("auth", "ferrum", "key_auth", PluginScope::Global);
    disabled.enabled = false;
    let reasons = plugin_modify_reasons(
        disabled,
        |p| p.plugin_name = "rate_limiting".to_string(),
        None,
    );
    assert!(
        reasons.is_empty(),
        "already-disabled auth is not breaking: {reasons:?}"
    );
}

/// Two proxies in `ferrum`; `orders` carries `orders_plugins` verbatim.
fn auth_coverage_config(orders_plugins: &str, plugin_configs: &str) -> GatewayConfig {
    let yaml = format!(
        "proxies:
  - id: orders
    listen_path: /orders
    backend_scheme: https
    backend_host: orders.internal
    backend_port: 443
    {orders_plugins}
  - id: payments
    listen_path: /payments
    backend_scheme: https
    backend_host: payments.internal
    backend_port: 443
plugin_configs:
{plugin_configs}"
    );
    let mut config: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
    gitforgeops::config::assembler::normalize_proxy_plugin_associations(&mut config);
    config
}

fn auth_coverage_reasons(desired: &GatewayConfig, actual: &GatewayConfig) -> Vec<String> {
    let diffs = compute_diff(desired, actual).unwrap();
    detect_breaking_changes(&diffs, desired, actual)
        .into_iter()
        .map(|bc| bc.reason)
        .collect()
}

const PROXY_GROUP_KEY_AUTH: &str = "  - id: sso
    plugin_name: key_auth
    scope: proxy_group
";

const GLOBAL_KEY_AUTH: &str = "  - id: sso
    plugin_name: key_auth
    scope: global
";

const KEY_AUTH_ON_PAYMENTS: &str = "  - id: sso
    plugin_name: key_auth
    scope: proxy
    proxy_id: payments
";

#[test]
fn breaking_detects_proxy_group_auth_association_removed() {
    let actual = auth_coverage_config("plugins: [{plugin_config_id: sso}]", PROXY_GROUP_KEY_AUTH);
    let desired = auth_coverage_config("", PROXY_GROUP_KEY_AUTH);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].starts_with("proxy ferrum/orders loses authenticator key_auth")
            && reasons[0].contains("no enabled authenticator"),
        "{reasons:?}"
    );
}

#[test]
fn breaking_detects_proxy_scoped_auth_retargeted_to_another_proxy() {
    let actual = auth_coverage_config(
        "",
        "  - id: sso
    plugin_name: key_auth
    scope: proxy
    proxy_id: orders
",
    );
    let desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(
        reasons,
        vec![
            "proxy ferrum/orders loses authenticator key_auth — consumer credentials for it \
             no longer apply on this proxy, which is left with no enabled authenticator"
                .to_string()
        ]
    );
}

#[test]
fn breaking_detects_global_auth_narrowed_to_another_proxy() {
    let actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    let desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    let reasons = auth_coverage_reasons(&desired, &actual);
    // `payments` keeps key_auth (now scoped); only `orders` loses it.
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].starts_with("proxy ferrum/orders loses authenticator key_auth"),
        "{reasons:?}"
    );
}

#[test]
fn breaking_names_only_the_lost_authenticator_when_others_remain() {
    let plugins = "  - id: sso
    plugin_name: key_auth
    scope: proxy_group
  - id: jwt
    plugin_name: jwt_auth
    scope: global
";
    let actual = auth_coverage_config("plugins: [{plugin_config_id: sso}]", plugins);
    let desired = auth_coverage_config("", plugins);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].contains("loses authenticator key_auth")
            && !reasons[0].contains("no enabled authenticator"),
        "{reasons:?}"
    );
}

#[test]
fn breaking_ignores_swapping_an_authenticator_for_another_of_the_same_name() {
    let plugins = "  - id: sso
    plugin_name: key_auth
    scope: proxy_group
  - id: sso-v2
    plugin_name: key_auth
    scope: proxy_group
";
    let actual = auth_coverage_config("plugins: [{plugin_config_id: sso}]", plugins);
    let desired = auth_coverage_config("plugins: [{plugin_config_id: sso-v2}]", plugins);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert!(reasons.is_empty(), "same authenticator kept: {reasons:?}");

    // Unchanged auth coverage is never reported.
    let reasons = auth_coverage_reasons(&actual, &actual);
    assert!(reasons.is_empty(), "{reasons:?}");
}

#[test]
fn breaking_does_not_repeat_a_plugin_level_auth_finding_per_proxy() {
    let actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    let desired = auth_coverage_config("", &format!("{GLOBAL_KEY_AUTH}    enabled: false\n"));
    let diffs = compute_diff(&desired, &actual).unwrap();
    let breaking = detect_breaking_changes(&diffs, &desired, &actual);
    let entries: Vec<(&str, &str)> = breaking
        .iter()
        .map(|bc| (bc.kind.as_str(), bc.id.as_str()))
        .collect();
    assert_eq!(entries, vec![("PluginConfig", "sso")], "{breaking:?}");
}

/// In shared mode a live global authenticator the repo never declared is
/// unmanaged and survives the apply, so no declared proxy loses it.
#[test]
fn breaking_ignores_undeclared_unmanaged_authenticator_in_shared_mode() {
    let actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    let desired = auth_coverage_config("", "  []\n");
    let managed = std::collections::HashSet::new();
    let result = compute_diff_with_scope(
        &desired,
        &actual,
        OwnershipScope::Shared {
            previously_managed: &managed,
        },
    )
    .unwrap();
    let breaking = detect_breaking_changes(&result.diffs, &desired, &actual);
    assert!(breaking.is_empty(), "{breaking:?}");
}

/// Diff `desired` against `actual` in shared mode with no prior ownership
/// state, returning the diff and the breaking reasons.
fn shared_auth_coverage_reasons(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
) -> (
    Vec<gitforgeops::diff::resource_diff::ResourceDiff>,
    Vec<String>,
) {
    let managed = std::collections::HashSet::new();
    let result = compute_diff_with_scope(
        desired,
        actual,
        OwnershipScope::Shared {
            previously_managed: &managed,
        },
    )
    .unwrap();
    let reasons = detect_breaking_changes(&result.diffs, desired, actual)
        .into_iter()
        .map(|bc| bc.reason)
        .collect();
    (result.diffs, reasons)
}

const ORDERS_LEFT_WITHOUT_KEY_AUTH: &str = "proxy ferrum/orders loses authenticator key_auth \
     — consumer credentials for it no longer apply on this proxy, which is left with no \
     enabled authenticator";

/// In shared mode a live proxy the repo does not declare is unmanaged and
/// survives the apply, yet a managed global authenticator still decides its
/// effective plugin list. Narrowing that global strands the proxy exactly as
/// it would a declared one.
#[test]
fn breaking_detects_auth_loss_on_surviving_unmanaged_proxy_in_shared_mode() {
    let actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    let mut desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    desired.proxies.retain(|p| p.id != "orders");

    let (diffs, reasons) = shared_auth_coverage_reasons(&desired, &actual);
    // orders is unmanaged: the apply neither writes nor deletes it.
    assert!(diffs.iter().all(|d| d.id != "orders"), "{diffs:?}");
    assert_eq!(reasons, vec![ORDERS_LEFT_WITHOUT_KEY_AUTH.to_string()]);
}

#[test]
fn breaking_shared_mode_controls_for_unmanaged_proxy_auth() {
    // Unchanged auth on a surviving unmanaged proxy is not a loss.
    let actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    let mut desired = actual.clone();
    desired.proxies.retain(|p| p.id != "orders");
    let (_, reasons) = shared_auth_coverage_reasons(&desired, &actual);
    assert!(reasons.is_empty(), "{reasons:?}");

    // A declared proxy is reported the same way in shared mode.
    let desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    let (_, reasons) = shared_auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons, vec![ORDERS_LEFT_WITHOUT_KEY_AUTH.to_string()]);
}

/// A proxy the diff deletes is reported as deleted, not as losing its
/// authenticators.
#[test]
fn breaking_skips_auth_coverage_for_deleted_proxies() {
    let actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    let mut desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    desired.proxies.retain(|p| p.id != "orders");
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons, vec!["Proxy deleted".to_string()]);
}

/// A live proxy an OpenAPI spec import owns is never deleted or written by
/// the repo, whether or not the repo declares it, so it survives the apply
/// in its live shape. Narrowing the managed global authenticator away from it
/// is still an authentication loss.
#[test]
fn breaking_detects_auth_loss_on_retained_spec_owned_proxy() {
    let mut actual = auth_coverage_config("", GLOBAL_KEY_AUTH);
    actual.proxies[0].api_spec_id = Some("spec-orders".to_string());

    // Undeclared: the diff retains the spec-owned row instead of deleting it.
    let mut desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    desired.proxies.retain(|p| p.id != "orders");
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert!(diffs.iter().all(|d| d.id != "orders"), "{diffs:?}");
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons, vec![ORDERS_LEFT_WITHOUT_KEY_AUTH.to_string()]);

    // Declared: the spec-owned row is an ownership conflict, not a Modify, so
    // it keeps its live shape and the loss is reported the same way.
    let desired = auth_coverage_config("", KEY_AUTH_ON_PAYMENTS);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons, vec![ORDERS_LEFT_WITHOUT_KEY_AUTH.to_string()]);
}

/// `orders` (the first proxy) as a TCP stream proxy that terminates TLS.
fn stream_orders_config(plugin_configs: &str) -> GatewayConfig {
    let mut config = auth_coverage_config("", plugin_configs);
    let orders = &mut config.proxies[0];
    orders.backend_scheme = Some(BackendScheme::Tcp);
    orders.listen_path = None;
    orders.listen_port = Some(19001);
    orders.frontend_tls = true;
    config
}

/// A TCP listener never runs `key_auth` (Ferrum Edge v0.9.7 declares it for
/// HTTP-family protocols only), so narrowing it away from the stream proxy
/// removes nothing that authenticated its connections.
#[test]
fn breaking_ignores_losing_an_authenticator_the_listener_never_ran() {
    let actual = stream_orders_config(GLOBAL_KEY_AUTH);
    let desired = stream_orders_config(KEY_AUTH_ON_PAYMENTS);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert!(reasons.is_empty(), "{reasons:?}");

    // mtls_auth does run on the listener, so losing it is reported.
    let actual = stream_orders_config(
        "  - id: sso
    plugin_name: mtls_auth
    scope: global
",
    );
    let desired = stream_orders_config(
        "  - id: sso
    plugin_name: mtls_auth
    scope: proxy
    proxy_id: payments
",
    );
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].starts_with("proxy ferrum/orders loses authenticator mtls_auth"),
        "{reasons:?}"
    );
}

/// soap_ws_security runs on plain HTTP only, so a proxy left with just it
/// serves gRPC and WebSocket requests unauthenticated.
#[test]
fn breaking_reports_protocols_left_unauthenticated() {
    let plugins = "  - id: sso
    plugin_name: key_auth
    scope: proxy_group
  - id: soap
    plugin_name: soap_ws_security
    scope: global
";
    let actual = auth_coverage_config("plugins: [{plugin_config_id: sso}]", plugins);
    let desired = auth_coverage_config("", plugins);
    let reasons = auth_coverage_reasons(&desired, &actual);
    assert_eq!(
        reasons,
        vec![
            "proxy ferrum/orders loses authenticator key_auth — consumer credentials for it \
             no longer apply on this proxy, which leaves its gRPC, WebSocket requests \
             unauthenticated"
                .to_string()
        ]
    );
}

#[test]
fn security_detects_literal_credential() {
    let mut creds = std::collections::BTreeMap::new();
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
fn secret_audit_and_broker_parser_agree_across_resource_kinds() {
    for value in [
        "${{ secrets.SYNTHETIC_KEY }}",
        "${gh-env-secret:alloc=generate} ",
        "${gh-env-secret:alloc=generate",
        "${GH-ENV-SECRET:alloc=generate}",
        "${env:SYNTHETIC_KEY}",
        "${gh-env-secret:alloc=synthetic-secret}",
        "${gh-env-secret:len=synthetic-secret}",
        "${gh-env-secret:synthetic-secret}",
        "${gh-env-secret:synthetic-secret=value}",
        "${gh-env-secret:alloc=require}",
        "${gh-env-secret:alloc=generate|len=64}",
    ] {
        let valid = matches!(gitforgeops::secrets::parse_placeholder(value), Some(Ok(_)));
        let mut consumer = make_consumer("app", "alice");
        consumer.credentials.clear();
        consumer
            .credentials
            .insert("keyauth".to_string(), serde_json::json!([{"key": value}]));
        let mut plugin = make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
        plugin.config = serde_json::json!({"authorization": value});
        let config = GatewayConfig {
            consumers: vec![consumer],
            plugin_configs: vec![plugin],
            upstreams: vec![upstream_with_consul(
                "orders",
                "https://consul.example.test",
                Some(value),
            )],
            ..GatewayConfig::default()
        };
        let findings = audit_security(&config);
        let blockers = gitforgeops::diff::security_blockers(&findings);
        assert_eq!(blockers.len(), if valid { 0 } else { 3 }, "{findings:?}");
        if !valid {
            for (kind, path) in [
                ("Consumer", "keyauth[0].key"),
                ("PluginConfig", "config.authorization"),
                ("Upstream", "service_discovery.consul.token"),
            ] {
                assert!(blockers
                    .iter()
                    .any(|finding| { finding.kind == kind && finding.message.contains(path) }));
            }
        }
        for finding in findings {
            assert!(!finding.message.contains(value));
            assert!(!finding.message.contains("synthetic-secret"));
        }
    }
}

#[test]
fn security_blocks_classified_plugin_literals_without_exposing_values() {
    use gitforgeops::diff::security_blockers;

    for enabled in [true, false] {
        let mut plugin = make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
        plugin.enabled = enabled;
        plugin.config = serde_json::json!({
            "authorization": "Bearer synthetic-authorization",
            "headers": {"x-api-key": "synthetic-header-value"},
            "endpoint": "https://collector.example.test",
            "service_name": "ordinary-service"
        });
        let config = GatewayConfig {
            plugin_configs: vec![plugin],
            ..GatewayConfig::default()
        };
        let findings = audit_security(&config);
        let blockers = security_blockers(&findings);
        assert_eq!(blockers.len(), 3, "{findings:?}");
        for field in ["authorization", "headers.x-api-key", "endpoint"] {
            assert!(blockers.iter().any(|finding| {
                finding.kind == "PluginConfig"
                    && finding.id == "otel"
                    && finding.message.contains(&format!("config.{field}"))
            }));
        }
        for finding in findings {
            for value in [
                "synthetic-authorization",
                "synthetic-header-value",
                "collector.example.test",
            ] {
                assert!(!finding.message.contains(value));
            }
        }
    }
}

#[test]
fn security_accepts_brokered_plugin_fields_and_unclassified_settings() {
    use gitforgeops::diff::security_blockers;

    let mut plugin = make_plugin_config("otel", "ferrum", "otel_tracing", PluginScope::Global);
    plugin.config = serde_json::json!({
        "authorization": "${gh-env-secret:alloc=require}",
        "headers": {"x-api-key": "${gh-env-secret:alloc=require}"},
        "endpoint": "${gh-env-secret:alloc=require}",
        "service_name": "ordinary-service"
    });
    let config = GatewayConfig {
        plugin_configs: vec![plugin],
        ..GatewayConfig::default()
    };
    assert!(security_blockers(&audit_security(&config)).is_empty());
}

#[test]
fn security_blockers_selects_only_error_severity_findings() {
    use gitforgeops::diff::security_blockers;

    // A literal credential (error) alongside the warning every auth-less proxy
    // produces. `apply` must refuse on the first and not the second.
    let mut creds = std::collections::BTreeMap::new();
    creds.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "literal-secret-key"}]),
    );
    let config = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds,
            ..make_consumer("c1", "alice")
        }],
        proxies: vec![make_proxy("p1", "/a", "backend.internal")],
        ..GatewayConfig::default()
    };

    let findings = audit_security(&config);
    assert!(
        findings.iter().any(|f| f.severity == "warning"),
        "fixture must produce at least one non-blocking finding: {findings:?}"
    );

    let blockers = security_blockers(&findings);
    assert_eq!(blockers.len(), 1, "got {blockers:?}");
    assert_eq!(blockers[0].kind, "Consumer");
    assert!(blockers[0].message.contains("Literal credential"));
    assert!(blockers.iter().all(|f| f.severity == "error"));
}

#[test]
fn security_blockers_is_empty_for_a_brokered_consumer() {
    use gitforgeops::diff::security_blockers;

    // The supported on-disk form. Placeholders are repository data, not
    // secrets, so nothing here may block an apply.
    let mut creds = std::collections::BTreeMap::new();
    creds.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "${gh-env-secret:alloc=require}"}]),
    );
    let config = GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds,
            ..make_consumer("c1", "alice")
        }],
        ..GatewayConfig::default()
    };

    assert!(security_blockers(&audit_security(&config)).is_empty());
}

#[test]
fn security_blockers_is_empty_for_no_findings() {
    use gitforgeops::diff::security_blockers;

    assert!(security_blockers(&[]).is_empty());
}

/// Build a one-consumer config carrying `credentials` verbatim.
fn config_with_credentials(entries: &[(&str, serde_json::Value)]) -> GatewayConfig {
    let mut creds = std::collections::BTreeMap::new();
    for (credential_type, value) in entries {
        creds.insert(credential_type.to_string(), value.clone());
    }
    GatewayConfig {
        consumers: vec![Consumer {
            credentials: creds,
            ..make_consumer("app", "app")
        }],
        ..GatewayConfig::default()
    }
}

/// The blocking messages an audit produced, for readable assertions.
fn literal_credential_blockers(config: &GatewayConfig) -> Vec<String> {
    use gitforgeops::diff::{audit_security_with_policy, security_blockers};

    security_blockers(&audit_security_with_policy(config, None))
        .into_iter()
        .filter(|f| f.message.contains("Literal credential"))
        .map(|f| f.message.clone())
        .collect()
}

#[test]
fn mtls_auth_identity_is_not_a_literal_secret() {
    // The issue's first reproduction, verbatim: an ordinary mTLS consumer.
    // `identity` is a certificate CN/SAN, the public half of the credential,
    // and the broker cannot generate one — blocking on it made a supported
    // declaration un-appliable.
    let config = config_with_credentials(&[(
        "mtls_auth",
        serde_json::json!([{"identity": "client.example"}]),
    )]);

    assert!(
        literal_credential_blockers(&config).is_empty(),
        "mtls_auth identity must not block apply: {:?}",
        literal_credential_blockers(&config)
    );
}

#[test]
fn basicauth_username_is_an_identity_but_its_secret_halves_still_block() {
    // The issue's second reproduction: an imported Basic-auth consumer whose
    // username is legible and whose secret half is brokered.
    let brokered = config_with_credentials(&[(
        "basicauth",
        serde_json::json!([{
            "username": "alice",
            "password_hash": "${gh-env-secret:alloc=require}"
        }]),
    )]);
    assert!(
        literal_credential_blockers(&brokered).is_empty(),
        "a brokered password beside a literal username must apply: {:?}",
        literal_credential_blockers(&brokered)
    );

    // The exemption is per-leaf, not per-credential: the same consumer with a
    // committed hash is still a committed secret.
    let committed = config_with_credentials(&[(
        "basicauth",
        serde_json::json!([{"username": "alice", "password_hash": "hmac_sha256:deadbeef"}]),
    )]);
    let blockers = literal_credential_blockers(&committed);
    assert_eq!(blockers.len(), 1, "{blockers:?}");
    assert!(
        blockers[0].contains("basicauth[0].password_hash"),
        "the finding must name the secret leaf, not the username: {}",
        blockers[0]
    );

    // Plaintext `password` is the other secret half of the same object.
    let plaintext = config_with_credentials(&[(
        "basicauth",
        serde_json::json!([{"username": "alice", "password": "hunter2"}]),
    )]);
    let blockers = literal_credential_blockers(&plaintext);
    assert_eq!(blockers.len(), 1, "{blockers:?}");
    assert!(
        blockers[0].contains("basicauth[0].password"),
        "{blockers:?}"
    );
}

#[test]
fn every_other_credential_secret_still_blocks() {
    // The gate this narrows exists for these. Each is a real secret leaf on
    // one of ferrum-edge's five credential types.
    for (credential_type, value, expected_path) in [
        (
            "keyauth",
            serde_json::json!([{"key": "live-api-key"}]),
            "keyauth[0].key",
        ),
        (
            // The `jwt` key id is deliberately NOT exempt: the exemption list
            // is exactly `basicauth[].username` and `mtls_auth[].identity`,
            // the two leaves ferrum-edge documents as public halves. Here the
            // kid is brokered so the assertion is about `secret` alone.
            "jwt",
            serde_json::json!([{
                "key": "${gh-env-secret:alloc=require}",
                "secret": "a-committed-jwt-signing-secret"
            }]),
            "jwt[0].secret",
        ),
        (
            "hmac_auth",
            serde_json::json!([{"secret": "a-committed-hmac-secret"}]),
            "hmac_auth[0].secret",
        ),
        (
            "mtls_auth",
            serde_json::json!([{"identity": "client.example", "secret": "not-an-identity"}]),
            "mtls_auth[0].secret",
        ),
    ] {
        let config = config_with_credentials(&[(credential_type, value)]);
        let blockers = literal_credential_blockers(&config);
        assert_eq!(
            blockers.len(),
            1,
            "{credential_type} must contribute exactly one blocker: {blockers:?}"
        );
        assert!(
            blockers[0].contains(expected_path),
            "expected {expected_path}: {}",
            blockers[0]
        );
    }
}

#[test]
fn unknown_credential_types_block_before_leaf_classification() {
    use gitforgeops::diff::security_blockers;

    let api_key = config_with_credentials(&[(
        "api_key",
        serde_json::json!([{"key": "${gh-env-secret:alloc=require}"}]),
    )]);
    let api_findings = audit_security(&api_key);
    let api_blockers = security_blockers(&api_findings);
    assert_eq!(api_blockers.len(), 1, "{api_blockers:?}");
    assert_eq!(api_blockers[0].severity, "error");
    assert_eq!(api_blockers[0].kind, "Consumer");
    assert_eq!(api_blockers[0].id, "app");
    assert_eq!(api_blockers[0].namespace, "ferrum");
    assert!(
        api_blockers[0]
            .message
            .contains("Unknown credential type 'api_key'"),
        "{}",
        api_blockers[0].message
    );
    assert!(
        api_blockers[0]
            .message
            .contains("on consumer app in namespace ferrum"),
        "{}",
        api_blockers[0].message
    );
    assert!(
        api_blockers[0].message.contains("did you mean 'keyauth'"),
        "{}",
        api_blockers[0].message
    );
    for known in ["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"] {
        assert!(
            api_blockers[0].message.contains(known),
            "recognized set must name {known}: {}",
            api_blockers[0].message
        );
    }

    let basic_auth = config_with_credentials(&[(
        "basic_auth",
        serde_json::json!([{"password": "${gh-env-secret:alloc=require}"}]),
    )]);
    let basic_findings = audit_security(&basic_auth);
    let basic_blockers = security_blockers(&basic_findings);
    assert_eq!(basic_blockers.len(), 1, "{basic_blockers:?}");
    assert!(
        basic_blockers[0]
            .message
            .contains("did you mean 'basicauth'"),
        "{}",
        basic_blockers[0].message
    );

    let vendor = config_with_credentials(&[(
        "vendor_token",
        serde_json::json!([{"username": "alice", "identity": "client.example"}]),
    )]);
    let vendor_findings = audit_security(&vendor);
    let vendor_blockers = security_blockers(&vendor_findings);
    assert_eq!(vendor_blockers.len(), 1, "{vendor_blockers:?}");
    assert!(
        vendor_blockers[0]
            .message
            .contains("Unknown credential type 'vendor_token'"),
        "{}",
        vendor_blockers[0].message
    );
    assert!(
        !vendor_blockers[0].message.contains("did you mean"),
        "{}",
        vendor_blockers[0].message
    );
    assert!(
        !vendor_blockers
            .iter()
            .any(|finding| finding.message.contains("Literal credential")),
        "unknown types fail on the map key, not each leaf: {vendor_blockers:?}"
    );
}

#[test]
fn the_identity_exemption_survives_extra_entries_and_the_object_form() {
    // Slot identity is positional, so entry 1 must be treated exactly like
    // entry 0 — an array index does not change which field a leaf is.
    let multi = config_with_credentials(&[(
        "basicauth",
        serde_json::json!([
            {"username": "alice", "password": "${gh-env-secret:alloc=require}"},
            {"username": "bob", "password": "${gh-env-secret:alloc=require}"},
        ]),
    )]);
    assert!(
        literal_credential_blockers(&multi).is_empty(),
        "{:?}",
        literal_credential_blockers(&multi)
    );

    // The bare-object form the assembler normalizes on load. The audit does
    // not depend on that normalization having happened.
    let object_form = config_with_credentials(&[
        (
            "mtls_auth",
            serde_json::json!({"identity": "client.example"}),
        ),
        (
            "basicauth",
            serde_json::json!({"username": "alice", "password": "${gh-env-secret:alloc=require}"}),
        ),
    ]);
    assert!(
        literal_credential_blockers(&object_form).is_empty(),
        "{:?}",
        literal_credential_blockers(&object_form)
    );

    // A bare string with no enclosing key is not an identity leaf: nothing
    // says which field it is, so it fails closed.
    let bare = config_with_credentials(&[("mtls_auth", serde_json::json!("client.example"))]);
    assert_eq!(literal_credential_blockers(&bare).len(), 1);
}

#[test]
fn security_detects_nested_literal_credential() {
    let mut creds = std::collections::BTreeMap::new();
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
fn security_passes_broker_template_credential() {
    let mut creds = std::collections::BTreeMap::new();
    creds.insert(
        "keyauth".to_string(),
        serde_json::json!({"key": "${gh-env-secret:alloc=require}"}),
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
    // Regression guard: audit_security classifies any string that isn't a
    // valid broker placeholder as a literal credential. If the caller (cmd_plan,
    // cmd_review) runs audit AFTER resolve_secrets, legitimate placeholders
    // have been replaced with real values and the auditor spuriously flags
    // them as literal credentials — drowning real findings in noise.
    //
    // This test verifies the invariant by simulating both orderings.

    // Pre-resolve: placeholder in the config. Audit sees a ${...} string.
    let mut creds_pre = std::collections::BTreeMap::new();
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
    let mut creds_post = std::collections::BTreeMap::new();
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
    // The check is scheme-aware: the gateway rejects
    // `backend_tls_verify_server_cert: false` outright on plaintext schemes,
    // so only a TLS-capable scheme makes the flag meaningful.
    proxy.backend_scheme = Some(BackendScheme::Https);
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
fn security_audit_uses_auth_allowlist() {
    let proxy = make_proxy("p1", "/api", "localhost");

    let jwt_config = GatewayConfig {
        proxies: vec![proxy.clone()],
        plugin_configs: vec![make_plugin_config(
            "global-auth",
            "ferrum",
            "jwt_auth",
            PluginScope::Global,
        )],
        ..GatewayConfig::default()
    };
    let jwt_findings = audit_security(&jwt_config);
    assert!(!jwt_findings
        .iter()
        .any(|f| f.message.contains("No auth plugin")));

    let fake_auth_config = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![make_plugin_config(
            "global-auth",
            "ferrum",
            "fake-auth-bypass",
            PluginScope::Global,
        )],
        ..GatewayConfig::default()
    };
    let fake_auth_findings = audit_security(&fake_auth_config);
    assert!(fake_auth_findings
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

/// Service discovery supplies targets at runtime, so an upstream that uses it
/// is not told to "attach service discovery" for having few static targets.
#[test]
fn best_practice_skips_target_count_for_service_discovery_upstream() {
    let config = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "u1",
            "https://consul.internal:8500",
            None,
        )],
        ..GatewayConfig::default()
    };
    let checks = check_best_practices(&config);
    assert!(
        !checks
            .iter()
            .any(|c| c.message.contains("nothing to fail over to")),
        "{:?}",
        checks.iter().map(|c| &c.message).collect::<Vec<_>>()
    );
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
            // `request_logging` is not a gateway plugin — the observability
            // check matches the explicit built-in set, not a "logging"
            // substring.
            make_plugin_config(
                "global-logging",
                "team-alpha",
                "http_logging",
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

// --- Spec-owned classification across kinds ----------------------------------
//
// `api_spec_id` lives on Proxy, Upstream and PluginConfig (never Consumer —
// spec ingestion does not provision identities). These cover the per-kind
// wiring; the ownership-mode semantics live in ownership_tests.rs.

#[test]
fn spec_owned_upstream_is_not_pruned_by_plain_compute_diff() {
    // `compute_diff` is the plain exclusive entry point used by callers with
    // no ownership context — it must protect spec-owned rows too.
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        upstreams: vec![Upstream {
            api_spec_id: Some("spec-3".to_string()),
            ..make_upstream("u-from-spec", 1)
        }],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual).unwrap();
    assert!(
        diffs.is_empty(),
        "spec-owned upstream must not produce a Delete: {diffs:?}"
    );
}

#[test]
fn spec_owned_plugin_config_is_bucketed_not_deleted() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            api_spec_id: Some("spec-4".to_string()),
            ..make_plugin_config("pc-from-spec", "ferrum", "rate-limit", PluginScope::Global)
        }],
        ..GatewayConfig::default()
    };

    let result = compute_diff_with_scope(&desired, &actual, OwnershipScope::Exclusive).unwrap();
    assert!(result.diffs.is_empty(), "{:?}", result.diffs);
    assert_eq!(result.spec_owned.len(), 1);
    assert_eq!(result.spec_owned[0].kind, "PluginConfig");
    assert_eq!(result.spec_owned[0].api_spec_id, "spec-4");
}

#[test]
fn consumers_are_never_classified_as_spec_owned() {
    // Consumers carry no `api_spec_id`; an admin-added one in exclusive mode
    // stays an ordinary prune candidate.
    let desired = GatewayConfig::default();
    let actual = GatewayConfig {
        consumers: vec![make_consumer("c1", "alice")],
        ..GatewayConfig::default()
    };

    let result = compute_diff_with_scope(&desired, &actual, OwnershipScope::Exclusive).unwrap();
    assert!(result.spec_owned.is_empty());
    assert_eq!(result.diffs.len(), 1);
    assert!(matches!(result.diffs[0].action, DiffAction::Delete));
}

#[test]
fn spec_owned_upstream_declared_in_repo_suppresses_modify() {
    // Repo declares two targets, the spec-provisioned live row has one. That
    // is a Modify under normal ownership — here it must become a conflict.
    let desired = GatewayConfig {
        upstreams: vec![make_upstream("u-shared", 2)],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        upstreams: vec![Upstream {
            api_spec_id: Some("spec-3".to_string()),
            ..make_upstream("u-shared", 1)
        }],
        ..GatewayConfig::default()
    };

    let result = compute_diff_with_scope(&desired, &actual, OwnershipScope::Exclusive).unwrap();
    assert!(
        result.diffs.is_empty(),
        "no Modify against a spec-owned row: {:?}",
        result.diffs
    );
    let conflicts: Vec<_> = result.spec_conflicts().collect();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].kind, "Upstream");
    assert_eq!(conflicts[0].id, "u-shared");
}

// ---------------------------------------------------------------------------
// #126: the Consul ACL token inside `Upstream.service_discovery` is secret
// material, but the block around it is exactly the drift a reviewer is there
// to catch. Redaction is leaf-by-leaf, never field-wide.
// ---------------------------------------------------------------------------

fn upstream_with_consul(id: &str, address: &str, token: Option<&str>) -> Upstream {
    let mut upstream = make_upstream(id, 0);
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Consul,
        dns_sd: None,
        kubernetes: None,
        consul: Some(ConsulConfig {
            address: address.to_string(),
            service_name: "orders".to_string(),
            datacenter: None,
            tag: None,
            healthy_only: true,
            token: token.map(str::to_string),
            poll_interval_seconds: 30,
        }),
        mesh: None,
        max_stale_seconds: None,
        stale_policy: None,
        default_weight: 100,
    });
    upstream
}

#[test]
fn service_discovery_diff_redacts_the_token_but_shows_the_address() {
    let desired = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "orders",
            "https://consul.new.test:8501",
            Some("DESIRED-SYNTHETIC-TOKEN"),
        )],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "orders",
            "https://consul.old.test:8501",
            Some("LIVE-SYNTHETIC-TOKEN"),
        )],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual).unwrap();
    let change = diffs
        .iter()
        .flat_map(|diff| &diff.details)
        .find(|change| change.field == "service_discovery")
        .expect("the discovery block changed");

    for side in [&change.old_value, &change.new_value] {
        assert!(!side.contains("SYNTHETIC-TOKEN"), "{side}");
        assert!(side.contains("[REDACTED]"), "{side}");
    }
    assert!(
        change.old_value.contains("consul.old.test"),
        "{}",
        change.old_value
    );
    assert!(
        change.new_value.contains("consul.new.test"),
        "{}",
        change.new_value
    );
    assert!(change.new_value.contains("orders"), "{}", change.new_value);

    // Whole-field suppression stays reserved for the two fields that are
    // secret through and through.
    assert!(!is_sensitive_diff_field("Upstream", "service_discovery"));
}

/// Value text alone cannot establish whether either token is unresolved.
#[test]
fn service_discovery_diff_redacts_placeholder_shaped_tokens() {
    let desired = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "orders",
            "https://consul.new.test:8501",
            Some("${gh-env-secret:alloc=require}"),
        )],
        ..GatewayConfig::default()
    };
    let actual = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "orders",
            "https://consul.old.test:8501",
            Some("${gh-env-secret:alloc=require}"),
        )],
        ..GatewayConfig::default()
    };

    let diffs = compute_diff(&desired, &actual).unwrap();
    let change = diffs
        .iter()
        .flat_map(|diff| &diff.details)
        .find(|change| change.field == "service_discovery")
        .expect("the address changed");

    for side in [&change.old_value, &change.new_value] {
        assert!(!side.contains("gh-env-secret"), "{side}");
        assert!(side.contains("[REDACTED]"), "{side}");
    }
}

/// Bundle-less review: an unresolvable placeholder must not read as drift
/// against the gateway's real token, while the address still does.
#[test]
fn masking_aligns_the_discovery_token_only() {
    let desired = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "orders",
            "https://consul.new.test:8501",
            Some("${gh-env-secret:alloc=require}"),
        )],
        ..GatewayConfig::default()
    };
    let mut actual = GatewayConfig {
        upstreams: vec![upstream_with_consul(
            "orders",
            "https://consul.old.test:8501",
            Some("LIVE-SYNTHETIC-TOKEN"),
        )],
        ..GatewayConfig::default()
    };

    mask_without_bundle(&desired, &mut actual);

    let consul = actual.upstreams[0]
        .service_discovery
        .as_ref()
        .and_then(|sd| sd.consul.as_ref())
        .expect("consul block");
    assert_eq!(
        consul.token.as_deref(),
        Some("${gh-env-secret:alloc=require}")
    );
    assert_eq!(consul.address, "https://consul.old.test:8501");

    let diffs = compute_diff(&desired, &actual).unwrap();
    let change = diffs
        .iter()
        .flat_map(|diff| &diff.details)
        .find(|change| change.field == "service_discovery")
        .expect("the address is still drift");
    assert!(
        change.old_value.contains("consul.old.test"),
        "{}",
        change.old_value
    );
}
