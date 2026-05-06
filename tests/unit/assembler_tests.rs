use std::path::PathBuf;

use gitforgeops::config::{
    apply_overlay, assemble, filter_config_by_namespace, load_resources, schema::Resource,
    select_config_namespace, split_config_by_namespace, validate_unique_resource_keys,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple-config")
}

fn overlay_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/overlay-test")
}

#[test]
fn assemble_produces_gateway_config() {
    let resources = load_resources(&fixtures_dir()).unwrap();
    let config = assemble(resources);

    assert_eq!(config.version, "1");
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.consumers.len(), 1);
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.plugin_configs.len(), 1);
}

#[test]
fn assemble_sets_namespace_from_directory() {
    let resources = load_resources(&fixtures_dir()).unwrap();
    let config = assemble(resources);

    assert_eq!(config.proxies[0].namespace, "ferrum");
    assert_eq!(config.consumers[0].namespace, "ferrum");
    assert_eq!(config.upstreams[0].namespace, "ferrum");
    assert_eq!(config.plugin_configs[0].namespace, "ferrum");
}

#[test]
fn assemble_preserves_resource_ids() {
    let resources = load_resources(&fixtures_dir()).unwrap();
    let config = assemble(resources);

    assert_eq!(config.proxies[0].id, "proxy-httpbin");
    assert_eq!(config.consumers[0].id, "consumer-alice");
    assert_eq!(config.upstreams[0].id, "upstream-api");
    assert_eq!(config.plugin_configs[0].id, "plugin-keyauth");
}

#[test]
fn assemble_serializes_to_valid_yaml() {
    let resources = load_resources(&fixtures_dir()).unwrap();
    let config = assemble(resources);
    let yaml = serde_yaml::to_string(&config).unwrap();

    assert!(yaml.contains("proxy-httpbin"));
    assert!(yaml.contains("consumer-alice"));
    assert!(yaml.contains("upstream-api"));
    assert!(yaml.contains("plugin-keyauth"));
}

#[test]
fn overlay_merges_fields() {
    let mut resources = load_resources(&fixtures_dir()).unwrap();
    apply_overlay(&mut resources, &overlay_dir()).unwrap();
    let config = assemble(resources);

    let proxy = &config.proxies[0];
    assert_eq!(proxy.id, "proxy-httpbin");
    assert_eq!(proxy.backend_host, "httpbin-prod.internal");
    assert_eq!(proxy.backend_connect_timeout_ms, 3000);
    assert_eq!(proxy.backend_read_timeout_ms, 15000);
    // Original fields should be preserved
    assert_eq!(proxy.listen_path, Some("/httpbin".to_string()));
    assert!(proxy.strip_listen_path);
}

#[test]
fn overlay_nonexistent_dir_is_noop() {
    let mut resources = load_resources(&fixtures_dir()).unwrap();
    let original_len = resources.len();
    apply_overlay(&mut resources, &PathBuf::from("/nonexistent")).unwrap();
    assert_eq!(resources.len(), original_len);
}

#[test]
fn overlay_matches_by_kind_namespace_and_id() {
    let temp = tempfile::tempdir().unwrap();
    let overlay_path = temp.path().join("team-alpha/proxies");
    std::fs::create_dir_all(&overlay_path).unwrap();
    std::fs::write(
        overlay_path.join("shared.yaml"),
        r#"
kind: Proxy
spec:
  id: shared
  backend_host: overlayed.internal
"#,
    )
    .unwrap();

    let mut resources = vec![
        ("team-alpha".to_string(), make_consumer("shared")),
        ("team-alpha".to_string(), make_proxy("shared")),
        ("team-beta".to_string(), make_proxy("shared")),
    ];

    apply_overlay(&mut resources, temp.path()).unwrap();
    let config = assemble(resources);

    let alpha = config
        .proxies
        .iter()
        .find(|p| p.namespace == "team-alpha" && p.id == "shared")
        .unwrap();
    let beta = config
        .proxies
        .iter()
        .find(|p| p.namespace == "team-beta" && p.id == "shared")
        .unwrap();

    assert_eq!(alpha.backend_host, "overlayed.internal");
    assert_eq!(beta.backend_host, "localhost");
    assert_eq!(config.consumers[0].username, "shared");
}

#[test]
fn overlay_replaces_arrays_by_default_and_merges_additive_fields() {
    let temp = tempfile::tempdir().unwrap();
    let proxy_overlay_path = temp.path().join("team-alpha/proxies");
    let consumer_overlay_path = temp.path().join("team-alpha/consumers");
    let upstream_overlay_path = temp.path().join("team-alpha/upstreams");
    std::fs::create_dir_all(&proxy_overlay_path).unwrap();
    std::fs::create_dir_all(&consumer_overlay_path).unwrap();
    std::fs::create_dir_all(&upstream_overlay_path).unwrap();
    std::fs::write(
        proxy_overlay_path.join("shared.yaml"),
        r#"
kind: Proxy
spec:
  id: shared
  hosts:
    - overlay.example.com
  allowed_methods:
    - GET
  allowed_ws_origins:
    - https://prod.example.com
  plugins:
    - plugin_config_id: auth-overlay
"#,
    )
    .unwrap();
    std::fs::write(
        consumer_overlay_path.join("app.yaml"),
        r#"
kind: Consumer
spec:
  id: app
  acl_groups:
    - prod
"#,
    )
    .unwrap();
    std::fs::write(
        upstream_overlay_path.join("pool.yaml"),
        r#"
kind: Upstream
spec:
  id: pool
  targets:
    - host: base.internal
      port: 8080
      weight: 5
      tags:
        role: canary
    - host: overlay.internal
      port: 9090
"#,
    )
    .unwrap();

    let mut proxy = make_proxy("shared");
    if let Resource::Proxy { spec } = &mut proxy {
        spec.hosts.push("base.example.com".to_string());
        spec.allowed_methods = Some(vec!["GET".to_string(), "POST".to_string()]);
        spec.allowed_ws_origins
            .push("https://base.example.com".to_string());
        spec.plugins
            .push(gitforgeops::config::schema::PluginAssociation {
                plugin_config_id: "auth-base".to_string(),
            });
    }
    let mut consumer = make_consumer("app");
    if let Resource::Consumer { spec } = &mut consumer {
        spec.acl_groups = vec!["base".to_string(), "ops".to_string()];
    }

    let mut resources = vec![
        ("team-alpha".to_string(), proxy),
        ("team-alpha".to_string(), consumer),
        ("team-alpha".to_string(), make_upstream("pool")),
    ];

    apply_overlay(&mut resources, temp.path()).unwrap();
    let config = assemble(resources);

    let proxy = &config.proxies[0];
    assert_eq!(proxy.hosts, vec!["overlay.example.com"]);
    assert_eq!(proxy.allowed_methods, Some(vec!["GET".to_string()]));
    assert_eq!(
        proxy.allowed_ws_origins,
        vec!["https://prod.example.com".to_string()]
    );
    assert_eq!(proxy.plugins.len(), 2);
    assert_eq!(proxy.plugins[0].plugin_config_id, "auth-base");
    assert_eq!(proxy.plugins[1].plugin_config_id, "auth-overlay");

    assert_eq!(config.consumers[0].acl_groups, vec!["prod".to_string()]);

    let upstream = &config.upstreams[0];
    assert_eq!(upstream.targets.len(), 2);
    assert_eq!(upstream.targets[0].host, "base.internal");
    assert_eq!(upstream.targets[0].weight, 5);
    assert_eq!(upstream.targets[0].tags.get("role").unwrap(), "canary");
    assert_eq!(upstream.targets[1].host, "overlay.internal");
}

#[test]
fn overlay_rejects_kind_that_disagrees_with_directory() {
    let temp = tempfile::tempdir().unwrap();
    let overlay_path = temp.path().join("team-alpha/proxies");
    std::fs::create_dir_all(&overlay_path).unwrap();
    std::fs::write(
        overlay_path.join("bad.yaml"),
        r#"
kind: Upstream
spec:
  id: shared
"#,
    )
    .unwrap();

    let mut resources = vec![("team-alpha".to_string(), make_proxy("shared"))];
    let err = apply_overlay(&mut resources, temp.path())
        .unwrap_err()
        .to_string();

    assert!(
        err.contains("declares kind"),
        "expected kind mismatch error, got: {err}"
    );
}

#[test]
fn overlay_rejects_orphan_resource() {
    let temp = tempfile::tempdir().unwrap();
    let overlay_path = temp.path().join("team-alpha/proxies");
    std::fs::create_dir_all(&overlay_path).unwrap();
    std::fs::write(
        overlay_path.join("missing.yaml"),
        r#"
kind: Proxy
spec:
  id: missing
"#,
    )
    .unwrap();

    let mut resources = vec![("team-alpha".to_string(), make_proxy("present"))];
    let err = apply_overlay(&mut resources, temp.path())
        .unwrap_err()
        .to_string();

    assert!(
        err.contains("team-alpha/Proxy/missing"),
        "expected full overlay key in orphan error, got: {err}"
    );
}

#[test]
fn assemble_empty_resources() {
    let config = assemble(vec![]);
    assert!(config.proxies.is_empty());
    assert!(config.consumers.is_empty());
    assert!(config.upstreams.is_empty());
    assert!(config.plugin_configs.is_empty());
}

#[test]
fn multi_namespace_assembly() {
    let resources = vec![
        ("ferrum".to_string(), make_proxy("proxy-default")),
        ("team-alpha".to_string(), make_proxy("proxy-alpha")),
    ];
    let config = assemble(resources);

    assert_eq!(config.proxies.len(), 2);
    assert_eq!(config.proxies[0].namespace, "ferrum");
    assert_eq!(config.proxies[1].namespace, "team-alpha");
}

#[test]
fn namespace_filter_only_keeps_target_namespace() {
    let resources = vec![
        ("ferrum".to_string(), make_proxy("proxy-default")),
        ("team-alpha".to_string(), make_proxy("proxy-alpha")),
    ];
    let config = assemble(resources);
    let filtered = filter_config_by_namespace(&config, "team-alpha");

    assert_eq!(filtered.proxies.len(), 1);
    assert_eq!(filtered.proxies[0].id, "proxy-alpha");
    assert_eq!(filtered.proxies[0].namespace, "team-alpha");
}

#[test]
fn split_config_by_namespace_preserves_empty_filtered_namespace() {
    let config = assemble(vec![("ferrum".to_string(), make_proxy("proxy-default"))]);
    let split = split_config_by_namespace(&config, Some("team-alpha"));

    assert_eq!(split.len(), 1);
    assert_eq!(split[0].0, "team-alpha");
    assert!(split[0].1.proxies.is_empty());
}

#[test]
fn select_config_namespace_leaves_all_namespaces_when_unfiltered() {
    let resources = vec![
        ("ferrum".to_string(), make_proxy("proxy-default")),
        ("team-alpha".to_string(), make_proxy("proxy-alpha")),
    ];
    let config = assemble(resources);
    let selected = select_config_namespace(&config, None);

    assert_eq!(selected.proxies.len(), 2);
}

#[test]
fn validate_unique_resource_keys_rejects_duplicates() {
    let config = assemble(vec![
        ("ferrum".to_string(), make_proxy("same")),
        ("ferrum".to_string(), make_proxy("same")),
    ]);

    let err = validate_unique_resource_keys(&config)
        .unwrap_err()
        .to_string();

    assert!(
        err.contains("duplicate resource key"),
        "expected duplicate resource key error, got: {err}"
    );
}

#[test]
fn validate_unique_resource_keys_runs_after_namespace_selection() {
    let config = assemble(vec![
        ("ferrum".to_string(), make_proxy("ok")),
        ("team-alpha".to_string(), make_proxy("same")),
        ("team-alpha".to_string(), make_proxy("same")),
    ]);

    let selected = select_config_namespace(&config, Some("ferrum"));
    validate_unique_resource_keys(&selected).unwrap();
}

fn make_proxy(id: &str) -> Resource {
    use gitforgeops::config::schema::*;
    Resource::Proxy {
        spec: Proxy {
            id: id.to_string(),
            name: None,
            namespace: "ferrum".to_string(),
            hosts: vec![],
            listen_path: Some("/test".to_string()),
            backend_protocol: BackendProtocol::Http,
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
        },
    }
}

fn make_consumer(id: &str) -> Resource {
    use gitforgeops::config::schema::*;
    Resource::Consumer {
        spec: Consumer {
            id: id.to_string(),
            username: id.to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: Default::default(),
            acl_groups: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        },
    }
}

fn make_upstream(id: &str) -> Resource {
    use gitforgeops::config::schema::*;
    Resource::Upstream {
        spec: Upstream {
            id: id.to_string(),
            name: None,
            namespace: "ferrum".to_string(),
            targets: vec![UpstreamTarget {
                host: "base.internal".to_string(),
                port: 8080,
                weight: 1,
                tags: Default::default(),
                path: None,
            }],
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
        },
    }
}
