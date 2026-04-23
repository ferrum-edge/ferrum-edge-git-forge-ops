use std::path::PathBuf;

use gitforgeops::config::{apply_overlay, assemble, load_resources, schema::Resource};

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
