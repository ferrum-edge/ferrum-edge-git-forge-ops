use gitforgeops::config::schema::*;
use gitforgeops::import::split_config;
use std::path::PathBuf;

fn make_test_config() -> GatewayConfig {
    GatewayConfig {
        proxies: vec![Proxy {
            id: "proxy-test".to_string(),
            name: Some("Test".to_string()),
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
        }],
        consumers: vec![Consumer {
            id: "consumer-test".to_string(),
            username: "testuser".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: std::collections::HashMap::new(),
            acl_groups: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..GatewayConfig::default()
    }
}

#[test]
fn split_config_creates_resource_files() {
    let tmp = tempfile::tempdir().unwrap();
    let config = make_test_config();
    let result = split_config(&config, tmp.path()).unwrap();

    assert_eq!(result.proxies, 1);
    assert_eq!(result.consumers, 1);

    let proxy_path = tmp.path().join("ferrum/proxies/proxy-test.yaml");
    assert!(proxy_path.exists(), "proxy file should be created");

    let consumer_path = tmp.path().join("ferrum/consumers/consumer-test.yaml");
    assert!(consumer_path.exists(), "consumer file should be created");
}

#[test]
fn split_config_produces_loadable_files() {
    let tmp = tempfile::tempdir().unwrap();
    let config = make_test_config();
    split_config(&config, tmp.path()).unwrap();

    let resources = gitforgeops::config::load_resources(tmp.path()).unwrap();
    assert_eq!(resources.len(), 2);
}

#[test]
fn split_config_empty_config() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GatewayConfig::default();
    let result = split_config(&config, tmp.path()).unwrap();

    assert_eq!(result.proxies, 0);
    assert_eq!(result.consumers, 0);
    assert_eq!(result.upstreams, 0);
    assert_eq!(result.plugin_configs, 0);
}

#[test]
fn split_config_rejects_path_traversal_in_namespace() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.proxies[0].namespace = "../evil".to_string();

    let err = split_config(&config, tmp.path()).unwrap_err();
    assert!(
        err.to_string().contains("unsafe"),
        "expected path-traversal rejection, got: {err}"
    );

    let escaped = tmp.path().parent().unwrap().join("evil");
    assert!(
        !escaped.exists(),
        "namespace traversal must not create files outside output_dir"
    );
}

#[test]
fn split_config_rejects_path_traversal_in_id() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.proxies[0].id = "../escape".to_string();

    let err = split_config(&config, tmp.path()).unwrap_err();
    assert!(err.to_string().contains("unsafe"));
}

#[test]
fn split_config_rejects_absolute_path_in_id() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.proxies[0].id = "/etc/passwd".to_string();

    let err = split_config(&config, tmp.path()).unwrap_err();
    assert!(err.to_string().contains("unsafe"));
}

#[test]
fn split_config_rejects_duplicate_output_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    let mut duplicate = config.proxies[0].clone();
    duplicate.backend_host = "other".to_string();
    config.proxies.push(duplicate);

    let err = split_config(&config, tmp.path()).unwrap_err().to_string();
    assert!(
        err.contains("duplicate namespace/kind/id"),
        "expected duplicate target error, got: {err}"
    );
}

#[test]
fn split_config_refuses_to_overwrite_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let target_dir = tmp.path().join("ferrum/proxies");
    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::write(target_dir.join("proxy-test.yaml"), "existing").unwrap();

    let config = make_test_config();
    let err = split_config(&config, tmp.path()).unwrap_err().to_string();

    assert!(
        err.contains("refusing to overwrite"),
        "expected overwrite refusal, got: {err}"
    );
}

#[test]
fn import_from_file_roundtrip() {
    let tmp_export = tempfile::tempdir().unwrap();
    let config = make_test_config();
    let flat_file = tmp_export.path().join("resources.yaml");
    let yaml = serde_yaml::to_string(&config).unwrap();
    std::fs::write(&flat_file, yaml).unwrap();

    let tmp_import = tempfile::tempdir().unwrap();
    let result =
        gitforgeops::import::from_file::import_from_file(&flat_file, tmp_import.path()).unwrap();
    assert_eq!(result.proxies, 1);
    assert_eq!(result.consumers, 1);

    let loaded = gitforgeops::config::load_resources(tmp_import.path()).unwrap();
    assert_eq!(loaded.len(), 2);

    let output_dir = PathBuf::from(tmp_import.path());
    let proxy_file = output_dir.join("ferrum/proxies/proxy-test.yaml");
    let content = std::fs::read_to_string(&proxy_file).unwrap();
    assert!(content.contains("kind: Proxy"));
    assert!(content.contains("proxy-test"));
}
