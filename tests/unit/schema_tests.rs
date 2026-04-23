use gitforgeops::config::schema::*;

#[test]
fn parse_proxy_resource_from_yaml() {
    let yaml = r#"
kind: Proxy
spec:
  id: "proxy-test"
  name: "Test Proxy"
  listen_path: "/test"
  backend_protocol: https
  backend_host: "example.com"
  backend_port: 443
  strip_listen_path: true
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Proxy { spec } => {
            assert_eq!(spec.id, "proxy-test");
            assert_eq!(spec.name, Some("Test Proxy".to_string()));
            assert_eq!(spec.listen_path, Some("/test".to_string()));
            assert_eq!(spec.backend_protocol, BackendProtocol::Https);
            assert_eq!(spec.backend_host, "example.com");
            assert_eq!(spec.backend_port, 443);
            assert!(spec.strip_listen_path);
            assert_eq!(spec.namespace, "ferrum");
            assert_eq!(spec.backend_connect_timeout_ms, 5000);
            assert_eq!(spec.backend_read_timeout_ms, 30000);
        }
        _ => panic!("expected Proxy"),
    }
}

#[test]
fn parse_consumer_resource_from_yaml() {
    let yaml = r#"
kind: Consumer
spec:
  id: "consumer-bob"
  username: "bob"
  acl_groups:
    - "admin"
    - "ops"
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Consumer { spec } => {
            assert_eq!(spec.id, "consumer-bob");
            assert_eq!(spec.username, "bob");
            assert_eq!(spec.acl_groups, vec!["admin", "ops"]);
            assert_eq!(spec.namespace, "ferrum");
        }
        _ => panic!("expected Consumer"),
    }
}

#[test]
fn parse_upstream_resource_from_yaml() {
    let yaml = r#"
kind: Upstream
spec:
  id: "upstream-pool"
  name: "Backend Pool"
  algorithm: weighted_round_robin
  targets:
    - host: "10.0.0.1"
      port: 8080
      weight: 3
    - host: "10.0.0.2"
      port: 8080
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Upstream { spec } => {
            assert_eq!(spec.id, "upstream-pool");
            assert_eq!(spec.algorithm, LoadBalancerAlgorithm::WeightedRoundRobin);
            assert_eq!(spec.targets.len(), 2);
            assert_eq!(spec.targets[0].weight, 3);
            assert_eq!(spec.targets[1].weight, 1); // default
        }
        _ => panic!("expected Upstream"),
    }
}

#[test]
fn parse_plugin_config_resource_from_yaml() {
    let yaml = r#"
kind: PluginConfig
spec:
  id: "plugin-rate"
  plugin_name: "rate_limiting"
  scope: global
  config:
    window_seconds: 60
    max_requests: 100
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::PluginConfig { spec } => {
            assert_eq!(spec.id, "plugin-rate");
            assert_eq!(spec.plugin_name, "rate_limiting");
            assert_eq!(spec.scope, PluginScope::Global);
            assert!(spec.enabled); // default true
            assert_eq!(spec.config["window_seconds"], 60);
        }
        _ => panic!("expected PluginConfig"),
    }
}

#[test]
fn all_backend_protocols_parse() {
    for proto in &[
        "http", "https", "ws", "wss", "grpc", "grpcs", "h3", "tcp", "tcp_tls", "udp", "dtls",
    ] {
        let yaml = format!(
            r#"
kind: Proxy
spec:
  id: "proxy-{proto}"
  backend_protocol: {proto}
  backend_host: "localhost"
  backend_port: 8080
"#
        );
        let resource: Resource = serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("failed to parse protocol {proto}: {e}"));
        assert!(matches!(resource, Resource::Proxy { .. }));
    }
}

#[test]
fn gateway_config_roundtrip() {
    let config = GatewayConfig::default();
    let yaml = serde_yaml::to_string(&config).unwrap();
    let parsed: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(parsed.version, "1");
    assert!(parsed.proxies.is_empty());
    assert!(parsed.consumers.is_empty());
    assert!(parsed.upstreams.is_empty());
    assert!(parsed.plugin_configs.is_empty());
}

#[test]
fn proxy_with_circuit_breaker_and_retry() {
    let yaml = r#"
kind: Proxy
spec:
  id: "proxy-resilient"
  backend_protocol: http
  backend_host: "localhost"
  backend_port: 8080
  circuit_breaker:
    failure_threshold: 10
    timeout_seconds: 60
  retry:
    max_retries: 5
    retryable_status_codes: [502, 503]
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Proxy { spec } => {
            let cb = spec.circuit_breaker.unwrap();
            assert_eq!(cb.failure_threshold, 10);
            assert_eq!(cb.timeout_seconds, 60);
            let retry = spec.retry.unwrap();
            assert_eq!(retry.max_retries, 5);
            assert_eq!(retry.retryable_status_codes, vec![502, 503]);
        }
        _ => panic!("expected Proxy"),
    }
}

#[test]
fn tcp_proxy_with_listen_port() {
    let yaml = r#"
kind: Proxy
spec:
  id: "proxy-tcp"
  backend_protocol: tcp
  backend_host: "db.internal"
  backend_port: 5432
  listen_port: 15432
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Proxy { spec } => {
            assert_eq!(spec.backend_protocol, BackendProtocol::Tcp);
            assert_eq!(spec.listen_port, Some(15432));
            assert_eq!(spec.listen_path, None);
        }
        _ => panic!("expected Proxy"),
    }
}
