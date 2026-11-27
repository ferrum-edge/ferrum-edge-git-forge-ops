use gitforgeops::config::schema::*;

#[test]
fn parse_proxy_resource_from_yaml() {
    let yaml = r#"
kind: Proxy
spec:
  id: "proxy-test"
  name: "Test Proxy"
  listen_path: "/test"
  backend_scheme: https
  backend_host: "example.com"
  backend_port: 443
  strip_listen_path: true
"#;
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Proxy { spec } => {
            assert_eq!(spec.id, "proxy-test");
            assert_eq!(spec.name, Some("Test Proxy".to_string()));
            assert_eq!(spec.listen_path, Some("/test".to_string()));
            assert_eq!(spec.backend_scheme, Some(BackendScheme::Https));
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
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
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
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
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
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
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

fn proxy_from_yaml(yaml: &str) -> Proxy {
    match gitforgeops::yaml::from_str::<Resource>(yaml)
        .unwrap_or_else(|e| panic!("failed to parse proxy: {e}\n{yaml}"))
    {
        Resource::Proxy { spec } => spec,
        _ => panic!("expected Proxy"),
    }
}

#[test]
fn all_backend_schemes_parse() {
    for (wire, expected) in &[
        ("http", BackendScheme::Http),
        ("https", BackendScheme::Https),
        ("tcp", BackendScheme::Tcp),
        ("tcps", BackendScheme::Tcps),
        ("udp", BackendScheme::Udp),
        ("dtls", BackendScheme::Dtls),
    ] {
        let spec = proxy_from_yaml(&format!(
            r#"
kind: Proxy
spec:
  id: "proxy-{wire}"
  backend_scheme: {wire}
  backend_host: "localhost"
  backend_port: 8080
"#
        ));
        assert_eq!(spec.backend_scheme, Some(*expected), "scheme {wire}");
    }
}

#[test]
fn legacy_backend_protocol_field_and_values_are_accepted() {
    // Users' existing git trees still carry the pre-rename field name and the
    // wider variant set. Both must load, folded onto the canonical six.
    for (legacy, expected) in &[
        ("http", BackendScheme::Http),
        ("https", BackendScheme::Https),
        ("ws", BackendScheme::Http),
        ("wss", BackendScheme::Https),
        ("grpc", BackendScheme::Http),
        ("grpcs", BackendScheme::Https),
        ("h3", BackendScheme::Https),
        ("tcp", BackendScheme::Tcp),
        ("tcp_tls", BackendScheme::Tcps),
        ("udp", BackendScheme::Udp),
        ("dtls", BackendScheme::Dtls),
    ] {
        let spec = proxy_from_yaml(&format!(
            r#"
kind: Proxy
spec:
  id: "proxy-{legacy}"
  backend_protocol: {legacy}
  backend_host: "localhost"
  backend_port: 8080
"#
        ));
        assert_eq!(
            spec.backend_scheme,
            Some(*expected),
            "legacy backend_protocol: {legacy}"
        );
    }
}

#[test]
fn legacy_grpcs_maps_to_https() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-grpc"
  backend_protocol: grpcs
  backend_host: "grpc.internal"
  backend_port: 443
"#,
    );
    assert_eq!(spec.backend_scheme, Some(BackendScheme::Https));
}

#[test]
fn legacy_tcp_tls_maps_to_tcps() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-tcp-tls"
  backend_protocol: tcp_tls
  backend_host: "db.internal"
  backend_port: 5432
  listen_port: 15432
"#,
    );
    assert_eq!(spec.backend_scheme, Some(BackendScheme::Tcps));
}

#[test]
fn unknown_backend_scheme_is_rejected() {
    let err = gitforgeops::yaml::from_str::<Resource>(
        r#"
kind: Proxy
spec:
  id: "proxy-bogus"
  backend_scheme: quic
  backend_host: "localhost"
  backend_port: 8080
"#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("quic"),
        "error should name the bad value: {err}"
    );
}

#[test]
fn serialization_emits_backend_scheme_only() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-legacy"
  backend_protocol: wss
  backend_host: "example.com"
  backend_port: 443
"#,
    );
    let yaml = gitforgeops::yaml::to_string(&spec).unwrap();
    assert!(
        yaml.contains("backend_scheme: https"),
        "expected canonical scheme in output:\n{yaml}"
    );
    assert!(
        !yaml.contains("backend_protocol"),
        "legacy field name must never be emitted:\n{yaml}"
    );
    assert!(
        !yaml.contains("wss"),
        "legacy value must never be emitted:\n{yaml}"
    );
}

#[test]
fn new_form_proxy_yaml_roundtrips() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-roundtrip"
  backend_scheme: tcps
  backend_host: "db.internal"
  backend_port: 5432
  listen_port: 15432
"#,
    );
    let yaml = gitforgeops::yaml::to_string(&spec).unwrap();
    let reparsed: Proxy = gitforgeops::yaml::from_str(&yaml).unwrap();
    assert_eq!(reparsed.backend_scheme, Some(BackendScheme::Tcps));
    assert_eq!(reparsed.backend_host, "db.internal");
    assert_eq!(reparsed.backend_port, 5432);
    assert_eq!(reparsed.listen_port, Some(15432));
}

/// An unset `backend_scheme` must serialize as an *absent key*, never as
/// `backend_scheme: null`. A DB-backed gateway always reports a resolved
/// scheme, so emitting an explicit null diffs against the live value forever
/// (and, before this, raised a breaking "backend_scheme changed" on every PR).
#[test]
fn absent_backend_scheme_is_omitted_not_serialized_as_null() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-schemeless"
  listen_path: "/api"
  upstream_id: "pool-a"
"#,
    );
    assert_eq!(spec.backend_scheme, None);

    let yaml = gitforgeops::yaml::to_string(&spec).unwrap();
    assert!(
        !yaml.contains("backend_scheme"),
        "an unset scheme must be omitted entirely, not emitted as null:\n{yaml}"
    );

    let json = serde_json::to_value(&spec).unwrap();
    assert!(
        json.get("backend_scheme").is_none(),
        "the JSON form feeds compare_fields; a null key there is perpetual drift"
    );
}

#[test]
fn proxy_backed_by_upstream_omits_host_port_and_scheme() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-upstream"
  listen_path: "/api"
  upstream_id: "pool-a"
  upstream_subset: "canary"
"#,
    );
    assert_eq!(spec.backend_scheme, None);
    assert_eq!(spec.backend_host, "");
    assert_eq!(spec.backend_port, 0);
    assert_eq!(spec.upstream_id, Some("pool-a".to_string()));
    assert_eq!(spec.upstream_subset, Some("canary".to_string()));
}

#[test]
fn proxy_stream_fields_roundtrip() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-stream"
  backend_scheme: tcp
  backend_host: "db.internal"
  backend_port: 5432
  listen_port: 15432
  stream_proxy_protocol: true
  backend_proxy_protocol: v2
  websocket_idle_timeout_seconds: 120
  pool_max_requests_per_connection: 1000
  api_spec_id: "spec-7"
  stream_match:
    arms:
      - source_namespace: "team-alpha"
        source_labels:
          app: "checkout"
        source_subnets: ["10.0.0.0/8"]
        destination_subnets: ["10.1.0.0/16"]
        gateways: ["mesh", "ferrum/edge"]
"#,
    );
    assert_eq!(spec.stream_proxy_protocol, Some(true));
    assert_eq!(spec.backend_proxy_protocol, Some(BackendProxyProtocol::V2));
    assert_eq!(spec.websocket_idle_timeout_seconds, Some(120));
    assert_eq!(spec.pool_max_requests_per_connection, Some(1000));
    assert_eq!(spec.api_spec_id, Some("spec-7".to_string()));

    let yaml = gitforgeops::yaml::to_string(&spec).unwrap();
    let reparsed: Proxy = gitforgeops::yaml::from_str(&yaml).unwrap();
    let arms = reparsed.stream_match.expect("stream_match preserved").arms;
    assert_eq!(arms.len(), 1);
    assert_eq!(arms[0].source_namespace, Some("team-alpha".to_string()));
    assert_eq!(
        arms[0].source_labels.get("app").map(String::as_str),
        Some("checkout")
    );
    assert_eq!(arms[0].source_subnets, vec!["10.0.0.0/8".to_string()]);
    assert_eq!(arms[0].destination_subnets, vec!["10.1.0.0/16".to_string()]);
    assert_eq!(
        arms[0].gateways,
        vec!["mesh".to_string(), "ferrum/edge".to_string()]
    );
    assert_eq!(
        reparsed.backend_proxy_protocol,
        Some(BackendProxyProtocol::V2)
    );
}

#[test]
fn upstream_subsets_and_tls_pinning_roundtrip() {
    let yaml = r#"
kind: Upstream
spec:
  id: "pool-a"
  targets:
    - host: "10.0.0.1"
      port: 8080
      locality: "us-east-1/az-1"
      tags:
        version: "v2"
  algorithm: passthrough
  subsets:
    - name: "canary"
      labels:
        version: "v2"
  backend_tls_sni: "api.internal"
  backend_tls_san_allow_list:
    - "spiffe://cluster.local/ns/prod/sa/api"
  api_spec_id: "spec-3"
"#;
    let spec = match gitforgeops::yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    assert_eq!(spec.algorithm, LoadBalancerAlgorithm::Passthrough);
    assert_eq!(spec.targets[0].locality, Some("us-east-1/az-1".to_string()));

    let round = gitforgeops::yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = gitforgeops::yaml::from_str(&round).unwrap();
    let subsets = reparsed.subsets.expect("subsets preserved");
    assert_eq!(subsets.len(), 1);
    assert_eq!(subsets[0].name, "canary");
    assert_eq!(
        subsets[0].labels.get("version").map(String::as_str),
        Some("v2")
    );
    assert_eq!(reparsed.backend_tls_sni, Some("api.internal".to_string()));
    assert_eq!(
        reparsed.backend_tls_san_allow_list,
        vec!["spiffe://cluster.local/ns/prod/sa/api".to_string()]
    );
    assert_eq!(reparsed.api_spec_id, Some("spec-3".to_string()));
    assert_eq!(
        reparsed.targets[0].locality,
        Some("us-east-1/az-1".to_string())
    );
}

#[test]
fn upstream_mesh_service_discovery_roundtrips() {
    let yaml = r#"
kind: Upstream
spec:
  id: "pool-mesh"
  targets: []
  service_discovery:
    provider: mesh
    mesh:
      service_name: "checkout"
      namespace: "prod"
      port: 8080
      topology: sidecar
    max_stale_seconds: 300
    stale_policy: fail_readiness
"#;
    let spec = match gitforgeops::yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    let round = gitforgeops::yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = gitforgeops::yaml::from_str(&round).unwrap();
    let sd = reparsed
        .service_discovery
        .expect("service_discovery preserved");
    assert_eq!(sd.provider, SdProvider::Mesh);
    assert_eq!(sd.max_stale_seconds, Some(300));
    assert_eq!(sd.stale_policy, Some(SdStalePolicy::FailReadiness));
    let mesh = sd.mesh.expect("mesh block preserved");
    assert_eq!(mesh.service_name, "checkout");
    assert_eq!(mesh.namespace, Some("prod".to_string()));
    assert_eq!(mesh.port, Some(8080));
    assert_eq!(mesh.poll_interval_seconds, 30);
    assert_eq!(mesh.topology, MeshSdTopology::Sidecar);
}

#[test]
fn kubernetes_service_discovery_address_type_roundtrips() {
    let with_type = r#"
kind: Upstream
spec:
  id: "pool-k8s"
  targets: []
  service_discovery:
    provider: kubernetes
    kubernetes:
      service_name: "checkout"
      namespace: "prod"
      address_type: IPv6
"#;
    let spec = match gitforgeops::yaml::from_str::<Resource>(with_type).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    let sd = spec
        .service_discovery
        .as_ref()
        .expect("service_discovery preserved");
    let k8s = sd.kubernetes.as_ref().expect("kubernetes block preserved");
    assert_eq!(k8s.address_type.as_deref(), Some("IPv6"));

    let round = gitforgeops::yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = gitforgeops::yaml::from_str(&round).unwrap();
    let reparsed_k8s = reparsed
        .service_discovery
        .expect("service_discovery preserved")
        .kubernetes
        .expect("kubernetes block preserved");
    assert_eq!(reparsed_k8s.address_type.as_deref(), Some("IPv6"));

    // Absent `address_type` stays absent (no fabricated default), so a
    // kubernetes block without it round-trips unchanged.
    let without_type = r#"
kind: Upstream
spec:
  id: "pool-k8s-auto"
  targets: []
  service_discovery:
    provider: kubernetes
    kubernetes:
      service_name: "checkout"
"#;
    let spec = match gitforgeops::yaml::from_str::<Resource>(without_type).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    assert_eq!(
        spec.service_discovery
            .as_ref()
            .and_then(|sd| sd.kubernetes.as_ref())
            .and_then(|k| k.address_type.as_deref()),
        None
    );
    let round = gitforgeops::yaml::to_string(&spec).unwrap();
    assert!(!round.contains("address_type"), "{round}");
}

#[test]
fn upstream_health_check_and_cookie_extensions_roundtrip() {
    let yaml = r#"
kind: Upstream
spec:
  id: "pool-health"
  targets: []
  hash_on: "cookie"
  hash_on_cookie_config:
    session_cookie: true
  health_checks:
    passive:
      max_ejection_percent: 40
"#;
    let spec = match gitforgeops::yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    let round = gitforgeops::yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = gitforgeops::yaml::from_str(&round).unwrap();
    let cookie = reparsed
        .hash_on_cookie_config
        .expect("cookie config preserved");
    assert!(cookie.session_cookie);
    let passive = reparsed
        .health_checks
        .expect("health_checks preserved")
        .passive
        .expect("passive preserved");
    assert_eq!(passive.max_ejection_percent, Some(40));
    assert!(!round.contains("gateway_error_codes"), "{round}");
    assert!(
        !round.contains("split_external_local_origin_errors"),
        "{round}"
    );
}

#[test]
fn plugin_trigger_match_key_deserializes_and_roundtrips() {
    let yaml = r#"
kind: PluginConfig
spec:
  id: "plugin-rate"
  plugin_name: "rate_limiting"
  scope: proxy
  proxy_id: "proxy-a"
  api_spec_id: "spec-9"
  trigger:
    when:
      all:
        - match:
            path:
              prefix: ["/v1/orders"]
              case_insensitive: true
        - not:
            match:
              header:
                name: "x-internal"
                presence: absent
                multi_value: all
        - any:
            - match:
                protocol: ["http2", "grpc_web"]
            - match:
                consumer:
                  presence: present
                  value:
                    exact: ["alice"]
"#;
    let spec = match gitforgeops::yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::PluginConfig { spec } => spec,
        _ => panic!("expected PluginConfig"),
    };
    assert_eq!(spec.api_spec_id, Some("spec-9".to_string()));

    let round = gitforgeops::yaml::to_string(&spec).unwrap();
    // The `match_` field must serialize back out under the reserved `match` key.
    assert!(
        round.contains("match:") && !round.contains("match_:"),
        "trigger must use the `match` wire key:\n{round}"
    );

    let reparsed: PluginConfig = gitforgeops::yaml::from_str(&round).unwrap();
    let when = reparsed.trigger.expect("trigger preserved").when;
    let all = when.all.expect("all branch preserved");
    assert_eq!(all.len(), 3);

    let path = all[0]
        .match_
        .as_ref()
        .expect("match_ populated from `match` key")
        .path
        .as_ref()
        .expect("path predicate preserved");
    assert_eq!(path.prefix, Some(vec!["/v1/orders".to_string()]));
    assert!(path.case_insensitive);

    let header = all[1]
        .not
        .as_ref()
        .expect("not branch preserved")
        .match_
        .as_ref()
        .expect("nested match preserved")
        .header
        .as_ref()
        .expect("header predicate preserved");
    assert_eq!(header.name, "x-internal");
    assert_eq!(header.presence, PluginTriggerPresence::Absent);
    assert_eq!(header.multi_value, PluginTriggerMultiValue::All);

    let any = all[2].any.as_ref().expect("any branch preserved");
    assert_eq!(
        any[0]
            .match_
            .as_ref()
            .and_then(|m| m.protocol.clone())
            .expect("protocol predicate preserved"),
        vec![PluginTriggerProtocol::Http2, PluginTriggerProtocol::GrpcWeb]
    );
    let consumer = any[1]
        .match_
        .as_ref()
        .and_then(|m| m.consumer.clone())
        .expect("consumer predicate preserved");
    assert_eq!(consumer.presence, PluginTriggerPresence::Present);
    assert_eq!(
        consumer.value.and_then(|v| v.exact),
        Some(vec!["alice".to_string()])
    );
}

#[test]
fn gateway_config_roundtrip() {
    let config = GatewayConfig::default();
    let yaml = gitforgeops::yaml::to_string(&config).unwrap();
    let parsed: GatewayConfig = gitforgeops::yaml::from_str(&yaml).unwrap();
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
  backend_scheme: http
  backend_host: "localhost"
  backend_port: 8080
  circuit_breaker:
    failure_threshold: 10
    timeout_seconds: 60
  retry:
    max_retries: 5
    retryable_status_codes: [502, 503]
"#;
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
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
  backend_scheme: tcp
  backend_host: "db.internal"
  backend_port: 5432
  listen_port: 15432
"#;
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Proxy { spec } => {
            assert_eq!(spec.backend_scheme, Some(BackendScheme::Tcp));
            assert_eq!(spec.listen_port, Some(15432));
            assert_eq!(spec.listen_path, None);
        }
        _ => panic!("expected Proxy"),
    }
}

#[test]
fn proxy_path_parameter_opt_in_is_typed_and_round_trips() {
    let spec = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-matrix"
  backend_scheme: https
  backend_host: "localhost"
  backend_port: 8443
  allow_path_parameters: true
"#,
    );

    assert!(spec.allow_path_parameters);
    let emitted = gitforgeops::yaml::to_string(&spec).unwrap();
    assert!(emitted.contains("allow_path_parameters: true"), "{emitted}");
    let reparsed: Proxy = gitforgeops::yaml::from_str(&emitted).unwrap();
    assert!(reparsed.allow_path_parameters);
}

const PERMESSAGE_DEFLATE_PROXY: &str = r#"
kind: Proxy
spec:
  id: "proxy-ws"
  listen_path: /ws
  backend_scheme: https
  backend_host: "ws.internal"
  backend_port: 8443
  websocket_permessage_deflate: passthrough
"#;

/// Edge v0.9.9 added `websocket_permessage_deflate`; the mirror models every
/// value and serializes the `strip` default the way Edge does (omitted), so an
/// undeclared value never reads as drift against a default live row.
#[test]
fn websocket_permessage_deflate_is_typed_and_omits_its_default() {
    for (wire, expected) in [
        ("strip", WebSocketPermessageDeflate::Strip),
        ("passthrough", WebSocketPermessageDeflate::Passthrough),
        ("terminate", WebSocketPermessageDeflate::Terminate),
    ] {
        let spec = proxy_from_yaml(&PERMESSAGE_DEFLATE_PROXY.replace("passthrough", wire));
        assert_eq!(spec.websocket_permessage_deflate, expected, "{wire}");
        let emitted = serde_json::to_value(&spec).unwrap();
        if expected.is_strip() {
            assert!(
                emitted.get("websocket_permessage_deflate").is_none(),
                "{emitted}"
            );
        } else {
            assert_eq!(emitted["websocket_permessage_deflate"], wire);
        }
    }

    let omitted = proxy_from_yaml(
        &PERMESSAGE_DEFLATE_PROXY.replace("  websocket_permessage_deflate: passthrough\n", ""),
    );
    assert_eq!(
        omitted.websocket_permessage_deflate,
        WebSocketPermessageDeflate::Strip
    );

    let error = gitforgeops::yaml::from_str::<Resource>(
        &PERMESSAGE_DEFLATE_PROXY.replace("passthrough", "Passthrough"),
    )
    .expect_err("an unknown value is refused, never defaulted");
    assert!(
        error.to_string().contains("unknown variant `Passthrough`"),
        "{error}"
    );
}

/// The field loads under the strict loader (no `FERRUM_ALLOW_UNKNOWN_FIELDS`),
/// reaches the exported document, and diffs like any modeled field.
#[test]
fn websocket_permessage_deflate_loads_exports_and_diffs_without_the_unknown_field_opt_in() {
    let tree = tempfile::tempdir().unwrap();
    let file = tree.path().join("ferrum/proxies/proxy-ws.yaml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, PERMESSAGE_DEFLATE_PROXY).unwrap();

    let resources = gitforgeops::config::load_resources(tree.path())
        .expect("strict load accepts the modeled field");
    let assembled = gitforgeops::config::assemble(resources).unwrap();
    let proxy = &assembled.gateway.proxies[0];
    assert!(proxy.extra.is_empty(), "{:?}", proxy.extra);
    assert_eq!(
        proxy.websocket_permessage_deflate,
        WebSocketPermessageDeflate::Passthrough
    );
    let exported = gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap();
    assert!(
        exported.contains("websocket_permessage_deflate: passthrough"),
        "{exported}"
    );

    // A live row carrying the same value is in sync.
    let live = assembled.gateway.clone();
    let diffs = gitforgeops::diff::compute_diff(&assembled.gateway, &live).unwrap();
    assert!(diffs.is_empty(), "{diffs:?}");

    // A live row with another value (or the omitted default) is drift on that
    // field, which apply now writes instead of refusing the namespace.
    for live_value in [
        WebSocketPermessageDeflate::Terminate,
        WebSocketPermessageDeflate::Strip,
    ] {
        let mut live = assembled.gateway.clone();
        live.proxies[0].websocket_permessage_deflate = live_value;
        let diffs = gitforgeops::diff::compute_diff(&assembled.gateway, &live).unwrap();
        assert_eq!(diffs.len(), 1, "{diffs:?}");
        let fields: Vec<&str> = diffs[0]
            .details
            .iter()
            .map(|change| change.field.as_str())
            .collect();
        assert_eq!(
            fields,
            vec!["websocket_permessage_deflate"],
            "{live_value:?}"
        );
    }
}

// --- MeshConfig mirror ------------------------------------------------------

#[test]
fn parse_mesh_config_resource_from_yaml() {
    let yaml = r#"
kind: MeshConfig
id: core
spec:
  istio_root_namespace: mesh-system
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      service_name: api
      namespace: ferrum
      trust_domain: cluster.local
  services:
    - name: api
      namespace: ferrum
  peer_authentications:
    - name: strict
      namespace: ferrum
      mtls_mode: strict
  outbound_traffic_policy:
    mode: registry_only
"#;
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
    match resource {
        Resource::MeshConfig { id, spec } => {
            assert_eq!(id.as_deref(), Some("core"));
            assert_eq!(spec.istio_root_namespace.as_deref(), Some("mesh-system"));
            assert_eq!(spec.workloads.len(), 1);
            assert_eq!(spec.services.len(), 1);
            assert_eq!(spec.peer_authentications.len(), 1);
            assert_eq!(
                spec.outbound_traffic_policy.unwrap()["mode"],
                "registry_only"
            );
            assert!(spec.sidecars.is_empty());
        }
        other => panic!("expected MeshConfig, got {other:?}"),
    }
}

/// The mirror is permissive by design: `ferrum-edge validate -m mesh` is the
/// authority on the deep shapes, so unknown keys inside a workload or service
/// must survive verbatim rather than being rejected or silently dropped.
#[test]
fn mesh_item_shapes_round_trip_unknown_fields_verbatim() {
    let yaml = r#"
kind: MeshConfig
spec:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      some_future_istio_field:
        nested: [1, 2, 3]
"#;
    let resource: Resource = gitforgeops::yaml::from_str(yaml).unwrap();
    let Resource::MeshConfig { spec, .. } = resource else {
        panic!("expected MeshConfig");
    };

    assert_eq!(spec.workloads[0]["some_future_istio_field"]["nested"][2], 3);

    let reparsed: MeshConfigSpec =
        gitforgeops::yaml::from_str(&gitforgeops::yaml::to_string(&spec).unwrap()).unwrap();
    assert_eq!(reparsed, spec);
}

/// Runtime-derived `#[serde(skip)]` fields on ferrum-edge's own `MeshConfig`
/// are never operator-settable and never on the wire. They must not be part of
/// the mirror, and a document that mentions one must not grow it back on
/// serialization.
#[test]
fn mesh_mirror_omits_runtime_derived_fields() {
    let spec: MeshConfigSpec = gitforgeops::yaml::from_str(
        "local_inbound_services: []\nnode_waypoint_assertors: []\nsidecar_ingress_declared: true\n",
    )
    .expect("unknown keys are tolerated, not mirrored");

    let emitted = gitforgeops::yaml::to_string(&spec).unwrap();
    for runtime_only in [
        "local_inbound_services",
        "node_waypoint_assertors",
        "node_waypoint_capture_destinations",
        "local_ingress_listeners",
        "sidecar_ingress_declared",
        "declared_ingress_http_ports",
        "local_inbound_tcp_routes",
        "local_workload_addresses",
        "sidecar_ingress_bind_overrides",
        "egress_udp_destinations",
        "external_udp_egress_routes",
    ] {
        assert!(
            !emitted.contains(runtime_only),
            "{runtime_only} in {emitted}"
        );
    }
}

#[test]
fn mesh_config_id_is_absent_from_a_default_fragment() {
    // `id` is a gitforgeops-side handle for overlay matching, not part of the
    // mesh schema — it must never reach the published mesh document, which
    // serializes `spec` alone.
    let resource: Resource = gitforgeops::yaml::from_str("kind: MeshConfig\nspec: {}\n").unwrap();
    let Resource::MeshConfig { id, spec } = resource else {
        panic!("expected MeshConfig");
    };
    assert!(id.is_none());
    assert!(spec.is_empty());
    assert_eq!(gitforgeops::yaml::to_string(&spec).unwrap().trim(), "{}");
}

#[test]
fn known_credential_types_match_the_ferrum_edge_builtin_set() {
    assert_eq!(
        KNOWN_CREDENTIAL_TYPES,
        ["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"]
    );
    for known in KNOWN_CREDENTIAL_TYPES {
        assert!(is_known_credential_type(known));
    }
    assert!(!is_known_credential_type("api_key"));
    assert!(!is_known_credential_type("basic_auth"));
    assert!(!is_known_credential_type("KEYAUTH"));
    assert_eq!(suggest_credential_type("api_key"), Some("keyauth"));
    assert_eq!(suggest_credential_type("API_KEY"), Some("keyauth"));
    assert_eq!(suggest_credential_type("basic_auth"), Some("basicauth"));
    assert_eq!(suggest_credential_type("vendor_token"), None);
    let message = unknown_credential_type_message("api_key", "app", "ferrum");
    assert!(message.contains("Unknown credential type 'api_key'"));
    assert!(message.contains("on consumer app in namespace ferrum"));
    assert!(message.contains("did you mean 'keyauth'"));
    assert!(message.contains(&recognized_credential_types_list()));
}

#[test]
fn resource_labels_are_typed_metadata_on_every_gateway_kind() {
    let labels = serde_json::json!({"provisioned-by":"ferrum-foundry","team":"platform"});
    for (kind, mut spec) in [
        (
            "Proxy",
            serde_json::json!({"backend_host":"example.com","backend_port":443}),
        ),
        ("Consumer", serde_json::json!({"username":"alice"})),
        ("Upstream", serde_json::json!({"targets":[]})),
        (
            "PluginConfig",
            serde_json::json!({"plugin_name":"cors","scope":"global"}),
        ),
    ] {
        spec["labels"] = labels.clone();
        let resource: gitforgeops::config::schema::Resource =
            serde_json::from_value(serde_json::json!({"kind":kind,"spec":spec})).unwrap();
        assert_eq!(
            serde_json::to_value(&resource).unwrap()["spec"]["labels"],
            labels
        );
        spec["labels"] = serde_json::json!({"team":42});
        assert!(
            serde_json::from_value::<gitforgeops::config::schema::Resource>(
                serde_json::json!({"kind":kind,"spec":spec})
            )
            .is_err()
        );
    }
}

/// `created_at` / `updated_at` keep the exact spelling chrono 0.4 gave them
/// (RFC 3339 in UTC, `Z`, a 0/3/6/9-digit fraction) through JSON and YAML, so
/// replacing chrono changes no exported or diffed byte (RUSTSEC-2026-0543).
#[test]
fn resource_timestamps_keep_chronos_rfc3339_spelling() {
    // (input, chrono's serialized form)
    let cases = [
        ("2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z"),
        (
            "2019-05-04T11:22:33.123456+02:00",
            "2019-05-04T09:22:33.123456Z",
        ),
        ("2021-09-12t08:15:00.5z", "2021-09-12T08:15:00.500Z"),
        (
            "2021-09-12 08:15:00.120000-01:30",
            "2021-09-12T09:45:00.120Z",
        ),
        (
            "2021-09-12T08:15:00.000000001Z",
            "2021-09-12T08:15:00.000000001Z",
        ),
        (
            "2021-09-12T08:15:00.1234567890Z",
            "2021-09-12T08:15:00.123456789Z",
        ),
    ];
    for (input, expected) in cases {
        let json = serde_json::json!({
            "id": "proxy-ts",
            "backend_host": "example.com",
            "backend_port": 443,
            "created_at": input,
            "updated_at": input,
        });
        let proxy: Proxy = serde_json::from_value(json).unwrap();
        let out = serde_json::to_value(&proxy).unwrap();
        assert_eq!(out["created_at"], expected, "{input}");
        assert_eq!(out["updated_at"], expected, "{input}");

        let yaml = gitforgeops::yaml::to_string(&proxy).unwrap();
        assert!(yaml.contains(expected), "{input}: {yaml}");
        let reparsed: Proxy = gitforgeops::yaml::from_str(&yaml).unwrap();
        assert_eq!(reparsed.created_at, proxy.created_at, "{input}");
        assert_eq!(
            serde_json::to_value(&reparsed).unwrap()["updated_at"],
            expected
        );
    }

    let from_yaml = proxy_from_yaml(
        r#"
kind: Proxy
spec:
  id: "proxy-ts"
  backend_host: "example.com"
  backend_port: 443
  created_at: 2026-08-01T00:00:00Z
  updated_at: "2026-08-20T10:00:00.250+02:00"
"#,
    );
    let out = serde_json::to_value(&from_yaml).unwrap();
    assert_eq!(out["created_at"], "2026-08-01T00:00:00Z");
    assert_eq!(out["updated_at"], "2026-08-20T08:00:00.250Z");
}

/// Only RFC 3339 loads: chrono's lenient extras (no offset, an offset without
/// a colon, a `UTC` suffix, unpadded fields) are refused at load.
#[test]
fn resource_timestamps_outside_rfc3339_are_refused() {
    for input in [
        "2026-08-01T00:00:00",
        "2026-08-01T00:00:00+0000",
        "2026-08-01T00:00:00 UTC",
        "2026-8-1T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "1754006400",
    ] {
        let json = serde_json::json!({
            "id": "proxy-ts",
            "backend_host": "example.com",
            "backend_port": 443,
            "created_at": input,
        });
        assert!(
            serde_json::from_value::<Proxy>(json).is_err(),
            "{input} must be refused"
        );
    }
}

/// A resource that loads must load again after it is written back (import,
/// overlay merging and export all serialize and re-read). An offset that
/// moves a four-digit local year into UTC year -1 or 10000 would serialize
/// with a signed year, so it is refused at load; the range edges themselves
/// round-trip.
#[test]
fn resource_timestamps_round_trip_at_the_year_range_edges() {
    for input in ["0000-01-01T00:30:00+01:00", "9999-12-31T23:30:00-01:00"] {
        let json = serde_json::json!({
            "id": "proxy-ts",
            "backend_host": "example.com",
            "backend_port": 443,
            "created_at": input,
        });
        let err = serde_json::from_value::<Proxy>(json).unwrap_err();
        assert!(err.to_string().contains("input is out of range"), "{err}");
        let yaml = format!(
            "kind: Proxy\nspec:\n  id: proxy-ts\n  backend_host: example.com\n  backend_port: 443\n  created_at: \"{input}\"\n"
        );
        assert!(
            gitforgeops::yaml::from_str::<Resource>(&yaml).is_err(),
            "{input} must be refused"
        );
    }

    for (input, expected) in [
        ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
        ("0000-01-01T00:30:00-01:00", "0000-01-01T01:30:00Z"),
        ("9999-12-31T23:30:00+01:00", "9999-12-31T22:30:00Z"),
        (
            "9999-12-31T23:59:59.999999999Z",
            "9999-12-31T23:59:59.999999999Z",
        ),
    ] {
        let json = serde_json::json!({
            "id": "proxy-ts",
            "backend_host": "example.com",
            "backend_port": 443,
            "created_at": input,
            "updated_at": input,
        });
        let proxy: Proxy = serde_json::from_value(json).unwrap();
        let yaml = gitforgeops::yaml::to_string(&proxy).unwrap();
        let reparsed: Proxy = gitforgeops::yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("{input}: written YAML does not load: {e}\n{yaml}"));
        assert_eq!(reparsed.created_at, proxy.created_at, "{input}");
        let json_text = serde_json::to_string(&reparsed).unwrap();
        let again: Proxy = serde_json::from_str(&json_text).unwrap();
        assert_eq!(
            serde_json::to_value(&again).unwrap()["updated_at"],
            expected,
            "{input}"
        );
    }
}

const EXTERNAL_IDENTITY_AUTHORITY: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Ferrum Edge v0.9.21 and later splits unmapped external identities out of
/// `consumer` into `external_identity`, scoped by
/// `external_identity_authority`. Both are nested `PluginTriggerMatch` keys,
/// which the escape hatch never covers, so the strict loader must model them.
#[test]
fn plugin_trigger_external_identity_predicates_load_strictly_and_roundtrip() {
    let yaml = format!(
        r#"kind: PluginConfig
spec:
  id: exempt-partner
  plugin_name: rate_limiting
  scope: global
  config: {{}}
  trigger:
    when:
      not:
        match:
          external_identity:
            value:
              exact: ["partner-service"]
      all:
        - match:
            external_identity:
              presence: present
        - match:
            external_identity_authority: ["{EXTERNAL_IDENTITY_AUTHORITY}"]
"#
    );
    let tree = tempfile::tempdir().unwrap();
    let file = tree.path().join("ferrum/plugins/exempt-partner.yaml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, yaml).unwrap();

    let resources = gitforgeops::config::load_resources(tree.path())
        .expect("strict load accepts the modeled trigger predicates");
    let assembled = gitforgeops::config::assemble(resources).unwrap();
    let plugin = &assembled.gateway.plugin_configs[0];
    assert!(plugin.extra.is_empty(), "{:?}", plugin.extra);
    let when = &plugin.trigger.as_ref().expect("trigger").when;

    let exempt = when
        .not
        .as_ref()
        .and_then(|node| node.match_.as_ref())
        .and_then(|leaf| leaf.external_identity.as_ref())
        .expect("external_identity under not");
    assert_eq!(exempt.presence, PluginTriggerPresence::Present);
    assert_eq!(
        exempt.value.as_ref().and_then(|value| value.exact.clone()),
        Some(vec!["partner-service".to_string()])
    );
    let all = when.all.as_ref().expect("all branch");
    assert!(all[0]
        .match_
        .as_ref()
        .and_then(|leaf| leaf.external_identity.as_ref())
        .is_some_and(|identity| identity.value.is_none()));
    assert_eq!(
        all[1]
            .match_
            .as_ref()
            .and_then(|leaf| leaf.external_identity_authority.clone()),
        Some(vec![EXTERNAL_IDENTITY_AUTHORITY.to_string()])
    );

    // Edge's wire names survive the export, and the exported document reads
    // back into the same configuration.
    let exported = gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap();
    assert!(exported.contains("external_identity:"), "{exported}");
    assert!(
        exported.contains("external_identity_authority:"),
        "{exported}"
    );
    let reparsed: gitforgeops::config::GatewayConfig = serde_json::from_value(
        gitforgeops::yaml::parse_value(&exported, gitforgeops::yaml::RESOURCE_LIMITS).unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&reparsed).unwrap(),
        serde_json::to_value(&assembled.gateway).unwrap()
    );

    // A misspelled sibling is still a nested unknown, and still fatal.
    let typo = std::fs::read_to_string(&file)
        .unwrap()
        .replace("external_identity_authority", "external_identity_authorty");
    std::fs::write(&file, typo).unwrap();
    let error = gitforgeops::config::load_resources(tree.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("external_identity_authorty"), "{error}");
}

/// Like Edge, every struct-valued trigger slot must be an object. serde's
/// derived visitors would otherwise build the struct positionally from an
/// array, so `external_identity: []` (or `consumer: []`) became a valid
/// `presence: present` predicate matching every such principal.
#[test]
fn plugin_trigger_struct_slots_must_be_objects_and_keep_unknown_key_detection() {
    let tree = tempfile::tempdir().unwrap();
    let file = tree.path().join("ferrum/plugins/gate.yaml");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let load = |trigger: &str| {
        let yaml = format!(
            "kind: PluginConfig\nspec:\n  id: gate\n  plugin_name: rate_limiting\n  \
             scope: global\n  config: {{}}\n  trigger: {trigger}\n"
        );
        std::fs::write(&file, yaml).unwrap();
        gitforgeops::config::load_resources(tree.path()).map(|_| ())
    };

    for (label, trigger) in [
        (
            "external_identity",
            r#"{when: {match: {external_identity: []}}}"#,
        ),
        ("consumer", r#"{when: {match: {consumer: []}}}"#),
        ("spiffe_id", r#"{when: {match: {spiffe_id: [present]}}}"#),
        ("path", r#"{when: {match: {path: []}}}"#),
        ("header", r#"{when: {match: {header: [x-a]}}}"#),
        (
            "identity value",
            r#"{when: {match: {external_identity: {value: []}}}}"#,
        ),
        (
            "field value",
            r#"{when: {match: {header: {name: x-a, value: []}}}}"#,
        ),
        ("match", r#"{when: {match: []}}"#),
        ("not", r#"{when: {not: []}}"#),
        ("all element", r#"{when: {all: [[]]}}"#),
        ("when", r#"{when: []}"#),
        ("trigger", r#"[]"#),
    ] {
        let error = load(trigger).expect_err(label).to_string();
        assert!(error.contains("a JSON object"), "{label}: {error}");
    }

    // Absent or null slots stay unset, and real objects still load.
    for trigger in [
        r#"null"#,
        r#"{when: {match: {external_identity: null, method: [GET]}}}"#,
        r#"{when: {all: [{match: {external_identity: {}}}, {not: {match: {consumer: {presence: absent}}}}]}}"#,
    ] {
        load(trigger).unwrap_or_else(|error| panic!("{trigger}: {error}"));
    }

    // A misspelled key inside an object slot is still a fatal unknown field.
    for (trigger, field) in [
        (
            r#"{when: {match: {external_identity: {presense: absent}}}}"#,
            ".spec.trigger.when.match.external_identity.presense",
        ),
        (
            r#"{when: {any: [{match: {consumer: {value: {exactt: [a]}}}}]}}"#,
            ".spec.trigger.when.any[0].match.consumer.value.exactt",
        ),
    ] {
        let error = load(trigger).expect_err(trigger).to_string();
        assert!(error.contains(field), "{trigger}: {error}");
    }
}
