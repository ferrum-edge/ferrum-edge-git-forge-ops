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
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
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

fn proxy_from_yaml(yaml: &str) -> Proxy {
    match serde_yaml::from_str::<Resource>(yaml)
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
    let err = serde_yaml::from_str::<Resource>(
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
    let yaml = serde_yaml::to_string(&spec).unwrap();
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
    let yaml = serde_yaml::to_string(&spec).unwrap();
    let reparsed: Proxy = serde_yaml::from_str(&yaml).unwrap();
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

    let yaml = serde_yaml::to_string(&spec).unwrap();
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

    let yaml = serde_yaml::to_string(&spec).unwrap();
    let reparsed: Proxy = serde_yaml::from_str(&yaml).unwrap();
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
    let spec = match serde_yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    assert_eq!(spec.algorithm, LoadBalancerAlgorithm::Passthrough);
    assert_eq!(spec.targets[0].locality, Some("us-east-1/az-1".to_string()));

    let round = serde_yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = serde_yaml::from_str(&round).unwrap();
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
    let spec = match serde_yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    let round = serde_yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = serde_yaml::from_str(&round).unwrap();
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
      gateway_error_codes: [502, 504]
      split_external_local_origin_errors: true
"#;
    let spec = match serde_yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::Upstream { spec } => spec,
        _ => panic!("expected Upstream"),
    };
    let round = serde_yaml::to_string(&spec).unwrap();
    let reparsed: Upstream = serde_yaml::from_str(&round).unwrap();
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
    assert_eq!(passive.gateway_error_codes, Some(vec![502, 504]));
    assert_eq!(passive.split_external_local_origin_errors, Some(true));
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
    let spec = match serde_yaml::from_str::<Resource>(yaml).unwrap() {
        Resource::PluginConfig { spec } => spec,
        _ => panic!("expected PluginConfig"),
    };
    assert_eq!(spec.api_spec_id, Some("spec-9".to_string()));

    let round = serde_yaml::to_string(&spec).unwrap();
    // The `match_` field must serialize back out under the reserved `match` key.
    assert!(
        round.contains("match:") && !round.contains("match_:"),
        "trigger must use the `match` wire key:\n{round}"
    );

    let reparsed: PluginConfig = serde_yaml::from_str(&round).unwrap();
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
  backend_scheme: tcp
  backend_host: "db.internal"
  backend_port: 5432
  listen_port: 15432
"#;
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    match resource {
        Resource::Proxy { spec } => {
            assert_eq!(spec.backend_scheme, Some(BackendScheme::Tcp));
            assert_eq!(spec.listen_port, Some(15432));
            assert_eq!(spec.listen_path, None);
        }
        _ => panic!("expected Proxy"),
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
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
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
    let resource: Resource = serde_yaml::from_str(yaml).unwrap();
    let Resource::MeshConfig { spec, .. } = resource else {
        panic!("expected MeshConfig");
    };

    assert_eq!(spec.workloads[0]["some_future_istio_field"]["nested"][2], 3);

    let reparsed: MeshConfigSpec =
        serde_yaml::from_str(&serde_yaml::to_string(&spec).unwrap()).unwrap();
    assert_eq!(reparsed, spec);
}

/// Runtime-derived `#[serde(skip)]` fields on ferrum-edge's own `MeshConfig`
/// are never operator-settable and never on the wire. They must not be part of
/// the mirror, and a document that mentions one must not grow it back on
/// serialization.
#[test]
fn mesh_mirror_omits_runtime_derived_fields() {
    let spec: MeshConfigSpec = serde_yaml::from_str(
        "local_inbound_services: []\nnode_waypoint_assertors: []\nsidecar_ingress_declared: true\n",
    )
    .expect("unknown keys are tolerated, not mirrored");

    let emitted = serde_yaml::to_string(&spec).unwrap();
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
    let resource: Resource = serde_yaml::from_str("kind: MeshConfig\nspec: {}\n").unwrap();
    let Resource::MeshConfig { id, spec } = resource else {
        panic!("expected MeshConfig");
    };
    assert!(id.is_none());
    assert!(spec.is_empty());
    assert_eq!(serde_yaml::to_string(&spec).unwrap().trim(), "{}");
}
