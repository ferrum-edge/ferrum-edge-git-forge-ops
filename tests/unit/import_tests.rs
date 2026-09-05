use gitforgeops::config::schema::*;
use gitforgeops::import::split_config;

/// Import's fail-closed default: no unmodelled top-level field is
/// acknowledged, which is what every pre-existing case expects.
fn strict_passthrough() -> gitforgeops::import::ImportPassthroughPolicy {
    gitforgeops::import::ImportPassthroughPolicy::strict()
}
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

fn make_test_config() -> GatewayConfig {
    GatewayConfig {
        proxies: vec![Proxy {
            extra: Default::default(),
            id: "proxy-test".to_string(),
            name: Some("Test".to_string()),
            namespace: "ferrum".to_string(),
            hosts: vec![],
            listen_path: Some("/test".to_string()),
            backend_scheme: Some(BackendScheme::Http),
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
            pool_max_requests_per_connection: None,
            upstream_subset: None,
            api_spec_id: None,
            websocket_idle_timeout_seconds: None,
            stream_proxy_protocol: None,
            backend_proxy_protocol: None,
            stream_match: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        consumers: vec![Consumer {
            extra: Default::default(),
            id: "consumer-test".to_string(),
            username: "testuser".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: std::collections::BTreeMap::new(),
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
fn file_import_rejects_passthrough_fields_without_publishing_them() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let mut config = make_test_config();
    config.consumers[0].extra.insert(
        "future_access_token".to_string(),
        serde_json::json!("plaintext-secret-that-must-not-be-published"),
    );
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        None,
        &strict_passthrough(),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("Consumer 'consumer-test'"), "{error}");
    assert!(error.contains("future_access_token"), "{error}");
    assert!(!error.contains("plaintext-secret"), "{error}");
    assert!(
        !output.exists(),
        "a rejected import must not publish an output tree"
    );
}

/// The acknowledgement is per field *name*, so a source carrying a second,
/// unreviewed field is still refused — and the refusal names only the field
/// that was not acknowledged.
#[test]
fn acknowledging_one_field_does_not_admit_another() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let mut config = make_test_config();
    config.consumers[0]
        .extra
        .insert("future_label".to_string(), serde_json::json!("team-a"));
    config.consumers[0].extra.insert(
        "future_access_token".to_string(),
        serde_json::json!("plaintext-secret-that-must-not-be-published"),
    );
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let policy = gitforgeops::import::ImportPassthroughPolicy {
        allow_unknown_fields: true,
        acknowledged: ["future_label".to_string()].into_iter().collect(),
    };
    let error =
        gitforgeops::import::from_file::import_from_file(&backup_path, &output, None, &policy)
            .unwrap_err()
            .to_string();

    assert!(error.contains("future_access_token"), "{error}");
    assert!(
        !error.contains("future_label"),
        "an acknowledged field must not be reported: {error}"
    );
    assert!(!error.contains("plaintext-secret"), "{error}");
    assert!(!output.exists(), "a rejected import must publish nothing");
}

/// Acknowledging a field without `FERRUM_ALLOW_UNKNOWN_FIELDS` would emit a
/// tree the strict loader rejects, so it is refused rather than written.
#[test]
fn acknowledged_fields_still_need_the_passthrough_load_policy() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let mut config = make_test_config();
    config.consumers[0]
        .extra
        .insert("future_label".to_string(), serde_json::json!("team-a"));
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let policy = gitforgeops::import::ImportPassthroughPolicy {
        allow_unknown_fields: false,
        acknowledged: ["future_label".to_string()].into_iter().collect(),
    };
    let error =
        gitforgeops::import::from_file::import_from_file(&backup_path, &output, None, &policy)
            .unwrap_err()
            .to_string();

    assert!(error.contains("FERRUM_ALLOW_UNKNOWN_FIELDS"), "{error}");
    assert!(!output.exists(), "a rejected import must publish nothing");
}

/// With both halves in place the field is carried verbatim, the tree loads
/// under the same policy that admitted it, and the operator is told which
/// resources relied on the acknowledgement.
#[test]
fn acknowledged_passthrough_round_trips_and_is_reported_for_review() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let mut config = make_test_config();
    config.consumers[0]
        .extra
        .insert("future_label".to_string(), serde_json::json!("team-a"));
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let policy = gitforgeops::import::ImportPassthroughPolicy {
        allow_unknown_fields: true,
        acknowledged: ["future_label".to_string()].into_iter().collect(),
    };
    let result =
        gitforgeops::import::from_file::import_from_file(&backup_path, &output, None, &policy)
            .expect("an acknowledged field imports");

    let written =
        std::fs::read_to_string(output.join("ferrum/consumers/consumer-test.yaml")).unwrap();
    assert!(written.contains("future_label"), "{written}");

    let notice = result
        .acknowledged_passthrough_notice()
        .expect("acknowledged fields must be surfaced for review");
    assert!(notice.contains("Consumer consumer-test"), "{notice}");
    assert!(notice.contains("future_label"), "{notice}");

    // The emitted tree is only usable under the policy that admitted it, which
    // is why the acknowledgement requires FERRUM_ALLOW_UNKNOWN_FIELDS.
    gitforgeops::config::load_resources_with_options(
        &output,
        gitforgeops::config::LoadOptions::ALLOW_UNKNOWN_FIELDS,
    )
    .expect("the imported tree loads under the passthrough policy");
    gitforgeops::config::load_resources(&output)
        .expect_err("and is rejected by the strict loader, as documented");
}

/// A clean source pays nothing for the policy: no notice, no refusal.
#[test]
fn a_source_without_unmodelled_fields_reports_no_passthrough_review() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    std::fs::write(
        &backup_path,
        serde_yaml::to_string(&make_test_config()).unwrap(),
    )
    .unwrap();

    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        None,
        &strict_passthrough(),
    )
    .expect("a modelled source imports under the fail-closed default");

    assert!(result.acknowledged_passthrough_notice().is_none());
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
    let result = gitforgeops::import::from_file::import_from_file(
        &flat_file,
        tmp_import.path(),
        None,
        &strict_passthrough(),
    )
    .unwrap();
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

#[test]
fn file_import_requires_an_explicit_private_bundle_for_live_credentials() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "live-production-key"}]
    }))
    .unwrap();
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        None,
        &strict_passthrough(),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("--credential-bundle-output"), "{error}");
    assert!(!output.exists(), "no resource tree may be published");
}

#[test]
fn file_import_preserves_existing_placeholders_without_a_migration_bundle() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("placeholder-export.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "${gh-env-secret:alloc=require}"}]
    }))
    .unwrap();
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        None,
        &strict_passthrough(),
    )
    .unwrap();

    assert_eq!(result.redacted_credential_values, 0);
    let consumer =
        std::fs::read_to_string(output.join("ferrum/consumers/consumer-test.yaml")).unwrap();
    assert!(
        consumer.contains("${gh-env-secret:alloc=require}"),
        "{consumer}"
    );
}

#[test]
fn malformed_placeholder_import_error_does_not_echo_credential_material() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "${gh-env-secret:alloc=must-not-leak}"}]
    }))
    .unwrap();

    let error = split_config(&config, tmp.path()).unwrap_err().to_string();
    assert!(
        error.contains("malformed gh-env-secret placeholder"),
        "{error}"
    );
    assert!(!error.contains("must-not-leak"), "{error}");
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn unterminated_placeholder_import_fails_closed_without_echoing_credential_material() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "${gh-env-secret:unterminated-sensitive-value"}]
    }))
    .unwrap();

    let error = split_config(&config, tmp.path()).unwrap_err().to_string();
    assert!(
        error.contains("malformed gh-env-secret placeholder"),
        "{error}"
    );
    assert!(!error.contains("unterminated-sensitive-value"), "{error}");
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn file_import_writes_a_private_migration_bundle_that_round_trips_exactly() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "first-live-key"}, {"key": "second-live-key"}],
        "jwt": [{"secret": "live-jwt-secret-that-is-long-enough"}],
        "custom": [{"nested": {"token": "custom-live-token"}}]
    }))
    .unwrap();
    let original_credentials = config.consumers[0].credentials.clone();
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("credential-migration.json");
    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &strict_passthrough(),
    )
    .unwrap();

    assert_eq!(result.redacted_credential_values, 4);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&bundle_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let raw_bundle = std::fs::read_to_string(&bundle_path).unwrap();
    let (merged, shards) = gitforgeops::secrets::load_bundles_from_env(&raw_bundle).unwrap();
    assert_eq!(shards.len(), 1);
    assert_eq!(
        merged,
        std::collections::BTreeMap::from([
            (
                "ferrum/consumer-test/custom/nested/token".to_string(),
                "custom-live-token".to_string(),
            ),
            (
                "ferrum/consumer-test/jwt/secret".to_string(),
                "live-jwt-secret-that-is-long-enough".to_string(),
            ),
            (
                "ferrum/consumer-test/keyauth/[1]/key".to_string(),
                "second-live-key".to_string(),
            ),
            (
                "ferrum/consumer-test/keyauth/key".to_string(),
                "first-live-key".to_string(),
            ),
        ])
    );

    let resources = gitforgeops::config::load_resources(&output).unwrap();
    let mut assembled = gitforgeops::config::assemble(resources).unwrap().gateway;
    gitforgeops::secrets::resolve_secrets_with_mode(
        &mut assembled,
        &merged,
        gitforgeops::config::env::GatewayMode::Api,
    )
    .unwrap();
    assert!(
        assembled.consumers[0].credentials == original_credentials,
        "import -> private bundle seed -> assemble introduced credential drift"
    );

    for entry in walkdir::WalkDir::new(&output) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        for secret in merged.values() {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "secret leaked into {}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn import_brokers_plugin_config_secrets_and_round_trips_exactly() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    let original_plugin_config = serde_json::json!({
        "endpoint": "https://collector.example/v1/traces?token=live-query-secret",
        "headers": {
            "x-honeycomb-team": "live-header-secret"
        },
        "protocol": "grpc"
    });
    config.plugin_configs.push(PluginConfig {
        extra: Default::default(),
        id: "otel-main".to_string(),
        plugin_name: "otel_tracing".to_string(),
        namespace: "ferrum".to_string(),
        config: original_plugin_config.clone(),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("secret-migration.json");
    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &strict_passthrough(),
    )
    .unwrap();

    assert_eq!(result.redacted_credential_values, 0);
    assert_eq!(result.redacted_plugin_config_values, 2);

    let plugin_yaml =
        std::fs::read_to_string(output.join("ferrum/plugins/otel-main.yaml")).unwrap();
    assert!(!plugin_yaml.contains("live-query-secret"));
    assert!(!plugin_yaml.contains("live-header-secret"));
    assert!(plugin_yaml.contains("protocol: grpc"));
    assert_eq!(
        plugin_yaml
            .matches("${gh-env-secret:alloc=require}")
            .count(),
        2
    );

    let raw_bundle = std::fs::read_to_string(&bundle_path).unwrap();
    let (merged, _) = gitforgeops::secrets::load_bundles_from_env(&raw_bundle).unwrap();
    assert_eq!(
        merged,
        std::collections::BTreeMap::from([
            (
                "ferrum/otel-main/@plugin-config/config/endpoint".to_string(),
                "https://collector.example/v1/traces?token=live-query-secret".to_string(),
            ),
            (
                "ferrum/otel-main/@plugin-config/config/headers/x-honeycomb-team".to_string(),
                "live-header-secret".to_string(),
            ),
        ])
    );

    let resources = gitforgeops::config::load_resources(&output).unwrap();
    let mut assembled = gitforgeops::config::assemble(resources).unwrap().gateway;
    gitforgeops::secrets::resolve_secrets_with_mode(
        &mut assembled,
        &merged,
        gitforgeops::config::env::GatewayMode::Api,
    )
    .unwrap();
    assert_eq!(assembled.plugin_configs[0].config, original_plugin_config);
}

/// F5: a plugin this build does not know has no schema to classify it by, so
/// only the key/URL sensitivity heuristics run. What they flag is brokered;
/// what they do not is left in the committed file and named in a review
/// notice, because capturing `mode: strict` into a GitHub Environment Secret
/// makes the imported repo unappliable without telling anyone why.
#[test]
fn custom_plugin_import_brokers_heuristic_matches_and_reports_the_rest() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("secret-migration.json");
    let mut config = make_test_config();
    config.plugin_configs.push(PluginConfig {
        extra: Default::default(),
        id: "custom".to_string(),
        plugin_name: "enterprise_custom".to_string(),
        namespace: "ferrum".to_string(),
        config: serde_json::json!({
            "mode": "strict",
            "opaque": {"value": "probably-a-tuning-knob"},
            "api_key": "live-vendor-key",
            "headers": {"x-vendor-auth": "live-vendor-header"}
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &strict_passthrough(),
    )
    .unwrap();

    assert_eq!(result.redacted_plugin_config_values, 2);
    let plugin_yaml = std::fs::read_to_string(output.join("ferrum/plugins/custom.yaml")).unwrap();
    assert!(!plugin_yaml.contains("live-vendor-key"), "{plugin_yaml}");
    assert!(!plugin_yaml.contains("live-vendor-header"), "{plugin_yaml}");
    // The plugin still says what it does.
    assert!(plugin_yaml.contains("strict"), "{plugin_yaml}");
    assert!(
        plugin_yaml.contains("probably-a-tuning-knob"),
        "{plugin_yaml}"
    );

    let notice = result.custom_plugin_review_notice().expect("review notice");
    assert!(notice.contains("WARNING"), "{notice}");
    assert!(notice.contains("plugin_name=enterprise_custom"), "{notice}");
    assert!(notice.contains("mode"), "{notice}");
    assert!(notice.contains("opaque.value"), "{notice}");
    assert!(!notice.contains("api_key"), "{notice}");
}

/// A builtin plugin's schema rules are authoritative, so there is nothing for
/// a human to review afterwards.
#[test]
fn builtin_plugin_import_raises_no_review_notice() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("secret-migration.json");
    let mut config = make_test_config();
    config.plugin_configs.push(PluginConfig {
        extra: Default::default(),
        id: "otel".to_string(),
        plugin_name: "otel_tracing".to_string(),
        namespace: "ferrum".to_string(),
        config: serde_json::json!({
            "endpoint": "https://collector.example/v1/traces",
            "headers": {"x-honeycomb-team": "live-team-key"}
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &strict_passthrough(),
    )
    .unwrap();

    assert_eq!(result.redacted_plugin_config_values, 2);
    assert!(result.custom_plugin_review_notice().is_none());
}

#[test]
fn spec_owned_plugin_secrets_are_skipped_without_creating_migration_slots() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.plugin_configs.push(PluginConfig {
        extra: Default::default(),
        id: "spec-otel".to_string(),
        plugin_name: "otel_tracing".to_string(),
        namespace: "ferrum".to_string(),
        config: serde_json::json!({"authorization": "Bearer spec-owned-secret"}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: Some("payments-v1".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    });
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        None,
        &strict_passthrough(),
    )
    .unwrap();
    assert_eq!(result.skipped_spec_owned, 1);
    assert_eq!(result.redacted_plugin_config_values, 0);
    assert!(!output.join("ferrum/plugins/spec-otel.yaml").exists());
}

#[test]
fn credential_migration_bundle_shards_by_exact_encoded_json_size() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    let values = (0..12)
        .map(|index| {
            serde_json::json!({
                "token": format!("{}-{index}", "\"".repeat(4_000))
            })
        })
        .collect::<Vec<_>>();
    config.consumers[0]
        .credentials
        .insert("custom".to_string(), serde_json::Value::Array(values));
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("credential-migration.json");
    gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &strict_passthrough(),
    )
    .unwrap();

    let raw = std::fs::read_to_string(&bundle_path).unwrap();
    let outer: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let shards = outer.as_object().unwrap();
    assert!(
        shards.len() > 1,
        "expected encoded values to require shards"
    );
    for (name, bundle) in shards {
        let compact_size = serde_json::to_vec(bundle).unwrap().len();
        assert!(
            compact_size <= gitforgeops::secrets::bundle::BUNDLE_SOFT_LIMIT_BYTES,
            "{name} encoded to {compact_size} bytes"
        );
    }
    let (merged, parsed_shards) = gitforgeops::secrets::load_bundles_from_env(&raw).unwrap();
    assert_eq!(merged.len(), 12);
    assert_eq!(parsed_shards.len(), shards.len());
}

#[test]
fn credential_migration_bundle_must_stay_outside_the_resource_tree() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "live-production-key"}]
    }))
    .unwrap();
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let unsafe_bundle = output.join("do-not-commit.json");
    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&unsafe_bundle),
        &strict_passthrough(),
    )
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("outside the import resource tree"),
        "{error}"
    );
    assert!(!output.exists());
}

#[test]
fn credential_migration_bundle_cannot_overwrite_its_source_backup() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "live-production-key"}]
    }))
    .unwrap();
    let original = serde_yaml::to_string(&config).unwrap();
    std::fs::write(&backup_path, &original).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&backup_path),
        &strict_passthrough(),
    )
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("may not overwrite its source backup"),
        "{error}"
    );
    assert_eq!(std::fs::read_to_string(&backup_path).unwrap(), original);
    assert!(!output.exists());
}

#[test]
fn credential_migration_bundle_is_rejected_inside_a_git_worktree() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "live-production-key"}]
    }))
    .unwrap();
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let unsafe_bundle = std::env::current_dir()
        .unwrap()
        .join(format!(".never-write-{}.json", std::process::id()));
    assert!(!unsafe_bundle.exists());
    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&unsafe_bundle),
        &strict_passthrough(),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("outside every Git worktree"), "{error}");
    assert!(!unsafe_bundle.exists());
    assert!(!output.exists());
}

#[test]
fn imported_resource_yaml_is_byte_deterministic() {
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "zeta": [{"token": "z"}],
        "alpha": [{"token": "a"}]
    }))
    .unwrap();
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();

    split_config(&config, left.path()).unwrap();
    split_config(&config, right.path()).unwrap();

    for relative in [
        ".gitforgeops-import.json",
        "ferrum/proxies/proxy-test.yaml",
        "ferrum/consumers/consumer-test.yaml",
    ] {
        assert_eq!(
            std::fs::read(left.path().join(relative)).unwrap(),
            std::fs::read(right.path().join(relative)).unwrap(),
            "non-deterministic import output at {relative}"
        );
    }
}

#[test]
fn import_rejects_an_empty_resource_id() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.proxies[0].id.clear();

    let error = split_config(&config, tmp.path()).unwrap_err().to_string();
    assert!(error.contains("unsafe id"), "{error}");
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn import_encodes_leading_underscore_ids_instead_of_dead_ending() {
    // A live id starting with `_` cannot become `_id.yaml` (the loader treats
    // that prefix as intentionally disabled and would silently drop the
    // resource), but failing the whole import is no better: the id belongs to
    // the gateway and the operator cannot rename it from here. The leading
    // character is percent-encoded instead, and identity still comes from
    // `spec.id`, so the resource round-trips.
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.proxies[0].id = "_disabled-by-loader".to_string();

    split_config(&config, tmp.path()).expect("import must not dead-end on an underscore id");
    let written = tmp.path().join("ferrum/proxies/%5Fdisabled-by-loader.yaml");
    assert!(written.is_file(), "expected {}", written.display());

    let loaded = gitforgeops::config::load_resources(tmp.path()).unwrap();
    let ids: Vec<String> = loaded
        .iter()
        .filter_map(|(_, resource)| match resource {
            Resource::Proxy { spec } => Some(spec.id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(ids, vec!["_disabled-by-loader".to_string()]);
}

#[test]
fn import_keeps_encoded_and_literal_ids_distinct() {
    // Encoding only the first character keeps the mapping injective: `_foo`
    // and `%5Ffoo` are different resources and must not collide on one path.
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.proxies[0].id = "_collide".to_string();
    let mut twin = config.proxies[0].clone();
    twin.id = "%5Fcollide".to_string();
    config.proxies.push(twin);

    split_config(&config, tmp.path()).unwrap();
    for name in ["%5Fcollide.yaml", "%255Fcollide.yaml"] {
        let path = tmp.path().join("ferrum/proxies").join(name);
        assert!(path.is_file(), "expected {}", path.display());
    }
}

#[test]
fn import_reports_backup_sections_it_cannot_represent() {
    // `Resource` models four kinds. API specs and gateway trust bundles are
    // admin-API-managed and must not be written as resource files that
    // `apply` could never round-trip — they are counted and reported instead.
    let result = gitforgeops::import::ImportResult {
        proxies: 2,
        skipped_api_specs: 3,
        skipped_trust_bundles: 1,
        ..Default::default()
    };

    let notice = result
        .unmanaged_sections_notice()
        .expect("expected a notice");
    assert!(notice.contains("3 API spec(s)"), "{notice}");
    assert!(notice.contains("1 gateway trust-bundle"), "{notice}");
    assert!(notice.contains("/api-specs"), "{notice}");
}

// --- Spec-owned resources (G2) ----------------------------------------------

/// A resource carrying an `api_spec_id` is owned by the gateway's OpenAPI-spec
/// ingestion, which rewrites it on every spec import. Writing it as a repo file
/// would give it a second owner and produce drift no edit resolves, so import
/// skips and counts it.
#[test]
fn split_config_skips_spec_provisioned_resources() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();

    // A second proxy, identical except that the spec owns it.
    let mut spec_proxy = config.proxies[0].clone();
    spec_proxy.id = "proxy-from-spec".to_string();
    spec_proxy.api_spec_id = Some("spec-petstore".to_string());
    config.proxies.push(spec_proxy);

    let result = split_config(&config, tmp.path()).unwrap();

    assert_eq!(result.proxies, 1, "only the repo-owned proxy is written");
    assert_eq!(result.skipped_spec_owned, 1);
    assert!(tmp.path().join("ferrum/proxies/proxy-test.yaml").exists());
    assert!(
        !tmp.path()
            .join("ferrum/proxies/proxy-from-spec.yaml")
            .exists(),
        "a spec-provisioned proxy must not be written as a repo file"
    );
}

#[test]
fn split_config_skips_spec_provisioned_upstreams_and_plugin_configs() {
    let tmp = tempfile::tempdir().unwrap();
    let upstream: Upstream = serde_yaml::from_str(
        "id: pool-from-spec\nnamespace: ferrum\ntargets: []\napi_spec_id: spec-petstore\n",
    )
    .unwrap();
    let plugin: PluginConfig = serde_yaml::from_str(
        "id: plugin-from-spec\nnamespace: ferrum\nplugin_name: cors\nscope: global\napi_spec_id: spec-petstore\n",
    )
    .unwrap();
    let config = GatewayConfig {
        upstreams: vec![upstream],
        plugin_configs: vec![plugin],
        ..GatewayConfig::default()
    };

    let result = split_config(&config, tmp.path()).unwrap();

    assert_eq!(result.upstreams, 0);
    assert_eq!(result.plugin_configs, 0);
    assert_eq!(result.skipped_spec_owned, 2);
    assert!(
        gitforgeops::config::load_resources(tmp.path())
            .unwrap()
            .is_empty(),
        "nothing spec-owned may land in the resource tree"
    );
}

#[test]
fn import_notice_reports_skipped_spec_provisioned_resources() {
    let result = gitforgeops::import::ImportResult {
        proxies: 2,
        skipped_spec_owned: 4,
        ..Default::default()
    };

    let notice = result
        .unmanaged_sections_notice()
        .expect("expected a notice");
    assert!(
        notice.contains("4 spec-provisioned resources skipped — managed by API spec ingestion"),
        "{notice}"
    );
    assert!(notice.contains("api_spec_id"), "{notice}");
}

#[test]
fn import_notice_covers_spec_owned_and_unmanaged_sections_together() {
    let result = gitforgeops::import::ImportResult {
        skipped_api_specs: 1,
        skipped_trust_bundles: 2,
        skipped_spec_owned: 3,
        ..Default::default()
    };

    let notice = result
        .unmanaged_sections_notice()
        .expect("expected a notice");
    assert!(notice.contains("1 API spec(s)"), "{notice}");
    assert!(notice.contains("2 gateway trust-bundle"), "{notice}");
    assert!(notice.contains("3 spec-provisioned resources"), "{notice}");
}

#[test]
fn import_is_quiet_when_the_backup_has_no_unmanaged_sections() {
    let result = gitforgeops::import::ImportResult {
        proxies: 1,
        ..Default::default()
    };
    assert!(result.unmanaged_sections_notice().is_none());
}

#[test]
fn import_replaces_every_string_credential_leaf_before_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "live-key"}, {"key": "second-key"}],
        "jwt": [{"secret": "live-jwt-secret-that-is-long-enough"}],
        "hmac_auth": [{"secret": "live-hmac-secret-that-is-long-enough"}],
        "mtls_auth": [{"identity": "CN=production-client"}],
        "basicauth": [{"password_hash": "hmac_sha256:live-hash"}],
        "custom": [{"nested": {"token": "custom-live-token"}}]
    }))
    .unwrap();

    let result = split_config(&config, tmp.path()).unwrap();
    // `mtls_auth[].identity` is a certificate subject, not a secret: it has to
    // match a real certificate, cannot be generated, and blanking it would
    // leave the resource file unable to say which certificate it means.
    assert_eq!(result.redacted_credential_values, 6);

    let consumer =
        std::fs::read_to_string(tmp.path().join("ferrum/consumers/consumer-test.yaml")).unwrap();
    for secret in [
        "live-key",
        "second-key",
        "live-jwt-secret-that-is-long-enough",
        "live-hmac-secret-that-is-long-enough",
        "hmac_sha256:live-hash",
        "custom-live-token",
    ] {
        assert!(
            !consumer.contains(secret),
            "redacted Consumer output contained a credential fixture"
        );
    }
    assert!(
        consumer.contains("CN=production-client"),
        "the mTLS identity must survive import: {consumer}"
    );
    assert_eq!(
        consumer.matches("${gh-env-secret:alloc=require}").count(),
        6,
        "redacted Consumer output did not contain every expected placeholder"
    );
    for entry in walkdir::WalkDir::new(tmp.path()) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        for secret in [
            "live-key",
            "second-key",
            "live-jwt-secret-that-is-long-enough",
            "live-hmac-secret-that-is-long-enough",
            "hmac_sha256:live-hash",
            "custom-live-token",
        ] {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "generated import output contained a credential fixture"
            );
        }
    }
    let notice = result.unmanaged_sections_notice().unwrap();
    assert!(notice.contains("6 credential value(s)"), "{notice}");
}

/// F5: `basicauth[].username` is the login name the caller presents, not a
/// secret. Brokering it would demand a hand-seeded slot for a public value.
#[test]
fn import_keeps_consumer_identity_fields_out_of_the_broker() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "basicauth": [{"username": "service-account-alpha", "password_hash": "hmac_sha256:live"}],
        "mtls_auth": [{"identity": "CN=production-client", "ca_pin": "live-pin-value"}]
    }))
    .unwrap();

    let result = split_config(&config, tmp.path()).unwrap();

    assert_eq!(result.redacted_credential_values, 2);
    let consumer =
        std::fs::read_to_string(tmp.path().join("ferrum/consumers/consumer-test.yaml")).unwrap();
    assert!(consumer.contains("service-account-alpha"), "{consumer}");
    assert!(consumer.contains("CN=production-client"), "{consumer}");
    assert!(!consumer.contains("hmac_sha256:live"), "{consumer}");
    assert!(!consumer.contains("live-pin-value"), "{consumer}");
}

#[test]
fn imported_placeholders_derive_the_expected_broker_slots() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "first"}, {"key": "second"}],
        "jwt": [{"secret": "jwt-secret"}],
        "custom": [{"nested": {"token": "custom-secret"}}]
    }))
    .unwrap();
    let original_credentials = config.consumers[0].credentials.clone();

    split_config(&config, tmp.path()).unwrap();
    let resources = gitforgeops::config::load_resources(tmp.path()).unwrap();
    let assembled = gitforgeops::config::assemble(resources).unwrap();
    let report = gitforgeops::secrets::report_secrets(
        &assembled.gateway,
        &std::collections::BTreeMap::new(),
    )
    .unwrap();
    let slots = report
        .results
        .iter()
        .map(|result| result.slot.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        slots,
        std::collections::BTreeSet::from([
            "ferrum/consumer-test/custom/nested/token",
            "ferrum/consumer-test/jwt/secret",
            "ferrum/consumer-test/keyauth/[1]/key",
            "ferrum/consumer-test/keyauth/key",
        ])
    );

    let bundle = std::collections::BTreeMap::from([
        (
            "ferrum/consumer-test/keyauth/key".to_string(),
            "first".to_string(),
        ),
        (
            "ferrum/consumer-test/keyauth/[1]/key".to_string(),
            "second".to_string(),
        ),
        (
            "ferrum/consumer-test/jwt/secret".to_string(),
            "jwt-secret".to_string(),
        ),
        (
            "ferrum/consumer-test/custom/nested/token".to_string(),
            "custom-secret".to_string(),
        ),
    ]);
    let mut round_tripped = assembled.gateway;
    gitforgeops::secrets::resolve_secrets_with_mode(
        &mut round_tripped,
        &bundle,
        gitforgeops::config::env::GatewayMode::Api,
    )
    .unwrap();
    assert_eq!(
        round_tripped.consumers[0].credentials, original_credentials,
        "seeding the derived slots must reconstruct the imported credential document without drift"
    );
}

#[test]
fn unsafe_credential_shape_fails_before_publishing_any_files() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = make_test_config();
    config.consumers[0]
        .credentials
        .insert("custom".to_string(), serde_json::json!({"token": 1234}));

    let error = split_config(&config, tmp.path()).unwrap_err().to_string();
    assert!(error.contains("non-string leaf"), "{error}");
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn import_requires_an_empty_output_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let sentinel = tmp.path().join("keep.txt");
    std::fs::write(&sentinel, "keep me").unwrap();

    let error = split_config(&make_test_config(), tmp.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("non-empty output directory"), "{error}");
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "keep me");
}

#[test]
fn import_atomically_creates_an_absent_output_tree() {
    let parent = tempfile::tempdir().unwrap();
    let output = parent.path().join("new-import");

    let result = split_config(&make_test_config(), &output).unwrap();
    assert_eq!(result.proxies, 1);
    assert!(output.join("ferrum/proxies/proxy-test.yaml").exists());
    assert!(std::fs::read_dir(parent.path()).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".gitforgeops-import-")));
}

#[test]
fn file_import_parses_and_reports_the_full_backup_envelope() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let config = make_test_config();
    let mut backup = serde_json::to_value(config).unwrap();
    let object = backup.as_object_mut().unwrap();
    object.insert(
        "api_specs".to_string(),
        serde_json::json!({"section_version": "2", "items": [{"id": "spec-one"}]}),
    );
    object.insert(
        "gateway_trust_bundles".to_string(),
        serde_json::json!([{"revision": 1}]),
    );
    object.insert(
        "future_backup_section".to_string(),
        serde_json::json!({"opaque": true}),
    );
    object.insert("ferrum_version".to_string(), serde_json::json!("2.4.0"));
    object.insert(
        "exported_at".to_string(),
        serde_json::json!("2026-08-30T12:00:00Z"),
    );
    object.insert("source".to_string(), serde_json::json!("database"));
    object.insert(
        "counts".to_string(),
        serde_json::json!({
            "proxies": 1,
            "consumers": 1,
            "plugin_configs": 0,
            "upstreams": 0,
            "api_specs": 1,
            "gateway_trust_bundles": 1
        }),
    );
    std::fs::write(&backup_path, serde_yaml::to_string(&backup).unwrap()).unwrap();

    let output = tempfile::tempdir().unwrap();
    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        output.path(),
        None,
        &strict_passthrough(),
    )
    .unwrap();

    assert_eq!(result.skipped_api_specs, 1);
    assert_eq!(result.skipped_trust_bundles, 1);
    assert_eq!(
        result.unsupported_sections,
        vec!["future_backup_section".to_string()]
    );
    assert_eq!(result.sources.len(), 1);
    assert_eq!(result.sources[0].source_kind, "file");
    assert_eq!(result.sources[0].config_version, "1");
    assert_eq!(result.sources[0].ferrum_version.as_deref(), Some("2.4.0"));
    assert_eq!(result.sources[0].source.as_deref(), Some("database"));
    let source_notice = result.source_metadata_notice().unwrap();
    assert!(
        source_notice.contains("ferrum_version=2.4.0"),
        "{source_notice}"
    );
    assert!(source_notice.contains("source=database"), "{source_notice}");
    let notice = result.unmanaged_sections_notice().unwrap();
    assert!(notice.contains("future_backup_section"), "{notice}");

    let manifest_path = output
        .path()
        .join(gitforgeops::import::IMPORT_MANIFEST_FILENAME);
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["format_version"], 1);
    assert_eq!(manifest["import"]["skipped_api_specs"], 1);
    assert_eq!(manifest["import"]["skipped_trust_bundles"], 1);
    assert_eq!(manifest["import"]["sources"][0]["namespaces"][0], "ferrum");
    assert_eq!(
        manifest["import"]["sources"][0]["declared_counts"]["api_specs"],
        1
    );
}

#[tokio::test]
async fn api_import_rejects_cross_namespace_resources_before_writing() {
    use gitforgeops::config::env::{ApplyStrategy, EnvConfig, GatewayMode};
    use gitforgeops::http_client::AdminClient;

    let mut config = make_test_config();
    config.proxies[0].namespace = "other".to_string();
    config.consumers.clear();
    let body = serde_json::to_string(&config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    let env = EnvConfig {
        gateway_url: Some(format!("http://{address}")),
        admin_jwt_secret: Some("test-secret-must-be-at-least-32-chars".to_string()),
        gateway_mode: GatewayMode::Api,
        apply_strategy: ApplyStrategy::Incremental,
        ..EnvConfig::default()
    };
    // `new_scoped` is the only public constructor; the import below is
    // scoped to the same single namespace it asks the gateway for.
    let client = AdminClient::new_scoped(&env, ["ferrum"]).unwrap();
    let output = tempfile::tempdir().unwrap();

    let error = gitforgeops::import::from_api::import_from_api(
        &client,
        output.path(),
        Some("ferrum"),
        None,
        &strict_passthrough(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("cross-namespace import"), "{error}");
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn api_import_refuses_cached_backup_before_writing() {
    use gitforgeops::config::env::{ApplyStrategy, EnvConfig, GatewayMode};
    use gitforgeops::http_client::AdminClient;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).unwrap();
        let body =
            r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[],"upstreams":[]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-data-source: cached\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    let env = EnvConfig {
        gateway_url: Some(format!("http://{address}")),
        admin_jwt_secret: Some("test-secret-must-be-at-least-32-chars".to_string()),
        gateway_mode: GatewayMode::Api,
        apply_strategy: ApplyStrategy::Incremental,
        ..EnvConfig::default()
    };
    // `new_scoped` is the only public constructor; the import below is
    // scoped to the same single namespace it asks the gateway for.
    let client = AdminClient::new_scoped(&env, ["ferrum"]).unwrap();
    let output = tempfile::tempdir().unwrap();

    let error = gitforgeops::import::from_api::import_from_api(
        &client,
        output.path(),
        Some("ferrum"),
        None,
        &strict_passthrough(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("X-Data-Source: cached"), "{error}");
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);
}

/// F6: top-level section names come out of an untrusted backup document, so a
/// crafted key must not carry ANSI escapes or line breaks into the operator's
/// terminal and the CI log.
#[test]
fn unsupported_section_names_are_sanitized_before_being_printed() {
    let result = gitforgeops::import::ImportResult {
        unsupported_sections: vec![
            "future_a\u{1b}[2J\u{1b}[H".to_string(),
            "future_b\nImported: 0 proxies".to_string(),
        ],
        ..Default::default()
    };

    let notice = result.unmanaged_sections_notice().expect("notice");

    assert!(
        !notice.chars().any(|character| character.is_control()),
        "{notice:?}"
    );
    assert!(notice.contains("future_a"), "{notice}");
    assert!(notice.contains("future_b"), "{notice}");
}

/// F11: a `..` under an ancestor that does not exist used to walk the
/// containment resolver up to a component with no file name and report
/// "cannot resolve path", which describes nothing an operator can act on.
/// Collapsing the components lexically first makes the path resolve normally.
#[test]
fn migration_bundle_paths_normalize_dotdot_under_a_missing_ancestor() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let mut config = make_test_config();
    config.consumers[0].credentials = serde_json::from_value(serde_json::json!({
        "keyauth": [{"key": "live-key"}]
    }))
    .unwrap();
    std::fs::write(&backup_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent
        .path()
        .join("not-created-yet")
        .join("..")
        .join("migration.json");

    gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &strict_passthrough(),
    )
    .expect("a normalizable path must not be refused by the containment resolver");

    assert!(destination_parent.path().join("migration.json").exists());
}
