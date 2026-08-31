use std::sync::Mutex;

use gitforgeops::diff::resource_diff::{state_key, state_key_namespace, DiffAction, ResourceDiff};
use gitforgeops::state::StateFile;
use tempfile::TempDir;

// Process-wide lock — tests in this file all mutate CWD, and cargo runs tests
// in parallel threads within one binary.
static CWD_LOCK: Mutex<()> = Mutex::new(());

fn with_cwd<F: FnOnce()>(dir: &std::path::Path, f: F) {
    let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::set_current_dir(original).unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn partial_apply_keeps_the_previous_last_applied_metadata() {
    let mut state = StateFile {
        last_applied_at: Some("2026-08-01T00:00:00Z".to_string()),
        last_applied_commit: Some("previous-clean-commit".to_string()),
        ..StateFile::default()
    };

    state.stamp_last_applied_if_clean(false);
    assert_eq!(
        state.last_applied_at.as_deref(),
        Some("2026-08-01T00:00:00Z")
    );
    assert_eq!(
        state.last_applied_commit.as_deref(),
        Some("previous-clean-commit")
    );

    state.stamp_last_applied_if_clean(true);
    assert_ne!(
        state.last_applied_at.as_deref(),
        Some("2026-08-01T00:00:00Z")
    );
}

#[test]
fn state_file_writes_and_reads_per_env() {
    let dir = TempDir::new().unwrap();

    with_cwd(dir.path(), || {
        assert!(StateFile::is_first_apply("staging"));

        let mut state = StateFile::load("staging").unwrap();
        state
            .resources
            .insert(state_key("ferrum", "Proxy", "p1"), "sha256:abc".to_string());
        state.last_applied_at = Some("2026-04-23T00:00:00Z".to_string());
        state.save().unwrap();

        assert!(!StateFile::is_first_apply("staging"));
        assert!(StateFile::is_first_apply("production"));

        let reloaded = StateFile::load("staging").unwrap();
        assert_eq!(reloaded.resources.len(), 1);
        assert_eq!(reloaded.environment, "staging");
    });
}

#[test]
fn scoped_record_preserves_entries_outside_scope() {
    // Regression guard: in shared mode with multiple namespaces, a scoped
    // apply (FERRUM_NAMESPACE=ferrum) used to clear the WHOLE resources
    // map and repopulate only from the namespace-filtered desired. That
    // dropped managed entries for every other namespace, so the next diff
    // classified them as unmanaged and stopped reconciling.
    use gitforgeops::config::schema::{BackendScheme, GatewayConfig, Proxy};

    fn proxy(id: &str, ns: &str) -> Proxy {
        Proxy {
            id: id.to_string(),
            name: None,
            namespace: ns.to_string(),
            hosts: vec![],
            listen_path: Some(format!("/{id}")),
            backend_scheme: Some(BackendScheme::Https),
            backend_host: "b".to_string(),
            backend_port: 443,
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

    let mut state = StateFile::default();
    // Prior state has entries in two namespaces.
    state
        .resources
        .insert(state_key("ferrum", "Proxy", "one"), "sha256:A".to_string());
    let platform_key = state_key("platform", "Proxy", "two");
    state
        .resources
        .insert(platform_key.clone(), "sha256:B".to_string());

    // Scoped apply: only ferrum is in scope, and desired has been filtered
    // to ferrum.
    let desired = GatewayConfig {
        proxies: vec![proxy("one-updated", "ferrum")],
        ..GatewayConfig::default()
    };
    state.record(&desired, &["ferrum".to_string()]);

    // ferrum entries refreshed.
    assert!(state
        .resources
        .contains_key(&state_key("ferrum", "Proxy", "one-updated")));
    assert!(!state
        .resources
        .contains_key(&state_key("ferrum", "Proxy", "one")));
    // platform entry preserved — this is the invariant the scoped apply
    // must honor.
    assert_eq!(
        state.resources.get(&platform_key),
        Some(&"sha256:B".to_string())
    );
}

#[test]
fn write_ahead_add_reservation_survives_before_gateway_success_is_recorded() {
    use gitforgeops::apply::AppliedOp;
    use gitforgeops::config::schema::{GatewayConfig, Upstream};

    let desired = GatewayConfig {
        upstreams: vec![serde_json::from_value::<Upstream>(serde_json::json!({
            "id": "new-upstream",
            "namespace": "ferrum",
            "targets": [{"host": "127.0.0.1", "port": 8080}]
        }))
        .unwrap()],
        ..GatewayConfig::default()
    };
    let diffs = vec![ResourceDiff {
        action: DiffAction::Add,
        kind: "Upstream".to_string(),
        id: "new-upstream".to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }];
    let mut state = StateFile::default();
    let key = state_key("ferrum", "Upstream", "new-upstream");

    assert_eq!(state.reserve_adds(&diffs, &desired).unwrap(), 1);
    assert!(state.pending_creates.contains(&key));
    assert!(
        !state.previously_managed_keys().contains(&key),
        "a pending request must not grant deletion authority"
    );

    state
        .record_op(
            &AppliedOp {
                kind: "Upstream".to_string(),
                namespace: "ferrum".to_string(),
                id: "new-upstream".to_string(),
                action: DiffAction::Add,
            },
            &desired,
        )
        .unwrap();
    assert!(!state.pending_creates.contains(&key));
    assert!(state.previously_managed_keys().contains(&key));
}

#[test]
fn exact_live_evidence_keeps_create_pending_until_an_idempotent_assertion() {
    use std::collections::BTreeMap;

    use gitforgeops::config::schema::{GatewayConfig, Upstream};

    let desired = GatewayConfig {
        upstreams: vec![serde_json::from_value::<Upstream>(serde_json::json!({
            "id": "new-upstream",
            "namespace": "ferrum",
            "targets": [{"host": "127.0.0.1", "port": 8080}]
        }))
        .unwrap()],
        ..GatewayConfig::default()
    };
    let diffs = vec![ResourceDiff {
        action: DiffAction::Add,
        kind: "Upstream".to_string(),
        id: "new-upstream".to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }];
    let key = state_key("ferrum", "Upstream", "new-upstream");
    let mut state = StateFile::default();
    state.reserve_adds(&diffs, &desired).unwrap();

    let mut exact_live = desired.clone();
    exact_live.upstreams[0].created_at += chrono::Duration::seconds(5);
    exact_live.upstreams[0].updated_at += chrono::Duration::seconds(5);
    let actual = BTreeMap::from([("ferrum".to_string(), exact_live)]);

    assert_eq!(
        state.reconcile_pending_creates(&desired, &actual).unwrap(),
        0
    );
    assert!(state.pending_creates.contains(&key));
    assert!(!state.previously_managed_keys().contains(&key));
}

#[test]
fn pending_create_stays_unmanaged_until_live_evidence_matches() {
    use std::collections::BTreeMap;

    use gitforgeops::config::schema::{GatewayConfig, Upstream};

    let desired = GatewayConfig {
        upstreams: vec![serde_json::from_value::<Upstream>(serde_json::json!({
            "id": "new-upstream",
            "namespace": "ferrum",
            "targets": [{"host": "127.0.0.1", "port": 8080}]
        }))
        .unwrap()],
        ..GatewayConfig::default()
    };
    let diffs = vec![ResourceDiff {
        action: DiffAction::Add,
        kind: "Upstream".to_string(),
        id: "new-upstream".to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }];
    let key = state_key("ferrum", "Upstream", "new-upstream");
    let mut state = StateFile::default();
    state.reserve_adds(&diffs, &desired).unwrap();

    let actual = BTreeMap::from([("ferrum".to_string(), GatewayConfig::default())]);
    assert_eq!(
        state.reconcile_pending_creates(&desired, &actual).unwrap(),
        0
    );
    assert!(state.pending_creates.contains(&key));
    assert!(!state.previously_managed_keys().contains(&key));
}

#[test]
fn pending_create_without_desired_or_live_row_is_cleared() {
    use std::collections::BTreeMap;

    use gitforgeops::config::schema::{GatewayConfig, Upstream};

    let original_desired = GatewayConfig {
        upstreams: vec![serde_json::from_value::<Upstream>(serde_json::json!({
            "id": "new-upstream",
            "namespace": "ferrum",
            "targets": [{"host": "127.0.0.1", "port": 8080}]
        }))
        .unwrap()],
        ..GatewayConfig::default()
    };
    let diffs = vec![ResourceDiff {
        action: DiffAction::Add,
        kind: "Upstream".to_string(),
        id: "new-upstream".to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }];
    let key = state_key("ferrum", "Upstream", "new-upstream");
    let mut state = StateFile::default();
    state.reserve_adds(&diffs, &original_desired).unwrap();

    let empty = GatewayConfig::default();
    let actual = BTreeMap::from([("ferrum".to_string(), empty.clone())]);
    assert_eq!(state.reconcile_pending_creates(&empty, &actual).unwrap(), 1);
    assert!(!state.pending_creates.contains(&key));
    assert!(!state.previously_managed_keys().contains(&key));
}

#[test]
fn pending_create_with_removed_desired_but_live_row_fails_closed() {
    use std::collections::BTreeMap;

    use gitforgeops::config::schema::{GatewayConfig, Upstream};

    let original_desired = GatewayConfig {
        upstreams: vec![serde_json::from_value::<Upstream>(serde_json::json!({
            "id": "new-upstream",
            "namespace": "ferrum",
            "targets": [{"host": "127.0.0.1", "port": 8080}]
        }))
        .unwrap()],
        ..GatewayConfig::default()
    };
    let diffs = vec![ResourceDiff {
        action: DiffAction::Add,
        kind: "Upstream".to_string(),
        id: "new-upstream".to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }];
    let key = state_key("ferrum", "Upstream", "new-upstream");
    let mut state = StateFile::default();
    state.reserve_adds(&diffs, &original_desired).unwrap();

    let actual = BTreeMap::from([("ferrum".to_string(), original_desired)]);
    let error = state
        .reconcile_pending_creates(&GatewayConfig::default(), &actual)
        .unwrap_err()
        .to_string();
    assert!(error.contains("ownership cannot be proven"), "{error}");
    assert!(state.pending_creates.contains(&key));
    assert!(!state.previously_managed_keys().contains(&key));
}

#[test]
fn authoritative_absence_removes_stale_managed_denominator_entries() {
    use std::collections::BTreeMap;

    use gitforgeops::config::schema::GatewayConfig;

    let stale_key = state_key("ferrum", "Upstream", "already-gone");
    let outside_scope_key = state_key("platform", "Upstream", "not-read");
    let mut state = StateFile::default();
    state
        .resources
        .insert(stale_key.clone(), "sha256:stale".to_string());
    state
        .resources
        .insert(outside_scope_key.clone(), "sha256:keep".to_string());
    let actual = BTreeMap::from([("ferrum".to_string(), GatewayConfig::default())]);

    assert_eq!(
        state.reconcile_absent_managed_resources(&GatewayConfig::default(), &actual),
        1
    );
    assert!(!state.resources.contains_key(&stale_key));
    assert_eq!(
        state.resources.get(&outside_scope_key),
        Some(&"sha256:keep".to_string())
    );
}

#[test]
fn state_load_uses_requested_environment_name() {
    // The selected environment path is authoritative. Loading a file through
    // `.state/production.json` should save back to the same path even if the
    // embedded environment field was edited by hand.
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        let key = state_key("ferrum", "Proxy", "p1");
        let state_json = format!(
            r#"{{
            "version": 2,
            "environment": "staging",
            "resources": {{"{key}": "sha256:abc"}}
        }}"#
        );
        std::fs::write(".state/production.json", state_json).unwrap();

        let state = StateFile::load("production").unwrap();
        assert_eq!(state.environment, "production");

        // Save must go to .state/production.json, not .state/.json.
        state.save().unwrap();
        assert!(std::path::Path::new(".state/production.json").exists());
        assert!(!std::path::Path::new(".state/.json").exists());
    });
}

#[test]
fn state_load_rejects_malformed_existing_state() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        std::fs::write(".state/production.json", "{not-json").unwrap();

        let err = StateFile::load("production").unwrap_err().to_string();
        assert!(
            err.contains("failed to parse state file"),
            "expected parse error for malformed state, got: {err}"
        );
    });
}

#[test]
fn state_lock_rejects_concurrent_mutation_and_cleans_up_on_drop() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        let lock = StateFile::lock("production").unwrap();
        let err = StateFile::lock("production").unwrap_err().to_string();
        assert!(
            err.contains("locked by another gitforgeops process"),
            "expected lock contention error, got: {err}"
        );

        drop(lock);
        let second = StateFile::lock("production").unwrap();
        drop(second);
        assert!(!std::path::Path::new(".state/production.lock").exists());
    });
}

#[test]
fn state_keys_escape_colons_in_namespace_and_id() {
    let key = state_key("team:alpha", "Proxy", "api:v1");

    assert_eq!(state_key_namespace(&key).as_deref(), Some("team:alpha"));
    assert_eq!(
        key,
        "__gitforgeops_state_key_v2:team%3Aalpha:Proxy:api%3Av1"
    );
}

#[test]
fn raw_state_key_namespace_is_rejected() {
    assert_eq!(state_key_namespace("team%3Ablue:Proxy:api"), None);
    assert_eq!(state_key_namespace("team:alpha:Proxy:api:v1"), None);
    assert_eq!(state_key_namespace("team:Proxy:alpha:Consumer:api"), None);
}

#[test]
fn state_load_rejects_raw_resource_keys() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        let state_json = r#"{
            "version": 2,
            "environment": "production",
            "resources": {"ferrum:Proxy:api": "sha256:old"}
        }"#;
        std::fs::write(".state/production.json", state_json).unwrap();

        let err = StateFile::load("production").unwrap_err().to_string();
        assert!(
            err.contains("invalid resource key"),
            "expected invalid key error, got: {err}"
        );
    });
}

#[test]
fn state_file_persists_override_records_for_audit() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        let mut state = StateFile::load("production").unwrap();
        state.record_override("backend_scheme", "abc123", "alice");
        state.record_override("proxy_timeout_bands", "abc123", "alice");
        state.save().unwrap();

        let reloaded = StateFile::load("production").unwrap();
        assert_eq!(reloaded.overrides.len(), 2);
        assert_eq!(reloaded.overrides[0].rule_id, "backend_scheme");
        assert_eq!(reloaded.overrides[0].approver, "alice");
        assert_eq!(reloaded.overrides[0].commit, "abc123");
        assert!(!reloaded.overrides[0].recorded_at.is_empty());
    });
}

#[test]
fn state_file_records_credential_metadata() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        let mut state = StateFile::load("staging").unwrap();
        state.record_credential("ferrum/app/api_key", 0, Some("alice"), Some("42"));
        state.save().unwrap();

        let reloaded = StateFile::load("staging").unwrap();
        let meta = reloaded.credentials.get("ferrum/app/api_key").unwrap();
        assert_eq!(meta.delivered_to.as_deref(), Some("alice"));
        assert_eq!(meta.delivered_run_id.as_deref(), Some("42"));
        let serialized = serde_json::to_string(&reloaded).unwrap();
        assert!(!serialized.contains("sha256_prefix"));
        assert!(!serialized.contains("secretvalue"));
    });
}

#[test]
fn public_state_is_identical_when_only_a_consumer_secret_changes() {
    use gitforgeops::config::schema::GatewayConfig;

    fn config(secret: &str) -> GatewayConfig {
        serde_yaml::from_str(&format!(
            r#"
consumers:
  - id: app
    username: app
    namespace: ferrum
    credentials:
      keyauth:
        - key: {secret}
"#
        ))
        .unwrap()
    }

    let key = state_key("ferrum", "Consumer", "app");
    let mut first = StateFile::default();
    first.record(&config("first-low-entropy-secret"), &["ferrum".to_string()]);
    let mut second = StateFile::default();
    second.record(
        &config("different-low-entropy-secret"),
        &["ferrum".to_string()],
    );

    assert_eq!(first.resources.get(&key), Some(&"managed:v1".to_string()));
    assert_eq!(first.resources, second.resources);
    assert!(!serde_json::to_string(&first)
        .unwrap()
        .contains("first-low-entropy-secret"));
}

#[test]
fn loading_v2_state_sanitizes_legacy_hash_oracles_on_next_save() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        let key = state_key("ferrum", "Consumer", "app");
        let old = serde_json::json!({
            "version": 2,
            "environment": "production",
            "last_applied_at": null,
            "last_applied_commit": null,
            "resources": {key.clone(): "sha256:consumer-secret-oracle"},
            "credentials": {
                "ferrum/app/keyauth/key": {
                    "slot": "ferrum/app/keyauth/key",
                    "shard": 0,
                    "last_rotated": "2026-01-01T00:00:00Z",
                    "sha256_prefix": "deadbeefdeadbeef"
                }
            },
            "credential_bundle_versions": {"0": "sha256:bundle-oracle"},
            "credential_shard_count": 1,
            "overrides": []
        });
        std::fs::write(
            ".state/production.json",
            serde_json::to_string_pretty(&old).unwrap(),
        )
        .unwrap();

        let state = StateFile::load("production").unwrap();
        assert_eq!(state.version, 3);
        assert_eq!(state.resources.get(&key), Some(&"managed:v1".to_string()));
        state.save().unwrap();

        let rewritten = std::fs::read_to_string(".state/production.json").unwrap();
        assert!(!rewritten.contains("sha256_prefix"), "{rewritten}");
        assert!(
            !rewritten.contains("credential_bundle_versions"),
            "{rewritten}"
        );
        assert!(!rewritten.contains("secret-oracle"), "{rewritten}");
        assert!(!rewritten.contains("bundle-oracle"), "{rewritten}");
    });
}

#[test]
fn state_load_rejects_future_versions_instead_of_downgrading_them() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        let state = serde_json::json!({
            "version": 99,
            "environment": "production",
            "resources": {}
        });
        std::fs::write(
            ".state/production.json",
            serde_json::to_string(&state).unwrap(),
        )
        .unwrap();

        let error = StateFile::load("production").unwrap_err().to_string();
        assert!(error.contains("unsupported version 99"), "{error}");
    });
}

#[test]
fn state_save_sanitizes_manually_inserted_resource_hashes() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        let mut state = StateFile {
            environment: "production".to_string(),
            ..StateFile::default()
        };
        state.resources.insert(
            state_key("ferrum", "Consumer", "app"),
            "sha256:credential-derived-oracle".to_string(),
        );
        state.save().unwrap();

        let persisted = std::fs::read_to_string(".state/production.json").unwrap();
        assert!(
            !persisted.contains("credential-derived-oracle"),
            "{persisted}"
        );
        assert!(persisted.contains("managed:v1"), "{persisted}");
    });
}

#[test]
fn record_op_preserves_state_for_failed_delete() {
    // For a failed Delete, the resource is absent from `desired` (user
    // removed it from the repo) but still live on the gateway because the
    // delete failed. State must keep tracking that resource so the next
    // compute_diff_with_ownership run retries the deletion instead of
    // classifying it as unmanaged.
    //
    // cmd_apply walks `ApplyResult::applied_incremental` and calls
    // `state.record_op` for each successful op. Failed ops never appear in
    // that list, so their state entries persist untouched and the next
    // apply's diff still sees the resource as managed →
    // generates another Delete → retries.
    use gitforgeops::apply::AppliedOp;
    use gitforgeops::config::schema::{BackendScheme, Consumer, GatewayConfig, Proxy};
    use gitforgeops::diff::resource_diff::DiffAction;

    fn proxy(id: &str, ns: &str) -> Proxy {
        Proxy {
            id: id.to_string(),
            name: None,
            namespace: ns.to_string(),
            hosts: vec![],
            listen_path: Some(format!("/{id}")),
            backend_scheme: Some(BackendScheme::Https),
            backend_host: "b".to_string(),
            backend_port: 443,
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

    // Prior state: two managed resources in `ferrum`.
    let mut state = StateFile::default();
    let keep_key = state_key("ferrum", "Proxy", "keep-me");
    let delete_key = state_key("ferrum", "Proxy", "to-delete");
    state
        .resources
        .insert(keep_key.clone(), "sha256:OLD".to_string());
    state
        .resources
        .insert(delete_key.clone(), "sha256:DEL".to_string());

    // User removed `to-delete` from the repo. Apply tried Delete but the
    // gateway returned 500. Apply also successfully created `new-one`.
    // `desired` reflects the repo state (no `to-delete`).
    let desired = GatewayConfig {
        proxies: vec![proxy("keep-me", "ferrum"), proxy("new-one", "ferrum")],
        ..GatewayConfig::default()
    };

    // Successful ops: only the create. The failed delete is NOT in this list.
    let successful_ops = vec![AppliedOp {
        kind: "Proxy".to_string(),
        namespace: "ferrum".to_string(),
        id: "new-one".to_string(),
        action: DiffAction::Add,
    }];

    for op in &successful_ops {
        state.record_op(op, &desired).unwrap();
    }

    // Successful create is in state.
    assert!(
        state
            .resources
            .contains_key(&state_key("ferrum", "Proxy", "new-one")),
        "successful Add must record into state"
    );
    // Failed delete's key is PRESERVED — the resource is still managed,
    // and the next diff will retry the delete instead of treating it as
    // unmanaged.
    assert!(
        state.resources.contains_key(&delete_key),
        "failed Delete must NOT remove the key from state, otherwise the resource is orphaned"
    );
    // Pre-existing managed entry is untouched.
    assert!(
        state.resources.contains_key(&keep_key),
        "unchanged managed entry must persist"
    );

    // Now confirm the successful-Delete path also works: same scenario but
    // the delete succeeds. record_op for a Delete should remove the key.
    let mut state2 = state.clone();
    state2
        .record_op(
            &AppliedOp {
                kind: "Proxy".to_string(),
                namespace: "ferrum".to_string(),
                id: "to-delete".to_string(),
                action: DiffAction::Delete,
            },
            &desired,
        )
        .unwrap();
    assert!(
        !state2.resources.contains_key(&delete_key),
        "successful Delete must remove the key from state"
    );

    // Successful Modify on a Consumer should install the safe marker and not
    // touch other namespaces.
    let mut state3 = StateFile::default();
    let other_key = state_key("platform", "Consumer", "other");
    let app_key = state_key("ferrum", "Consumer", "app");
    state3
        .resources
        .insert(other_key.clone(), "sha256:OTHER".to_string());
    state3
        .resources
        .insert(app_key.clone(), "sha256:STALE".to_string());
    let consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let cfg = GatewayConfig {
        consumers: vec![consumer],
        ..GatewayConfig::default()
    };
    state3
        .record_op(
            &AppliedOp {
                kind: "Consumer".to_string(),
                namespace: "ferrum".to_string(),
                id: "app".to_string(),
                action: DiffAction::Modify,
            },
            &cfg,
        )
        .unwrap();
    assert_eq!(
        state3.resources.get(&app_key),
        Some(&"managed:v1".to_string()),
        "Modify must install the non-secret ownership marker"
    );
    assert_eq!(
        state3.resources.get(&other_key),
        Some(&"sha256:OTHER".to_string()),
        "out-of-namespace entry must remain untouched"
    );
}
