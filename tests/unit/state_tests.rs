use std::sync::Mutex;

use gitforgeops::state::StateFile;
use tempfile::TempDir;

// Process-wide lock — tests in this file all mutate CWD, and cargo runs tests
// in parallel threads within one binary.
static CWD_LOCK: Mutex<()> = Mutex::new(());

fn with_cwd<F: FnOnce()>(dir: &std::path::Path, f: F) {
    let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir).unwrap();
    f();
    std::env::set_current_dir(original).unwrap();
}

#[test]
fn state_file_writes_and_reads_per_env() {
    let dir = TempDir::new().unwrap();

    with_cwd(dir.path(), || {
        assert!(StateFile::is_first_apply("staging"));

        let mut state = StateFile::load("staging");
        state
            .resources
            .insert("ferrum:Proxy:p1".to_string(), "sha256:abc".to_string());
        state.last_applied_at = Some("2026-04-23T00:00:00Z".to_string());
        state.save().unwrap();

        assert!(!StateFile::is_first_apply("staging"));
        assert!(StateFile::is_first_apply("production"));

        let reloaded = StateFile::load("staging");
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
    use gitforgeops::config::schema::{BackendProtocol, GatewayConfig, Proxy};

    fn proxy(id: &str, ns: &str) -> Proxy {
        Proxy {
            id: id.to_string(),
            name: None,
            namespace: ns.to_string(),
            hosts: vec![],
            listen_path: Some(format!("/{id}")),
            backend_protocol: BackendProtocol::Https,
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    let mut state = StateFile::default();
    // Prior state has entries in two namespaces.
    state
        .resources
        .insert("ferrum:Proxy:one".to_string(), "sha256:A".to_string());
    state
        .resources
        .insert("platform:Proxy:two".to_string(), "sha256:B".to_string());

    // Scoped apply: only ferrum is in scope, and desired has been filtered
    // to ferrum.
    let desired = GatewayConfig {
        proxies: vec![proxy("one-updated", "ferrum")],
        ..GatewayConfig::default()
    };
    state.record(&desired, &["ferrum".to_string()]);

    // ferrum entries refreshed.
    assert!(state.resources.contains_key("ferrum:Proxy:one-updated"));
    assert!(!state.resources.contains_key("ferrum:Proxy:one"));
    // platform entry preserved — this is the invariant the scoped apply
    // must honor.
    assert_eq!(
        state.resources.get("platform:Proxy:two"),
        Some(&"sha256:B".to_string())
    );
}

#[test]
fn state_load_normalizes_environment_to_requested_name() {
    // Regression guard: if an env-specific state file was created via the
    // legacy migration from a read-only command, the on-disk `environment`
    // field is empty (serde default). Loading that file must patch the
    // in-memory state to the requested env name; otherwise the next
    // save() would path to `.state/.json`.
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        // Write a state file whose environment field is missing/default.
        let state_json = r#"{
            "version": 2,
            "resources": {"ferrum:Proxy:p1": "sha256:abc"}
        }"#;
        std::fs::write(".state/production.json", state_json).unwrap();

        let state = StateFile::load("production");
        assert_eq!(state.environment, "production");

        // Save must go to .state/production.json, not .state/.json.
        state.save().unwrap();
        assert!(std::path::Path::new(".state/production.json").exists());
        assert!(!std::path::Path::new(".state/.json").exists());
    });
}

#[test]
fn state_file_persists_override_records_for_audit() {
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        let mut state = StateFile::load("production");
        state.record_override("backend_scheme", "abc123", "alice");
        state.record_override("proxy_timeout_bands", "abc123", "alice");
        state.save().unwrap();

        let reloaded = StateFile::load("production");
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
        let mut state = StateFile::load("staging");
        state.record_credential(
            "ferrum/app/api_key",
            0,
            "secretvalue",
            Some("alice"),
            Some("42"),
        );
        state.save().unwrap();

        let reloaded = StateFile::load("staging");
        let meta = reloaded.credentials.get("ferrum/app/api_key").unwrap();
        assert_eq!(meta.delivered_to.as_deref(), Some("alice"));
        assert_eq!(meta.delivered_run_id.as_deref(), Some("42"));
        assert_eq!(meta.sha256_prefix.len(), 16);
        // Prefix should not reveal the value.
        assert_ne!(meta.sha256_prefix, "secretvalue");
    });
}

#[test]
fn record_op_preserves_state_for_failed_delete() {
    // Regression: cmd_apply previously used `state.record(&desired,
    // &namespaces)` which rewrites the in-scope managed set from desired.
    // For a failed Delete, the resource is absent from `desired` (user
    // removed it from the repo) but still live on the gateway because the
    // delete failed. The wholesale rewrite drops the resource's state
    // entry; the next compute_diff_with_ownership classifies the still-
    // live resource as unmanaged and stops retrying the deletion,
    // orphaning it indefinitely.
    //
    // The fix: cmd_apply walks `ApplyResult::applied_incremental` and
    // calls `state.record_op` for each successful op. Failed ops never
    // appear in that list, so their state entries persist untouched and
    // the next apply's diff still sees the resource as managed →
    // generates another Delete → retries.
    use gitforgeops::apply::AppliedOp;
    use gitforgeops::config::schema::{BackendProtocol, Consumer, GatewayConfig, Proxy};
    use gitforgeops::diff::resource_diff::DiffAction;

    fn proxy(id: &str, ns: &str) -> Proxy {
        Proxy {
            id: id.to_string(),
            name: None,
            namespace: ns.to_string(),
            hosts: vec![],
            listen_path: Some(format!("/{id}")),
            backend_protocol: BackendProtocol::Https,
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // Prior state: two managed resources in `ferrum`.
    let mut state = StateFile::default();
    state
        .resources
        .insert("ferrum:Proxy:keep-me".to_string(), "sha256:OLD".to_string());
    state.resources.insert(
        "ferrum:Proxy:to-delete".to_string(),
        "sha256:DEL".to_string(),
    );

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
        state.resources.contains_key("ferrum:Proxy:new-one"),
        "successful Add must record into state"
    );
    // Failed delete's key is PRESERVED — the resource is still managed,
    // and the next diff will retry the delete instead of treating it as
    // unmanaged.
    assert!(
        state.resources.contains_key("ferrum:Proxy:to-delete"),
        "failed Delete must NOT remove the key from state, otherwise the resource is orphaned"
    );
    // Pre-existing managed entry is untouched.
    assert!(
        state.resources.contains_key("ferrum:Proxy:keep-me"),
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
        !state2.resources.contains_key("ferrum:Proxy:to-delete"),
        "successful Delete must remove the key from state"
    );

    // Successful Modify on a Consumer should refresh the hash and not
    // touch other namespaces.
    let mut state3 = StateFile::default();
    state3.resources.insert(
        "platform:Consumer:other".to_string(),
        "sha256:OTHER".to_string(),
    );
    state3.resources.insert(
        "ferrum:Consumer:app".to_string(),
        "sha256:STALE".to_string(),
    );
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
    assert_ne!(
        state3.resources.get("ferrum:Consumer:app"),
        Some(&"sha256:STALE".to_string()),
        "Modify must refresh the hash"
    );
    assert_eq!(
        state3.resources.get("platform:Consumer:other"),
        Some(&"sha256:OTHER".to_string()),
        "out-of-namespace entry must remain untouched"
    );
}
