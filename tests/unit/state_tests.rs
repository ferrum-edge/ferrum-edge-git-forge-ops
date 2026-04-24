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
fn state_file_migrates_v1_legacy_format() {
    // v1 .state/state.json has no `environment`, no credential fields, no
    // overrides, no shard_count. Serde defaults must fill the gaps so the
    // migration path succeeds instead of silently dropping prior state.
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        let v1 = r#"{
            "version": 1,
            "last_applied_at": "2026-04-20T12:00:00Z",
            "last_applied_commit": "abc123",
            "resources": {
                "ferrum:Proxy:httpbin": "sha256:deadbeef"
            }
        }"#;
        std::fs::write(".state/state.json", v1).unwrap();

        // Env-specific file doesn't exist; load() should rename legacy into
        // .state/production.json atomically.
        assert!(!std::path::Path::new(".state/production.json").exists());
        let state = StateFile::load("production");

        assert_eq!(state.environment, "production");
        assert_eq!(state.resources.len(), 1);
        assert!(state.resources.contains_key("ferrum:Proxy:httpbin"));
        // v2-only fields get defaults without blowing up.
        assert_eq!(state.credential_shard_count, 1);
        assert!(state.credentials.is_empty());
        assert!(state.overrides.is_empty());

        // Legacy file must be gone after adoption so subsequent envs don't
        // inherit the same resources.
        assert!(
            !std::path::Path::new(".state/state.json").exists(),
            "legacy .state/state.json should have been renamed, not just read"
        );
        assert!(
            std::path::Path::new(".state/production.json").exists(),
            "adopted file should now exist at .state/production.json"
        );
    });
}

#[test]
fn legacy_state_is_consumed_exactly_once_across_environments() {
    // Multi-env rollout scenario: legacy state exists and no env-specific
    // files exist. The first env to load() adopts the legacy state; the
    // second env must see an empty default, not the same resource set
    // (otherwise shared-mode diffs would double-claim every resource and
    // apply could delete resources in the wrong environment).
    let dir = TempDir::new().unwrap();
    with_cwd(dir.path(), || {
        std::fs::create_dir_all(".state").unwrap();
        let legacy = r#"{
            "version": 1,
            "resources": {
                "ferrum:Proxy:httpbin": "sha256:abc"
            }
        }"#;
        std::fs::write(".state/state.json", legacy).unwrap();

        // First env adopts the legacy content.
        let staging = StateFile::load("staging");
        assert_eq!(staging.resources.len(), 1);
        assert_eq!(staging.environment, "staging");

        // Legacy is gone.
        assert!(!std::path::Path::new(".state/state.json").exists());

        // Second env sees no legacy and no env-specific → empty default.
        let production = StateFile::load("production");
        assert_eq!(
            production.resources.len(),
            0,
            "second env must not inherit the legacy state — that would cross-contaminate shared-mode tracking and risk cross-env deletes"
        );
        assert_eq!(production.environment, "production");

        // Staging's file persists and can be re-read unchanged.
        let staging_again = StateFile::load("staging");
        assert_eq!(staging_again.resources.len(), 1);
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
