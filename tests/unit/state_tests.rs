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

        // Env-specific file doesn't exist; load() should fall through to the
        // legacy file and adopt it.
        assert!(!std::path::Path::new(".state/production.json").exists());
        let state = StateFile::load("production");

        assert_eq!(state.environment, "production");
        assert_eq!(state.resources.len(), 1);
        assert!(state.resources.contains_key("ferrum:Proxy:httpbin"));
        // v2-only fields get defaults without blowing up.
        assert_eq!(state.credential_shard_count, 1);
        assert!(state.credentials.is_empty());
        assert!(state.overrides.is_empty());
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
