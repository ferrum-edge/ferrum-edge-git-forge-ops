use std::sync::{Mutex, MutexGuard};

use gitforgeops::config::env::{load_env_config, ApplyStrategy, GatewayMode};

// Env tests mutate process-global state and must run serially. Cargo's test
// harness runs tests in parallel by default; this mutex gates every env test
// so they don't stomp on each other's `set_var` / `remove_var` calls.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn env_guard() -> MutexGuard<'static, ()> {
    // `lock()` returns Err only on poisoning (a prior test panicked while
    // holding the lock). The guard is still usable, so unwrap the inner value.
    ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

fn clear_env() {
    for var in &[
        "FERRUM_GATEWAY_URL",
        "FERRUM_ADMIN_JWT_SECRET",
        "FERRUM_NAMESPACE",
        "FERRUM_GATEWAY_MODE",
        "FERRUM_APPLY_STRATEGY",
        "FERRUM_OVERLAY",
        "FERRUM_FILE_OUTPUT_PATH",
        "FERRUM_EDGE_BINARY_PATH",
        "FERRUM_TLS_NO_VERIFY",
        "FERRUM_GATEWAY_CA_CERT",
        "FERRUM_GATEWAY_CLIENT_CERT",
        "FERRUM_GATEWAY_CLIENT_KEY",
        "FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS",
        "FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS",
        "FERRUM_GITHUB_CONNECT_TIMEOUT_SECS",
        "FERRUM_GITHUB_REQUEST_TIMEOUT_SECS",
        "FERRUM_GATEWAY_MAX_RETRIES",
    ] {
        std::env::remove_var(var);
    }
}

#[test]
fn env_config_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config();
    assert!(config.gateway_url.is_none());
    assert!(config.admin_jwt_secret.is_none());
    assert!(config.namespace_filter.is_none());
    assert_eq!(config.gateway_mode, GatewayMode::Api);
    assert_eq!(config.apply_strategy, ApplyStrategy::Incremental);
    assert!(config.overlay.is_none());
    assert_eq!(config.file_output_path, "./assembled/resources.yaml");
    assert_eq!(config.edge_binary_path, "ferrum-edge");
    assert!(!config.tls_no_verify);

    std::env::set_var("FERRUM_GATEWAY_MODE", "file");
    let config = load_env_config();
    assert_eq!(config.gateway_mode, GatewayMode::File);

    std::env::set_var("FERRUM_GATEWAY_MODE", "api");
    std::env::set_var("FERRUM_APPLY_STRATEGY", "full_replace");
    let config = load_env_config();
    assert_eq!(config.gateway_mode, GatewayMode::Api);
    assert_eq!(config.apply_strategy, ApplyStrategy::FullReplace);

    std::env::set_var("FERRUM_TLS_NO_VERIFY", "true");
    let config = load_env_config();
    assert!(config.tls_no_verify);

    std::env::set_var("FERRUM_GATEWAY_URL", "https://gw:9000");
    std::env::set_var("FERRUM_ADMIN_JWT_SECRET", "secret123");
    std::env::set_var("FERRUM_NAMESPACE", "team-alpha");
    let config = load_env_config();
    assert_eq!(config.gateway_url.as_deref(), Some("https://gw:9000"));
    assert_eq!(config.admin_jwt_secret.as_deref(), Some("secret123"));
    assert_eq!(config.namespace_filter.as_deref(), Some("team-alpha"));

    clear_env();
}

#[test]
fn env_config_timeout_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config();
    assert_eq!(config.gateway_connect_timeout_secs, 10);
    assert_eq!(config.gateway_request_timeout_secs, 60);
    assert_eq!(config.github_connect_timeout_secs, 10);
    assert_eq!(config.github_request_timeout_secs, 30);

    std::env::set_var("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", "5");
    std::env::set_var("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "120");
    std::env::set_var("FERRUM_GITHUB_CONNECT_TIMEOUT_SECS", "7");
    std::env::set_var("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", "45");
    let config = load_env_config();
    assert_eq!(config.gateway_connect_timeout_secs, 5);
    assert_eq!(config.gateway_request_timeout_secs, 120);
    assert_eq!(config.github_connect_timeout_secs, 7);
    assert_eq!(config.github_request_timeout_secs, 45);

    // Non-numeric value falls back to default.
    std::env::set_var("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", "not-a-number");
    std::env::set_var("FERRUM_GITHUB_CONNECT_TIMEOUT_SECS", "bogus");
    let config = load_env_config();
    assert_eq!(config.gateway_connect_timeout_secs, 10);
    assert_eq!(config.github_connect_timeout_secs, 10);

    clear_env();
}

#[test]
fn env_config_max_retries_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config();
    assert_eq!(config.gateway_max_retries, 3);

    std::env::set_var("FERRUM_GATEWAY_MAX_RETRIES", "0");
    let config = load_env_config();
    assert_eq!(config.gateway_max_retries, 0);

    std::env::set_var("FERRUM_GATEWAY_MAX_RETRIES", "7");
    let config = load_env_config();
    assert_eq!(config.gateway_max_retries, 7);

    // Non-numeric falls back to default.
    std::env::set_var("FERRUM_GATEWAY_MAX_RETRIES", "many");
    let config = load_env_config();
    assert_eq!(config.gateway_max_retries, 3);

    clear_env();
}
