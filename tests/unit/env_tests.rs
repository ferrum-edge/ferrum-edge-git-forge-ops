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
        "FERRUM_MESH_FILE_OUTPUT_PATH",
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
        "FERRUM_ADMIN_JWT_ISSUER",
        "FERRUM_ADMIN_JWT_ROLE",
        "FERRUM_ADMIN_JWT_AUDIENCE",
        "FERRUM_ADMIN_JWT_TTL_SECS",
    ] {
        std::env::remove_var(var);
    }
}

#[test]
fn env_config_jwt_claim_defaults_match_the_gateway() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config().unwrap();
    // The gateway's own defaults: iss `ferrum-edge`, no audience, TTL at the
    // 3600s max. Role must be `admin` — /backup, /restore, /batch and consumer
    // CRUD are all admin-only.
    assert_eq!(config.admin_jwt_issuer, "ferrum-edge");
    assert_eq!(config.admin_jwt_role, "admin");
    assert!(config.admin_jwt_audience.is_none());
    assert_eq!(config.admin_jwt_ttl_secs, 3600);

    clear_env();
}

#[test]
fn env_config_jwt_claim_overrides() {
    let _guard = env_guard();
    clear_env();

    std::env::set_var("FERRUM_ADMIN_JWT_ISSUER", "my-gateway");
    std::env::set_var("FERRUM_ADMIN_JWT_ROLE", "operator");
    std::env::set_var("FERRUM_ADMIN_JWT_AUDIENCE", "ferrum-admin");
    std::env::set_var("FERRUM_ADMIN_JWT_TTL_SECS", "600");

    let config = load_env_config().unwrap();
    assert_eq!(config.admin_jwt_issuer, "my-gateway");
    assert_eq!(config.admin_jwt_role, "operator");
    assert_eq!(config.admin_jwt_audience.as_deref(), Some("ferrum-admin"));
    assert_eq!(config.admin_jwt_ttl_secs, 600);

    clear_env();
}

#[test]
fn env_config_treats_blank_jwt_vars_as_unset() {
    let _guard = env_guard();
    clear_env();

    // A workflow that interpolates an unset secret produces an empty string.
    // An empty `aud` must stay absent — a gateway with no configured audience
    // rejects any token that carries the claim at all.
    std::env::set_var("FERRUM_ADMIN_JWT_AUDIENCE", "  ");
    std::env::set_var("FERRUM_ADMIN_JWT_ISSUER", "");
    std::env::set_var("FERRUM_ADMIN_JWT_TTL_SECS", "  ");

    let config = load_env_config().unwrap();
    assert!(config.admin_jwt_audience.is_none());
    assert_eq!(config.admin_jwt_issuer, "ferrum-edge");
    // Blank is absent and retains the documented default.
    assert_eq!(config.admin_jwt_ttl_secs, 3600);

    clear_env();
}

/// Every var CI feeds from a `${{ secrets.* }}` expression arrives as an empty
/// string when the GitHub Environment doesn't define it. Blank must read as
/// unset so callers get the clear "not configured" errors (NoJwtSecret /
/// NoGatewayUrl) instead of misleading ones like "secret must be at least 32
/// characters" for a secret that was never set at all.
#[test]
fn env_config_treats_blank_secret_backed_vars_as_unset() {
    let _guard = env_guard();
    clear_env();

    std::env::set_var("FERRUM_GATEWAY_URL", "");
    std::env::set_var("FERRUM_ADMIN_JWT_SECRET", "");
    std::env::set_var("FERRUM_NAMESPACE", "  ");
    std::env::set_var("FERRUM_GATEWAY_CA_CERT", "");
    std::env::set_var("FERRUM_GATEWAY_CLIENT_CERT", "");
    std::env::set_var("FERRUM_GATEWAY_CLIENT_KEY", "");

    let config = load_env_config().unwrap();
    assert!(config.gateway_url.is_none());
    assert!(config.admin_jwt_secret.is_none());
    assert!(config.namespace_filter.is_none());
    assert!(config.ca_cert.is_none());
    assert!(config.client_cert.is_none());
    assert!(config.client_key.is_none());

    clear_env();
}

/// `FERRUM_MESH_FILE_OUTPUT_PATH` follows the same shape as every other
/// path-valued variable: absent or blank falls back to the documented default,
/// a real value wins. Blank matters because CI writes these from `secrets` /
/// `vars` expansions that render to an empty string when unset.
#[test]
fn mesh_file_output_path_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    assert_eq!(
        load_env_config().unwrap().mesh_file_output_path,
        "./assembled/mesh.yaml"
    );

    std::env::set_var("FERRUM_MESH_FILE_OUTPUT_PATH", "   ");
    assert_eq!(
        load_env_config().unwrap().mesh_file_output_path,
        "./assembled/mesh.yaml",
        "a blank value must not produce an empty output path"
    );

    std::env::set_var("FERRUM_MESH_FILE_OUTPUT_PATH", "/srv/mesh/slice.yaml");
    assert_eq!(
        load_env_config().unwrap().mesh_file_output_path,
        "/srv/mesh/slice.yaml"
    );

    clear_env();
}

#[test]
fn env_config_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config().unwrap();
    assert!(config.gateway_url.is_none());
    assert!(config.admin_jwt_secret.is_none());
    assert!(config.namespace_filter.is_none());
    assert_eq!(config.gateway_mode, GatewayMode::Api);
    assert_eq!(config.apply_strategy, ApplyStrategy::Incremental);
    assert!(config.overlay.is_none());
    assert_eq!(config.file_output_path, "./assembled/resources.yaml");
    assert_eq!(config.mesh_file_output_path, "./assembled/mesh.yaml");
    assert_eq!(config.edge_binary_path, "ferrum-edge");
    assert!(!config.tls_no_verify);

    std::env::set_var("FERRUM_GATEWAY_MODE", "file");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_mode, GatewayMode::File);

    std::env::set_var("FERRUM_GATEWAY_MODE", "api");
    std::env::set_var("FERRUM_APPLY_STRATEGY", "full_replace");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_mode, GatewayMode::Api);
    assert_eq!(config.apply_strategy, ApplyStrategy::FullReplace);

    std::env::set_var("FERRUM_TLS_NO_VERIFY", "true");
    let config = load_env_config().unwrap();
    assert!(config.tls_no_verify);

    std::env::set_var("FERRUM_GATEWAY_URL", "https://gw:9000");
    std::env::set_var("FERRUM_ADMIN_JWT_SECRET", "secret123");
    std::env::set_var("FERRUM_NAMESPACE", "team-alpha");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_url.as_deref(), Some("https://gw:9000"));
    assert_eq!(config.admin_jwt_secret.as_deref(), Some("secret123"));
    assert_eq!(config.namespace_filter.as_deref(), Some("team-alpha"));

    clear_env();
}

#[test]
fn env_config_timeout_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_connect_timeout_secs, 10);
    assert_eq!(config.gateway_request_timeout_secs, 60);
    assert_eq!(config.github_connect_timeout_secs, 10);
    assert_eq!(config.github_request_timeout_secs, 30);

    std::env::set_var("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", "5");
    std::env::set_var("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "120");
    std::env::set_var("FERRUM_GITHUB_CONNECT_TIMEOUT_SECS", "7");
    std::env::set_var("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", "45");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_connect_timeout_secs, 5);
    assert_eq!(config.gateway_request_timeout_secs, 120);
    assert_eq!(config.github_connect_timeout_secs, 7);
    assert_eq!(config.github_request_timeout_secs, 45);

    // Present malformed values fail closed and name the exact variable.
    std::env::set_var("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", "not-a-number");
    std::env::set_var("FERRUM_GITHUB_CONNECT_TIMEOUT_SECS", "bogus");
    let error = load_env_config().unwrap_err().to_string();
    assert!(
        error.contains("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS"),
        "{error}"
    );

    clear_env();
}

#[test]
fn env_config_max_retries_defaults_and_overrides() {
    let _guard = env_guard();
    clear_env();

    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_max_retries, 3);

    std::env::set_var("FERRUM_GATEWAY_MAX_RETRIES", "0");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_max_retries, 0);

    std::env::set_var("FERRUM_GATEWAY_MAX_RETRIES", "7");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_max_retries, 7);

    // Non-numeric is a configuration error, never a silent retry-policy
    // change.
    std::env::set_var("FERRUM_GATEWAY_MAX_RETRIES", "many");
    let error = load_env_config().unwrap_err().to_string();
    assert!(error.contains("FERRUM_GATEWAY_MAX_RETRIES"), "{error}");

    clear_env();
}

#[test]
fn env_config_rejects_invalid_modes_booleans_and_positive_numbers() {
    let _guard = env_guard();
    clear_env();

    for (variable, value) in [
        ("FERRUM_GATEWAY_MODE", "fiel"),
        ("FERRUM_APPLY_STRATEGY", "full-replcae"),
        ("FERRUM_TLS_NO_VERIFY", "tru"),
        ("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", "0"),
        ("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "-1"),
        ("FERRUM_ADMIN_JWT_TTL_SECS", "0"),
        ("FERRUM_GATEWAY_MAX_RETRIES", "4294967296"),
        ("FERRUM_ADMIN_JWT_ROLE", "superuser"),
    ] {
        clear_env();
        std::env::set_var(variable, value);
        let error = load_env_config().unwrap_err().to_string();
        assert!(error.contains(variable), "{variable}={value:?}: {error}");
        assert!(error.contains(value), "{variable}={value:?}: {error}");
    }

    clear_env();
}

#[test]
fn env_config_accepts_documented_normalization_and_blank_defaults() {
    let _guard = env_guard();
    clear_env();

    std::env::set_var("FERRUM_GATEWAY_MODE", "  FiLe ");
    std::env::set_var("FERRUM_APPLY_STRATEGY", " FULL_REPLACE ");
    std::env::set_var("FERRUM_TLS_NO_VERIFY", " FALSE ");
    std::env::set_var("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "   ");
    let config = load_env_config().unwrap();
    assert_eq!(config.gateway_mode, GatewayMode::File);
    assert_eq!(config.apply_strategy, ApplyStrategy::FullReplace);
    assert!(!config.tls_no_verify);
    assert_eq!(config.gateway_request_timeout_secs, 60);

    clear_env();
}
