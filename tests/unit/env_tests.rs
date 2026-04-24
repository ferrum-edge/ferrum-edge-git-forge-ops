use gitforgeops::config::env::{load_env_config, ApplyStrategy, GatewayMode};

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
    ] {
        std::env::remove_var(var);
    }
}

#[test]
fn env_config_defaults_and_overrides() {
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
