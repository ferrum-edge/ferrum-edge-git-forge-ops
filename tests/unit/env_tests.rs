use gitforgeops::config::env::{load_env_config, ApplyStrategy, GatewayMode};

#[test]
fn default_env_config() {
    // Clear any set vars to test defaults
    std::env::remove_var("FERRUM_GATEWAY_URL");
    std::env::remove_var("FERRUM_ADMIN_JWT_SECRET");
    std::env::remove_var("FERRUM_NAMESPACE");
    std::env::remove_var("FERRUM_GATEWAY_MODE");
    std::env::remove_var("FERRUM_APPLY_STRATEGY");
    std::env::remove_var("FERRUM_OVERLAY");
    std::env::remove_var("FERRUM_FILE_OUTPUT_PATH");
    std::env::remove_var("FERRUM_EDGE_BINARY_PATH");
    std::env::remove_var("FERRUM_TLS_NO_VERIFY");

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
}

#[test]
fn file_mode_from_env() {
    std::env::set_var("FERRUM_GATEWAY_MODE", "file");
    let config = load_env_config();
    assert_eq!(config.gateway_mode, GatewayMode::File);
    std::env::remove_var("FERRUM_GATEWAY_MODE");
}

#[test]
fn full_replace_strategy_from_env() {
    std::env::set_var("FERRUM_APPLY_STRATEGY", "full_replace");
    let config = load_env_config();
    assert_eq!(config.apply_strategy, ApplyStrategy::FullReplace);
    std::env::remove_var("FERRUM_APPLY_STRATEGY");
}

#[test]
fn tls_no_verify_from_env() {
    std::env::set_var("FERRUM_TLS_NO_VERIFY", "true");
    let config = load_env_config();
    assert!(config.tls_no_verify);
    std::env::remove_var("FERRUM_TLS_NO_VERIFY");
}
