use gitforgeops::config::env::{ApplyStrategy, EnvConfig, GatewayMode};
use gitforgeops::http_client::AdminClient;

fn base_env() -> EnvConfig {
    EnvConfig {
        gateway_url: Some("https://gateway.example:9000".to_string()),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        namespace_filter: None,
        gateway_mode: GatewayMode::Api,
        apply_strategy: ApplyStrategy::Incremental,
        overlay: None,
        file_output_path: "./assembled/resources.yaml".to_string(),
        edge_binary_path: "ferrum-edge".to_string(),
        tls_no_verify: false,
        ca_cert: None,
        client_cert: None,
        client_key: None,
        gateway_connect_timeout_secs: 10,
        gateway_request_timeout_secs: 60,
        github_connect_timeout_secs: 10,
        github_request_timeout_secs: 30,
    }
}

#[test]
fn admin_client_rejects_client_cert_without_key() {
    let mut env = base_env();
    env.client_cert = Some("dummy".to_string());
    env.client_key = None;

    let err = match AdminClient::new(&env) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err.contains("FERRUM_GATEWAY_CLIENT_KEY"),
        "expected missing-key error, got: {err}"
    );
}

#[test]
fn admin_client_rejects_client_key_without_cert() {
    let mut env = base_env();
    env.client_cert = None;
    env.client_key = Some("dummy".to_string());

    let err = match AdminClient::new(&env) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err.contains("FERRUM_GATEWAY_CLIENT_CERT"),
        "expected missing-cert error, got: {err}"
    );
}

#[test]
fn admin_client_builds_without_mtls() {
    let env = base_env();
    AdminClient::new(&env).expect("client should build without mTLS");
}

#[test]
fn admin_client_honors_custom_timeouts() {
    let mut env = base_env();
    env.gateway_connect_timeout_secs = 3;
    env.gateway_request_timeout_secs = 15;
    AdminClient::new(&env).expect("client should build with custom timeouts");
}
