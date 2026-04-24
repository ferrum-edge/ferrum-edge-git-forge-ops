use std::env;

use serde::{Deserialize, Serialize};

/// Gateway interaction mode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayMode {
    /// Push config via the admin REST API.
    #[default]
    Api,
    /// Write a flat file for `ferrum-edge` file mode.
    File,
}

/// Strategy for applying configuration changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStrategy {
    /// Only apply changed resources (diff-based).
    #[default]
    Incremental,
    /// Replace entire config atomically.
    FullReplace,
}

/// Environment-driven configuration for the gitforgeops tool.
#[derive(Debug, Clone)]
pub struct EnvConfig {
    /// URL of the Ferrum Edge admin API (e.g. `http://localhost:9000`).
    pub gateway_url: Option<String>,
    /// JWT secret for authenticating with the admin API.
    pub admin_jwt_secret: Option<String>,
    /// Only process resources for this namespace.
    pub namespace_filter: Option<String>,
    /// How to interact with the gateway.
    pub gateway_mode: GatewayMode,
    /// How to apply config changes.
    pub apply_strategy: ApplyStrategy,
    /// Overlay name to apply (e.g. `production`, `staging`).
    pub overlay: Option<String>,
    /// Selected environment name (from repo config). Takes precedence over `overlay` if set.
    pub env_name: Option<String>,
    /// GitHub repository slug in `owner/repo` form (used for policy/secret APIs).
    pub github_repository: Option<String>,
    /// Token used for GitHub API calls (policy overrides, PR comments, author lookup).
    pub github_token: Option<String>,
    /// Token used to write GitHub Environment Secrets (provisioner).
    pub github_provisioner_token: Option<String>,
    /// JSON-encoded credential bundle map, loaded from workflow secrets.
    pub creds_bundle_json: Option<String>,
    /// Output path for assembled file (file mode).
    pub file_output_path: String,
    /// Path to the `ferrum-edge` binary for validation.
    pub edge_binary_path: String,
    /// Skip TLS certificate verification when talking to the gateway.
    pub tls_no_verify: bool,
    /// Path to CA certificate for gateway TLS.
    pub ca_cert: Option<String>,
    /// Path to client certificate for mTLS to gateway.
    pub client_cert: Option<String>,
    /// Path to client key for mTLS to gateway.
    pub client_key: Option<String>,
    /// Timeout for TCP/TLS connection establishment to the gateway, in seconds.
    pub gateway_connect_timeout_secs: u64,
    /// Timeout for a complete HTTP request/response cycle to the gateway, in seconds.
    /// Applies end-to-end including response body read. `/backup` on large
    /// configs or `/restore` on gateways with slow commit paths may need this
    /// raised above the 60s default.
    pub gateway_request_timeout_secs: u64,
    /// Timeout for TCP/TLS connection establishment to `api.github.com`
    /// (used by `gitforgeops review --pr <N>`), in seconds.
    pub github_connect_timeout_secs: u64,
    /// Timeout for a complete HTTP request/response cycle to `api.github.com`, in seconds.
    pub github_request_timeout_secs: u64,
    /// Max automatic retries on transient admin-API failures (connection
    /// errors, HTTP 5xx, 429). `0` disables retry. Retries use exponential
    /// backoff starting at 500ms. Request timeouts are NOT retried — their
    /// state is ambiguous (may or may not have applied).
    pub gateway_max_retries: u32,
}

/// Load tool configuration from environment variables.
///
/// | Variable                     | Field              | Default                          |
/// |------------------------------|--------------------|----------------------------------|
/// | `FERRUM_GATEWAY_URL`         | `gateway_url`      | `None`                           |
/// | `FERRUM_ADMIN_JWT_SECRET`    | `admin_jwt_secret` | `None`                           |
/// | `FERRUM_NAMESPACE`           | `namespace_filter` | `None`                           |
/// | `FERRUM_GATEWAY_MODE`        | `gateway_mode`     | `api`                            |
/// | `FERRUM_APPLY_STRATEGY`      | `apply_strategy`   | `incremental`                    |
/// | `FERRUM_OVERLAY`             | `overlay`          | `None`                           |
/// | `FERRUM_ENV`                 | `env_name`         | `None`                           |
/// | `GITHUB_REPOSITORY`          | `github_repository`| `None`                           |
/// | `GITHUB_TOKEN`               | `github_token`     | `None`                           |
/// | `FERRUM_GH_PROVISIONER_TOKEN`| `github_provisioner_token` | `None`                   |
/// | `FERRUM_CREDS_JSON`          | `creds_bundle_json`| `None`                           |
/// | `FERRUM_FILE_OUTPUT_PATH`    | `file_output_path` | `./assembled/resources.yaml`     |
/// | `FERRUM_EDGE_BINARY_PATH`    | `edge_binary_path` | `ferrum-edge`                    |
/// | `FERRUM_TLS_NO_VERIFY`       | `tls_no_verify`    | `false`                          |
/// | `FERRUM_GATEWAY_CA_CERT`     | `ca_cert`          | `None`                           |
/// | `FERRUM_GATEWAY_CLIENT_CERT` | `client_cert`      | `None`                           |
/// | `FERRUM_GATEWAY_CLIENT_KEY`  | `client_key`       | `None`                           |
/// | `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `gateway_connect_timeout_secs` | `10`        |
/// | `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `gateway_request_timeout_secs` | `60`        |
/// | `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS`  | `github_connect_timeout_secs`  | `10`        |
/// | `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS`  | `github_request_timeout_secs`  | `30`        |
/// | `FERRUM_GATEWAY_MAX_RETRIES`          | `gateway_max_retries`          | `3`         |
pub fn load_env_config() -> EnvConfig {
    EnvConfig {
        gateway_url: env::var("FERRUM_GATEWAY_URL").ok(),
        admin_jwt_secret: env::var("FERRUM_ADMIN_JWT_SECRET").ok(),
        namespace_filter: env::var("FERRUM_NAMESPACE").ok(),
        gateway_mode: match env::var("FERRUM_GATEWAY_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "file" => GatewayMode::File,
            _ => GatewayMode::Api,
        },
        apply_strategy: match env::var("FERRUM_APPLY_STRATEGY")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "full_replace" => ApplyStrategy::FullReplace,
            _ => ApplyStrategy::Incremental,
        },
        overlay: env::var("FERRUM_OVERLAY").ok(),
        env_name: env::var("FERRUM_ENV").ok(),
        github_repository: env::var("GITHUB_REPOSITORY").ok(),
        github_token: env::var("GITHUB_TOKEN").ok(),
        github_provisioner_token: env::var("FERRUM_GH_PROVISIONER_TOKEN").ok(),
        creds_bundle_json: env::var("FERRUM_CREDS_JSON").ok(),
        file_output_path: env::var("FERRUM_FILE_OUTPUT_PATH")
            .unwrap_or_else(|_| "./assembled/resources.yaml".to_string()),
        edge_binary_path: env::var("FERRUM_EDGE_BINARY_PATH")
            .unwrap_or_else(|_| "ferrum-edge".to_string()),
        tls_no_verify: env::var("FERRUM_TLS_NO_VERIFY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        ca_cert: env::var("FERRUM_GATEWAY_CA_CERT").ok(),
        client_cert: env::var("FERRUM_GATEWAY_CLIENT_CERT").ok(),
        client_key: env::var("FERRUM_GATEWAY_CLIENT_KEY").ok(),
        gateway_connect_timeout_secs: parse_timeout_env("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", 10),
        gateway_request_timeout_secs: parse_timeout_env("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", 60),
        github_connect_timeout_secs: parse_timeout_env("FERRUM_GITHUB_CONNECT_TIMEOUT_SECS", 10),
        github_request_timeout_secs: parse_timeout_env("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", 30),
        gateway_max_retries: parse_u32_env("FERRUM_GATEWAY_MAX_RETRIES", 3),
    }
}

fn parse_timeout_env(var: &str, default_secs: u64) -> u64 {
    env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default_secs)
}

fn parse_u32_env(var: &str, default: u32) -> u32 {
    env::var(var)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default)
}
