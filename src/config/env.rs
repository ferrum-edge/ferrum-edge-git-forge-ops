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
    /// Replace an entire namespace atomically via `/restore?confirm=true`.
    ///
    /// **Atomicity scope is per-namespace, not environment-wide.** When an
    /// apply targets multiple namespaces (exclusive mode with an
    /// `ownership.namespaces` list longer than one), each namespace is
    /// restored in its own API call. A failure on the Nth namespace
    /// leaves namespaces 0..N already replaced. The apply result
    /// enumerates which namespaces succeeded and which failed (rather
    /// than bailing on the first error and hiding later namespaces), but
    /// operators must still manually reconcile any partial state. For
    /// strict environment-wide atomicity, scope `full_replace` to a
    /// single namespace or use `incremental`.
    FullReplace,
}

/// Environment-driven configuration for the gitforgeops tool.
#[derive(Debug, Clone)]
pub struct EnvConfig {
    /// URL of the Ferrum Edge admin API (e.g. `http://localhost:9000`).
    pub gateway_url: Option<String>,
    /// JWT secret for authenticating with the admin API.
    pub admin_jwt_secret: Option<String>,
    /// `iss` claim minted into admin API tokens. Must equal the gateway's
    /// `FERRUM_ADMIN_JWT_ISSUER` (default `ferrum-edge`) or every request is
    /// rejected with 401 `InvalidIssuer`.
    pub admin_jwt_issuer: String,
    /// `role` claim minted into admin API tokens (`viewer` | `operator` |
    /// `admin`). The gateway requires this claim on every request. gitforgeops
    /// needs `admin`: `/backup`, `/restore`, `/batch` and consumer CRUD are all
    /// admin-only.
    pub admin_jwt_role: String,
    /// Optional `aud` claim. The gateway rejects a token carrying `aud` unless
    /// its own `FERRUM_ADMIN_JWT_AUDIENCE` is configured (RFC 7519 §4.1.3
    /// strict default), so the claim is emitted only when this is set.
    pub admin_jwt_audience: Option<String>,
    /// Token lifetime in seconds. Must be within the gateway's
    /// `FERRUM_ADMIN_JWT_MAX_TTL` (default 3600; acceptance is `max + 60`).
    pub admin_jwt_ttl_secs: i64,
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
    /// Prefer `creds_bundle_json_file` for large bundles — a multi-MB env
    /// var will collide with OS environment-block limits.
    pub creds_bundle_json: Option<String>,
    /// Path to a file containing the same JSON as `creds_bundle_json`. When
    /// set, the binary reads from disk and this takes precedence over the
    /// inline `creds_bundle_json` — routes the bundle around env-var size
    /// limits at scale.
    pub creds_bundle_json_file: Option<String>,
    /// Output path for assembled file (file mode).
    pub file_output_path: String,
    /// Output path for the standalone mesh document (`{version, mesh}`).
    ///
    /// Written by file-mode `apply` and by `export` whenever the repo declares
    /// any `MeshConfig` resource. This is a **separate document** from
    /// `file_output_path`: a mesh node's loader is `deny_unknown_fields` and
    /// rejects a document carrying `proxies:` / `upstreams:`, and the gateway's
    /// own `mesh:` key is inert. Points at whatever a mesh node reads via its
    /// `FERRUM_MESH_FILE_CONFIG_PATH`.
    pub mesh_file_output_path: String,
    /// Path to the `ferrum-edge` binary for validation.
    pub edge_binary_path: String,
    /// Skip TLS certificate verification when talking to the gateway.
    pub tls_no_verify: bool,
    /// Base64-encoded PEM CA certificate for gateway TLS.
    pub ca_cert: Option<String>,
    /// Base64-encoded PEM client certificate for mTLS to gateway.
    pub client_cert: Option<String>,
    /// Base64-encoded PEM client key for mTLS to gateway.
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

impl Default for EnvConfig {
    /// The configuration `load_env_config()` produces with no `FERRUM_*` /
    /// `GITHUB_*` variables set. Keeps struct-literal construction (tests,
    /// synthetic runs) from having to restate every default when a field is
    /// added.
    fn default() -> Self {
        Self {
            gateway_url: None,
            admin_jwt_secret: None,
            admin_jwt_issuer: DEFAULT_JWT_ISSUER.to_string(),
            admin_jwt_role: DEFAULT_JWT_ROLE.to_string(),
            admin_jwt_audience: None,
            admin_jwt_ttl_secs: DEFAULT_JWT_TTL_SECS,
            namespace_filter: None,
            gateway_mode: GatewayMode::default(),
            apply_strategy: ApplyStrategy::default(),
            overlay: None,
            env_name: None,
            github_repository: None,
            github_token: None,
            github_provisioner_token: None,
            creds_bundle_json: None,
            creds_bundle_json_file: None,
            file_output_path: "./assembled/resources.yaml".to_string(),
            mesh_file_output_path: DEFAULT_MESH_FILE_OUTPUT_PATH.to_string(),
            edge_binary_path: "ferrum-edge".to_string(),
            tls_no_verify: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            gateway_connect_timeout_secs: 10,
            gateway_request_timeout_secs: 60,
            github_connect_timeout_secs: 10,
            github_request_timeout_secs: 30,
            gateway_max_retries: 3,
        }
    }
}

/// Load tool configuration from environment variables.
///
/// | Variable                     | Field              | Default                          |
/// |------------------------------|--------------------|----------------------------------|
/// | `FERRUM_GATEWAY_URL`         | `gateway_url`      | `None`                           |
/// | `FERRUM_ADMIN_JWT_SECRET`    | `admin_jwt_secret` | `None`                           |
/// | `FERRUM_ADMIN_JWT_ISSUER`    | `admin_jwt_issuer` | `ferrum-edge`                    |
/// | `FERRUM_ADMIN_JWT_ROLE`      | `admin_jwt_role`   | `admin`                          |
/// | `FERRUM_ADMIN_JWT_AUDIENCE`  | `admin_jwt_audience` | `None` (claim omitted)         |
/// | `FERRUM_ADMIN_JWT_TTL_SECS`  | `admin_jwt_ttl_secs` | `3600`                         |
/// | `FERRUM_NAMESPACE`           | `namespace_filter` | `None`                           |
/// | `FERRUM_GATEWAY_MODE`        | `gateway_mode`     | `api`                            |
/// | `FERRUM_APPLY_STRATEGY`      | `apply_strategy`   | `incremental`                    |
/// | `FERRUM_OVERLAY`             | `overlay`          | `None`                           |
/// | `FERRUM_ENV`                 | `env_name`         | `None`                           |
/// | `GITHUB_REPOSITORY`          | `github_repository`| `None`                           |
/// | `GITHUB_TOKEN`               | `github_token`     | `None`                           |
/// | `FERRUM_GH_PROVISIONER_TOKEN`| `github_provisioner_token` | `None`                   |
/// | `FERRUM_CREDS_JSON`          | `creds_bundle_json`| `None`                           |
/// | `FERRUM_CREDS_JSON_FILE`     | `creds_bundle_json_file` | `None` (path, preferred at scale) |
/// | `FERRUM_FILE_OUTPUT_PATH`    | `file_output_path` | `./assembled/resources.yaml`     |
/// | `FERRUM_MESH_FILE_OUTPUT_PATH` | `mesh_file_output_path` | `./assembled/mesh.yaml`   |
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
        // Blank-as-unset matters for every var CI feeds from a `${{ secrets.* }}`
        // expression: an unconfigured GitHub secret interpolates to "", and
        // Some("") would produce misleading downstream errors ("secret too
        // short") instead of the clear "not configured" ones.
        gateway_url: non_empty_env("FERRUM_GATEWAY_URL"),
        admin_jwt_secret: non_empty_env("FERRUM_ADMIN_JWT_SECRET"),
        admin_jwt_issuer: non_empty_env("FERRUM_ADMIN_JWT_ISSUER")
            .unwrap_or_else(|| DEFAULT_JWT_ISSUER.to_string()),
        admin_jwt_role: non_empty_env("FERRUM_ADMIN_JWT_ROLE")
            .unwrap_or_else(|| DEFAULT_JWT_ROLE.to_string()),
        admin_jwt_audience: non_empty_env("FERRUM_ADMIN_JWT_AUDIENCE"),
        admin_jwt_ttl_secs: parse_i64_env("FERRUM_ADMIN_JWT_TTL_SECS", DEFAULT_JWT_TTL_SECS),
        namespace_filter: non_empty_env("FERRUM_NAMESPACE"),
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
        overlay: non_empty_env("FERRUM_OVERLAY"),
        env_name: non_empty_env("FERRUM_ENV"),
        github_repository: non_empty_env("GITHUB_REPOSITORY"),
        github_token: non_empty_env("GITHUB_TOKEN"),
        github_provisioner_token: non_empty_env("FERRUM_GH_PROVISIONER_TOKEN"),
        creds_bundle_json: non_empty_env("FERRUM_CREDS_JSON"),
        creds_bundle_json_file: non_empty_env("FERRUM_CREDS_JSON_FILE"),
        file_output_path: env::var("FERRUM_FILE_OUTPUT_PATH")
            .unwrap_or_else(|_| "./assembled/resources.yaml".to_string()),
        mesh_file_output_path: non_empty_env("FERRUM_MESH_FILE_OUTPUT_PATH")
            .unwrap_or_else(|| DEFAULT_MESH_FILE_OUTPUT_PATH.to_string()),
        edge_binary_path: env::var("FERRUM_EDGE_BINARY_PATH")
            .unwrap_or_else(|_| "ferrum-edge".to_string()),
        tls_no_verify: env::var("FERRUM_TLS_NO_VERIFY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        ca_cert: non_empty_env("FERRUM_GATEWAY_CA_CERT"),
        client_cert: non_empty_env("FERRUM_GATEWAY_CLIENT_CERT"),
        client_key: non_empty_env("FERRUM_GATEWAY_CLIENT_KEY"),
        gateway_connect_timeout_secs: parse_timeout_env("FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS", 10),
        gateway_request_timeout_secs: parse_timeout_env("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", 60),
        github_connect_timeout_secs: parse_timeout_env("FERRUM_GITHUB_CONNECT_TIMEOUT_SECS", 10),
        github_request_timeout_secs: parse_timeout_env("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", 30),
        gateway_max_retries: parse_u32_env("FERRUM_GATEWAY_MAX_RETRIES", 3),
    }
}

/// Where the standalone `{version, mesh}` document lands when
/// `FERRUM_MESH_FILE_OUTPUT_PATH` is unset. Sits alongside the assembled
/// gateway file rather than overwriting it — the two documents are mutually
/// exclusive in shape.
pub const DEFAULT_MESH_FILE_OUTPUT_PATH: &str = "./assembled/mesh.yaml";

/// `iss` the gateway expects by default (`FERRUM_ADMIN_JWT_ISSUER` there).
pub const DEFAULT_JWT_ISSUER: &str = "ferrum-edge";
/// Role gitforgeops needs: `/backup`, `/restore`, `/batch` and consumer CRUD
/// are all admin-only, so `operator` is insufficient.
pub const DEFAULT_JWT_ROLE: &str = "admin";
/// Matches the gateway's default `FERRUM_ADMIN_JWT_MAX_TTL`. Acceptance is
/// `max_ttl + 60`, so the default sits comfortably inside the window.
pub const DEFAULT_JWT_TTL_SECS: i64 = 3600;

/// Read an env var, treating empty/whitespace as unset. `aud` in particular
/// must be *absent*, not empty, when the gateway has no audience configured.
fn non_empty_env(var: &str) -> Option<String> {
    env::var(var)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_i64_env(var: &str, default: i64) -> i64 {
    env::var(var)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
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
