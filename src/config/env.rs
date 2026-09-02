use std::env;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

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
    /// URL of the Ferrum Edge admin API (e.g. `https://gateway.internal:9000`).
    ///
    /// Validated at load: `https://` only, unless `allow_insecure_http` opts
    /// into a cleartext `http://` gateway. Every other scheme, and any URL
    /// carrying embedded `user:password@` credentials, is refused outright.
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
    /// Carry unknown **top-level** `spec` fields verbatim instead of rejecting
    /// them (default `false`, fail-closed).
    ///
    /// The typed mirror in `config::schema` is authoritative-by-rejection so a
    /// misspelled field cannot silently drop out of desired state. That makes a
    /// gateway release which adds a field an outage until gitforgeops ships a
    /// matching release; this is the escape hatch. Unknown top-level fields are
    /// kept in `PassthroughFields` and passed through export/diff/apply for the
    /// gateway — the authoritative schema — to judge, with a loud per-file
    /// warning on stderr. Nested unknown fields stay hard errors either way.
    pub allow_unknown_fields: bool,
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
    ///
    /// Dev only, and independent of [`EnvConfig::allow_insecure_http`]: this
    /// one keeps TLS on the wire but accepts any certificate, so a MITM is
    /// indistinguishable from the real gateway. Setting it prints a loud
    /// stderr warning, and under `GITHUB_ACTIONS` it is refused unless the
    /// gateway host is loopback.
    pub tls_no_verify: bool,
    /// Permit a cleartext `http://` gateway URL (default `false`).
    ///
    /// The admin JWT and every resolved consumer credential travel in the
    /// body and headers of admin API calls, so `http://` puts production
    /// secrets on the wire in the clear. The opt-in exists for a gateway
    /// running on the developer's own machine: it prints a loud stderr
    /// warning, and under `GITHUB_ACTIONS` it is refused unless the gateway
    /// host is loopback (`localhost`, `127.0.0.0/8`, `::1`).
    pub allow_insecure_http: bool,
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
            allow_unknown_fields: false,
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
            allow_insecure_http: false,
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
/// Transport security is settled here, before any HTTP client exists, so a
/// cleartext or unverified gateway fails the run rather than one request at a
/// time: see [`validate_gateway_transport`]. The insecure opt-ins print their
/// warning once per process.
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
/// | `FERRUM_ALLOW_UNKNOWN_FIELDS`| `allow_unknown_fields` | `false` (unknown fields are rejected) |
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
/// | `FERRUM_ALLOW_INSECURE_HTTP` | `allow_insecure_http` | `false` (an `http://` gateway URL is refused) |
/// | `FERRUM_GATEWAY_CA_CERT`     | `ca_cert`          | `None`                           |
/// | `FERRUM_GATEWAY_CLIENT_CERT` | `client_cert`      | `None`                           |
/// | `FERRUM_GATEWAY_CLIENT_KEY`  | `client_key`       | `None`                           |
/// | `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `gateway_connect_timeout_secs` | `10`        |
/// | `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `gateway_request_timeout_secs` | `60`        |
/// | `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS`  | `github_connect_timeout_secs`  | `10`        |
/// | `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS`  | `github_request_timeout_secs`  | `30`        |
/// | `FERRUM_GATEWAY_MAX_RETRIES`          | `gateway_max_retries`          | `3`         |
pub fn load_env_config() -> crate::error::Result<EnvConfig> {
    let gateway_mode = match normalized_env("FERRUM_GATEWAY_MODE").as_deref() {
        None | Some("api") => GatewayMode::Api,
        Some("file") => GatewayMode::File,
        Some(value) => return Err(invalid_env("FERRUM_GATEWAY_MODE", value, "api or file")),
    };
    let apply_strategy = match normalized_env("FERRUM_APPLY_STRATEGY").as_deref() {
        None | Some("incremental") => ApplyStrategy::Incremental,
        Some("full_replace") => ApplyStrategy::FullReplace,
        Some(value) => {
            return Err(invalid_env(
                "FERRUM_APPLY_STRATEGY",
                value,
                "incremental or full_replace",
            ))
        }
    };
    let admin_jwt_role =
        non_empty_env("FERRUM_ADMIN_JWT_ROLE").unwrap_or_else(|| DEFAULT_JWT_ROLE.to_string());
    if !matches!(admin_jwt_role.as_str(), "viewer" | "operator" | "admin") {
        return Err(invalid_env(
            "FERRUM_ADMIN_JWT_ROLE",
            &admin_jwt_role,
            "viewer, operator, or admin",
        ));
    }

    // Blank-as-unset applies here too: `FERRUM_GATEWAY_URL` is a GitHub
    // Environment secret, so an unset one interpolates to "" and must read as
    // "no gateway configured" rather than as a malformed URL.
    let gateway_url = non_empty_env("FERRUM_GATEWAY_URL");
    let tls_no_verify = parse_bool_env("FERRUM_TLS_NO_VERIFY", false)?;
    let allow_insecure_http = parse_bool_env("FERRUM_ALLOW_INSECURE_HTTP", false)?;
    let warnings = validate_gateway_transport(
        gateway_url.as_deref(),
        allow_insecure_http,
        tls_no_verify,
        running_in_github_actions(),
    )?;
    warn_insecure_transport_once(&warnings);

    Ok(EnvConfig {
        // Blank-as-unset matters for every var CI feeds from a `${{ secrets.* }}`
        // expression: an unconfigured GitHub secret interpolates to "", and
        // Some("") would produce misleading downstream errors ("secret too
        // short") instead of the clear "not configured" ones.
        gateway_url,
        admin_jwt_secret: non_empty_env("FERRUM_ADMIN_JWT_SECRET"),
        admin_jwt_issuer: non_empty_env("FERRUM_ADMIN_JWT_ISSUER")
            .unwrap_or_else(|| DEFAULT_JWT_ISSUER.to_string()),
        admin_jwt_role,
        admin_jwt_audience: non_empty_env("FERRUM_ADMIN_JWT_AUDIENCE"),
        admin_jwt_ttl_secs: parse_positive_i64_env(
            "FERRUM_ADMIN_JWT_TTL_SECS",
            DEFAULT_JWT_TTL_SECS,
        )?,
        namespace_filter: non_empty_env("FERRUM_NAMESPACE"),
        allow_unknown_fields: parse_bool_env("FERRUM_ALLOW_UNKNOWN_FIELDS", false)?,
        gateway_mode,
        apply_strategy,
        overlay: non_empty_env("FERRUM_OVERLAY"),
        env_name: non_empty_env("FERRUM_ENV"),
        github_repository: non_empty_env("GITHUB_REPOSITORY"),
        github_token: non_empty_env("GITHUB_TOKEN"),
        github_provisioner_token: non_empty_env("FERRUM_GH_PROVISIONER_TOKEN"),
        creds_bundle_json: non_empty_env("FERRUM_CREDS_JSON"),
        creds_bundle_json_file: non_empty_env("FERRUM_CREDS_JSON_FILE"),
        file_output_path: non_empty_env("FERRUM_FILE_OUTPUT_PATH")
            .unwrap_or_else(|| "./assembled/resources.yaml".to_string()),
        mesh_file_output_path: non_empty_env("FERRUM_MESH_FILE_OUTPUT_PATH")
            .unwrap_or_else(|| DEFAULT_MESH_FILE_OUTPUT_PATH.to_string()),
        edge_binary_path: non_empty_env("FERRUM_EDGE_BINARY_PATH")
            .unwrap_or_else(|| "ferrum-edge".to_string()),
        tls_no_verify,
        allow_insecure_http,
        ca_cert: non_empty_env("FERRUM_GATEWAY_CA_CERT"),
        client_cert: non_empty_env("FERRUM_GATEWAY_CLIENT_CERT"),
        client_key: non_empty_env("FERRUM_GATEWAY_CLIENT_KEY"),
        gateway_connect_timeout_secs: parse_positive_u64_env(
            "FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS",
            10,
        )?,
        gateway_request_timeout_secs: parse_positive_u64_env(
            "FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS",
            60,
        )?,
        github_connect_timeout_secs: parse_positive_u64_env(
            "FERRUM_GITHUB_CONNECT_TIMEOUT_SECS",
            10,
        )?,
        github_request_timeout_secs: parse_positive_u64_env(
            "FERRUM_GITHUB_REQUEST_TIMEOUT_SECS",
            30,
        )?,
        gateway_max_retries: parse_u32_env("FERRUM_GATEWAY_MAX_RETRIES", 3)?,
    })
}

/// Accepted forms of `FERRUM_GATEWAY_URL`, quoted verbatim by every rejection
/// so the error tells the operator what to type instead.
const GATEWAY_URL_ACCEPTED: &str = "an absolute https:// URL with a host and no \
     embedded credentials (for example https://gateway.internal:9000); an http:// URL is \
     accepted only with FERRUM_ALLOW_INSECURE_HTTP=true, and no other scheme is ever accepted";

/// Rule drawn above and below an insecure-transport warning. The warning has
/// to survive a scrolling CI log, so it is banner-shaped rather than a line of
/// prose lost among the diff output.
const WARNING_RULE: &str =
    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

/// Set once the process has printed its insecure-transport banner. Commands
/// load the environment more than once per run, and repeating the banner
/// trains operators to scroll past it.
static INSECURE_TRANSPORT_WARNED: AtomicBool = AtomicBool::new(false);

/// Decide whether this process may talk to the gateway the way the
/// environment asks it to, and report what to shout about if it may.
///
/// Runs at env-load time — before any [`crate::http_client::AdminClient`]
/// exists — so a cleartext or unverified transport fails the whole command
/// once instead of leaking the admin JWT and every resolved consumer
/// credential onto the wire request by request.
///
/// The rules:
///
/// - `https://` is the only scheme accepted by default. `http://` needs
///   `FERRUM_ALLOW_INSECURE_HTTP=true`; every other scheme (`ftp`, `file`,
///   `ws`, …) is refused unconditionally.
/// - A URL embedding `user:password@` credentials is refused unconditionally.
///   The value is never echoed back in that error.
/// - Both insecure opt-ins (`FERRUM_ALLOW_INSECURE_HTTP`, and
///   `FERRUM_TLS_NO_VERIFY`, which keeps TLS but accepts any certificate) are
///   refused under `GITHUB_ACTIONS` unless the gateway host is loopback —
///   `localhost`, `127.0.0.0/8`, or `::1`. They are laptop switches; a CI run
///   reaching a real gateway must do it over verified TLS.
/// - Otherwise each opt-in that is actually load-bearing contributes a
///   warning, returned rather than printed so callers control the banner.
///
/// `in_github_actions` is passed in rather than read here so the matrix is
/// testable without mutating a process-global.
pub fn validate_gateway_transport(
    gateway_url: Option<&str>,
    allow_insecure_http: bool,
    tls_no_verify: bool,
    in_github_actions: bool,
) -> crate::error::Result<Vec<String>> {
    let mut warnings = Vec::new();

    let parsed = match gateway_url {
        None => None,
        Some(raw) => Some(parse_gateway_url(raw)?),
    };
    // `None` here means no gateway is configured at all — a file-mode run, or
    // an environment whose URL secret is still unset. That is not a loopback
    // target, but it is not a remote one either: there is no request to
    // protect yet, and `AdminClient` refuses to build without a URL. Only a
    // host we can see and that is *not* loopback trips the CI refusals.
    let remote_host = parsed
        .as_ref()
        .and_then(Url::host)
        .filter(|host| !host_is_loopback(host))
        .map(|host| host.to_string());

    if let (Some(url), Some(raw)) = (parsed.as_ref(), gateway_url) {
        if url.scheme() == "http" {
            if !allow_insecure_http {
                return Err(cleartext_gateway_refused(raw));
            }
            if in_github_actions {
                if let Some(ref host) = remote_host {
                    return Err(refused_in_github_actions(
                        "FERRUM_ALLOW_INSECURE_HTTP",
                        &format!(
                            "the gateway host {host} is not loopback, so an http:// admin API \
                             would put the admin JWT and every resolved consumer credential on \
                             the wire in cleartext"
                        ),
                    ));
                }
            }
            warnings.push(insecure_warning(
                "FERRUM_ALLOW_INSECURE_HTTP=true: talking to the admin API over cleartext http://.",
                "The admin JWT and every resolved consumer credential are sent unencrypted, and \
                 anything on the path can read or rewrite them. Local development only.",
            ));
        }
    }

    if tls_no_verify {
        if in_github_actions {
            if let Some(ref host) = remote_host {
                return Err(refused_in_github_actions(
                    "FERRUM_TLS_NO_VERIFY",
                    &format!(
                        "the gateway host {host} is not loopback, so skipping certificate \
                         verification would make any interceptor's certificate acceptable"
                    ),
                ));
            }
        }
        warnings.push(insecure_warning(
            "FERRUM_TLS_NO_VERIFY=true: the gateway's TLS certificate is NOT verified.",
            "Any certificate is accepted, so an interceptor is indistinguishable from the real \
             gateway. Local development only — use FERRUM_GATEWAY_CA_CERT for a private CA.",
        ));
    }

    Ok(warnings)
}

/// Parse `FERRUM_GATEWAY_URL` and enforce the scheme/userinfo/host rules that
/// hold regardless of any opt-in. Whether an `http://` URL is *allowed* is the
/// caller's decision; this only guarantees the URL is one of the two schemes
/// gitforgeops speaks and that it names a host.
fn parse_gateway_url(raw: &str) -> crate::error::Result<Url> {
    let parsed = Url::parse(raw).map_err(|e| {
        invalid_env(
            "FERRUM_GATEWAY_URL",
            &redacted_url(raw),
            &format!("{GATEWAY_URL_ACCEPTED} ({e})"),
        )
    })?;

    // Checked before the scheme so a rejected value carrying a password is
    // never echoed by a later error.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(crate::error::Error::Config(format!(
            "invalid FERRUM_GATEWAY_URL: the URL embeds credentials (user:password@host), which \
             would be sent to the gateway and recorded by anything logging the URL; expected \
             {GATEWAY_URL_ACCEPTED}. Put the admin secret in FERRUM_ADMIN_JWT_SECRET instead \
             (value withheld from this message)"
        )));
    }

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid_env(
            "FERRUM_GATEWAY_URL",
            &redacted_url(raw),
            GATEWAY_URL_ACCEPTED,
        ));
    }

    // `url` guarantees a non-empty host for http/https, so this is a
    // belt-and-braces check that keeps the loopback test total.
    if parsed.host().is_none() {
        return Err(invalid_env(
            "FERRUM_GATEWAY_URL",
            &redacted_url(raw),
            GATEWAY_URL_ACCEPTED,
        ));
    }

    Ok(parsed)
}

/// Is the gateway host the machine running gitforgeops?
///
/// Deliberately literal: `localhost`, anything in `127.0.0.0/8`, and `::1`.
/// A name that merely *resolves* to a loopback address does not count — DNS is
/// not a trust boundary, and the check has to be decidable without a lookup.
fn host_is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

/// A gateway URL is never echoed verbatim once it carries an `@`: the
/// authority may hold `user:password`, and these errors land in CI logs.
fn redacted_url(raw: &str) -> String {
    if raw.contains('@') {
        "<redacted: value contains '@' and may embed credentials>".to_string()
    } else {
        raw.to_string()
    }
}

/// The default refusal: a well-formed `http://` gateway URL with no opt-in.
/// Says what is at stake and names the one variable that changes the answer.
fn cleartext_gateway_refused(raw: &str) -> crate::error::Error {
    crate::error::Error::Config(format!(
        "invalid FERRUM_GATEWAY_URL value {:?}; expected {GATEWAY_URL_ACCEPTED}. The admin JWT \
         and every resolved consumer credential travel in these requests, so a cleartext gateway \
         is refused unless FERRUM_ALLOW_INSECURE_HTTP=true declares it a local development \
         gateway",
        redacted_url(raw)
    ))
}

fn refused_in_github_actions(var: &str, reason: &str) -> crate::error::Error {
    crate::error::Error::Config(format!(
        "{var}=true is refused under GITHUB_ACTIONS: {reason}. Point FERRUM_GATEWAY_URL at an \
         https:// gateway with a certificate this runner trusts (FERRUM_GATEWAY_CA_CERT carries a \
         private CA), or unset {var} — the insecure opt-ins are allowed in CI only against a \
         loopback host (localhost, 127.0.0.0/8, ::1)"
    ))
}

fn insecure_warning(headline: &str, detail: &str) -> String {
    format!("{WARNING_RULE}\n!!! {headline}\n!!! {detail}\n{WARNING_RULE}")
}

/// Print the insecure-transport banners, at most once for the life of the
/// process. stderr, never stdout: `gitforgeops export` writes the assembled
/// YAML to stdout and a banner interleaved into it would corrupt the document.
fn warn_insecure_transport_once(warnings: &[String]) {
    if warnings.is_empty() || INSECURE_TRANSPORT_WARNED.swap(true, Ordering::SeqCst) {
        return;
    }
    for warning in warnings {
        eprintln!("{warning}");
    }
}

/// True when running inside a GitHub Actions job. Actions sets
/// `GITHUB_ACTIONS=true` for every run, including forks and `act`-style
/// emulators that mimic the contract.
fn running_in_github_actions() -> bool {
    matches!(
        normalized_env("GITHUB_ACTIONS").as_deref(),
        Some("true" | "1")
    )
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

fn normalized_env(var: &str) -> Option<String> {
    non_empty_env(var).map(|value| value.to_ascii_lowercase())
}

fn parse_bool_env(var: &str, default: bool) -> crate::error::Result<bool> {
    match normalized_env(var).as_deref() {
        None => Ok(default),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(value) => Err(invalid_env(var, value, "true, false, 1, or 0")),
    }
}

fn parse_positive_i64_env(var: &str, default: i64) -> crate::error::Result<i64> {
    match non_empty_env(var) {
        None => Ok(default),
        Some(value) => value
            .parse::<i64>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or_else(|| invalid_env(var, &value, "a positive base-10 integer")),
    }
}

fn parse_positive_u64_env(var: &str, default: u64) -> crate::error::Result<u64> {
    match non_empty_env(var) {
        None => Ok(default),
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .ok_or_else(|| invalid_env(var, &value, "a positive base-10 integer")),
    }
}

fn parse_u32_env(var: &str, default: u32) -> crate::error::Result<u32> {
    match non_empty_env(var) {
        None => Ok(default),
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| invalid_env(var, &value, "a base-10 integer in 0..=4294967295")),
    }
}

fn invalid_env(var: &str, value: &str, accepted: &str) -> crate::error::Error {
    crate::error::Error::Config(format!(
        "invalid {var} value {value:?}; expected {accepted} (unset or blank uses the documented default)"
    ))
}
