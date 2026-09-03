use std::sync::{Mutex, MutexGuard};

use gitforgeops::config::env::{
    load_env_config, validate_gateway_transport, ApplyStrategy, GatewayMode,
};

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
        "FERRUM_ALLOW_INSECURE_HTTP",
        // Cleared so the transport rules are exercised deterministically:
        // `cargo test` itself runs under GitHub Actions in this repo's CI,
        // where the insecure opt-ins are refused for non-loopback hosts.
        "GITHUB_ACTIONS",
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

// --- Transport security ------------------------------------------------------
//
// The admin JWT and every resolved consumer credential travel in admin API
// requests, so the scheme of `FERRUM_GATEWAY_URL` is a security control, not a
// preference. These exercise `validate_gateway_transport` directly (the matrix
// is decided by four inputs, and passing `in_github_actions` beats mutating a
// process-global for every case) plus the `load_env_config` wiring.

/// `https://` needs no opt-in and warns about nothing.
#[test]
fn gateway_transport_accepts_https_without_warnings() {
    let warnings =
        validate_gateway_transport(Some("https://gateway.internal:9000"), false, false, true)
            .expect("https is the default-accepted scheme");
    assert!(warnings.is_empty(), "{warnings:?}");
}

/// A cleartext gateway is refused by default, and the refusal names both the
/// variable that is wrong and the variable that would change the answer.
#[test]
fn gateway_transport_refuses_cleartext_http_by_default() {
    let error =
        validate_gateway_transport(Some("http://gateway.internal:9000"), false, false, false)
            .expect_err("http:// must not be accepted without the opt-in");
    let error = error.to_string();
    assert!(error.contains("FERRUM_GATEWAY_URL"), "{error}");
    assert!(error.contains("http://gateway.internal:9000"), "{error}");
    assert!(error.contains("https://"), "{error}");
    assert!(error.contains("FERRUM_ALLOW_INSECURE_HTTP"), "{error}");
}

/// With the opt-in, a local dev gateway works — loudly.
#[test]
fn gateway_transport_allows_cleartext_http_with_opt_in_and_warns() {
    let warnings = validate_gateway_transport(Some("http://localhost:9000"), true, false, false)
        .expect("the documented opt-in must be honored outside CI");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("FERRUM_ALLOW_INSECURE_HTTP"),
        "{warnings:?}"
    );
    assert!(
        warnings[0].contains("!!!"),
        "the warning must be banner-shaped: {warnings:?}"
    );
}

/// Neither opt-in unlocks a scheme gitforgeops does not speak. `file://` in
/// particular would otherwise read as "assemble from a local path".
#[test]
fn gateway_transport_refuses_every_other_scheme_unconditionally() {
    for url in [
        "ftp://gateway.internal:9000",
        "file:///etc/ferrum/gateway.yaml",
        "ws://gateway.internal:9000",
        "gopher://gateway.internal",
    ] {
        for (allow_insecure_http, tls_no_verify) in
            [(false, false), (true, false), (true, true), (false, true)]
        {
            let error =
                validate_gateway_transport(Some(url), allow_insecure_http, tls_no_verify, false)
                    .expect_err("only http/https are ever accepted");
            let error = error.to_string();
            assert!(error.contains("FERRUM_GATEWAY_URL"), "{url}: {error}");
            assert!(error.contains("https://"), "{url}: {error}");
        }
    }
}

/// A URL that is not a URL fails at load, naming the variable rather than
/// surfacing later as an opaque request error.
#[test]
fn gateway_transport_refuses_a_malformed_url() {
    for url in ["gateway.internal:9000", "https://", "not a url"] {
        let error = validate_gateway_transport(Some(url), true, false, false)
            .expect_err("a malformed URL must fail at env load");
        let error = error.to_string();
        assert!(error.contains("FERRUM_GATEWAY_URL"), "{url}: {error}");
    }
}

/// Credentials in the authority are refused, and the value is withheld from
/// the error — these messages land in CI logs.
#[test]
fn gateway_transport_refuses_embedded_credentials_without_echoing_them() {
    for url in [
        "https://admin:hunter2@gateway.internal:9000",
        "http://admin@gateway.internal:9000",
    ] {
        let error = validate_gateway_transport(Some(url), true, false, false)
            .expect_err("userinfo must never reach the gateway");
        let error = error.to_string();
        assert!(error.contains("FERRUM_GATEWAY_URL"), "{url}: {error}");
        assert!(error.contains("credentials"), "{url}: {error}");
        assert!(!error.contains("hunter2"), "secret echoed back: {error}");
        assert!(!error.contains("admin@"), "userinfo echoed back: {error}");
    }
}

/// In CI the opt-ins survive only against the runner's own machine.
#[test]
fn insecure_opt_ins_survive_in_ci_only_for_loopback_hosts() {
    for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.0.0.53", "[::1]"] {
        let url = format!("http://{host}:9000");
        let warnings = validate_gateway_transport(Some(&url), true, true, true)
            .unwrap_or_else(|e| panic!("{url} is loopback and must stay allowed in CI: {e}"));
        // One banner for the cleartext scheme, one for the disabled
        // certificate check.
        assert_eq!(warnings.len(), 2, "{url}: {warnings:?}");
    }
}

/// A CI run reaching a real gateway must do it over verified TLS. Both
/// opt-ins are refused, and each refusal names itself.
#[test]
fn insecure_opt_ins_are_refused_in_ci_for_remote_hosts() {
    let error = validate_gateway_transport(Some("http://gateway.internal:9000"), true, false, true)
        .expect_err("cleartext to a remote host must be refused in CI")
        .to_string();
    assert!(error.contains("FERRUM_ALLOW_INSECURE_HTTP"), "{error}");
    assert!(error.contains("GITHUB_ACTIONS"), "{error}");
    assert!(error.contains("gateway.internal"), "{error}");

    // Same rule for the certificate check, independent of the scheme: TLS
    // that verifies nothing is not transport security.
    let error =
        validate_gateway_transport(Some("https://gateway.internal:9000"), false, true, true)
            .expect_err("an unverified certificate must be refused in CI")
            .to_string();
    assert!(error.contains("FERRUM_TLS_NO_VERIFY"), "{error}");
    assert!(error.contains("GITHUB_ACTIONS"), "{error}");

    // Outside CI the same combination is a developer's own machine: allowed,
    // with a banner.
    let warnings =
        validate_gateway_transport(Some("https://gateway.internal:9000"), false, true, false)
            .expect("local runs keep the dev escape hatch");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("FERRUM_TLS_NO_VERIFY"), "{warnings:?}");
}

/// File-mode runs have no gateway URL at all. With no host to judge, there is
/// nothing to refuse — the flags are inert and the run proceeds.
#[test]
fn insecure_opt_ins_are_inert_without_a_gateway_url() {
    let warnings = validate_gateway_transport(None, true, false, true)
        .expect("no gateway URL means no cleartext gateway call");
    assert!(warnings.is_empty(), "{warnings:?}");

    let warnings = validate_gateway_transport(None, false, true, true)
        .expect("no gateway URL means no certificate to skip verifying");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

/// The whole point of validating at load: every command fails before a client
/// is built, so no request ever leaves with the JWT in cleartext.
#[test]
fn load_env_config_enforces_the_gateway_scheme() {
    let _guard = env_guard();
    clear_env();

    std::env::set_var("FERRUM_GATEWAY_URL", "http://gateway.internal:9000");
    let error = load_env_config()
        .expect_err("http:// must fail the whole command")
        .to_string();
    assert!(error.contains("FERRUM_ALLOW_INSECURE_HTTP"), "{error}");

    std::env::set_var("FERRUM_ALLOW_INSECURE_HTTP", "true");
    let config = load_env_config().expect("the opt-in must be honored outside CI");
    assert!(config.allow_insecure_http);
    assert_eq!(
        config.gateway_url.as_deref(),
        Some("http://gateway.internal:9000"),
        "the URL is validated, never rewritten"
    );

    // The same repo config in Actions is refused.
    std::env::set_var("GITHUB_ACTIONS", "true");
    let error = load_env_config()
        .expect_err("CI must not accept a remote cleartext gateway")
        .to_string();
    assert!(error.contains("GITHUB_ACTIONS"), "{error}");

    // Loopback is the exemption, and https needs no opt-in at all.
    std::env::set_var("FERRUM_GATEWAY_URL", "http://127.0.0.1:9000");
    assert!(load_env_config().is_ok());
    std::env::set_var("FERRUM_GATEWAY_URL", "https://gateway.internal:9000");
    std::env::remove_var("FERRUM_ALLOW_INSECURE_HTTP");
    let config = load_env_config().expect("https is always accepted");
    assert!(!config.allow_insecure_http);

    clear_env();
}

/// `FERRUM_ALLOW_INSECURE_HTTP` parses like every other boolean on the
/// surface: trimmed, case-folded, blank-as-default, invalid-as-fatal.
#[test]
fn allow_insecure_http_parses_like_the_other_booleans() {
    let _guard = env_guard();
    clear_env();

    assert!(!load_env_config().unwrap().allow_insecure_http);

    std::env::set_var("FERRUM_ALLOW_INSECURE_HTTP", "   ");
    assert!(!load_env_config().unwrap().allow_insecure_http);

    std::env::set_var("FERRUM_ALLOW_INSECURE_HTTP", " TRUE ");
    assert!(load_env_config().unwrap().allow_insecure_http);

    std::env::set_var("FERRUM_ALLOW_INSECURE_HTTP", "yes");
    let error = load_env_config().unwrap_err().to_string();
    assert!(error.contains("FERRUM_ALLOW_INSECURE_HTTP"), "{error}");
    assert!(error.contains("yes"), "{error}");

    clear_env();
}
