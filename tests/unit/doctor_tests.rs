//! The setup doctor's three load-bearing properties.
//!
//! 1. It never guesses: a check that could not be performed reports `Unknown`,
//!    and `Unknown` is never a pass.
//! 2. It never mutates: the gateway scope issues reads, proven by recording
//!    what a stub server actually received.
//! 3. It never prints a secret value: credentials are described by presence.
//!
//! Everything else here is the fourth requirement — that a fresh template
//! reads as intentionally unconfigured while a half-configured deployment
//! repository reads as a list of specific, fixable blockers.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use gitforgeops::config::env::GatewayMode;
use gitforgeops::config::{resolve_env, EnvConfig, GatewayConfig, RepoConfig};
use gitforgeops::diff::state_key;
use gitforgeops::doctor::local::RepositoryKind;
use gitforgeops::doctor::{self, Check, Report, Scope, Status};
use gitforgeops::reconcile::resolved_namespaces;
use gitforgeops::state::StateFile;
use tempfile::TempDir;

const SECRET: &str = "super-secret-signing-key-that-is-long-enough";

fn repo(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    for (relative, contents) in files {
        let path = dir.path().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(&path, contents).expect("write");
    }
    dir
}

fn find<'a>(checks: &'a [Check], id: &str) -> &'a Check {
    checks
        .iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| panic!("no check {id}: {:?}", ids(checks)))
}

fn ids(checks: &[Check]) -> Vec<&str> {
    checks.iter().map(|check| check.id).collect()
}

fn api_env() -> EnvConfig {
    EnvConfig {
        gateway_mode: GatewayMode::Api,
        ..EnvConfig::default()
    }
}

// -- a template is unconfigured on purpose ---------------------------------

#[test]
fn a_fresh_template_reports_intentionally_unconfigured_not_broken() {
    // The template is what customers copy. It has no repository config, no
    // deployment environment and no gateway credentials, and reporting that as
    // a failure would teach every new operator to ignore the exit code.
    let dir = repo(&[
        (".gitforgeops/config.example.yaml", "version: 1\n"),
        (".github/ferrum-edge-checksums.txt", "abc123  ferrum-edge\n"),
    ]);
    let checks = doctor::local::run(dir.path(), Some(&api_env()));

    assert_eq!(
        doctor::local::repository_kind(dir.path()),
        RepositoryKind::Template
    );
    for id in [
        "repository-kind",
        "repo-config",
        "gateway-url",
        "admin-jwt-secret",
    ] {
        assert_eq!(find(&checks, id).status, Status::Skipped, "{id}");
    }
    // ...and the skip explains how to become a deployment repository.
    assert!(find(&checks, "repo-config")
        .remediation
        .as_ref()
        .expect("remediation")
        .contains(".gitforgeops/config.yaml"));
}

#[test]
fn an_incomplete_deployment_repository_names_each_blocker() {
    let dir = repo(&[
        (
            ".gitforgeops/config.yaml",
            "version: 1\nenvironments:\n  production:\n    overlay: production\n",
        ),
        (".github/ferrum-edge-checksums.txt", "abc123  ferrum-edge\n"),
        ("resources/ferrum/proxies/orders.yaml", "kind: Proxy\n"),
    ]);
    let checks = doctor::local::run(dir.path(), Some(&api_env()));

    assert_eq!(
        doctor::local::repository_kind(dir.path()),
        RepositoryKind::Deployment
    );
    assert_eq!(find(&checks, "repository-kind").status, Status::Pass);
    assert_eq!(find(&checks, "repo-config").status, Status::Pass);

    // The overlay the config selects is not in the tree: every command for
    // that environment would fail, and the doctor names which environment.
    let overlays = find(&checks, "overlays");
    assert_eq!(overlays.status, Status::Fail);
    assert!(overlays
        .detail
        .contains("production -> overlays/production"));
    assert!(overlays.remediation.is_some());

    // On a deployment repository the absent gateway credentials ARE blockers.
    for id in ["gateway-url", "admin-jwt-secret"] {
        assert_eq!(find(&checks, id).status, Status::Fail, "{id}");
        assert!(find(&checks, id).remediation.is_some(), "{id}");
    }
}

#[test]
fn a_non_admin_jwt_role_is_a_blocker_because_backup_is_admin_only() {
    // `/cluster` has no role requirement, so the gateway scope cannot catch
    // this; the first real command would 403 on `GET /backup`.
    let dir = repo(&[]);
    for role in ["viewer", "operator"] {
        let env = EnvConfig {
            admin_jwt_role: role.to_string(),
            ..api_env()
        };
        let checks = doctor::local::run(dir.path(), Some(&env));
        let claims = find(&checks, "admin-jwt-claims");
        assert_eq!(claims.status, Status::Fail, "{role}");
        assert!(claims
            .remediation
            .as_deref()
            .is_some_and(|text| text.contains("admin-only")));
    }
    let checks = doctor::local::run(dir.path(), Some(&api_env()));
    assert_eq!(find(&checks, "admin-jwt-claims").status, Status::Pass);
}

#[test]
fn a_repository_config_that_does_not_load_is_a_named_failure() {
    let dir = repo(&[(
        ".gitforgeops/config.yaml",
        "version: 1\nenvironments:\n  production:\n    ownership:\n      mode: exclusive\n",
    )]);
    let checks = doctor::local::run(dir.path(), Some(&api_env()));
    let check = find(&checks, "repo-config");
    assert_eq!(check.status, Status::Fail);
    // Exclusive mode with no namespaces — the loader's own message, surfaced
    // here instead of from the middle of an apply.
    assert!(check.detail.contains("ownership.namespaces"), "{check:?}");
}

#[test]
fn a_missing_validator_pin_and_binary_are_separate_findings() {
    // "The validator is not installed" and "CI trusts no validator build" have
    // different fixes, so they are different checks.
    let dir = repo(&[(
        ".gitforgeops/config.yaml",
        "version: 1\nenvironments:\n  a: {}\n",
    )]);
    let checks = doctor::local::run(dir.path(), Some(&api_env()));
    let pin = find(&checks, "validator-pin");
    assert_eq!(pin.status, Status::Fail);
    // The file is absent entirely, which is a different fix from an allowlist
    // that exists but trusts nothing.
    assert!(pin
        .remediation
        .as_ref()
        .expect("remediation")
        .contains("trusted validator build"));
    assert_ne!(find(&checks, "validator-binary").id, pin.id);
}

#[test]
fn a_comment_only_validator_allowlist_is_not_a_populated_allowlist() {
    let dir = repo(&[
        (
            ".gitforgeops/config.yaml",
            "version: 1\nenvironments:\n  a: {}\n",
        ),
        (
            ".github/ferrum-edge-checksums.txt",
            "# every line here is a comment\n#\n",
        ),
    ]);
    let checks = doctor::local::run(dir.path(), Some(&api_env()));
    let pin = find(&checks, "validator-pin");
    assert_eq!(pin.status, Status::Fail);
    assert!(pin
        .remediation
        .as_ref()
        .expect("remediation")
        .contains("refresh-ferrum-edge-pin.sh"));
}

#[test]
fn file_mode_checks_the_output_path_instead_of_gateway_credentials() {
    let dir = repo(&[
        (
            ".gitforgeops/config.yaml",
            "version: 1\nenvironments:\n  a: {}\n",
        ),
        (".github/ferrum-edge-checksums.txt", "abc  ferrum-edge\n"),
    ]);
    let env = EnvConfig {
        gateway_mode: GatewayMode::File,
        file_output_path: "./nowhere/resources.yaml".to_string(),
        ..EnvConfig::default()
    };
    let checks = doctor::local::run(dir.path(), Some(&env));
    assert_eq!(find(&checks, "file-output").status, Status::Fail);
    assert!(ids(&checks).iter().all(|id| *id != "gateway-url"));
}

// -- unknown is not a pass -------------------------------------------------

#[test]
fn github_checks_without_a_token_are_unknown_rather_than_passed() {
    let dir = repo(&[]);
    let checks = doctor::github::run(
        dir.path(),
        &doctor::github::GithubContext {
            repository: Some("acme/repo".to_string()),
            token: None,
            state_writer_app_id: Some("99".to_string()),
            template_repo: false,
        },
    );
    let check = find(&checks, "settings-audit");
    assert_eq!(check.status, Status::Unknown);
    assert!(check.detail.contains("Administration: read"));
    // An unknown check must not be able to make a repository look ready...
    let mut report = Report::default();
    report.extend(checks);
    assert!(report.is_ready());
    // ...so the rendered report says out loud that it did not look.
    let rendered = report.render_text();
    assert!(rendered.contains("UNKNOWN is not a pass"), "{rendered}");
}

#[test]
fn github_checks_without_the_state_writer_app_id_are_unknown() {
    let dir = repo(&[]);
    let checks = doctor::github::run(
        dir.path(),
        &doctor::github::GithubContext {
            repository: Some("acme/repo".to_string()),
            token: Some("token".to_string()),
            state_writer_app_id: None,
            template_repo: false,
        },
    );
    assert_eq!(find(&checks, "settings-audit").status, Status::Unknown);
}

#[test]
fn github_doctor_does_not_execute_the_checkout_auditor() {
    // Neither the checkout's auditor nor a checkout module shadowing a
    // standard-library import of the bundled one may run.
    let dir = repo(&[
        (
            ".github/scripts/audit_settings.py",
            "from pathlib import Path\nPath('checkout-auditor-ran').write_text('bad')\n",
        ),
        (
            "argparse.py",
            "from pathlib import Path\nPath('checkout-module-ran').write_text('bad')\n",
        ),
    ]);
    let checks = doctor::github::run(
        dir.path(),
        &doctor::github::GithubContext {
            repository: Some("acme/repo".to_string()),
            token: Some("token".to_string()),
            state_writer_app_id: Some("99".to_string()),
            template_repo: false,
        },
    );
    assert!(!dir.path().join("checkout-auditor-ran").exists());
    assert!(!dir.path().join("checkout-module-ran").exists());
    assert_eq!(find(&checks, "settings-audit").status, Status::Unknown);
}

#[test]
fn github_checks_surface_each_auditor_violation_as_its_own_finding() {
    // Doctor owns no settings baseline: it runs the same auditor the bootstrap
    // writes for and the scheduled audit runs, and republishes its findings.
    let checks = doctor::github::audit_checks(
        false,
        "Repository protection evidence:\n  PASS: something is fine\n",
        "Repository protection violations:\n  \
         FAIL: environment 'production' must require at least one reviewer\n",
    );
    assert_eq!(find(&checks, "settings-audit").status, Status::Fail);
    assert!(
        checks.iter().any(|check| check.id == "settings-control"
            && check.detail.contains("must require at least one reviewer")),
        "{checks:?}"
    );
}

#[test]
fn github_checks_surface_each_auditor_warning_as_a_warn_finding() {
    // A state the auditor accepts but flags (a monitoring environment holding
    // both gateway signing keys) passes the audit and is still reported.
    let checks = doctor::github::audit_checks(
        true,
        "Repository protection evidence:\n  PASS: something is fine\n\
         Repository protection warnings:\n  \
         WARN: monitoring environment 'production-monitor' holds both keys\n\
         All launch protection controls are active.\n",
        "",
    );
    assert_eq!(find(&checks, "settings-audit").status, Status::Pass);
    let warning = find(&checks, "settings-warning");
    assert_eq!(warning.status, Status::Warn, "{warning:?}");
    assert!(warning.detail.contains("holds both keys"), "{warning:?}");
    assert!(
        checks.iter().all(|check| check.id != "settings-control"),
        "{checks:?}"
    );
}

#[test]
fn an_auditor_that_could_not_run_is_unknown_not_a_failed_control() {
    // Violations are a finding about the repository; an API error or a token
    // without Administration: read means the audit did not happen.
    let checks = doctor::github::audit_checks(
        false,
        "",
        "settings audit failed closed: GitHub API request failed for \
         repos/acme/repo/rulesets: 403\n",
    );
    let check = find(&checks, "settings-audit");
    assert_eq!(check.status, Status::Unknown, "{check:?}");
    assert!(check.detail.contains("could not complete"), "{check:?}");
    assert!(check.detail.contains("403"), "{check:?}");
    assert!(
        checks.iter().all(|check| check.id != "settings-control"),
        "{checks:?}"
    );
}

#[test]
fn github_doctor_uses_its_bundled_auditor_when_checkout_copy_is_missing() {
    let dir = repo(&[]);
    let checks = doctor::github::run(
        dir.path(),
        &doctor::github::GithubContext {
            repository: Some("acme/repo".to_string()),
            token: Some("token".to_string()),
            state_writer_app_id: Some("99".to_string()),
            template_repo: false,
        },
    );
    let check = find(&checks, "settings-audit");
    assert_eq!(check.status, Status::Unknown);
    assert!(
        !check.detail.contains("is not in this checkout"),
        "{check:?}"
    );
}

// -- the gateway scope reads, and only reads -------------------------------

/// Answer `GET /health` and `GET /cluster` the way Ferrum Edge does, recording
/// every request line so a test can prove nothing was mutated.
///
/// `/health` is unauthenticated on the real gateway — it answers 200 whatever
/// token is presented — so only `/cluster`, which sits behind the admin JWT
/// gate, takes `status`. A stub that rejected `/health` would test a gateway
/// that does not exist, and let a token check pass on the one that does.
fn spawn_gateway_stub(status: u16, requests: Arc<Mutex<Vec<String>>>) -> String {
    spawn_gateway_stub_with(status, None, requests)
}

/// [`spawn_gateway_stub`] with an explicit `/cluster` body.
fn spawn_gateway_stub_with(
    status: u16,
    cluster_body: Option<&'static str>,
    requests: Arc<Mutex<Vec<String>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || loop {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut buf = [0_u8; 8192];
                let mut n = 0;
                while !buf[..n].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if n == buf.len()
                        || remaining.is_zero()
                        || stream.set_read_timeout(Some(remaining)).is_err()
                    {
                        return;
                    }
                    match stream.read(&mut buf[n..]) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => n += read,
                    }
                }
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = request.lines().next().unwrap_or_default().to_string();
                requests.lock().expect("lock").push(first.clone());
                let body = if first.contains("/cluster") {
                    r#"{"mode":"cp","control_plane":null,"data_planes":[]}"#.to_string()
                } else {
                    r#"{"status":"ok","ready":true,"mode":"cp","admin_writes_enabled":true}"#
                        .to_string()
                };
                let status = if first.contains("/cluster") {
                    status
                } else {
                    200
                };
                let body = match (first.contains("/cluster"), cluster_body) {
                    (true, Some(custom)) => custom.to_string(),
                    _ if status == 200 => body,
                    _ => r#"{"error":"InvalidIssuer"}"#.to_string(),
                };
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    format!("http://{addr}")
}

fn stub_env(url: String) -> EnvConfig {
    EnvConfig {
        gateway_mode: GatewayMode::Api,
        gateway_url: Some(url),
        admin_jwt_secret: Some(SECRET.to_string()),
        allow_insecure_http: true,
        ..EnvConfig::default()
    }
}

#[tokio::test]
async fn the_gateway_scope_issues_reads_only() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_gateway_stub(200, Arc::clone(&requests));
    let checks = doctor::gateway::run("production", &stub_env(url), &[]).await;

    assert_eq!(find(&checks, "gateway-transport").status, Status::Pass);
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Pass);
    assert_eq!(find(&checks, "gateway-token").status, Status::Pass);
    assert_eq!(
        find(&checks, "gateway-reachable").environment.as_deref(),
        Some("production")
    );

    let seen = requests.lock().expect("lock").clone();
    assert!(!seen.is_empty(), "the stub saw no request");
    for line in &seen {
        assert!(line.starts_with("GET "), "non-read request: {line}");
    }
    // And only the diagnostic endpoints: /health, /cluster, and the
    // namespace listing the entity-tag probe starts from (this stub lists
    // none). Not /backup, and certainly not /restore or /batch.
    for line in &seen {
        assert!(
            line.contains("/health") || line.contains("/cluster") || line.contains("/namespaces"),
            "unexpected endpoint: {line}"
        );
    }
    // With no row to read, entity-tag support is unknown, never a pass.
    assert_eq!(
        find(&checks, "gateway-conditional-writes").status,
        Status::Unknown
    );
}

#[tokio::test]
async fn a_rejected_token_is_reported_with_the_claim_settings_to_compare() {
    // The most common "it worked on my laptop" failure: every local check
    // passes and the gateway answers 401 halfway through an apply.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_gateway_stub(401, Arc::clone(&requests));
    let mut env = stub_env(url);
    env.admin_jwt_issuer = "wrong-issuer".to_string();
    let checks = doctor::gateway::run("production", &env, &[]).await;

    // `/health` is unauthenticated, so reaching it proves nothing about the
    // token: the gateway is reachable AND rejects the token, and the report
    // must say both rather than letting the first stand in for the second.
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Pass);
    let token = find(&checks, "gateway-token");
    assert_eq!(token.status, Status::Fail);
    let remediation = token.remediation.as_ref().expect("remediation");
    assert!(remediation.contains("issuer=wrong-issuer"), "{remediation}");
    assert!(remediation.contains("audience=<unset>"), "{remediation}");
}

#[tokio::test]
async fn a_server_error_mentioning_401_is_not_a_rejected_token() {
    // The body (and, for transport errors, the URL) is part of the error text;
    // a `401`/`403` substring there says nothing about the token.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_gateway_stub_with(
        500,
        Some(r#"{"error":"upstream pool 4013 exhausted"}"#),
        Arc::clone(&requests),
    );
    let mut env = stub_env(url);
    env.gateway_max_retries = 0;
    let checks = doctor::gateway::run("production", &env, &[]).await;
    assert_eq!(find(&checks, "gateway-token").status, Status::Unknown);
}

#[tokio::test]
async fn an_accepted_token_with_an_unparseable_cluster_body_still_passes() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_gateway_stub_with(
        200,
        Some(r#"{"mode":"cp","data_planes":"three"}"#),
        Arc::clone(&requests),
    );
    let checks = doctor::gateway::run("production", &stub_env(url), &[]).await;
    let token = find(&checks, "gateway-token");
    assert_eq!(token.status, Status::Pass);
    assert!(
        token.detail.contains("cluster status unavailable"),
        "{}",
        token.detail
    );
}

#[tokio::test]
async fn an_unreachable_gateway_leaves_the_token_question_unknown() {
    let env = stub_env("http://127.0.0.1:1".to_string());
    let checks = doctor::gateway::run("production", &env, &[]).await;
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Fail);
    // Not attempted, and said so rather than silently missing from the report.
    assert_eq!(find(&checks, "gateway-token").status, Status::Unknown);
}

#[tokio::test]
async fn file_mode_skips_the_gateway_scope_rather_than_failing_it() {
    let env = EnvConfig {
        gateway_mode: GatewayMode::File,
        ..EnvConfig::default()
    };
    let checks = doctor::gateway::run("sandbox", &env, &[]).await;
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Skipped);
}

#[tokio::test]
async fn the_gateway_scope_without_credentials_is_unknown() {
    let checks = doctor::gateway::run("production", &api_env(), &[]).await;
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Unknown);
}

// -- namespace-scoped tokens (Ferrum Edge v0.9.16) --------------------------

type EdgeReply = (u16, &'static str);

/// A gateway that answers from `reply` and records each request's head
/// (request line and headers), so a test can read the token it carried.
fn spawn_edge_stub(
    reply: impl Fn(&str) -> EdgeReply + Send + Sync + 'static,
    requests: Arc<Mutex<Vec<String>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    let reply = Arc::new(reply);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let requests = Arc::clone(&requests);
            let reply = Arc::clone(&reply);
            std::thread::spawn(move || loop {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut buf = [0_u8; 8192];
                let mut n = 0;
                while !buf[..n].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if n == buf.len()
                        || remaining.is_zero()
                        || stream.set_read_timeout(Some(remaining)).is_err()
                    {
                        return;
                    }
                    match stream.read(&mut buf[n..]) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => n += read,
                    }
                }
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                requests.lock().expect("lock").push(request.clone());
                let (status, body) = reply(&request);
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    format!("http://{addr}")
}

/// The `ns` claim of the admin token a recorded request carried (`null` when
/// the token has none).
fn ns_claim(request: &str) -> serde_json::Value {
    use base64::Engine as _;
    let token = request
        .lines()
        .find_map(|line| line.strip_prefix("authorization: Bearer "))
        .expect("authorization header");
    let payload = token.split('.').nth(1).expect("JWT payload");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("JSON claims");
    claims["ns"].clone()
}

/// The detailed `/health` tier Ferrum Edge v0.9.15 serves any valid admin
/// JWT, `ns` claim or not (abridged).
const DETAILED_HEALTH: &str = r#"{"status":"ok","ready":true,"mode":"database","admin_writes_enabled":true,"cached_config":{"available":false}}"#;

/// Ferrum Edge v0.9.16's tenant `/health` tier for a token with an `ns`
/// claim: the write state and namespace block, nothing fleet-wide.
const TENANT_HEALTH: &str = r#"{"status":"ok","ready":true,"mode":"database","admin_writes_enabled":true,"namespace":{"active":"team-alpha","serving_scope":"single_namespace_data_plane","data_plane_single_namespace":true}}"#;

/// Ferrum Edge v0.9.16's answer to a token with an `ns` claim on a
/// fleet-global route.
const FLEET_GLOBAL_REFUSAL: &str = r#"{"error":"global route '/cluster' is unavailable to admin JWTs with an `ns` claim; fleet-global routes require a token without one"}"#;

fn has(checks: &[Check], id: &str) -> bool {
    checks.iter().any(|check| check.id == id)
}

fn scoped_env(url: String) -> EnvConfig {
    EnvConfig {
        namespace_filter: Some("team-alpha".to_string()),
        gateway_max_retries: 0,
        ..stub_env(url)
    }
}

/// The `ns` claim a run of [`scoped_env`] mints: its namespace filter.
fn team_alpha() -> Vec<String> {
    vec!["team-alpha".to_string()]
}

#[tokio::test]
async fn a_namespace_scoped_token_refused_on_cluster_is_proven_on_namespaces() {
    // Edge v0.9.16 refuses every fleet-global route, /cluster included, to a
    // token with an `ns` claim. That refusal is expected: the token is proven
    // on GET /namespaces, which stays open to it, and the cluster view is
    // skipped with its reason rather than failed.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_edge_stub(
        |request| {
            if request.starts_with("GET /health") {
                (200, TENANT_HEALTH)
            } else if request.starts_with("GET /cluster") {
                if ns_claim(request).is_null() {
                    (200, r#"{"mode":"database","message":"no cluster"}"#)
                } else {
                    (403, FLEET_GLOBAL_REFUSAL)
                }
            } else if request.starts_with("GET /namespaces") {
                (200, r#"{"data":["team-alpha"],"pagination":{"total":1}}"#)
            } else {
                (404, r#"{"error":"not found"}"#)
            }
        },
        Arc::clone(&requests),
    );
    let checks = doctor::gateway::run("production", &scoped_env(url), &team_alpha()).await;

    assert_eq!(find(&checks, "gateway-reachable").status, Status::Pass);
    let token = find(&checks, "gateway-token");
    assert_eq!(token.status, Status::Pass, "{token:?}");
    assert!(token.detail.contains("GET /namespaces"));
    let cluster = find(&checks, "gateway-cluster-view");
    assert_eq!(cluster.status, Status::Skipped);
    assert!(
        cluster.detail.contains("namespace-scoped credential"),
        "{}",
        cluster.detail
    );
    let remediation = cluster.remediation.as_deref().expect("remediation");
    assert!(remediation.contains("v0.9.16"), "{remediation}");
    assert_eq!(cluster.environment.as_deref(), Some("production"));
    // The tenant tier reports the write state, so nothing is unknown there.
    assert!(!has(&checks, "gateway-writable"));
    assert!(checks.iter().all(|check| check.status != Status::Fail));

    // Every request carried the environment's namespace-scoped token, and
    // every one was a read.
    let seen = requests.lock().expect("lock").clone();
    assert!(seen.iter().any(|line| line.starts_with("GET /cluster")));
    for request in &seen {
        assert!(request.starts_with("GET "), "non-read request: {request}");
        assert_eq!(ns_claim(request), serde_json::json!(["team-alpha"]));
    }
}

#[tokio::test]
async fn a_full_cluster_view_is_kept_when_the_scoped_token_can_read_it() {
    // Through Edge v0.9.15 a token with an `ns` claim still reads /cluster;
    // the convergence detail stays in the token check.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_edge_stub(
        |request| {
            if request.starts_with("GET /cluster") {
                (200, r#"{"mode":"database","message":"no cluster"}"#)
            } else if request.starts_with("GET /health") {
                (200, DETAILED_HEALTH)
            } else {
                (200, r#"{"data":[]}"#)
            }
        },
        Arc::clone(&requests),
    );
    let checks = doctor::gateway::run("production", &scoped_env(url), &team_alpha()).await;
    let token = find(&checks, "gateway-token");
    assert_eq!(token.status, Status::Pass);
    assert!(
        token.detail.contains("convergence: mode=database"),
        "{}",
        token.detail
    );
    assert!(!has(&checks, "gateway-cluster-view"));
}

#[tokio::test]
async fn a_namespace_scoped_token_rejected_on_namespaces_too_is_a_rejected_token() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_edge_stub(
        |request| {
            if request.starts_with("GET /health") {
                (200, TENANT_HEALTH)
            } else if request.starts_with("GET /cluster") {
                (403, FLEET_GLOBAL_REFUSAL)
            } else {
                (401, r#"{"error":"InvalidSignature"}"#)
            }
        },
        Arc::clone(&requests),
    );
    let checks = doctor::gateway::run("production", &scoped_env(url), &team_alpha()).await;
    let token = find(&checks, "gateway-token");
    assert_eq!(token.status, Status::Fail);
    let remediation = token.remediation.as_deref().expect("remediation");
    assert!(remediation.contains("issuer="), "{remediation}");
    // The cluster view is not excused when the token itself is not proven.
    assert!(!has(&checks, "gateway-cluster-view"));
}

#[tokio::test]
async fn a_cluster_refusal_of_a_token_without_an_ns_claim_is_still_a_rejected_token() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_edge_stub(
        |request| {
            if request.starts_with("GET /cluster") {
                (403, r#"{"error":"forbidden"}"#)
            } else if request.starts_with("GET /health") {
                (200, TENANT_HEALTH)
            } else {
                (200, r#"{"data":[]}"#)
            }
        },
        Arc::clone(&requests),
    );
    let mut env = scoped_env(url);
    env.namespace_filter = None;
    let checks = doctor::gateway::run("production", &env, &[]).await;
    assert_eq!(find(&checks, "gateway-token").status, Status::Fail);
    assert!(!has(&checks, "gateway-cluster-view"));
    let seen = requests.lock().expect("lock").clone();
    assert!(seen.iter().all(|request| ns_claim(request).is_null()));
}

#[tokio::test]
async fn a_minimal_health_tier_leaves_the_write_state_unknown() {
    // A namespace-scoped token on a gateway without the tenant tier gets only
    // `status` and `ready`. That is not evidence the plane is writable.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_edge_stub(
        |request| {
            if request.starts_with("GET /health") {
                (200, r#"{"status":"ok","ready":true}"#)
            } else if request.starts_with("GET /cluster") {
                (403, FLEET_GLOBAL_REFUSAL)
            } else {
                (200, r#"{"data":[]}"#)
            }
        },
        Arc::clone(&requests),
    );
    let checks = doctor::gateway::run("production", &scoped_env(url), &team_alpha()).await;
    let reachable = find(&checks, "gateway-reachable");
    assert_eq!(reachable.status, Status::Pass);
    assert!(
        reachable.detail.contains("admin_writes_enabled=unknown"),
        "{}",
        reachable.detail
    );
    let writable = find(&checks, "gateway-writable");
    assert_eq!(writable.status, Status::Unknown);
    let remediation = writable.remediation.as_deref().expect("remediation");
    assert!(remediation.contains("`ns` claim"), "{remediation}");
    assert!(remediation.contains("tenant"), "{remediation}");
    assert!(checks.iter().all(|check| check.status != Status::Fail));
}

// -- doctor probes with the token the environment's runs mint --------------

/// An environment-file environment with no namespace filter, shared mode.
const UNFILTERED_SHARED: &str = r#"
version: 1
environments:
  production:
    ownership:
      mode: shared
"#;

/// An environment-file environment with no namespace filter, exclusive mode.
const UNFILTERED_EXCLUSIVE: &str = r#"
version: 1
environments:
  production:
    ownership:
      mode: exclusive
      namespaces: [team-alpha, team-beta]
"#;

/// The namespaces a run of the one environment in `config_yaml` claims,
/// resolved as `cmd_doctor` and `apply` resolve them: the environment comes
/// from the environment file (no `FERRUM_NAMESPACE`), and the claim from
/// `resolved_namespaces` over the desired configuration and the state ledger.
fn run_token_namespaces(config_yaml: &str, env: &EnvConfig, state: &StateFile) -> Vec<String> {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, config_yaml).expect("write config");
    let repo = RepoConfig::load_from_path(&path).unwrap().unwrap();
    let resolved = resolve_env(Some(&repo), env, None).unwrap();
    assert_eq!(resolved.name, "production");
    assert_eq!(
        resolved.namespace_filter, None,
        "the environment has no filter"
    );
    resolved_namespaces(&resolved, &GatewayConfig::default(), state)
}

#[tokio::test]
async fn an_unfiltered_shared_environment_is_probed_with_the_namespaces_its_runs_claim() {
    // Without a namespace filter, a shared-mode run still mints an `ns` claim:
    // every declared and previously managed namespace. Doctor must probe with
    // that token, not a claim-less fleet-global one, or a gateway that bounds
    // `ns` tokens passes doctor and then refuses the environment's runs.
    let mut state = StateFile::default();
    for ns in ["team-beta", "team-alpha"] {
        let key = state_key(ns, "Proxy", "orders");
        state.resources.insert(key, "managed".to_string());
    }
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_edge_stub(
        |request| {
            if request.starts_with("GET /health") {
                (200, TENANT_HEALTH)
            } else if request.starts_with("GET /cluster") {
                if ns_claim(request).is_null() {
                    (200, r#"{"mode":"database","message":"no cluster"}"#)
                } else {
                    (403, FLEET_GLOBAL_REFUSAL)
                }
            } else if request.starts_with("GET /namespaces") {
                (200, r#"{"data":["team-alpha","team-beta"]}"#)
            } else {
                (404, r#"{"error":"not found"}"#)
            }
        },
        Arc::clone(&requests),
    );
    let env = EnvConfig {
        gateway_max_retries: 0,
        ..stub_env(url)
    };
    let namespaces = run_token_namespaces(UNFILTERED_SHARED, &env, &state);
    assert_eq!(namespaces, ["team-alpha", "team-beta"]);

    let checks = doctor::gateway::run("production", &env, &namespaces).await;
    // A claim-less token would have read /cluster. The run's token is refused
    // it and proven on /namespaces, as the environment's runs would be.
    assert_eq!(find(&checks, "gateway-token").status, Status::Pass);
    let cluster = find(&checks, "gateway-cluster-view");
    assert_eq!(cluster.status, Status::Skipped);
    let seen = requests.lock().expect("lock").clone();
    assert!(seen.iter().any(|line| line.starts_with("GET /cluster")));
    let claim = serde_json::json!(["team-alpha", "team-beta"]);
    for request in &seen {
        assert_eq!(ns_claim(request), claim);
    }
}

#[test]
fn an_unfiltered_exclusive_environment_claims_its_owned_namespaces() {
    let state = StateFile::default();
    let namespaces = run_token_namespaces(UNFILTERED_EXCLUSIVE, &api_env(), &state);
    assert_eq!(namespaces, ["team-alpha", "team-beta"]);
}

// -- no secret value is ever printed ---------------------------------------

#[tokio::test]
async fn no_rendered_output_contains_a_credential_value() {
    let dir = repo(&[
        (
            ".gitforgeops/config.yaml",
            "version: 1\nenvironments:\n  production: {}\n",
        ),
        (".github/ferrum-edge-checksums.txt", "abc  ferrum-edge\n"),
    ]);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_gateway_stub(401, Arc::clone(&requests));
    let env = stub_env(url);

    let mut report = Report::default();
    report.extend(doctor::local::run(dir.path(), Some(&env)));
    report.extend(doctor::gateway::run("production", &env, &[]).await);

    let text = report.render_text();
    let json = gitforgeops::json_output::pretty(&report).expect("json");
    for rendered in [&text, &json] {
        assert!(!rendered.contains(SECRET), "a secret value was printed");
    }
    // Presence is still reported — by name, and labelled as presence only.
    assert!(text.contains("FERRUM_ADMIN_JWT_SECRET is set"), "{text}");
    assert!(
        text.contains("presence is proven by the gateway checks") || text.contains("presence only")
    );
}

// -- report semantics ------------------------------------------------------

#[test]
fn only_a_failure_blocks_and_the_exit_code_is_distinct_from_a_crash() {
    for status in [Status::Pass, Status::Warn, Status::Unknown, Status::Skipped] {
        let mut report = Report::default();
        report.push(Check::new("x", "X", Scope::Local, status, "detail"));
        assert!(report.is_ready(), "{status:?} must not block");
        assert_eq!(report.exit_code(), 0);
    }
    let mut report = Report::default();
    report.push(Check::new("x", "X", Scope::Local, Status::Fail, "detail"));
    assert!(!report.is_ready());
    // 3, not 1: "diagnosed, and the answer is no" is not "the diagnosis
    // itself failed".
    assert_eq!(report.exit_code(), doctor::DOCTOR_FAILED_EXIT_CODE);
    assert_ne!(doctor::DOCTOR_FAILED_EXIT_CODE, 1);
}

#[test]
fn the_json_report_carries_status_scope_environment_and_remediation() {
    let mut report = Report::default();
    report.push(
        Check::new("x", "X", Scope::Gateway, Status::Fail, "detail")
            .for_environment("production")
            .remedy("do the thing"),
    );
    let json: serde_json::Value =
        serde_json::from_str(&gitforgeops::json_output::pretty(&report).expect("json"))
            .expect("parse");
    let check = &json["checks"][0];
    assert_eq!(check["id"], "x");
    assert_eq!(check["status"], "fail");
    assert_eq!(check["scope"], "gateway");
    assert_eq!(check["environment"], "production");
    assert_eq!(check["remediation"], "do the thing");
}

#[test]
fn a_control_character_in_a_detail_cannot_forge_a_workflow_command() {
    let mut report = Report::default();
    report.push(Check::new(
        "x",
        "X",
        Scope::Local,
        Status::Fail,
        "first\n::error::forged",
    ));
    let rendered = report.render_text();
    assert!(!rendered.contains("\n::error::forged"), "{rendered}");
}
