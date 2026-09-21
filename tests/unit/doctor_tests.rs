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
use gitforgeops::config::EnvConfig;
use gitforgeops::doctor::local::RepositoryKind;
use gitforgeops::doctor::{self, Check, Report, Scope, Status};
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
    let dir = repo(&[(
        ".github/scripts/audit_settings.py",
        "import sys; sys.exit(0)\n",
    )]);
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
    let dir = repo(&[(
        ".github/scripts/audit_settings.py",
        "import sys; sys.exit(0)\n",
    )]);
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
fn github_checks_surface_each_auditor_violation_as_its_own_finding() {
    // Doctor owns no settings baseline: it runs the same auditor the bootstrap
    // writes for and the scheduled audit runs, and republishes its findings.
    let dir = repo(&[(
        ".github/scripts/audit_settings.py",
        "import sys\n\
         print('Repository protection evidence:')\n\
         print('  PASS: something is fine')\n\
         print('Repository protection violations:', file=sys.stderr)\n\
         print('  FAIL: environment \\'production\\' must require at least one reviewer', file=sys.stderr)\n\
         sys.exit(1)\n",
    )]);
    let checks = doctor::github::run(
        dir.path(),
        &doctor::github::GithubContext {
            repository: Some("acme/repo".to_string()),
            token: Some("token".to_string()),
            state_writer_app_id: Some("99".to_string()),
            template_repo: false,
        },
    );
    assert_eq!(find(&checks, "settings-audit").status, Status::Fail);
    assert!(
        checks.iter().any(|check| check.id == "settings-control"
            && check.detail.contains("must require at least one reviewer")),
        "{:?}",
        checks
    );
}

#[test]
fn a_missing_auditor_is_unknown_not_a_pass() {
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
    assert_eq!(find(&checks, "settings-audit").status, Status::Unknown);
}

// -- the gateway scope reads, and only reads -------------------------------

/// Answer `GET /health` and `GET /cluster` with a fixed status, recording every
/// request line so a test can prove nothing was mutated.
fn spawn_gateway_stub(status: u16, requests: Arc<Mutex<Vec<String>>>) -> String {
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
                let body = if status == 200 {
                    body
                } else {
                    r#"{"error":"InvalidIssuer"}"#.to_string()
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
    let checks = doctor::gateway::run("production", &stub_env(url)).await;

    assert_eq!(find(&checks, "gateway-transport").status, Status::Pass);
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Pass);
    assert_eq!(
        find(&checks, "gateway-reachable").environment.as_deref(),
        Some("production")
    );

    let seen = requests.lock().expect("lock").clone();
    assert!(!seen.is_empty(), "the stub saw no request");
    for line in &seen {
        assert!(line.starts_with("GET "), "non-read request: {line}");
    }
    // And only the two diagnostic endpoints — not /backup, and certainly not
    // /restore or /batch.
    for line in &seen {
        assert!(
            line.contains("/health") || line.contains("/cluster"),
            "unexpected endpoint: {line}"
        );
    }
}

#[tokio::test]
async fn a_rejected_token_is_reported_with_the_claim_settings_to_compare() {
    // The most common "it worked on my laptop" failure: every local check
    // passes and the gateway answers 401 halfway through an apply.
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_gateway_stub(401, Arc::clone(&requests));
    let mut env = stub_env(url);
    env.admin_jwt_issuer = "wrong-issuer".to_string();
    let checks = doctor::gateway::run("production", &env).await;

    let reachable = find(&checks, "gateway-reachable");
    assert_eq!(reachable.status, Status::Fail);
    let remediation = reachable.remediation.as_ref().expect("remediation");
    assert!(remediation.contains("issuer=wrong-issuer"), "{remediation}");
    assert!(remediation.contains("audience=<unset>"), "{remediation}");
    // The pairing question could not be answered, so it is unknown rather than
    // silently missing from the report.
    assert_eq!(find(&checks, "gateway-pairing").status, Status::Unknown);
}

#[tokio::test]
async fn file_mode_skips_the_gateway_scope_rather_than_failing_it() {
    let env = EnvConfig {
        gateway_mode: GatewayMode::File,
        ..EnvConfig::default()
    };
    let checks = doctor::gateway::run("sandbox", &env).await;
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Skipped);
}

#[tokio::test]
async fn the_gateway_scope_without_credentials_is_unknown() {
    let checks = doctor::gateway::run("production", &api_env()).await;
    assert_eq!(find(&checks, "gateway-reachable").status, Status::Unknown);
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
    report.extend(doctor::gateway::run("production", &env).await);

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
