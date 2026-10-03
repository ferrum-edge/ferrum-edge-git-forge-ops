//! `verify`'s exit codes, end to end.
//!
//! A deployment job decides pass, skip or fail from the process status alone,
//! so these run the real binary. An environment with no declared check has
//! not failed verification, and it has not passed it either: it exits
//! `VERIFY_SKIPPED_EXIT_CODE`, which the workflow records as `skipped`. Only a
//! check that ran and failed (4) or a `verify` that could not run (1) fails
//! the job.
//!
//! Hermetic: the child inherits only the variables named here, and the data
//! plane is a loopback socket.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::Duration;

use gitforgeops::verify::{VERIFY_FAILED_EXIT_CODE, VERIFY_PROBE_LABEL, VERIFY_SKIPPED_EXIT_CODE};
use tempfile::TempDir;

/// Checks for `staging` only, the way the shipped example leaves out
/// `production`.
const STAGING_ONLY: &str = r#"version: 1
environments:
  staging:
    checks:
      - name: orders route answers
        path: /orders/healthz
        expect_status: 200
        attempts: 1
        timeout_secs: 5
"#;

/// `production` is present and lists nothing.
const PRODUCTION_EMPTY: &str = "version: 1\nenvironments:\n  production:\n    checks: []\n";

/// A key the closed schema does not know: a load error.
const PRODUCTION_UNPARSABLE: &str = "version: 1\nenvironments:\n  production:\n    run: ./x\n";

const PRODUCTION: &[(&str, &str)] = &[("FERRUM_ENV", "production")];

fn repo(smoke: Option<&str>) -> TempDir {
    let dir = TempDir::new().expect("repo tempdir");
    if let Some(smoke) = smoke {
        let gitforgeops = dir.path().join(".gitforgeops");
        std::fs::create_dir_all(&gitforgeops).expect("create .gitforgeops");
        std::fs::write(gitforgeops.join("smoke.yaml"), smoke).expect("write smoke.yaml");
    }
    dir
}

fn verify(dir: &TempDir, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
    command
        .arg("verify")
        .args(args)
        .current_dir(dir.path())
        .env_clear();
    for name in ["PATH", "HOME", "TMPDIR"] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    // Keep coverage profiles outside the repository, preserving the hosted
    // collector's destination despite env_clear().
    let profile_dir = TempDir::new().expect("profile tempdir");
    let profile_path = std::env::var_os("LLVM_PROFILE_FILE")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| profile_dir.path().join("default_%m_%p.profraw"));
    let profile_path = std::env::current_dir()
        .expect("test working directory")
        .join(profile_path);
    command.env("LLVM_PROFILE_FILE", profile_path);
    command.envs(env.iter().copied());
    command.output().expect("run gitforgeops verify")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A loopback data plane that answers one request with `status`.
fn data_plane(status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind data plane");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            // The whole request head, so the answer never races the write.
            let mut request: Vec<u8> = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let response =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
        }
    });
    url
}

/// A loopback address nothing is listening on.
fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    drop(listener);
    url
}

#[test]
fn an_environment_with_no_declared_check_is_skipped_not_failed() {
    let dir = repo(Some(STAGING_ONLY));
    // No data-plane URL either: with nothing to check, nothing needs one.
    let output = verify(&dir, &[], PRODUCTION);
    assert_eq!(
        output.status.code(),
        Some(VERIFY_SKIPPED_EXIT_CODE),
        "{output:?}"
    );
    let text = stdout(&output);
    assert!(
        text.contains("skipped: no smoke checks declared for production"),
        "{text}"
    );
    assert!(text.contains("not a pass"), "{text}");
}

#[test]
fn an_empty_checks_list_is_the_same_skip() {
    let dir = repo(Some(PRODUCTION_EMPTY));
    let output = verify(&dir, &[], PRODUCTION);
    assert_eq!(
        output.status.code(),
        Some(VERIFY_SKIPPED_EXIT_CODE),
        "{output:?}"
    );
}

#[test]
fn an_absent_smoke_file_is_the_same_skip() {
    let dir = repo(None);
    let output = verify(&dir, &[], PRODUCTION);
    assert_eq!(
        output.status.code(),
        Some(VERIFY_SKIPPED_EXIT_CODE),
        "{output:?}"
    );
}

#[test]
fn a_skip_says_so_in_json() {
    let dir = repo(Some(STAGING_ONLY));
    let output = verify(&dir, &["--format", "json"], PRODUCTION);
    assert_eq!(
        output.status.code(),
        Some(VERIFY_SKIPPED_EXIT_CODE),
        "{output:?}"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["environment"], "production");
    assert_eq!(report["status"], "skipped");
    assert_eq!(report["results"], serde_json::json!([]));
}

#[test]
fn an_unparsable_smoke_file_is_an_error_not_a_skip() {
    let dir = repo(Some(PRODUCTION_UNPARSABLE));
    let output = verify(&dir, &[], PRODUCTION);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn declared_checks_without_a_data_plane_url_are_an_error_not_a_skip() {
    let dir = repo(Some(STAGING_ONLY));
    let output = verify(&dir, &[], &[("FERRUM_ENV", "staging")]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn a_declared_check_that_fails_exits_with_the_failure_code() {
    let dir = repo(Some(STAGING_ONLY));
    let url = closed_port();
    let output = verify(
        &dir,
        &["--format", "json"],
        &[
            ("FERRUM_ENV", "staging"),
            ("FERRUM_VERIFY_BASE_URL", url.as_str()),
            ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(VERIFY_FAILED_EXIT_CODE),
        "{output:?}"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["status"], "failed");
}

#[test]
fn a_declared_check_that_passes_exits_zero() {
    let dir = repo(Some(STAGING_ONLY));
    let url = data_plane(200);
    let output = verify(
        &dir,
        &["--format", "json"],
        &[
            ("FERRUM_ENV", "staging"),
            ("FERRUM_VERIFY_BASE_URL", url.as_str()),
            ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["status"], "passed");
}

// -- probe credentials (GHSA-8mhw-ghx8-9m63) ----------------------------------

/// A check that sends the probe Consumer's key.
const STAGING_PROBE: &str = r#"version: 1
environments:
  staging:
    checks:
      - name: orders route serves authenticated traffic
        path: /orders/healthz
        headers:
          X-API-Key:
            slot: ferrum/orders-probe/keyauth/key
        expect_status: 200
        attempts: 1
        timeout_secs: 5
"#;

/// The same check, naming a customer's key instead.
const STAGING_CUSTOMER: &str = r#"version: 1
environments:
  staging:
    checks:
      - name: orders route serves authenticated traffic
        path: /orders/healthz
        headers:
          X-API-Key:
            slot: ferrum/orders-client/keyauth/key
        expect_status: 200
        attempts: 1
        timeout_secs: 5
"#;

const PROBE_VALUE: &str = "probe-value-0001";
const CUSTOMER_VALUE: &str = "customer-value-0002";

/// The finalized bundle the apply hands `verify`: both Consumers' keys.
fn bundle_json() -> String {
    serde_json::json!({
        "FERRUM_CREDS_BUNDLE": {
            "ferrum/orders-probe/keyauth/key": PROBE_VALUE,
            "ferrum/orders-client/keyauth/key": CUSTOMER_VALUE,
        }
    })
    .to_string()
}

/// A repository declaring `smoke` and two Consumers: `orders-probe`, labelled
/// as the verification probe when `labelled`, and the customer
/// `orders-client`, never labelled.
fn repo_with_consumers(smoke: &str, labelled: bool) -> TempDir {
    let dir = repo(Some(smoke));
    let consumers = dir.path().join("resources/ferrum/consumers");
    std::fs::create_dir_all(&consumers).expect("create consumers");
    let labels = if labelled {
        format!("  labels:\n    {VERIFY_PROBE_LABEL}: \"true\"\n")
    } else {
        String::new()
    };
    let probe = format!(
        "kind: Consumer\nspec:\n  id: orders-probe\n  username: orders-probe\n{labels}\
         \n  credentials:\n    keyauth:\n      - key: \"${{gh-env-secret:alloc=require}}\"\n"
    );
    std::fs::write(consumers.join("orders-probe.yaml"), probe).expect("write probe");
    let customer = "kind: Consumer\nspec:\n  id: orders-client\n  username: orders-client\n\
         \n  credentials:\n    keyauth:\n      - key: \"${gh-env-secret:alloc=require}\"\n";
    std::fs::write(consumers.join("orders-client.yaml"), customer).expect("write customer");
    dir
}

/// A non-blocking listener nothing answers on, and its URL.
fn silent_data_plane() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind data plane");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    (listener, url)
}

/// Did anything connect to `listener`? It is non-blocking, so a pending
/// connection is accepted and an empty backlog is `WouldBlock`.
fn connected(listener: &TcpListener) -> bool {
    match listener.accept() {
        Ok(_) => true,
        Err(error) => error.kind() != ErrorKind::WouldBlock,
    }
}

/// A loopback data plane that answers 200 only when the request carries the
/// probe key, and 401 otherwise.
fn probe_data_plane() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind data plane");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut request: Vec<u8> = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            let status = if head.contains(&format!("x-api-key: {PROBE_VALUE}")) {
                200
            } else {
                401
            };
            let response =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
        }
    });
    url
}

#[test]
fn a_customer_credential_refuses_the_run_before_any_request() {
    // The customer's key is in the bundle the job holds. Naming it in a
    // smoke check must not send it anywhere.
    let dir = repo_with_consumers(STAGING_CUSTOMER, true);
    let (listener, url) = silent_data_plane();
    let bundle = bundle_json();
    let output = verify(
        &dir,
        &[],
        &[
            ("FERRUM_ENV", "staging"),
            ("FERRUM_VERIFY_BASE_URL", url.as_str()),
            ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
            ("FERRUM_CREDS_JSON", bundle.as_str()),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ferrum/orders-client/keyauth/key"), "{stderr}");
    assert!(stderr.contains(VERIFY_PROBE_LABEL), "{stderr}");
    for value in [PROBE_VALUE, CUSTOMER_VALUE] {
        assert!(
            !stderr.contains(value) && !stdout(&output).contains(value),
            "verify must never print a bundle value"
        );
    }
    // Nothing connected: the refusal came before any request.
    assert!(!connected(&listener), "verify reached the data plane");
}

#[test]
fn an_unlabelled_consumer_is_not_a_probe() {
    let dir = repo_with_consumers(STAGING_PROBE, false);
    let (listener, url) = silent_data_plane();
    let bundle = bundle_json();
    let output = verify(
        &dir,
        &[],
        &[
            ("FERRUM_ENV", "staging"),
            ("FERRUM_VERIFY_BASE_URL", url.as_str()),
            ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
            ("FERRUM_CREDS_JSON", bundle.as_str()),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!connected(&listener), "verify reached the data plane");
}

#[test]
fn a_labelled_probe_credential_is_sent_and_verifies() {
    let dir = repo_with_consumers(STAGING_PROBE, true);
    let url = probe_data_plane();
    let bundle = bundle_json();
    let output = verify(
        &dir,
        &["--format", "json"],
        &[
            ("FERRUM_ENV", "staging"),
            ("FERRUM_VERIFY_BASE_URL", url.as_str()),
            ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
            ("FERRUM_CREDS_JSON", bundle.as_str()),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json report");
    assert_eq!(report["status"], "passed");
}

// -- budgets (GHSA-p95x-q89j-hrhv) -------------------------------------------

#[test]
fn an_over_budget_smoke_file_is_an_error_before_any_request() {
    let dir = repo(Some(
        "version: 1\nenvironments:\n  staging:\n    checks:\n      - name: forever\n\
         \n        path: /orders/healthz\n        expect_status: 200\n\
         \n        attempts: 1000000\n",
    ));
    let (listener, url) = silent_data_plane();
    let output = verify(
        &dir,
        &[],
        &[
            ("FERRUM_ENV", "staging"),
            ("FERRUM_VERIFY_BASE_URL", url.as_str()),
            ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("above the maximum"), "{stderr}");
    assert!(!connected(&listener), "verify reached the data plane");
}
