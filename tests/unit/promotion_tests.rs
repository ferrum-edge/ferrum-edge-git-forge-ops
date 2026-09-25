//! Staged promotion: the configuration half and the verification half.
//!
//! The property that matters is that a promotion is *authorized* rather than
//! merely *ordered*. Two jobs running in sequence prove nothing about what is
//! running; an apply that succeeded and a gateway that was shown to serve the
//! same source revision do. These tests pin the pieces the binary owns —
//! chain validation, the declarative check contract, and the fail-closed rules
//! that stop "we did not verify" from reading as "verified".

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gitforgeops::config::repo_config::RepoConfig;
use gitforgeops::verify::runner::run_check;
use gitforgeops::verify::{
    is_idempotent_method, resolve_headers, HeaderValue, Outcome, SmokeCheck, SmokeConfig,
    VerifyReport, SMOKE_CONFIG_VERSION, VERIFY_FAILED_EXIT_CODE,
};
use tempfile::NamedTempFile;

fn write_yaml(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("tempfile");
    file.write_all(contents.as_bytes()).expect("write");
    file.flush().expect("flush");
    file
}

fn load_repo(contents: &str) -> Result<RepoConfig, String> {
    let file = write_yaml(contents);
    RepoConfig::load_from_path(file.path())
        .map(|config| config.expect("config present"))
        .map_err(|error| error.to_string())
}

fn load_smoke(contents: &str) -> Result<SmokeConfig, String> {
    let file = write_yaml(contents);
    SmokeConfig::load_from_path(file.path())
        .map(|config| config.expect("config present"))
        .map_err(|error| error.to_string())
}

// -- the chain --------------------------------------------------------------

#[test]
fn an_environment_without_requires_stays_in_the_parallel_matrix() {
    // Independent deployment is the default and must remain untouched:
    // `apply-on-merge.yml` splits its matrix on exactly this field being null.
    let config =
        load_repo("version: 1\nenvironments:\n  staging: {}\n  production: {}\n").expect("loads");
    for scope in config.environment_scopes() {
        assert_eq!(scope.promotion_requires, None, "{scope:?}");
    }
}

#[test]
fn requires_names_the_predecessor_for_the_promotion_matrix() {
    let config = load_repo(
        "version: 1\nenvironments:\n  staging: {}\n  production:\n    promotion:\n      requires: staging\n",
    )
    .expect("loads");
    let scopes = config.environment_scopes();
    let production = scopes
        .iter()
        .find(|scope| scope.environment == "production")
        .expect("production");
    assert_eq!(production.promotion_requires.as_deref(), Some("staging"));
    let staging = scopes
        .iter()
        .find(|scope| scope.environment == "staging")
        .expect("staging");
    assert_eq!(staging.promotion_requires, None);
}

#[test]
fn a_promotion_that_names_a_missing_environment_is_refused_at_load() {
    // It would emit a matrix entry waiting on a predecessor no job will ever
    // produce a record for — a deployment that hangs instead of failing.
    let error = load_repo(
        "version: 1\nenvironments:\n  production:\n    promotion:\n      requires: staging\n",
    )
    .expect_err("must refuse");
    assert!(error.contains("not a declared environment"), "{error}");
}

#[test]
fn a_self_referencing_promotion_is_refused() {
    let error = load_repo(
        "version: 1\nenvironments:\n  production:\n    promotion:\n      requires: production\n",
    )
    .expect_err("must refuse");
    assert!(error.contains("names itself"), "{error}");
}

#[test]
fn a_promotion_cycle_is_refused_at_load() {
    // Every environment in a cycle waits for another that is waiting for it.
    // Nothing deploys, and nothing says why.
    let error = load_repo(
        "version: 1\nenvironments:\n  a:\n    promotion:\n      requires: b\n\
         \n  b:\n    promotion:\n      requires: c\n  c:\n    promotion:\n      requires: a\n",
    )
    .expect_err("must refuse");
    assert!(error.contains("cycle"), "{error}");
}

#[test]
fn a_chain_deeper_than_one_stage_is_refused_at_load() {
    // The workflow runs every promoted environment in one parallel phase, so
    // `production` would look for `staging`'s record while `staging` is still
    // running — and refuse on every merge. Loading would be the lie.
    let error = load_repo(
        "version: 1\nenvironments:\n  dev: {}\n  staging:\n    promotion:\n      requires: dev\n\
         \n  production:\n    promotion:\n      requires: staging\n",
    )
    .expect_err("must refuse");
    assert!(error.contains("one stage deep"), "{error}");
    assert!(error.contains("'production'"), "{error}");
}

#[test]
fn several_environments_may_share_one_independent_predecessor() {
    let config = load_repo(
        "version: 1\nenvironments:\n  staging: {}\n  production:\n    promotion:\n      requires: staging\n\
         \n  dr:\n    promotion:\n      requires: staging\n",
    )
    .expect("loads");
    assert_eq!(config.environment_scopes().len(), 3);
}

// -- the declarative check contract -----------------------------------------

#[test]
fn smoke_checks_are_data_with_no_execution_surface() {
    // The closed schema IS the security control: this job runs with the
    // environment's deployment credentials, so a `run:`/`command:`/`script:`
    // key must not be silently accepted.
    for key in ["command", "run", "script", "exec"] {
        let error = load_smoke(&format!(
            "version: 1\nenvironments:\n  staging:\n    checks:\n      - name: x\n\
             \n        path: /x\n        expect_status: 200\n        {key}: 'rm -rf /'\n"
        ))
        .expect_err("must refuse");
        assert!(error.contains(key), "{key}: {error}");
    }
}

#[test]
fn a_check_declares_the_status_it_expects() {
    let config = load_smoke(
        "version: 1\nenvironments:\n  staging:\n    checks:\n\
         \n      - name: authenticated\n        path: /orders\n        expect_status: 200\n\
         \n        headers:\n          X-API-Key:\n            slot: ferrum/c/keyauth/key\n\
         \n      - name: unauthenticated is rejected\n        path: /orders\n        expect_status: 401\n",
    )
    .expect("loads");
    let checks = &config.for_environment("staging").expect("staging").checks;
    assert_eq!(checks.len(), 2);
    // Expecting a 401 is how "authentication is enforced" is stated, as
    // opposed to "an auth plugin exists in the document".
    assert_eq!(checks[1].expect_status, 401);
    assert_eq!(checks[0].method, "GET");
    assert_eq!(
        checks[0].headers.get("X-API-Key"),
        Some(&HeaderValue::slot("ferrum/c/keyauth/key"))
    );
}

#[test]
fn malformed_checks_are_refused_at_load_not_at_promotion_time() {
    for (fragment, expected) in [
        ("        path: orders\n        expect_status: 200\n", "must start with '/'"),
        ("        path: /orders\n        expect_status: 99\n", "not an HTTP status"),
        (
            "        path: /orders\n        expect_status: 200\n        attempts: 0\n",
            "attempts must be at least 1",
        ),
        (
            "        path: /orders\n        expect_status: 200\n        timeout_secs: 0\n",
            "timeout_secs must be at least 1",
        ),
        (
            "        path: /orders\n        expect_status: 200\n        method: 'GET /admin HTTP/1.1'\n",
            "not an HTTP method",
        ),
    ] {
        let error = load_smoke(&format!(
            "version: 1\nenvironments:\n  staging:\n    checks:\n      - name: x\n{fragment}"
        ))
        .expect_err("must refuse");
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn an_unsupported_smoke_version_is_refused() {
    let error = load_smoke("version: 2\nenvironments: {}\n").expect_err("must refuse");
    assert!(
        error.contains("unsupported smoke-check config version"),
        "{error}"
    );
    assert_eq!(SMOKE_CONFIG_VERSION, 1);
}

// -- header values: literal or slot, never guessed --------------------------

#[test]
fn a_header_must_name_exactly_one_source() {
    // "Neither" would send nothing and "both" would hide which value the
    // request actually carried. A schema that merely accepts either shape is
    // silent about both mistakes.
    for (fragment, expected) in [
        (
            "            literal: acme\n            slot: ferrum/c/keyauth/key\n",
            "sets both",
        ),
        ("            {}\n", "sets neither"),
        ("            slot: '  '\n", "empty credential slot"),
    ] {
        let error = load_smoke(&format!(
            "version: 1\nenvironments:\n  staging:\n    checks:\n      - name: x\n\
             \n        path: /x\n        expect_status: 200\n        headers:\n\
             \n          X-Api-Key:\n{fragment}"
        ))
        .expect_err("must refuse");
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn a_missing_credential_slot_fails_the_check_rather_than_sending_nothing() {
    // Sending the request without the credential would make a check that
    // expects 401 pass for entirely the wrong reason — the auth plugin could
    // be missing and the check would still be green.
    let headers = [
        (
            "X-API-Key".to_string(),
            HeaderValue::slot("ferrum/c/keyauth/key"),
        ),
        ("X-Tenant".to_string(), HeaderValue::literal("acme")),
    ]
    .into_iter()
    .collect();
    let missing = resolve_headers(&headers, &Default::default()).expect_err("must fail");
    assert_eq!(missing, vec!["ferrum/c/keyauth/key".to_string()]);

    let bundle = [(
        "ferrum/c/keyauth/key".to_string(),
        "s3cret-value".to_string(),
    )]
    .into_iter()
    .collect();
    let resolved = resolve_headers(&headers, &bundle).expect("resolves");
    assert!(resolved.contains(&("X-Tenant".to_string(), "acme".to_string())));
    assert!(resolved.contains(&("X-API-Key".to_string(), "s3cret-value".to_string())));
}

// -- ambiguous attempts are not replayed (#353) ------------------------------

/// A loopback endpoint that commits each request the moment its head arrives
/// and answers the first one only after the check has given up on it. The
/// counter is what a replay costs.
fn spawn_committing_endpoint(status: u16) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
    let addr = listener.local_addr().expect("endpoint addr");
    let committed = Arc::new(AtomicUsize::new(0));
    let thread_committed = Arc::clone(&committed);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let committed = Arc::clone(&thread_committed);
            std::thread::spawn(move || {
                if !read_request_head(&mut stream) {
                    return;
                }
                // The side effect lands here, before any answer is written.
                if committed.fetch_add(1, Ordering::SeqCst) == 0 {
                    std::thread::sleep(Duration::from_millis(2500));
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
            });
        }
    });
    (format!("http://{addr}"), committed)
}

fn read_request_head(stream: &mut TcpStream) -> bool {
    if stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
    {
        return false;
    }
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0_u8; 1024];
    while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    true
}

/// The check from #353: `attempts` omitted, so the default of three applies.
fn enqueue_probe(extra: &str) -> SmokeCheck {
    let config = load_smoke(&format!(
        "version: 1\nenvironments:\n  staging:\n    checks:\n      - name: enqueue probe\n\
         \n        path: /smoke/enqueue\n        expect_status: 201\n        timeout_secs: 1\n\
         \n        retry_backoff_ms: 0\n{extra}"
    ))
    .expect("loads");
    let staging = config.for_environment("staging").expect("staging");
    staging.checks[0].clone()
}

#[test]
fn only_methods_idempotent_by_definition_are_replayed_automatically() {
    for method in ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"] {
        assert!(is_idempotent_method(method), "{method}");
    }
    // Methods are case-sensitive: `get` is an extension method, and an
    // extension method's semantics are unknown.
    for method in ["POST", "PATCH", "CONNECT", "PURGE", "get"] {
        assert!(!is_idempotent_method(method), "{method}");
    }
    let probe = enqueue_probe("        method: POST\n");
    assert_eq!(probe.attempts, 3);
    assert!(!probe.replay_safe);
    assert!(!probe.replays_ambiguous_attempts());
    let opted_in = enqueue_probe("        method: POST\n        replay_safe: true\n");
    assert!(opted_in.replays_ambiguous_attempts());
    let put = enqueue_probe("        method: PUT\n");
    assert!(put.replays_ambiguous_attempts());
}

#[tokio::test]
async fn a_post_that_committed_but_answered_late_is_not_replayed() {
    // The endpoint applied the first POST and lost only the reply. Sending it
    // again duplicated the side effect, and the second 201 passed the check.
    for extra in [
        "        method: POST\n",
        "        method: POST\n        replay_safe: false\n",
    ] {
        let (base_url, committed) = spawn_committing_endpoint(201);
        let check = enqueue_probe(extra);
        let result = run_check(&base_url, &check, &BTreeMap::new(), None).await;
        assert_eq!(committed.load(Ordering::SeqCst), 1, "{extra}");
        assert_eq!(result.outcome, Outcome::TimedOut, "{extra}");
        assert_eq!(result.attempts, 1, "{extra}");
        assert_eq!(result.actual_status, None, "{extra}");
        assert!(result.detail.contains("not retried"), "{}", result.detail);
        assert!(result.detail.contains("replay_safe"), "{}", result.detail);
    }
}

#[tokio::test]
async fn patch_and_unknown_methods_are_not_replayed_either() {
    for method in ["PATCH", "PURGE", "get"] {
        let (base_url, committed) = spawn_committing_endpoint(201);
        let check = enqueue_probe(&format!("        method: {method}\n"));
        let result = run_check(&base_url, &check, &BTreeMap::new(), None).await;
        assert_eq!(committed.load(Ordering::SeqCst), 1, "{method}");
        assert_eq!(result.outcome, Outcome::TimedOut, "{method}");
        assert_eq!(result.attempts, 1, "{method}");
    }
}

#[tokio::test]
async fn an_idempotent_check_still_retries_a_timeout_within_its_bound() {
    // A freshly applied route can take a moment to become live; bounded
    // retries of a GET remain the point of `attempts`.
    let (base_url, committed) = spawn_committing_endpoint(201);
    let check = enqueue_probe("        method: GET\n");
    let result = run_check(&base_url, &check, &BTreeMap::new(), None).await;
    assert_eq!(committed.load(Ordering::SeqCst), 2);
    assert_eq!(result.outcome, Outcome::Passed);
    assert_eq!(result.attempts, 2);
    assert_eq!(result.actual_status, Some(201));
}

#[tokio::test]
async fn replay_safe_is_the_explicit_opt_in_for_a_non_idempotent_retry() {
    let (base_url, committed) = spawn_committing_endpoint(201);
    let check = enqueue_probe("        method: POST\n        replay_safe: true\n");
    let result = run_check(&base_url, &check, &BTreeMap::new(), None).await;
    assert_eq!(committed.load(Ordering::SeqCst), 2);
    assert_eq!(result.outcome, Outcome::Passed);
    assert_eq!(result.attempts, 2);
}

#[tokio::test]
async fn a_connection_that_was_never_established_is_retried_for_any_method() {
    // A refused connection carried no request, so nothing can have been
    // applied: that much is provable, and the bound still holds.
    let closed = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base_url = format!("http://{}", closed.local_addr().expect("addr"));
    drop(closed);
    let check = enqueue_probe("        method: POST\n");
    let result = run_check(&base_url, &check, &BTreeMap::new(), None).await;
    assert_eq!(result.outcome, Outcome::Unreachable);
    assert_eq!(result.attempts, 3);
    assert!(!result.detail.contains("not retried"), "{}", result.detail);
}

// -- TLS is verified, always -------------------------------------------------

#[test]
fn the_verify_path_never_accepts_an_invalid_certificate() {
    // A check that accepts any certificate has not verified TLS; it has
    // verified that *something* answered. A promotion gate that passes
    // against an interceptor is worse than no gate, because it is believed.
    // A private CA is configuration (`FERRUM_GATEWAY_CA_CERT`), not a reason
    // to weaken the check.
    let runner = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/verify/runner.rs"),
    )
    .expect("read runner");
    let code: String = runner
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("danger_accept_invalid_certs"),
        "the verification client must not accept invalid certificates"
    );
    assert!(code.contains("add_root_certificate"), "{code}");
}

// -- reporting: never a pass we did not earn --------------------------------

fn report(outcomes: &[Outcome]) -> VerifyReport {
    VerifyReport {
        environment: "staging".to_string(),
        results: outcomes
            .iter()
            .enumerate()
            .map(|(index, outcome)| gitforgeops::verify::CheckResult {
                name: format!("check-{index}"),
                method: "GET".to_string(),
                path: "/orders".to_string(),
                expected_status: 200,
                actual_status: None,
                outcome: *outcome,
                attempts: 1,
                detail: "detail".to_string(),
            })
            .collect(),
    }
}

#[test]
fn an_environment_with_no_declared_checks_has_not_verified_anything() {
    // The dangerous default: zero checks trivially "all pass". A promotion
    // gate reading that as authorization is worse than having no gate.
    let empty = report(&[]);
    assert!(empty.passed(), "vacuously");
    assert!(empty.is_empty());
    assert_eq!(empty.exit_code(), VERIFY_FAILED_EXIT_CODE);
    assert!(empty
        .render_text()
        .contains("has not been shown to serve it"));
}

#[test]
fn every_non_passing_outcome_fails_the_verification() {
    for outcome in [Outcome::Unexpected, Outcome::TimedOut, Outcome::Unreachable] {
        let report = report(&[Outcome::Passed, outcome]);
        assert!(!report.passed(), "{outcome:?}");
        assert_eq!(report.exit_code(), VERIFY_FAILED_EXIT_CODE);
    }
    let clean = report(&[Outcome::Passed, Outcome::Passed]);
    assert!(clean.passed());
    assert_eq!(clean.exit_code(), 0);
}

#[test]
fn the_report_distinguishes_acceptance_from_healthy_traffic() {
    let rendered = report(&[Outcome::Unexpected]).render_text();
    assert!(
        rendered.contains("accepted the configuration write"),
        "{rendered}"
    );
    assert!(
        rendered.contains("not serving it as declared"),
        "{rendered}"
    );
}

#[test]
fn a_report_never_prints_a_header_value_or_a_response_body() {
    // `CheckResult` has no field for either, and the rendered line is built
    // only from the name, method, path, expected status and a bounded detail.
    let rendered = report(&[Outcome::Unexpected]).render_text();
    assert!(rendered.contains("/orders"));
    assert!(!rendered.contains("s3cret"));
    let json = gitforgeops::json_output::pretty(&report(&[Outcome::Unexpected])).expect("json");
    assert!(!json.contains("headers"), "{json}");
}

// -- the shipped example is loadable ---------------------------------------

#[test]
fn the_shipped_smoke_example_loads_and_demonstrates_both_halves() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".gitforgeops/smoke.example.yaml");
    let config = SmokeConfig::load_from_path(&path)
        .expect("the shipped example must load")
        .expect("present");
    let staging = config.for_environment("staging").expect("staging");
    // One check proves the route serves; one proves auth is enforced. An
    // example with only the first teaches people to miss the second.
    assert!(staging
        .checks
        .iter()
        .any(|check| check.expect_status == 200));
    assert!(staging
        .checks
        .iter()
        .any(|check| check.expect_status == 401));
    // ...and production deliberately has none, so a promotion gated on it
    // stays blocked until someone says what "serving correctly" means.
    assert!(config.for_environment("production").is_none());
}

#[test]
fn the_shipped_config_example_still_loads_with_a_promotion_chain() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".gitforgeops/config.example.yaml");
    let config = RepoConfig::load_from_path(&path)
        .expect("the shipped example must load")
        .expect("present");
    let production = config.environment("production").expect("production");
    assert_eq!(production.promotion.requires.as_deref(), Some("staging"));
    assert_eq!(
        config
            .environment("staging")
            .expect("staging")
            .promotion
            .requires,
        None
    );
}
