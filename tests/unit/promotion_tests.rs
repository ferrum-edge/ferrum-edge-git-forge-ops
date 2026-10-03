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
use gitforgeops::config::GatewayConfig;
use gitforgeops::verify::runner::{deadline_budget, run_check, run_within};
use gitforgeops::verify::{
    authorize_probe_credentials, authorize_probe_slots, bind_probe_slots, is_idempotent_method,
    labelled_probe_consumers, probe_credential_slots, refuse_unbound_slots, resolve_headers,
    BindingStatus, EnvironmentChecks, HeaderValue, Outcome, ProbeConsumerAllowlist,
    ProbeCredentials, SmokeCheck, SmokeConfig, VerifyReport, VerifyStatus,
    LEGACY_SMOKE_CONFIG_VERSION, MAX_CHECKS_PER_ENVIRONMENT, MAX_CHECK_ATTEMPTS,
    MAX_CHECK_RETRY_BACKOFF_MS, MAX_CHECK_TIMEOUT_SECS, MAX_ENVIRONMENT_VERIFY_BUDGET_SECS,
    SMOKE_CONFIG_VERSION, VERIFY_DEADLINE_GRACE_SECS, VERIFY_FAILED_EXIT_CODE,
    VERIFY_PROBE_CONSUMERS_ENV, VERIFY_PROBE_LABEL, VERIFY_SKIPPED_EXIT_CODE,
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

#[test]
fn smoke_config_refuses_oversized_input() {
    let file = write_yaml(&" ".repeat(1024 * 1024 + 1));
    let error = SmokeConfig::load_from_path(file.path()).expect_err("must refuse oversized input");
    assert!(error.to_string().contains("1048576 byte limit"), "{error}");
}

#[cfg(unix)]
#[test]
fn smoke_config_refuses_symbolic_links() {
    use std::os::unix::fs::symlink;

    let target = write_yaml("version: 1\nenvironments: {}\n");
    let directory = tempfile::tempdir().expect("tempdir");
    let link = directory.path().join("smoke.yaml");
    symlink(target.path(), &link).expect("symlink");

    let error = SmokeConfig::load_from_path(&link).expect_err("must refuse symlink");
    assert!(error.to_string().contains("symbolic links"), "{error}");
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
            "version: 2\nenvironments:\n  staging:\n    checks:\n      - name: x\n\
             \n        path: /x\n        expect_status: 200\n        {key}: 'rm -rf /'\n"
        ))
        .expect_err("must refuse");
        assert!(error.contains(key), "{key}: {error}");
    }
}

#[test]
fn a_check_declares_the_status_it_expects() {
    let config = load_smoke(
        "version: 2\nenvironments:\n  staging:\n    checks:\n\
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
            "version: 2\nenvironments:\n  staging:\n    checks:\n      - name: x\n{fragment}"
        ))
        .expect_err("must refuse");
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

#[test]
fn an_unsupported_smoke_version_is_refused() {
    let error = load_smoke("version: 3\nenvironments: {}\n").expect_err("must refuse");
    assert!(
        error.contains("unsupported smoke-check config version"),
        "{error}"
    );
    assert_eq!(SMOKE_CONFIG_VERSION, 2);
    assert_eq!(LEGACY_SMOKE_CONFIG_VERSION, 1);
}

/// A check sending `ferrum/orders-client/keyauth/key`, at `version`.
fn slot_file(version: Option<u32>) -> String {
    let version = version
        .map(|version| format!("version: {version}\n"))
        .unwrap_or_default();
    format!(
        "{version}environments:\n  staging:\n    checks:\n      - name: x\n\
         \n        path: /x\n        expect_status: 200\n        headers:\n\
         \n          X-API-Key:\n            slot: ferrum/orders-client/keyauth/key\n"
    )
}

#[test]
fn a_version_1_file_that_names_a_slot_is_refused_for_review_again() {
    // Under version 1 a slot could name any credential in the bundle, so the
    // checks written then may name customer keys. They are refused rather
    // than reinterpreted under the probe binding, and leaving `version` out
    // does not slip past.
    for version in [Some(LEGACY_SMOKE_CONFIG_VERSION), None] {
        let error = load_smoke(&slot_file(version)).expect_err("must refuse");
        for expected in [
            "names a credential slot",
            "Review every slot again",
            "version: 2",
            VERIFY_PROBE_CONSUMERS_ENV,
        ] {
            assert!(error.contains(expected), "{version:?} {expected}: {error}");
        }
    }
    load_smoke(&slot_file(Some(SMOKE_CONFIG_VERSION))).expect("version 2 loads");
    // A version 1 file that sends no credential carries no such risk.
    load_smoke(
        "version: 1\nenvironments:\n  staging:\n    checks:\n      - name: x\n\
         \n        path: /x\n        expect_status: 401\n",
    )
    .expect("a slot-free version 1 file loads");
}

// -- budgets (GHSA-p95x-q89j-hrhv) -------------------------------------------

fn one_check(fragment: &str) -> String {
    format!(
        "version: 2\nenvironments:\n  staging:\n    checks:\n      - name: x\n\
         \n        path: /x\n        expect_status: 200\n{fragment}"
    )
}

#[test]
fn each_check_budget_has_a_hard_upper_bound() {
    // Verification runs after the gateway changed and before the ledger is
    // committed. An attempt count, timeout or backoff nobody bounded is a
    // deployment job nobody can finish.
    for (fragment, expected) in [
        (
            format!("        attempts: {}\n", MAX_CHECK_ATTEMPTS + 1),
            format!("above the maximum of {MAX_CHECK_ATTEMPTS}"),
        ),
        (
            "        attempts: 4294967295\n".to_string(),
            format!("above the maximum of {MAX_CHECK_ATTEMPTS}"),
        ),
        (
            format!("        timeout_secs: {}\n", MAX_CHECK_TIMEOUT_SECS + 1),
            format!("above the maximum of {MAX_CHECK_TIMEOUT_SECS}"),
        ),
        (
            "        timeout_secs: 18446744073709551615\n".to_string(),
            format!("above the maximum of {MAX_CHECK_TIMEOUT_SECS}"),
        ),
        (
            format!(
                "        retry_backoff_ms: {}\n",
                MAX_CHECK_RETRY_BACKOFF_MS + 1
            ),
            format!("above the maximum of {MAX_CHECK_RETRY_BACKOFF_MS}"),
        ),
    ] {
        let error = load_smoke(&one_check(&fragment)).expect_err("must refuse");
        assert!(error.contains(&expected), "{fragment}: {error}");
    }
}

#[test]
fn a_check_at_every_per_check_maximum_that_fits_the_environment_budget_loads() {
    let config = load_smoke(&one_check(&format!(
        "        attempts: {MAX_CHECK_ATTEMPTS}\n        timeout_secs: {MAX_CHECK_TIMEOUT_SECS}\n\
         \n        retry_backoff_ms: 0\n"
    )))
    .expect("a single bounded check loads");
    let staging = config.for_environment("staging").expect("staging");
    assert_eq!(
        staging.checks[0].worst_case_budget(),
        Duration::from_secs(u64::from(MAX_CHECK_ATTEMPTS) * MAX_CHECK_TIMEOUT_SECS)
    );
}

#[test]
fn the_worst_case_budget_counts_every_timeout_and_every_backoff() {
    // 5 attempts of 10s, and pauses of 1, 2, 3 and 4 times 500ms.
    let config = load_smoke(&one_check(
        "        attempts: 5\n        timeout_secs: 10\n        retry_backoff_ms: 500\n",
    ))
    .expect("loads");
    let staging = config.for_environment("staging").expect("staging");
    assert_eq!(
        staging.checks[0].worst_case_budget(),
        Duration::from_millis(55_000)
    );
    assert_eq!(staging.worst_case_budget(), Duration::from_millis(55_000));
    // A single attempt never pauses.
    let single = load_smoke(&one_check(
        "        attempts: 1\n        timeout_secs: 7\n        retry_backoff_ms: 30000\n",
    ))
    .expect("loads");
    let single = single.for_environment("staging").expect("staging");
    assert_eq!(single.worst_case_budget(), Duration::from_secs(7));
}

fn many_checks(count: usize, fields: &str) -> String {
    let mut yaml = String::from("version: 2\nenvironments:\n  staging:\n    checks:\n");
    for index in 0..count {
        yaml.push_str(&format!(
            "      - name: check-{index}\n        path: /x\n        expect_status: 200\n{fields}"
        ));
    }
    yaml
}

#[test]
fn individually_valid_checks_are_refused_when_their_sum_exceeds_the_environment_budget() {
    let fields = format!(
        "        attempts: {MAX_CHECK_ATTEMPTS}\n        timeout_secs: {MAX_CHECK_TIMEOUT_SECS}\n\
         \n        retry_backoff_ms: 0\n"
    );
    // One fits; two together do not.
    load_smoke(&many_checks(1, &fields)).expect("one check fits");
    let error = load_smoke(&many_checks(2, &fields)).expect_err("must refuse the sum");
    assert!(error.contains("worst-case duration is 1200s"), "{error}");
    assert!(
        error.contains(&format!("{MAX_ENVIRONMENT_VERIFY_BUDGET_SECS}s limit")),
        "{error}"
    );
    // The refusal applies to every environment in the file, not only the one
    // a run selects, exactly as `verify` loads it.
    let other = many_checks(2, &fields).replace("  staging:", "  production:");
    assert!(load_smoke(&other).is_err());
}

#[test]
fn an_environment_may_declare_a_bounded_number_of_checks() {
    let tiny = "        attempts: 1\n        timeout_secs: 1\n        retry_backoff_ms: 0\n";
    load_smoke(&many_checks(MAX_CHECKS_PER_ENVIRONMENT, tiny)).expect("at the cap loads");
    let error = load_smoke(&many_checks(MAX_CHECKS_PER_ENVIRONMENT + 1, tiny))
        .expect_err("over the cap is refused");
    assert!(
        error.contains(&format!("at most {MAX_CHECKS_PER_ENVIRONMENT} are allowed")),
        "{error}"
    );
}

#[test]
fn the_shipped_example_fits_its_budget() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".gitforgeops/smoke.example.yaml");
    let config = SmokeConfig::load_from_path(&path)
        .expect("the shipped example must load")
        .expect("present");
    let staging = config.for_environment("staging").expect("staging");
    // 55s for the authenticated check, 31.5s for the 401 check.
    assert_eq!(staging.worst_case_budget(), Duration::from_millis(86_500));
    assert_eq!(
        deadline_budget(staging),
        Duration::from_millis(86_500) + Duration::from_secs(VERIFY_DEADLINE_GRACE_SECS)
    );
}

#[test]
fn the_runner_deadline_is_capped_even_for_checks_that_skipped_load() {
    // `run` can be handed checks that never went through `load`. The outer
    // deadline still never exceeds the environment cap plus the grace.
    let check = SmokeCheck {
        name: "unbounded".to_string(),
        method: "GET".to_string(),
        path: "/x".to_string(),
        headers: BTreeMap::new(),
        expect_status: 200,
        timeout_secs: u64::MAX,
        attempts: u32::MAX,
        retry_backoff_ms: u64::MAX,
        replay_safe: false,
    };
    let checks = EnvironmentChecks {
        checks: vec![check],
    };
    assert_eq!(
        deadline_budget(&checks),
        Duration::from_secs(MAX_ENVIRONMENT_VERIFY_BUDGET_SECS + VERIFY_DEADLINE_GRACE_SECS)
    );
}

/// A `timeout-minutes` key at step indentation in `apply-on-merge.yml`.
const STEP_TIMEOUT: &str = "        timeout-minutes: ";

#[test]
fn both_verify_steps_carry_a_step_timeout_that_covers_the_budget() {
    // A backstop for the in-process deadline. It must be a STEP timeout: a job
    // timeout cancels the job, and the `!cancelled()` ledger commit after a
    // live mutation is then skipped.
    let workflow = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/apply-on-merge.yml"),
    )
    .expect("read apply-on-merge.yml");
    let marker = "      - name: Verify traffic\n";
    let steps: Vec<&str> = workflow
        .match_indices(marker)
        .map(|(start, _)| {
            let body = &workflow[start + marker.len()..];
            &body[..body.find("\n      - name: ").unwrap_or(body.len())]
        })
        .collect();
    assert_eq!(steps.len(), 2, "the apply and promote jobs each verify");
    let needed = MAX_ENVIRONMENT_VERIFY_BUDGET_SECS + VERIFY_DEADLINE_GRACE_SECS;
    for step in steps {
        let found = step.lines().find_map(|line| line.strip_prefix(STEP_TIMEOUT));
        let value = found.expect("a step-level timeout-minutes");
        let minutes: u64 = value.trim().parse().expect("a whole number of minutes");
        assert!(minutes * 60 > needed, "{minutes} minutes");
        assert!(step.contains("continue-on-error: true"), "{step}");
    }
    for line in workflow.lines() {
        assert!(
            !line.starts_with("    timeout-minutes:"),
            "a job-level timeout would skip the ledger commit: {line}"
        );
    }
}

/// The bodies of every step named `name` in `workflow`, at step indentation.
fn workflow_steps<'a>(workflow: &'a str, name: &str) -> Vec<&'a str> {
    let marker = format!("      - name: {name}\n");
    workflow
        .match_indices(marker.as_str())
        .map(|(start, _)| {
            let body = &workflow[start + marker.len()..];
            &body[..body.find("\n      - name: ").unwrap_or(body.len())]
        })
        .collect()
}

#[test]
fn the_operator_allowlist_reaches_verify_and_the_steps_before_a_change() {
    // GHSA-8mhw-ghx8-9m63: the allowlist must come from a GitHub Environment
    // variable, which no merge can change. `verify` enforces it; `validate`
    // before Apply and the trusted review refuse an unlisted Consumer before
    // the gateway changes.
    let binding = "FERRUM_VERIFY_PROBE_CONSUMERS: ${{ vars.FERRUM_VERIFY_PROBE_CONSUMERS }}";
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let apply = std::fs::read_to_string(root.join("apply-on-merge.yml")).expect("read apply");
    for name in ["Verify traffic", "Validate"] {
        let steps = workflow_steps(&apply, name);
        assert_eq!(steps.len(), 2, "the apply and promote jobs each run {name}");
        for step in steps {
            assert!(step.contains(binding), "{name}: {step}");
        }
    }
    assert!(
        !apply.contains("secrets.FERRUM_VERIFY_PROBE_CONSUMERS"),
        "the allowlist is a variable, not a secret"
    );
    let review = std::fs::read_to_string(root.join("trusted-pr-review.yml")).expect("read review");
    let steps = workflow_steps(&review, "Post trusted live review");
    assert_eq!(steps.len(), 1);
    assert!(steps[0].contains(binding), "{}", steps[0]);
}

#[tokio::test]
async fn the_outer_deadline_times_out_a_hung_check_and_sends_nothing_after_it() {
    // The endpoint holds the first request for 2.5s; the run's deadline is
    // far shorter. The interrupted check and the one after it both fail, and
    // the second is never sent.
    let (base_url, committed) = spawn_committing_endpoint(200);
    let config = load_smoke(
        "version: 2\nenvironments:\n  staging:\n    checks:\n\
         \n      - name: first\n        path: /a\n        expect_status: 200\n\
         \n        attempts: 1\n        timeout_secs: 5\n\
         \n      - name: second\n        path: /b\n        expect_status: 200\n\
         \n        attempts: 1\n        timeout_secs: 5\n",
    )
    .expect("loads");
    let staging = config.for_environment("staging").expect("staging");
    let report = run_within(
        "staging",
        &base_url,
        staging,
        &ProbeCredentials::none(),
        None,
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(report.results.len(), 2);
    assert_eq!(report.results[0].outcome, Outcome::TimedOut);
    assert!(
        report.results[0].detail.contains("interrupted"),
        "{}",
        report.results[0].detail
    );
    assert_eq!(report.results[1].outcome, Outcome::TimedOut);
    assert_eq!(report.results[1].attempts, 0);
    assert!(
        report.results[1].detail.contains("not run"),
        "{}",
        report.results[1].detail
    );
    assert!(committed.load(Ordering::SeqCst) <= 1);
    assert_eq!(report.status(), VerifyStatus::Failed);
}

// -- probe credentials (GHSA-8mhw-ghx8-9m63) ----------------------------------

const PROBE_SLOT: &str = "ferrum/orders-probe/keyauth/key";
const PROBE_PASSWORD_SLOT: &str = "ferrum/orders-probe/basicauth/password";
const CUSTOMER_SLOT: &str = "ferrum/orders-client/keyauth/key";
const MISLABELLED_SLOT: &str = "ferrum/almost-probe/keyauth/key";
const PLUGIN_SLOT: &str = "ferrum/upstream-auth/@plugin/http_logging/config/token";
const PROBE_VALUE: &str = "probe-value-0001";
const CUSTOMER_VALUE: &str = "customer-value-0002";
const PLUGIN_VALUE: &str = "plugin-value-0003";

fn desired() -> GatewayConfig {
    serde_json::from_value(serde_json::json!({
        "consumers": [
            {
                "id": "orders-probe",
                "username": "orders-probe",
                "namespace": "ferrum",
                "labels": { VERIFY_PROBE_LABEL: "true" },
                "credentials": {
                    "keyauth": [{ "key": "${gh-env-secret:alloc=generate}" }],
                    "basicauth": [{
                        "username": "orders-probe",
                        "password": "${gh-env-secret:alloc=generate}"
                    }]
                }
            },
            {
                "id": "orders-client",
                "username": "orders-client",
                "namespace": "ferrum",
                "credentials": {
                    "keyauth": [{ "key": "${gh-env-secret:alloc=require}" }]
                }
            },
            {
                "id": "almost-probe",
                "username": "almost-probe",
                "namespace": "ferrum",
                "labels": { VERIFY_PROBE_LABEL: "yes" },
                "credentials": {
                    "keyauth": [{ "key": "${gh-env-secret:alloc=generate}" }]
                }
            }
        ]
    }))
    .expect("desired config")
}

fn bundle() -> BTreeMap<String, String> {
    [
        (PROBE_SLOT, PROBE_VALUE),
        (CUSTOMER_SLOT, CUSTOMER_VALUE),
        (MISLABELLED_SLOT, CUSTOMER_VALUE),
        (PLUGIN_SLOT, PLUGIN_VALUE),
    ]
    .into_iter()
    .map(|(slot, value)| (slot.to_string(), value.to_string()))
    .collect()
}

/// One check, built directly so the runtime binding is tested without the
/// load-time half in front of it.
fn checks_sending(method: &str, slot: &str) -> EnvironmentChecks {
    EnvironmentChecks {
        checks: vec![SmokeCheck {
            name: "probe".to_string(),
            method: method.to_string(),
            path: "/orders/healthz".to_string(),
            headers: BTreeMap::from([("X-API-Key".to_string(), HeaderValue::slot(slot))]),
            expect_status: 200,
            timeout_secs: 5,
            attempts: 1,
            retry_backoff_ms: 0,
            replay_safe: false,
        }],
    }
}

#[test]
fn only_brokered_secrets_of_labelled_consumers_are_probe_slots() {
    let slots = probe_credential_slots(&desired());
    let expected: std::collections::BTreeSet<String> = [PROBE_SLOT, PROBE_PASSWORD_SLOT]
        .into_iter()
        .map(str::to_string)
        .collect();
    // Not the customer, not a label that only looks like opt-in, and never an
    // identity such as basicauth.username.
    assert_eq!(slots, expected);
}

/// The operator's allowlist: the probe, and nothing else.
fn allowlist() -> ProbeConsumerAllowlist {
    ProbeConsumerAllowlist::parse("ferrum/orders-probe").expect("allowlist")
}

/// `desired()` after a pull request labelled the customer as a probe.
fn desired_with_labelled_customer() -> GatewayConfig {
    let mut desired = desired();
    let customer = desired
        .consumers
        .iter_mut()
        .find(|consumer| consumer.id == "orders-client")
        .expect("customer");
    customer
        .labels
        .insert(VERIFY_PROBE_LABEL.to_string(), "true".to_string());
    desired
}

/// No synthetic bundle value may appear in `text`.
fn assert_no_value(text: &str, context: &str) {
    for value in [PROBE_VALUE, CUSTOMER_VALUE, PLUGIN_VALUE] {
        assert!(
            !text.contains(value),
            "{context}: a bundle value was printed"
        );
    }
}

#[test]
fn a_probe_slot_is_projected_and_nothing_else_is() {
    let credentials = authorize_probe_credentials(
        "staging",
        &checks_sending("GET", PROBE_SLOT),
        &desired(),
        Some(&allowlist()),
        &bundle(),
    )
    .expect("an allowlisted, labelled probe credential is authorized");
    assert_eq!(credentials.slots().collect::<Vec<_>>(), vec![PROBE_SLOT]);
    // The runner resolves against the projection only.
    let debug = format!("{credentials:?}");
    assert_no_value(&debug, "ProbeCredentials Debug");
}

#[test]
fn a_check_cannot_spend_an_unrelated_credential_from_the_bundle() {
    for (method, slot) in [
        // A customer Consumer with no opt-in.
        ("GET", CUSTOMER_SLOT),
        // A label that is not exactly "true".
        ("GET", MISLABELLED_SLOT),
        // A plugin's upstream credential.
        ("GET", PLUGIN_SLOT),
        // A service-discovery secret.
        ("GET", "ferrum/registry/@service-discovery/consul/token"),
        // An identity of the probe itself.
        ("HEAD", "ferrum/orders-probe/basicauth/username"),
        // The probe credential on a request that may act on the endpoint.
        ("POST", PROBE_SLOT),
        ("PUT", PROBE_SLOT),
        // A Consumer the environment does not declare at all.
        ("GET", "other/orders-probe/keyauth/key"),
    ] {
        let error = authorize_probe_credentials(
            "staging",
            &checks_sending(method, slot),
            &desired(),
            Some(&allowlist()),
            &bundle(),
        )
        .expect_err("must refuse")
        .to_string();
        for expected in [slot, "no request was sent", VERIFY_PROBE_LABEL] {
            assert!(error.contains(expected), "{method} {slot}: {error}");
        }
        assert_no_value(&error, &format!("{method} {slot}"));
    }
}

#[test]
fn the_label_alone_authorizes_nothing_without_the_operator_allowlist() {
    // The label lives in resources/, which the pull request naming the slot
    // can change. Without the operator's list, a labelled probe is refused
    // before the bundle is read.
    let empty = ProbeConsumerAllowlist::parse(" , ").expect("parses");
    for allowlist in [None, Some(&empty)] {
        let error = authorize_probe_slots(
            "staging",
            &checks_sending("GET", PROBE_SLOT),
            &desired(),
            allowlist,
        )
        .expect_err("must refuse")
        .to_string();
        for expected in [
            VERIFY_PROBE_CONSUMERS_ENV,
            "unset or empty",
            "no request was sent",
        ] {
            assert!(error.contains(expected), "{allowlist:?}: {error}");
        }
    }
}

#[test]
fn a_customer_labelled_by_a_pull_request_is_refused_unless_the_operator_lists_it() {
    // GHSA-8mhw-ghx8-9m63: one pull request labels a customer Consumer and
    // names its key. The label is now present, so only the operator's list
    // stands between the check and the customer's key.
    let desired = desired_with_labelled_customer();
    assert!(probe_credential_slots(&desired).contains(CUSTOMER_SLOT));
    let error = authorize_probe_credentials(
        "staging",
        &checks_sending("GET", CUSTOMER_SLOT),
        &desired,
        Some(&allowlist()),
        &bundle(),
    )
    .expect_err("an unlisted Consumer must be refused")
    .to_string();
    for expected in [
        CUSTOMER_SLOT,
        "ferrum/orders-client",
        VERIFY_PROBE_CONSUMERS_ENV,
        "no request was sent",
    ] {
        assert!(error.contains(expected), "{expected}: {error}");
    }
    assert_no_value(&error, "labelled customer refusal");
    // Listing a Consumer is not enough without the label either.
    let both = ProbeConsumerAllowlist::parse("ferrum/orders-probe,ferrum/orders-client")
        .expect("allowlist");
    let error = authorize_probe_slots(
        "staging",
        &checks_sending("GET", CUSTOMER_SLOT),
        &desired(),
        Some(&both),
    )
    .expect_err("an unlabelled Consumer must be refused")
    .to_string();
    assert!(error.contains("not labelled"), "{error}");
}

#[test]
fn an_authorized_slot_missing_from_the_bundle_still_fails_its_check() {
    let mut partial = bundle();
    partial.remove(PROBE_SLOT);
    let authorization = authorize_probe_slots(
        "staging",
        &checks_sending("GET", PROBE_SLOT),
        &desired(),
        Some(&allowlist()),
    )
    .expect("authorized");
    assert_eq!(authorization.slots().collect::<Vec<_>>(), vec![PROBE_SLOT]);
    assert_eq!(authorization.project(&partial).slots().count(), 0);
}

#[test]
fn checks_that_send_no_credential_need_no_authorization() {
    let checks = EnvironmentChecks {
        checks: vec![SmokeCheck {
            headers: BTreeMap::from([("X-Tenant".to_string(), HeaderValue::literal("acme"))]),
            ..checks_sending("POST", PROBE_SLOT).checks[0].clone()
        }],
    };
    assert!(!checks.sends_credentials());
    // No slot, so neither the label nor the operator's list is needed.
    let credentials = authorize_probe_credentials(
        "staging",
        &checks,
        &GatewayConfig::default(),
        None,
        &bundle(),
    )
    .expect("nothing to authorize");
    assert_eq!(credentials.slots().count(), 0);
    assert!(checks_sending("GET", PROBE_SLOT).sends_credentials());
}

#[test]
fn the_operator_allowlist_names_namespace_qualified_consumers() {
    let list = ProbeConsumerAllowlist::parse(" ferrum/orders-probe , ,team-a/probe ,")
        .expect("parses");
    assert!(list.contains("ferrum", "orders-probe"));
    assert!(list.contains("team-a", "probe"));
    // Exact, namespace-qualified matches only.
    assert!(!list.contains("team-a", "orders-probe"));
    assert!(!list.contains("ferrum", "orders"));
    assert_eq!(
        list.consumers().collect::<Vec<_>>(),
        vec!["ferrum/orders-probe", "team-a/probe"]
    );
    // A typo surfaces instead of silently allowing nothing.
    for raw in [
        "orders-probe",
        "ferrum/",
        "/orders-probe",
        "ferrum/orders probe",
    ] {
        let error = ProbeConsumerAllowlist::parse(raw)
            .expect_err("must refuse")
            .to_string();
        assert!(error.contains(VERIFY_PROBE_CONSUMERS_ENV), "{raw}: {error}");
        assert!(error.contains("<namespace>/<consumer-id>"), "{raw}: {error}");
    }
}

#[test]
fn bindings_map_each_slot_to_the_consumer_it_would_spend() {
    let checks = EnvironmentChecks {
        checks: vec![SmokeCheck {
            headers: BTreeMap::from([
                ("A-Probe".to_string(), HeaderValue::slot(PROBE_SLOT)),
                ("B-Customer".to_string(), HeaderValue::slot(CUSTOMER_SLOT)),
                ("C-Plugin".to_string(), HeaderValue::slot(PLUGIN_SLOT)),
                (
                    "D-Elsewhere".to_string(),
                    HeaderValue::slot("team-b/probe/keyauth/key"),
                ),
                ("E-Tenant".to_string(), HeaderValue::literal("acme")),
            ]),
            ..checks_sending("GET", PROBE_SLOT).checks[0].clone()
        }],
    };
    let statuses = |allowlist: Option<&ProbeConsumerAllowlist>, filter: Option<&str>| {
        bind_probe_slots(&checks, &desired(), allowlist, filter)
            .into_iter()
            .map(|binding| (binding.header, binding.consumer, binding.status))
            .collect::<Vec<_>>()
    };
    let probe = Some("ferrum/orders-probe".to_string());
    let customer = Some("ferrum/orders-client".to_string());

    // A pull request's run cannot see the operator's list: the label half is
    // judged, the list half is left to `verify`, and a slot in a namespace
    // the run did not select is not judged at all.
    let preview = statuses(None, Some("ferrum"));
    assert_eq!(
        preview,
        vec![
            (
                "A-Probe".to_string(),
                probe,
                BindingStatus::AllowlistNotVisible,
            ),
            (
                "B-Customer".to_string(),
                customer,
                BindingStatus::NotLabelled,
            ),
            ("C-Plugin".to_string(), None, BindingStatus::InvalidSlot),
            (
                "D-Elsewhere".to_string(),
                None,
                BindingStatus::OutsideNamespaceScope,
            ),
        ]
    );
    // With the list visible and no namespace selection, everything is judged.
    let full = statuses(Some(&allowlist()), None);
    assert_eq!(full[0].2, BindingStatus::Approved);
    assert_eq!(full[3].2, BindingStatus::NotAConsumerSecret);
    let unlisted = ProbeConsumerAllowlist::parse("ferrum/someone-else").expect("parses");
    assert_eq!(
        statuses(Some(&unlisted), None)[0].2,
        BindingStatus::NotAllowlisted
    );

    // Only the refusals stop a run, and they name slot and Consumer.
    let probe_only = bind_probe_slots(
        &checks_sending("GET", PROBE_SLOT),
        &desired(),
        None,
        Some("ferrum"),
    );
    refuse_unbound_slots("staging", &probe_only).expect("label half satisfied");
    let error = refuse_unbound_slots(
        "staging",
        &bind_probe_slots(&checks, &desired(), None, Some("ferrum")),
    )
    .expect_err("customer and plugin slots refuse")
    .to_string();
    for expected in [CUSTOMER_SLOT, "ferrum/orders-client", PLUGIN_SLOT] {
        assert!(error.contains(expected), "{expected}: {error}");
    }
    assert!(!error.contains("team-b/probe"), "{error}");
}

#[test]
fn a_review_lists_every_labelled_probe_consumer() {
    assert_eq!(
        labelled_probe_consumers(&desired()),
        vec!["ferrum/orders-probe".to_string()]
    );
    assert_eq!(
        labelled_probe_consumers(&desired_with_labelled_customer()),
        vec![
            "ferrum/orders-client".to_string(),
            "ferrum/orders-probe".to_string(),
        ]
    );
}

#[test]
fn a_slot_that_cannot_be_a_consumer_credential_is_refused_at_load() {
    for (slot, expected) in [
        (PLUGIN_SLOT, "not a Consumer credential type"),
        (
            "ferrum/registry/@service-discovery/consul/token",
            "not a Consumer credential type",
        ),
        ("ferrum/c/custom/key", "not a Consumer credential type"),
        ("ferrum/c/keyauth", "is not a Consumer credential slot"),
        ("ferrum//keyauth/key", "is not a Consumer credential slot"),
        ("ferrum/c/basicauth/username", "credential identity"),
        ("ferrum/c/mtls_auth/identity", "credential identity"),
    ] {
        let error = load_smoke(&one_check(&format!(
            "        headers:\n          X-API-Key:\n            slot: '{slot}'\n"
        )))
        .expect_err("must refuse");
        assert!(error.contains(expected), "{slot}: {error}");
    }
}

#[test]
fn a_check_that_sends_a_slot_must_be_get_or_head() {
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "get"] {
        let error = load_smoke(&one_check(&format!(
            "        method: {method}\n        headers:\n          X-API-Key:\n\
             \n            slot: {PROBE_SLOT}\n"
        )))
        .expect_err("must refuse");
        assert!(error.contains("must be GET or HEAD"), "{method}: {error}");
    }
    for method in ["GET", "HEAD"] {
        load_smoke(&one_check(&format!(
            "        method: {method}\n        headers:\n          X-API-Key:\n\
             \n            slot: {PROBE_SLOT}\n"
        )))
        .expect("a read-only probe loads");
    }
    // A literal header carries no credential, so the method stays free.
    load_smoke(&one_check(
        "        method: POST\n        headers:\n          X-Tenant:\n            literal: acme\n",
    ))
    .expect("loads");
}

#[test]
fn routing_and_hop_by_hop_headers_are_refused() {
    for name in [
        "Host",
        "host",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "x_forwarded_proto",
        "Forwarded",
        "X-Real-IP",
        "Via",
        "Connection",
        "Transfer-Encoding",
        "Content-Length",
        "Upgrade",
        "Proxy-Authorization",
        // A GET probe must not become a DELETE at an upstream that honours
        // a method override.
        "X-HTTP-Method-Override",
        "x-http-method",
        "X_Method_Override",
        "X-METHOD-OVERRIDE",
    ] {
        let error = load_smoke(&one_check(&format!(
            "        headers:\n          {name}:\n            literal: x\n"
        )))
        .expect_err("must refuse");
        assert!(error.contains("is reserved"), "{name}: {error}");
    }
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
            "version: 2\nenvironments:\n  staging:\n    checks:\n      - name: x\n\
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
        "version: 2\nenvironments:\n  staging:\n    checks:\n      - name: enqueue probe\n\
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
        let result = run_check(&base_url, &check, &ProbeCredentials::none(), None).await;
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
        let result = run_check(&base_url, &check, &ProbeCredentials::none(), None).await;
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
    let result = run_check(&base_url, &check, &ProbeCredentials::none(), None).await;
    assert_eq!(committed.load(Ordering::SeqCst), 2);
    assert_eq!(result.outcome, Outcome::Passed);
    assert_eq!(result.attempts, 2);
    assert_eq!(result.actual_status, Some(201));
}

#[tokio::test]
async fn replay_safe_is_the_explicit_opt_in_for_a_non_idempotent_retry() {
    let (base_url, committed) = spawn_committing_endpoint(201);
    let check = enqueue_probe("        method: POST\n        replay_safe: true\n");
    let result = run_check(&base_url, &check, &ProbeCredentials::none(), None).await;
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
    let result = run_check(&base_url, &check, &ProbeCredentials::none(), None).await;
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
fn an_environment_with_no_declared_checks_is_skipped_not_passed_or_failed() {
    // The dangerous default: zero checks trivially "all pass". A promotion
    // gate reading that as authorization is worse than having no gate. It is
    // not a failed check either: nothing ran, so the deployment job records
    // `skipped` and stays green.
    let empty = report(&[]);
    assert!(empty.passed(), "vacuously");
    assert!(empty.is_empty());
    assert_eq!(empty.status(), VerifyStatus::Skipped);
    assert_eq!(empty.exit_code(), VERIFY_SKIPPED_EXIT_CODE);
    let rendered = empty.render_text();
    assert!(
        rendered.contains("skipped: no smoke checks declared for staging"),
        "{rendered}"
    );
    assert!(rendered.contains("not a pass"), "{rendered}");
    assert!(rendered.contains("authorizes no promotion"), "{rendered}");
}

#[test]
fn the_three_verify_results_have_three_exit_codes() {
    // 1 is "verify could not run". Skipped must be distinguishable from it
    // and from a failed check, and must never be 0.
    let codes = [0, 1, VERIFY_FAILED_EXIT_CODE, VERIFY_SKIPPED_EXIT_CODE];
    for (index, code) in codes.iter().enumerate() {
        assert!(!codes[index + 1..].contains(code), "{code} is reused");
    }
    let skipped = VerifyReport::skipped("production");
    assert_eq!(skipped.environment, "production");
    assert_eq!(skipped.status(), VerifyStatus::Skipped);
    assert_eq!(skipped.exit_code(), VERIFY_SKIPPED_EXIT_CODE);
    let failed = report(&[Outcome::Passed, Outcome::Unexpected]);
    assert_eq!(failed.status(), VerifyStatus::Failed);
    let passed = report(&[Outcome::Passed]);
    assert_eq!(passed.status(), VerifyStatus::Passed);
}

#[test]
fn the_json_report_states_its_status() {
    // A machine reader must not infer "skipped" from an empty list.
    for (verified, status) in [
        (VerifyReport::skipped("production"), "skipped"),
        (report(&[Outcome::Passed]), "passed"),
        (report(&[Outcome::TimedOut]), "failed"),
    ] {
        let json = gitforgeops::json_output::pretty(&verified).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(value["status"], status, "{json}");
        assert_eq!(value["environment"], verified.environment.as_str());
        assert!(value["results"].is_array(), "{json}");
    }
}

#[test]
fn an_empty_or_absent_entry_declares_no_checks() {
    let yaml = r#"
version: 1
environments:
  staging:
    checks:
      - name: orders
        path: /orders
        expect_status: 200
  production:
    checks: []
"#;
    let config = load_smoke(yaml).expect("loads");
    let staging = config.declared_checks("staging").expect("staging");
    assert_eq!(staging.checks.len(), 1);
    // Present but empty, and absent, are the same: nothing to verify.
    assert!(config.for_environment("production").is_some());
    assert!(config.declared_checks("production").is_none());
    assert!(config.declared_checks("qa").is_none());
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
    // stays blocked until someone says what "serving correctly" means. Its
    // own deployment records the verification as skipped and stays green.
    assert!(config.for_environment("production").is_none());
    assert!(config.declared_checks("production").is_none());
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
