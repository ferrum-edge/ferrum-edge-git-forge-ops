//! Issue the declared checks against a data-plane base URL.
//!
//! This talks to the *data plane*, not the admin API: the question is whether
//! a client can reach the route that was just deployed, which is a different
//! question from whether the admin API accepted the write. The two even have
//! different URLs, so `FERRUM_VERIFY_BASE_URL` is its own setting rather than
//! a reuse of `FERRUM_GATEWAY_URL`.
//!
//! Every attempt is bounded and every retry is counted, because a promotion
//! gate that can hang is a promotion gate that is never blocked — it is just
//! late, indefinitely.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;

use super::{resolve_headers, CheckResult, EnvironmentChecks, Outcome, SmokeCheck, VerifyReport};

/// Build a client for one check. Each gets its own because the per-check
/// timeout is the bound that matters.
///
/// There is deliberately **no** `danger_accept_invalid_certs` here, and it is
/// not an oversight that `FERRUM_TLS_NO_VERIFY` does not reach it. A check
/// that accepts any certificate has not verified TLS; it has verified that
/// *something* answered. A promotion gate that passes against an interceptor
/// is worse than no gate, because it is believed.
///
/// A data plane behind a private CA is supported the way the admin client
/// supports it: give the CA. `FERRUM_GATEWAY_CA_CERT` is already an
/// environment secret and already bound in the workflow, so this is a
/// configuration the operator has rather than a check they have to weaken.
///
/// Redirects are **not** followed. A check states the status the route must
/// answer with, so a `301` is an answer to compare, not an instruction. And
/// following one would re-send the declared headers — including a resolved
/// credential slot in an ordinary header such as `X-API-Key`, which reqwest
/// does not strip — to whatever host the `Location` names.
fn client(check: &SmokeCheck, ca_cert: Option<&str>) -> crate::error::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(check.timeout())
        .connect_timeout(Duration::from_secs(check.timeout_secs.min(10)))
        .redirect(reqwest::redirect::Policy::none());

    if let Some(ca_b64) = ca_cert {
        let ca_pem = base64::engine::general_purpose::STANDARD
            .decode(ca_b64)
            .map_err(|error| {
                crate::error::Error::HttpClient(format!("verify CA cert decode: {error}"))
            })?;
        let certificate = reqwest::Certificate::from_pem(&ca_pem).map_err(|error| {
            crate::error::Error::HttpClient(format!("verify CA cert parse: {error}"))
        })?;
        builder = builder
            .add_root_certificate(certificate)
            .tls_built_in_root_certs(false);
    }

    builder
        .build()
        .map_err(|error| crate::error::Error::HttpClient(format!("verify client: {error}")))
}

fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// Run one check, retrying on an unreachable or timed-out attempt.
///
/// A *wrong status* is not retried: the gateway answered, and answering
/// differently later would mean the route is flapping, which is not a thing to
/// paper over with another attempt.
///
/// Nor is an ambiguous attempt of a request that is unsafe to replay. A
/// timeout, or a failure after the connection was established, says nothing
/// about whether the endpoint acted on the request; for a `POST`, a `PATCH` or
/// an extension method, sending it again could repeat the side effect and let
/// the second answer pass the check. Only a connection that was never
/// established — so carried no request — is retried for such a method, unless
/// the check declares `replay_safe`.
pub async fn run_check(
    base_url: &str,
    check: &SmokeCheck,
    bundle: &BTreeMap<String, String>,
    ca_cert: Option<&str>,
) -> CheckResult {
    let url = join(base_url, &check.path);
    let failed = |outcome: Outcome, attempts: u32, detail: String| CheckResult {
        name: check.name.clone(),
        method: check.method.clone(),
        path: check.path.clone(),
        expected_status: check.expect_status,
        actual_status: None,
        outcome,
        attempts,
        detail,
    };
    // Fail closed on a slot that is not in the bundle. Sending the request
    // without the credential would make a check that expects 401 pass for
    // entirely the wrong reason.
    let headers = match resolve_headers(&check.headers, bundle) {
        Ok(headers) => headers,
        Err(missing) => {
            return failed(
                Outcome::Unreachable,
                0,
                format!(
                    "credential slot(s) not in the bundle: {}",
                    missing.join(", ")
                ),
            )
        }
    };
    let mut last = Outcome::Unreachable;
    let mut detail = String::from("no attempt was made");
    let mut attempts = 0;
    let mut replay_refused = false;

    for attempt in 0..check.attempts {
        attempts = attempt + 1;
        if attempt > 0 {
            tokio::time::sleep(check.backoff(attempt)).await;
        }
        let client = match client(check, ca_cert) {
            Ok(client) => client,
            Err(error) => return failed(Outcome::Unreachable, attempts, error.to_string()),
        };
        let method = match reqwest::Method::from_bytes(check.method.as_bytes()) {
            Ok(method) => method,
            Err(_) => {
                return failed(
                    Outcome::Unreachable,
                    attempts,
                    "method is not an HTTP method".to_string(),
                )
            }
        };
        let mut request = client.request(method, &url);
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                // The body is deliberately never read: a failing route can
                // return anything, including a credential echoed back.
                return CheckResult {
                    name: check.name.clone(),
                    method: check.method.clone(),
                    path: check.path.clone(),
                    expected_status: check.expect_status,
                    actual_status: Some(status),
                    outcome: if status == check.expect_status {
                        Outcome::Passed
                    } else {
                        Outcome::Unexpected
                    },
                    attempts,
                    detail: format!("got {status}"),
                };
            }
            Err(error) => {
                if error.is_timeout() {
                    last = Outcome::TimedOut;
                    detail = format!("timed out after {}s", check.timeout_secs);
                } else {
                    last = Outcome::Unreachable;
                    // `reqwest`'s Display can carry the URL; the path is
                    // already reported and the base URL is an environment
                    // secret.
                    detail = if error.is_connect() {
                        "could not connect".to_string()
                    } else {
                        "request failed".to_string()
                    };
                }
                // Each attempt builds its own client, so there is no pooled
                // connection: a connect error means this request was never
                // written. Anything later may have reached the endpoint.
                if !error.is_connect() && !check.replays_ambiguous_attempts() {
                    replay_refused = true;
                    break;
                }
            }
        }
    }

    let detail = if replay_refused {
        format!(
            "{detail} on attempt {attempts}; not retried, because {} is not idempotent and \
             the endpoint may already have applied it (declare `replay_safe: true` only if \
             a replay is harmless)",
            check.method
        )
    } else {
        format!("{detail} after {attempts} attempt(s)")
    };
    CheckResult {
        name: check.name.clone(),
        method: check.method.clone(),
        path: check.path.clone(),
        expected_status: check.expect_status,
        actual_status: None,
        outcome: last,
        attempts,
        detail,
    }
}

pub async fn run(
    environment: &str,
    base_url: &str,
    checks: &EnvironmentChecks,
    bundle: &BTreeMap<String, String>,
    ca_cert: Option<&str>,
) -> VerifyReport {
    let mut results = Vec::with_capacity(checks.checks.len());
    for check in &checks.checks {
        results.push(run_check(base_url, check, bundle, ca_cert).await);
    }
    VerifyReport {
        environment: environment.to_string(),
        results,
    }
}
