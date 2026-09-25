//! Declarative traffic checks: did the gateway *serve* what we deployed?
//!
//! A successful apply proves the gateway accepted a configuration write. It
//! does not prove a route answers, that an upstream is reachable, or that
//! authentication is enforced — and promoting a revision to production on the
//! strength of "the write returned 200" is precisely the gap this closes.
//!
//! Two decisions shape the whole module.
//!
//! **The checks are data, never code.** `.gitforgeops/smoke.yaml` declares
//! requests and expected statuses; there is no hook, no shell, no plugin. A
//! promotion gate runs with deployment credentials in the environment, so an
//! arbitrary command in a repository file would be a way to spend them. A
//! closed, `deny_unknown_fields` schema is the whole execution surface.
//!
//! **Nothing sensitive is printed.** Header *values* may be broker
//! placeholders resolved from the credential bundle, so a check reports its
//! name, its method and path, the status it got and the status it wanted —
//! never a header value, never a response body. A failing check tells you
//! which route is wrong, not what a valid key looks like.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub mod runner;

pub const SMOKE_CONFIG_PATH: &str = ".gitforgeops/smoke.yaml";
/// The only smoke contract this release reads.
pub const SMOKE_CONFIG_VERSION: u32 = 1;

/// Exit code when a declared check did not pass. Distinct from 1 (the run
/// could not be performed at all), because a promotion gate has to tell
/// "verified and the answer is no" from "we never verified".
pub const VERIFY_FAILED_EXIT_CODE: i32 = 4;

fn default_version() -> u32 {
    SMOKE_CONFIG_VERSION
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_attempts() -> u32 {
    3
}

fn default_retry_backoff_ms() -> u64 {
    500
}

/// Where a header's value comes from.
///
/// Spelled out rather than inferred from string syntax. A check that sends a
/// credential and a check that sends a tenant id look identical as bare
/// strings, and the difference decides whether the value may be printed, so
/// the file states it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct HeaderValue {
    /// A non-secret value, safe in the repository and in a log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub literal: Option<String>,
    /// A credential-bundle slot, e.g. `ferrum/orders-client/keyauth/key`.
    /// Resolved from `FERRUM_CREDS_JSON_FILE` / `FERRUM_CREDS_JSON`; an
    /// unresolvable slot fails the check rather than sending an empty header,
    /// because an empty credential would make a 401-expecting check pass for
    /// entirely the wrong reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
}

impl HeaderValue {
    pub fn literal(value: impl Into<String>) -> Self {
        Self {
            literal: Some(value.into()),
            slot: None,
        }
    }

    pub fn slot(value: impl Into<String>) -> Self {
        Self {
            literal: None,
            slot: Some(value.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SmokeCheck {
    /// Printed in the report. Make it say what the check is for.
    pub name: String,
    #[serde(default = "default_method")]
    pub method: String,
    /// Appended to the environment's data-plane base URL.
    pub path: String,
    /// Header values, each either a literal or a credential-bundle slot.
    /// A slot's value is resolved at run time and never printed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, HeaderValue>,
    /// The status this route must answer with. A check that expects `401` is
    /// how you prove authentication is *enforced*, not merely configured.
    pub expect_status: u16,
    /// Per-attempt cap.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Total attempts, including the first. A freshly applied route can take a
    /// moment to become live, so the default retries; it is bounded because an
    /// unbounded wait is a hung promotion rather than a blocked one.
    ///
    /// A method that is not idempotent (see [`is_idempotent_method`]) spends
    /// further attempts only on a connection that was never established. A
    /// timeout or a failure after the request may have been sent is ambiguous
    /// — the endpoint may already have acted on it — so it ends the check
    /// unless `replay_safe` says a replay is harmless.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
    /// The operator's statement that replaying this request is harmless: the
    /// endpoint is idempotent, or it deduplicates. Only a method that is not
    /// idempotent by definition needs it. There is no inference from headers
    /// — an `Idempotency-Key` proves nothing about what the server does with
    /// it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replay_safe: bool,
}

/// Is `method` idempotent by definition (RFC 9110 §9.2.2)?
///
/// Exact, case-sensitive names only: HTTP methods are case-sensitive, so
/// `get` is an extension method, and an extension method's semantics are
/// unknown. Unknown is treated like `POST`.
pub fn is_idempotent_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentChecks {
    #[serde(default)]
    pub checks: Vec<SmokeCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub environments: BTreeMap<String, EnvironmentChecks>,
}

impl SmokeConfig {
    pub fn load_from_path(path: &Path) -> crate::error::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let contents =
            std::fs::read_to_string(path).map_err(|source| crate::error::Error::FileRead {
                path: path.to_path_buf(),
                source,
            })?;
        let config: SmokeConfig =
            serde_yaml::from_str(&contents).map_err(|source| crate::error::Error::YamlParse {
                path: path.to_path_buf(),
                source,
            })?;
        if config.version != SMOKE_CONFIG_VERSION {
            return Err(crate::error::Error::Config(format!(
                "unsupported smoke-check config version {} in {}; expected version {}",
                config.version,
                path.display(),
                SMOKE_CONFIG_VERSION
            )));
        }
        for (environment, entry) in &config.environments {
            for check in &entry.checks {
                check.validate(environment)?;
            }
        }
        Ok(Some(config))
    }

    pub fn load() -> crate::error::Result<Option<Self>> {
        Self::load_from_path(Path::new(SMOKE_CONFIG_PATH))
    }

    pub fn for_environment(&self, environment: &str) -> Option<&EnvironmentChecks> {
        self.environments.get(environment)
    }
}

impl SmokeCheck {
    fn validate(&self, environment: &str) -> crate::error::Result<()> {
        let refuse = |detail: String| {
            Err(crate::error::Error::Config(format!(
                "{SMOKE_CONFIG_PATH}: environment '{environment}', check '{}': {detail}",
                crate::diagnostics::sanitize_line(&self.name)
            )))
        };
        // A request line is built from these, and a method or path carrying a
        // control character would forge one.
        if !self
            .method
            .chars()
            .all(|c| c.is_ascii_alphabetic() || c == '-')
            || self.method.is_empty()
        {
            return refuse(format!(
                "method {:?} is not an HTTP method",
                crate::diagnostics::sanitize_line(&self.method)
            ));
        }
        if !self.path.starts_with('/') {
            return refuse("path must start with '/'".to_string());
        }
        if self.path.chars().any(|c| c.is_control() || c == ' ') {
            return refuse("path contains a control character or a space".to_string());
        }
        if self.attempts == 0 {
            return refuse("attempts must be at least 1".to_string());
        }
        // A check that can never run is a check that silently proves nothing.
        if self.timeout_secs == 0 {
            return refuse("timeout_secs must be at least 1".to_string());
        }
        if !(100..=599).contains(&self.expect_status) {
            return refuse(format!(
                "expect_status {} is not an HTTP status code",
                self.expect_status
            ));
        }
        for (name, value) in &self.headers {
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return refuse(format!(
                    "header name {:?} is not a token",
                    crate::diagnostics::sanitize_line(name)
                ));
            }
            // Exactly one source, stated. "Neither" would send nothing and
            // "both" would hide which one the request actually carried, and
            // both are silent in a schema that merely accepts either shape.
            match (&value.literal, &value.slot) {
                (Some(_), Some(_)) => {
                    return refuse(format!(
                        "header {:?} sets both `literal` and `slot`; it must name one source",
                        crate::diagnostics::sanitize_line(name)
                    ));
                }
                (None, None) => {
                    return refuse(format!(
                        "header {:?} sets neither `literal` nor `slot`",
                        crate::diagnostics::sanitize_line(name)
                    ));
                }
                (Some(literal), None) if literal.chars().any(char::is_control) => {
                    return refuse(format!(
                        "header {:?} has a literal value containing a control character",
                        crate::diagnostics::sanitize_line(name)
                    ));
                }
                (None, Some(slot)) if slot.trim().is_empty() => {
                    return refuse(format!(
                        "header {:?} names an empty credential slot",
                        crate::diagnostics::sanitize_line(name)
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    pub fn backoff(&self, attempt: u32) -> Duration {
        Duration::from_millis(self.retry_backoff_ms.saturating_mul(u64::from(attempt)))
    }

    /// May an attempt whose outcome is unknown — a timeout, or a failure after
    /// the request may have reached the server — be sent again?
    ///
    /// A slow response to a `POST` is not evidence that nothing happened; the
    /// endpoint may have committed it and lost only the reply. Replaying it
    /// would repeat the side effect, and a later success would then read as a
    /// clean pass.
    pub fn replays_ambiguous_attempts(&self) -> bool {
        self.replay_safe || is_idempotent_method(&self.method)
    }
}

/// Turn declared header values into the exact bytes to send.
///
/// Returns the unresolvable slot names on failure — names only; a bundle value
/// never appears in an error, and the caller reports the check as failed
/// rather than sending the request without the credential.
pub fn resolve_headers(
    headers: &BTreeMap<String, HeaderValue>,
    bundle: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>, Vec<String>> {
    let mut resolved = Vec::with_capacity(headers.len());
    let mut missing = Vec::new();
    for (name, value) in headers {
        match (&value.literal, &value.slot) {
            (Some(literal), None) => resolved.push((name.clone(), literal.clone())),
            (None, Some(slot)) => match bundle.get(slot) {
                Some(secret) => resolved.push((name.clone(), secret.clone())),
                None => missing.push(slot.clone()),
            },
            // Refused at load; treat as unresolvable rather than guessing.
            _ => missing.push(format!("<header {name}: exactly one of literal/slot>")),
        }
    }
    if missing.is_empty() {
        Ok(resolved)
    } else {
        missing.sort();
        Err(missing)
    }
}

/// Why a check did not pass. The distinction is what a promotion gate acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The route answered with the expected status.
    Passed,
    /// The route answered, with the wrong status.
    Unexpected,
    /// Every attempt timed out.
    TimedOut,
    /// The route could not be reached at all.
    Unreachable,
}

impl Outcome {
    pub fn passed(self) -> bool {
        matches!(self, Outcome::Passed)
    }

    pub fn label(self) -> &'static str {
        match self {
            Outcome::Passed => "PASS",
            Outcome::Unexpected => "UNEXPECTED",
            Outcome::TimedOut => "TIMEOUT",
            Outcome::Unreachable => "UNREACHABLE",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub method: String,
    pub path: String,
    pub expected_status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_status: Option<u16>,
    pub outcome: Outcome,
    pub attempts: u32,
    /// Never a response body and never a header value.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub environment: String,
    pub results: Vec<CheckResult>,
}

impl VerifyReport {
    pub fn passed(&self) -> bool {
        self.results.iter().all(|result| result.outcome.passed())
    }

    /// A configured environment with no declared check has verified nothing,
    /// which a promotion gate must not read as a pass.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    pub fn exit_code(&self) -> i32 {
        if self.passed() && !self.is_empty() {
            0
        } else {
            VERIFY_FAILED_EXIT_CODE
        }
    }

    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "=== Traffic verification: {} ===",
            crate::diagnostics::sanitize_line(&self.environment)
        );
        if self.results.is_empty() {
            let _ = writeln!(
                out,
                "No checks are declared for this environment in {SMOKE_CONFIG_PATH}. \
                 A gateway that accepted a configuration write has not been shown to \
                 serve it; declare at least one representative route."
            );
            return out;
        }
        for result in &self.results {
            let _ = writeln!(
                out,
                "{:<11} {} {} {} -> expected {}, {}",
                result.outcome.label(),
                crate::diagnostics::sanitize_line(&result.name),
                crate::diagnostics::sanitize_line(&result.method),
                crate::diagnostics::sanitize_line(&result.path),
                result.expected_status,
                crate::diagnostics::sanitize_line(&result.detail),
            );
        }
        let passed = self
            .results
            .iter()
            .filter(|result| result.outcome.passed())
            .count();
        let _ = writeln!(out, "\n{passed} of {} checks passed.", self.results.len());
        let _ = writeln!(
            out,
            "{}",
            if self.passed() {
                "The gateway is serving this revision."
            } else {
                "The gateway accepted the configuration write; it is not serving it \
                 as declared. Configuration acceptance and healthy traffic are not \
                 the same result."
            }
        );
        out
    }
}
