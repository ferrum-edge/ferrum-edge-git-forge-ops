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
//!
//! Two bounds follow from the job these checks run in.
//!
//! **A check spends only a probe credential.** The environment's credential
//! bundle holds every Consumer, plugin-config and service-discovery secret.
//! A `slot:` header is honoured only when it names a brokered secret of a
//! Consumer that the operator lists in [`VERIFY_PROBE_CONSUMERS_ENV`] (a
//! GitHub Environment variable, outside anything a merge can change) **and**
//! the environment's desired configuration labels
//! [`VERIFY_PROBE_LABEL`]` = "true"`. `verify` hands the runner a projection
//! holding exactly those values ([`authorize_probe_slots`]); anything else
//! refuses the run before the bundle is read or a request is sent. The label
//! alone authorizes nothing: it lives in `resources/`, which the same pull
//! request that names the slot can change.
//!
//! **A check spends a bounded amount of time.** Verification runs after the
//! gateway changed and before the ownership ledger is committed, in the
//! environment's serialized deployment job. Per-check limits, a per-environment
//! check count and an aggregate worst-case budget are refused at load, and the
//! runner holds the whole run to an outer deadline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::schema::{is_known_credential_type, KNOWN_CREDENTIAL_TYPES};
use crate::config::{read_bounded_repo_file, GatewayConfig, MAX_REPO_CONFIG_FILE_BYTES};
use crate::secrets::parse_placeholder;
use crate::secrets::plugin_config::ConfigPathComponent;
use crate::secrets::resolver::{
    consumer_credential_slot, credential_type_from_slot, escape_slot_component,
    is_identity_credential_leaf,
};

pub mod runner;

pub const SMOKE_CONFIG_PATH: &str = ".gitforgeops/smoke.yaml";
/// The smoke contract this release writes and reads in full.
///
/// Version 2 is the contract in which a `slot:` names only an operator
/// allowlisted, labelled probe Consumer's credential.
pub const SMOKE_CONFIG_VERSION: u32 = 2;
/// The earlier contract, under which a `slot:` could name any credential in
/// the environment's bundle. A file at this version (or with no `version`)
/// still loads when it sends no credential; one that names a slot is refused,
/// so every slot written under the old meaning is reviewed again.
pub const LEGACY_SMOKE_CONFIG_VERSION: u32 = 1;

/// Exit code when a declared check did not pass. Distinct from 1 (the run
/// could not be performed at all), because a promotion gate has to tell
/// "verified and the answer is no" from "we never verified".
pub const VERIFY_FAILED_EXIT_CODE: i32 = 4;

/// Exit code when no check is declared for the environment: `smoke.yaml` is
/// absent, has no entry for it, or its entry lists no checks. Nothing was
/// verified and nothing failed. Non-zero, so a caller that ignores the
/// distinction still does not read it as a pass; distinct from 4 and 1, so a
/// deployment job can record it as `skipped` rather than failing on it.
pub const VERIFY_SKIPPED_EXIT_CODE: i32 = 5;

/// Most attempts one check may make, including the first.
pub const MAX_CHECK_ATTEMPTS: u32 = 10;
/// Longest one attempt may wait for an answer.
pub const MAX_CHECK_TIMEOUT_SECS: u64 = 60;
/// Largest base delay between attempts. The delay grows linearly with the
/// attempt number, so no pause exceeds `MAX_CHECK_ATTEMPTS - 1` times it.
pub const MAX_CHECK_RETRY_BACKOFF_MS: u64 = 30_000;
/// Most checks one environment may declare.
pub const MAX_CHECKS_PER_ENVIRONMENT: usize = 50;
/// Longest an environment's checks may take together when every attempt of
/// every check times out ([`EnvironmentChecks::worst_case_budget`]).
///
/// Verification runs after the gateway changed and before the ownership
/// ledger is committed, while the environment's deployment concurrency group
/// is held. A budget nobody bounded is a deployment nobody can finish.
pub const MAX_ENVIRONMENT_VERIFY_BUDGET_SECS: u64 = 15 * 60;
/// Slack the runner's outer deadline allows past the declared worst case, for
/// client construction and scheduling. The deadline is never a pass: a check
/// it interrupts is reported as timed out.
pub const VERIFY_DEADLINE_GRACE_SECS: u64 = 30;

/// The Consumer label that makes its brokered secrets spendable by a traffic
/// check. The value must be exactly `"true"`.
///
/// A check runs in a job that holds the environment's whole credential
/// bundle. Without this opt-in, a merged `smoke.yaml` could send any
/// customer's key, a plugin's upstream token or a service-discovery secret to
/// a route the same change declared. Put the label on a dedicated,
/// low-privilege Consumer that exists to be probed, never on a customer.
pub const VERIFY_PROBE_LABEL: &str = "gitforgeops/verify-probe";

/// The operator-held allowlist of probe Consumers: a comma-separated list of
/// `<namespace>/<consumer-id>` entries.
///
/// Bound from a GitHub Environment variable of the same name
/// (`vars.FERRUM_VERIFY_PROBE_CONSUMERS`), which only a repository
/// administrator can set and no merge can change. `verify` refuses every check
/// that sends a slot while it is unset or empty, and every slot whose Consumer
/// it does not list. [`VERIFY_PROBE_LABEL`] is required as well, but a label
/// is repository content and authorizes nothing by itself.
pub const VERIFY_PROBE_CONSUMERS_ENV: &str = "FERRUM_VERIFY_PROBE_CONSUMERS";

/// Headers a check may not set, compared case-insensitively with `_` read as
/// `-`. `Host` and the forwarding headers would steer a request (and a
/// credential) to a different virtual host or misstate its origin; the
/// method-override headers would turn a `GET` probe into a `DELETE` at any
/// upstream that honours them; the hop-by-hop and framing headers belong to
/// the client, not the check.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "forwarded",
    "via",
    "x-real-ip",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

fn is_reserved_header(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    RESERVED_HEADERS.contains(&normalized.as_str()) || normalized.starts_with("x-forwarded-")
}

/// May a check that sends a credential use `method`? Only the two methods
/// that read without acting, so a probe credential cannot be spent on a side
/// effect.
fn is_credential_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

/// A file that does not state its version is read as the earlier contract,
/// so a slot written under the old meaning cannot slip past by omission.
fn default_version() -> u32 {
    LEGACY_SMOKE_CONFIG_VERSION
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
    /// A Consumer credential slot, e.g. `ferrum/orders-probe/keyauth/key`.
    ///
    /// Only a brokered secret of a Consumer the operator lists in
    /// [`VERIFY_PROBE_CONSUMERS_ENV`] and the environment's desired
    /// configuration labels [`VERIFY_PROBE_LABEL`]` = "true"` is honoured, and
    /// only on a `GET` or `HEAD` check; plugin-config and service-discovery
    /// slots never are. Resolved from
    /// `FERRUM_CREDS_JSON_FILE` / `FERRUM_CREDS_JSON`; an unresolvable slot
    /// fails the check rather than sending an empty header, because an empty
    /// credential would make a 401-expecting check pass for entirely the
    /// wrong reason.
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
    /// Per-attempt cap, at most [`MAX_CHECK_TIMEOUT_SECS`].
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Total attempts, including the first. A freshly applied route can take a
    /// moment to become live, so the default retries; it is bounded (at most
    /// [`MAX_CHECK_ATTEMPTS`]) because an unbounded wait is a hung promotion
    /// rather than a blocked one.
    ///
    /// A method that is not idempotent (see [`is_idempotent_method`]) spends
    /// further attempts only on a connection that was never established. A
    /// timeout or a failure after the request may have been sent is ambiguous
    /// — the endpoint may already have acted on it — so it ends the check
    /// unless `replay_safe` says a replay is harmless.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    /// Base delay between attempts, at most [`MAX_CHECK_RETRY_BACKOFF_MS`];
    /// the pause before attempt `n + 1` is `n` times it.
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

impl EnvironmentChecks {
    /// The longest these checks can take together: the sum of each check's
    /// [`SmokeCheck::worst_case_budget`], because they run one after another.
    pub fn worst_case_budget(&self) -> Duration {
        let mut total = Duration::ZERO;
        for check in &self.checks {
            total = total.saturating_add(check.worst_case_budget());
        }
        total
    }

    /// Does any check send a credential-bundle slot?
    pub fn sends_credentials(&self) -> bool {
        self.checks.iter().any(SmokeCheck::sends_credential)
    }
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
        let Some(contents) = read_bounded_repo_file(path, MAX_REPO_CONFIG_FILE_BYTES)? else {
            return Ok(None);
        };
        let config: SmokeConfig =
            serde_yaml::from_str(&contents).map_err(|source| crate::error::Error::YamlParse {
                path: path.to_path_buf(),
                source,
            })?;
        match config.version {
            SMOKE_CONFIG_VERSION => {}
            // Under version 1 a slot could name any credential in the
            // bundle. Such a file is refused rather than reinterpreted, so a
            // reviewer decides again what each slot may send.
            LEGACY_SMOKE_CONFIG_VERSION => {
                if config
                    .environments
                    .values()
                    .any(EnvironmentChecks::sends_credentials)
                {
                    return Err(crate::error::Error::Config(format!(
                        "{}: smoke-check config version {LEGACY_SMOKE_CONFIG_VERSION} (or no \
                         `version`) names a credential slot. Under that contract a slot could \
                         name any credential in the environment's bundle; version \
                         {SMOKE_CONFIG_VERSION} sends only the credential of a dedicated probe \
                         Consumer that the operator lists in {VERIFY_PROBE_CONSUMERS_ENV} and \
                         the desired configuration labels `{VERIFY_PROBE_LABEL}: \"true\"`. \
                         Review every slot again, then declare `version: {SMOKE_CONFIG_VERSION}`.",
                        path.display()
                    )));
                }
            }
            other => {
                return Err(crate::error::Error::Config(format!(
                    "unsupported smoke-check config version {other} in {}; expected version \
                     {SMOKE_CONFIG_VERSION}",
                    path.display()
                )));
            }
        }
        for (environment, entry) in &config.environments {
            entry.validate(environment)?;
        }
        Ok(Some(config))
    }

    pub fn load() -> crate::error::Result<Option<Self>> {
        Self::load_from_path(Path::new(SMOKE_CONFIG_PATH))
    }

    pub fn for_environment(&self, environment: &str) -> Option<&EnvironmentChecks> {
        self.environments.get(environment)
    }

    /// The checks `environment` declares, or `None` when it declares none —
    /// no entry and an empty `checks:` list alike. `verify` reports that as
    /// skipped: never a pass, and never a failed check.
    pub fn declared_checks(&self, environment: &str) -> Option<&EnvironmentChecks> {
        self.for_environment(environment)
            .filter(|entry| !entry.checks.is_empty())
    }
}

impl EnvironmentChecks {
    fn validate(&self, environment: &str) -> crate::error::Result<()> {
        let refuse = |detail: String| {
            Err(crate::error::Error::Config(format!(
                "{SMOKE_CONFIG_PATH}: environment '{}': {detail}",
                crate::diagnostics::sanitize_line(environment)
            )))
        };
        if self.checks.len() > MAX_CHECKS_PER_ENVIRONMENT {
            return refuse(format!(
                "declares {} checks; at most {MAX_CHECKS_PER_ENVIRONMENT} are allowed",
                self.checks.len()
            ));
        }
        for check in &self.checks {
            check.validate(environment)?;
        }
        // Checks run one after another, after the gateway changed and before
        // the ledger is committed. Each may be within its own limits and the
        // set still hold the deployment for hours.
        let budget = self.worst_case_budget();
        if budget > Duration::from_secs(MAX_ENVIRONMENT_VERIFY_BUDGET_SECS) {
            return refuse(format!(
                "the checks' worst-case duration is {}s (every attempt timing out, plus \
                 backoff), above the {MAX_ENVIRONMENT_VERIFY_BUDGET_SECS}s limit per \
                 environment; lower attempts, timeout_secs or retry_backoff_ms, or declare \
                 fewer checks",
                budget.as_secs()
            ));
        }
        Ok(())
    }
}

/// Why `slot` cannot name a probe credential, judged from its spelling alone,
/// or `None` when it has the shape of a Consumer credential secret slot:
/// `<namespace>/<consumer-id>/<credential-type>/<field>…`.
///
/// This is the half of the binding `load` can decide without the assembled
/// configuration. [`bind_probe_slots`] and [`authorize_probe_slots`] decide
/// the rest.
fn slot_shape_refusal(slot: &str) -> Option<String> {
    if slot.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Some("contains whitespace or a control character".to_string());
    }
    let components: Vec<&str> = slot.split('/').collect();
    if components.len() < 4 || components.iter().any(|component| component.is_empty()) {
        return Some(
            "is not a Consumer credential slot \
             (<namespace>/<consumer-id>/<credential-type>/<field>)"
                .to_string(),
        );
    }
    let credential_type = credential_type_from_slot(slot).unwrap_or_default();
    if !is_known_credential_type(&credential_type) {
        return Some(format!(
            "names {:?}, not a Consumer credential type ({}); plugin-config and \
             service-discovery secrets are never sent by a traffic check",
            crate::diagnostics::sanitize_line(&credential_type),
            KNOWN_CREDENTIAL_TYPES.join(", ")
        ));
    }
    let leaf = components.last().copied();
    if is_identity_credential_leaf(&credential_type, leaf) {
        return Some("names a credential identity, not a secret".to_string());
    }
    None
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
        if self.attempts > MAX_CHECK_ATTEMPTS {
            return refuse(format!(
                "attempts {} is above the maximum of {MAX_CHECK_ATTEMPTS}",
                self.attempts
            ));
        }
        // A check that can never run is a check that silently proves nothing.
        if self.timeout_secs == 0 {
            return refuse("timeout_secs must be at least 1".to_string());
        }
        if self.timeout_secs > MAX_CHECK_TIMEOUT_SECS {
            return refuse(format!(
                "timeout_secs {} is above the maximum of {MAX_CHECK_TIMEOUT_SECS}",
                self.timeout_secs
            ));
        }
        if self.retry_backoff_ms > MAX_CHECK_RETRY_BACKOFF_MS {
            return refuse(format!(
                "retry_backoff_ms {} is above the maximum of {MAX_CHECK_RETRY_BACKOFF_MS}",
                self.retry_backoff_ms
            ));
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
            if is_reserved_header(name) {
                return refuse(format!(
                    "header {:?} is reserved: a check may not set Host, forwarding, \
                     method-override, hop-by-hop or framing headers",
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
                (None, Some(slot)) => {
                    if let Some(reason) = slot_shape_refusal(slot) {
                        return refuse(format!(
                            "header {:?}: slot {:?} {reason}",
                            crate::diagnostics::sanitize_line(name),
                            crate::diagnostics::sanitize_line(slot)
                        ));
                    }
                    // A probe credential reads a route; it is never spent on a
                    // request that may act on the endpoint.
                    if !is_credential_method(&self.method) {
                        return refuse(format!(
                            "header {:?} sends a credential slot, so the method must be GET \
                             or HEAD, not {:?}",
                            crate::diagnostics::sanitize_line(name),
                            crate::diagnostics::sanitize_line(&self.method)
                        ));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Does this check send a credential-bundle slot?
    pub fn sends_credential(&self) -> bool {
        self.headers.values().any(|value| value.slot.is_some())
    }

    /// The longest this check can take: every attempt running to
    /// `timeout_secs`, plus every backoff pause between them.
    pub fn worst_case_budget(&self) -> Duration {
        let attempts = u64::from(self.attempts);
        let per_attempt_ms = self.timeout_secs.saturating_mul(1000);
        let requests = attempts.saturating_mul(per_attempt_ms);
        // The pause before attempt `n + 1` is `n * retry_backoff_ms`, for
        // n = 1..attempts-1: an arithmetic series.
        let pause_units = attempts.saturating_sub(1).saturating_mul(attempts) / 2;
        let pauses = self.retry_backoff_ms.saturating_mul(pause_units);
        Duration::from_millis(requests.saturating_add(pauses))
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

/// The credential values a verification run may send: brokered secrets of
/// allowlisted, labelled probe Consumers that a declared check names, and
/// nothing else.
///
/// Built only by [`ProbeAuthorization::project`] (or empty, by
/// [`ProbeCredentials::none`]), so neither [`runner::run`] nor
/// [`runner::run_check`] can ever be handed the environment's whole bundle.
#[derive(Default)]
pub struct ProbeCredentials {
    values: BTreeMap<String, String>,
}

impl ProbeCredentials {
    /// No credential at all, for checks that send none.
    pub fn none() -> Self {
        Self::default()
    }

    /// The authorized slots that had a bundle value, by name. Never the values.
    pub fn slots(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    pub(crate) fn values(&self) -> &BTreeMap<String, String> {
        &self.values
    }
}

// Hand-written so a debug print can never carry a value.
impl std::fmt::Debug for ProbeCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeCredentials")
            .field("slots", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The operator-held list of Consumers whose credentials a traffic check may
/// send, parsed from [`VERIFY_PROBE_CONSUMERS_ENV`].
///
/// Entries are `<namespace>/<consumer-id>`, separated by commas; surrounding
/// whitespace and empty entries are ignored. Names only: the list holds no
/// credential and may appear in a diagnostic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeConsumerAllowlist {
    consumers: BTreeSet<String>,
}

impl ProbeConsumerAllowlist {
    /// Parse the variable's value. A malformed entry is refused rather than
    /// skipped, so a typo surfaces instead of silently allowing nothing.
    pub fn parse(raw: &str) -> crate::error::Result<Self> {
        let mut consumers = BTreeSet::new();
        for entry in raw.split(',').map(str::trim) {
            if entry.is_empty() {
                continue;
            }
            let qualified = entry
                .split_once('/')
                .is_some_and(|(namespace, id)| !namespace.is_empty() && !id.is_empty());
            let clean = !entry.chars().any(|c| c.is_control() || c.is_whitespace());
            if !qualified || !clean {
                return Err(crate::error::Error::Config(format!(
                    "{VERIFY_PROBE_CONSUMERS_ENV}: entry {:?} is not \
                     <namespace>/<consumer-id>; list probe Consumers as a comma-separated \
                     list such as ferrum/orders-probe",
                    crate::diagnostics::sanitize_line(entry)
                )));
            }
            consumers.insert(entry.to_string());
        }
        Ok(Self { consumers })
    }

    /// Does the list name the Consumer `namespace`/`consumer_id`?
    pub fn contains(&self, namespace: &str, consumer_id: &str) -> bool {
        self.consumers
            .contains(&format!("{namespace}/{consumer_id}"))
    }

    pub fn is_empty(&self) -> bool {
        self.consumers.is_empty()
    }

    /// The listed Consumers, as `<namespace>/<consumer-id>`.
    pub fn consumers(&self) -> impl Iterator<Item = &str> {
        self.consumers.iter().map(String::as_str)
    }
}

/// The Consumer a brokered credential slot belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SlotOwner {
    namespace: String,
    consumer_id: String,
    labelled: bool,
}

impl SlotOwner {
    fn qualified(&self) -> String {
        format!("{}/{}", self.namespace, self.consumer_id)
    }

    /// The label half, then the allowlist half when this run can see it.
    fn binding_status(&self, allowlist: Option<&ProbeConsumerAllowlist>) -> BindingStatus {
        if !self.labelled {
            return BindingStatus::NotLabelled;
        }
        match allowlist {
            None => BindingStatus::AllowlistNotVisible,
            Some(list) if list.contains(&self.namespace, &self.consumer_id) => {
                BindingStatus::Approved
            }
            Some(_) => BindingStatus::NotAllowlisted,
        }
    }
}

/// Every brokered (`${gh-env-secret:…}`) secret leaf of every Consumer in
/// `desired`, in the canonical slot spelling, with the Consumer it belongs to.
///
/// Identity leaves (`basicauth.username`, `mtls_auth.identity`), unknown
/// credential types and literal values are never slots, and no plugin-config
/// or service-discovery slot can be produced here.
fn consumer_secret_slots(desired: &GatewayConfig) -> BTreeMap<String, SlotOwner> {
    let mut owners = BTreeMap::new();
    for consumer in &desired.consumers {
        if consumer.id.is_empty() || consumer.namespace.is_empty() {
            continue;
        }
        let mut slots = BTreeSet::new();
        for (credential_type, value) in &consumer.credentials {
            if !is_known_credential_type(credential_type) {
                continue;
            }
            collect_brokered_secret_slots(
                &consumer.namespace,
                &consumer.id,
                credential_type,
                value,
                &mut Vec::new(),
                None,
                &mut slots,
            );
        }
        let owner = SlotOwner {
            namespace: consumer.namespace.clone(),
            consumer_id: consumer.id.clone(),
            labelled: is_probe_consumer(&consumer.labels),
        };
        for slot in slots {
            owners.insert(slot, owner.clone());
        }
    }
    owners
}

/// Every slot of a Consumer labelled [`VERIFY_PROBE_LABEL`]` = "true"` in
/// `desired`: the label half of the binding. A slot must also belong to a
/// Consumer in the operator's [`ProbeConsumerAllowlist`] before `verify`
/// sends it.
pub fn probe_credential_slots(desired: &GatewayConfig) -> BTreeSet<String> {
    consumer_secret_slots(desired)
        .into_iter()
        .filter(|(_, owner)| owner.labelled)
        .map(|(slot, _)| slot)
        .collect()
}

/// The Consumers `desired` labels [`VERIFY_PROBE_LABEL`]` = "true"`, as
/// `<namespace>/<consumer-id>`, so a review shows every label a change adds.
pub fn labelled_probe_consumers(desired: &GatewayConfig) -> Vec<String> {
    let labelled: BTreeSet<String> = desired
        .consumers
        .iter()
        .filter(|consumer| is_probe_consumer(&consumer.labels))
        .map(|consumer| format!("{}/{}", consumer.namespace, consumer.id))
        .collect();
    labelled.into_iter().collect()
}

/// Exactly `"true"`: a label that merely looks like consent is not consent.
fn is_probe_consumer(labels: &BTreeMap<String, String>) -> bool {
    labels.get(VERIFY_PROBE_LABEL).map(String::as_str) == Some("true")
}

fn collect_brokered_secret_slots(
    namespace: &str,
    consumer_id: &str,
    credential_type: &str,
    value: &serde_json::Value,
    path: &mut Vec<ConfigPathComponent>,
    leaf: Option<&str>,
    slots: &mut BTreeSet<String>,
) {
    match value {
        serde_json::Value::String(text) => {
            let brokered = matches!(parse_placeholder(text), Some(Ok(_)));
            if brokered && !is_identity_credential_leaf(credential_type, leaf) {
                slots.insert(consumer_credential_slot(
                    namespace,
                    consumer_id,
                    credential_type,
                    path.as_slice(),
                ));
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                collect_brokered_secret_slots(
                    namespace,
                    consumer_id,
                    credential_type,
                    item,
                    path,
                    leaf,
                    slots,
                );
                path.pop();
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                path.push(ConfigPathComponent::Key(key.clone()));
                collect_brokered_secret_slots(
                    namespace,
                    consumer_id,
                    credential_type,
                    item,
                    path,
                    Some(key.as_str()),
                    slots,
                );
                path.pop();
            }
        }
        _ => {}
    }
}

/// How one `slot:` header binds to the environment's Consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingStatus {
    /// A brokered secret of a labelled Consumer the operator allowlists, sent
    /// by a `GET` or `HEAD` check: `verify` may send it.
    Approved,
    /// Labelled, but the operator allowlist is not visible to this run, so
    /// `verify` decides the allowlist half. Not a refusal here.
    AllowlistNotVisible,
    /// The slot is in a namespace this run did not select, so its Consumer
    /// is not in this run's desired configuration. Not judged here.
    OutsideNamespaceScope,
    /// Not the shape of a Consumer credential secret slot.
    InvalidSlot,
    /// Sent by a check whose method is not `GET` or `HEAD`.
    NotReadOnlyMethod,
    /// Not a brokered secret of any Consumer in the desired configuration.
    NotAConsumerSecret,
    /// The Consumer does not carry [`VERIFY_PROBE_LABEL`]` = "true"`.
    NotLabelled,
    /// The Consumer is not in the operator's [`VERIFY_PROBE_CONSUMERS_ENV`].
    NotAllowlisted,
}

impl BindingStatus {
    /// Does this binding stop the run?
    pub fn is_refusal(self) -> bool {
        !matches!(
            self,
            BindingStatus::Approved
                | BindingStatus::AllowlistNotVisible
                | BindingStatus::OutsideNamespaceScope
        )
    }

    /// Fixed wording: nothing from the repository or the environment.
    pub fn describe(self) -> &'static str {
        match self {
            BindingStatus::Approved => "approved probe credential",
            BindingStatus::AllowlistNotVisible => {
                "labelled probe Consumer; the operator allowlist is not visible to this run"
            }
            BindingStatus::OutsideNamespaceScope => {
                "in a namespace this run did not select; not judged here"
            }
            BindingStatus::InvalidSlot => "is not a Consumer credential secret slot",
            BindingStatus::NotReadOnlyMethod => {
                "is sent by a check whose method is not GET or HEAD"
            }
            BindingStatus::NotAConsumerSecret => {
                "is not a brokered secret of a Consumer in this environment's desired \
                 configuration"
            }
            BindingStatus::NotLabelled => {
                "belongs to a Consumer not labelled `gitforgeops/verify-probe: \"true\"`"
            }
            BindingStatus::NotAllowlisted => {
                "belongs to a Consumer the operator does not list in \
                 FERRUM_VERIFY_PROBE_CONSUMERS"
            }
        }
    }
}

/// One `slot:` header of a declared check, the Consumer it would spend, and
/// whether it may. Names only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlotBinding {
    pub check: String,
    pub header: String,
    pub slot: String,
    /// `<namespace>/<consumer-id>` of the Consumer whose brokered secret the
    /// slot names, when the desired configuration declares one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    pub status: BindingStatus,
}

/// Bind every `slot:` header in `checks` to the Consumer of `desired` it
/// would spend.
///
/// `allowlist` is the operator's [`ProbeConsumerAllowlist`] when this run can
/// see it, and `None` when it cannot (a pull request's `validate` or `plan`),
/// in which case a labelled Consumer reads as
/// [`BindingStatus::AllowlistNotVisible`]. `verify` always passes it.
/// `namespace_filter` is the run's namespace selection: a slot outside it is
/// [`BindingStatus::OutsideNamespaceScope`] rather than a false refusal.
pub fn bind_probe_slots(
    checks: &EnvironmentChecks,
    desired: &GatewayConfig,
    allowlist: Option<&ProbeConsumerAllowlist>,
    namespace_filter: Option<&str>,
) -> Vec<SlotBinding> {
    let owners = consumer_secret_slots(desired);
    let selected_namespace = namespace_filter.map(escape_slot_component);
    let mut bindings = Vec::new();
    for check in &checks.checks {
        for (header, value) in &check.headers {
            let Some(slot) = &value.slot else {
                continue;
            };
            let owner = owners.get(slot);
            // The first slot component is the escaped namespace.
            let in_scope = match &selected_namespace {
                Some(selected) => slot.split('/').next() == Some(selected.as_str()),
                None => true,
            };
            let status = if slot_shape_refusal(slot).is_some() {
                BindingStatus::InvalidSlot
            } else if !is_credential_method(&check.method) {
                BindingStatus::NotReadOnlyMethod
            } else if let Some(owner) = owner {
                owner.binding_status(allowlist)
            } else if in_scope {
                BindingStatus::NotAConsumerSecret
            } else {
                BindingStatus::OutsideNamespaceScope
            };
            bindings.push(SlotBinding {
                check: check.name.clone(),
                header: header.clone(),
                slot: slot.clone(),
                consumer: owner.map(SlotOwner::qualified),
                status,
            });
        }
    }
    bindings
}

/// Refuse when any binding is a refusal. The error names checks, headers,
/// slots and Consumers; it never carries a credential value.
pub fn refuse_unbound_slots(
    environment: &str,
    bindings: &[SlotBinding],
) -> crate::error::Result<()> {
    let mut refusals: Vec<String> = bindings
        .iter()
        .filter(|binding| binding.status.is_refusal())
        .map(refusal_line)
        .collect();
    if refusals.is_empty() {
        return Ok(());
    }
    refusals.sort();
    refusals.dedup();
    Err(crate::error::Error::Config(format!(
        "{SMOKE_CONFIG_PATH}: environment '{}': a traffic check may send only a credential \
         of a dedicated verification probe Consumer; no request was sent.\n  - {}\n\
         Create a dedicated, low-privilege Consumer with a brokered ${{gh-env-secret:...}} \
         credential, label it `{VERIFY_PROBE_LABEL}: \"true\"`, ask a repository \
         administrator to add it as <namespace>/<consumer-id> to the \
         {VERIFY_PROBE_CONSUMERS_ENV} variable of this GitHub Environment, and name that \
         slot. Never label or list a customer Consumer.",
        crate::diagnostics::sanitize_line(environment),
        refusals.join("\n  - ")
    )))
}

fn refusal_line(binding: &SlotBinding) -> String {
    use crate::diagnostics::sanitize_line;
    let consumer = match &binding.consumer {
        Some(consumer) => format!(" (Consumer {:?})", sanitize_line(consumer)),
        None => String::new(),
    };
    format!(
        "check {:?}, header {:?}: slot {:?}{consumer} {}",
        sanitize_line(&binding.check),
        sanitize_line(&binding.header),
        sanitize_line(&binding.slot),
        binding.status.describe()
    )
}

/// The slots a verification run may send, decided from the desired
/// configuration and the operator allowlist before any bundle is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeAuthorization {
    slots: BTreeSet<String>,
}

impl ProbeAuthorization {
    /// The authorized slots, by name.
    pub fn slots(&self) -> impl Iterator<Item = &str> {
        self.slots.iter().map(String::as_str)
    }

    /// Project `bundle` down to the authorized slots. An authorized slot the
    /// bundle lacks is left out, so its check fails as unresolvable.
    pub fn project(&self, bundle: &BTreeMap<String, String>) -> ProbeCredentials {
        let mut values = BTreeMap::new();
        for slot in &self.slots {
            if let Some(secret) = bundle.get(slot) {
                values.insert(slot.clone(), secret.clone());
            }
        }
        ProbeCredentials { values }
    }
}

/// Bind every credential `checks` would send to an allowlisted, labelled
/// verification probe Consumer of `desired`.
///
/// Fails closed, before the bundle is read and before any request, when a
/// check sends a slot while `allowlist` is absent or empty, or names a slot
/// that is not a brokered secret of a Consumer both listed in the operator's
/// [`VERIFY_PROBE_CONSUMERS_ENV`] and labelled [`VERIFY_PROBE_LABEL`]` =
/// "true"`, or sends one with a method other than `GET` or `HEAD`. Checks
/// that send no slot need no allowlist.
pub fn authorize_probe_slots(
    environment: &str,
    checks: &EnvironmentChecks,
    desired: &GatewayConfig,
    allowlist: Option<&ProbeConsumerAllowlist>,
) -> crate::error::Result<ProbeAuthorization> {
    if !checks.sends_credentials() {
        return Ok(ProbeAuthorization::default());
    }
    let Some(allowlist) = allowlist.filter(|list| !list.is_empty()) else {
        return Err(crate::error::Error::Config(format!(
            "{SMOKE_CONFIG_PATH}: environment '{}': a traffic check sends a credential slot, \
             but {VERIFY_PROBE_CONSUMERS_ENV} is unset or empty; no request was sent. A \
             repository administrator must list the environment's dedicated probe Consumers \
             (comma-separated <namespace>/<consumer-id>) in the {VERIFY_PROBE_CONSUMERS_ENV} \
             variable of this GitHub Environment. The `{VERIFY_PROBE_LABEL}` label alone \
             authorizes nothing.",
            crate::diagnostics::sanitize_line(environment)
        )));
    };
    let bindings = bind_probe_slots(checks, desired, Some(allowlist), None);
    refuse_unbound_slots(environment, &bindings)?;
    let slots = bindings
        .into_iter()
        .filter(|binding| binding.status == BindingStatus::Approved)
        .map(|binding| binding.slot)
        .collect();
    Ok(ProbeAuthorization { slots })
}

/// [`authorize_probe_slots`], then [`ProbeAuthorization::project`] `bundle`.
pub fn authorize_probe_credentials(
    environment: &str,
    checks: &EnvironmentChecks,
    desired: &GatewayConfig,
    allowlist: Option<&ProbeConsumerAllowlist>,
    bundle: &BTreeMap<String, String>,
) -> crate::error::Result<ProbeCredentials> {
    let authorization = authorize_probe_slots(environment, checks, desired, allowlist)?;
    Ok(authorization.project(bundle))
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

/// What a verification run concluded, as a deployment job records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    /// Every declared check passed.
    Passed,
    /// At least one declared check did not pass.
    Failed,
    /// No check is declared for the environment, so nothing was verified.
    Skipped,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub environment: String,
    pub results: Vec<CheckResult>,
}

// Hand-written so the JSON carries `status`: a machine reader must not have
// to infer "skipped" from an empty `results` list.
impl Serialize for VerifyReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut report = serializer.serialize_struct("VerifyReport", 3)?;
        report.serialize_field("environment", &self.environment)?;
        report.serialize_field("status", &self.status())?;
        report.serialize_field("results", &self.results)?;
        report.end()
    }
}

impl VerifyReport {
    /// The report for an environment that declares no check.
    pub fn skipped(environment: &str) -> Self {
        Self {
            environment: environment.to_string(),
            results: Vec::new(),
        }
    }

    pub fn passed(&self) -> bool {
        self.results.iter().all(|result| result.outcome.passed())
    }

    /// No check was declared, so nothing was verified. That is not a pass —
    /// zero checks trivially "all pass" — and it is not a failure either.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    pub fn status(&self) -> VerifyStatus {
        if self.is_empty() {
            VerifyStatus::Skipped
        } else if self.passed() {
            VerifyStatus::Passed
        } else {
            VerifyStatus::Failed
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.status() {
            VerifyStatus::Passed => 0,
            VerifyStatus::Failed => VERIFY_FAILED_EXIT_CODE,
            VerifyStatus::Skipped => VERIFY_SKIPPED_EXIT_CODE,
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
                "skipped: no smoke checks declared for {} in {SMOKE_CONFIG_PATH}. \
                 Nothing was verified: this is not a pass, and it authorizes no \
                 promotion. A gateway that accepted a configuration write has not \
                 been shown to serve it; declare at least one representative route.",
                crate::diagnostics::sanitize_line(&self.environment)
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
