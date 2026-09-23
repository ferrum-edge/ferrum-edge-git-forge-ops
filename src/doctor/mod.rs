//! One answer to "is this repository ready to deploy, and what is missing?"
//!
//! The pieces already existed — a bootstrap writer, a settings auditor, local
//! validation, the credential preflight `apply` runs — but a new operator had
//! to know which to run, in which order, and had to read a gateway 401 or an
//! empty environment matrix and work backwards to the setting behind it. This
//! is the diagnostic entry point over those capabilities. It provisions
//! nothing, mutates nothing, and prints no secret value.
//!
//! The checks are grouped by **trust boundary**, not by subject, because that
//! is what decides whether a check can run at all:
//!
//! * [`Scope::Local`] needs no credential. It reads the repository.
//! * [`Scope::Github`] needs an administration-read token, and delegates to
//!   `audit_settings.py` so doctor, bootstrap and the scheduled audit cannot
//!   describe different baselines.
//! * [`Scope::Gateway`] needs that environment's deployment credentials, so it
//!   is opt-in and issues reads only.
//!
//! Every check reports one of five statuses, and the three that are *not*
//! pass/fail exist because guessing is worse than saying so: a check that
//! could not run ([`Status::Unknown`]) and a check that does not apply
//! ([`Status::Skipped`]) must never render as a pass. A fresh template
//! reporting "unconfigured" is a correct answer, not a failure.

use serde::Serialize;

pub mod gateway;
pub mod github;
pub mod local;

/// Exit code when at least one check failed. Distinct from 1 (the command
/// itself could not run) so a wrapper can tell "diagnosed, and the answer is
/// no" from "the diagnosis did not happen".
pub const DOCTOR_FAILED_EXIT_CODE: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Verified against the real thing.
    Pass,
    /// Verified, and it is wrong. `remediation` says what to do.
    Fail,
    /// Verified, and it will work but is not what the baseline asks for.
    Warn,
    /// Could not be verified — no credential, no permission, or the platform
    /// does not expose the answer. Never a pass: a check that could not look
    /// is not a check that found nothing.
    Unknown,
    /// Does not apply to this configuration (a file-mode environment has no
    /// gateway; a template repository has no deployment target).
    Skipped,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Warn => "WARN",
            Status::Unknown => "UNKNOWN",
            Status::Skipped => "SKIP",
        }
    }

    /// Only an outright failure blocks. `Unknown` is reported loudly and
    /// counted separately: a laptop with no `GH_TOKEN` cannot audit repository
    /// settings, and failing there would train operators to ignore the exit
    /// code.
    pub fn is_blocking(self) -> bool {
        matches!(self, Status::Fail)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// No credential required.
    Local,
    /// Read-only repository administration metadata.
    Github,
    /// The environment's own deployment credentials. Reads only.
    Gateway,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::Local => "local",
            Scope::Github => "github",
            Scope::Gateway => "gateway",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Stable identifier, safe to grep for in CI output.
    pub id: &'static str,
    pub title: &'static str,
    pub scope: Scope,
    pub status: Status,
    /// Which environment this check is about, when it is about one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// What was observed. Never a secret value — see `Check::secret_presence`.
    pub detail: String,
    /// What to do about it. Present on everything that is not a pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Check {
    pub fn new(
        id: &'static str,
        title: &'static str,
        scope: Scope,
        status: Status,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            title,
            scope,
            status,
            environment: None,
            detail: detail.into(),
            remediation: None,
        }
    }

    pub fn pass(
        id: &'static str,
        title: &'static str,
        scope: Scope,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(id, title, scope, Status::Pass, detail)
    }

    pub fn for_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Attach what to do about a non-passing check. A passing check keeps no
    /// remediation: the report would otherwise print instructions under a PASS
    /// line, which reads as "there is still something to fix".
    pub fn remedy(mut self, remediation: impl Into<String>) -> Self {
        if self.status != Status::Pass {
            self.remediation = Some(remediation.into());
        }
        self
    }

    /// Describe a credential by presence, never by value.
    ///
    /// A present name is not proof the value is correct — a wrong JWT secret
    /// is present and still answers 401 — so this deliberately reports
    /// "configured" rather than "valid", and the gateway scope is where
    /// correctness is actually established.
    pub fn secret_presence(
        id: &'static str,
        title: &'static str,
        scope: Scope,
        name: &str,
        present: bool,
    ) -> Self {
        if present {
            Self::new(
                id,
                title,
                scope,
                Status::Pass,
                format!(
                    "{name} is set (presence only; correctness is proven by the gateway checks)"
                ),
            )
        } else {
            Self::new(id, title, scope, Status::Fail, format!("{name} is not set"))
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    pub fn extend(&mut self, checks: impl IntoIterator<Item = Check>) {
        self.checks.extend(checks);
    }

    pub fn count(&self, status: Status) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == status)
            .count()
    }

    pub fn is_ready(&self) -> bool {
        !self.checks.iter().any(|check| check.status.is_blocking())
    }

    pub fn exit_code(&self) -> i32 {
        if self.is_ready() {
            0
        } else {
            DOCTOR_FAILED_EXIT_CODE
        }
    }

    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "=== GitForgeOps Setup Doctor ===");
        for scope in [Scope::Local, Scope::Github, Scope::Gateway] {
            let scoped: Vec<&Check> = self
                .checks
                .iter()
                .filter(|check| check.scope == scope)
                .collect();
            if scoped.is_empty() {
                continue;
            }
            let _ = writeln!(out, "\n-- {} --", scope.label());
            for check in scoped {
                let environment = check
                    .environment
                    .as_deref()
                    .map(|name| format!(" [{}]", crate::diagnostics::sanitize_line(name)))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "{:<7} {}{}: {}",
                    check.status.label(),
                    check.title,
                    environment,
                    crate::diagnostics::sanitize_line(&check.detail)
                );
                if let Some(remediation) = &check.remediation {
                    let _ = writeln!(
                        out,
                        "        -> {}",
                        crate::diagnostics::sanitize_line(remediation)
                    );
                }
            }
        }
        let _ = writeln!(
            out,
            "\n{} passed, {} failed, {} warned, {} unknown, {} skipped.",
            self.count(Status::Pass),
            self.count(Status::Fail),
            self.count(Status::Warn),
            self.count(Status::Unknown),
            self.count(Status::Skipped),
        );
        if self.count(Status::Unknown) > 0 {
            let _ = writeln!(
                out,
                "UNKNOWN is not a pass: those checks could not be performed. \
                 Re-run with the credentials they name before treating this \
                 repository as ready."
            );
        }
        let _ = writeln!(
            out,
            "{}",
            if self.is_ready() {
                "No blocking problems found."
            } else {
                "Not ready to deploy: resolve every FAIL above."
            }
        );
        out
    }
}
