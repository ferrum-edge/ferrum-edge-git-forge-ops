//! Read-only repository administration metadata.
//!
//! This scope deliberately owns no baseline of its own. The auditor bundled into
//! the binary is the specification of what the launch controls are,
//! `bootstrap_repo_settings.py` writes exactly that, and doctor runs that auditor
//! rather than reimplementing
//! its rules — otherwise three descriptions of the same controls would drift
//! apart, which is the failure mode this whole tier exists to catch.
//!
//! Nothing here writes. The auditor is invoked in its normal read-only mode
//! with a token the operator already has; when there is no token, or no
//! Python, the result is [`Status::Unknown`] and never a pass.

use std::path::Path;
use std::process::Command;

use super::{Check, Scope, Status};

const AUDITOR: &str = ".github/scripts/audit_settings.py";
const BUNDLED_AUDITOR: &str = include_str!("../../.github/scripts/audit_settings.py");
/// The only parent variables the auditor inherits besides `GH_TOKEN`: what
/// `python3` and `gh` need to be found and to reach GitHub. Gateway, broker and
/// credential-bundle secrets, and anything else in doctor's environment, stay
/// behind.
const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "XDG_CONFIG_HOME",
    "GH_HOST",
    "GH_CONFIG_DIR",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "SYSTEMROOT",
];

/// What doctor needs in order to ask GitHub anything.
pub struct GithubContext {
    /// `owner/repo`.
    pub repository: Option<String>,
    /// An administration-read token. Presence only; the value is passed to the
    /// auditor's environment and never printed.
    pub token: Option<String>,
    /// The state-writer App's numeric id (repository variable
    /// `GITFORGEOPS_STATE_APP_ID`) — public metadata, not a credential.
    pub state_writer_app_id: Option<String>,
    /// Audit the template baseline instead of the deployment one.
    pub template_repo: bool,
}

/// The line the auditor prints, last, when the whole baseline holds
/// (`AUDIT_SUCCESS_LINE` in `audit_settings.py`). An exit status of 0 without
/// it is not evidence of a completed audit.
pub const AUDIT_SUCCESS_LINE: &str = "All launch protection controls are active.";

/// Repository variable that marks the template customers copy. `settings-audit.yml`
/// passes `--template-repo` exactly when its lowercased value is `true`.
pub const TEMPLATE_REPO_VARIABLE: &str = "GITFORGEOPS_TEMPLATE_REPO";

/// Repository variable holding the state-writer App id.
pub const STATE_APP_ID_VARIABLE: &str = "GITFORGEOPS_STATE_APP_ID";

/// `settings-audit.yml`'s template test: `tr '[:upper:]' '[:lower:]'` over
/// the raw value, compared with `true`. No trimming.
pub fn is_template_repo_value(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
}

impl GithubContext {
    /// Build the context from the CLI flags and a variable lookup (the
    /// process environment in `cmd_doctor`). A blank value is unset
    /// everywhere: a blank `GH_TOKEN` falls back to `GITHUB_TOKEN`, and a
    /// blank slug is no slug rather than `--repo ""`.
    pub fn from_lookup(
        repository: Option<&str>,
        state_writer_app_id: Option<&str>,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Self {
        let present = |value: Option<String>| value.filter(|value| !value.trim().is_empty());
        Self {
            repository: present(repository.map(str::to_string))
                .or_else(|| present(lookup("GITHUB_REPOSITORY"))),
            token: present(lookup("GH_TOKEN")).or_else(|| present(lookup("GITHUB_TOKEN"))),
            state_writer_app_id: present(state_writer_app_id.map(str::to_string))
                .or_else(|| present(lookup(STATE_APP_ID_VARIABLE))),
            template_repo: lookup(TEMPLATE_REPO_VARIABLE)
                .is_some_and(|value| is_template_repo_value(&value)),
        }
    }
}

/// Whether `value` is a canonical numeric App id: surrounding whitespace, an
/// optional sign, and ASCII digits with single underscores between them —
/// the ASCII subset of what Python's `int()` (argparse's `type=int` on
/// `--state-writer-app-id`) accepts. Deliberately stricter than `int()`,
/// which also takes Unicode decimal digits, so a value refused here is not
/// necessarily one the scheduled audit refuses.
fn is_canonical_app_id(value: &str) -> bool {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    !digits.is_empty()
        && digits
            .split('_')
            .all(|group| !group.is_empty() && group.bytes().all(|byte| byte.is_ascii_digit()))
}

pub fn run(root: &Path, context: &GithubContext) -> Vec<Check> {
    let Some(repository) = context.repository.as_deref() else {
        return vec![Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Unknown,
            "no repository slug: neither --repo nor GITHUB_REPOSITORY is set",
        )
        .remedy("Re-run with --repo owner/repo.")];
    };

    if context.token.is_none() {
        return vec![Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Unknown,
            "no GH_TOKEN with Administration: read, so branch rules, environment \
             protections, App bypass, labels, required checks and secret-name \
             metadata were not inspected",
        )
        .remedy(
            "Export GH_TOKEN=$(gh auth token) (or a fine-grained token with \
             Administration: read) and re-run. This is reported as unknown rather \
             than passed on purpose.",
        )];
    }

    if !context.template_repo && context.state_writer_app_id.is_none() {
        return vec![Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Unknown,
            "the state-writer App id is unknown, so the `main` ruleset's bypass \
             actor cannot be checked",
        )
        .remedy(
            "Set repository variable GITFORGEOPS_STATE_APP_ID (public metadata, not \
             a secret) and export it, or pass --state-writer-app-id. On the template \
             repository customers copy, export GITFORGEOPS_TEMPLATE_REPO=true instead, \
             as the repository variable settings-audit.yml reads. See \
             docs/github-launch-controls.md §1.",
        )];
    }

    // An App id is a plain decimal number. Refuse anything else here, naming
    // the value's source, instead of relaying argparse's usage text (or, for
    // a value `int()` happens to take, auditing against the wrong actor).
    let app_id = (!context.template_repo)
        .then_some(context.state_writer_app_id.as_deref())
        .flatten();
    if let Some(app_id) = app_id {
        if !is_canonical_app_id(app_id) {
            return vec![Check::new(
                "settings-audit",
                "Repository settings match the launch baseline",
                Scope::Github,
                Status::Fail,
                format!(
                    "the state-writer App id ({STATE_APP_ID_VARIABLE} or \
                     --state-writer-app-id) is not a canonical numeric App id \
                     (ASCII digits): '{}'",
                    crate::diagnostics::sanitize_line(app_id)
                ),
            )
            .remedy(
                "Set GITFORGEOPS_STATE_APP_ID to the App's numeric id (the App's \
                 settings page lists it as \"App ID\"), not its slug or client id.",
            )];
        }
    }

    let mut command = Command::new("python3");
    command
        // Never execute the checkout's copy: doctor is commonly run with both
        // repository-administration and gateway credentials in its parent.
        // `-I` (isolated mode) also keeps the checkout directory off
        // `sys.path` and ignores PYTHON* variables, so a checkout cannot shadow
        // a standard-library module the bundled auditor imports.
        .arg("-I")
        .arg("-c")
        .arg(BUNDLED_AUDITOR)
        .arg("--repo")
        .arg(repository)
        .current_dir(root)
        .env_clear();
    for name in INHERITED_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    // Exactly settings-audit.yml's choice: `--template-repo` for the
    // template, otherwise the App id. `--branch` is left out on purpose: the
    // workflow passes the repository's default branch, and without the flag
    // the auditor reads that same value from the repository metadata.
    if context.template_repo {
        command.arg("--template-repo");
    } else if let Some(app_id) = app_id {
        command.arg("--state-writer-app-id").arg(app_id);
    }
    if let Some(token) = &context.token {
        command.env("GH_TOKEN", token);
    }

    match command.output() {
        Err(error) => vec![Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Unknown,
            format!("could not run {AUDITOR}: {error}"),
        )
        .remedy("Install python3, or run the auditor yourself and read its output.")],
        Ok(output) => audit_checks(
            output.status.success(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
    }
}

/// Turn one auditor run into doctor checks: a pass, an audit that did not
/// happen (unknown), or one failed check per reported control.
pub fn audit_checks(success: bool, stdout: &str, stderr: &str) -> Vec<Check> {
    let violations = violation_lines(stderr).count();
    let completed = stdout.lines().any(|line| line.trim() == AUDIT_SUCCESS_LINE);
    let mut checks = vec![if violations == 0 && success && completed {
        Check::pass(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            format!(
                "{AUDITOR} reported {} control(s) active",
                evidence_lines(stdout).count()
            ),
        )
    } else if violations == 0 && success {
        // Exit 0 alone is not a completed audit: the auditor prints its
        // success line only after every control was read and held.
        Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Unknown,
            format!(
                "{AUDITOR} exited 0 without printing {AUDIT_SUCCESS_LINE:?}, so the \
                 audit is not known to have completed"
            ),
        )
        .remedy(
            "This is not a finding about the repository. Run the auditor yourself \
             (`python3 -I .github/scripts/audit_settings.py --repo <slug> ...`) and \
             read its output.",
        )
    } else if violations == 0 {
        // The auditor exits non-zero for two different reasons, and
        // collapsing them is the mistake this whole scope is built to
        // avoid. Violations are a finding about the repository; an
        // API error, a token without Administration: read, or a
        // missing App id means the audit *did not happen*. Reporting
        // the second as a failed control would be inventing a result,
        // and reporting it as a pass would be worse.
        let reason = failure_line(stderr);
        let remedy = if reason.is_some_and(looks_like_token_failure) {
            "This is not a finding about the repository — the audit did not \
             run. Check that GH_TOKEN carries Administration: read for this \
             repository, then re-run."
        } else {
            "This is not a finding about the repository — the audit did not \
             run. The auditor's own message is above; fix that input or the \
             local Python environment, then re-run."
        };
        Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Unknown,
            format!(
                "{AUDITOR} could not complete: {}",
                reason.unwrap_or("it exited non-zero without saying why")
            ),
        )
        .remedy(remedy)
    } else {
        Check::new(
            "settings-audit",
            "Repository settings match the launch baseline",
            Scope::Github,
            Status::Fail,
            format!("{AUDITOR} reported {violations} violation(s)"),
        )
        .remedy(
            "Each line below names one control. \
             `python3 .github/scripts/bootstrap_repo_settings.py --repo <slug>` \
             plans the fixes it can write; the rest are documented in \
             docs/github-launch-controls.md.",
        )
    }];
    // The auditor's own findings, one check each, so a machine-readable
    // doctor report carries them rather than a single opaque exit code.
    for violation in violation_lines(stderr) {
        checks.push(
            Check::new(
                "settings-control",
                "Launch control",
                Scope::Github,
                Status::Fail,
                violation.to_string(),
            )
            .remedy("See docs/github-launch-controls.md for this control."),
        );
    }
    // States the auditor accepts but flags for attention (for example a
    // monitoring environment holding both gateway signing keys). They do not
    // fail the audit, so they are warnings here too.
    for warning in warning_lines(stdout) {
        checks.push(
            Check::new(
                "settings-warning",
                "Launch control",
                Scope::Github,
                Status::Warn,
                warning.to_string(),
            )
            .remedy("See docs/github-launch-controls.md for this control."),
        );
    }
    checks
}

/// The line of a failed run's stderr that says why. argparse prints usage
/// first and its `error:` last, a traceback puts the exception last, and the
/// auditor's own refusals start with `settings audit`, so the last line of
/// one of those shapes wins, then the last non-empty line.
fn failure_line(stderr: &str) -> Option<&str> {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    lines
        .iter()
        .rev()
        .find(|line| {
            line.to_ascii_lowercase().contains("error:") || line.starts_with("settings audit")
        })
        .or_else(|| lines.last())
        .copied()
}

/// Whether the auditor's reason is about the token: it is missing, or the
/// GitHub API refused or hid what it asked for.
fn looks_like_token_failure(reason: &str) -> bool {
    [
        "GH_TOKEN",
        "HTTP 401",
        "HTTP 403",
        "HTTP 404",
        "Bad credentials",
        "Resource not accessible",
        "Not Found",
        "gh auth login",
    ]
    .iter()
    .any(|marker| reason.contains(marker))
        || reason.contains(": 401")
        || reason.contains(": 403")
        || reason.contains(": 404")
}

fn evidence_lines(stdout: &str) -> impl Iterator<Item = &str> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PASS: "))
}

fn warning_lines(stdout: &str) -> impl Iterator<Item = &str> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("WARN: "))
}

fn violation_lines(stderr: &str) -> impl Iterator<Item = &str> {
    stderr
        .lines()
        .filter_map(|line| line.trim().strip_prefix("FAIL: "))
}
