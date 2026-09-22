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
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

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
             a secret) and export it, or pass --state-writer-app-id. See \
             docs/github-launch-controls.md §1.",
        )];
    }

    let mut command = Command::new("python3");
    command
        // Never execute the checkout's copy: doctor is commonly run with both
        // repository-administration and gateway credentials in its parent.
        .arg("-c")
        .arg(BUNDLED_AUDITOR)
        .arg("--repo")
        .arg(repository)
        .current_dir(root)
        // The auditor needs only the GitHub token. In particular, do not expose
        // gateway, broker, credential-bundle, or unrelated process secrets.
        .env_clear()
        .env("PATH", CHILD_PATH);
    if context.template_repo {
        command.arg("--template-repo");
    }
    if let Some(app_id) = &context.state_writer_app_id {
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
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let violations = violation_lines(&stderr).count();
            let mut checks = vec![if output.status.success() {
                Check::pass(
                    "settings-audit",
                    "Repository settings match the launch baseline",
                    Scope::Github,
                    format!(
                        "{AUDITOR} reported {} control(s) active",
                        evidence_lines(&stdout).count()
                    ),
                )
            } else if violations == 0 {
                // The auditor exits non-zero for two different reasons, and
                // collapsing them is the mistake this whole scope is built to
                // avoid. Violations are a finding about the repository; an
                // API error, a token without Administration: read, or a
                // missing App id means the audit *did not happen*. Reporting
                // the second as a failed control would be inventing a result,
                // and reporting it as a pass would be worse.
                Check::new(
                    "settings-audit",
                    "Repository settings match the launch baseline",
                    Scope::Github,
                    Status::Unknown,
                    format!(
                        "{AUDITOR} could not complete: {}",
                        stderr
                            .lines()
                            .map(str::trim)
                            .find(|line| !line.is_empty())
                            .unwrap_or("it exited non-zero without saying why")
                    ),
                )
                .remedy(
                    "This is not a finding about the repository — the audit did not \
                     run. Check that GH_TOKEN carries Administration: read for this \
                     repository, then re-run.",
                )
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
            for violation in violation_lines(&stderr) {
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
            checks
        }
    }
}

fn evidence_lines(stdout: &str) -> impl Iterator<Item = &str> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PASS: "))
}

fn violation_lines(stderr: &str) -> impl Iterator<Item = &str> {
    stderr
        .lines()
        .filter_map(|line| line.trim().strip_prefix("FAIL: "))
}
