//! The verdicts the preview commands report through their exit codes.
//!
//! Two of them, both pure and total so the rule and the process behaviour
//! cannot drift apart:
//!
//! * [`apply_blockers`] — every fail-closed gate `apply` refuses on that is
//!   decidable *without* a gateway. `plan` evaluates the whole set and exits
//!   non-zero on any of them; `apply` enforces the same per-class predicates
//!   one at a time, in the order that preserves its own fail-fast guarantees
//!   (the security audit must refuse before the credential bundle is read, the
//!   required-slot check before the first gateway call, and so on). Sharing
//!   the predicates rather than the control flow is what keeps a clean `plan`
//!   from promising an `apply` that deterministically refuses.
//! * [`DriftVerdict`] — what makes `diff --exit-on-drift` return
//!   [`DRIFT_EXIT_CODE`].
//!
//! Gates that need a live gateway (large-prune threshold, stale-view block,
//! per-resource apply failures) are deliberately **not** here: a preview
//! cannot decide them offline, and pretending otherwise would make `plan`
//! fail for reasons the operator cannot act on from the repository.

use crate::config::repo_config::DriftAlertOn;
use crate::diff::{
    DiffAction, ResourceDiff, SecurityFinding, SpecOwnedResource, UnmanagedResource,
};
use crate::policy::PolicyFinding;
use crate::secrets::ResolveReport;

/// Process exit code for `diff --exit-on-drift` when the live gateway and the
/// repository disagree.
///
/// Distinct from `1` (which every command uses for an ordinary error) so a
/// scheduled drift monitor can tell "the gateway drifted" from "the run
/// failed". `drift-check.yml` treats any non-zero exit as a failed check, so
/// the distinction is for humans and for anything that inspects `$?`.
pub const DRIFT_EXIT_CODE: i32 = 2;

/// One class of fail-closed refusal, decidable without a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockerKind {
    /// `ferrum-edge validate` rejected the assembled document (gateway or
    /// mesh), or could not be run at all.
    Validation,
    /// The pre-resolve security audit reported error-severity findings that
    /// were not overridden.
    Security,
    /// Policy rules of severity `error` that were not overridden.
    Policy,
    /// `alloc=require` slots with no value in the bundle.
    RequiredCredentials,
    /// A credential-array shape change that re-owns a stored broker slot,
    /// without `--allow-credential-slot-remap`.
    SlotRemap,
}

impl BlockerKind {
    /// Stable, machine-greppable name for this class.
    pub fn label(self) -> &'static str {
        match self {
            BlockerKind::Validation => "validation",
            BlockerKind::Security => "security",
            BlockerKind::Policy => "policy",
            BlockerKind::RequiredCredentials => "required-credentials",
            BlockerKind::SlotRemap => "credential-slot-remap",
        }
    }

    /// The refusal `apply` prints for this class, in the words an operator can
    /// act on. Kept beside the predicate so a new gate cannot be added to one
    /// command and not described in the other.
    pub fn remedy(self) -> &'static str {
        match self {
            BlockerKind::Validation => {
                "the assembled document does not validate; fix the reported schema errors"
            }
            BlockerKind::Security => {
                "error-severity security finding(s); move committed secrets into the broker as \
                 ${gh-env-secret:...} placeholders, or override on the PR"
            }
            BlockerKind::Policy => {
                "error-severity policy violation(s); fix the resource or override on the PR"
            }
            BlockerKind::RequiredCredentials => {
                "alloc=require slot(s) with no bundle value; seed the credential bundle, or \
                 switch the placeholder to alloc=generate"
            }
            BlockerKind::SlotRemap => {
                "credential-slot reassignment(s); rotate the affected slot before removing the \
                 entry, or re-run with --allow-credential-slot-remap"
            }
        }
    }
}

/// One blocker class, with how many findings of it there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyBlocker {
    pub kind: BlockerKind,
    /// Number of findings in this class. [`BlockerKind::Validation`] is a
    /// single pass/fail gate and always reports `1`.
    pub count: usize,
}

impl ApplyBlocker {
    fn new(kind: BlockerKind, count: usize) -> Self {
        Self { kind, count }
    }

    /// `security (2): …` — one line naming the class, the count and the fix.
    pub fn summary(&self) -> String {
        format!(
            "{} ({}): {}",
            self.kind.label(),
            self.count,
            self.kind.remedy()
        )
    }
}

/// Everything the offline gate needs, gathered by the caller.
///
/// `policy_findings` must already have the override decision applied
/// ([`crate::policy::github_override::apply_override`]): [`PolicyFinding::is_blocking`]
/// consults `overridden_by`, and an unapplied override would make `plan`
/// refuse a repository `apply` would accept. An *absent* or *unverified*
/// override is never an acceptance — nothing here turns a blocker into a
/// success on its own.
#[derive(Debug, Clone, Copy)]
pub struct ApplyGateInputs<'a> {
    /// `false` when validation failed or could not be run. Callers that skip
    /// validation entirely must pass `true` and say so.
    pub validation_ok: bool,
    /// Pre-resolve security audit output.
    pub security_findings: &'a [SecurityFinding],
    /// A maintainer's PR override cleared the security audit.
    pub security_overridden: bool,
    /// Policy findings **after** override application.
    pub policy_findings: &'a [PolicyFinding],
    /// Credential resolution report for this run.
    pub secret_report: &'a ResolveReport,
    /// `--allow-credential-slot-remap` was passed.
    pub allow_credential_slot_remap: bool,
}

/// Validation is a single gate: it either passed or `apply` refuses.
pub fn validation_blocker(validation_ok: bool) -> Option<ApplyBlocker> {
    (!validation_ok).then(|| ApplyBlocker::new(BlockerKind::Validation, 1))
}

/// Error-severity security findings, unless a maintainer overrode the audit.
pub fn security_blocker(findings: &[SecurityFinding], overridden: bool) -> Option<ApplyBlocker> {
    if overridden {
        return None;
    }
    let count = crate::diff::security_blockers(findings).len();
    (count > 0).then(|| ApplyBlocker::new(BlockerKind::Security, count))
}

/// Error-severity policy findings that no override cleared.
///
/// `findings` are expected post-override; [`PolicyFinding::is_blocking`] is the
/// same predicate `apply` filters on.
pub fn policy_blocker(findings: &[PolicyFinding]) -> Option<ApplyBlocker> {
    let count = findings.iter().filter(|f| f.is_blocking()).count();
    (count > 0).then(|| ApplyBlocker::new(BlockerKind::Policy, count))
}

/// `alloc=require` slots with no value.
///
/// Distinct from [`crate::secrets::ResolveReport::needs_allocation`], which is
/// ordinary first-apply work the allocator performs — those must never be
/// reported as a blocker or every new credential would fail its own plan.
pub fn required_credentials_blocker(report: &ResolveReport) -> Option<ApplyBlocker> {
    let count = report.missing_required().len();
    (count > 0).then(|| ApplyBlocker::new(BlockerKind::RequiredCredentials, count))
}

/// A proven credential-slot reassignment the run has not acknowledged.
pub fn slot_remap_blocker(report: &ResolveReport, allowed: bool) -> Option<ApplyBlocker> {
    if allowed {
        return None;
    }
    let count = report.slot_remaps.len();
    (count > 0).then(|| ApplyBlocker::new(BlockerKind::SlotRemap, count))
}

/// Every offline reason `apply` would refuse, in the order `apply` checks
/// them.
///
/// Empty means: nothing decidable from the repository alone stops an apply.
/// It does **not** promise the apply succeeds — a gateway can still be
/// unreachable, a prune can still exceed the threshold, a write can still
/// fail.
pub fn apply_blockers(inputs: ApplyGateInputs<'_>) -> Vec<ApplyBlocker> {
    [
        security_blocker(inputs.security_findings, inputs.security_overridden),
        slot_remap_blocker(inputs.secret_report, inputs.allow_credential_slot_remap),
        required_credentials_blocker(inputs.secret_report),
        validation_blocker(inputs.validation_ok),
        policy_blocker(inputs.policy_findings),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The single line `plan` prints above its non-zero exit, naming each blocker
/// class. `None` when nothing blocks.
pub fn blocker_summary(blockers: &[ApplyBlocker]) -> Option<String> {
    if blockers.is_empty() {
        return None;
    }
    let classes: Vec<&str> = blockers.iter().map(|b| b.kind.label()).collect();
    Some(format!(
        "apply is blocked by {} class(es): {}",
        blockers.len(),
        classes.join(", ")
    ))
}

/// Which drift categories a `diff` run found.
///
/// The first three mirror `ownership.drift_alert_on`, so an operator can mute
/// a noisy category. [`Self::spec_conflicts`] deliberately has no flag: a repo
/// declaring a resource the gateway's OpenAPI spec importer owns is not drift
/// noise but two owners writing one row, and `apply` refuses the namespace
/// over it. Muting the unmanaged category must not mute that.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DriftVerdict {
    /// A managed resource differs from, or is missing on, the gateway.
    pub managed_modified: bool,
    /// A managed resource would be deleted.
    pub managed_deleted: bool,
    /// The gateway holds resources this repo never applied.
    pub unmanaged_added: bool,
    /// A live `api_spec_id`-tagged resource is also declared in this repo.
    pub spec_conflicts: bool,
}

impl DriftVerdict {
    /// Classify one run's diff output against the environment's alert flags.
    pub fn evaluate(
        alert: &DriftAlertOn,
        diffs: &[ResourceDiff],
        unmanaged: &[UnmanagedResource],
        spec_owned: &[SpecOwnedResource],
    ) -> Self {
        let modify_or_add = diffs
            .iter()
            .any(|d| matches!(d.action, DiffAction::Modify | DiffAction::Add));
        let delete = diffs.iter().any(|d| matches!(d.action, DiffAction::Delete));
        Self {
            managed_modified: alert.managed_modified && modify_or_add,
            managed_deleted: alert.managed_deleted && delete,
            unmanaged_added: alert.unmanaged_added && !unmanaged.is_empty(),
            // Informational spec-owned rows — ones the repo does not declare —
            // are a stable steady state and stay non-blocking.
            spec_conflicts: spec_owned.iter().any(|s| s.is_conflict()),
        }
    }

    pub fn has_drift(&self) -> bool {
        self.managed_modified || self.managed_deleted || self.unmanaged_added || self.spec_conflicts
    }

    /// `0` when in sync, [`DRIFT_EXIT_CODE`] otherwise. The only mapping;
    /// `cmd_diff` calls this rather than writing `2` anywhere.
    pub fn exit_code(&self) -> i32 {
        if self.has_drift() {
            DRIFT_EXIT_CODE
        } else {
            0
        }
    }

    /// Human-readable category names for the verdict, for the line printed
    /// before a non-zero exit.
    pub fn reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.managed_modified {
            reasons.push("managed resources added or modified");
        }
        if self.managed_deleted {
            reasons.push("managed resources deleted");
        }
        if self.unmanaged_added {
            reasons.push("unmanaged resources on the gateway");
        }
        if self.spec_conflicts {
            reasons.push("API-spec ownership conflicts");
        }
        reasons
    }
}
