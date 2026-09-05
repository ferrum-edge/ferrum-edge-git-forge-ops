//! The verdicts the preview commands report through their exit codes.
//!
//! [`apply_blockers`] is every fail-closed gate `apply` refuses on that is
//! decidable *without* a gateway. It is pure and total so the rule and the
//! process behaviour cannot drift apart: `plan` evaluates the whole set and
//! exits non-zero on any of them, while `apply` enforces the same per-class
//! predicates one at a time, in the order that preserves its own fail-fast
//! guarantees (the security audit must refuse before the credential bundle is
//! read, the required-slot check before the first gateway call, and so on).
//! Sharing the predicates rather than the control flow is what keeps a clean
//! `plan` from promising an `apply` that deterministically refuses.
//!
//! Gates that need a live gateway (large-prune threshold, stale-view block,
//! per-resource apply failures) are deliberately **not** here: a preview
//! cannot decide them offline, and pretending otherwise would make `plan`
//! fail for reasons the operator cannot act on from the repository.

use crate::diff::SecurityFinding;
use crate::policy::PolicyFinding;
use crate::secrets::ResolveReport;

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
