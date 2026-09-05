//! The shared verdicts: what blocks `apply` (and therefore `plan`), and what
//! makes `diff --exit-on-drift` return non-zero.
//!
//! These are pure functions precisely so the rules can be asserted without a
//! gateway, a repository checkout or a process; `apply_gate_tests.rs` and
//! `diff_exit_tests.rs` cover the same rules end to end through the binary.

use gitforgeops::config::repo_config::DriftAlertOn;
use gitforgeops::diff::{
    DiffAction, ResourceDiff, SecurityFinding, SpecOwnedResource, UnmanagedResource,
};
use gitforgeops::policy::{PolicyFinding, Severity};
use gitforgeops::secrets::{
    PlaceholderAlloc, ResolveReport, ResolveResult, SecretPlaceholder, SlotStatus,
};
use gitforgeops::verdict::{
    apply_blockers, blocker_summary, policy_blocker, required_credentials_blocker,
    security_blocker, slot_remap_blocker, validation_blocker, ApplyGateInputs, BlockerKind,
    DriftVerdict, DRIFT_EXIT_CODE,
};

fn security_finding(severity: &str) -> SecurityFinding {
    SecurityFinding {
        severity: severity.to_string(),
        kind: "Consumer".to_string(),
        id: "app".to_string(),
        namespace: "ferrum".to_string(),
        message: "Literal credential in 'keyauth[0].key'".to_string(),
    }
}

fn policy_finding(severity: Severity, overridden_by: Option<&str>) -> PolicyFinding {
    PolicyFinding {
        rule_id: "backend_scheme".to_string(),
        severity,
        kind: "Proxy".to_string(),
        id: "app".to_string(),
        namespace: "ferrum".to_string(),
        message: "backend_scheme http is not allowed".to_string(),
        remediation: None,
        overridden_by: overridden_by.map(str::to_string),
    }
}

fn slot(status: SlotStatus, alloc: PlaceholderAlloc) -> ResolveResult {
    ResolveResult {
        consumer_id: "app".to_string(),
        namespace: "ferrum".to_string(),
        cred_key: "keyauth/key".to_string(),
        slot: "ferrum/app/keyauth/key".to_string(),
        placeholder: SecretPlaceholder {
            alloc,
            length_bytes: 32,
        },
        status,
    }
}

fn report(results: Vec<ResolveResult>, slot_remaps: Vec<String>) -> ResolveReport {
    ResolveReport {
        results,
        slot_remaps,
        ..ResolveReport::default()
    }
}

fn clean_inputs<'a>(report: &'a ResolveReport) -> ApplyGateInputs<'a> {
    ApplyGateInputs {
        validation_ok: true,
        security_findings: &[],
        security_overridden: false,
        policy_findings: &[],
        secret_report: report,
        allow_credential_slot_remap: false,
    }
}

#[test]
fn nothing_blocks_a_clean_repository() {
    let report = report(
        vec![slot(SlotStatus::Resolved, PlaceholderAlloc::Require)],
        vec![],
    );
    let blockers = apply_blockers(clean_inputs(&report));

    assert!(blockers.is_empty(), "{blockers:?}");
    assert!(blocker_summary(&blockers).is_none());
}

#[test]
fn failed_validation_blocks() {
    let report = report(vec![], vec![]);
    let mut inputs = clean_inputs(&report);
    inputs.validation_ok = false;

    assert_eq!(
        validation_blocker(false).map(|b| b.kind),
        Some(BlockerKind::Validation)
    );
    assert_eq!(validation_blocker(true), None);
    let blockers = apply_blockers(inputs);
    assert_eq!(blockers.len(), 1);
    assert_eq!(blockers[0].kind, BlockerKind::Validation);
    // A single pass/fail gate always counts one.
    assert_eq!(blockers[0].count, 1);
}

#[test]
fn only_error_severity_security_findings_block_and_an_override_clears_them() {
    let findings = vec![
        security_finding("warning"),
        security_finding("error"),
        security_finding("error"),
    ];

    let gate = security_blocker(&findings, false).expect("two error findings block");
    assert_eq!(gate.kind, BlockerKind::Security);
    assert_eq!(gate.count, 2, "warnings must not be counted");

    assert_eq!(
        security_blocker(&findings, true),
        None,
        "an active override clears the audit"
    );
    assert_eq!(
        security_blocker(&[security_finding("warning")], false),
        None,
        "a warning-only audit never blocks"
    );
}

#[test]
fn only_unoverridden_error_policies_block() {
    // The gate reads post-override findings: `is_blocking()` is false once a
    // sufficiently-permissioned maintainer has cleared the rule, and an
    // *absent* override leaves the finding standing.
    let blocking = vec![policy_finding(Severity::Error, None)];
    let gate = policy_blocker(&blocking).expect("an error-severity policy blocks");
    assert_eq!(gate.kind, BlockerKind::Policy);
    assert_eq!(gate.count, 1);

    assert_eq!(
        policy_blocker(&[policy_finding(Severity::Error, Some("maintainer"))]),
        None,
        "an applied override clears the rule"
    );
    assert_eq!(
        policy_blocker(&[policy_finding(Severity::Warning, None)]),
        None,
        "a warning is advisory"
    );
    assert_eq!(
        policy_blocker(&[policy_finding(Severity::Info, None)]),
        None
    );
}

#[test]
fn required_slots_block_but_pending_generation_does_not() {
    let missing = report(
        vec![slot(SlotStatus::MissingRequired, PlaceholderAlloc::Require)],
        vec![],
    );
    let gate = required_credentials_blocker(&missing).expect("alloc=require with no value blocks");
    assert_eq!(gate.kind, BlockerKind::RequiredCredentials);
    assert_eq!(gate.count, 1);

    // First-apply allocation work is not a blocker; treating it as one would
    // make every brand-new credential fail its own plan.
    let pending = report(
        vec![slot(
            SlotStatus::NeedsAllocation,
            PlaceholderAlloc::Generate,
        )],
        vec![],
    );
    assert_eq!(required_credentials_blocker(&pending), None);

    let resolved = report(
        vec![slot(SlotStatus::Resolved, PlaceholderAlloc::Require)],
        vec![],
    );
    assert_eq!(required_credentials_blocker(&resolved), None);
}

#[test]
fn slot_remaps_block_until_explicitly_allowed() {
    let remapped = report(
        vec![],
        vec!["ferrum/app/keyauth/[1]/key is orphaned".to_string()],
    );

    let gate = slot_remap_blocker(&remapped, false).expect("an unacknowledged remap blocks");
    assert_eq!(gate.kind, BlockerKind::SlotRemap);
    assert_eq!(gate.count, 1);
    assert_eq!(
        slot_remap_blocker(&remapped, true),
        None,
        "--allow-credential-slot-remap is the acknowledgement"
    );
}

#[test]
fn every_blocker_class_is_reported_together_and_named_in_the_summary() {
    // The regression this whole module exists for: a preview must not report
    // only the classes it happened to be written to check.
    let report = report(
        vec![slot(SlotStatus::MissingRequired, PlaceholderAlloc::Require)],
        vec!["ferrum/app/keyauth/[1]/key is orphaned".to_string()],
    );
    let security = vec![security_finding("error")];
    let policy = vec![policy_finding(Severity::Error, None)];

    let blockers = apply_blockers(ApplyGateInputs {
        validation_ok: false,
        security_findings: &security,
        security_overridden: false,
        policy_findings: &policy,
        secret_report: &report,
        allow_credential_slot_remap: false,
    });

    let kinds: Vec<BlockerKind> = blockers.iter().map(|b| b.kind).collect();
    assert_eq!(
        kinds,
        vec![
            BlockerKind::Security,
            BlockerKind::SlotRemap,
            BlockerKind::RequiredCredentials,
            BlockerKind::Validation,
            BlockerKind::Policy,
        ],
        "all five classes, in apply's own order"
    );

    let summary = blocker_summary(&blockers).expect("blocked");
    assert!(summary.contains("5 class(es)"), "{summary}");
    for kind in kinds {
        assert!(
            summary.contains(kind.label()),
            "summary must name {}: {summary}",
            kind.label()
        );
        // Every class carries an operator-actionable remedy.
        assert!(!kind.remedy().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Drift verdict
// ---------------------------------------------------------------------------

fn diff(action: DiffAction) -> ResourceDiff {
    ResourceDiff {
        action,
        kind: "Proxy".to_string(),
        id: "app".to_string(),
        namespace: "ferrum".to_string(),
        details: vec![],
    }
}

fn unmanaged() -> UnmanagedResource {
    UnmanagedResource {
        kind: "Proxy".to_string(),
        id: "legacy".to_string(),
        namespace: "ferrum".to_string(),
    }
}

fn spec_owned(declared_in_repo: bool) -> SpecOwnedResource {
    SpecOwnedResource {
        kind: "Proxy".to_string(),
        id: "app".to_string(),
        namespace: "ferrum".to_string(),
        api_spec_id: "spec-1".to_string(),
        declared_in_repo,
        pruned: false,
    }
}

/// Every alert category muted, which is the strictest possible setting for
/// the flags a conflict must ignore.
fn all_muted() -> DriftAlertOn {
    DriftAlertOn {
        managed_modified: false,
        managed_deleted: false,
        unmanaged_added: false,
    }
}

/// The repository's effective default (`OwnershipConfig::default()`): alert on
/// managed changes, stay quiet about unmanaged additions.
///
/// Spelled out rather than taken from `DriftAlertOn::default()`, whose derived
/// all-false value is not what an environment without an explicit
/// `drift_alert_on` block gets.
fn defaults() -> DriftAlertOn {
    DriftAlertOn {
        managed_modified: true,
        managed_deleted: true,
        unmanaged_added: false,
    }
}

#[test]
fn an_in_sync_gateway_reports_no_drift() {
    let verdict = DriftVerdict::evaluate(&defaults(), &[], &[], &[]);

    assert!(!verdict.has_drift());
    assert_eq!(verdict.exit_code(), 0);
    assert!(verdict.reasons().is_empty());
}

#[test]
fn a_spec_ownership_conflict_is_drift_even_with_identical_fields() {
    // Issue-131 reproduction: the repo declares a row the gateway's OpenAPI
    // spec importer owns. The diff engine suppresses the Modify, so there is
    // no ordinary diff entry and no unmanaged resource — and the nightly
    // monitor used to report success on a namespace apply refuses.
    let verdict = DriftVerdict::evaluate(&defaults(), &[], &[], &[spec_owned(true)]);

    assert!(verdict.spec_conflicts);
    assert!(verdict.has_drift());
    assert_eq!(verdict.exit_code(), DRIFT_EXIT_CODE);
    assert_eq!(verdict.exit_code(), 2, "the documented drift exit code");
    assert!(
        verdict
            .reasons()
            .iter()
            .any(|r| r.contains("API-spec ownership")),
        "{:?}",
        verdict.reasons()
    );
}

#[test]
fn a_spec_conflict_ignores_the_drift_alert_flags() {
    // `drift_alert_on` mutes categories an operator has decided are noise.
    // Two owners writing one row is a correctness problem apply refuses over,
    // so it deliberately has no flag to mute.
    let verdict = DriftVerdict::evaluate(&all_muted(), &[], &[unmanaged()], &[spec_owned(true)]);

    assert!(!verdict.unmanaged_added, "the muted category stays muted");
    assert!(verdict.spec_conflicts);
    assert_eq!(verdict.exit_code(), DRIFT_EXIT_CODE);
}

#[test]
fn informational_spec_owned_rows_are_not_drift() {
    // The repo does not declare these. Staying off them is a stable steady
    // state, and calling it drift meant any gateway ingesting API specs could
    // never report in sync.
    let verdict = DriftVerdict::evaluate(&defaults(), &[], &[], &[spec_owned(false)]);

    assert!(!verdict.spec_conflicts);
    assert!(!verdict.has_drift());
    assert_eq!(verdict.exit_code(), 0);
}

#[test]
fn a_conflict_alongside_ordinary_drift_reports_both() {
    let verdict = DriftVerdict::evaluate(
        &defaults(),
        &[diff(DiffAction::Modify), diff(DiffAction::Delete)],
        &[],
        &[spec_owned(true), spec_owned(false)],
    );

    assert!(verdict.managed_modified);
    assert!(verdict.managed_deleted);
    assert!(verdict.spec_conflicts);
    assert_eq!(verdict.reasons().len(), 3, "{:?}", verdict.reasons());
}

#[test]
fn ordinary_categories_still_honor_their_flags() {
    let muted = DriftVerdict::evaluate(
        &all_muted(),
        &[diff(DiffAction::Add), diff(DiffAction::Delete)],
        &[unmanaged()],
        &[],
    );
    assert!(!muted.has_drift(), "{muted:?}");
    assert_eq!(muted.exit_code(), 0);

    let unmuted = DriftVerdict::evaluate(
        &DriftAlertOn {
            managed_modified: true,
            managed_deleted: true,
            unmanaged_added: true,
        },
        &[diff(DiffAction::Add)],
        &[unmanaged()],
        &[],
    );
    assert!(unmuted.managed_modified, "Add counts as modified-or-added");
    assert!(unmuted.unmanaged_added);
    assert_eq!(unmuted.exit_code(), DRIFT_EXIT_CODE);
}
