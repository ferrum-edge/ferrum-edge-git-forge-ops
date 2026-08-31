use gitforgeops::diff::{
    best_practice::BestPractice, breaking::BreakingChange, resource_diff::*,
    security::SecurityFinding,
};
use gitforgeops::policy::config::OverrideConfig;
use gitforgeops::policy::{PolicyFinding, Severity};
use gitforgeops::review::comment_status_is_retryable;
use gitforgeops::review::enforce_comment_delivery;
use gitforgeops::review::live_comparison_precondition_error;
use gitforgeops::review::pr_comment::{
    build_review_comment, build_review_comment_v2, render_spec_owned,
};
use gitforgeops::secrets::ResolveReport;

#[test]
fn review_comment_shows_validation_pass() {
    let comment = build_review_comment(true, "", &[], &[], &[], &[], None);
    assert!(comment.contains("PASS"));
}

#[test]
fn review_comment_shows_validation_fail() {
    let comment = build_review_comment(false, "some error", &[], &[], &[], &[], None);
    assert!(comment.contains("FAIL"));
}

#[test]
fn review_comment_includes_changes_table() {
    let diffs = vec![ResourceDiff {
        action: DiffAction::Add,
        kind: "Proxy".to_string(),
        id: "proxy-new".to_string(),
        namespace: "ferrum".to_string(),
        details: vec![],
    }];
    let comment = build_review_comment(true, "", &diffs, &[], &[], &[], None);
    assert!(comment.contains("proxy-new"));
    assert!(comment.contains("Add"));
}

#[test]
fn review_comment_includes_breaking_changes() {
    let breaking = vec![BreakingChange {
        kind: "Proxy".to_string(),
        id: "proxy-1".to_string(),
        reason: "listen_path changed".to_string(),
    }];
    let comment = build_review_comment(true, "", &[], &breaking, &[], &[], None);
    assert!(comment.contains("listen_path changed"));
    assert!(comment.contains("Breaking"));
}

#[test]
fn review_comment_includes_security_findings() {
    let findings = vec![SecurityFinding {
        severity: "warning".to_string(),
        kind: "Consumer".to_string(),
        id: "consumer-1".to_string(),
        namespace: "team-alpha".to_string(),
        message: "Literal credential detected".to_string(),
    }];
    let comment = build_review_comment(true, "", &[], &[], &findings, &[], None);
    assert!(comment.contains("Literal credential"));
    // Two namespaces can hold same-named resources, so a finding is only
    // actionable when the reader can tell which one it names.
    assert!(comment.contains("team-alpha"));
}

#[test]
fn review_comment_includes_best_practices() {
    let practices = vec![BestPractice {
        severity: "warning".to_string(),
        kind: "Proxy".to_string(),
        id: "proxy-1".to_string(),
        namespace: "team-alpha".to_string(),
        message: "No rate limiting plugin".to_string(),
    }];
    let comment = build_review_comment(true, "", &[], &[], &[], &practices, None);
    assert!(comment.contains("rate limiting"));
    assert!(comment.contains("team-alpha"));
    assert!(comment.contains("[warning]"));
}

#[test]
fn review_comment_marks_live_comparison_as_skipped() {
    let comment = build_review_comment(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        Some("Live gateway comparison skipped: gateway unavailable"),
    );
    assert!(comment.contains("Changes: Skipped"));
    assert!(comment.contains("Breaking Changes: Skipped"));
    assert!(comment.contains("gateway unavailable"));
}

#[test]
fn live_review_rejects_a_vacuous_zero_namespace_comparison() {
    let error = live_comparison_precondition_error(&[]).expect("empty scope must fail closed");
    assert!(error.contains("no trusted namespaces"));
    assert!(live_comparison_precondition_error(&["default".to_string()]).is_none());
}

#[test]
fn trusted_live_review_requires_pr_comment_delivery() {
    let error = enforce_comment_delivery(true, Some("GitHub returned 403"))
        .expect_err("trusted live review must fail when its comment is not delivered");
    assert!(error.to_string().contains("could not post its result"));
    assert!(enforce_comment_delivery(false, Some("GitHub returned 403")).is_ok());
    assert!(enforce_comment_delivery(true, None).is_ok());
}

#[test]
fn github_comment_retries_only_explicit_transient_responses() {
    for status in [408, 429, 503] {
        assert!(comment_status_is_retryable(status), "status {status}");
    }
    for status in [400, 401, 403, 404, 409, 422, 500, 501, 502, 504] {
        assert!(!comment_status_is_retryable(status), "status {status}");
    }
}

#[test]
fn review_comment_v2_uses_configured_override_label_and_permission() {
    let policy = vec![PolicyFinding {
        rule_id: "backend_scheme".to_string(),
        severity: Severity::Error,
        kind: "Proxy".to_string(),
        id: "my-api".to_string(),
        namespace: "ferrum".to_string(),
        message: "http is not allowed".to_string(),
        remediation: None,
        overridden_by: None,
    }];

    let override_cfg = OverrideConfig {
        require_label: "acme/bypass".to_string(),
        required_permission: "admin".to_string(),
    };

    let comment = build_review_comment_v2(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        &policy,
        &[],
        &[],
        None,
        Some(&override_cfg),
        None,
        None,
        &ResolveReport::default(),
        true, // bundle_loaded — test contexts have a bundle
    );

    assert!(
        comment.contains("acme/bypass"),
        "message should include configured label; got:\n{comment}"
    );
    assert!(
        comment.contains("`admin` permission"),
        "message should include configured permission tier; got:\n{comment}"
    );
    assert!(
        !comment.contains("`write` permission"),
        "stale hardcoded permission should be gone; got:\n{comment}"
    );
}

#[test]
fn review_comment_v2_falls_back_to_defaults_when_no_override_config() {
    let policy = vec![PolicyFinding {
        rule_id: "backend_scheme".to_string(),
        severity: Severity::Error,
        kind: "Proxy".to_string(),
        id: "my-api".to_string(),
        namespace: "ferrum".to_string(),
        message: "http is not allowed".to_string(),
        remediation: None,
        overridden_by: None,
    }];

    let comment = build_review_comment_v2(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        &policy,
        &[],
        &[],
        None,
        None,
        None,
        None,
        &ResolveReport::default(),
        true, // bundle_loaded — test contexts have a bundle
    );

    assert!(comment.contains("gitforgeops/policy-override"));
    assert!(comment.contains("`write` permission"));
}

#[test]
fn review_comment_credential_section_discloses_bundle_context_when_absent() {
    use gitforgeops::secrets::placeholder::{PlaceholderAlloc, SecretPlaceholder};
    use gitforgeops::secrets::{ResolveReport, ResolveResult, SlotStatus};

    // Build a report that looks like what resolve_secrets would produce
    // against an empty bundle: a single placeholder marked NeedsAllocation.
    let mut report = ResolveReport::default();
    report.results.push(ResolveResult {
        consumer_id: "app".to_string(),
        namespace: "ferrum".to_string(),
        cred_key: "api_key".to_string(),
        slot: "ferrum/app/api_key".to_string(),
        placeholder: SecretPlaceholder {
            alloc: PlaceholderAlloc::Generate,
            length_bytes: 32,
        },
        status: SlotStatus::NeedsAllocation,
    });

    // bundle_loaded=false → disclaimer present, status wording not shown
    let no_bundle = build_review_comment_v2(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        None,
        None,
        None,
        None,
        &report,
        false,
    );
    assert!(
        no_bundle.contains("actual allocation status is determined at apply time"),
        "expected bundle-context disclaimer when bundle_loaded=false; got:\n{no_bundle}"
    );
    // Without bundle, we show the alloc mode, not a bundle-dependent status.
    assert!(no_bundle.contains("Generate"));
    assert!(!no_bundle.contains("needs allocation (generated on apply)"));

    // bundle_loaded=true → no disclaimer, full status wording
    let with_bundle = build_review_comment_v2(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        None,
        None,
        None,
        None,
        &report,
        true,
    );
    assert!(!with_bundle.contains("actual allocation status is determined at apply time"));
    assert!(with_bundle.contains("needs allocation (generated on apply)"));
}

// --- Spec-owned section ------------------------------------------------------

fn spec_owned_entry(id: &str, declared_in_repo: bool, pruned: bool) -> SpecOwnedResource {
    SpecOwnedResource {
        kind: "Proxy".to_string(),
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        api_spec_id: "spec-7".to_string(),
        declared_in_repo,
        pruned,
    }
}

#[test]
fn spec_owned_section_is_omitted_when_empty() {
    assert!(render_spec_owned(&[]).is_empty());
}

#[test]
fn spec_owned_section_lists_resources_with_owning_spec() {
    let md = render_spec_owned(&[spec_owned_entry("from-spec", false, false)]);

    assert!(md.contains("### Spec-owned Resources"), "{md}");
    assert!(md.contains("`from-spec`"), "{md}");
    assert!(md.contains("spec `spec-7`"), "{md}");
    assert!(md.contains("api_spec_id"), "{md}");
    assert!(!md.contains("CONFLICT"), "{md}");
}

#[test]
fn spec_owned_section_calls_out_repo_conflicts() {
    let md = render_spec_owned(&[
        spec_owned_entry("from-spec", false, false),
        spec_owned_entry("shared-id", true, false),
    ]);

    assert!(md.contains("CONFLICT: this repo also declares it"), "{md}");
    assert!(
        md.contains("1 resource(s) are declared both here and by an API spec"),
        "{md}"
    );
}

#[test]
fn spec_owned_section_marks_confirmed_deletions() {
    let md = render_spec_owned(&[spec_owned_entry("from-spec", false, true)]);

    assert!(md.contains("will be DELETED"), "{md}");
    assert!(md.contains("--confirm-api-spec-deletion"), "{md}");
}

#[test]
fn review_comment_v2_renders_spec_owned_section() {
    let spec_owned = vec![spec_owned_entry("shared-id", true, false)];

    let comment = build_review_comment_v2(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &spec_owned,
        None,
        None,
        None,
        None,
        &ResolveReport::default(),
        true,
    );

    assert!(comment.contains("### Spec-owned Resources"), "{comment}");
    assert!(comment.contains("`shared-id`"), "{comment}");
    assert!(comment.contains("CONFLICT"), "{comment}");
}

#[test]
fn review_comment_v2_omits_spec_owned_section_when_empty() {
    let comment = build_review_comment_v2(
        true,
        "",
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
        None,
        None,
        None,
        None,
        &ResolveReport::default(),
        true,
    );

    assert!(!comment.contains("Spec-owned"), "{comment}");
}
