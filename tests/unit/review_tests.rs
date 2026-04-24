use gitforgeops::diff::{
    best_practice::BestPractice, breaking::BreakingChange, resource_diff::*,
    security::SecurityFinding,
};
use gitforgeops::policy::config::OverrideConfig;
use gitforgeops::policy::{PolicyFinding, Severity};
use gitforgeops::review::pr_comment::{build_review_comment, build_review_comment_v2};
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
        message: "Literal credential detected".to_string(),
    }];
    let comment = build_review_comment(true, "", &[], &[], &findings, &[], None);
    assert!(comment.contains("Literal credential"));
}

#[test]
fn review_comment_includes_best_practices() {
    let practices = vec![BestPractice {
        kind: "Proxy".to_string(),
        id: "proxy-1".to_string(),
        message: "No rate limiting plugin".to_string(),
    }];
    let comment = build_review_comment(true, "", &[], &[], &[], &practices, None);
    assert!(comment.contains("rate limiting"));
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
        None,
        Some(&override_cfg),
        None,
        None,
        &ResolveReport::default(),
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
        None,
        None,
        None,
        None,
        &ResolveReport::default(),
    );

    assert!(comment.contains("gitforgeops/policy-override"));
    assert!(comment.contains("`write` permission"));
}
