use gitforgeops::diff::{
    best_practice::BestPractice, breaking::BreakingChange, resource_diff::*,
    security::SecurityFinding,
};
use gitforgeops::review::pr_comment::build_review_comment;

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
