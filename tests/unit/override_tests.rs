//! Hosted-only regression fixtures: no live GitHub account or gateway needed.
use std::path::Path;
use std::process::Command;

use gitforgeops::policy::github_override::{authorized_review, OverrideReview};
use gitforgeops::policy::override_input::verify_input;
use gitforgeops::policy::OverrideDecision;
use gitforgeops::state::{OverrideRecord, StateFile};
use serde_json::{json, Value};

const LABEL: &str = "gitforgeops/policy-override";

fn review(head: Option<&str>, state: &str, body: &str) -> OverrideReview {
    serde_json::from_value(json!({
        "id": 42, "commit_id": head, "state": state, "body": body,
        "user": {"login": "maintainer"}
    }))
    .unwrap()
}

#[test]
fn override_review_binds_immutable_commit_and_explicit_intent() {
    let head = "a".repeat(40);
    let next = "b".repeat(40);
    let marker = format!("gitforgeops-override {LABEL}");
    for state in ["APPROVED", "COMMENTED"] {
        let reviews = [review(Some(&head), state, &marker)];
        assert!(authorized_review(&reviews, "maintainer", LABEL, &head).is_some());
        assert!(authorized_review(&reviews, "maintainer", LABEL, &next).is_none());
        assert!(authorized_review(&reviews, "different-labeler", LABEL, &head).is_none());
        assert!(authorized_review(&reviews, "maintainer", "different-label", &head).is_none());
    }
    for candidate in [
        review(None, "APPROVED", &marker),
        review(Some(&head), "PENDING", &marker),
        review(Some(&head), "DISMISSED", &marker),
        review(Some(&head), "CHANGES_REQUESTED", &marker),
        review(Some(&head), "APPROVED", "LGTM"),
        review(Some(&head), "APPROVED", &format!("quoted: {marker}")),
    ] {
        assert!(authorized_review(&[candidate], "maintainer", LABEL, &head).is_none());
    }
}

#[test]
fn later_review_revokes_override_and_other_users_cannot_reinstate_it() {
    let head = "a".repeat(40);
    let marker = format!("gitforgeops-override {LABEL}");
    let reviews = [
        review(Some(&head), "APPROVED", &marker),
        review(Some(&head), "CHANGES_REQUESTED", "reconsidered"),
    ];
    assert!(authorized_review(&reviews, "maintainer", LABEL, &head).is_none());
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn write(root: &Path, path: &str, content: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn commit(root: &Path) -> String {
    git(root, &["add", "."]);
    git(root, &["commit", "--no-verify", "-m", "fixture"]);
    git(root, &["rev-parse", "HEAD"]).trim().into()
}

fn fixture() -> (tempfile::TempDir, String, Value) {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init"]);
    git(dir.path(), &["config", "user.name", "Fixture"]);
    git(
        dir.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(dir.path(), &["config", "commit.gpgsign", "false"]);
    write(dir.path(), "src/main.rs", "// reviewed executable source\n");
    write(dir.path(), "resources/team/proxies/app.yaml", "kind: Proxy\n");
    write(dir.path(), ".gitforgeops/policies.yaml", "version: 1\n");
    let head = commit(dir.path());
    let tree = git(dir.path(), &["ls-tree", "-rz", "HEAD"]);
    let entries: Vec<_> = tree
        .split('\0')
        .filter(|row| !row.is_empty())
        .map(|row| {
            let (metadata, path) = row.split_once('\t').unwrap();
            let fields: Vec<_> = metadata.split_whitespace().collect();
            json!({"path": path, "mode": fields[0], "type": fields[1], "sha": fields[2]})
        })
        .collect();
    (dir, head, json!({"truncated": false, "tree": entries}))
}

#[test]
fn actual_input_allows_merge_and_generated_state_only_descendants() {
    let (dir, head, tree) = fixture();
    assert_eq!(
        verify_input(&tree, dir.path(), dir.path(), false, None),
        Ok(head.clone())
    );
    // A squash merge can have a distinct commit with the same reviewed input.
    write(dir.path(), ".state/dev.json", "{}\n");
    let merge = commit(dir.path());
    write(dir.path(), "assembled/dev.yaml", "generated\n");
    let descendant = commit(dir.path());
    assert_eq!(
        verify_input(&tree, dir.path(), dir.path(), true, Some(&merge)),
        Ok(descendant)
    );
    assert!(verify_input(&tree, dir.path(), dir.path(), true, None).is_err());
    assert!(verify_input(&tree, dir.path(), dir.path(), true, Some(&"f".repeat(40))).is_err());
    write(dir.path(), "resources/team/proxies/app.yaml", "kind: Consumer\n");
    commit(dir.path());
    assert!(verify_input(&tree, dir.path(), dir.path(), true, Some(&merge)).is_err());
}

#[test]
fn actual_input_rejects_dirty_executable_policy_overlay_and_untracked_yaml() {
    for path in [
        "src/main.rs",
        ".gitforgeops/policies.yaml",
        "resources/team/proxies/app.yaml",
        "resources/team/proxies/new.yaml",
        "overlays/production/team/proxies/app.yaml",
    ] {
        let (dir, _, tree) = fixture();
        write(dir.path(), path, "changed\n");
        assert!(
            verify_input(&tree, dir.path(), dir.path(), false, None).is_err(),
            "{path}"
        );
    }
    let (dir, _, mut tree) = fixture();
    tree["truncated"] = json!(true);
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());
    assert!(verify_input(&json!({}), dir.path(), dir.path(), false, None).is_err());
}

#[test]
fn source_hashing_ignores_git_stat_cache_and_rejects_staged_new_executables() {
    let (dir, _, tree) = fixture();
    git(
        dir.path(),
        &["update-index", "--assume-unchanged", "src/main.rs"],
    );
    write(dir.path(), "src/main.rs", "// hidden dirty source\n");
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());
    let (dir, _, tree) = fixture();
    write(dir.path(), "build.rs", "// newly staged build input\n");
    git(dir.path(), &["add", "build.rs"]);
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());
}

#[test]
fn split_trusted_review_proves_candidate_bytes_and_protected_executable() {
    let (source, _, tree) = fixture();
    let data = tempfile::tempdir().unwrap();
    write(data.path(), "resources/team/proxies/app.yaml", "kind: Proxy\n");
    write(data.path(), ".gitforgeops/policies.yaml", "version: 1\n");
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_ok());
    write(data.path(), ".gitforgeops/policies.yaml", "version: 2\n");
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_err());
    write(data.path(), ".gitforgeops/policies.yaml", "version: 1\n");
    write(
        source.path(),
        "src/main.rs",
        "// different protected executable\n",
    );
    commit(source.path());
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_err());
}

#[test]
fn override_audit_distinguishes_reviewed_and_applied_revisions_and_loads_legacy() {
    let old: OverrideRecord = serde_json::from_value(json!({
        "rule_id": "backend_scheme", "commit": "legacy", "approver": "alice",
        "recorded_at": "2026-01-01T00:00:00Z"
    }))
    .unwrap();
    assert!(old.authorized_head.is_none());
    assert!(old.pr_number.is_none());
    let decision = OverrideDecision {
        active: true,
        approver: Some("maintainer".into()),
        permission: Some("write".into()),
        reason: "verified".into(),
        pr_number: Some(7),
        authorized_head: Some("a".repeat(40)),
        review_id: Some(42),
        applied_revision: Some("b".repeat(40)),
    };
    let mut state = StateFile::default();
    state.record_verified_override("diff.security", &decision);
    state.record_verified_override("backend_scheme", &OverrideDecision::inactive("stale"));
    let reloaded: StateFile = serde_json::from_value(serde_json::to_value(state).unwrap()).unwrap();
    assert_eq!(reloaded.overrides.len(), 1);
    assert_eq!(reloaded.overrides[0].pr_number, Some(7));
    assert_eq!(reloaded.overrides[0].review_id, Some(42));
    assert_eq!(reloaded.overrides[0].authorized_head, decision.authorized_head);
    assert_eq!(reloaded.overrides[0].commit, "b".repeat(40));
}
