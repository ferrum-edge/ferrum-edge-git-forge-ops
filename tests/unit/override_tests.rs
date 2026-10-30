//! Hosted-only regression fixtures: no live GitHub account or gateway needed.
use std::path::Path;
use std::process::Command;

use gitforgeops::policy::github_override::{authorized_review, OverrideReview, PermissionResponse};
use gitforgeops::policy::override_input::verify_input;
use gitforgeops::policy::OverrideConfig;
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
    write(
        dir.path(),
        "resources/team/proxies/app.yaml",
        "kind: Proxy\n",
    );
    write(dir.path(), ".gitforgeops/policies.yaml", "version: 1\n");
    let head = commit(dir.path());
    let tree = head_tree(dir.path());
    (dir, head, tree)
}

/// The GitHub recursive-tree evidence for the fixture's current `HEAD`.
fn head_tree(root: &Path) -> Value {
    let tree = git(root, &["ls-tree", "-rz", "HEAD"]);
    let entries: Vec<_> = tree
        .split('\0')
        .filter(|row| !row.is_empty())
        .map(|row| {
            let (metadata, path) = row.split_once('\t').unwrap();
            let fields: Vec<_> = metadata.split_whitespace().collect();
            json!({"path": path, "mode": fields[0], "type": fields[1], "sha": fields[2]})
        })
        .collect();
    json!({"truncated": false, "tree": entries})
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
    write(
        dir.path(),
        "resources/team/proxies/app.yaml",
        "kind: Consumer\n",
    );
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

#[cfg(unix)]
#[test]
fn actual_input_accepts_a_read_only_checkout() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, head, tree) = fixture();
    let permissions: Vec<_> = walkdir::WalkDir::new(dir.path())
        .into_iter()
        .map(|entry| {
            let entry = entry.unwrap();
            let permissions = entry.metadata().unwrap().permissions();
            (entry.into_path(), permissions)
        })
        .collect();
    for (path, permissions) in &permissions {
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(permissions.mode() & !0o222),
        )
        .unwrap();
    }
    let result = verify_input(&tree, dir.path(), dir.path(), false, None);
    // Restore directory permissions so TempDir can remove the fixture even
    // when the assertion fails. The container runs this test as a non-root UID.
    for (path, permissions) in permissions {
        std::fs::set_permissions(path, permissions).unwrap();
    }
    assert_eq!(result, Ok(head));
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
    write(
        data.path(),
        "resources/team/proxies/app.yaml",
        "kind: Proxy\n",
    );
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
    assert_eq!(
        reloaded.overrides[0].authorized_head,
        decision.authorized_head
    );
    assert_eq!(reloaded.overrides[0].commit, "b".repeat(40));
}

fn permission_response(body: Value) -> PermissionResponse {
    serde_json::from_value(body).unwrap()
}

#[test]
fn maintain_role_satisfies_maintain_requirement_despite_legacy_write_field() {
    // GitHub reports Maintain as legacy `permission: write`; the real rank is
    // only in `role_name`.
    let maintainer = permission_response(json!({"permission": "write", "role_name": "maintain"}));
    assert_eq!(maintainer.effective_permission(), "maintain");
    let cfg = OverrideConfig {
        require_label: LABEL.into(),
        required_permission: "maintain".into(),
    };
    assert!(cfg.is_sufficient(maintainer.effective_permission()));

    let writer = permission_response(json!({"permission": "write", "role_name": "write"}));
    assert!(!cfg.is_sufficient(writer.effective_permission()));

    // Triage collapses to legacy `read`; the full role must still rank as triage.
    let triage = permission_response(json!({"permission": "read", "role_name": "triage"}));
    assert_eq!(triage.effective_permission(), "triage");
}

#[test]
fn custom_or_absent_role_name_falls_back_to_legacy_permission() {
    let custom =
        permission_response(json!({"permission": "write", "role_name": "release-manager"}));
    assert_eq!(custom.effective_permission(), "write");
    let absent = permission_response(json!({"permission": "admin"}));
    assert_eq!(absent.effective_permission(), "admin");
}

/// #562: every file under `.gitforgeops/` is bound input, including files Git
/// ignores. The binary reads `smoke.yaml` from disk, so an excluded untracked
/// copy must not slip past the reviewed tree.
#[test]
fn actual_input_binds_ignored_files_under_gitforgeops() {
    // `.git/info/exclude`
    let (dir, head, tree) = fixture();
    write(dir.path(), ".git/info/exclude", ".gitforgeops/smoke.yaml\n");
    assert_eq!(
        verify_input(&tree, dir.path(), dir.path(), false, None),
        Ok(head)
    );
    write(dir.path(), ".gitforgeops/smoke.yaml", "version: 2\n");
    assert!(git(dir.path(), &["status", "--porcelain"]).is_empty());
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());

    // `core.excludesFile`
    let (dir, _, tree) = fixture();
    let excludes = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(excludes.path(), "smoke.yaml\n").unwrap();
    git(
        dir.path(),
        &[
            "config",
            "core.excludesFile",
            excludes.path().to_str().unwrap(),
        ],
    );
    write(dir.path(), ".gitforgeops/smoke.yaml", "version: 2\n");
    assert!(git(dir.path(), &["status", "--porcelain"]).is_empty());
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());

    // A reviewed `.gitignore` entry.
    let (dir, _, _) = fixture();
    write(dir.path(), ".gitignore", ".gitforgeops/*.local.yaml\n");
    let head = commit(dir.path());
    let tree = head_tree(dir.path());
    assert_eq!(
        verify_input(&tree, dir.path(), dir.path(), false, None),
        Ok(head)
    );
    write(dir.path(), ".gitforgeops/smoke.local.yaml", "version: 2\n");
    assert!(git(dir.path(), &["status", "--porcelain"]).is_empty());
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());
}

/// Binding `.gitforgeops/` does not start comparing ignored build and runtime
/// outputs elsewhere.
#[test]
fn actual_input_still_ignores_build_and_runtime_outputs() {
    let (dir, head, tree) = fixture();
    write(dir.path(), ".git/info/exclude", "target/\n.worktrees/\n");
    write(dir.path(), "target/debug/gitforgeops", "binary\n");
    write(dir.path(), ".worktrees/other/src/main.rs", "// elsewhere\n");
    write(dir.path(), ".state/dev.json", "{}\n");
    write(dir.path(), "assembled/resources.yaml", "generated\n");
    assert_eq!(
        verify_input(&tree, dir.path(), dir.path(), false, None),
        Ok(head)
    );
}

/// Split trusted review copies only protected configuration into the data
/// checkout. A reviewed `.gitforgeops` file may be absent there, but each file
/// present must be the reviewed blob, and nothing unreviewed may be added.
#[test]
fn split_review_binds_present_gitforgeops_files_to_the_reviewed_tree() {
    let (source, _, _) = fixture();
    write(source.path(), ".gitforgeops/smoke.yaml", "version: 2\n");
    write(source.path(), ".gitforgeops/baseline.json", "{}\n");
    commit(source.path());
    let tree = head_tree(source.path());
    let data = tempfile::tempdir().unwrap();
    write(
        data.path(),
        "resources/team/proxies/app.yaml",
        "kind: Proxy\n",
    );
    write(data.path(), ".gitforgeops/policies.yaml", "version: 1\n");
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_ok());
    write(data.path(), ".gitforgeops/smoke.yaml", "version: 2\n");
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_ok());
    write(
        data.path(),
        ".gitforgeops/smoke.yaml",
        "version: 2\nchecks: {}\n",
    );
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_err());
    write(data.path(), ".gitforgeops/smoke.yaml", "version: 2\n");
    write(data.path(), ".gitforgeops/extra/notes.yaml", "unreviewed\n");
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_err());
}

#[cfg(unix)]
#[test]
fn actual_input_refuses_symlinks_under_gitforgeops() {
    let (dir, _, tree) = fixture();
    std::os::unix::fs::symlink("policies.yaml", dir.path().join(".gitforgeops/smoke.yaml"))
        .unwrap();
    assert!(verify_input(&tree, dir.path(), dir.path(), false, None).is_err());

    let (source, _, tree) = fixture();
    let data = tempfile::tempdir().unwrap();
    let real = tempfile::tempdir().unwrap();
    write(real.path(), "policies.yaml", "version: 1\n");
    write(
        data.path(),
        "resources/team/proxies/app.yaml",
        "kind: Proxy\n",
    );
    std::os::unix::fs::symlink(real.path(), data.path().join(".gitforgeops")).unwrap();
    assert!(verify_input(&tree, source.path(), data.path(), false, None).is_err());
}

fn policy_finding(rule_id: &str, id: &str, message: &str) -> gitforgeops::policy::PolicyFinding {
    gitforgeops::policy::PolicyFinding {
        rule_id: rule_id.into(),
        severity: gitforgeops::policy::Severity::Error,
        kind: "PluginConfig".into(),
        id: id.into(),
        namespace: "ferrum".into(),
        message: message.into(),
        remediation: None,
        overridden_by: None,
    }
}

fn active_decision() -> OverrideDecision {
    OverrideDecision {
        active: true,
        approver: Some("maintainer".into()),
        permission: Some("write".into()),
        reason: "verified".into(),
        pr_number: Some(7),
        authorized_head: Some("a".repeat(40)),
        review_id: Some(42),
        applied_revision: Some("a".repeat(40)),
    }
}

/// #562: apply re-evaluates policy after credential resolution. The override
/// covers the findings plan and review showed; a blocking finding that appears
/// only after resolution refuses apply and says why, without its value.
#[test]
fn override_covers_only_findings_present_before_credential_resolution() {
    use gitforgeops::policy::refusal::refuse_post_resolution_policy_violations;
    use gitforgeops::secrets::{
        PlaceholderAlloc, ResolveReport, ResolveResult, SecretPlaceholder, SecretScrubber,
        SlotStatus,
    };

    let reviewed = vec![policy_finding(
        "backend_scheme",
        "app",
        "http is not allowed",
    )];
    let decision = active_decision();

    // Exactly the reviewed findings: covered, apply continues.
    let mut same = reviewed.clone();
    assert!(
        refuse_post_resolution_policy_violations(&mut same, &reviewed, Some(&decision), None)
            .is_none()
    );
    assert_eq!(same[0].overridden_by.as_deref(), Some("maintainer"));

    // A resolution-only finding is not covered, even with an active override.
    let secret = "Q7m2Vx9c2L-resolved";
    let config: gitforgeops::config::schema::GatewayConfig = serde_json::from_value(json!({
        "consumers": [{
            "id": "app",
            "username": "app",
            "namespace": "ferrum",
            "credentials": {"keyauth": [{"key": secret}]}
        }]
    }))
    .unwrap();
    let report = ResolveReport {
        results: vec![ResolveResult {
            consumer_id: "app".into(),
            namespace: "ferrum".into(),
            cred_key: "keyauth/key".into(),
            slot: gitforgeops::secrets::slot_path("ferrum", "app", "keyauth/key"),
            placeholder: SecretPlaceholder {
                alloc: PlaceholderAlloc::Require,
                length_bytes: 32,
            },
            status: SlotStatus::Resolved,
        }],
        ..ResolveReport::default()
    };
    let scrubber = SecretScrubber::from_gateway_config_with_report(&config, &report);
    let mut resolved = reviewed.clone();
    resolved.push(policy_finding(
        "rate_limit_completeness",
        "limiter",
        &format!("resolved value {secret} weakens the limiter"),
    ));
    let message = refuse_post_resolution_policy_violations(
        &mut resolved,
        &reviewed,
        Some(&decision),
        Some(&scrubber),
    )
    .expect("a resolution-only finding refuses apply");
    assert!(message.contains("after credential resolution"), "{message}");
    assert!(
        message.contains("1 blocking finding(s) appeared only after credential resolution"),
        "{message}"
    );
    assert!(message.contains("does not cover them"), "{message}");
    assert!(message.contains("rate_limit_completeness"), "{message}");
    assert!(!message.contains("backend_scheme"), "{message}");
    assert!(!message.contains(secret), "{message}");
    assert_eq!(resolved[0].overridden_by.as_deref(), Some("maintainer"));
    assert!(resolved[1].is_blocking());

    // The same rule on the same resource with a different message is a
    // different finding than the one reviewed.
    let mut changed = vec![policy_finding(
        "backend_scheme",
        "app",
        "http is not allowed (resolved)",
    )];
    assert!(refuse_post_resolution_policy_violations(
        &mut changed,
        &reviewed,
        Some(&decision),
        None
    )
    .is_some());

    // Without an active override every blocking finding refuses as before.
    let mut inactive = reviewed.clone();
    let message = refuse_post_resolution_policy_violations(
        &mut inactive,
        &reviewed,
        Some(&OverrideDecision::inactive("label missing")),
        None,
    )
    .expect("no override");
    assert!(!message.contains("appeared only after"), "{message}");
}

/// #562: `GITFORGEOPS_PR_NUMBER` is either unset/blank or a positive integer.
/// Anything else is an error, never a fallback to the commit's associated PR.
#[test]
fn pr_number_override_must_be_a_positive_integer() {
    use gitforgeops::policy::github_override::parse_pr_number;
    assert_eq!(parse_pr_number(None).unwrap(), None);
    assert_eq!(parse_pr_number(Some("")).unwrap(), None);
    assert_eq!(parse_pr_number(Some("  ")).unwrap(), None);
    assert_eq!(parse_pr_number(Some("7")).unwrap(), Some(7));
    for malformed in [
        "0",
        "-1",
        "+7",
        "7 ",
        " 7",
        "seven",
        "7.0",
        "null",
        "18446744073709551616",
    ] {
        let error = parse_pr_number(Some(malformed)).expect_err(malformed);
        assert!(
            error.to_string().contains("GITFORGEOPS_PR_NUMBER"),
            "{malformed}: {error}"
        );
    }
}

/// #562: plan quotes the approver (GitHub's text) through `peer_text`, which
/// bounds it.
#[test]
fn plan_override_note_quotes_the_approver_through_peer_text() {
    use gitforgeops::policy::github_override::plan_override_note;
    let mut decision = active_decision();
    assert_eq!(
        plan_override_note(&decision),
        "Blocking findings overridden by @maintainer."
    );
    decision.approver = Some("x".repeat(20 * 1024));
    let note = plan_override_note(&decision);
    assert!(note.contains("[truncated]"), "{}", note.len());
    assert!(note.len() < 17 * 1024, "{}", note.len());
    assert_eq!(
        plan_override_note(&OverrideDecision::inactive("label missing")),
        "Override inactive: label missing."
    );
}
