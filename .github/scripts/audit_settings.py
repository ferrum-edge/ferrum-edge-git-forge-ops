#!/usr/bin/env python3
"""Fail when repository/deployment controls drift below the launch baseline."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from urllib.parse import quote


ALLOWED_ACTION_PATTERNS = {
    "aquasecurity/setup-trivy@*",
    "aquasecurity/trivy-action@*",
    "docker/build-push-action@*",
    "docker/login-action@*",
    "docker/metadata-action@*",
    "docker/setup-buildx-action@*",
    "docker/setup-qemu-action@*",
    "dtolnay/rust-toolchain@*",
    "taiki-e/install-action@*",
}


@dataclass
class Audit:
    violations: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def require(self, condition: bool, violation: str, evidence: str | None = None) -> None:
        if condition:
            if evidence:
                self.evidence.append(evidence)
        else:
            self.violations.append(violation)


def gh_json(path: str, *, paginate: bool = False):
    command = ["gh", "api", path]
    if paginate:
        command.extend(["--paginate", "--slurp"])
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"GitHub API request failed for {path}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def flatten_pages(value):
    if not isinstance(value, list):
        raise RuntimeError("paginated GitHub response was not an array")
    flattened = []
    for page in value:
        if not isinstance(page, list):
            raise RuntimeError("paginated GitHub response page was not an array")
        flattened.extend(page)
    return flattened


def audit_action_permissions(
    audit: Audit, workflow: dict, actions: dict, selected: dict
) -> None:
    audit.require(
        workflow.get("default_workflow_permissions") == "read",
        "repository default GITHUB_TOKEN permission must be read",
        "default GITHUB_TOKEN permission: read",
    )
    audit.require(
        workflow.get("can_approve_pull_request_reviews") is False,
        "GitHub Actions must not be allowed to approve pull requests",
        "Actions PR approval: disabled",
    )
    audit.require(
        actions.get("allowed_actions") in {"selected", "local_only"},
        "allowed Actions policy must be selected/local-only, not all actions",
        f"allowed Actions policy: {actions.get('allowed_actions')}",
    )
    audit.require(
        actions.get("sha_pinning_required") is True,
        "repository must require full-SHA pinning for Actions",
        "full-SHA Action pinning: required",
    )
    if actions.get("allowed_actions") == "selected":
        patterns = selected.get("patterns_allowed")
        configured_patterns = set(patterns) if isinstance(patterns, list) else set()
        audit.require(
            selected.get("github_owned_allowed") is True,
            "selected Actions policy must allow GitHub-owned actions used by the workflows",
        )
        audit.require(
            selected.get("verified_allowed") is False,
            "selected Actions policy must not allow every verified Marketplace creator",
        )
        audit.require(
            configured_patterns == ALLOWED_ACTION_PATTERNS,
            "selected Actions allowlist must exactly match the reviewed third-party repositories: "
            f"expected={sorted(ALLOWED_ACTION_PATTERNS)}, actual={sorted(configured_patterns)}",
            f"third-party Action allowlist: {sorted(configured_patterns)}",
        )


def ruleset_targets_branch(ruleset: dict, branch: str) -> bool:
    if ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
        return False
    ref_name = ruleset.get("conditions", {}).get("ref_name", {})
    includes = ref_name.get("include", [])
    excludes = ref_name.get("exclude", [])
    candidates = {"~DEFAULT_BRANCH", f"refs/heads/{branch}", branch}
    # This is a launch-control audit, not a general ref-pattern evaluator.
    # Accept exactly one of GitHub's three spellings for the default branch and
    # no exclusion patterns. A broad include or wildcard exclusion is too easy
    # to misread and may leave the protected branch outside the effective set.
    return len(includes) == 1 and includes[0] in candidates and not excludes


def audit_main_ruleset(
    audit: Audit,
    ruleset: dict,
    required_checks: set[str],
    state_writer_app_id: int,
) -> None:
    rules = {rule.get("type"): rule for rule in ruleset.get("rules", [])}
    for rule_type in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        audit.require(
            rule_type in rules,
            f"main ruleset is missing required rule: {rule_type}",
        )

    pull_request = rules.get("pull_request", {}).get("parameters", {})
    audit.require(
        int(pull_request.get("required_approving_review_count", 0)) >= 1,
        "main ruleset must require at least one approving review",
    )
    audit.require(
        pull_request.get("require_code_owner_review") is True,
        "main ruleset must require Code Owner review",
    )
    audit.require(
        pull_request.get("required_review_thread_resolution") is True,
        "main ruleset must require review-thread resolution",
    )
    audit.require(
        pull_request.get("dismiss_stale_reviews_on_push") is True,
        "main ruleset must dismiss stale approvals after reviewable pushes",
    )

    status_parameters = rules.get("required_status_checks", {}).get("parameters", {})
    audit.require(
        status_parameters.get("strict_required_status_checks_policy") is True,
        "main ruleset must test pull requests against the latest main commit",
    )
    configured_checks = {
        check.get("context")
        for check in status_parameters.get("required_status_checks", [])
        if isinstance(check, dict) and check.get("context")
    }
    missing_checks = sorted(required_checks - configured_checks)
    audit.require(
        not missing_checks,
        f"main ruleset is missing required status checks: {missing_checks}",
        f"required status checks: {sorted(configured_checks)}",
    )

    bypasses = ruleset.get("bypass_actors", [])
    audit.require(
        len(bypasses) == 1,
        "main ruleset must have exactly one bypass actor in any mode: the state-writer App",
    )
    if len(bypasses) == 1:
        bypass = bypasses[0]
        audit.require(
            bypass.get("actor_type") == "Integration"
            and str(bypass.get("actor_id", "")) == str(state_writer_app_id),
            "main ruleset bypass must be the configured state-writer App",
        )
        audit.require(
            bypass.get("bypass_mode") == "always",
            "main ruleset state-writer App bypass must use always mode",
        )
    audit.evidence.append(
        f"active default-branch ruleset: {ruleset.get('name')} ({ruleset.get('id')})"
    )


def ruleset_targets_release_tags(ruleset: dict, pattern: str) -> bool:
    if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
        return False
    ref_name = ruleset.get("conditions", {}).get("ref_name", {})
    return ref_name.get("include", []) == [pattern] and not ref_name.get("exclude", [])


def audit_tag_ruleset(audit: Audit, ruleset: dict) -> None:
    rules = {rule.get("type") for rule in ruleset.get("rules", [])}
    for rule_type in ("creation", "update", "deletion"):
        audit.require(
            rule_type in rules,
            f"release-tag ruleset is missing required rule: {rule_type}",
        )
    # The bypass list is release publishing's only route past the `creation`
    # rule. An empty list is therefore not "maximum strictness": nobody can push
    # a `v*` tag at all and the tag half of release.yml can never fire, so it is
    # reported as a misconfiguration rather than accepted. See
    # docs/github-launch-controls.md section 2, which states the same rule.
    bypasses = ruleset.get("bypass_actors", [])
    audit.require(
        bool(bypasses),
        "release-tag ruleset must name at least one bypass actor; with the creation rule and no bypass, no release tag can ever be pushed",
    )
    narrow_bypasses = all(
        bypass.get("actor_type") in {"Integration", "Team", "User"}
        and isinstance(bypass.get("actor_id"), int)
        and bypass.get("bypass_mode") == "always"
        for bypass in bypasses
    )
    audit.require(
        narrow_bypasses,
        "release-tag ruleset bypasses must be explicit Apps, teams, or users; broad repository roles are forbidden",
    )
    audit.evidence.append(
        f"active release-tag ruleset: {ruleset.get('name')} ({ruleset.get('id')})"
    )


def audit_environment(audit: Audit, repo: str, environment: dict, branch: str) -> None:
    name = environment.get("name")
    if not isinstance(name, str) or not name:
        audit.violations.append("environment listing contained an unnamed environment")
        return
    encoded_name = quote(name, safe="")
    detail = gh_json(f"repos/{repo}/environments/{encoded_name}")
    rules = detail.get("protection_rules", [])
    reviewer_rules = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    has_reviewers = any(rule.get("reviewers") for rule in reviewer_rules)
    audit.require(
        has_reviewers,
        f"environment {name!r} must require at least one reviewer",
    )
    prevents_self_review = any(
        rule.get("prevent_self_review") is True for rule in reviewer_rules
    )
    audit.require(
        prevents_self_review,
        f"environment {name!r} must prevent self-review",
    )

    policy = detail.get("deployment_branch_policy") or {}
    branch_limited = policy.get("protected_branches") is True
    if policy.get("custom_branch_policies") is True:
        pages = gh_json(
            f"repos/{repo}/environments/{encoded_name}/deployment-branch-policies?per_page=100",
            paginate=True,
        )
        if not isinstance(pages, list) or not all(isinstance(page, dict) for page in pages):
            raise RuntimeError("deployment branch policy response had an unexpected shape")
        policies = [
            item
            for page in pages
            for item in page.get("branch_policies", [])
            if isinstance(item, dict)
        ]
        policy_names = [item.get("name") for item in policies]
        branch_limited = policy_names == [branch]
    audit.require(
        branch_limited,
        f"environment {name!r} must restrict deployments to protected branches or exact {branch!r}",
    )
    if has_reviewers and branch_limited:
        audit.evidence.append(f"environment {name}: reviewer + branch policy present")


def run(
    repo: str,
    branch: str,
    required_checks: set[str],
    state_writer_app_id: int,
    release_tag_pattern: str,
) -> Audit:
    audit = Audit()
    workflow = gh_json(f"repos/{repo}/actions/permissions/workflow")
    actions = gh_json(f"repos/{repo}/actions/permissions")
    selected = (
        gh_json(f"repos/{repo}/actions/permissions/selected-actions")
        if actions.get("allowed_actions") == "selected"
        else {}
    )
    audit_action_permissions(audit, workflow, actions, selected)

    summaries = gh_json(f"repos/{repo}/rulesets?per_page=100", paginate=True)
    rulesets = []
    for summary in flatten_pages(summaries):
        identifier = summary.get("id")
        if identifier is not None:
            rulesets.append(gh_json(f"repos/{repo}/rulesets/{identifier}"))
    matching = [item for item in rulesets if ruleset_targets_branch(item, branch)]
    audit.require(
        len(matching) == 1,
        f"expected exactly one active ruleset targeting {branch!r}; found {len(matching)}",
    )
    if len(matching) == 1:
        audit_main_ruleset(
            audit, matching[0], required_checks, state_writer_app_id
        )

    tag_matching = [
        item
        for item in rulesets
        if ruleset_targets_release_tags(item, release_tag_pattern)
    ]
    audit.require(
        len(tag_matching) == 1,
        "expected exactly one active ruleset targeting release tags "
        f"{release_tag_pattern!r}; found {len(tag_matching)}",
    )
    if len(tag_matching) == 1:
        audit_tag_ruleset(audit, tag_matching[0])

    environments = gh_json(f"repos/{repo}/environments?per_page=100", paginate=True)
    if not isinstance(environments, list) or not all(
        isinstance(page, dict) for page in environments
    ):
        raise RuntimeError("environment listing response had an unexpected shape")
    # The endpoint wraps entries in an `environments` field on every page.
    listed = [
        item
        for page in environments
        for item in page.get("environments", [])
        if isinstance(item, dict)
    ]
    audit.require(bool(listed), "repository must define at least one protected environment")
    for environment in listed:
        audit_environment(audit, repo, environment, branch)
    return audit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--required-check", action="append", default=[])
    parser.add_argument("--state-writer-app-id", required=True, type=int)
    parser.add_argument("--release-tag-pattern", default="refs/tags/v*")
    args = parser.parse_args()
    if not os.environ.get("GH_TOKEN"):
        print(
            "settings audit requires GH_TOKEN with read access to repository administration settings",
            file=sys.stderr,
        )
        return 1
    try:
        audit = run(
            args.repo,
            args.branch,
            set(args.required_check),
            args.state_writer_app_id,
            args.release_tag_pattern,
        )
    except (
        RuntimeError,
        json.JSONDecodeError,
        AttributeError,
        TypeError,
        ValueError,
    ) as error:
        print(f"settings audit failed closed: {error}", file=sys.stderr)
        return 1

    print("Repository protection evidence:")
    for item in audit.evidence:
        print(f"  PASS: {item}")
    if audit.violations:
        print("Repository protection violations:", file=sys.stderr)
        for item in audit.violations:
            print(f"  FAIL: {item}", file=sys.stderr)
        return 1
    print("All launch protection controls are active.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
