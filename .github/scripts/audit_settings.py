#!/usr/bin/env python3
"""Fail when repository/deployment controls drift below the launch baseline."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

# The launch-required status checks, spelled as ruleset contexts (the job name,
# not the `Workflow / job` pull-request display label). `settings-audit.yml`
# still passes them explicitly so a workflow diff shows what is enforced;
# `bootstrap_repo_settings.py` imports this tuple to build the ruleset it
# applies, so the writer and the auditor cannot drift apart.
REQUIRED_STATUS_CHECKS = (
    "rust-ci-check",
    "security-cargo-audit",
    "security-supply-chain-policy",
    "state-guard-reject-state-edits",
    "gitforgeops-required-static-validation",
)

RELEASE_TAG_PATTERN = "refs/tags/v*"

# `settings-audit.yml` binds this environment so its administration-read token
# is released only to a job running from the protected default branch. It is
# not a deployment target: nothing applies to a gateway through it and it holds
# no gateway credential, so it is exempt from the reviewer and self-review rules
# (a reviewer would park every scheduled run in "waiting for approval", which is
# exactly the silently-stopped audit the workflow exists to prevent) and it does
# not satisfy the at-least-one-protected-environment requirement. Its branch
# policy is audited like any other environment's — that restriction is the whole
# point of moving the token here.
SETTINGS_AUDIT_ENVIRONMENT = "settings-audit"

# A deployment environment that opted into unattended drift monitoring gets a
# second GitHub Environment named `<deployment-env>-monitor`. It exists only so
# a nightly `gitforgeops diff` can read the gateway without parking in "waiting
# for approval" — an approval-gated environment withholds its secrets until a
# human releases the job, which turns scheduled monitoring into no monitoring.
#
# That is a narrow, named exception and not a general weakening: the reviewer
# rule is waived ONLY for this suffix, only when the deployment environment it
# is derived from also exists, and only while the environment holds no
# deployment, broker or state-writing authority (below). `repo_config.rs`
# reserves the suffix so a deployment environment can never be named into the
# waiver, and `check_supply_chain.py` separately fences what `drift-check.yml`
# is allowed to reach at all.
MONITORING_ENVIRONMENT_SUFFIX = "-monitor"

# Secret NAMES that must never appear in a monitoring environment. Names are
# readable through the API; values are not, and are never requested. Presence
# of a name is not proof a value is correct, but absence is proof the job
# cannot reach that authority.
MONITORING_FORBIDDEN_SECRETS = (
    "FERRUM_GH_PROVISIONER_TOKEN",
    "GITFORGEOPS_STATE_APP_PRIVATE_KEY",
    "SETTINGS_AUDIT_TOKEN",
)
MONITORING_FORBIDDEN_SECRET_PREFIXES = ("FERRUM_CREDS_BUNDLE",)

# The drift workflow whose last successful run is the monitoring evidence.
MONITORING_WORKFLOW_FILE = "drift-check.yml"
# The cron is daily; two periods of slack absorbs one missed or queued run
# without letting a silently disabled schedule pass for coverage. GitHub
# disables scheduled workflows after 60 days without repository activity, so
# "the cron line is still in the file" proves nothing on its own.
MONITORING_MAX_AGE_HOURS = 48

# A template repository is the copy customers clone from. It has no deployment
# environments and no state-writer App, because nothing on it ever applies to a
# gateway or commits an ownership ledger. Those two controls are therefore not
# audited there; everything else is.
TEMPLATE_SKIPPED_CONTROLS = (
    "template repository mode: state-writer App bypass on the default-branch "
    "ruleset is not audited (a template never commits an ownership ledger)",
    "template repository mode: the at-least-one-protected-environment "
    "requirement is not audited (a template has no deployment target)",
)


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
    state_writer_app_id: int | None,
    template_repo: bool = False,
) -> None:
    rules = {rule.get("type"): rule for rule in ruleset.get("rules", [])}
    for rule_type in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        audit.require(
            rule_type in rules,
            f"main ruleset is missing required rule: {rule_type}",
        )

    pull_request = rules.get("pull_request", {}).get("parameters", {})
    audit.require(
        pull_request.get("required_approving_review_count") == 0,
        "main ruleset must allow root-reviewed PRs without approval submissions",
    )
    audit.require(
        pull_request.get("require_code_owner_review") is False,
        "main ruleset must not require Code Owner approval",
    )
    for field in (
        "require_last_push_approval",
        "require_extra_approval_for_unattributed_changes",
    ):
        audit.require(
            pull_request.get(field, False) is False,
            f"main ruleset must not require additional approval via {field}",
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

    if not template_repo:
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


def is_monitoring_environment(name: str, all_names: set[str]) -> bool:
    """Is this the derived read-only monitoring environment of a real one?

    The suffix alone is not enough: an environment named `anything-monitor`
    with no corresponding deployment environment would otherwise mint its own
    reviewer waiver. `repo_config.rs` refuses to name a deployment environment
    into the suffix, so the base name can only be a genuine deployment target.
    """
    if not name.endswith(MONITORING_ENVIRONMENT_SUFFIX):
        return False
    base = name[: -len(MONITORING_ENVIRONMENT_SUFFIX)]
    return bool(base) and base in all_names


def audit_monitoring_secrets(audit: Audit, repo: str, name: str) -> None:
    """A monitoring environment may hold gateway read material and nothing else.

    Only secret *names* are read — never values, and never through a path that
    could print one. A name present is not proof its value is correct, which is
    why this check only ever proves the negative: the job cannot reach an
    authority whose secret is not bound to it.
    """
    encoded_name = quote(name, safe="")
    pages = gh_json(
        f"repos/{repo}/environments/{encoded_name}/secrets?per_page=100",
        paginate=True,
    )
    if not isinstance(pages, list) or not all(isinstance(page, dict) for page in pages):
        raise RuntimeError("environment secret listing had an unexpected shape")
    secret_names = {
        item.get("name")
        for page in pages
        for item in page.get("secrets", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    forbidden = sorted(
        secret
        for secret in secret_names
        if secret in MONITORING_FORBIDDEN_SECRETS
        or secret.startswith(MONITORING_FORBIDDEN_SECRET_PREFIXES)
    )
    audit.require(
        not forbidden,
        f"monitoring environment {name!r} must not hold deployment, credential-broker "
        f"or state-writing secrets; found {', '.join(forbidden)}. It runs without a "
        "required reviewer, so its authority must stop at reading the gateway",
        f"environment {name}: holds no deployment/broker/state secret",
    )


def audit_monitoring_coverage(
    audit: Audit, repo: str, monitoring_names: set[str], max_age_hours: int, now: datetime
) -> None:
    """A cron entry is not monitoring coverage; a completed run is.

    The schedule can be disabled by GitHub after 60 days of repository
    inactivity, turned off in the Actions tab, or fail every night against an
    unreachable gateway — and in each case the workflow file still contains a
    perfectly good `cron:` line. So the evidence is the newest *successful* run
    of the drift workflow, not its existence.

    Only enforced once at least one environment has opted into unattended
    monitoring. A repository that has not is reported, accurately, as having
    approval-gated monitoring and no unattended coverage claim.
    """
    if not monitoring_names:
        audit.evidence.append(
            "drift monitoring is approval-gated: no environment declares "
            "`monitoring.unattended`, so scheduled checks wait for a reviewer "
            "and no unattended coverage is claimed"
        )
        return
    listed = ", ".join(sorted(monitoring_names))
    try:
        runs = gh_json(
            f"repos/{repo}/actions/workflows/{MONITORING_WORKFLOW_FILE}/runs"
            "?status=success&per_page=1"
        )
    except RuntimeError as error:
        audit.violations.append(
            f"unattended drift monitoring is configured ({listed}) but its run "
            f"history could not be read: {error}"
        )
        return
    entries = runs.get("workflow_runs") if isinstance(runs, dict) else None
    newest = entries[0] if isinstance(entries, list) and entries else None
    timestamp = newest.get("updated_at") if isinstance(newest, dict) else None
    if not isinstance(timestamp, str):
        audit.violations.append(
            f"unattended drift monitoring is configured ({listed}) but "
            f"{MONITORING_WORKFLOW_FILE} has never completed successfully; a cron "
            "entry alone is not monitoring coverage"
        )
        return
    try:
        completed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        audit.violations.append(
            f"{MONITORING_WORKFLOW_FILE} reported an unparseable completion time "
            f"{timestamp!r}"
        )
        return
    age_hours = (now - completed).total_seconds() / 3600
    audit.require(
        age_hours <= max_age_hours,
        f"unattended drift monitoring last completed successfully {age_hours:.0f}h "
        f"ago ({timestamp}), beyond the {max_age_hours}h window; scheduled "
        "monitoring has stopped even though the cron entry is still present",
        f"drift monitoring completed successfully {age_hours:.0f}h ago "
        f"({timestamp}) for {listed}",
    )


def audit_environment(
    audit: Audit,
    repo: str,
    environment: dict,
    branch: str,
    all_names: set[str] | None = None,
) -> None:
    name = environment.get("name")
    if not isinstance(name, str) or not name:
        audit.violations.append("environment listing contained an unnamed environment")
        return
    all_names = all_names or set()
    encoded_name = quote(name, safe="")
    detail = gh_json(f"repos/{repo}/environments/{encoded_name}")
    rules = detail.get("protection_rules", [])
    reviewer_rules = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    has_reviewers = any(rule.get("reviewers") for rule in reviewer_rules)
    # The settings-audit environment gates a read-only token, not a deployment.
    # Requiring a reviewer there would hold every scheduled run for approval and
    # produce the silently-stopped audit this whole control exists to prevent.
    # Its branch policy is still audited below.
    if name == SETTINGS_AUDIT_ENVIRONMENT:
        audit.evidence.append(
            f"environment {name}: reviewer rules waived (gates the "
            "administration-read audit token, deploys nothing)"
        )
        has_reviewers = True
    elif is_monitoring_environment(name, all_names):
        # Same shape of exception, same reason: a required reviewer on an
        # environment whose only job is a scheduled read produces a check that
        # never completes. The waiver is paid for by the secret-name fence.
        audit.evidence.append(
            f"environment {name}: reviewer rules waived (read-only drift "
            "monitoring for "
            f"{name[: -len(MONITORING_ENVIRONMENT_SUFFIX)]!r}, mutates nothing)"
        )
        has_reviewers = True
        audit_monitoring_secrets(audit, repo, name)
    else:
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
    state_writer_app_id: int | None,
    release_tag_pattern: str,
    template_repo: bool = False,
    monitoring_max_age_hours: int = MONITORING_MAX_AGE_HOURS,
    now: datetime | None = None,
) -> Audit:
    audit = Audit()
    if template_repo:
        audit.evidence.extend(TEMPLATE_SKIPPED_CONTROLS)
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
            audit, matching[0], required_checks, state_writer_app_id, template_repo
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
    names = {
        item.get("name") for item in listed if isinstance(item.get("name"), str)
    }
    # A template repository has no deployment environment, but it still runs the
    # settings audit, so it still needs the environment that holds the audit
    # token — in both modes.
    audit.require(
        SETTINGS_AUDIT_ENVIRONMENT in names,
        f"repository must define the {SETTINGS_AUDIT_ENVIRONMENT!r} environment; "
        "settings-audit.yml binds it so the administration-read token is "
        "released only to the protected default branch",
        f"audit-token environment {SETTINGS_AUDIT_ENVIRONMENT} present",
    )
    monitoring_names = {
        name for name in names if is_monitoring_environment(name, names)
    }
    if not template_repo:
        # Neither the audit-token environment nor a read-only monitoring
        # environment is a deployment target, so neither can be the one
        # protected environment a deployment repository is required to have.
        audit.require(
            bool(names - {SETTINGS_AUDIT_ENVIRONMENT} - monitoring_names),
            "repository must define at least one protected environment",
        )
    for environment in listed:
        audit_environment(audit, repo, environment, branch, names)
    if not template_repo:
        audit_monitoring_coverage(
            audit,
            repo,
            monitoring_names,
            monitoring_max_age_hours,
            now or datetime.now(timezone.utc),
        )
    return audit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--required-check", action="append", default=[])
    parser.add_argument("--state-writer-app-id", type=int)
    parser.add_argument("--release-tag-pattern", default=RELEASE_TAG_PATTERN)
    parser.add_argument(
        "--monitoring-max-age-hours",
        type=int,
        default=MONITORING_MAX_AGE_HOURS,
        help=(
            "how recently the drift workflow must have completed successfully "
            "before unattended monitoring counts as covered"
        ),
    )
    parser.add_argument(
        "--template-repo",
        action="store_true",
        help=(
            "audit the template repository customers copy: skip the state-writer "
            "App bypass and protected-environment requirements, audit everything else"
        ),
    )
    args = parser.parse_args()
    required_checks = set(args.required_check) or set(REQUIRED_STATUS_CHECKS)
    if args.state_writer_app_id is None and not args.template_repo:
        print(
            "settings audit requires --state-writer-app-id unless --template-repo is set",
            file=sys.stderr,
        )
        return 1
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
            required_checks,
            args.state_writer_app_id,
            args.release_tag_pattern,
            args.template_repo,
            args.monitoring_max_age_hours,
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
