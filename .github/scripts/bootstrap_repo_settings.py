#!/usr/bin/env python3
"""Apply the gitforgeops launch baseline to a repository. Dry run by default.

GitHub repository settings — Actions policy, rulesets, security features,
labels, environments — are not carried by "Use this template" or by a fork.
Every customer therefore has to recreate them, and
`docs/github-launch-controls.md` describes doing it by hand. This script does
the same work through the REST API so it can be repeated, reviewed as a diff,
and re-run after someone changes a setting in the UI.

It writes nothing without `--apply`. Without that flag it prints the plan and,
for each control, the difference between the repository's current state and the
baseline.

Secrets are deliberately out of scope: this script neither accepts nor prints a
secret value. It ends by listing the exact `gh secret set` commands the operator
still has to run themselves.

The baseline constants live in `audit_settings.py` and are imported from there,
so the writer and the scheduled auditor cannot drift apart.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_settings import (  # noqa: E402  (the path bootstrap above must run first)
    ALLOWED_ACTION_PATTERNS,
    RELEASE_TAG_PATTERN,
    REQUIRED_STATUS_CHECKS,
)

CREATE = "CREATE"
UPDATE = "UPDATE"
UNCHANGED = "UNCHANGED"
BLOCKED = "BLOCKED"
FAILED = "FAILED"

MAIN_RULESET_NAME = "main"
RELEASE_TAG_RULESET_NAME = "release-tags"
# GitHub's built-in repository roles. 5 is Admin; it is the only actor a solo
# maintainer with no team and no App can name.
REPOSITORY_ADMIN_ROLE_ID = 5
STATE_APP_VARIABLE = "GITFORGEOPS_STATE_APP_ID"
TEMPLATE_VARIABLE = "GITFORGEOPS_TEMPLATE_REPO"
DEFAULT_CONFIG_PATH = Path(".gitforgeops/config.yaml")

OVERRIDE_LABELS = (
    {
        "name": "gitforgeops/policy-override",
        "color": "B60205",
        "description": (
            "Bypass blocking policy violations on this PR (requires write permission)"
        ),
    },
    {
        "name": "gitforgeops/state-override",
        "color": "B60205",
        "description": "Allow this PR to modify the CI-owned .state/ ledger",
    },
)

# Printed as the manual remainder. Values never pass through this script.
REPOSITORY_SECRETS = ("SETTINGS_AUDIT_TOKEN",)
ENVIRONMENT_SECRETS = (
    ("FERRUM_GATEWAY_URL", "required for api mode; must be an https:// URL"),
    ("FERRUM_ADMIN_JWT_SECRET", "required for api mode; at least 32 characters"),
    (
        "GITFORGEOPS_STATE_APP_PRIVATE_KEY",
        "required; PEM private key of the state-writer App",
    ),
    (
        "FERRUM_GH_PROVISIONER_TOKEN",
        "required only for the credential broker (allocate/rotate)",
    ),
    ("FERRUM_GATEWAY_CA_CERT", "optional; base64 PEM for a private CA"),
    ("FERRUM_GATEWAY_CLIENT_CERT", "optional; base64 PEM, mTLS (needs the key too)"),
    ("FERRUM_GATEWAY_CLIENT_KEY", "optional; base64 PEM, mTLS (needs the cert too)"),
)

ENVIRONMENT_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
REPOSITORY_NAME = re.compile(r"\A[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\Z")
HTTP_STATUS = re.compile(r"\(HTTP (\d{3})\)")


class ApiError(RuntimeError):
    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class GitHubApi:
    """Thin `gh api` wrapper, split so tests can substitute a fake."""

    def __init__(self, *, dry_run: bool) -> None:
        self.dry_run = dry_run

    def get(self, path: str, *, paginate: bool = False):
        command = ["gh", "api", path]
        if paginate:
            command.extend(["--paginate", "--slurp"])
        return self._decode(*self._run(command))

    def write(self, method: str, path: str, body: dict | None = None):
        command = ["gh", "api", "--method", method, path]
        payload = None
        if body is not None:
            command.append("--input=-")
            payload = json.dumps(body)
        return self._decode(*self._run(command, payload))

    def _run(self, command: list[str], payload: str | None = None):
        result = subprocess.run(
            command, check=False, text=True, capture_output=True, input=payload
        )
        return result.returncode, result.stdout, result.stderr

    @staticmethod
    def _decode(returncode: int, stdout: str, stderr: str):
        if returncode != 0:
            match = HTTP_STATUS.search(stderr)
            status = int(match.group(1)) if match else None
            raise ApiError(status, stderr.strip() or "GitHub API request failed")
        if not stdout.strip():
            return None
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as error:
            raise ApiError(None, f"GitHub API response was not JSON: {error}") from error


@dataclass
class Step:
    action: str
    target: str
    summary: str
    details: list[str] = field(default_factory=list)
    writes: list[tuple[str, str, dict | None]] = field(default_factory=list)


@dataclass
class Plan:
    steps: list[Step] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(step.action in {BLOCKED, FAILED} for step in self.steps)


def render(value) -> str:
    return json.dumps(value, sort_keys=True)


def field_differences(current, desired: dict) -> list[str]:
    """Report every declared key whose current value differs.

    Only the keys the baseline declares are compared. GitHub adds defaults to
    rulesets and environments that this script has no opinion about, and
    treating them as drift would make every run report an update.
    """
    if not isinstance(current, dict):
        current = {}
    lines = []
    for key in sorted(desired):
        want = desired[key]
        have = current.get(key, "<absent>")
        if have != want:
            lines.append(f"{key}: {render(have)} -> {render(want)}")
    return lines


def optional_get(api: GitHubApi, path: str, *, absent_statuses=(404,)):
    """GET a resource whose absence is an expected answer, not an error."""
    try:
        return api.get(path)
    except ApiError as error:
        if error.status in absent_statuses:
            return None
        raise


# --------------------------------------------------------------------------
# `.gitforgeops/config.yaml`
# --------------------------------------------------------------------------


def environment_names_from_config(text: str) -> list[str]:
    """Read the environment names out of `.gitforgeops/config.yaml`.

    This is a deliberately small reader rather than a YAML parse: the script
    runs on a customer's laptop, PyYAML is not in the standard library, and the
    only thing needed here is the set of keys directly under `environments:`.
    Anything that is not a plain, correctly indented mapping key is ignored,
    and `--environment` overrides the file entirely.
    """
    names: list[str] = []
    inside = False
    depth: int | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if indent == 0:
            inside = stripped.rstrip() == "environments:"
            depth = None
            continue
        if not inside:
            continue
        if depth is None:
            depth = indent
        if indent != depth or not stripped.endswith(":"):
            continue
        name = stripped[:-1].strip().strip("'\"")
        if ENVIRONMENT_NAME.match(name) and name not in names:
            names.append(name)
    return names


def resolve_environments(args) -> list[str]:
    if args.environment:
        return list(dict.fromkeys(args.environment))
    config = Path(args.config)
    if not config.is_file():
        return []
    return environment_names_from_config(config.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Actor resolution
# --------------------------------------------------------------------------


def resolve_user(api: GitHubApi, login: str) -> dict:
    user = api.get(f"users/{quote(login, safe='')}")
    identifier = user.get("id") if isinstance(user, dict) else None
    if not isinstance(identifier, int):
        raise ApiError(None, f"GitHub user {login!r} has no numeric id")
    return {"type": "User", "id": identifier}


def resolve_team(api: GitHubApi, slug: str) -> dict:
    org, _, name = slug.partition("/")
    if not org or not name:
        raise ApiError(None, f"team {slug!r} must be spelled org/slug")
    team = api.get(f"orgs/{quote(org, safe='')}/teams/{quote(name, safe='')}")
    identifier = team.get("id") if isinstance(team, dict) else None
    if not isinstance(identifier, int):
        raise ApiError(None, f"team {slug!r} has no numeric id")
    return {"type": "Team", "id": identifier}


def resolve_reviewers(api: GitHubApi, args) -> list[dict]:
    reviewers = [resolve_user(api, login) for login in args.reviewer]
    reviewers.extend(resolve_team(api, slug) for slug in args.reviewer_team)
    return reviewers


def resolve_bypass_actor(api: GitHubApi, spec: str) -> dict:
    """Parse `admin`, `app:<id>`, `user:<login>`, or `team:<org/slug>`."""
    if spec == "admin":
        return {
            "actor_type": "RepositoryRole",
            "actor_id": REPOSITORY_ADMIN_ROLE_ID,
            "bypass_mode": "always",
        }
    kind, _, value = spec.partition(":")
    if not value:
        raise ApiError(None, f"bypass actor {spec!r} must be admin, app:, user:, or team:")
    if kind == "app":
        if not value.isdigit():
            raise ApiError(None, "app: bypass actor takes the numeric App id")
        return {
            "actor_type": "Integration",
            "actor_id": int(value),
            "bypass_mode": "always",
        }
    if kind == "user":
        return {
            "actor_type": "User",
            "actor_id": resolve_user(api, value)["id"],
            "bypass_mode": "always",
        }
    if kind == "team":
        return {
            "actor_type": "Team",
            "actor_id": resolve_team(api, value)["id"],
            "bypass_mode": "always",
        }
    raise ApiError(None, f"bypass actor {spec!r} must be admin, app:, user:, or team:")


# --------------------------------------------------------------------------
# Desired ruleset shapes
# --------------------------------------------------------------------------


def main_ruleset_body(bypass_actors: list[dict]) -> dict:
    return {
        "name": MAIN_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": bypass_actors,
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "require_code_owner_review": True,
                    "required_review_thread_resolution": True,
                    "dismiss_stale_reviews_on_push": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": context} for context in REQUIRED_STATUS_CHECKS
                    ],
                },
            },
            # `[skip ci]` suppresses every workflow, required checks included.
            # The ledger commits that used to carry it now use `paths-ignore`
            # in release.yml instead; nothing else may reintroduce the marker.
            {
                "type": "commit_message_pattern",
                "parameters": {
                    "name": "no skip-ci on main",
                    "operator": "contains",
                    "pattern": "[skip ci]",
                    "negate": True,
                },
            },
        ],
    }


def release_tag_ruleset_body(bypass_actors: list[dict]) -> dict:
    return {
        "name": RELEASE_TAG_RULESET_NAME,
        "target": "tag",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": [RELEASE_TAG_PATTERN], "exclude": []}
        },
        "bypass_actors": bypass_actors,
        "rules": [
            {"type": "creation"},
            {"type": "update"},
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
    }


def normalize_actors(actors) -> list[list]:
    if not isinstance(actors, list):
        return []
    return sorted(
        [
            actor.get("actor_type"),
            actor.get("actor_id"),
            actor.get("bypass_mode"),
        ]
        for actor in actors
        if isinstance(actor, dict)
    )


def ruleset_differences(current, desired: dict) -> list[str]:
    if not isinstance(current, dict):
        current = {}
    lines = field_differences(
        current, {key: desired[key] for key in ("name", "target", "enforcement")}
    )
    current_ref = (current.get("conditions") or {}).get("ref_name") or {}
    desired_ref = desired["conditions"]["ref_name"]
    for key in ("include", "exclude"):
        have = sorted(current_ref.get(key) or [])
        want = sorted(desired_ref.get(key) or [])
        if have != want:
            lines.append(f"conditions.ref_name.{key}: {render(have)} -> {render(want)}")

    have_actors = normalize_actors(current.get("bypass_actors"))
    want_actors = normalize_actors(desired["bypass_actors"])
    if have_actors != want_actors:
        lines.append(f"bypass_actors: {render(have_actors)} -> {render(want_actors)}")

    current_rules = {
        rule.get("type"): rule
        for rule in current.get("rules", [])
        if isinstance(rule, dict)
    }
    for rule in desired["rules"]:
        rule_type = rule["type"]
        if rule_type not in current_rules:
            lines.append(f"rules.{rule_type}: <absent> -> present")
            continue
        parameters = rule.get("parameters")
        if not parameters:
            continue
        have_parameters = current_rules[rule_type].get("parameters") or {}
        for key in sorted(parameters):
            want = parameters[key]
            have = have_parameters.get(key, "<absent>")
            if key == "required_status_checks":
                have_contexts = sorted(
                    check.get("context")
                    for check in (have if isinstance(have, list) else [])
                    if isinstance(check, dict)
                )
                want_contexts = sorted(check["context"] for check in want)
                if have_contexts != want_contexts:
                    lines.append(
                        f"rules.{rule_type}.{key}: "
                        f"{render(have_contexts)} -> {render(want_contexts)}"
                    )
                continue
            if have != want:
                lines.append(
                    f"rules.{rule_type}.{key}: {render(have)} -> {render(want)}"
                )
    return lines


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------


def step_repository_variables(api: GitHubApi, repo: str, args) -> list[Step]:
    steps: list[Step] = []
    wanted: list[tuple[str, str]] = []
    if args.template_repo:
        wanted.append((TEMPLATE_VARIABLE, "true"))
    if args.state_writer_app_id is not None:
        wanted.append((STATE_APP_VARIABLE, str(args.state_writer_app_id)))
    for name, value in wanted:
        current = optional_get(api, f"repos/{repo}/actions/variables/{name}")
        if current is None:
            steps.append(
                Step(
                    CREATE,
                    f"variable {name}",
                    f"{name}={value}",
                    [f"value: <absent> -> {render(value)}"],
                    [("POST", f"repos/{repo}/actions/variables", {"name": name, "value": value})],
                )
            )
        elif current.get("value") != value:
            steps.append(
                Step(
                    UPDATE,
                    f"variable {name}",
                    f"{name}={value}",
                    [f"value: {render(current.get('value'))} -> {render(value)}"],
                    [
                        (
                            "PATCH",
                            f"repos/{repo}/actions/variables/{name}",
                            {"name": name, "value": value},
                        )
                    ],
                )
            )
        else:
            steps.append(Step(UNCHANGED, f"variable {name}", f"{name}={value}"))

    if not args.template_repo:
        current = optional_get(api, f"repos/{repo}/actions/variables/{TEMPLATE_VARIABLE}")
        if current is not None and str(current.get("value", "")).lower() == "true":
            # A deployment repository that claims to be a template would have
            # the audit skip the state-App bypass and environment checks.
            steps.append(
                Step(
                    UPDATE,
                    f"variable {TEMPLATE_VARIABLE}",
                    "template mode is not valid on a deployment repository",
                    ["value: \"true\" -> \"false\""],
                    [
                        (
                            "PATCH",
                            f"repos/{repo}/actions/variables/{TEMPLATE_VARIABLE}",
                            {"name": TEMPLATE_VARIABLE, "value": "false"},
                        )
                    ],
                )
            )
    return steps


def step_actions_permissions(api: GitHubApi, repo: str) -> list[Step]:
    current = optional_get(api, f"repos/{repo}/actions/permissions") or {}
    desired = {
        "enabled": True,
        "allowed_actions": "selected",
        "sha_pinning_required": True,
    }
    details = field_differences(current, desired)
    steps = [
        Step(
            UNCHANGED if not details else UPDATE,
            "actions permissions",
            "selected actions only, full-SHA pinning required",
            details,
            []
            if not details
            else [("PUT", f"repos/{repo}/actions/permissions", desired)],
        )
    ]

    patterns = sorted(ALLOWED_ACTION_PATTERNS)
    selected_desired = {
        "github_owned_allowed": True,
        "verified_allowed": False,
        "patterns_allowed": patterns,
    }
    selected_current = (
        optional_get(api, f"repos/{repo}/actions/permissions/selected-actions") or {}
    )
    comparable = dict(selected_current)
    if isinstance(comparable.get("patterns_allowed"), list):
        comparable["patterns_allowed"] = sorted(comparable["patterns_allowed"])
    details = field_differences(comparable, selected_desired)
    steps.append(
        Step(
            UNCHANGED if not details else UPDATE,
            "third-party action allowlist",
            f"{len(patterns)} reviewed repositories, no verified-creator blanket",
            details,
            []
            if not details
            else [
                (
                    "PUT",
                    f"repos/{repo}/actions/permissions/selected-actions",
                    selected_desired,
                )
            ],
        )
    )
    return steps


def step_workflow_permissions(api: GitHubApi, repo: str) -> list[Step]:
    desired = {
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
    }
    current = optional_get(api, f"repos/{repo}/actions/permissions/workflow") or {}
    details = field_differences(current, desired)
    return [
        Step(
            UNCHANGED if not details else UPDATE,
            "workflow token defaults",
            "read-only GITHUB_TOKEN, Actions may not approve pull requests",
            details,
            []
            if not details
            else [("PUT", f"repos/{repo}/actions/permissions/workflow", desired)],
        )
    ]


def step_secret_scanning(api: GitHubApi, repo: str) -> list[Step]:
    repository = api.get(f"repos/{repo}") or {}
    analysis = repository.get("security_and_analysis") or {}
    current = {
        "secret_scanning": (analysis.get("secret_scanning") or {}).get("status"),
        "secret_scanning_push_protection": (
            analysis.get("secret_scanning_push_protection") or {}
        ).get("status"),
    }
    desired = {
        "secret_scanning": "enabled",
        "secret_scanning_push_protection": "enabled",
    }
    details = field_differences(current, desired)
    body = {
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }
    }
    return [
        Step(
            UNCHANGED if not details else UPDATE,
            "secret scanning",
            "secret scanning and push protection enabled",
            details,
            [] if not details else [("PATCH", f"repos/{repo}", body)],
        )
    ]


def step_private_vulnerability_reporting(api: GitHubApi, repo: str) -> list[Step]:
    path = f"repos/{repo}/private-vulnerability-reporting"
    current = optional_get(api, path) or {}
    enabled = current.get("enabled") is True
    return [
        Step(
            UNCHANGED if enabled else UPDATE,
            "private vulnerability reporting",
            "security researchers can report privately",
            [] if enabled else ["enabled: false -> true"],
            [] if enabled else [("PUT", path, None)],
        )
    ]


def step_dependabot(api: GitHubApi, repo: str) -> list[Step]:
    steps: list[Step] = []
    alerts_path = f"repos/{repo}/vulnerability-alerts"
    try:
        api.get(alerts_path)
        alerts_enabled = True
    except ApiError as error:
        if error.status != 404:
            raise
        alerts_enabled = False
    steps.append(
        Step(
            UNCHANGED if alerts_enabled else UPDATE,
            "dependabot alerts",
            "vulnerability alerts enabled",
            [] if alerts_enabled else ["enabled: false -> true"],
            [] if alerts_enabled else [("PUT", alerts_path, None)],
        )
    )

    fixes_path = f"repos/{repo}/automated-security-fixes"
    current = optional_get(api, fixes_path) or {}
    fixes_enabled = current.get("enabled") is True
    steps.append(
        Step(
            UNCHANGED if fixes_enabled else UPDATE,
            "dependabot security updates",
            "automated security fix pull requests enabled",
            [] if fixes_enabled else ["enabled: false -> true"],
            [] if fixes_enabled else [("PUT", fixes_path, None)],
        )
    )
    return steps


def find_ruleset(api: GitHubApi, repo: str, name: str, target: str):
    summaries = api.get(f"repos/{repo}/rulesets?per_page=100", paginate=True)
    flattened = []
    for page in summaries if isinstance(summaries, list) else []:
        if isinstance(page, list):
            flattened.extend(page)
        elif isinstance(page, dict):
            flattened.append(page)
    by_target = None
    for summary in flattened:
        if not isinstance(summary, dict) or summary.get("id") is None:
            continue
        detail = api.get(f"repos/{repo}/rulesets/{summary['id']}")
        if not isinstance(detail, dict):
            continue
        if detail.get("name") == name:
            return detail
        if by_target is None and detail.get("target") == target:
            by_target = detail
    # A ruleset that already protects this ref under another name is updated in
    # place rather than duplicated: two active rulesets on one ref are exactly
    # what the settings audit refuses.
    return by_target


def step_ruleset(
    api: GitHubApi, repo: str, name: str, target: str, desired: dict
) -> list[Step]:
    current = find_ruleset(api, repo, name, target)
    if current is None:
        return [
            Step(
                CREATE,
                f"{name} ruleset",
                f"active {target} ruleset {name!r}",
                [f"rules.{rule['type']}: <absent> -> present" for rule in desired["rules"]],
                [("POST", f"repos/{repo}/rulesets", desired)],
            )
        ]
    details = ruleset_differences(current, desired)
    return [
        Step(
            UNCHANGED if not details else UPDATE,
            f"{name} ruleset",
            f"active {target} ruleset {name!r} (id {current.get('id')})",
            details,
            []
            if not details
            else [("PUT", f"repos/{repo}/rulesets/{current['id']}", desired)],
        )
    ]


def step_labels(api: GitHubApi, repo: str) -> list[Step]:
    steps: list[Step] = []
    for label in OVERRIDE_LABELS:
        name = label["name"]
        encoded = quote(name, safe="")
        current = optional_get(api, f"repos/{repo}/labels/{encoded}")
        if current is None:
            steps.append(
                Step(
                    CREATE,
                    f"label {name}",
                    label["description"],
                    [f"label {name}: <absent> -> present"],
                    [("POST", f"repos/{repo}/labels", dict(label))],
                )
            )
            continue
        desired = {"color": label["color"], "description": label["description"]}
        comparable = {
            "color": str(current.get("color", "")).upper(),
            "description": current.get("description"),
        }
        details = field_differences(
            comparable, {"color": label["color"].upper(), "description": label["description"]}
        )
        steps.append(
            Step(
                UNCHANGED if not details else UPDATE,
                f"label {name}",
                label["description"],
                details,
                []
                if not details
                else [("PATCH", f"repos/{repo}/labels/{encoded}", desired)],
            )
        )
    return steps


def environment_reviewers(detail: dict) -> tuple[list[dict], bool]:
    rules = detail.get("protection_rules", []) if isinstance(detail, dict) else []
    reviewers: list[dict] = []
    prevents = False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_reviewers":
            continue
        prevents = prevents or rule.get("prevent_self_review") is True
        for entry in rule.get("reviewers") or []:
            if not isinstance(entry, dict):
                continue
            reviewer = entry.get("reviewer") or {}
            identifier = reviewer.get("id")
            if isinstance(identifier, int):
                reviewers.append({"type": entry.get("type"), "id": identifier})
    return reviewers, prevents


def step_environments(
    api: GitHubApi, repo: str, environments: list[str], reviewers: list[dict]
) -> list[Step]:
    steps: list[Step] = []
    for name in environments:
        encoded = quote(name, safe="")
        detail = optional_get(api, f"repos/{repo}/environments/{encoded}")
        current_reviewers, prevents = environment_reviewers(detail or {})
        target_reviewers = reviewers or current_reviewers
        if not target_reviewers:
            steps.append(
                Step(
                    BLOCKED,
                    f"environment {name}",
                    "needs at least one reviewer; pass --reviewer LOGIN "
                    "or --reviewer-team org/slug",
                )
            )
            continue
        body = {
            "wait_timer": 0,
            "prevent_self_review": True,
            "reviewers": target_reviewers,
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        if detail is None:
            steps.append(
                Step(
                    CREATE,
                    f"environment {name}",
                    f"{len(target_reviewers)} reviewer(s), self-review prevented, "
                    "protected branches only",
                    ["environment: <absent> -> present"],
                    [("PUT", f"repos/{repo}/environments/{encoded}", body)],
                )
            )
            continue
        policy = detail.get("deployment_branch_policy") or {}
        comparable = {
            "prevent_self_review": prevents,
            "reviewers": sorted(
                (entry["type"], entry["id"]) for entry in current_reviewers
            ),
            "deployment_branch_policy.protected_branches": policy.get(
                "protected_branches"
            )
            is True,
        }
        wanted = {
            "prevent_self_review": True,
            "reviewers": sorted((entry["type"], entry["id"]) for entry in target_reviewers),
            "deployment_branch_policy.protected_branches": True,
        }
        details = field_differences(comparable, wanted)
        steps.append(
            Step(
                UNCHANGED if not details else UPDATE,
                f"environment {name}",
                f"{len(target_reviewers)} reviewer(s), self-review prevented, "
                "protected branches only",
                details,
                []
                if not details
                else [("PUT", f"repos/{repo}/environments/{encoded}", body)],
            )
        )
    return steps


# --------------------------------------------------------------------------
# Planning and reporting
# --------------------------------------------------------------------------


def build_plan(api: GitHubApi, args) -> Plan:
    repo = args.repo
    plan = Plan()

    if args.state_writer_app_id is not None:
        main_bypass = [
            {
                "actor_type": "Integration",
                "actor_id": args.state_writer_app_id,
                "bypass_mode": "always",
            }
        ]
    else:
        main_bypass = [
            {
                "actor_type": "RepositoryRole",
                "actor_id": REPOSITORY_ADMIN_ROLE_ID,
                "bypass_mode": "pull_request",
            }
        ]
        plan.warnings.append(
            "No --state-writer-app-id: the main ruleset bypass is the Repository "
            "Admin role in pull_request mode. Merge with `gh pr merge --admin`. "
            "The settings audit flags this — it requires exactly one always-mode "
            "bypass belonging to the state-writer App — so run it in template mode "
            "or create the App and re-run with --state-writer-app-id."
        )

    environments = [] if args.template_repo else resolve_environments(args)
    reviewers = resolve_reviewers(api, args) if environments else []

    plan.steps.extend(step_repository_variables(api, repo, args))
    plan.steps.extend(step_actions_permissions(api, repo))
    plan.steps.extend(step_workflow_permissions(api, repo))
    plan.steps.extend(step_secret_scanning(api, repo))
    plan.steps.extend(step_private_vulnerability_reporting(api, repo))
    plan.steps.extend(step_dependabot(api, repo))
    plan.steps.extend(
        step_ruleset(api, repo, MAIN_RULESET_NAME, "branch", main_ruleset_body(main_bypass))
    )
    plan.steps.extend(
        step_ruleset(
            api,
            repo,
            RELEASE_TAG_RULESET_NAME,
            "tag",
            release_tag_ruleset_body([resolve_bypass_actor(api, args.release_tag_bypass)]),
        )
    )
    plan.steps.extend(step_labels(api, repo))

    if args.template_repo:
        plan.notes.append("")
        plan.notes.append(
            "Template repository: deployment environments are not created, and "
            f"repository variable {TEMPLATE_VARIABLE}=true tells the scheduled "
            "settings audit to skip the state-writer App bypass and "
            "protected-environment checks."
        )
    elif environments:
        plan.steps.extend(step_environments(api, repo, environments, reviewers))
    else:
        plan.notes.append("")
        plan.notes.append(
            "No environments were resolved. Write .gitforgeops/config.yaml (copy "
            "it from .gitforgeops/config.example.yaml) or pass --environment NAME, "
            "then re-run; the settings audit requires at least one protected "
            "environment on a deployment repository."
        )

    if args.release_tag_bypass == "admin":
        plan.warnings.append(
            "The release-tag ruleset bypass is the Repository Admin role. The "
            "settings audit requires an explicit App, team, or user instead; pass "
            "--release-tag-bypass app:<id>, user:<login>, or team:<org/slug> once "
            "one exists."
        )

    plan.notes.extend(secret_remainder(args.repo, environments, args.template_repo))
    return plan


def secret_remainder(repo: str, environments: list[str], template_repo: bool) -> list[str]:
    lines = [
        "",
        "Secrets are not set by this script and never pass through it. Run these "
        "yourself and paste each value at the prompt:",
    ]
    for name in REPOSITORY_SECRETS:
        lines.append(f"  gh secret set {name} --repo {repo}")
    if template_repo:
        lines.append(
            "  (a template repository needs no environment secrets: nothing on it "
            "applies to a gateway)"
        )
        return lines
    if not environments:
        lines.append("  (per-environment secrets: none, no environment is declared yet)")
        return lines
    for environment in environments:
        lines.append(f"  # environment {environment}")
        for name, note in ENVIRONMENT_SECRETS:
            lines.append(
                f"  gh secret set {name} --repo {repo} --env {environment}"
                f"   # {note}"
            )
    lines.append(
        "  # FERRUM_CREDS_BUNDLE[_N] are written by the credential broker on the "
        "first apply that resolves an alloc=generate placeholder; seed them by "
        "hand only when adopting an existing gateway."
    )
    return lines


def execute(api: GitHubApi, plan: Plan) -> None:
    for step in plan.steps:
        if step.action in {UNCHANGED, BLOCKED}:
            continue
        try:
            for method, path, body in step.writes:
                api.write(method, path, body)
        except ApiError as error:
            step.action = FAILED
            step.details.append(f"error: HTTP {error.status}: {error.message}")


def report(plan: Plan, *, dry_run: bool) -> None:
    print("gitforgeops repository bootstrap" + (" (dry run)" if dry_run else ""))
    print("")
    for step in plan.steps:
        print(f"  {step.action:<9} {step.target} — {step.summary}")
        for line in step.details:
            print(f"                {line}")
    counts: dict[str, int] = {}
    for step in plan.steps:
        counts[step.action] = counts.get(step.action, 0) + 1
    print("")
    print(
        "  ".join(
            f"{action}={counts.get(action, 0)}"
            for action in (CREATE, UPDATE, UNCHANGED, BLOCKED, FAILED)
        )
    )
    for warning in plan.warnings:
        print(f"\nWARNING: {warning}")
    for note in plan.notes:
        print(note)
    if dry_run:
        print("\nNothing was written. Re-run with --apply to make these changes.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply the gitforgeops GitHub launch baseline to a repository."
    )
    parser.add_argument("--repo", required=True, help="owner/name of the repository")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the changes; without it the plan and diff are printed only",
    )
    parser.add_argument(
        "--state-writer-app-id",
        type=int,
        help="numeric App id of the state-writer App; becomes the ruleset's sole "
        "always-mode bypass and repository variable " + STATE_APP_VARIABLE,
    )
    parser.add_argument(
        "--environment",
        action="append",
        default=[],
        help="deployment environment to protect; repeatable. Default: the "
        "environments declared in .gitforgeops/config.yaml",
    )
    parser.add_argument(
        "--reviewer",
        action="append",
        default=[],
        help="GitHub login required to approve deployments; repeatable",
    )
    parser.add_argument(
        "--reviewer-team",
        action="append",
        default=[],
        help="org/slug of a team required to approve deployments; repeatable",
    )
    parser.add_argument(
        "--release-tag-bypass",
        default="admin",
        help="who may push a v* tag: admin, app:<id>, user:<login>, team:<org/slug>",
    )
    parser.add_argument(
        "--template-repo",
        action="store_true",
        help="this repository is the template customers copy: create no "
        f"environments and set {TEMPLATE_VARIABLE}=true",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="path to .gitforgeops/config.yaml for environment discovery",
    )
    args = parser.parse_args(argv)

    if not REPOSITORY_NAME.match(args.repo):
        print("--repo must be spelled owner/name", file=sys.stderr)
        return 1
    if args.template_repo and args.environment:
        print(
            "--template-repo and --environment contradict each other: a template "
            "repository has no deployment environment",
            file=sys.stderr,
        )
        return 1
    if not os.environ.get("GH_TOKEN"):
        print(
            "bootstrap requires GH_TOKEN with administration write access to the "
            "repository (GH_TOKEN=$(gh auth token) when your account is an admin)",
            file=sys.stderr,
        )
        return 1

    api = GitHubApi(dry_run=not args.apply)
    try:
        plan = build_plan(api, args)
        if args.apply:
            execute(api, plan)
    except (ApiError, OSError, ValueError) as error:
        print(f"bootstrap failed closed: {error}", file=sys.stderr)
        return 1

    report(plan, dry_run=not args.apply)
    return 1 if plan.blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
