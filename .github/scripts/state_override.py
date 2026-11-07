#!/usr/bin/env python3
"""Decide a protected-state override with the rule `src/policy/github_override.rs` uses.

`state-guard.yml` runs this from its default-branch checkout twice: once to
authorize (`authorize`) and once as the last step before the run records
success (`recheck`). Both run the whole decision:

1. The pull request carries the exact override label, is still on the head
   the run was delivered for, and still targets the default branch.
2. The account that most recently added that label (issue events) currently
   holds at least `write`. The permission is read from `role_name` when it is
   a built-in rank, so `maintain` is seen as `maintain`, and from the legacy
   `permission` field otherwise.
3. That account's latest submitted review approves or comments on that exact
   head with the exact override body.
4. A final re-read of the pull request, the labeler, the permission and the
   reviews finds the same evidence.

Event and review histories are read as numbered pages from the fixed API
route until a page is empty. A `Link` header is never followed or consulted,
and a history longer than the page cap fails closed. Every failure, malformed
response or changed piece of evidence refuses the override.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable


# `MAX_ISSUE_EVENT_PAGES` in src/policy/github_override.rs.
MAX_PAGES = 20
PER_PAGE = 100
# `VALID_PERMISSIONS` in src/policy/config.rs, weakest first.
VALID_PERMISSIONS = ("read", "triage", "write", "maintain", "admin")
REQUIRED_PERMISSION = "write"
API_TIMEOUT_SECONDS = 60

LOGIN_RE = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}|[A-Za-z0-9-]{0,33}\[bot\])\Z")
REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
PR_NUMBER_RE = re.compile(r"\A[1-9][0-9]{0,18}\Z")
REVIEW_ID_RE = re.compile(r"\A[1-9][0-9]{0,19}\Z")
# `override_input::is_revision`.
REVISION_RE = re.compile(r"\A[0-9A-Fa-f]{40}\Z")
# Rust's `str::trim` removes Unicode `White_Space`, which (unlike Python's
# `str.isspace`) excludes the U+001C..U+001F separators.
WHITE_SPACE = (
    "\t\n\x0b\x0c\r \x85\xa0 "
    "           "
    "    　"
)


class OverrideRefused(Exception):
    """The override is not authorized; the message says why."""


Fetch = Callable[[str], Any]


def gh_api(route: str) -> Any:
    """GET one fixed route through `gh api`: no `--paginate`, so no `Link`."""
    try:
        completed = subprocess.run(
            ["gh", "api", route],
            capture_output=True,
            text=True,
            check=False,
            timeout=API_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OverrideRefused(f"GitHub API request failed: {route}") from error
    if completed.returncode != 0:
        raise OverrideRefused(f"GitHub API request failed: {route}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise OverrideRefused(f"GitHub returned malformed JSON: {route}") from error


@dataclass(frozen=True)
class Context:
    repo: str
    pr_number: str
    expected_head: str
    default_branch: str
    label: str
    marker: str


@dataclass(frozen=True)
class PullRequest:
    head: str
    base_sha: str
    base_ref: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class Review:
    id: int
    commit_id: str | None
    state: str
    body: str | None
    login: str | None


@dataclass(frozen=True)
class Evidence:
    actor: str
    # The permission verified first, as `VerifiedOverride::permission` records.
    permission: str
    review_id: int
    head: str
    # The permission the final re-read found (also sufficient).
    current_permission: str


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OverrideRefused(f"GitHub returned an invalid {what}")
    return value


def _string(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise OverrideRefused(f"GitHub returned an invalid {what}")
    return value


def _optional_string(value: Any, what: str) -> str | None:
    return None if value is None else _string(value, what)


def pull_request(value: Any) -> PullRequest:
    pr = _object(value, "pull request")
    head = _object(pr.get("head"), "pull request head")
    base = _object(pr.get("base"), "pull request base")
    labels = pr.get("labels", [])
    if not isinstance(labels, list):
        raise OverrideRefused("GitHub returned invalid pull request labels")
    return PullRequest(
        head=_string(head.get("sha"), "pull request head"),
        base_sha=_string(base.get("sha"), "pull request base"),
        base_ref=_string(base.get("ref"), "pull request base"),
        labels=tuple(
            _string(_object(label, "label").get("name"), "label") for label in labels
        ),
    )


def numbered_pages(fetch: Fetch, route: str, what: str) -> list[Any]:
    """Every record of `route`, page by page, until a page is empty.

    A short page is not taken as the last one: the listing may grow while it
    is read, or GitHub may cap `per_page`. Reaching the cap without an empty
    page fails closed.
    """
    records: list[Any] = []
    for page in range(1, MAX_PAGES + 1):
        batch = fetch(f"{route}?per_page={PER_PAGE}&page={page}")
        if not isinstance(batch, list):
            raise OverrideRefused(f"GitHub returned an invalid {what} page")
        if not batch:
            return records
        records.extend(batch)
    raise OverrideRefused(f"{what} history exceeds the pagination safety cap")


def override_labeler(events: list[Any], label: str) -> str | None:
    """The login that most recently added `label`, `None` once it was removed."""
    latest: str | None = None
    for value in events:
        event = _object(value, "issue event")
        kind = _string(event.get("event"), "issue event")
        event_label = event.get("label")
        if event_label is None:
            continue
        if _string(_object(event_label, "issue event label").get("name"), "label") != label:
            continue
        if kind == "labeled":
            actor = event.get("actor")
            latest = (
                None
                if actor is None
                else _string(_object(actor, "issue event actor").get("login"), "login")
            )
        elif kind == "unlabeled":
            latest = None
    return latest


def effective_permission(value: Any) -> str:
    """`PermissionResponse::effective_permission`: built-in `role_name` first."""
    response = _object(value, "permission")
    permission = _string(response.get("permission"), "permission")
    role = _optional_string(response.get("role_name"), "role name")
    return role if role in VALID_PERMISSIONS else permission


def is_sufficient(permission: str) -> bool:
    """`OverrideConfig::is_sufficient`; an unknown permission never is."""
    if permission not in VALID_PERMISSIONS:
        return False
    return VALID_PERMISSIONS.index(permission) >= VALID_PERMISSIONS.index(
        REQUIRED_PERMISSION
    )


SUFFICIENT_PERMISSIONS = tuple(
    permission for permission in VALID_PERMISSIONS if is_sufficient(permission)
)


def reviews(records: list[Any]) -> list[Review]:
    parsed = []
    for value in records:
        record = _object(value, "review")
        review_id = record.get("id")
        if isinstance(review_id, bool) or not isinstance(review_id, int) or review_id <= 0:
            raise OverrideRefused("GitHub returned an invalid review id")
        user = record.get("user")
        parsed.append(
            Review(
                id=review_id,
                commit_id=_optional_string(record.get("commit_id"), "review commit"),
                state=_string(record.get("state"), "review state"),
                body=_optional_string(record.get("body"), "review body"),
                login=None
                if user is None
                else _string(_object(user, "review author").get("login"), "login"),
            )
        )
    return parsed


def authorized_review(
    history: list[Review], labeler: str, marker: str, head: str
) -> Review | None:
    """The labeler's latest submitted review, when it authorizes `head`.

    A later review of any kind or a dismissal revokes an earlier override;
    pending drafts are no word at all.
    """
    if REVISION_RE.match(head) is None:
        return None
    latest = next(
        (
            review
            for review in reversed(history)
            if review.state != "PENDING" and review.login == labeler
        ),
        None,
    )
    if (
        latest is not None
        and latest.state in ("APPROVED", "COMMENTED")
        and latest.commit_id == head
        and latest.body is not None
        and latest.body.strip(WHITE_SPACE) == marker
    ):
        return latest
    return None


def decide(fetch: Fetch, context: Context) -> Evidence:
    """Every check `check_override_at` makes, including its final re-read."""
    pr_route = f"repos/{context.repo}/pulls/{context.pr_number}"
    events_route = f"repos/{context.repo}/issues/{context.pr_number}/events"
    reviews_route = f"{pr_route}/reviews"

    pr = pull_request(fetch(pr_route))
    if pr.head != context.expected_head:
        raise OverrideRefused(
            "PR head changed after state-scope detection; wait for the new run."
        )
    if pr.base_ref != context.default_branch:
        raise OverrideRefused(
            "PR no longer targets the protected default branch."
        )
    if context.label not in pr.labels:
        raise OverrideRefused("State override label is not currently applied.")

    labeler = override_labeler(
        numbered_pages(fetch, events_route, "issue event"), context.label
    )
    if labeler is None:
        raise OverrideRefused(
            "No labeling event for the state override label was found across all event pages."
        )
    if LOGIN_RE.match(labeler) is None:
        raise OverrideRefused("The override labeler is not a valid GitHub login.")

    permission_route = f"repos/{context.repo}/collaborators/{labeler}/permission"
    try:
        permission = effective_permission(fetch(permission_route))
    except OverrideRefused as error:
        raise OverrideRefused(
            f"Could not read @{labeler}'s permission; the override is not authorized."
        ) from error
    if not is_sufficient(permission):
        raise OverrideRefused(
            f"@{labeler} applied the override label but does not have write, maintain or admin permission."
        )

    review = authorized_review(
        reviews(numbered_pages(fetch, reviews_route, "review")),
        labeler,
        context.marker,
        pr.head,
    )
    if review is None:
        raise OverrideRefused(
            f"@{labeler}, who last applied the override label, has no latest review "
            f"with body exactly '{context.marker}' on head {pr.head}."
        )

    # Close the API-read window as far as a client can: a push, retarget or
    # label change, a relabel, a demotion or a later review while the evidence
    # was collected invalidates this decision.
    try:
        current = pull_request(fetch(pr_route))
    except OverrideRefused as error:
        raise OverrideRefused("PR changed during override verification.") from error
    if current != pr:
        raise OverrideRefused("PR changed during override verification.")
    try:
        current_labeler = override_labeler(
            numbered_pages(fetch, events_route, "issue event"), context.label
        )
        current_permission = effective_permission(fetch(permission_route))
        current_review = authorized_review(
            reviews(numbered_pages(fetch, reviews_route, "review")),
            labeler,
            context.marker,
            pr.head,
        )
    except OverrideRefused as error:
        raise OverrideRefused("Override evidence changed during verification.") from error
    if (
        current_labeler != labeler
        or not is_sufficient(current_permission)
        or current_review != review
    ):
        raise OverrideRefused("Override evidence changed during verification.")

    return Evidence(
        actor=labeler,
        permission=permission,
        review_id=review.id,
        head=pr.head,
        current_permission=current_permission,
    )


def _required(environ: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = environ.get(name, "")
    if not value or (pattern is not None and pattern.match(value) is None):
        raise OverrideRefused(f"{name} is missing or malformed.")
    return value


def context_from_env(environ: dict[str, str]) -> Context:
    return Context(
        repo=_required(environ, "REPO", REPO_RE),
        pr_number=_required(environ, "PR_NUMBER", PR_NUMBER_RE),
        expected_head=_required(environ, "EXPECTED_HEAD_SHA", REVISION_RE),
        default_branch=_required(environ, "DEFAULT_BRANCH"),
        label=_required(environ, "OVERRIDE_LABEL"),
        marker=_required(environ, "OVERRIDE_REVIEW"),
    )


def authorize(fetch: Fetch, environ: dict[str, str]) -> Evidence:
    return decide(fetch, context_from_env(environ))


def output_lines(evidence: Evidence) -> str:
    """The step outputs; every value is validated, so none spans a line."""
    return (
        f"actor={evidence.actor}\n"
        f"permission={evidence.permission}\n"
        f"review_id={evidence.review_id}\n"
        f"head_sha={evidence.head}\n"
    )


def recheck(fetch: Fetch, environ: dict[str, str]) -> Evidence:
    """Decide again and require the evidence the authorize step recorded.

    The permission is not bound: it may change between the steps as long as it
    stays sufficient, and the step reports the one this decision found.
    """
    actor = _required(environ, "ACTOR", LOGIN_RE)
    review_id = int(_required(environ, "REVIEW_ID", REVIEW_ID_RE))
    authorized_head = _required(environ, "AUTHORIZED_HEAD", REVISION_RE)
    evidence = decide(fetch, context_from_env(environ))
    if (
        evidence.actor != actor
        or evidence.review_id != review_id
        or evidence.head != authorized_head
    ):
        raise OverrideRefused(
            "Override evidence changed after authorization; the override is not recorded."
        )
    if evidence.current_permission not in SUFFICIENT_PERMISSIONS:
        raise OverrideRefused("The labeler's current permission is not sufficient.")
    return evidence


def main(argv: list[str] | None = None, fetch: Fetch = gh_api) -> int:
    """Diagnostics go to stderr.

    On success `authorize` prints only its step outputs to stdout, and
    `recheck` only the current permission, so the step can report it.
    """
    parser = argparse.ArgumentParser(description="Decide a protected-state override.")
    parser.add_argument("command", choices=("authorize", "recheck"))
    args = parser.parse_args(argv)
    environ = dict(os.environ)
    try:
        if args.command == "authorize":
            evidence = authorize(fetch, environ)
        else:
            evidence = recheck(fetch, environ)
    except OverrideRefused as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(
        f"State override evidence: @{evidence.actor} ({evidence.permission}), "
        f"review {evidence.review_id}, head {evidence.head}.",
        file=sys.stderr,
    )
    if args.command == "authorize":
        sys.stdout.write(output_lines(evidence))
    else:
        sys.stdout.write(f"{evidence.current_permission}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
