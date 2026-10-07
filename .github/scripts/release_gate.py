#!/usr/bin/env python3
"""Require the published commit's merged pull request to have passed its checks.

`release.yml`'s `authorize-release` job runs this from the release commit's
own checkout (#473). It replaced an inline bash and jq gate and keeps that
gate's verdicts, except where noted below:

* The release commit maps to exactly one merged default-branch pull request
  (an exact merge-commit match wins over a rebase association). A missing
  association is retried five times with a growing delay; an ambiguous or
  malformed one fails at once.
* One sampling budget (`BUDGET_SECONDS`) bounds every API call and wait. It is
  checked before each call, at the top of each poll and again after the final
  identity read, so no pass is reported after the deadline and an exhausted
  budget reports only the timeout.
* Each poll brackets its samples with an identity read of the pull request,
  re-reads the effective branch rules, reads the required and the full
  `gh pr checks` rollups and every check run on the merged head, and judges
  them together. A failed, cancelled or skipped required or transitional check
  fails at once; skipped is never a pass, which is why a required job in an
  `edited`-triggered workflow must not be skipped by a job-level `if:`.
* Check-run pages whose advertised totals disagree are a pagination race:
  the sample is not judged, and the gate polls again. Duplicate, conflicting
  or missing check-run identities in a consistent sample fail closed.
* The same-head check-run read retries once, after a bounded backoff, when its
  error names an HTTP 5xx status. Malformed data never retries.

It differs from the inline gate only in these cases, each stricter or more robust:

* A head or merge commit SHA with a trailing newline is refused. jq's
  `test("^...$")` accepted one.
* A completed check run whose `conclusion` is not a string is refused. jq's
  `index` would have matched an array conclusion as a subarray.
* `NaN` and `Infinity` in any response are refused; jq parsed them.
* When the budget runs out during a call, only the timeout is reported. The
  inline gate also printed the interrupted call's own failure, such as a
  changed identity. Both exit 1.
* A timed-out `gh` is killed at once rather than after a five-second TERM
  grace period.
* The pull request number is always rendered as an integer, in API paths and
  messages. jq 1.7 could render an integral float as `5.0`.

Run it from a checkout with `python3 -I .github/scripts/release_gate.py`.
`gh` reads `GH_TOKEN`; the gate reads `REPO`, `RELEASE_SHA` and
`DEFAULT_BRANCH`. The supply-chain checker pins the launch check lists, the
GitHub Actions App binding and the budget below, and the small import,
reference and call surface this file uses: only `gh api` and `gh pr checks`,
and the environment only as a copy. Those pins catch drift, not a deliberate
rewrite; review of every change to this file is the control for that.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from typing import Callable

# The contexts `bootstrap_repo_settings.py` requires on `main`, as
# `<workflow> / <job>`. Each must be required by the ruleset, bound to the
# GitHub Actions App, and green on the merged head.
REQUIRED_CHECKS = (
    "Rust CI / rust-ci-check",
    "Security / security-cargo-audit",
    "Security / security-supply-chain-policy",
    "GitForgeOps State Guard / state-guard-reject-state-edits",
    "GitForgeOps PR Static Validation / gitforgeops-required-static-validation",
)
# Being added to the ruleset (GHSA-x5m2-4555-q4cr): tolerated while absent,
# but a reported result must pass, and once required it is waited for.
ACCEPTED_CHECKS = ("GitForgeOps Supply-Chain Policy / trusted-supply-chain-policy",)
ACTIONS_APP_ID = 15368
BUDGET_SECONDS = 900
ASSOCIATION_ATTEMPTS = 5
POLL_SECONDS = 15
RETRY_DELAY_SECONDS = 2

BUCKETS = ("pass", "pending", "fail", "cancel", "skipping")
STATUSES = ("queued", "in_progress", "completed", "pending", "waiting", "requested")
CONCLUSIONS = (
    "success",
    "failure",
    "cancelled",
    "timed_out",
    "action_required",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
)
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
TRANSIENT_HTTP = re.compile(r"HTTP 5[0-9][0-9]")
JSON_WHITESPACE = re.compile(r"[ \t\n\r]*")


class GateError(Exception):
    """Malformed, ambiguous or failing evidence: refuse without waiting."""


class BudgetExhausted(Exception):
    """The shared sampling budget ran out."""


class Result:
    """One `gh` invocation: exit status and decoded streams."""

    def __init__(self, status: int, stdout: str, stderr: str) -> None:
        self.status = status
        self.stdout = stdout
        self.stderr = stderr


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-finite number {name}")


DECODER = json.JSONDecoder(parse_constant=_reject_constant)


def slurp(text: str) -> list:
    """Every JSON value in `text`, in order, as `jq -s` reads a file."""
    values = []
    position = JSON_WHITESPACE.match(text, 0).end()
    while position < len(text):
        try:
            value, position = DECODER.raw_decode(text, position)
        except ValueError as error:
            raise GateError(f"invalid JSON response ({error})") from None
        values.append(value)
        position = JSON_WHITESPACE.match(text, position).end()
    return values


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def positive_integer(value) -> bool:
    """jq's `type == "number" and . > 0 and . == floor`."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value > 0
    return isinstance(value, float) and value.is_integer() and value > 0


def non_negative_integer(value) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    return isinstance(value, float) and value.is_integer() and value >= 0


def canonical(value):
    """A hashable form under which two JSON values are equal exactly as in jq.

    Python treats `True == 1`; jq does not, so booleans are tagged apart from
    numbers. Numbers compare by value, so `5` and `5.0` are one value in both.
    """
    if isinstance(value, bool):
        return ("boolean", value)
    if is_number(value):
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if value is None:
        return ("null",)
    if isinstance(value, list):
        return ("array", tuple(canonical(item) for item in value))
    if isinstance(value, dict):
        return ("object", tuple(sorted((key, canonical(item)) for key, item in value.items())))
    raise GateError("unexpected JSON value")


def same(left, right) -> bool:
    return canonical(left) == canonical(right)


def field(value, *path):
    """jq's `.a.b`: null passes through, indexing a non-object is an error."""
    for key in path:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise GateError(f"cannot index a non-object with {key!r}")
        value = value.get(key)
    return value


def context_name(context: str) -> str:
    """The job name a ruleset records for `<workflow> / <job>`."""
    return context.split(" / ")[-1]


def merged_association(text: str, sha: str, branch: str, repo: str) -> dict | None:
    """The one merged default-branch PR of the release commit; None while absent."""
    values = slurp(text)
    if len(values) != 1 or not isinstance(values[0], list) or not values[0]:
        raise GateError("invalid commit-to-PR response")
    pages = values[0]
    if any(not isinstance(page, list) for page in pages) or any(
        not isinstance(record, dict) for page in pages for record in page
    ):
        raise GateError("invalid commit-to-PR pages")
    associated = [record for page in pages for record in page]
    for record in associated:
        merged_at = record.get("merged_at")
        if (
            not positive_integer(record.get("number"))
            or not positive_integer(record.get("id"))
            or record.get("state") not in ("open", "closed")
            or not isinstance(field(record, "base", "ref"), str)
            or not isinstance(field(record, "base", "repo", "full_name"), str)
            or not isinstance(field(record, "head", "sha"), str)
            or (merged_at is not None and not isinstance(merged_at, str))
        ):
            raise GateError("invalid commit-to-PR record")
    identities: dict = {}
    for record in associated:
        identities.setdefault(record["number"], set()).add(canonical(record))
    if any(len(records) != 1 for records in identities.values()):
        raise GateError("conflicting commit-to-PR identities")
    candidates: dict = {}
    for record in associated:
        if (
            record["state"] == "closed"
            and record["base"]["ref"] == branch
            and isinstance(record.get("merged_at"), str)
        ):
            candidates.setdefault(record["number"], record)
    exact = [record for record in candidates.values() if record.get("merge_commit_sha") == sha]
    chosen = exact or list(candidates.values())
    if not chosen:
        if not associated:
            return None
        raise GateError("invalid merged default-branch association")
    if len(chosen) != 1:
        raise GateError("release commit must map to exactly one merged PR")
    record = chosen[0]
    head = record["head"]["sha"]
    merge = record.get("merge_commit_sha")
    if not (
        record["base"]["repo"]["full_name"] == repo
        and COMMIT_SHA.fullmatch(head)
        and isinstance(merge, str)
        and COMMIT_SHA.fullmatch(merge)
    ):
        raise GateError("invalid merged PR identity")
    return {
        "number": record["number"],
        "id": record["id"],
        "merged_at": record["merged_at"],
        "merge_commit_sha": merge,
        "head_sha": head,
    }


def identity_matches(text: str, association: dict, branch: str, repo: str) -> dict | None:
    """The pull request when it still has the associated identity, else None."""
    try:
        values = slurp(text)
        if len(values) != 1 or not isinstance(values[0], dict):
            return None
        pr = values[0]
        matches = (
            same(pr.get("id"), association["id"])
            and same(pr.get("number"), association["number"])
            and same(pr.get("state"), "closed")
            and same(pr.get("merged"), True)
            and same(pr.get("merged_at"), association["merged_at"])
            and same(pr.get("merge_commit_sha"), association["merge_commit_sha"])
            and same(field(pr, "head", "sha"), association["head_sha"])
            and same(field(pr, "base", "ref"), branch)
            and same(field(pr, "base", "repo", "full_name"), repo)
        )
    except GateError:
        return None
    return pr if matches else None


def check_contexts(value) -> list[dict]:
    """Validated `gh pr checks` records as `{context, name, bucket}`."""
    if not isinstance(value, list):
        raise GateError("invalid checks response")
    if any(not isinstance(check, dict) for check in value):
        raise GateError("invalid check record")
    contexts = []
    for check in value:
        name = check.get("name")
        bucket = check.get("bucket")
        workflow = check.get("workflow")
        if (
            not isinstance(name, str)
            or name == ""
            or not isinstance(bucket, str)
            or bucket not in BUCKETS
            or (workflow is not None and not isinstance(workflow, str))
        ):
            raise GateError("invalid check fields")
        context = f"{workflow} / {name}" if workflow else name
        contexts.append({"context": context, "name": name, "bucket": bucket})
    return contexts


def required_settings(pages) -> list[dict]:
    """Every required status check of the effective rules, as `{name, app}`."""
    settings: dict = {}
    for page in pages:
        if not isinstance(page, list):
            raise GateError("invalid rules page")
        for rule in page:
            if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
                raise GateError("invalid rule record")
            if rule["type"] != "required_status_checks":
                continue
            entries = field(rule, "parameters", "required_status_checks")
            if not isinstance(entries, list):
                raise GateError("invalid required-check settings")
            for entry in entries:
                name = field(entry, "context")
                app = field(entry, "integration_id")
                if not isinstance(name, str) or name == "" or not positive_integer(app):
                    raise GateError("required checks must be source-bound")
                settings[(name, app)] = {"name": name, "app": app}
    return list(settings.values())


def valid_run(run, head: str) -> bool:
    if not isinstance(run, dict):
        return False
    try:
        app = field(run, "app", "id")
    except GateError:
        return False
    status = run.get("status")
    conclusion = run.get("conclusion")
    return (
        positive_integer(run.get("id"))
        and isinstance(run.get("name"), str)
        and run["name"] != ""
        and same(run.get("head_sha"), head)
        and positive_integer(app)
        and isinstance(status, str)
        and status in STATUSES
        and (
            isinstance(conclusion, str) and conclusion in CONCLUSIONS
            if status == "completed"
            else conclusion is None
        )
    )


def judge(
    checks_text: str,
    all_checks_text: str,
    rules_text: str,
    runs_text: str,
    head: str,
    required_missing: str,
    all_missing: str,
) -> str:
    """`pass` or `wait` for one consistent sample; GateError refuses it."""
    checks_values = slurp(checks_text)
    all_values = slurp(all_checks_text)
    rules_values = slurp(rules_text)
    runs_values = slurp(runs_text)
    if (
        len(checks_values) != 1
        or len(all_values) != 1
        or len(rules_values) != 1
        or not isinstance(rules_values[0], list)
        or not rules_values[0]
        or len(runs_values) != 1
        or not isinstance(runs_values[0], list)
        or not runs_values[0]
    ):
        raise GateError("expected one response per checks lookup")
    checks = check_contexts(checks_values[0])
    reported = check_contexts(all_values[0])
    settings = required_settings(rules_values[0])
    launch = REQUIRED_CHECKS + ACCEPTED_CHECKS
    launch_names = {context_name(context) for context in launch}
    if any(
        sum(
            1
            for setting in settings
            if setting["name"] == context_name(context) and setting["app"] == ACTIONS_APP_ID
        )
        != 1
        for context in REQUIRED_CHECKS
    ) or any(
        setting["name"] in launch_names and setting["app"] != ACTIONS_APP_ID
        for setting in settings
    ):
        raise GateError("launch-required checks must retain their GitHub Actions source binding")
    watched: dict = {(setting["name"], setting["app"]): setting for setting in settings}
    for context in ACCEPTED_CHECKS:
        name = context_name(context)
        watched.setdefault((name, ACTIONS_APP_ID), {"name": name, "app": ACTIONS_APP_ID})
    setting_names = {setting["name"] for setting in settings}
    required_contexts = REQUIRED_CHECKS + tuple(
        context for context in ACCEPTED_CHECKS if context_name(context) in setting_names
    )
    if any(check["name"] not in setting_names for check in checks):
        raise GateError("required check has no source-bound rule")

    pages = runs_values[0]
    history = []
    for page in pages:
        if (
            not isinstance(page, dict)
            or not isinstance(page.get("check_runs"), list)
            or not non_negative_integer(page.get("total_count"))
        ):
            raise GateError("invalid check-run page")
        for run in page["check_runs"]:
            if not valid_run(run, head):
                raise GateError("invalid or wrong-head check run")
            history.append(run)
    # Pagination can race a new retry even when both CLI samples pass. Every
    # page must agree on the total, and distinct IDs must account for it before
    # selecting any newest result. A race repeats or drops records across
    # pages: wait for a consistent sample before judging any record in this one.
    totals = {page["total_count"] for page in pages}
    if len(totals) != 1:
        return "wait"
    identities: dict = {}
    for run in history:
        identities.setdefault(run["id"], []).append(run)
    if any(len({canonical(run) for run in runs}) != 1 for runs in identities.values()):
        raise GateError("conflicting check-run identities")
    if any(len(runs) != 1 for runs in identities.values()):
        raise GateError("duplicate check-run identities")
    if len(identities) != pages[0]["total_count"]:
        raise GateError("incomplete check-run evidence")
    latest = []
    for setting in watched.values():
        matching = [
            run for run in history
            if run["name"] == setting["name"] and run["app"]["id"] == setting["app"]
        ]
        newest = max(matching, key=lambda run: run["id"]) if matching else None
        latest.append((setting, newest))
    guarded = checks + [check for check in reported if check["context"] in launch]
    if any(check["bucket"] not in ("pass", "pending") for check in guarded) or any(
        run is not None and run["status"] == "completed" and run["conclusion"] != "success"
        for _, run in latest
    ):
        raise GateError("required or transitional check failed, was cancelled or skipped")
    # Runs may arrive after an empty CLI sample. They still cannot authorize
    # it: an empty lookup must be sampled again.
    sampled = {check["context"] for check in checks}
    if (
        required_missing
        or all_missing
        or any(check["bucket"] == "pending" for check in checks)
        or any(context not in sampled for context in required_contexts)
        or any(check["bucket"] == "pending" for check in guarded)
        or any(run is None and setting in settings for setting, run in latest)
        or any(run is not None and run["status"] != "completed" for _, run in latest)
    ):
        return "wait"
    return "pass"


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


class Gate:
    def __init__(
        self,
        environ,
        clock: Callable[[], int],
        sleep: Callable[[int], None],
        subprocess_env,
    ) -> None:
        self.repo = environ.get("REPO", "")
        self.sha = environ.get("RELEASE_SHA", "")
        self.branch = environ.get("DEFAULT_BRANCH", "")
        self.clock = clock
        self.sleep = sleep
        self.subprocess_env = subprocess_env
        self.deadline = clock() + BUDGET_SECONDS
        self.association: dict = {}
        self.pr: dict | None = None

    def remaining(self) -> int:
        left = self.deadline - self.clock()
        if left <= 0:
            raise BudgetExhausted
        return left

    def gh(self, arguments: list[str]) -> Result:
        """Run `gh api` or `gh pr checks` within the remaining budget.

        A timeout is exit status 124. Each subcommand is a literal at its call,
        which is how the supply-chain checker pins the commands gh may run.
        """
        budget = self.remaining()
        try:
            if arguments[:1] == ["api"]:
                completed = subprocess.run(
                    ["gh", "api", *arguments[1:]],
                    capture_output=True,
                    timeout=budget,
                    env=self.subprocess_env,
                    check=False,
                )
            elif arguments[:2] == ["pr", "checks"]:
                completed = subprocess.run(
                    ["gh", "pr", "checks", *arguments[2:]],
                    capture_output=True,
                    timeout=budget,
                    env=self.subprocess_env,
                    check=False,
                )
            else:
                raise ValueError(f"unsupported gh command {arguments[:2]!r}")
        except subprocess.TimeoutExpired as expired:
            return Result(124, _decode(expired.stdout), _decode(expired.stderr))
        except OSError as error:
            return Result(127, "", f"gh could not be run: {error}\n")
        return Result(completed.returncode, _decode(completed.stdout), _decode(completed.stderr))

    def api(self, endpoint: str, *options: str) -> Result:
        result = self.gh(["api", endpoint, *options])
        sys.stderr.write(result.stderr)
        return result

    def verify_identity(self) -> bool:
        result = self.api(f"repos/{self.repo}/pulls/{self.number}")
        if result.status != 0:
            return False
        pr = identity_matches(result.stdout, self.association, self.branch, self.repo)
        if pr is not None:
            self.pr = pr
        return pr is not None

    @property
    def number(self) -> str:
        number = self.association["number"]
        return str(int(number))

    def classify(self, result: Result, mode: str) -> tuple[str, str]:
        """The missing marker and checks JSON of one `gh pr checks` lookup.

        gh errors before exporting JSON for an empty rollup. Accept only that
        diagnostic, for the verified head branch; every other error refuses.
        """
        if result.status == 0:
            return "", result.stdout
        head_branch = field(self.pr, "head", "ref")
        if not isinstance(head_branch, str) or head_branch == "":
            raise GateError("the merged PR has no head branch")
        diagnostic = result.stderr.rstrip("\n")
        if result.status == 1 and result.stdout == "":
            if diagnostic == f"no checks reported on the '{head_branch}' branch":
                return "all", "[]"
            if (
                mode == "required"
                and diagnostic == f"no required checks reported on the '{head_branch}' branch"
            ):
                return "required", "[]"
        sys.stderr.write(result.stderr)
        raise GateError("checks lookup failed")

    def read_runs(self, head: str) -> str | None:
        """Every check run on the merged head, retrying one transient HTTP 5xx."""
        endpoint = f"repos/{self.repo}/commits/{head}/check-runs?per_page=100&filter=all"
        for attempt in (1, 2):
            result = self.gh(["api", endpoint, "--paginate", "--slurp"])
            if result.status == 0:
                return result.stdout
            if attempt == 1 and TRANSIENT_HTTP.search(result.stderr):
                print(
                    "Same-head check-run API returned a transient HTTP 5xx; retrying once.",
                    file=sys.stderr,
                )
                # Back off briefly, never past the shared sampling budget.
                self.sleep(min(self.remaining(), RETRY_DELAY_SECONDS))
                continue
            sys.stderr.write(result.stderr)
            return None
        return None

    def associate(self) -> int:
        association = None
        for attempt in range(1, ASSOCIATION_ATTEMPTS + 1):
            result = self.api(
                f"repos/{self.repo}/commits/{self.sha}/pulls?per_page=100", "--paginate", "--slurp"
            )
            if result.status != 0:
                print("::error::Release merge association could not be read.")
                return 1
            # None means no association yet. Parse errors, ambiguous
            # associations and malformed identities never retry.
            try:
                association = merged_association(result.stdout, self.sha, self.branch, self.repo)
            except GateError as error:
                print(f"::error::Release merge association is invalid: {error}.")
                return 1
            if association is not None:
                break
            print(
                "Release merge association is not yet available and unambiguous; "
                f"retrying ({attempt}/{ASSOCIATION_ATTEMPTS}).",
                file=sys.stderr,
            )
            if attempt < ASSOCIATION_ATTEMPTS:
                self.sleep(attempt * 2)
        if association is None:
            print("::error::Release commit could not be mapped to exactly one merged PR.")
            return 1
        self.association = association
        return 0

    def run(self) -> int:
        status = self.associate()
        if status != 0:
            return status
        number = self.number
        head = self.association["head_sha"]
        branch_path = urllib.parse.quote(self.branch, safe="")
        while True:
            self.remaining()
            if not self.verify_identity():
                print(
                    f"::error::Merged PR #{number} changed identity, head or "
                    "default-branch association."
                )
                return 1
            # Read the effective rules each time: an accepted context cannot
            # pass by absence after the ruleset makes it required.
            rules = self.api(
                f"repos/{self.repo}/rules/branches/{branch_path}?per_page=100",
                "--paginate",
                "--slurp",
            )
            if rules.status != 0:
                print("::error::Required-check settings could not be read.")
                return 1
            checks_call = ["pr", "checks", number, "--repo", self.repo]
            required = self.gh([*checks_call, "--required", "--json", "bucket,name,workflow"])
            try:
                required_missing, checks_text = self.classify(required, "required")
            except GateError:
                print(f"::error::Required checks for merged PR #{number} could not be read.")
                sys.stdout.write(required.stdout)
                return 1
            # --required hides transitional results. Inspect the full rollup
            # too; every error other than verified absence fails closed.
            reported = self.gh([*checks_call, "--json", "bucket,name,workflow"])
            try:
                all_missing, all_checks_text = self.classify(reported, "all")
            except GateError:
                print(f"::error::All checks for merged PR #{number} could not be read.")
                return 1
            # gh deduplicates by startedAt: a queued retry can disappear behind
            # an older success. Read every run on the expected head and select
            # the newest check-run ID per source-bound context instead.
            runs_text = self.read_runs(head)
            if runs_text is None:
                print("::error::Same-head check-run evidence could not be read.")
                return 1
            try:
                verdict = judge(
                    checks_text,
                    all_checks_text,
                    rules.stdout,
                    runs_text,
                    head,
                    required_missing,
                    all_missing,
                )
            except GateError as error:
                print(f"Release gate refused the sample: {error}", file=sys.stderr)
                print(
                    "::error::The merged PR lacks successful launch-required checks or has an "
                    "unsuccessful transitional check or invalid check response."
                )
                sys.stdout.write(checks_text)
                sys.stdout.write(all_checks_text)
                return 1
            # Both gh lookups follow a mutable PR number; bracket them with the
            # identity from the commit association, including the final pass.
            self.remaining()
            if not self.verify_identity():
                print(f"::error::Merged PR #{number} changed while its checks were sampled.")
                return 1
            # The identity read spends budget too: no pass after the deadline.
            left = self.remaining()
            if verdict == "pass":
                print(f"Merged PR #{number} has successful source-bound checks on {head}.")
                return 0
            print(
                f"Required or transitional checks are pending or missing on {head}; "
                f"waiting ({left}s left)."
            )
            self.sleep(min(left, POLL_SECONDS))


def _monotonic_seconds() -> int:
    return int(time.monotonic())


def main(
    environ=None,
    *,
    clock: Callable[[], int] | None = None,
    sleep: Callable[[int], None] | None = None,
) -> int:
    """Run the gate. Tests inject the environment, clock and sleep.

    The gate reads a copy of the process environment; gh inherits the
    original, which nothing here changes.
    """
    source = dict(os.environ) if environ is None else environ
    for name in ("REPO", "RELEASE_SHA", "DEFAULT_BRANCH"):
        if not source.get(name):
            print(f"::error::{name} is required.")
            return 1
    gate = Gate(
        source,
        clock or _monotonic_seconds,
        sleep or time.sleep,
        None if environ is None else dict(environ),
    )
    try:
        return gate.run()
    except BudgetExhausted:
        print(
            "::error::Timed out waiting for same-head release checks "
            f"({BUDGET_SECONDS} seconds).",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
