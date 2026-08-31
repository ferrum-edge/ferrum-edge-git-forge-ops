#!/usr/bin/env python3
"""Run cargo-audit and enforce exact, expiring dependency-risk exceptions."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_REVIEW_HORIZON_DAYS = 120
REQUIRED_TEXT_FIELDS = (
    "kind",
    "package",
    "version",
    "source",
    "owner",
    "review_by",
    "rationale",
    "upstream",
)
REQUIRED_LIST_FIELDS = ("affected_call_paths", "compensating_controls")


class PolicyError(ValueError):
    """Raised when the checked-in exception policy is malformed."""


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(finding["kind"]),
        str(finding.get("advisory") or ""),
        str(finding["package"]),
        str(finding["version"]),
        str(finding["source"]),
    )


def collect_findings(report: dict[str, Any]) -> list[dict[str, str | None]]:
    """Flatten cargo-audit's vulnerability and warning buckets."""
    findings: list[dict[str, str | None]] = []

    vulnerabilities = report.get("vulnerabilities", {}).get("list", [])
    if not isinstance(vulnerabilities, list):
        raise PolicyError("cargo-audit report has a malformed vulnerabilities.list")
    for item in vulnerabilities:
        try:
            findings.append(
                {
                    "kind": "vulnerability",
                    "advisory": item["advisory"]["id"],
                    "package": item["package"]["name"],
                    "version": item["package"]["version"],
                    "source": item["package"]["source"],
                }
            )
        except (KeyError, TypeError) as exc:
            raise PolicyError("cargo-audit returned a malformed vulnerability") from exc

    warnings = report.get("warnings", {})
    if not isinstance(warnings, dict):
        raise PolicyError("cargo-audit report has a malformed warnings object")
    for warning_kind, entries in warnings.items():
        if not isinstance(entries, list):
            raise PolicyError(f"cargo-audit warning bucket {warning_kind!r} is not a list")
        for item in entries:
            try:
                advisory = item.get("advisory")
                findings.append(
                    {
                        "kind": str(warning_kind),
                        "advisory": advisory.get("id") if advisory else None,
                        "package": item["package"]["name"],
                        "version": item["package"]["version"],
                        "source": item["package"]["source"],
                    }
                )
            except (KeyError, TypeError) as exc:
                raise PolicyError(
                    f"cargo-audit returned a malformed {warning_kind!r} warning"
                ) from exc

    return findings


def load_policy(
    path: Path, today: dt.date
) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read audit policy {path}: {exc}") from exc

    if raw.get("schema_version") != 1:
        raise PolicyError("audit policy schema_version must be 1")
    exceptions = raw.get("exceptions")
    if not isinstance(exceptions, list):
        raise PolicyError("audit policy exceptions must be a list")

    indexed: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for index, exception in enumerate(exceptions):
        label = f"exceptions[{index}]"
        if not isinstance(exception, dict):
            raise PolicyError(f"{label} must be an object")
        for field in REQUIRED_TEXT_FIELDS:
            if not _nonempty_text(exception.get(field)):
                raise PolicyError(f"{label}.{field} must be non-empty text")
        for field in REQUIRED_LIST_FIELDS:
            values = exception.get(field)
            if not isinstance(values, list) or not values or not all(
                _nonempty_text(value) for value in values
            ):
                raise PolicyError(f"{label}.{field} must be a non-empty text list")

        kind = exception["kind"]
        advisory = exception.get("advisory")
        if kind != "yanked" and not _nonempty_text(advisory):
            raise PolicyError(f"{label}.advisory is required for {kind!r} findings")
        if kind == "yanked" and advisory not in (None, ""):
            raise PolicyError(f"{label}.advisory must be null for yanked packages")

        try:
            review_by = dt.date.fromisoformat(exception["review_by"])
        except ValueError as exc:
            raise PolicyError(f"{label}.review_by must use YYYY-MM-DD") from exc
        if review_by < today:
            raise PolicyError(
                f"{label} expired on {review_by.isoformat()}; remove or re-review it"
            )
        horizon = (review_by - today).days
        if horizon > MAX_REVIEW_HORIZON_DAYS:
            raise PolicyError(
                f"{label}.review_by is {horizon} days away; maximum is "
                f"{MAX_REVIEW_HORIZON_DAYS}"
            )

        key = _finding_key(exception)
        if key in indexed:
            raise PolicyError(f"duplicate audit exception for {key}")
        indexed[key] = exception

    return indexed


def evaluate(
    report: dict[str, Any],
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]],
) -> tuple[
    list[dict[str, str | None]],
    list[dict[str, str | None]],
    list[tuple[str, str, str, str, str]],
]:
    findings = collect_findings(report)
    reviewed: list[dict[str, str | None]] = []
    blocked: list[dict[str, str | None]] = []
    used: set[tuple[str, str, str, str, str]] = set()

    for finding in findings:
        key = _finding_key(finding)
        if key in policy:
            reviewed.append(finding)
            used.add(key)
        else:
            blocked.append(finding)

    stale = sorted(set(policy) - used)
    return reviewed, blocked, stale


def _format_finding(finding: dict[str, str | None]) -> str:
    advisory = f" {finding['advisory']}" if finding.get("advisory") else ""
    return (
        f"{finding['kind']}{advisory}: "
        f"{finding['package']} {finding['version']}"
    )


def run_cargo_audit() -> tuple[dict[str, Any], int]:
    try:
        result = subprocess.run(
            ["cargo", "audit", "--json", "--deny", "unsound", "--deny", "yanked"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise PolicyError(f"could not execute cargo audit: {exc}") from exc

    try:
        return json.loads(result.stdout), result.returncode
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise PolicyError(f"cargo audit did not return JSON: {detail}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(".github/cargo-audit-policy.json"),
        help="checked-in exception policy",
    )
    parser.add_argument(
        "--audit-json",
        type=Path,
        help="read a saved cargo-audit JSON report instead of invoking cargo audit",
    )
    parser.add_argument(
        "--today",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        help="policy evaluation date (YYYY-MM-DD; intended for tests)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        policy = load_policy(args.policy, args.today)
        if args.audit_json:
            report = json.loads(args.audit_json.read_text(encoding="utf-8"))
            audit_status = 0
        else:
            report, audit_status = run_cargo_audit()
        reviewed, blocked, stale = evaluate(report, policy)
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(f"cargo-audit policy error: {exc}", file=sys.stderr)
        return 2

    for finding in reviewed:
        exception = policy[_finding_key(finding)]
        print(
            f"REVIEWED until {exception['review_by']} by {exception['owner']}: "
            f"{_format_finding(finding)}"
        )

    if blocked:
        print("Unreviewed cargo-audit findings:", file=sys.stderr)
        for finding in blocked:
            print(f"  - {_format_finding(finding)}", file=sys.stderr)
    if stale:
        print("Stale cargo-audit exceptions (finding no longer present):", file=sys.stderr)
        for key in stale:
            print(f"  - {key}", file=sys.stderr)

    if blocked or stale:
        return 1
    if audit_status not in (0, 1):
        print(f"cargo audit failed operationally with exit {audit_status}", file=sys.stderr)
        return 2

    print(
        f"cargo-audit policy passed: {len(reviewed)} reviewed exception(s), "
        "no unreviewed vulnerability/unsound/yanked findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
