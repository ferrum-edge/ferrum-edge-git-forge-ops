#!/usr/bin/env python3
"""Turn one drift check's raw result into an unambiguous monitoring outcome.

`gitforgeops diff --exit-on-drift` answers with three exit codes, and the
scheduled workflow can end in states the binary never reports at all — the job
was never released by an environment approval, the runner was cancelled, file
mode has no live surface to compare. Collapsing all of that into "the job is
green / the job is red" is what makes a monitoring setup lie: an approval that
never came looks exactly like a gateway that is in sync, and a cron entry looks
exactly like a check that ran.

So every outcome is named, and only ONE of them means "this gateway was
compared and matched":

    in_sync        the gateway was read and matches the repository
    drift          the gateway was read and differs
    failed         the check itself failed (auth, connectivity, stale view,
                   configuration) — nothing is known about the gateway
    skipped        file mode: there is no live Admin API to compare against
    not_completed  the job never ran the comparison (approval pending,
                   cancelled, runner lost)

`failed`, `skipped` and `not_completed` are explicitly *not* `in_sync`. The
aggregate exit code fails the workflow for `drift`, `failed` and
`not_completed`; `skipped` is a deliberate configuration, not a gap.

Usage::

    drift_report.py record --environment NAME --check-environment NAME \\
        --outcome OUTCOME [--exit-code N] [--unattended] [--detail TEXT] \\
        --output FILE

    drift_report.py summarize --input FILE [FILE ...] [--summary FILE]

`record` writes one JSON object per environment; `summarize` renders the job
summary table and decides the workflow's exit status.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

IN_SYNC = "in_sync"
DRIFT = "drift"
FAILED = "failed"
SKIPPED = "skipped"
NOT_COMPLETED = "not_completed"

OUTCOMES = (IN_SYNC, DRIFT, FAILED, SKIPPED, NOT_COMPLETED)

# Only `in_sync` is evidence that a gateway was compared and matched.
SUCCESSFUL_COMPARISON = frozenset({IN_SYNC})
# `skipped` is a configured absence of a live surface, not an unknown.
BLOCKING = frozenset({DRIFT, FAILED, NOT_COMPLETED})

LABELS = {
    IN_SYNC: ("✅", "In sync", "the gateway was read and matches the repository"),
    DRIFT: ("🔶", "Drift detected", "the gateway was read and differs"),
    FAILED: (
        "❌",
        "Check failed",
        "the check could not complete; nothing is known about the gateway",
    ),
    SKIPPED: (
        "⏭️",
        "Skipped (file mode)",
        "no live Admin API to compare against",
    ),
    NOT_COMPLETED: (
        "⏳",
        "Not completed",
        "the comparison never ran (approval pending, cancelled, or runner lost)",
    ),
}

# `gitforgeops diff --exit-on-drift`.
EXIT_CODES = {0: IN_SYNC, 2: DRIFT}


def outcome_for_exit_code(exit_code: int) -> str:
    """Map a `diff --exit-on-drift` exit code onto an outcome.

    Anything that is neither 0 nor the drift code is a failure of the check,
    never a statement about the gateway. That includes exit 1, which covers
    authentication, connectivity, a cached (non-authoritative) backup, and
    configuration errors alike.
    """
    return EXIT_CODES.get(exit_code, FAILED)


def record(
    environment: str,
    check_environment: str,
    outcome: str,
    unattended: bool,
    detail: str = "",
    exit_code: int | None = None,
) -> dict:
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown outcome {outcome!r}; expected one of {OUTCOMES}")
    return {
        "environment": environment,
        "check_environment": check_environment,
        "approval_gated": check_environment == environment,
        "unattended": unattended,
        "outcome": outcome,
        "exit_code": exit_code,
        "detail": detail,
    }


def _approval_note(entry: dict) -> str:
    if entry["outcome"] == NOT_COMPLETED and entry["approval_gated"]:
        return (
            " The check is bound to the deployment environment, so GitHub "
            "withholds its secrets until a reviewer approves the job. Set "
            "`monitoring.unattended: true` for this environment to move the "
            "check into its own read-scoped monitoring environment."
        )
    return ""


def summarize(entries: list[dict]) -> tuple[str, int]:
    """Render the monitoring table and decide the workflow's exit status."""
    if not entries:
        return (
            "## GitForgeOps drift monitoring\n\n"
            "No environment produced a drift-check outcome. A scheduled run "
            "that compares nothing is not monitoring coverage.\n",
            1,
        )

    lines = [
        "## GitForgeOps drift monitoring",
        "",
        "| Environment | Bound environment | Unattended | Outcome | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in sorted(entries, key=lambda item: item["environment"]):
        icon, label, meaning = LABELS[entry["outcome"]]
        detail = entry.get("detail") or meaning
        detail += _approval_note(entry)
        lines.append(
            "| `{environment}` | `{check_environment}` | {unattended} | "
            "{icon} {label} | {detail} |".format(
                environment=entry["environment"],
                check_environment=entry["check_environment"],
                unattended="yes" if entry["unattended"] else "no",
                icon=icon,
                label=label,
                detail=detail.replace("|", "\\|"),
            )
        )

    compared = [item for item in entries if item["outcome"] in SUCCESSFUL_COMPARISON]
    blocking = [item for item in entries if item["outcome"] in BLOCKING]
    skipped = [item for item in entries if item["outcome"] == SKIPPED]

    lines += [
        "",
        f"**{len(compared)} of {len(entries)} environments were compared and "
        "matched.**",
        "",
        "Only `In sync` means a gateway was read and matched. `Check failed`, "
        "`Not completed` and `Skipped` each say something different about "
        "coverage and none of them is a clean result.",
    ]
    if skipped:
        names = ", ".join(f"`{item['environment']}`" for item in skipped)
        lines.append(
            f"\n{names} run in file mode and have no live Admin API drift "
            "surface. That is a configured absence, not a monitoring gap."
        )
    if blocking:
        names = ", ".join(
            f"`{item['environment']}` ({item['outcome']})" for item in blocking
        )
        lines.append(f"\nNeeds attention: {names}.")

    return "\n".join(lines) + "\n", 1 if blocking else 0


def _load(paths: list[str]) -> list[dict]:
    entries: list[dict] = []
    for pattern in paths:
        path = Path(pattern)
        candidates = (
            sorted(path.rglob("*.json")) if path.is_dir() else [path]
        )
        for candidate in candidates:
            if not candidate.is_file():
                continue
            loaded = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                entries.extend(loaded)
            else:
                entries.append(loaded)
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    record_parser = sub.add_parser("record")
    record_parser.add_argument("--environment", required=True)
    record_parser.add_argument("--check-environment", required=True)
    record_parser.add_argument("--outcome", choices=OUTCOMES)
    record_parser.add_argument("--exit-code", type=int)
    record_parser.add_argument("--unattended", action="store_true")
    record_parser.add_argument("--detail", default="")
    record_parser.add_argument("--output", required=True)

    summarize_parser = sub.add_parser("summarize")
    summarize_parser.add_argument("--input", nargs="+", required=True)
    summarize_parser.add_argument("--summary")

    args = parser.parse_args(argv)

    if args.command == "record":
        if args.outcome is None and args.exit_code is None:
            parser.error("record needs --outcome or --exit-code")
        outcome = args.outcome or outcome_for_exit_code(args.exit_code)
        entry = record(
            environment=args.environment,
            check_environment=args.check_environment,
            outcome=outcome,
            unattended=args.unattended,
            detail=args.detail,
            exit_code=args.exit_code,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
        print(f"{entry['environment']}: {entry['outcome']}")
        return 0

    entries = _load(args.input)
    text, status = summarize(entries)
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    return status


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
