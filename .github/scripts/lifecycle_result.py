#!/usr/bin/env python3
"""The acceptance result a release is allowed to be published on.

A release gate is only worth having if it cannot be satisfied by an absence.
The failure mode it exists to prevent is not "the suite failed and we shipped
anyway" — that one is loud. It is the quiet ones:

* the suite never ran for this revision, and nothing said so;
* it ran for an older revision, and the result was reused;
* it ran against a different gateway build than the one being certified;
* it started, was cancelled, and left a green-looking partial record;
* a scenario was skipped, and "no failures" was read as "everything passed".

So a result is a closed record — the exact GitForgeOps revision, the exact
gateway build, and one entry per declared scenario — and `verify` refuses
unless every scenario in `REQUIRED_SCENARIOS` is present and `passed`, the
recorded revision is the one being published, and the record is newer than the
staleness window.

`skipped` is a status a scenario may legitimately have. It is never a pass.

Usage::

    lifecycle_result.py declare                     # the required scenario ids
    lifecycle_result.py record --result FILE --scenario ID --status STATUS \\
        [--detail TEXT]
    lifecycle_result.py seal --result FILE --revision SHA --gateway BUILD
    lifecycle_result.py verify --result FILE --revision SHA \\
        [--gateway BUILD] [--max-age-hours N] [--summary FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"
NOT_RUN = "not_run"

STATUSES = (PASSED, FAILED, SKIPPED, NOT_RUN)
# Only one of them certifies anything.
AUTHORIZING = frozenset({PASSED})

# The customer lifecycle, as scenarios. Every one of these must pass before a
# revision may be published; adding a gate to `apply` means adding a scenario
# here, or the suite goes back to certifying a narrower product than it ships.
REQUIRED_SCENARIOS: tuple[tuple[str, str], ...] = (
    (
        "create-and-route",
        "Create upstream, proxy, scoped plugin and consumer; send real traffic "
        "and verify routing and authentication behaviour.",
    ),
    (
        "reapply-is-a-no-op",
        "Apply the same desired state again: no unintended changes and no "
        "normalization-induced false drift.",
    ),
    (
        "modify-and-delete-in-order",
        "Modify and delete managed resources in dependency-safe order; "
        "unmanaged resources survive in shared mode.",
    ),
    (
        "credentials-generate-and-rotate",
        "Generate and rotate a consumer credential; prove the new value "
        "authenticates, the old one does not, and no plaintext reaches logs, "
        "Git, comments or artifacts.",
    ),
    (
        "partial-failure-recovery",
        "Inject a partial failure and an ambiguous gateway response; retry and "
        "verify the recovery safeguards preserve successful work and ownership.",
    ),
    (
        "ledger-publication-failure",
        "Reject state publication after a gateway mutation, exhaust retries, "
        "then resume in a fresh runner; prove the documented ownership-recovery "
        "procedure rather than treating a runner-local ledger as durable.",
    ),
    (
        "runner-interruption",
        "Interrupt the runner after a mutation and verify the documented "
        "reconciliation path, including state-override authorization where it "
        "is genuinely required.",
    ),
    (
        "scheduling-and-attribution",
        "Queued and superseded applies, unrelated later merges, re-runs of an "
        "older workflow, PR-author credential delivery and policy-override "
        "attribution — including the regression from #261.",
    ),
    (
        "drift-monitoring",
        "The supported monitoring model: drift is distinguished from a failed "
        "check and from a skipped one.",
    ),
    (
        "file-and-mesh-boundary",
        "For the advertised file/mesh profile, verify assembly, encrypted "
        "materialization and the delivery boundary — and that assembly is not "
        "reported as live fleet deployment.",
    ),
)

REQUIRED_SCENARIO_IDS = tuple(identifier for identifier, _ in REQUIRED_SCENARIOS)

# A nightly suite plus a generous margin. The point of the window is that a
# result cannot be reused indefinitely; a release always reruns the suite for
# the revision it is publishing, so this only catches reuse.
DEFAULT_MAX_AGE_HOURS = 72


class ResultError(RuntimeError):
    """The record cannot support a release."""


def empty_result() -> dict:
    return {
        "schema": 1,
        "gitforgeops_revision": None,
        "gateway_build": None,
        "sealed_at": None,
        "scenarios": {
            identifier: {"status": NOT_RUN, "detail": "never started"}
            for identifier in REQUIRED_SCENARIO_IDS
        },
    }


def load(path: Path) -> dict:
    if not path.is_file():
        raise ResultError(
            f"{path} does not exist: the acceptance suite left no record for this "
            "revision. A release may not be published on the absence of a result."
        )
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ResultError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(result, dict) or result.get("schema") != 1:
        raise ResultError(f"{path} is not a version-1 acceptance result")
    return result


def save(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def record(result: dict, scenario: str, status: str, detail: str = "") -> dict:
    if scenario not in REQUIRED_SCENARIO_IDS:
        raise ResultError(
            f"unknown scenario {scenario!r}; declared scenarios are "
            f"{', '.join(REQUIRED_SCENARIO_IDS)}"
        )
    if status not in STATUSES:
        raise ResultError(f"unknown status {status!r}; expected one of {STATUSES}")
    result["scenarios"][scenario] = {"status": status, "detail": detail}
    return result


def seal(result: dict, revision: str, gateway_build: str, now: datetime) -> dict:
    result["gitforgeops_revision"] = revision
    result["gateway_build"] = gateway_build
    result["sealed_at"] = now.replace(microsecond=0).isoformat()
    return result


def blockers(
    result: dict,
    revision: str,
    gateway_build: str | None,
    max_age_hours: int,
    now: datetime,
) -> list[str]:
    """Why this result may not authorize publishing `revision`."""
    reasons: list[str] = []

    recorded = result.get("gitforgeops_revision")
    if not recorded:
        reasons.append(
            "the result was never sealed, so it describes a run that did not "
            "finish. A cancelled suite leaves exactly this."
        )
    elif recorded != revision:
        reasons.append(
            f"the result certifies {recorded}, not {revision}. An acceptance run "
            "for a different revision proves nothing about this one."
        )

    if gateway_build is not None:
        recorded_gateway = result.get("gateway_build")
        if recorded_gateway != gateway_build:
            reasons.append(
                f"the result was produced against gateway build "
                f"{recorded_gateway!r}, but {gateway_build!r} is the pinned "
                "build being certified."
            )

    sealed_at = result.get("sealed_at")
    if not sealed_at:
        # Already reported above as an unsealed result; do not repeat it.
        pass
    else:
        try:
            completed = datetime.fromisoformat(str(sealed_at).replace("Z", "+00:00"))
        except ValueError:
            reasons.append(f"the result has an unparseable sealed_at {sealed_at!r}")
        else:
            if completed.tzinfo is None:
                completed = completed.replace(tzinfo=timezone.utc)
            age = (now - completed).total_seconds() / 3600
            if age > max_age_hours:
                reasons.append(
                    f"the result is {age:.0f}h old, beyond the {max_age_hours}h "
                    "window. A stale result is a result for a gateway and a "
                    "toolchain that have both moved."
                )

    scenarios = result.get("scenarios")
    if not isinstance(scenarios, dict):
        return reasons + ["the result carries no scenario outcomes at all"]

    for identifier in REQUIRED_SCENARIO_IDS:
        entry = scenarios.get(identifier)
        if not isinstance(entry, dict):
            reasons.append(
                f"scenario {identifier!r} is absent from the result. An absent "
                "scenario is not a passing one."
            )
            continue
        status = entry.get("status")
        if status in AUTHORIZING:
            continue
        detail = entry.get("detail") or ""
        reasons.append(
            f"scenario {identifier!r} reported {status!r}"
            + (f": {detail}" if detail else "")
            + (
                " — a skipped scenario is not a passing one."
                if status == SKIPPED
                else ""
            )
        )
    return reasons


def render(result: dict) -> str:
    lines = [
        "## GitForgeOps lifecycle acceptance",
        "",
        f"- revision: `{result.get('gitforgeops_revision') or 'UNSEALED'}`",
        f"- gateway build: `{result.get('gateway_build') or 'unknown'}`",
        f"- sealed at: `{result.get('sealed_at') or 'never'}`",
        "",
        "| Scenario | Status | Detail |",
        "| --- | --- | --- |",
    ]
    scenarios = result.get("scenarios") or {}
    for identifier, description in REQUIRED_SCENARIOS:
        entry = scenarios.get(identifier) or {}
        status = entry.get("status", NOT_RUN)
        detail = entry.get("detail") or description
        lines.append(
            f"| `{identifier}` | {status} | {detail.replace('|', chr(92) + '|')} |"
        )
    lines += [
        "",
        "Only `passed` certifies a scenario. `skipped`, `not_run` and `failed` "
        "each say something different, and none of them authorizes a release.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("declare", help="print the declared scenario ids")

    initialize = sub.add_parser("init")
    initialize.add_argument("--result", required=True)

    recorder = sub.add_parser("record")
    recorder.add_argument("--result", required=True)
    recorder.add_argument("--scenario", required=True)
    recorder.add_argument("--status", required=True, choices=STATUSES)
    recorder.add_argument("--detail", default="")

    sealer = sub.add_parser("seal")
    sealer.add_argument("--result", required=True)
    sealer.add_argument("--revision", required=True)
    sealer.add_argument("--gateway", required=True)

    verifier = sub.add_parser("verify")
    verifier.add_argument("--result", required=True)
    verifier.add_argument("--revision", required=True)
    verifier.add_argument("--gateway")
    verifier.add_argument("--max-age-hours", type=int, default=DEFAULT_MAX_AGE_HOURS)
    verifier.add_argument("--summary")

    args = parser.parse_args(argv)

    try:
        if args.command == "declare":
            for identifier, description in REQUIRED_SCENARIOS:
                print(f"{identifier}\t{description}")
            return 0

        if args.command == "init":
            save(Path(args.result), empty_result())
            print(f"initialized {len(REQUIRED_SCENARIO_IDS)} scenario(s) as {NOT_RUN}")
            return 0

        path = Path(args.result)

        if args.command == "record":
            result = load(path)
            save(path, record(result, args.scenario, args.status, args.detail))
            print(f"{args.scenario}: {args.status}")
            return 0

        if args.command == "seal":
            result = load(path)
            save(
                path,
                seal(result, args.revision, args.gateway, datetime.now(timezone.utc)),
            )
            print(f"sealed for {args.revision} against {args.gateway}")
            return 0

        result = load(path)
        reasons = blockers(
            result,
            args.revision,
            args.gateway,
            args.max_age_hours,
            datetime.now(timezone.utc),
        )
        text = render(result)
        print(text, end="")
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as handle:
                handle.write(text)
        if not reasons:
            print(f"::notice::Lifecycle acceptance certifies {args.revision}.")
            return 0
        print(
            "::error::Lifecycle acceptance does not certify this revision."
            + "".join(f"%0A  - {reason}" for reason in reasons)
        )
        return 1
    except ResultError as error:
        print(f"::error::Lifecycle acceptance result is unusable: {error}")
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
