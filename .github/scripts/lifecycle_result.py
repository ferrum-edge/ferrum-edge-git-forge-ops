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

Some scenarios can only run against a disposable GitHub repository, which CI
cannot create. Their outcomes reach the release gate as an **attestation**: the
operator's own sealed result for the same revision, merged into the CI run's
record by `attest`. An attestation can only fill a scenario the CI run itself
recorded as `skipped` — it can never overwrite what the suite actually ran —
and every attested entry names who attested it.

Usage::

    lifecycle_result.py declare                     # the required scenario ids
    lifecycle_result.py record --result FILE --scenario ID --status STATUS \\
        [--detail TEXT]
    lifecycle_result.py seal --result FILE --revision SHA --gateway BUILD
    lifecycle_result.py attest --result FILE --attestation FILE \\
        --revision SHA --attested-by LOGIN
    lifecycle_result.py verify --result FILE --revision SHA \\
        [--gateway BUILD | --gateway-allowlist FILE] [--max-age-hours N] \\
        [--summary FILE]
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
        "staged-promotion",
        "An opted-in production environment cannot start until the required "
        "staging apply and its traffic checks succeed for the same approved "
        "source revision; breaking staging routing blocks production even "
        "though the gateway accepted the write.",
    ),
    (
        "drift-monitoring",
        "The supported monitoring model: drift is distinguished from a failed "
        "check and from a skipped one.",
    ),
    (
        "file-and-mesh-boundary",
        "For the advertised file/mesh profile, verify assembly (placeholders "
        "preserved, a separate mesh document), 0600 materialization that never "
        "touches the committed artifact — and that assembly is not reported as "
        "live fleet deployment.",
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


def attest(
    result: dict, attestation: dict, revision: str, attested_by: str
) -> list[str]:
    """Fill the CI run's `skipped` scenarios from an operator's sealed result.

    Returns the scenario ids that were filled. Refuses an attestation that is
    unsealed or sealed for a different revision: it describes a run of some
    other code. Entries for scenarios the CI run did NOT skip are ignored —
    what the suite ran itself is never replaced by what someone typed.
    """
    if not attested_by.strip():
        raise ResultError("an attestation must name who attested it")
    attested_revision = attestation.get("gitforgeops_revision")
    if not attested_revision:
        raise ResultError(
            "the attestation was never sealed; run `lifecycle_result.py seal` on it "
            "for the revision you tested"
        )
    if attested_revision != revision:
        raise ResultError(
            f"the attestation certifies {attested_revision}, not {revision}. An "
            "acceptance run against other code proves nothing about this revision."
        )
    theirs = attestation.get("scenarios")
    ours = result.get("scenarios")
    if not isinstance(theirs, dict) or not isinstance(ours, dict):
        raise ResultError("the attestation or the result carries no scenario outcomes")

    filled: list[str] = []
    for identifier in REQUIRED_SCENARIO_IDS:
        current = ours.get(identifier)
        entry = theirs.get(identifier)
        if not isinstance(current, dict) or current.get("status") != SKIPPED:
            continue
        if not isinstance(entry, dict) or entry.get("status") not in (PASSED, FAILED):
            continue
        detail = str(entry.get("detail") or "").splitlines()[0:1]
        ours[identifier] = {
            "status": entry["status"],
            "detail": f"attested by @{attested_by}"
            + (f": {detail[0]}" if detail and detail[0] else ""),
        }
        filled.append(identifier)
    result["attested_by"] = attested_by
    result["attested_scenarios"] = filled
    return filled


def allowlisted_digests(text: str) -> list[str]:
    """The validator builds `.github/ferrum-edge-checksums.txt` trusts."""
    digests = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        digests.append(stripped.split()[0])
    return digests


def blockers(
    result: dict,
    revision: str,
    gateway_build: str | None,
    max_age_hours: int,
    now: datetime,
    gateway_allowlist: list[str] | None = None,
) -> list[str]:
    """Why this result may not authorize publishing `revision`.

    `gateway_build` pins one exact build; `gateway_allowlist` accepts any build
    the revision's own checksum allowlist trusts. The release gate uses the
    allowlist, because the suite runs whichever allowlisted build the installer
    resolves on the day.
    """
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

    if gateway_allowlist is not None:
        recorded_gateway = result.get("gateway_build")
        if recorded_gateway not in gateway_allowlist:
            reasons.append(
                f"the result was produced against gateway build "
                f"{recorded_gateway!r}, which this revision's validator allowlist "
                "does not trust. A result from an unapproved gateway certifies "
                "nothing about the build this revision pins."
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
    ]
    if result.get("attested_by"):
        filled = ", ".join(f"`{item}`" for item in result.get("attested_scenarios") or [])
        lines.append(
            f"- GitHub-repository scenarios attested by `@{result['attested_by']}`: "
            + (filled or "none filled")
        )
    lines += [
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

    attester = sub.add_parser(
        "attest",
        help="fill this run's skipped scenarios from an operator's sealed result",
    )
    attester.add_argument("--result", required=True)
    attester.add_argument("--attestation", required=True)
    attester.add_argument("--revision", required=True)
    attester.add_argument("--attested-by", required=True)

    verifier = sub.add_parser("verify")
    verifier.add_argument("--result", required=True)
    verifier.add_argument("--revision", required=True)
    gateway = verifier.add_mutually_exclusive_group()
    gateway.add_argument("--gateway")
    gateway.add_argument(
        "--gateway-allowlist",
        help="a checksum allowlist; the recorded gateway build must be one of its digests",
    )
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

        if args.command == "attest":
            result = load(path)
            attestation = load(Path(args.attestation))
            filled = attest(result, attestation, args.revision, args.attested_by)
            save(path, result)
            print(
                f"attested by @{args.attested_by}: "
                + (", ".join(filled) if filled else "no skipped scenario to fill")
            )
            return 0

        result = load(path)
        allowlist = None
        if args.gateway_allowlist:
            allowlist_path = Path(args.gateway_allowlist)
            if not allowlist_path.is_file():
                raise ResultError(f"{allowlist_path} does not exist")
            allowlist = allowlisted_digests(allowlist_path.read_text(encoding="utf-8"))
        reasons = blockers(
            result,
            args.revision,
            args.gateway,
            args.max_age_hours,
            datetime.now(timezone.utc),
            allowlist,
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
