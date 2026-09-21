#!/usr/bin/env python3
"""The evidence one environment's apply leaves for the next one in a chain.

A promotion is an authorization claim: *this source revision applied cleanly
to staging and staging then served it, so production may have it.* The claim
has to be checkable by the job that acts on it, and it has to be bound to
something immutable — otherwise "production was promoted from staging" is a
statement about job ordering rather than about what is running.

So a promoting job does not trust that its predecessor job is green. It reads
the predecessor's record and refuses unless:

* the record exists at all (a missing one is a promotion that never happened,
  not a promotion that succeeded),
* the apply succeeded,
* traffic verification succeeded — configuration acceptance is not healthy
  traffic, and this is the whole reason the gate exists,
* and the **source revision matches the one this job is about to apply**.

That last one is what makes the promotion revision-bound. Staging and
production legitimately assemble different bytes, because they select
different overlays; what must be identical is the commit the desired
resources, the policy, the engine and the workflows all came from.

Usage::

    promotion_record.py write --environment NAME --revision SHA \\
        --apply-result RESULT --verify-result RESULT \\
        --run-id ID --actor LOGIN [--pr NUMBER] --output FILE

    promotion_record.py require --environment NAME --revision SHA \\
        --records DIR [--summary FILE]

    promotion_record.py summarize --records DIR [--summary FILE]

`require` exits non-zero — loudly, naming which condition failed — when the
promotion is not authorized.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SUCCESS = "success"
FAILURE = "failure"
SKIPPED = "skipped"
CANCELLED = "cancelled"
NOT_RUN = "not_run"

RESULTS = (SUCCESS, FAILURE, SKIPPED, CANCELLED, NOT_RUN)

# Only an outright success authorizes a promotion. `skipped` and `cancelled`
# are listed so a workflow can record them honestly rather than omitting the
# record — an omitted record and a cancelled one look the same to a reader, and
# they must not look the same to the gate.
AUTHORIZING = frozenset({SUCCESS})


def record_path(directory: Path, environment: str) -> Path:
    return directory / f"{environment}.json"


def write(
    environment: str,
    revision: str,
    apply_result: str,
    verify_result: str,
    run_id: str,
    actor: str,
    pull_request: str | None = None,
) -> dict:
    for label, value in (("apply", apply_result), ("verify", verify_result)):
        if value not in RESULTS:
            raise ValueError(f"{label} result {value!r} is not one of {RESULTS}")
    return {
        "environment": environment,
        # The revision the apply actually ran against: the refreshed protected
        # head the freshness guard let through, not the triggering commit.
        "source_revision": revision,
        "apply_result": apply_result,
        "verify_result": verify_result,
        "authorized": apply_result in AUTHORIZING and verify_result in AUTHORIZING,
        # Provenance, so the summary can say who authorized what.
        "run_id": run_id,
        "actor": actor,
        "pull_request": pull_request,
    }


def load(directory: Path, environment: str) -> dict | None:
    path = record_path(directory, environment)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def blockers(record: dict | None, required_environment: str, revision: str) -> list[str]:
    """Why this promotion may not proceed. Empty means it may."""
    if record is None:
        return [
            f"{required_environment} left no promotion record. The job did not "
            "reach the point of writing one — it was never started, it was "
            "cancelled before recording, or the runner was lost. A promotion "
            "that cannot be shown to have happened has not happened."
        ]
    reasons: list[str] = []
    if record.get("apply_result") != SUCCESS:
        reasons.append(
            f"{required_environment} apply reported "
            f"{record.get('apply_result')!r}, not {SUCCESS!r}"
        )
    if record.get("verify_result") != SUCCESS:
        reasons.append(
            f"{required_environment} traffic verification reported "
            f"{record.get('verify_result')!r}, not {SUCCESS!r}. The gateway may "
            "well have accepted the configuration write; it was not shown to be "
            "serving it."
        )
    recorded = record.get("source_revision")
    if recorded != revision:
        reasons.append(
            f"{required_environment} was applied at {recorded}, but this job "
            f"would apply {revision}. A promotion authorizes one revision; the "
            "protected branch moved, so this one is not it. Let the newer "
            "merge's own run promote its revision."
        )
    return reasons


def summarize(directory: Path) -> str:
    records = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if not records:
        return (
            "## GitForgeOps promotion\n\nNo environment recorded a promotion "
            "result.\n"
        )
    lines = [
        "## GitForgeOps promotion",
        "",
        "| Environment | Source revision | Apply | Traffic | Authorized by |",
        "| --- | --- | --- | --- | --- |",
    ]
    for path in records:
        record = json.loads(path.read_text(encoding="utf-8"))
        provenance = f"run {record.get('run_id')}"
        if record.get("pull_request"):
            provenance += f", PR #{record['pull_request']}"
        if record.get("actor"):
            provenance += f", {record['actor']}"
        lines.append(
            "| `{environment}` | `{revision}` | {apply} | {verify} | {provenance} |".format(
                environment=record.get("environment"),
                revision=str(record.get("source_revision"))[:12],
                apply=record.get("apply_result"),
                verify=record.get("verify_result"),
                provenance=provenance,
            )
        )
    lines += [
        "",
        "Apply is configuration acceptance. Traffic is whether the gateway is "
        "serving it. A promotion needs both, for the same source revision.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    writer = sub.add_parser("write")
    writer.add_argument("--environment", required=True)
    writer.add_argument("--revision", required=True)
    writer.add_argument("--apply-result", required=True, choices=RESULTS)
    writer.add_argument("--verify-result", required=True, choices=RESULTS)
    writer.add_argument("--run-id", required=True)
    writer.add_argument("--actor", default="")
    writer.add_argument("--pr", default=None)
    writer.add_argument("--output", required=True)

    gate = sub.add_parser("require")
    gate.add_argument("--environment", required=True, help="the required predecessor")
    gate.add_argument("--revision", required=True)
    gate.add_argument("--records", required=True)
    gate.add_argument("--summary")

    reporter = sub.add_parser("summarize")
    reporter.add_argument("--records", required=True)
    reporter.add_argument("--summary")

    args = parser.parse_args(argv)

    if args.command == "write":
        record = write(
            environment=args.environment,
            revision=args.revision,
            apply_result=args.apply_result,
            verify_result=args.verify_result,
            run_id=args.run_id,
            actor=args.actor,
            pull_request=args.pr or None,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(
            f"{record['environment']}: apply={record['apply_result']} "
            f"verify={record['verify_result']} at {record['source_revision']}"
        )
        return 0

    if args.command == "summarize":
        text = summarize(Path(args.records))
        print(text, end="")
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as handle:
                handle.write(text)
        return 0

    directory = Path(args.records)
    record = load(directory, args.environment)
    reasons = blockers(record, args.environment, args.revision)
    if not reasons:
        print(
            f"::notice::Promotion authorized: {args.environment} applied and "
            f"verified {args.revision}."
        )
        return 0
    print(
        "::error::Promotion blocked."
        + "".join(f"%0A  - {reason}" for reason in reasons)
    )
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(
                "\n> **Promotion blocked.**\n"
                + "".join(f">\n> - {reason}\n" for reason in reasons)
            )
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
