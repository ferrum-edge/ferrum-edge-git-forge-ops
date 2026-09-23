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
* and the **source revision is the one this job is about to apply** — or an
  ancestor of it whose deployment inputs are byte-identical.

That last one is what makes the promotion revision-bound. Staging and
production legitimately assemble different bytes, because they select
different overlays; what must be identical is what the desired resources, the
policy, the engine and the workflows all came from.

"Or an ancestor with identical inputs" is not a loosening; without it the gate
could never pass. Every apply publishes `.state/<env>.json` back to the
protected branch, so by the time the promoting job refreshes the branch, the
head it holds is staging's own ledger commit — never the revision staging
recorded. The difference is judged by the same `DEPLOYMENT_INPUT_PATHS`
classifier the freshness guard uses, so a head that differs only in the
ledger, documentation or tests is the same deployment, and one that differs in
anything that could change what is deployed is not.

Usage::

    promotion_record.py write --environment NAME --revision SHA \\
        --apply-result RESULT --verify-result RESULT \\
        --run-id ID --actor LOGIN [--pr NUMBER] --output FILE

    promotion_record.py require --environment NAME --revision SHA \\
        --records DIR [--repo DIR] [--summary FILE]

    promotion_record.py summarize --records DIR [--summary FILE]

`require` exits non-zero — loudly, naming which condition failed — when the
promotion is not authorized.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# The supersession classifier lives beside this file. Importing it — rather
# than re-listing paths here — is what keeps "same deployment" meaning exactly
# what the freshness guard means by it.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deployment_scope  # noqa: E402  (path set above)

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


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def equivalent_revision(recorded: str, revision: str, repo: Path) -> str | None:
    """Why `recorded` is not the same deployment as `revision`; None if it is.

    Same deployment means: `recorded` is an ancestor of `revision`, and every
    path between them is outside `DEPLOYMENT_INPUT_PATHS`. Anything that cannot
    be established — an unknown object, a shallow clone, a git failure — is a
    reason, never a pass.
    """
    if not (FULL_SHA.match(str(recorded)) and FULL_SHA.match(str(revision))):
        return "the recorded revision is not a full commit id"
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", recorded, revision],
        cwd=str(repo),
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        return f"{recorded} is not an ancestor of {revision}"
    try:
        decision = deployment_scope.classify(recorded, revision, repo)
    except subprocess.CalledProcessError as error:
        return f"the two revisions could not be compared: {error}"
    if decision.superseded:
        listed = ", ".join(decision.superseding[:5])
        if len(decision.superseding) > 5:
            listed += f", ... ({len(decision.superseding)} paths)"
        return f"deployment inputs changed in between ({listed})"
    return None


def blockers(
    record: dict | None,
    required_environment: str,
    revision: str,
    repo: Path | None = None,
) -> list[str]:
    """Why this promotion may not proceed. Empty means it may.

    `repo` is the checkout holding both revisions. Without one, only an exact
    revision match is accepted.
    """
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
        why = (
            "no repository was given to compare them"
            if repo is None
            else equivalent_revision(str(recorded), revision, repo)
        )
        if why is not None:
            reasons.append(
                f"{required_environment} was applied at {recorded}, but this job "
                f"would apply {revision}, and {why}. A promotion authorizes one "
                "revision; the protected branch moved a deployment input, so "
                "this one is not it. Let the newer merge's own run promote its "
                "revision."
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
    gate.add_argument(
        "--repo",
        default=".",
        help="checkout holding both revisions, for the same-deployment comparison",
    )
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
    reasons = blockers(record, args.environment, args.revision, Path(args.repo))
    if not reasons:
        recorded = record.get("source_revision") if record else None
        if recorded != args.revision:
            print(
                f"::notice::Promotion authorized: {args.environment} applied and "
                f"verified {recorded}; {args.revision} differs from it only outside "
                "the deployment inputs (the ledger, documentation or tests)."
            )
        else:
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
