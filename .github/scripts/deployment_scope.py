#!/usr/bin/env python3
"""Decide whether a refreshed protected head supersedes a pending apply.

`apply-on-merge.yml` is serialized per environment, so a merge can sit in the
queue for a long time. When its turn comes it re-fetches the protected branch
and reconciles *that* head, because the ownership ledger and the desired
resources have to come from one consistent revision. The run is still
authorized by — and delivers credentials for — the pull request that produced
the TRIGGERING merge, so it may only proceed while the refreshed head carries
the same deployment inputs the triggering merge did.

The failure this module exists to prevent is the mirror image of that rule
applied too broadly. Rejecting *every* difference stranded a queued apply
whenever any later merge touched any file: a README-only merge that cannot
change what a deployment does, and that does not itself schedule an apply,
silently cancelled an authorized configuration change with nothing left to
reconcile it.

So supersession and scheduling are defined by one list. `DEPLOYMENT_INPUT_PATHS`
is both:

* the ``on.push.paths`` filter of `apply-on-merge.yml` — every path here
  schedules its own apply run, and
* the supersession pathspec — a difference here refuses the queued run.

Because the two sets are identical, a change that supersedes a pending apply
always has a replacement run of its own, and a change with no replacement run
can never supersede anything. `check_supply_chain.py` enforces the equality so
the halves cannot drift apart.

Paths outside the list are *inert*: they cannot change the desired gateway
configuration, the policy configuration, or the `gitforgeops` executable that
this job builds from the refreshed checkout. Documentation, tests (which are
not compiled into the installed binary), and unrelated workflows are inert.
Generated ledger and assembled output (`GENERATED_PATHS`) are inert by the same
argument and additionally must never appear in the trigger, or every apply
would re-trigger itself through its own state commit.

Usage::

    deployment_scope.py classify <trigger_sha> <fresh_head> [--repo DIR]

Exits 0 when the queued run may proceed and 1 when it is superseded, emitting
GitHub Actions annotations either way.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# Every input that can change what an apply run does to a gateway:
#
#   resources/, overlays/, .gitforgeops/  desired configuration, environment
#                                         routing and enforceable policy
#   src/, build.rs, Cargo.*,              the gitforgeops binary this job
#   rust-toolchain.toml, .cargo/          installs with `cargo install --path .`
#                                         (`.cargo/config.toml` can set
#                                         rustflags, env and source replacement)
#   .github/scripts/                      helper programs the job executes
#                                         (credential loading, installer,
#                                         merge attribution, this file)
#   .github/ferrum-edge-checksums.txt     which validator binary is trusted
#   .github/workflows/apply-on-merge.yml  the deployment procedure itself
#
# Sorted, and written with the same `**` spelling the workflow trigger uses so
# the two can be compared literally.
DEPLOYMENT_INPUT_PATHS: tuple[str, ...] = (
    ".cargo/**",
    ".github/ferrum-edge-checksums.txt",
    ".github/scripts/**",
    ".github/workflows/apply-on-merge.yml",
    ".gitforgeops/**",
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "overlays/**",
    "resources/**",
    "rust-toolchain.toml",
    "src/**",
)

# Written back to the protected branch by the apply itself. Never a deployment
# input, and never a trigger: a self-triggering ledger commit would loop.
GENERATED_PATHS: tuple[str, ...] = (
    ".state/**",
    "assembled/**",
)

RECOVERY_DOC = "README.md#recovering-a-superseded-apply"


def pathspecs(paths: tuple[str, ...] = DEPLOYMENT_INPUT_PATHS) -> list[str]:
    """Translate the trigger spelling into git pathspecs.

    ``resources/**`` in a workflow filter means "anything under resources".
    Git says that with the directory name alone; a literal ``**`` would be
    matched as a filename component under the default pathspec magic.
    """
    return [path[: -len("/**")] if path.endswith("/**") else path for path in paths]


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def changed_paths(
    trigger_sha: str,
    fresh_head: str,
    repo: Path,
    limit_to: tuple[str, ...] | None = None,
) -> list[str]:
    """Paths that differ between the two revisions, optionally scoped."""
    args = ["diff", "--name-only", trigger_sha, fresh_head]
    if limit_to is not None:
        args += ["--", *pathspecs(limit_to)]
    return [line for line in _git(repo, *args).splitlines() if line]


class ScopeDecision:
    """Why a queued apply may or may not reconcile the refreshed head."""

    def __init__(self, superseding: list[str], inert: list[str]) -> None:
        self.superseding = superseding
        self.inert = inert

    @property
    def superseded(self) -> bool:
        return bool(self.superseding)

    def messages(self, trigger_sha: str, fresh_head: str, branch: str) -> list[str]:
        if self.superseded:
            listed = "%0A".join(f"  - {path}" for path in self.superseding[:20])
            if len(self.superseding) > 20:
                listed += f"%0A  - ... and {len(self.superseding) - 20} more"
            return [
                f"::error::Superseded deployment: {branch} at {fresh_head} changed "
                f"deployment-affecting inputs since triggering commit {trigger_sha}:"
                f"%0A{listed}%0AEvery one of those paths schedules its own "
                "GitForgeOps Apply run, which reconciles this revision together "
                "with everything it carries forward. Wait for — or re-run — the "
                f"apply for {fresh_head}. See {RECOVERY_DOC}."
            ]
        if self.inert:
            listed = ", ".join(sorted(self.inert)[:5])
            if len(self.inert) > 5:
                listed += f", ... ({len(self.inert)} paths)"
            return [
                f"::notice::{branch} advanced past triggering commit {trigger_sha} "
                f"with no deployment-affecting change ({listed}). Applying "
                f"{fresh_head}: desired resources, policy and executable are "
                "byte-identical to the revision this run was authorized for."
            ]
        return [
            f"::notice::{branch} is unchanged since triggering commit "
            f"{trigger_sha}; applying {fresh_head}."
        ]


def classify(trigger_sha: str, fresh_head: str, repo: Path) -> ScopeDecision:
    superseding = changed_paths(
        trigger_sha, fresh_head, repo, limit_to=DEPLOYMENT_INPUT_PATHS
    )
    everything = changed_paths(trigger_sha, fresh_head, repo)
    superseding_set = set(superseding)
    inert = [path for path in everything if path not in superseding_set]
    return ScopeDecision(sorted(superseding), inert)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    classify_parser = sub.add_parser(
        "classify",
        help="decide whether fresh_head supersedes the apply triggered by trigger_sha",
    )
    classify_parser.add_argument("trigger_sha")
    classify_parser.add_argument("fresh_head")
    classify_parser.add_argument("--repo", default=".")
    classify_parser.add_argument("--branch", default="main")
    args = parser.parse_args(argv)

    decision = classify(args.trigger_sha, args.fresh_head, Path(args.repo))
    for message in decision.messages(args.trigger_sha, args.fresh_head, args.branch):
        print(message)
    return 1 if decision.superseded else 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
