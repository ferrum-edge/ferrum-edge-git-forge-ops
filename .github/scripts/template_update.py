#!/usr/bin/env python3
"""Adopt an upstream GitForgeOps fix into a repository created from the template.

Creating a repository from the template copies files, not history: GitHub gives
the new repository a fresh root commit with no ancestor in common with upstream.
`git merge` therefore has nothing to merge, and publishing a new container image
does not update a copied workflow or a copied `src/`. Without a deliberate
mechanism, an upstream security or correctness fix simply never reaches the
customer.

The mechanism here is an explicit three-way comparison against a recorded
baseline:

    baseline (B)   the upstream commit this tree was last synced from,
                   recorded in `.gitforgeops/baseline.json`
    upstream (U)   the same path at the target upstream ref
    local    (L)   the path as it stands in this repository

Per upstream-managed path:

    B == U                  upstream did not change it      -> skip
    L == B, B != U          customer never touched it       -> take U
    L == U                  already adopted                 -> skip
    otherwise               both sides changed it           -> CONFLICT

A conflict is *reported*, never resolved. Copying an upstream tree over a
customer's file is exactly the failure this exists to prevent, and a machine
cannot know whether a local edit to `apply-on-merge.yml` was a deliberate
policy or a stale copy.

`CUSTOMER_OWNED` is the fence in the other direction: desired resources,
overlays, environment and policy configuration, the ownership ledger, generated
output, and the repository's own CODEOWNERS are never read as upstream-managed
and never written, whatever an upstream tree contains. Secrets and repository
settings live outside Git entirely and are untouched by construction.

Usage::

    template_update.py identify [--repo-root .]
    template_update.py detect-baseline [--upstream PATH|URL] [--to REF] [--write]
    template_update.py status   [--upstream PATH|URL] [--to REF] [--keep PATH ...]
    template_update.py plan     [--upstream PATH|URL] [--to REF] [--keep PATH ...]
                                [--format text|json]
    template_update.py apply    [--upstream PATH|URL] [--to REF] [--keep PATH ...]

`apply` writes only the clean updates and refuses to advance the recorded
baseline while any conflict remains, so a half-adopted update cannot be
mistaken for a completed one. `--keep PATH` is how a conflict is resolved in
favour of the local file: it is a decision named on the command line, never a
default, and it may only name a path that is actually in conflict.

`detect-baseline` answers "which upstream commit was this tree copied from?"
by finding the upstream commit whose upstream-managed files match the local
ones most closely. A repository created with "Use this template" inherits
upstream's own `baseline.json`, which names whatever commit last wrote it —
not the commit the copy was taken from — so a fresh copy should record its
real baseline once before its first update.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

BASELINE_PATH = Path(".gitforgeops/baseline.json")
DEFAULT_UPSTREAM = "https://github.com/ferrum-edge/ferrum-edge-git-forge-ops.git"
DEFAULT_REF = "main"

# Paths upstream owns. A customer may edit them, but upstream's version is the
# one that carries security and correctness fixes, so a change on both sides is
# a conflict rather than a silent overwrite in either direction.
UPSTREAM_MANAGED = (
    "src",
    "tests",
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "Dockerfile",
    ".dockerignore",
    ".github/workflows",
    ".github/scripts",
    ".github/ferrum-edge-checksums.txt",
    ".github/cargo-audit-policy.json",
    ".github/dependabot.yml",
    ".gitforgeops/config.example.yaml",
    ".gitforgeops/policies.example.yaml",
    ".gitforgeops/smoke.example.yaml",
    "release",
    "docs",
    "README.md",
    "CLAUDE.md",
    "SECURITY.md",
    "LICENSE.md",
)

# Never read from upstream, never written. This is the customer's repository.
#
# `.github/CODEOWNERS` is here because the template ships upstream's
# maintainers in it and step 3 of the README tells every customer to replace
# them; adopting upstream's copy would hand review of a customer's
# launch-critical paths back to people who do not work there.
CUSTOMER_OWNED = (
    "resources",
    "overlays",
    ".gitforgeops/config.yaml",
    ".gitforgeops/policies.yaml",
    ".state",
    "assembled",
    ".github/CODEOWNERS",
)

# Written by this tool, compared by nothing.
GENERATED = (str(BASELINE_PATH),)

# What must be re-run after adopting an update, in order. Printed by `apply`
# and asserted by the test suite so the runbook and the tool cannot disagree.
POST_ADOPTION_CHECKS = (
    ("cargo fmt --all -- --check", "the engine still formats"),
    ("cargo clippy --all-targets -- -D warnings", "the engine still lints"),
    ("cargo test --test unit_tests", "the engine's own suite"),
    (
        "python3 .github/scripts/check_supply_chain.py",
        "every Action, container and validator input is still immutably pinned",
    ),
    (
        "python3 -m unittest discover -s .github/scripts/tests",
        "the workflow helpers this update may have changed",
    ),
    ("gitforgeops validate", "your resources against the pinned validator"),
    (
        "python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO",
        "repository settings drift (plan only; add --apply to write)",
    ),
    (
        "gitforgeops --env ENV plan",
        "a no-op reconciliation: an engine update must not move desired state",
    ),
)


class UpdateError(RuntimeError):
    """Something the operator has to decide about."""


FULL_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def validate_object_id(value: object, field: str) -> str:
    """Accept only a full SHA-1 or SHA-256 object ID from repository data."""
    if not isinstance(value, str) or FULL_OBJECT_ID.fullmatch(value) is None:
        raise UpdateError(
            f"{field} must be a full 40- or 64-character lowercase hexadecimal "
            "Git object ID"
        )
    return value


def validate_ref(value: object, field: str) -> str:
    """Reject option-like and syntactically invalid revisions before invoking Git."""
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise UpdateError(f"{field} must be a valid Git ref name")
    result = subprocess.run(
        ["git", "check-ref-format", "--allow-onelevel", value],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise UpdateError(f"{field} must be a valid Git ref name")
    return value


@dataclass
class Baseline:
    upstream: str
    ref: str
    commit: str

    @classmethod
    def load(cls, root: Path) -> "Baseline | None":
        path = root / BASELINE_PATH
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise UpdateError(f"{BASELINE_PATH} is not valid JSON: {error}") from error
        if not isinstance(data, dict):
            raise UpdateError(f"{BASELINE_PATH} must contain a JSON object")
        missing = [key for key in ("upstream", "ref", "commit") if not data.get(key)]
        if missing:
            raise UpdateError(
                f"{BASELINE_PATH} is missing {', '.join(missing)}; it records which "
                "upstream revision this tree was last synced from and an update "
                "cannot be computed without it"
            )
        if not isinstance(data["upstream"], str) or data["upstream"].startswith("-"):
            raise UpdateError(
                f"{BASELINE_PATH} upstream must be a path or URL, not a Git option"
            )
        return cls(
            data["upstream"],
            validate_ref(data["ref"], f"{BASELINE_PATH} ref"),
            validate_object_id(data["commit"], f"{BASELINE_PATH} commit"),
        )

    def write(self, root: Path) -> None:
        path = root / BASELINE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "upstream": self.upstream,
                    "ref": self.ref,
                    "commit": self.commit,
                    "_comment": (
                        "The upstream revision this repository's upstream-managed "
                        "files were last synced from. Written by "
                        ".github/scripts/template_update.py; see "
                        "docs/template-updates.md."
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )


UNCHANGED = "unchanged"
ADOPT = "adopt"
ALREADY = "already-adopted"
LOCAL_ONLY = "local-only"
CONFLICT = "conflict"
KEPT = "kept"


@dataclass
class Change:
    path: str
    action: str
    detail: str


@dataclass
class Plan:
    baseline: Baseline
    target: str
    changes: list[Change] = field(default_factory=list)

    @property
    def adoptable(self) -> list[Change]:
        return [change for change in self.changes if change.action == ADOPT]

    @property
    def conflicts(self) -> list[Change]:
        return [change for change in self.changes if change.action == CONFLICT]

    @property
    def preserved(self) -> list[Change]:
        return [change for change in self.changes if change.action == LOCAL_ONLY]

    @property
    def kept(self) -> list[Change]:
        return [change for change in self.changes if change.action == KEPT]


def _git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=str(repo), check=False, text=True, capture_output=True
    )
    if check and result.returncode != 0:
        raise UpdateError(
            f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}"
        )
    return result.stdout


def _blob(repo: Path, rev: str, path: str) -> bytes | None:
    """File content at a revision, or None when the path does not exist there."""
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=str(repo),
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def _tracked(repo: Path, rev: str, prefix: str) -> list[str]:
    listing = _git(repo, "ls-tree", "-r", "--name-only", rev, "--", prefix, check=False)
    return [line for line in listing.splitlines() if line]


def is_customer_owned(path: str) -> bool:
    return any(
        path == owned or path.startswith(f"{owned}/") for owned in CUSTOMER_OWNED
    ) or path in GENERATED


def upstream_paths(mirror: Path, revisions: tuple[str, ...]) -> list[str]:
    """Every upstream-managed path present at any of the revisions."""
    found: set[str] = set()
    for rev in revisions:
        for prefix in UPSTREAM_MANAGED:
            found.update(_tracked(mirror, rev, prefix))
    # The fence, applied to upstream's own tree: whatever upstream ships under
    # a customer-owned path is not ours to copy.
    return sorted(path for path in found if not is_customer_owned(path))


def build_plan(
    root: Path,
    mirror: Path,
    baseline: Baseline,
    target: str,
    keep: tuple[str, ...] = (),
) -> Plan:
    plan = Plan(baseline=baseline, target=target)
    for path in upstream_paths(mirror, (baseline.commit, target)):
        before = _blob(mirror, baseline.commit, path)
        after = _blob(mirror, target, path)
        local_path = root / path
        local = local_path.read_bytes() if local_path.is_file() else None

        if before == after:
            plan.changes.append(
                Change(
                    path,
                    LOCAL_ONLY if local != before else UNCHANGED,
                    "upstream did not change this file"
                    + (
                        "; your local edit is preserved"
                        if local != before
                        else ""
                    ),
                )
            )
            continue
        if local == after:
            plan.changes.append(
                Change(path, ALREADY, "already matches the target revision")
            )
            continue
        if local == before:
            plan.changes.append(
                Change(
                    path,
                    ADOPT,
                    "upstream changed it, you did not"
                    if after is not None
                    else "upstream removed it, you did not change it",
                )
            )
            continue
        if path in keep:
            plan.changes.append(
                Change(
                    path,
                    KEPT,
                    "changed upstream AND locally; your version kept by --keep",
                )
            )
            continue
        plan.changes.append(
            Change(
                path,
                CONFLICT,
                "changed upstream AND locally since the recorded baseline",
            )
        )

    # A `--keep` that matches no conflict is a typo or a stale decision. Either
    # way, silently ignoring it would let an operator believe they had resolved
    # something they had not.
    kept = {change.path for change in plan.kept}
    unmatched = sorted(set(keep) - kept)
    if unmatched:
        raise UpdateError(
            f"--keep names {', '.join(unmatched)}, which "
            f"{'is' if len(unmatched) == 1 else 'are'} not in conflict for this "
            "update; --keep only resolves a reported conflict"
        )
    return plan


def _blob_hash(content: bytes) -> str:
    """The git blob id of `content`, without needing the local tree in git."""
    import hashlib

    return hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()


def _local_managed_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for prefix in UPSTREAM_MANAGED:
        base = root / prefix
        candidates = [base] if base.is_file() else (
            sorted(item for item in base.rglob("*") if item.is_file())
            if base.is_dir()
            else []
        )
        for candidate in candidates:
            relative = candidate.relative_to(root).as_posix()
            if is_customer_owned(relative):
                continue
            hashes[relative] = _blob_hash(candidate.read_bytes())
    return hashes


def _tree_hashes(mirror: Path, rev: str) -> dict[str, str]:
    listing = _git(mirror, "ls-tree", "-r", rev, "--", *UPSTREAM_MANAGED, check=False)
    hashes: dict[str, str] = {}
    for line in listing.splitlines():
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and parts[1] == "blob" and not is_customer_owned(path):
            hashes[path] = parts[2]
    return hashes


def detect_baseline(
    root: Path, mirror: Path, ref: str, limit: int = 2000
) -> tuple[str, int, int]:
    """The upstream commit on `ref` closest to this tree's upstream-managed files.

    Returns (commit, differing paths, commits examined). Zero differing paths
    is an exact match; anything else is the closest candidate, and the caller
    reports how far off it is rather than pretending it is exact. Ties go to
    the newest commit, which is the one a copy was most likely taken from.
    """
    local = _local_managed_hashes(root)
    revisions = _git(
        mirror, "rev-list", "--first-parent", f"--max-count={limit}", ref
    ).split()
    if not revisions:
        raise UpdateError(f"upstream revision {ref!r} has no history to search")
    best: tuple[str, int] | None = None
    for rev in revisions:
        upstream = _tree_hashes(mirror, rev)
        differing = sum(
            1
            for path in set(local) | set(upstream)
            if local.get(path) != upstream.get(path)
        )
        if best is None or differing < best[1]:
            best = (rev, differing)
        if differing == 0:
            break
    assert best is not None
    return best[0], best[1], len(revisions)


def prepare_mirror(upstream: str, refs: tuple[str, ...], workdir: Path) -> Path:
    """A local clone of upstream with the revisions this run needs.

    Accepts a path as readily as a URL so the procedure can be rehearsed, and
    tested, entirely offline.
    """
    mirror = workdir / "upstream"
    source = Path(upstream)
    if source.is_dir():
        _git(
            workdir, "clone", "--quiet", "--no-local", "--", str(source), str(mirror)
        )
    else:
        mirror.mkdir(parents=True)
        _git(mirror, "init", "--quiet")
        _git(mirror, "remote", "add", "origin", "--", upstream)
        _git(mirror, "fetch", "--quiet", "--tags", "origin")
    for ref in refs:
        # Fail here, with the ref named, rather than deep inside a comparison.
        if not _git(mirror, "rev-parse", "--verify", f"{ref}^{{commit}}", check=False):
            _git(mirror, "fetch", "--quiet", "origin", "--", ref, check=False)
        if not _git(mirror, "rev-parse", "--verify", f"{ref}^{{commit}}", check=False):
            raise UpdateError(
                f"upstream revision {ref!r} could not be resolved in {upstream}"
            )
    return mirror


def resolve(mirror: Path, ref: str) -> str:
    resolved = _git(mirror, "rev-parse", f"{ref}^{{commit}}").strip()
    if not resolved:
        raise UpdateError(f"upstream revision {ref!r} could not be resolved")
    return resolved


def identify(root: Path) -> dict:
    """Everything needed to say which versions this repository is running."""
    baseline = Baseline.load(root)
    validator = root / ".github/ferrum-edge-checksums.txt"
    pins = []
    if validator.is_file():
        pins = [
            line.split()[0]
            for line in validator.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#") and line.split()
        ]
    cargo = root / "Cargo.toml"
    version = None
    if cargo.is_file():
        for line in cargo.read_text(encoding="utf-8").splitlines():
            if line.startswith("version") and "=" in line:
                version = line.split("=", 1)[1].strip().strip('"')
                break
    return {
        "engine_version": version,
        "template_baseline": (
            None
            if baseline is None
            else {
                "upstream": baseline.upstream,
                "ref": baseline.ref,
                "commit": baseline.commit,
            }
        ),
        "validator_digests": pins,
        "gateway_version": (
            "run `gitforgeops doctor --scope gateway` (or GET /health) against "
            "the environment; the gateway reports its own mode and readiness"
        ),
    }


def render_plan(plan: Plan) -> str:
    lines = [
        "=== GitForgeOps template update ===",
        f"baseline: {plan.baseline.commit} ({plan.baseline.ref})",
        f"target:   {plan.target}",
        "",
    ]
    if plan.adoptable:
        lines.append(f"Adopt ({len(plan.adoptable)}):")
        lines += [f"  {change.path}" for change in plan.adoptable]
        lines.append("")
    if plan.preserved:
        lines.append(f"Preserved local edits ({len(plan.preserved)}):")
        lines += [f"  {change.path} — {change.detail}" for change in plan.preserved]
        lines.append("")
    if plan.kept:
        lines.append(f"Kept by decision ({len(plan.kept)}):")
        lines += [f"  {change.path} — {change.detail}" for change in plan.kept]
        lines.append("")
    if plan.conflicts:
        lines.append(f"CONFLICTS ({len(plan.conflicts)}) — resolve these by hand:")
        lines += [f"  {change.path} — {change.detail}" for change in plan.conflicts]
        lines += [
            "",
            "Each of these changed upstream AND in this repository since the "
            "recorded baseline. Nothing is overwritten. Compare them with:",
            f"  git -C <upstream-clone> diff {plan.baseline.commit}..{plan.target} -- <path>",
            "resolve each one deliberately — take upstream's version, merge the "
            "two, or keep yours with `--keep <path>` — then re-run `apply`.",
            "",
        ]
    if not plan.adoptable and not plan.conflicts:
        lines.append("Nothing to adopt: this repository already carries the target.")
    lines.append(
        f"{len(plan.adoptable)} to adopt, {len(plan.conflicts)} conflict(s), "
        f"{len(plan.preserved)} local edit(s) preserved."
    )
    return "\n".join(lines) + "\n"


def apply_plan(root: Path, mirror: Path, plan: Plan) -> list[str]:
    written: list[str] = []
    for change in plan.adoptable:
        destination = root / change.path
        content = _blob(mirror, plan.target, change.path)
        if content is None:
            if destination.is_file():
                destination.unlink()
                written.append(f"removed {change.path}")
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        # `git show` drops the mode; carry the executable bit across so a
        # helper script does not arrive un-runnable.
        mode = _git(
            mirror, "ls-tree", plan.target, "--", change.path, check=False
        ).split()
        if mode and mode[0].endswith("755"):
            destination.chmod(destination.stat().st_mode | 0o111)
        written.append(change.path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("identify", help="which engine, baseline and validator are installed")
    detector = sub.add_parser(
        "detect-baseline",
        help="find the upstream commit this tree was copied from",
    )
    detector.add_argument("--upstream")
    detector.add_argument("--to", default=None)
    detector.add_argument(
        "--write",
        action="store_true",
        help="record the match as the baseline (an inexact one needs --accept-closest)",
    )
    detector.add_argument(
        "--accept-closest",
        action="store_true",
        help="with --write, record the closest commit even though files differ",
    )
    for name in ("status", "plan", "apply"):
        command = sub.add_parser(name)
        command.add_argument("--upstream")
        command.add_argument("--to", default=None)
        command.add_argument(
            "--keep",
            action="append",
            default=[],
            metavar="PATH",
            help="resolve this conflict by keeping the local file (repeatable)",
        )
        if name != "apply":
            command.add_argument("--format", choices=("text", "json"), default="text")

    args = parser.parse_args(argv)
    root = Path(args.repo_root)

    try:
        if args.command == "identify":
            print(json.dumps(identify(root), indent=2))
            return 0

        if args.command == "detect-baseline":
            recorded = Baseline.load(root)
            upstream = args.upstream or (recorded.upstream if recorded else DEFAULT_UPSTREAM)
            ref = args.to or (recorded.ref if recorded else DEFAULT_REF)
            with tempfile.TemporaryDirectory() as temporary:
                mirror = prepare_mirror(upstream, (ref,), Path(temporary))
                commit, differing, examined = detect_baseline(root, mirror, ref)
            if differing and not (args.write and args.accept_closest):
                print(
                    f"closest upstream commit: {commit} ({differing} upstream-managed "
                    f"path(s) differ; searched {examined} commit(s) of {ref}). This "
                    "tree has local edits or was copied from a revision outside that "
                    "range, so it is not recorded without a decision: confirm it, "
                    "then re-run with --write --accept-closest, or pass --to the ref "
                    "the copy came from."
                )
                return 1
            if differing:
                print(
                    f"closest upstream commit: {commit} ({differing} path(s) differ); "
                    "recording it because --accept-closest was given. The differing "
                    "paths will surface as local edits or conflicts on the next plan."
                )
            else:
                print(f"exact match: this tree was copied from {commit}.")
            if recorded and recorded.commit == commit:
                print(f"{BASELINE_PATH} already records it.")
                return 0
            if args.write:
                Baseline(upstream=upstream, ref=ref, commit=commit).write(root)
                print(f"Recorded {commit} in {BASELINE_PATH}.")
            elif recorded:
                print(
                    f"{BASELINE_PATH} records {recorded.commit} instead. Re-run with "
                    "--write to record the real baseline before your first update."
                )
            return 0

        baseline = Baseline.load(root)
        if baseline is None:
            raise UpdateError(
                f"{BASELINE_PATH} is absent, so there is no recorded upstream "
                "revision to compare against. Create it with the upstream commit "
                "this tree was copied from — see docs/template-updates.md."
            )
        upstream = args.upstream or baseline.upstream or DEFAULT_UPSTREAM
        if upstream.startswith("-"):
            raise UpdateError("upstream must be a path or URL, not a Git option")
        target_ref = args.to or baseline.ref or DEFAULT_REF
        target_ref = validate_ref(target_ref, "target ref")

        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            mirror = prepare_mirror(upstream, (baseline.commit, target_ref), workdir)
            target = resolve(mirror, target_ref)
            plan = build_plan(root, mirror, baseline, target, tuple(args.keep))

            if args.command in ("status", "plan"):
                if args.format == "json":
                    print(
                        json.dumps(
                            {
                                "baseline": baseline.__dict__,
                                "target": target,
                                "changes": [
                                    change.__dict__ for change in plan.changes
                                ],
                            },
                            indent=2,
                        )
                    )
                else:
                    print(render_plan(plan), end="")
                # `status` answers "is there anything to do"; `plan` also fails
                # on a conflict so it can gate a pull request.
                if args.command == "plan" and plan.conflicts:
                    return 1
                return 0

            written = apply_plan(root, mirror, plan)
            print(render_plan(plan), end="")
            for path in written:
                print(f"updated {path}")
            if plan.conflicts:
                print(
                    "\nBaseline NOT advanced: "
                    f"{len(plan.conflicts)} conflict(s) remain. Resolve them and "
                    "re-run `apply`; a half-adopted update must not be recorded "
                    "as a completed one.",
                    file=sys.stderr,
                )
                return 1
            Baseline(upstream=upstream, ref=target_ref, commit=target).write(root)
            print(f"\nBaseline advanced to {target}.")
            print("\nRe-run before deploying:")
            for command, why in POST_ADOPTION_CHECKS:
                print(f"  {command}\n      # {why}")
            return 0
    except UpdateError as error:
        print(f"template update failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    if shutil.which("git") is None:
        print("git is required", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(main())
