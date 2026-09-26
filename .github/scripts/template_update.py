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

Every file this tool reads or writes in the repository is reached one real
directory at a time from the repository root, never through a symbolic link:
a link, or a special file, at a managed path or at any directory above it is
refused with an error before anything is written, and a path that does not
normalize to somewhere under the root is refused outright. Adopted files are
written to a sibling temporary file and renamed into place, so a destination
that is a link to (or a hard link of) a file elsewhere has its own directory
entry replaced instead of the other file written through it.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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
    ("cargo test --lib", "the engine's inline library tests"),
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


# `HEAD`, `FETCH_HEAD`, `ORIG_HEAD`, `MERGE_HEAD`, ... in any case, alone or as
# the last component (`origin/HEAD`).
PSEUDO_REF = re.compile(r"(?:[A-Z]+_)*HEAD\Z", re.IGNORECASE)


def validate_target_ref(value: object, field: str) -> str:
    """A valid ref that names a revision, not whatever a copy last pointed at."""
    ref = validate_ref(value, field)
    if PSEUDO_REF.fullmatch(ref.rsplit("/", 1)[-1]):
        raise UpdateError(
            f"{field} {ref} is ambiguous: HEAD and the other *HEAD pseudo-refs "
            "move with whichever copy resolves them; provide an explicit branch, "
            "tag, or SHA"
        )
    return ref


# -- confined filesystem access ------------------------------------------------
#
# The path lists above are lexical. What keeps them true on disk is that every
# component is opened with O_NOFOLLOW relative to the directory before it, so a
# link cannot carry a read or a write anywhere the lists do not name.

_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
)


def require_confinement_support() -> None:
    """Refuse to run where a path cannot be opened without following links."""
    supported = (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and all(
            call in os.supports_dir_fd
            for call in (os.open, os.stat, os.mkdir, os.rename, os.unlink, os.readlink)
        )
        and os.listdir in os.supports_fd
        and os.stat in os.supports_follow_symlinks
        and hasattr(os, "fchmod")
    )
    if not supported:
        raise UpdateError(
            "this platform cannot open a file without following symbolic links, "
            "so the template updater cannot keep its reads and writes inside the "
            "repository; run it on Linux or macOS"
        )


def _components(relative: str) -> list[str]:
    """The components of a repository-relative path that cannot leave the root."""
    parts = relative.split("/")
    if not relative or "\0" in relative or any(
        part in ("", ".", "..") or part.lower() == ".git" for part in parts
    ):
        raise UpdateError(
            f"refusing {relative!r}: it is not a normalized path inside the repository"
        )
    return parts


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "a symbolic link"
    if stat.S_ISDIR(mode):
        return "a directory"
    if stat.S_ISREG(mode):
        return "a regular file"
    return "a special file"


def _lstat_at(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _refusal(relative: str, shown: str, what: str) -> UpdateError:
    return UpdateError(
        f"refusing {relative}: {shown} is {what}. The template updater reads and "
        "writes only regular files reached through real directories inside the "
        "repository; replace the link or special file with the real file or "
        "directory, then re-run"
    )


@contextlib.contextmanager
def _parent_directory(
    root: Path, relative: str, *, create: bool = False, missing_parent: bool = False
):
    """The directory holding `relative`, reached without following any link.

    Yields (descriptor, final component), or (None, final component) when a
    parent directory does not exist and `create` is false. Each component is
    opened relative to the descriptor of the one before it, so a link swapped
    in while the path is walked is refused rather than followed.
    """
    parts = _components(relative)
    try:
        current = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as error:
        raise UpdateError(
            f"repository root {root} cannot be opened: {error}"
        ) from error
    missing = False
    try:
        for index, part in enumerate(parts[:-1]):
            shown = "/".join(parts[: index + 1])
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    missing = True
                    break
                try:
                    os.mkdir(part, dir_fd=current)
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
                except OSError as error:
                    raise UpdateError(
                        f"refusing {relative}: {shown} could not be created as a "
                        f"directory: {error}"
                    ) from error
            except OSError as error:
                if missing_parent and error.errno == errno.ENOTDIR:
                    info = _lstat_at(current, part)
                    if info is not None and stat.S_ISREG(info.st_mode):
                        missing = True
                        break
                info = _lstat_at(current, part)
                what = "not a directory" if info is None else _kind(info.st_mode)
                raise _refusal(relative, shown, what) from None
            os.close(current)
            current = child
        yield (None if missing else current), parts[-1]
    finally:
        os.close(current)


def read_local(
    root: Path, relative: str, *, missing_parent: bool = False
) -> bytes | None:
    """A regular file's bytes, or None when it (or a parent) does not exist."""
    found = _read_local_file(root, relative, missing_parent=missing_parent)
    return None if found is None else found[0]


def _read_local_file(
    root: Path, relative: str, *, missing_parent: bool = False
) -> tuple[bytes, int] | None:
    """A regular file's bytes and the mode of the very file they were read from."""
    with _parent_directory(root, relative, missing_parent=missing_parent) as (parent, name):
        if parent is None:
            return None
        try:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
        except FileNotFoundError:
            return None
        except OSError:
            info = _lstat_at(parent, name)
            what = "not readable" if info is None else _kind(info.st_mode)
            raise _refusal(relative, relative, what) from None
        with os.fdopen(descriptor, "rb") as handle:
            mode = os.fstat(handle.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise _refusal(relative, relative, _kind(mode))
            return handle.read(), mode


def _umask() -> int:
    mask = os.umask(0)
    os.umask(mask)
    return mask


def write_local(
    root: Path, relative: str, content: bytes, executable: bool = False
) -> None:
    """Replace a regular file (or create it) without following any link.

    The bytes go to a sibling temporary file that is renamed over the
    destination, which replaces the destination's own directory entry: a hard
    link to a file elsewhere is detached from it rather than written through.
    The new file's mode is the one Git would check out, `0777` or `0666` less
    the umask; the permission and special bits of the file it replaces are
    not carried over.
    """
    mode = (0o777 if executable else 0o666) & ~_umask()
    with _parent_directory(root, relative, create=True) as (parent, name):
        existing = _lstat_at(parent, name)
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise _refusal(relative, relative, _kind(existing.st_mode))
        temporary = f".{name}.template-update-{secrets.token_hex(8)}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o666,
            dir_fd=parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                os.fchmod(handle.fileno(), mode)
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent)
            raise


def remove_local(root: Path, relative: str) -> bool:
    """Unlink a regular file; False when there was nothing to remove."""
    with _parent_directory(root, relative) as (parent, name):
        if parent is None:
            return False
        existing = _lstat_at(parent, name)
        if existing is None:
            return False
        if not stat.S_ISREG(existing.st_mode):
            raise _refusal(relative, relative, _kind(existing.st_mode))
        os.unlink(name, dir_fd=parent)
        return True


@dataclass
class Baseline:
    upstream: str
    ref: str
    commit: str

    @classmethod
    def load(cls, root: Path) -> "Baseline | None":
        content = read_local(root, BASELINE_PATH.as_posix())
        if content is None:
            return None
        try:
            data = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
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
        write_local(
            root,
            BASELINE_PATH.as_posix(),
            (
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
                + "\n"
            ).encode("utf-8"),
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


@dataclass(frozen=True)
class TreeEntry:
    """One `git ls-tree` row: the mode says whether the blob is a file or a link."""

    mode: str
    kind: str
    object_id: str

    @property
    def regular(self) -> bool:
        return self.kind == "blob" and self.mode in ("100644", "100755")

    @property
    def executable(self) -> bool:
        return self.mode == "100755"

    def describe(self) -> str:
        if self.mode == "120000":
            return "a symbolic link"
        if self.kind == "commit":
            return "a submodule"
        return f"a {self.kind} with mode {self.mode}"


@dataclass
class Plan:
    baseline: Baseline
    target: str
    changes: list[Change] = field(default_factory=list)
    # The target revision's managed entries, so `apply` writes exactly the blob
    # and mode the plan was computed from.
    target_tree: dict[str, TreeEntry] = field(default_factory=dict)

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


def _c_locale() -> dict[str, str]:
    """The environment with Git's messages in English, so they can be matched."""
    return {**os.environ, "LC_ALL": "C"}


def _object(mirror: Path, object_id: str) -> bytes:
    result = subprocess.run(
        ["git", "cat-file", "blob", object_id],
        cwd=str(mirror),
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise UpdateError(
            f"upstream blob {object_id} could not be read: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def _local_state(
    root: Path, relative: str, *, missing_parent: bool = False
) -> tuple[bytes, bool] | None:
    """A local file's bytes and, as Git records it, whether it is executable."""
    found = _read_local_file(root, relative, missing_parent=missing_parent)
    if found is None:
        return None
    content, mode = found
    return content, bool(mode & stat.S_IXUSR)


def _honours_file_mode(root: Path) -> bool:
    """False when the customer repository sets `core.fileMode=false`.

    Git then ignores the executable bit in the work tree, so neither does the
    comparison: a checkout on a filesystem without one is not a local edit.
    """
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "config",
            "--type=bool",
            "--get",
            "core.fileMode",
        ],
        cwd=str(root),
        check=False,
        capture_output=True,
        text=True,
        env=_c_locale(),
    )
    if result.returncode == 1:
        return True
    if result.returncode != 0:
        raise UpdateError(
            f"git config core.fileMode failed in {root}: {result.stderr.strip()}"
        )
    return result.stdout.strip() != "false"


def is_customer_owned(path: str) -> bool:
    return any(
        path == owned or path.startswith(f"{owned}/") for owned in CUSTOMER_OWNED
    ) or path in GENERATED


def is_upstream_managed(path: str) -> bool:
    """Inside the upstream-managed fence and outside the customer-owned one."""
    return any(
        path == managed or path.startswith(f"{managed}/")
        for managed in UPSTREAM_MANAGED
    ) and not is_customer_owned(path)


def _tree_entries(mirror: Path, rev: str) -> dict[str, TreeEntry]:
    """Every upstream-managed entry at a revision, with its mode."""
    listing = _git(mirror, "ls-tree", "-r", "-z", rev, "--", *UPSTREAM_MANAGED)
    entries: dict[str, TreeEntry] = {}
    for record in listing.split("\0"):
        meta, _, path = record.partition("\t")
        parts = meta.split()
        # The fence, applied to upstream's own tree: whatever upstream ships
        # under a customer-owned path is not ours to copy.
        if len(parts) == 3 and path and is_upstream_managed(path):
            entries[path] = TreeEntry(*parts)
    return entries


def build_plan(
    root: Path,
    mirror: Path,
    baseline: Baseline,
    target: str,
    keep: tuple[str, ...] = (),
    *,
    file_mode: bool = True,
) -> Plan:
    """Classify every upstream-managed path between the baseline and `target`.

    Like Git, only a file's executable bit takes part in the comparison, and
    not even that when `file_mode` is false (`core.fileMode=false`).
    """
    before_tree = _tree_entries(mirror, baseline.commit)
    after_tree = _tree_entries(mirror, target)
    removed_files = set(before_tree) - set(after_tree)
    plan = Plan(baseline=baseline, target=target, target_tree=after_tree)
    for path in sorted(set(before_tree) | set(after_tree)):
        contents: list[bytes | None] = []
        for tree, rev in ((before_tree, baseline.commit), (after_tree, target)):
            entry = tree.get(path)
            if entry is not None and not entry.regular:
                raise UpdateError(
                    f"upstream records {path} as {entry.describe()} at {rev}; the "
                    "template updater adopts only regular files, so this path has "
                    "to be reviewed and adopted by hand"
                )
            contents.append(None if entry is None else _object(mirror, entry.object_id))
        before, after = contents
        local_state = _local_state(
            root,
            path,
            missing_parent=any(path.startswith(f"{removed}/") for removed in removed_files),
        )
        local = None if local_state is None else local_state[0]
        local_executable = False if local_state is None else local_state[1]
        before_executable = before_tree.get(path) is not None and before_tree[path].executable
        after_executable = after_tree.get(path) is not None and after_tree[path].executable

        def matches(content: bytes | None, executable: bool) -> bool:
            return local == content and (not file_mode or local_executable == executable)

        if before == after and before_executable == after_executable:
            edited = not matches(before, before_executable)
            plan.changes.append(
                Change(
                    path,
                    LOCAL_ONLY if edited else UNCHANGED,
                    "upstream did not change this file"
                    + ("; your local edit is preserved" if edited else ""),
                )
            )
            continue
        if matches(after, after_executable):
            plan.changes.append(
                Change(path, ALREADY, "already matches the target revision")
            )
            continue
        if matches(before, before_executable):
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

    # Upstream replaced a file with a directory. Nothing can be written under
    # that path while the file's removal is itself a conflict or kept by
    # --keep, so the new files there wait for the same decision instead of
    # stopping `apply` half-way through.
    actions = {change.path: change.action for change in plan.changes}
    for change in plan.changes:
        if change.action != ADOPT or change.path not in after_tree:
            continue
        blocking = [
            removed
            for removed in sorted(removed_files)
            if change.path.startswith(f"{removed}/") and actions[removed] in (CONFLICT, KEPT)
        ]
        if not blocking:
            continue
        parent = blocking[0]
        if change.path in keep:
            change.action = KEPT
            change.detail = (
                f"upstream adds it under {parent}, which stays a file here; not "
                "adopted, kept by --keep"
            )
        elif actions[parent] == KEPT:
            change.action = CONFLICT
            change.detail = (
                f"upstream adds it under {parent}, which upstream made a directory "
                "but --keep keeps as a file here; adopt the removal of "
                f"{parent} instead, or name this path with --keep as well"
            )
        else:
            change.action = CONFLICT
            change.detail = (
                f"upstream adds it under {parent}, which upstream made a directory "
                f"but which is in conflict here; resolve {parent} first"
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


def _walk_local(root: Path) -> list[str]:
    """Every entry under the upstream-managed paths, walked without following links."""
    found: list[str] = []
    pending = list(UPSTREAM_MANAGED)
    while pending:
        relative = pending.pop()
        with _parent_directory(root, relative) as (parent, name):
            info = None if parent is None else _lstat_at(parent, name)
            if info is None:
                continue
            if not stat.S_ISDIR(info.st_mode):
                # A link or special file is refused when it is read.
                found.append(relative)
                continue
            descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                names = os.listdir(descriptor)
            finally:
                os.close(descriptor)
            # A nested clone's own `.git` is not part of this tree.
            pending.extend(
                f"{relative}/{child}" for child in names if child.lower() != ".git"
            )
    return found


def _local_paths(root: Path) -> list[str]:
    """Upstream-managed paths in this tree that Git would not ignore.

    A Git work tree is listed by Git itself — tracked files plus untracked ones
    its ignore rules do not exclude — so a `__pycache__/` or `.DS_Store` left by
    running the tools is not mistaken for a local edit (#362), while a
    genuinely added source file still is. A tree outside Git has no ignore
    rules to apply, so every file counts.
    """
    inside = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "rev-parse", "--is-inside-work-tree"],
        cwd=str(root),
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
        env=_c_locale(),
    )
    if inside.returncode != 0:
        error = inside.stderr.strip()
        if "not a git repository" in error.lower():
            return _walk_local(root)
        raise UpdateError(f"git rev-parse failed in {root}: {error or 'unknown error'}")
    answer = inside.stdout.strip()
    if answer != "true":
        raise UpdateError(
            f"git rev-parse in {root} did not identify a Git work tree: {answer!r}"
        )
    listing = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *UPSTREAM_MANAGED,
        ],
        cwd=str(root),
        check=False,
        capture_output=True,
        env=_c_locale(),
    )
    if listing.returncode != 0:
        raise UpdateError(
            f"git ls-files failed in {root}: "
            f"{listing.stderr.decode('utf-8', 'replace').strip()}"
        )
    return sorted({os.fsdecode(path) for path in listing.stdout.split(b"\0") if path})


def _local_managed_hashes(root: Path) -> dict[str, tuple[str, str]]:
    hashes: dict[str, tuple[str, str]] = {}
    for relative in _local_paths(root):
        if not is_upstream_managed(relative):
            continue
        if relative.endswith("/"):
            # Git lists a nested repository as its directory and does not look
            # inside it. It is still something upstream never shipped there.
            hashes[relative.rstrip("/")] = ("repository", "")
            continue
        with _parent_directory(root, relative) as (parent, name):
            if parent is None:
                continue
            info = _lstat_at(parent, name)
            if info is None:
                continue
            if stat.S_ISLNK(info.st_mode):
                target = os.fsencode(os.readlink(name, dir_fd=parent))
                hashes[relative] = ("120000", _blob_hash(target))
            elif stat.S_ISREG(info.st_mode):
                content = read_local(root, relative)
                if content is not None:
                    hashes[relative] = ("file", _blob_hash(content))
            else:
                raise _refusal(relative, relative, _kind(info.st_mode))
    return hashes


def _tree_hashes(mirror: Path, rev: str) -> dict[str, tuple[str, str]]:
    # A link's blob holds its target, so the mode takes part in the comparison
    # or a regular file containing that text would match it.
    return {
        path: ("file" if entry.regular else entry.mode, entry.object_id)
        for path, entry in _tree_entries(mirror, rev).items()
        if entry.kind == "blob"
    }


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


# Written into the throwaway upstream copy before its first fetch. A fetch
# otherwise starts `git maintenance run --auto` (or `gc --auto`) detached, which
# can still be writing `objects/` while the temporary directory is removed.
# Nothing may outlive the git command that started it.
MIRROR_CONFIG = (
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("core.fsmonitor", "false"),
    ("fetch.fsckObjects", "true"),
)


def prepare_mirror(upstream: str, refs: tuple[str, ...], workdir: Path) -> Path:
    """A local bare copy of upstream with the revisions this run needs.

    Accepts a path as readily as a URL so the procedure can be rehearsed, and
    tested, entirely offline. Both take the same fetch, and it maps upstream's
    branches to `refs/heads/` and its tags to `refs/tags/`, so `main`, a tag
    and a full commit ID resolve the same way whichever form upstream was given
    in (#361). `origin/<branch>` keeps resolving too.
    """
    mirror = workdir / "upstream"
    source = Path(upstream)
    # The fetch runs inside the mirror, so a relative directory is anchored to
    # where the operator named it first.
    location = str(source.resolve()) if source.is_dir() else upstream
    _git(workdir, "init", "--quiet", "--bare", str(mirror))
    for key, value in MIRROR_CONFIG:
        _git(mirror, "config", key, value)
    _git(mirror, "remote", "add", "origin", "--", location)
    _git(mirror, "config", "--add", "remote.origin.fetch", "+refs/heads/*:refs/heads/*")
    _git(mirror, "fetch", "--quiet", "--tags", "origin")
    for ref in refs:
        # Fail here, with the ref named, rather than deep inside a comparison.
        # A commit no branch or tag reaches can still be fetched by its ID.
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


# The name `write_local` gives its temporary file, and how old one has to be
# before no run can still be writing it.
TEMPORARY_NAME = re.compile(r"\..+\.template-update-[0-9a-f]{16}")
STALE_TEMPORARY_SECONDS = 10 * 60


def _remove_stale_temporaries(root: Path, *, remove: bool) -> None:
    """Deal with sibling files an interrupted atomic write left behind.

    Only a command that writes (`apply`, `detect-baseline --write`) removes
    one, and only once it is old enough that no other run can still own it;
    otherwise it is reported and left in place. Nothing but a regular file
    with exactly the name `write_local` gives is ever touched.
    """
    now = time.time()
    minutes = STALE_TEMPORARY_SECONDS // 60
    pending = list(UPSTREAM_MANAGED)
    while pending:
        relative = pending.pop()
        with _parent_directory(root, relative) as (parent, name):
            info = None if parent is None else _lstat_at(parent, name)
            if info is None or not stat.S_ISDIR(info.st_mode):
                continue
            descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                for child in os.listdir(descriptor):
                    # A nested clone's own `.git` is not part of this tree.
                    if child.lower() == ".git":
                        continue
                    child_info = _lstat_at(descriptor, child)
                    if child_info is None:
                        continue
                    if stat.S_ISDIR(child_info.st_mode):
                        pending.append(f"{relative}/{child}")
                        continue
                    if not stat.S_ISREG(child_info.st_mode):
                        continue
                    if TEMPORARY_NAME.fullmatch(child) is None:
                        continue
                    shown = f"{relative}/{child}"
                    stale = now - child_info.st_mtime >= STALE_TEMPORARY_SECONDS
                    if remove and stale:
                        os.unlink(child, dir_fd=descriptor)
                        print(
                            f"removed {shown}, left by an interrupted template update",
                            file=sys.stderr,
                        )
                    elif remove:
                        print(
                            f"left {shown} in place: it is less than {minutes} "
                            "minutes old, so another template update may still be "
                            "writing it",
                            file=sys.stderr,
                        )
                    else:
                        print(
                            f"found {shown}, apparently left by an interrupted "
                            "template update; `apply` or `detect-baseline --write` "
                            f"removes it once it is {minutes} minutes old",
                            file=sys.stderr,
                        )
            finally:
                os.close(descriptor)


def identify(root: Path) -> dict:
    """Everything needed to say which versions this repository is running."""
    baseline = Baseline.load(root)
    validator = read_local(root, ".github/ferrum-edge-checksums.txt")
    pins = []
    if validator is not None:
        pins = [
            line.split()[0]
            for line in validator.decode("utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#") and line.split()
        ]
    cargo = read_local(root, "Cargo.toml")
    version = None
    if cargo is not None:
        for line in cargo.decode("utf-8").splitlines():
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
        # The plan only ever names managed paths; a write outside the fence
        # would be a bug, and it is refused as one rather than carried out.
        if not is_upstream_managed(change.path):
            raise UpdateError(f"refusing {change.path}: it is not upstream-managed")
        entry = plan.target_tree.get(change.path)
        if entry is None:
            if remove_local(root, change.path):
                written.append(f"removed {change.path}")
            continue
        write_local(
            root, change.path, _object(mirror, entry.object_id), entry.executable
        )
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
        require_confinement_support()
        if args.command == "identify":
            print(json.dumps(identify(root), indent=2))
            return 0

        if args.command == "detect-baseline":
            recorded = Baseline.load(root)
            upstream = args.upstream or (recorded.upstream if recorded else DEFAULT_UPSTREAM)
            if upstream.startswith("-"):
                raise UpdateError("upstream must be a path or URL, not a Git option")
            ref = validate_target_ref(
                args.to or (recorded.ref if recorded else DEFAULT_REF), "target ref"
            )
            _remove_stale_temporaries(root, remove=args.write)
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
        target_ref = validate_target_ref(
            args.to or baseline.ref or DEFAULT_REF, "target ref"
        )
        _remove_stale_temporaries(root, remove=args.command == "apply")
        file_mode = _honours_file_mode(root)

        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            mirror = prepare_mirror(upstream, (baseline.commit, target_ref), workdir)
            target = resolve(mirror, target_ref)
            plan = build_plan(
                root, mirror, baseline, target, tuple(args.keep), file_mode=file_mode
            )

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
    except OSError as error:
        # A path that changed underneath a confined walk lands here rather
        # than being followed.
        print(f"template update failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    if shutil.which("git") is None:
        print("git is required", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(main())
