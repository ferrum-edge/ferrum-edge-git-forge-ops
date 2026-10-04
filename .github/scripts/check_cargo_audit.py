#!/usr/bin/env python3
"""Run cargo-audit and enforce reviewed, expiring dependency-risk exceptions."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import http.client
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator


MAX_REVIEW_HORIZON_DAYS = 120
REVIEW_WARNING_WINDOW_DAYS = 21
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

# cargo-audit buckets that fail the build. Everything else (unmaintained,
# notice, ...) is reported as a non-fatal GitHub annotation: an advisory that
# only says "this crate is no longer maintained" must not turn every open pull
# request red before a human can write a reviewed exception for it.
BLOCKING_KINDS = frozenset({"vulnerability", "unsound", "yanked"})

# Reachability verifiers are selected by the exception's own `reachability`
# field, or by (kind, advisory, package) for the entries that predate it.
# Version is deliberately NOT part of the selector: a patch bump of the
# vulnerable crate must not silently switch the verifier off.
AGE_ENCRYPTION_ONLY = "age-encryption-only"
IMPLICIT_REACHABILITY: dict[tuple[str, str, str], str] = {
    ("vulnerability", "RUSTSEC-2023-0071", "rsa"): AGE_ENCRYPTION_ONLY,
}
# Packages whose exceptions must always resolve to a verifier. An rsa
# exception the gate cannot machine-check is a policy error, never a pass.
VERIFIER_REQUIRED_PACKAGES = frozenset({"rsa"})

EXPECTED_RSA_TREE = re.compile(
    r"^rsa v0\.9\.\d+\n"
    r"└── age v0\.12\.\d+\n"
    r"    └── gitforgeops v\d+\.\d+\.\d+ \([^\n]+\)\n?$"
)
AGE_VERSION_REQUIREMENT = re.compile(r"^0\.12(?:\.\d+)?$")
REQUIRED_AGE_FEATURES = frozenset({"ssh", "armor"})
REVIEWED_AGE_MODULE = Path("src/secrets/delivery.rs")
ALLOWED_AGE_REFERENCES = {
    "age::Encryptor",
    "age::Recipient",
    "age::armor::ArmoredWriter",
    "age::armor::Format",
    "age::ssh::Recipient",
}
AGE_REFERENCE = re.compile(r"\bage(?:::[A-Za-z_][A-Za-z0-9_]*)+")
CARGO_TREE_NO_MATCH = "did not match any packages"

# Files that steer `cargo` or `cargo audit` from the working directory: cargo
# discovers `.cargo/config[.toml]` (aliases, `[env]`, source replacement) in the
# working directory and every ancestor, rustup discovers `rust-toolchain[.toml]`
# (including a `path` toolchain) the same way, and cargo-audit reads
# `./.cargo/audit.toml` (ignore lists, advisory database location, yanked
# checks). None of them is looked up next to `--manifest-path` or `--file`, so
# the gate runs cargo from an isolated directory: candidate copies are ignored
# (and only listed in the log), and none may exist at or above that directory.
CARGO_CONTROL_FILES = (
    ".cargo/config",
    ".cargo/config.toml",
    ".cargo/audit.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
)
# Inherited variables that would otherwise select a toolchain, wrap rustc,
# unlock nightly-only behaviour (`RUSTC_BOOTSTRAP`, cargo's internal
# `__CARGO_*` overrides) or configure cargo (`CARGO_ALIAS_<name>`,
# `CARGO_HOME`, ...) for the gate.
SCRUBBED_ENVIRONMENT = frozenset(
    {
        "CARGO",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
    }
)
SCRUBBED_ENVIRONMENT_PREFIXES = ("CARGO_", "__CARGO_")

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_LOCKFILE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCE_ENTRIES = 4096
MAX_SOURCE_DEPTH = 32
MAX_INDEX_BYTES = 16 * 1024 * 1024
INDEX_TIMEOUT_SECONDS = 30
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CRATE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
CRATE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?$")
CHECKSUM = re.compile(r"^[0-9a-f]{64}$")

_RAW_STRING_START = re.compile(r'b?r(?P<hashes>#*)"')
_CHAR_LITERAL = re.compile(r"b?'(?:\\.|[^\\'\n])'")


class PolicyError(ValueError):
    """Raised when the checked-in exception policy is malformed."""


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_ident_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def strip_rust_comments_and_strings(text: str) -> str:
    """Blank out comments, string literals, and character literals.

    Removed spans become spaces (newlines preserved) so line structure and the
    surrounding statement text survive. A `// age::Decryptor` note, a doc
    comment, or a "age::Decryptor" string is documentation, not a call, and
    must not trip the API allowlist.
    """
    out: list[str] = []
    index = 0
    length = len(text)

    def blank(span: str) -> None:
        out.append("".join("\n" if char == "\n" else " " for char in span))

    while index < length:
        char = text[index]
        preceded_by_ident = index > 0 and _is_ident_char(text[index - 1])

        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            blank(text[index:end])
            index = end
            continue

        if text.startswith("/*", index):
            start = index
            depth = 0
            while index < length:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                    if depth == 0:
                        break
                else:
                    index += 1
            blank(text[start:index])
            continue

        if char in ("r", "b") and not preceded_by_ident:
            raw = _RAW_STRING_START.match(text, index)
            if raw:
                terminator = '"' + raw.group("hashes")
                end = text.find(terminator, raw.end())
                end = length if end == -1 else end + len(terminator)
                blank(text[index:end])
                index = end
                continue

        if char == '"' or (
            char == "b" and text.startswith('b"', index) and not preceded_by_ident
        ):
            start = index
            index += 2 if char == "b" else 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            blank(text[start:index])
            continue

        if char in ("'", "b") and not preceded_by_ident:
            literal = _CHAR_LITERAL.match(text, index)
            if literal:
                blank(literal.group(0))
                index = literal.end()
                continue

        out.append(char)
        index += 1

    return "".join(out)


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
    if not isinstance(report, dict):
        raise PolicyError("cargo-audit report must be a JSON object")
    findings: list[dict[str, str | None]] = []

    vulnerability_section = report.get("vulnerabilities", {})
    if not isinstance(vulnerability_section, dict):
        raise PolicyError("cargo-audit report has a malformed vulnerabilities object")
    vulnerabilities = vulnerability_section.get("list", [])
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

    reported_count = vulnerability_section.get("count")
    if reported_count is not None and reported_count != len(vulnerabilities):
        raise PolicyError(
            f"cargo-audit reported {reported_count} vulnerabilities but this gate "
            f"parsed {len(vulnerabilities)}; the report shape changed"
        )

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

        if "reachability" in exception and not _nonempty_text(exception["reachability"]):
            raise PolicyError(f"{label}.reachability must be non-empty text when present")

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


def review_deadline_warnings(
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]], today: dt.date
) -> list[str]:
    """Warn before an exception expires; expiry itself is a hard, repo-wide stop."""
    annotations: list[str] = []
    for key in sorted(policy):
        exception = policy[key]
        try:
            review_by = dt.date.fromisoformat(str(exception["review_by"]))
        except (KeyError, ValueError):  # pragma: no cover - load_policy validated it
            continue
        remaining = (review_by - today).days
        if remaining > REVIEW_WARNING_WINDOW_DAYS:
            continue
        advisory = f" ({exception['advisory']})" if exception.get("advisory") else ""
        annotations.append(
            f"::warning::cargo-audit exception for {exception['package']} "
            f"{exception['version']}{advisory} is due for re-review by "
            f"{review_by.isoformat()} ({remaining} day(s) left, owner "
            f"{exception['owner']}); once it expires every pull request, push, and "
            "scheduled security run fails"
        )
    return annotations


def evaluate(
    report: dict[str, Any],
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]],
) -> tuple[
    list[dict[str, str | None]],
    list[dict[str, str | None]],
    list[tuple[str, str, str, str, str]],
    list[dict[str, str | None]],
]:
    findings = collect_findings(report)
    reviewed: list[dict[str, str | None]] = []
    blocked: list[dict[str, str | None]] = []
    informational: list[dict[str, str | None]] = []
    used: set[tuple[str, str, str, str, str]] = set()

    for finding in findings:
        key = _finding_key(finding)
        if key in policy:
            reviewed.append(finding)
            used.add(key)
        elif str(finding["kind"]) in BLOCKING_KINDS:
            blocked.append(finding)
        else:
            informational.append(finding)

    stale = sorted(set(policy) - used)
    return reviewed, blocked, stale, informational


def ignored_candidate_cargo_inputs(source_root: Path) -> list[str]:
    """Candidate cargo/toolchain control files this gate deliberately ignores."""
    return [name for name in CARGO_CONTROL_FILES if os.path.lexists(source_root / name)]


def _candidate_regular_file(
    source_root: Path, name: str, limit: int, directory_fd: int
) -> None:
    """Check initial metadata; the bounded descriptor read checks again at open."""
    path = source_root / name
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise PolicyError(f"candidate {name} must be a regular file: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyError(f"candidate {name} must be a regular file: {path}")
    if metadata.st_size > limit:
        raise PolicyError(f"candidate {name} exceeds the {limit}-byte limit")


def _read_regular_text(path: Path, limit: int, directory_fd: int | None = None) -> str:
    """Bound reads and refuse links/devices even if the checked path is replaced."""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise PolicyError(f"candidate input must be a regular file: {path}")
            if metadata.st_size > limit:
                raise PolicyError(f"candidate input exceeds the {limit}-byte limit: {path}")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise PolicyError(f"candidate input exceeds the {limit}-byte limit: {path}")
        return data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError(f"cannot inspect {path}: {exc}") from exc


@contextlib.contextmanager
def _directory_descriptor(path: Path, parent_fd: int | None = None) -> Iterator[int]:
    """Pin directories before descending and refuse symlinked child directories."""
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise PolicyError(f"candidate source must be a real directory: {path}: {exc}") from exc
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _capture_sources(root_fd: int) -> dict[Path, str] | None:
    """Read Rust sources once through pinned directories, with per-tree bounds."""
    try:
        metadata = os.stat("src", dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        raise PolicyError("candidate src must be a real directory, never a symlink")
    sources: dict[Path, str] = {}
    entries_seen = 0
    total_bytes = 0

    def visit(directory_fd: int, relative: Path, depth: int) -> None:
        nonlocal entries_seen, total_bytes
        if depth > MAX_SOURCE_DEPTH:
            raise PolicyError("candidate source tree exceeds the directory depth limit")
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_SOURCE_ENTRIES:
                    raise PolicyError("candidate source tree exceeds the entry limit")
                path = relative / entry.name
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    with _directory_descriptor(Path(entry.name), directory_fd) as child_fd:
                        visit(child_fd, path, depth + 1)
                elif not stat.S_ISREG(metadata.st_mode):
                    raise PolicyError(
                        f"candidate source must be a regular file or real directory: {path}"
                    )
                elif path.suffix == ".rs":
                    text = _read_regular_text(
                        Path(entry.name), MAX_SOURCE_BYTES, directory_fd
                    )
                    total_bytes += len(text.encode("utf-8"))
                    if total_bytes > MAX_SOURCE_TOTAL_BYTES:
                        raise PolicyError("candidate source tree exceeds the total byte limit")
                    sources[path] = text

    with _directory_descriptor(Path("src"), root_fd) as source_fd:
        visit(source_fd, Path("src"), 0)
    return sources


def _refuse_ancestor_manifests(root: Path) -> None:
    # Cargo discovers implicit workspaces even outside --manifest-path's tree.
    # Refuse without reading any ancestor's contents.
    for ancestor in root.resolve().parents:
        if os.path.lexists(ancestor / "Cargo.toml"):
            raise PolicyError(
                "audit gate requires a standalone checkout without an ancestor "
                f"Cargo.toml that could select a workspace: {ancestor / 'Cargo.toml'}"
            )


def _validate_manifest_and_lockfile(
    source_root: Path, manifest_text: str, lockfile_text: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        manifest = tomllib.loads(manifest_text)
        lockfile = tomllib.loads(lockfile_text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"cannot parse candidate Cargo inputs: {exc}") from exc
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("name") != "gitforgeops":
        raise PolicyError("audit gate requires the single gitforgeops root package")
    if "workspace" in package or "workspace" in manifest:
        raise PolicyError(
            "audit gate requires a single-package repository; package.workspace and "
            "[workspace] are refused because Cargo could use a different dependency "
            "graph or lockfile than the audited root Cargo.lock"
        )
    _refuse_ancestor_manifests(source_root)
    if lockfile.get("version") not in (3, 4):
        raise PolicyError("audit gate requires a version 3 or 4 Cargo.lock")
    # A data-only snapshot must not send Cargo back into candidate-controlled
    # local dependency manifests (including target deps, patches and replaces).
    def table_values(value: Any) -> list[Any]:
        if not isinstance(value, dict):
            raise PolicyError("audit snapshot requires Cargo dependency tables")
        return list(value.values())

    dependency_tables = [manifest, *table_values(manifest.get("target", {}))]
    dependencies = []
    for table in dependency_tables:
        if not isinstance(table, dict):
            raise PolicyError("audit snapshot requires Cargo dependency tables")
        for section in (
            "dependencies",
            "dev-dependencies",
            "dev_dependencies",
            "build-dependencies",
            "build_dependencies",
        ):
            dependencies.extend(table_values(table.get(section, {})))
    for table in table_values(manifest.get("patch", {})):
        dependencies.extend(table_values(table))
    dependencies.extend(table_values(manifest.get("replace", {})))
    if any(isinstance(dependency, dict) and "path" in dependency for dependency in dependencies):
        raise PolicyError("audit snapshot does not support local path dependencies")
    return manifest, lockfile


@dataclass(frozen=True)
class CandidateSnapshot:
    root: Path
    manifest: dict[str, Any]
    lockfile: dict[str, Any]
    sources: dict[Path, str] | None
    workdir: Path
    environment: dict[str, str]


@contextlib.contextmanager
def candidate_snapshot(source_root: Path) -> Iterator[CandidateSnapshot]:
    """Capture bounded data once; every verifier and Cargo command uses this copy."""
    with _directory_descriptor(source_root) as root_fd:
        # Reject BOTH invalid inputs before reading either one's contents.
        _candidate_regular_file(source_root, "Cargo.toml", MAX_MANIFEST_BYTES, root_fd)
        _candidate_regular_file(source_root, "Cargo.lock", MAX_LOCKFILE_BYTES, root_fd)
        manifest_text = _read_regular_text(Path("Cargo.toml"), MAX_MANIFEST_BYTES, root_fd)
        lockfile_text = _read_regular_text(Path("Cargo.lock"), MAX_LOCKFILE_BYTES, root_fd)
        manifest, lockfile = _validate_manifest_and_lockfile(
            source_root, manifest_text, lockfile_text
        )
        _registry_packages(lockfile)
        sources = _capture_sources(root_fd)
    with isolated_cargo(source_root) as (workdir, environment):
        root = workdir.parent / "snapshot"
        _refuse_ancestor_manifests(root)
        root.mkdir()
        (root / "Cargo.toml").write_text(manifest_text, encoding="utf-8")
        (root / "Cargo.lock").write_text(lockfile_text, encoding="utf-8")
        for relative, text in (sources or {}).items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        # No configuration, scripts, executables or arbitrary repository files
        # are copied. cargo tree only needs target discovery, never compilation.
        yield CandidateSnapshot(root, manifest, lockfile, sources, workdir, environment)


def _scrubbed_cargo_environment(cargo_home: Path, home: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in SCRUBBED_ENVIRONMENT
        and not key.startswith(SCRUBBED_ENVIRONMENT_PREFIXES)
    }
    # HOME must not expose Git/user configuration. Rustup still needs the
    # runner's installed default toolchain, so retain only its trusted store.
    environment["RUSTUP_HOME"] = str(
        Path(os.environ.get("RUSTUP_HOME") or Path.home() / ".rustup").resolve()
    )
    environment["HOME"] = str(home)
    environment["CARGO_HOME"] = str(cargo_home)
    return environment


@contextlib.contextmanager
def isolated_cargo(source_root: Path) -> Iterator[tuple[Path, dict[str, str]]]:
    """Yield a working directory and environment that no candidate file reaches.

    Cargo, rustup and cargo-audit all read configuration relative to the
    working directory, not to `--manifest-path` or `--file`. Running from a
    fresh directory outside the candidate tree, with fresh `HOME`/`CARGO_HOME` and
    no inherited cargo/rustup selection variables, keeps candidate control
    files out of the data snapshot. The toolchain is the runner's
    default, installed by the workflow's pinned toolchain step.
    """
    root = source_root.resolve()
    # Downloaded crate sources and the advisory database land in this
    # CARGO_HOME; failing to delete them afterwards must not fail the gate.
    with tempfile.TemporaryDirectory(
        prefix="cargo-audit-isolated-", ignore_cleanup_errors=True
    ) as directory:
        base = Path(directory).resolve()
        workdir = base / "work"
        cargo_home = base / "cargo-home"
        home = base / "home"
        workdir.mkdir()
        cargo_home.mkdir()
        home.mkdir()
        if root == workdir or root in workdir.parents:
            raise PolicyError(
                f"the isolated cargo directory {workdir} is inside the candidate "
                f"tree {root}; point TMPDIR outside the checkout"
            )
        for ancestor in (workdir, *workdir.parents):
            for name in CARGO_CONTROL_FILES:
                if os.path.lexists(ancestor / name):
                    raise PolicyError(
                        f"cargo would read {ancestor / name} from the isolated "
                        "working directory; point TMPDIR at a directory without "
                        "cargo or rustup configuration above it"
                    )
        environment = _scrubbed_cargo_environment(cargo_home, home)
        rustup_home = Path(environment["RUSTUP_HOME"])
        if root == rustup_home or root in rustup_home.parents:
            raise PolicyError("RUSTUP_HOME must not point inside the candidate tree")
        yield workdir, environment


def _read_dependency_tree(
    package: str,
    version: str,
    snapshot: CandidateSnapshot,
    dependency_tree_path: Path | None,
) -> str:
    if dependency_tree_path is not None:
        try:
            return dependency_tree_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(
                f"cannot inspect dependency tree {dependency_tree_path}: {exc}"
            ) from exc

    spec = f"{package}@{version}"
    manifest = snapshot.root / "Cargo.toml"
    try:
        result = subprocess.run(
            [
                "cargo",
                "tree",
                "--manifest-path",
                str(manifest),
                "--color",
                "never",
                "--locked",
                "--all-features",
                "--target",
                "all",
                "-i",
                spec,
            ],
            cwd=snapshot.workdir,
            env=snapshot.environment,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise PolicyError(
            f"could not inspect the {package} dependency path: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        if CARGO_TREE_NO_MATCH in detail:
            raise PolicyError(
                f"stale exception: {spec} is no longer in the dependency graph. "
                "Remove the entry from .github/cargo-audit-policy.json (or update "
                "its version if the dependency was upgraded rather than dropped)."
            )
        raise PolicyError(f"cargo tree failed while checking the {package} path: {detail}")
    return result.stdout


def verify_age_encryption_only(
    exception: dict[str, Any], snapshot: CandidateSnapshot, dependency_tree_path: Path | None
) -> None:
    """Fail closed if the RSA exception outlives its encryption-only premise."""
    manifest = snapshot.manifest
    age_dependency = manifest.get("dependencies", {}).get("age")
    if not isinstance(age_dependency, dict):
        raise PolicyError("RSA exception requires age to use an explicit dependency table")
    version = age_dependency.get("version")
    features = age_dependency.get("features")
    if (
        not isinstance(version, str)
        or not AGE_VERSION_REQUIREMENT.fullmatch(version)
        or not isinstance(features, list)
        or set(features) != REQUIRED_AGE_FEATURES
    ):
        raise PolicyError(
            "RSA exception requires an age 0.12 requirement with exactly the "
            "ssh and armor features"
        )

    if snapshot.sources is None:
        raise PolicyError("RSA exception source directory is missing: src")
    for relative, raw_text in sorted(snapshot.sources.items()):
        # Comments and string literals are prose, not reachable calls.
        text = strip_rust_comments_and_strings(raw_text)
        references = set(AGE_REFERENCE.findall(text))
        if references and relative != REVIEWED_AGE_MODULE:
            raise PolicyError(
                f"RSA exception permits age calls only in {REVIEWED_AGE_MODULE}; "
                f"found {relative}"
            )
        for reference in sorted(references):
            allowed = any(
                reference == prefix or reference.startswith(f"{prefix}::")
                for prefix in ALLOWED_AGE_REFERENCES
            )
            if not allowed:
                raise PolicyError(
                    f"RSA exception encountered an unreviewed age API reference: "
                    f"{reference}"
                )
        age_use_statements = re.findall(
            r"^\s*use\s+(?:::)?age(?:\s|::).*?;\s*$", text, re.MULTILINE
        )
        if age_use_statements and (
            relative != REVIEWED_AGE_MODULE
            or [statement.strip() for statement in age_use_statements]
            != ["use age::ssh::Recipient;"]
        ):
            raise PolicyError(
                "RSA exception permits only the reviewed age::ssh::Recipient import"
            )
        if re.search(r"\bextern\s+crate\s+age\b|\bage\s*::\s*\{", text):
            raise PolicyError("RSA exception forbids alternate age import forms")

    dependency_tree = _read_dependency_tree(
        str(exception["package"]),
        str(exception["version"]),
        snapshot,
        dependency_tree_path,
    )
    if not EXPECTED_RSA_TREE.fullmatch(dependency_tree):
        raise PolicyError(
            "RSA exception dependency path changed; expected only "
            "gitforgeops -> age 0.12.x -> rsa 0.9.x"
        )


REACHABILITY_VERIFIERS: dict[
    str, Callable[[dict[str, Any], CandidateSnapshot, Path | None], None]
] = {
    AGE_ENCRYPTION_ONLY: verify_age_encryption_only,
}


def _reachability_verifier_name(
    key: tuple[str, str, str, str, str], exception: dict[str, Any]
) -> str | None:
    declared = exception.get("reachability")
    if declared is not None:
        return str(declared).strip()
    kind, advisory, package, _version, _source = key
    return IMPLICIT_REACHABILITY.get((kind, advisory, package))


def verify_exception_reachability(
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]],
    snapshot: CandidateSnapshot,
    dependency_tree_path: Path | None,
) -> None:
    """Run every exception's reachability verifier, or refuse to accept it."""
    for key in sorted(policy):
        exception = policy[key]
        package = key[2]
        name = _reachability_verifier_name(key, exception)
        if name is None:
            if package in VERIFIER_REQUIRED_PACKAGES:
                raise PolicyError(
                    f"exception for {package} {key[3]} has no reachability verifier; "
                    f'set "reachability" to one of '
                    f"{sorted(REACHABILITY_VERIFIERS)} or remove the exception"
                )
            continue
        verifier = REACHABILITY_VERIFIERS.get(name)
        if verifier is None:
            raise PolicyError(
                f"exception for {package} {key[3]} requests unknown reachability "
                f"verifier {name!r}; known verifiers are "
                f"{sorted(REACHABILITY_VERIFIERS)}"
            )
        verifier(exception, snapshot, dependency_tree_path)


def _format_finding(finding: dict[str, str | None]) -> str:
    advisory = f" {finding['advisory']}" if finding.get("advisory") else ""
    return (
        f"{finding['kind']}{advisory}: "
        f"{finding['package']} {finding['version']}"
    )


def run_cargo_audit(snapshot: CandidateSnapshot) -> tuple[dict[str, Any], int]:
    # An explicit `--file` also stops cargo-audit from generating a lockfile
    # when the candidate has none: a missing lockfile is a refusal, not a
    # fresh resolution.
    lockfile = snapshot.root / "Cargo.lock"
    try:
        result = subprocess.run(
            [
                "cargo",
                "audit",
                "--json",
                "--deny",
                "unsound",
                "--deny",
                "yanked",
                "--file",
                str(lockfile),
            ],
            cwd=snapshot.workdir,
            env=snapshot.environment,
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


def _registry_packages(lockfile: dict[str, Any]) -> list[dict[str, str]]:
    packages = lockfile.get("package", [])
    if not isinstance(packages, list):
        raise PolicyError("Cargo.lock package entries must be a list")
    registry_packages = []
    identities = set()
    for package in packages:
        if not isinstance(package, dict):
            raise PolicyError("Cargo.lock contains a malformed package")
        name, version, source = (package.get(key) for key in ("name", "version", "source"))
        if not isinstance(name, str) or not CRATE_NAME.fullmatch(name):
            raise PolicyError("Cargo.lock contains an invalid package name")
        if not isinstance(version, str) or not CRATE_VERSION.fullmatch(version):
            raise PolicyError(f"Cargo.lock contains an invalid version for {name}")
        if source is not None and not isinstance(source, str):
            raise PolicyError(f"Cargo.lock contains an invalid source for {name}")
        identity = (name, version, source)
        if identity in identities:
            raise PolicyError(f"Cargo.lock repeats package {name}@{version}")
        identities.add(identity)
        if source is None or source.startswith("git+"):
            # Local and Git dependencies have no registry yanked status.
            continue
        if source != CRATES_IO_SOURCE:
            raise PolicyError(
                f"complete yanked scan does not support source {source!r} for "
                f"{name}@{version}; this repository uses only the crates.io registry"
            )
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or not CHECKSUM.fullmatch(checksum):
            raise PolicyError(f"Cargo.lock lacks a valid checksum for {name}@{version}")
        registry_packages.append(
            {"name": name, "version": version, "source": source, "checksum": checksum}
        )
    return registry_packages


def _fetch_crate_index(name: str) -> list[dict[str, Any]]:
    lower = name.lower()
    if len(lower) <= 2:
        prefix = str(len(lower))
    elif len(lower) == 3:
        prefix = f"3/{lower[0]}"
    else:
        prefix = f"{lower[:2]}/{lower[2:4]}"
    url = f"https://index.crates.io/{prefix}/{lower}"
    request = urllib.request.Request(
        url, headers={"Accept": "text/plain", "Cache-Control": "no-cache"}
    )
    try:
        with urllib.request.urlopen(request, timeout=INDEX_TIMEOUT_SECONDS) as response:
            if response.status != 200 or response.geturl() != url:
                raise PolicyError(f"unexpected crates.io index response for {name}")
            data = response.read(MAX_INDEX_BYTES + 1)
            if len(data) > MAX_INDEX_BYTES:
                raise PolicyError(f"crates.io index entry exceeds the byte limit for {name}")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) != len(data):
                raise PolicyError(f"incomplete crates.io index response for {name}")
        entries = [json.loads(line) for line in data.decode("utf-8").splitlines()]
    except (OSError, http.client.HTTPException, urllib.error.URLError, ValueError) as exc:
        raise PolicyError(f"complete yanked scan cannot read index for {name}: {exc}") from exc
    if not entries or not all(isinstance(entry, dict) for entry in entries):
        raise PolicyError(f"malformed crates.io index entry for {name}")
    return entries


def scan_yanked_packages(lockfile: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """Require positive index evidence for EVERY locked registry package version.

    cargo-audit 0.22.1 can return successful JSON without an index and after
    individual lookup errors. Its warning list is not completeness evidence.
    Query the published crates.io sparse index independently, without Cargo
    configuration, local cache or fallback. Any unavailable or missing record
    is an operational failure, even when all advisories have exceptions.
    """
    packages = _registry_packages(lockfile)
    names = sorted({package["name"] for package in packages})
    # Fetch each crate once, including crates with multiple locked versions.
    # Executor.map preserves deterministic processing and propagates failures.
    with ThreadPoolExecutor(max_workers=8) as executor:
        indices = dict(zip(names, executor.map(_fetch_crate_index, names)))
    yanked = []
    for package in packages:
        name, version = package["name"], package["version"]
        matching = [
            entry
            for entry in indices[name]
            if entry.get("name") == name and entry.get("vers") == version
        ]
        if len(matching) != 1:
            raise PolicyError(f"complete yanked scan lacks a unique record for {name}@{version}")
        entry = matching[0]
        if entry.get("cksum") != package["checksum"]:
            raise PolicyError(f"crates.io checksum differs from Cargo.lock for {name}@{version}")
        if not isinstance(entry.get("yanked"), bool):
            raise PolicyError(f"complete yanked scan lacks a boolean status for {name}@{version}")
        if entry["yanked"]:
            yanked.append({"kind": "yanked", "package": package, "advisory": None})
    return yanked, len(packages)


def merge_yanked_findings(report: dict[str, Any], yanked: list[dict[str, Any]]) -> None:
    # Validate the original report before adding independently verified rows.
    findings = collect_findings(report)
    seen = {_finding_key(finding) for finding in findings if finding["kind"] == "yanked"}
    for item in yanked:
        package = item["package"]
        key = ("yanked", "", package["name"], package["version"], package["source"])
        if key not in seen:
            report.setdefault("warnings", {}).setdefault("yanked", []).append(item)
            seen.add(key)


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
        "--audit-exit-status",
        type=int,
        default=0,
        help="cargo-audit exit status to assume alongside --audit-json (tests)",
    )
    parser.add_argument(
        "--today",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        help="policy evaluation date (YYYY-MM-DD; intended for tests)",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("."),
        help="repository root whose exception reachability premises must be verified",
    )
    parser.add_argument(
        "--dependency-tree",
        type=Path,
        help="read a saved cargo-tree result instead of invoking cargo tree (tests)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = args.source_root.resolve()
    ignored = ignored_candidate_cargo_inputs(source_root)
    if ignored:
        print(
            "cargo runs outside the candidate tree; ignoring candidate cargo and "
            f"toolchain configuration: {', '.join(ignored)}"
        )
    try:
        with candidate_snapshot(source_root) as snapshot:
            policy = load_policy(args.policy, args.today)
            verify_exception_reachability(policy, snapshot, args.dependency_tree)
            if args.audit_json:
                report = json.loads(args.audit_json.read_text(encoding="utf-8"))
                audit_status = args.audit_exit_status
            else:
                report, audit_status = run_cargo_audit(snapshot)
            audit_findings = collect_findings(report)
            if audit_status == 1 and not audit_findings:
                raise PolicyError("cargo audit reported findings this gate could not parse")
            if audit_status not in (0, 1):
                raise PolicyError(f"cargo audit failed operationally with exit {audit_status}")
            yanked, checked_packages = scan_yanked_packages(snapshot.lockfile)
            merge_yanked_findings(report, yanked)
            reviewed, blocked, stale, informational = evaluate(report, policy)
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(f"cargo-audit policy error: {exc}", file=sys.stderr)
        return 2

    print(
        f"yanked scan complete: {checked_packages} crates.io package version(s), "
        f"{len(yanked)} yanked"
    )
    for annotation in review_deadline_warnings(policy, args.today):
        print(annotation)

    for finding in reviewed:
        exception = policy[_finding_key(finding)]
        print(
            f"REVIEWED until {exception['review_by']} by {exception['owner']}: "
            f"{_format_finding(finding)}"
        )
    for finding in informational:
        advisory = finding.get("advisory") or "no advisory id"
        print(
            f"::warning::cargo-audit {finding['kind']} {advisory} affects "
            f"{finding['package']} {finding['version']} (reported, not blocking)"
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

    print(
        f"cargo-audit policy passed: {len(reviewed)} reviewed exception(s), "
        f"{len(informational)} non-blocking advisory warning(s), "
        "no unreviewed vulnerability/unsound/yanked findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
