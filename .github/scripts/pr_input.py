#!/usr/bin/env python3
"""Prepare and verify the declarative input used by trusted PR live review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

MANIFEST_NAME = ".gitforgeops-input-manifest.json"
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_FILES = 5_000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_CHANGED_PATHS = 10_000
MAX_LIVE_REVIEW_TARGETS = 256
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
class InputError(RuntimeError):
    pass


def _validate_sha(head_sha: str) -> str:
    normalized = head_sha.strip().lower()
    if not SHA_RE.fullmatch(normalized):
        raise InputError("expected PR head SHA to be exactly 40 hexadecimal characters")
    return normalized


def _normalize_member_name(name: str) -> tuple[str, str]:
    if not name or "\0" in name or "\\" in name or name.startswith("/"):
        raise InputError(f"unsafe archive path: {name!r}")
    raw_parts = name.rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise InputError(f"unsafe archive path: {name!r}")
    if len(raw_parts) < 2:
        return raw_parts[0], ""
    relative = str(PurePosixPath(*raw_parts[1:]))
    return raw_parts[0], relative


def _is_allowed_file(relative: str) -> bool:
    path = PurePosixPath(relative)
    return (
        len(path.parts) >= 3
        and path.parts[0] in {"resources", "overlays"}
        and path.suffix in {".yaml", ".yml"}
    )


def _is_protected_area(relative: str) -> bool:
    if not relative:
        return False
    first = PurePosixPath(relative).parts[0]
    return first in {"resources", "overlays", ".gitforgeops"}


def _prepare_output(output: Path) -> None:
    if output.exists() or output.is_symlink():
        if output.is_symlink() or not output.is_dir():
            raise InputError(f"output path must be a new or empty directory: {output}")
        if any(output.iterdir()):
            raise InputError(f"output directory is not empty: {output}")
    else:
        output.mkdir(parents=True, mode=0o700)


def _safe_write(output: Path, relative: str, data: bytes) -> None:
    destination = output.joinpath(*PurePosixPath(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def prepare(archive: Path, output: Path, head_sha: str) -> dict[str, object]:
    head_sha = _validate_sha(head_sha)
    archive_size = archive.stat().st_size
    if archive_size > MAX_ARCHIVE_BYTES:
        raise InputError(
            f"PR archive is {archive_size} bytes; limit is {MAX_ARCHIVE_BYTES}"
        )
    _prepare_output(output)

    root: str | None = None
    selected: dict[str, bytes] = {}
    selected_size = 0
    member_count = 0

    with tarfile.open(archive, mode="r:gz") as bundle:
        for member in bundle:
            member_count += 1
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise InputError(
                    f"PR archive contains more than {MAX_ARCHIVE_MEMBERS} entries"
                )
            member_root, relative = _normalize_member_name(member.name)
            if root is None:
                root = member_root
            elif root != member_root:
                raise InputError("PR archive contains more than one top-level root")

            if not relative:
                if not member.isdir():
                    raise InputError("PR archive root must be a directory")
                continue

            protected = _is_protected_area(relative)
            if member.issym() or member.islnk():
                if protected:
                    raise InputError(f"links are forbidden in declarative input: {relative}")
                continue
            if protected and not (member.isdir() or member.isfile()):
                raise InputError(
                    f"special files are forbidden in declarative input: {relative}"
                )
            if not _is_allowed_file(relative):
                continue
            if not member.isfile():
                raise InputError(f"expected a regular declarative file: {relative}")
            if member.mode & 0o111:
                raise InputError(f"executable declarative file is forbidden: {relative}")
            if member.size > MAX_FILE_BYTES:
                raise InputError(
                    f"declarative file exceeds {MAX_FILE_BYTES} bytes: {relative}"
                )
            if relative in selected:
                raise InputError(f"duplicate declarative path in PR archive: {relative}")
            if len(selected) >= MAX_FILES:
                raise InputError(f"declarative input exceeds {MAX_FILES} files")
            selected_size += member.size
            if selected_size > MAX_TOTAL_BYTES:
                raise InputError(
                    f"declarative input exceeds {MAX_TOTAL_BYTES} total bytes"
                )
            stream = bundle.extractfile(member)
            if stream is None:
                raise InputError(f"could not read declarative file: {relative}")
            data = stream.read(MAX_FILE_BYTES + 1)
            if len(data) != member.size:
                raise InputError(f"archive size mismatch for declarative file: {relative}")
            selected[relative] = data

    entries: list[dict[str, object]] = []
    for relative in sorted(selected):
        data = selected[relative]
        _safe_write(output, relative, data)
        entries.append(
            {
                "path": relative,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )

    manifest: dict[str, object] = {
        "schema_version": 1,
        "head_sha": head_sha,
        "limits": {
            "max_files": MAX_FILES,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
        },
        "files": entries,
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    _safe_write(output, MANIFEST_NAME, encoded)
    return manifest


def _walk_regular_files(root: Path) -> dict[str, Path]:
    observed: dict[str, Path] = {}

    def fail_walk(error: OSError) -> None:
        raise InputError(f"could not inspect review artifact: {error}") from error

    for directory, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=fail_walk
    ):
        directory_path = Path(directory)
        for dirname in dirnames:
            candidate = directory_path / dirname
            if candidate.is_symlink():
                raise InputError(f"symlinked directory in review artifact: {candidate}")
        for filename in filenames:
            candidate = directory_path / filename
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise InputError(f"non-regular file in review artifact: {candidate}")
            relative = candidate.relative_to(root).as_posix()
            if relative in observed:
                raise InputError(f"duplicate review artifact path: {relative}")
            observed[relative] = candidate
    return observed


def verify(root: Path, expected_head_sha: str) -> dict[str, object]:
    expected_head_sha = _validate_sha(expected_head_sha)
    if root.is_symlink() or not root.is_dir():
        raise InputError(f"review artifact root must be a real directory: {root}")
    observed = _walk_regular_files(root)
    manifest_path = observed.pop(MANIFEST_NAME, None)
    if manifest_path is None:
        raise InputError(f"review artifact is missing {MANIFEST_NAME}")
    if manifest_path.stat().st_size > MAX_FILE_BYTES:
        raise InputError("review artifact manifest is unreasonably large")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputError(f"invalid review artifact manifest: {error}") from error

    if manifest.get("schema_version") != 1:
        raise InputError("unsupported review artifact manifest schema")
    if manifest.get("head_sha") != expected_head_sha:
        raise InputError("review artifact head SHA does not match workflow_run")
    entries = manifest.get("files")
    if not isinstance(entries, list) or len(entries) > MAX_FILES:
        raise InputError("review artifact manifest has an invalid file list")

    declared: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise InputError("review artifact manifest entry must be an object")
        relative = entry.get("path")
        if not isinstance(relative, str) or not _is_allowed_file(relative):
            raise InputError(f"unexpected path in review artifact manifest: {relative!r}")
        if relative in declared:
            raise InputError(f"duplicate path in review artifact manifest: {relative}")
        declared[relative] = entry

    if set(observed) != set(declared):
        unexpected = sorted(set(observed) - set(declared))
        missing = sorted(set(declared) - set(observed))
        raise InputError(
            f"review artifact path set differs from manifest; "
            f"unexpected={unexpected}, missing={missing}"
        )

    total_size = 0
    for relative, path in observed.items():
        metadata = path.stat()
        if metadata.st_mode & 0o111:
            raise InputError(f"executable file in review artifact: {relative}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise InputError(f"oversized file in review artifact: {relative}")
        total_size += metadata.st_size
        if total_size > MAX_TOTAL_BYTES:
            raise InputError("review artifact exceeds the total size limit")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entry = declared[relative]
        if entry.get("size") != metadata.st_size or entry.get("sha256") != digest:
            raise InputError(f"review artifact integrity mismatch: {relative}")

    return manifest


def _touched_namespaces(changed_paths_file: Path) -> set[str]:
    try:
        changed_paths = json.loads(changed_paths_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputError(f"invalid trusted changed-path list: {error}") from error
    if not isinstance(changed_paths, list) or len(changed_paths) > MAX_CHANGED_PATHS:
        raise InputError("trusted changed paths must be a bounded array")

    namespaces: set[str] = set()
    for raw_path in changed_paths:
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or "\0" in raw_path
            or "\\" in raw_path
            or raw_path.startswith("/")
        ):
            raise InputError("trusted changed path must be a safe repository-relative string")
        raw_parts = raw_path.split("/")
        if any(part in {"", ".", ".."} for part in raw_parts):
            raise InputError(f"unsafe trusted changed path: {raw_path!r}")
        parts = PurePosixPath(raw_path).parts
        if PurePosixPath(raw_path).suffix not in {".yaml", ".yml"}:
            continue
        if parts[0] == "resources":
            if len(parts) < 3:
                continue
            if not SAFE_COMPONENT_RE.fullmatch(parts[1]):
                continue
            namespaces.add(parts[1])
        elif parts[0] == "overlays":
            if len(parts) < 4:
                continue
            if not SAFE_COMPONENT_RE.fullmatch(
                parts[1]
            ) or not SAFE_COMPONENT_RE.fullmatch(parts[2]):
                continue
            namespaces.add(parts[2])
        elif parts[0] != ".gitforgeops":
            raise InputError(f"non-declarative trusted changed path: {raw_path!r}")
    return namespaces


def trusted_targets(
    root: Path, environment_scopes_json: str, changed_paths_file: Path
) -> list[dict[str, str]]:
    """Build the live-review matrix from protected scopes and touched namespaces."""
    try:
        scopes = json.loads(environment_scopes_json)
    except json.JSONDecodeError as error:
        raise InputError(f"invalid trusted environment scope list: {error}") from error
    if not isinstance(scopes, list):
        raise InputError("trusted environment scopes must be an array")

    normalized_scopes: list[tuple[str, set[str] | None]] = []
    seen_environments: set[str] = set()
    for scope in scopes:
        if not isinstance(scope, dict) or set(scope) != {
            "environment",
            "live_review",
            "namespaces",
        }:
            raise InputError(
                "trusted environment scope must contain only environment, live_review, and namespaces"
            )
        environment = scope.get("environment")
        live_review = scope.get("live_review")
        namespaces = scope.get("namespaces")
        if not isinstance(environment, str) or not SAFE_COMPONENT_RE.fullmatch(
            environment
        ):
            raise InputError("trusted environment name must be a safe path component")
        if environment in seen_environments:
            raise InputError(f"duplicate trusted environment scope: {environment}")
        seen_environments.add(environment)
        if not isinstance(live_review, bool):
            raise InputError(
                f"trusted live_review flag for {environment!r} must be a boolean"
            )
        if not live_review:
            continue
        if namespaces is not None and (
            not isinstance(namespaces, list)
            or not all(
                isinstance(namespace, str)
                and SAFE_COMPONENT_RE.fullmatch(namespace)
                for namespace in namespaces
            )
        ):
            raise InputError(
                f"trusted namespace scope for {environment!r} must be null or safe strings"
            )
        normalized_scopes.append(
            (environment, None if namespaces is None else set(namespaces))
        )

    touched_namespaces = _touched_namespaces(changed_paths_file)
    resources = root / "resources"
    namespaces: list[str] = []
    if resources.exists() or resources.is_symlink():
        if resources.is_symlink() or not resources.is_dir():
            raise InputError("trusted resources root must be a real directory")
        for entry in resources.iterdir():
            if entry.is_symlink():
                raise InputError(f"trusted namespace path may not be a symlink: {entry}")
            if not entry.is_dir():
                continue
            if not SAFE_COMPONENT_RE.fullmatch(entry.name):
                print(
                    f"Ignoring non-targetable trusted namespace directory: {entry.name!r}",
                    file=sys.stderr,
                )
                continue
            if entry.name in touched_namespaces:
                namespaces.append(entry.name)

    targets = []
    for environment, allowed in sorted(normalized_scopes):
        for namespace in sorted(set(namespaces)):
            if allowed is None or namespace in allowed:
                targets.append({"environment": environment, "namespace": namespace})
                if len(targets) > MAX_LIVE_REVIEW_TARGETS:
                    raise InputError(
                        "live-review scope exceeds GitHub's 256-job matrix limit; "
                        "split the pull request into smaller namespace groups"
                    )
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("archive", type=Path)
    prepare_parser.add_argument("output", type=Path)
    prepare_parser.add_argument("head_sha")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("root", type=Path)
    verify_parser.add_argument("head_sha")
    targets_parser = subparsers.add_parser("targets")
    targets_parser.add_argument("root", type=Path)
    targets_parser.add_argument("environments_json")
    targets_parser.add_argument("changed_paths", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args.archive, args.output, args.head_sha)
            print(
                f"Prepared {len(result['files'])} declarative files for {result['head_sha']}."
            )
        elif args.command == "verify":
            result = verify(args.root, args.head_sha)
            print(
                f"Verified {len(result['files'])} declarative files for {result['head_sha']}."
            )
        else:
            print(
                json.dumps(
                    trusted_targets(
                        args.root, args.environments_json, args.changed_paths
                    ),
                    separators=(",", ":"),
                )
            )
    except (InputError, OSError, tarfile.TarError) as error:
        print(f"pr-input error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
