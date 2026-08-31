#!/usr/bin/env python3
"""Classify paginated pull-request file metadata without rename blind spots."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PATTERNS = {
    "rust": re.compile(
        r"^(?:src/|tests/|benches/|examples/|\.cargo/|build\.rs$|"
        r"(?:.*/)?Cargo\.(?:toml|lock)$|Dockerfile$|"
        r"rust-toolchain(?:\.toml)?$|(?:\.?(?:rustfmt|clippy)\.toml)$|"
        r"\.github/workflows/rust-ci\.yml$)"
    ),
    "declarative": re.compile(r"^(?:resources/|overlays/|\.gitforgeops/)"),
    "state": re.compile(r"^\.state/"),
}


class ChangedFilesError(RuntimeError):
    pass


def analyze(pages: Any, declared_count: int, area: str) -> dict[str, object]:
    if area not in PATTERNS:
        raise ChangedFilesError(f"unknown changed-file area: {area!r}")
    if declared_count < 0:
        raise ChangedFilesError("declared changed-file count must not be negative")
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise ChangedFilesError("paginated pull-request files must be an array of pages")

    records = [record for page in pages for record in page]
    paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("filename"), str):
            raise ChangedFilesError("pull-request file entry is missing a filename")
        paths.add(record["filename"])
        previous = record.get("previous_filename")
        if previous is not None:
            if not isinstance(previous, str):
                raise ChangedFilesError("previous_filename must be a string when present")
            paths.add(previous)

    matched = sorted(path for path in paths if PATTERNS[area].search(path))
    observed_count = len(records)
    return {
        "area": area,
        "declared_count": declared_count,
        "observed_count": observed_count,
        "complete": observed_count == declared_count,
        "matches": bool(matched),
        "matched_paths": matched,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pages", type=Path)
    parser.add_argument("declared_count", type=int)
    parser.add_argument("area", choices=sorted(PATTERNS))
    args = parser.parse_args()
    try:
        pages = json.loads(args.pages.read_text(encoding="utf-8"))
        print(json.dumps(analyze(pages, args.declared_count, args.area), sort_keys=True))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ChangedFilesError,
    ) as error:
        print(f"changed-file classification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
