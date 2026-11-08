#!/usr/bin/env python3
"""Resolve one merged pull request for an apply-triggering main commit."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}|[A-Za-z0-9-]{0,33}\[bot\])$")
# A PR number is a JSON integer in 1..=u64::MAX. `bool` is excluded explicitly
# (it subclasses `int`), so this matches the Rust copy of the rule
# (`github_override::select_merged_pr`, which reads it with `as_u64`).
MAX_PR_NUMBER = 2**64 - 1


def is_pr_number(value: Any) -> bool:
    return type(value) is int and 0 < value <= MAX_PR_NUMBER


class MergeContextError(RuntimeError):
    pass


def resolve(pages: Any, sha: str, base_branch: str) -> dict[str, object]:
    if not SHA_RE.fullmatch(sha):
        raise MergeContextError("push SHA must be 40 lowercase hexadecimal characters")
    if not base_branch or any(character in base_branch for character in "\r\n\0"):
        raise MergeContextError("base branch is invalid")
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise MergeContextError("associated pull requests must be an array of pages")

    candidates: list[dict[str, Any]] = []
    for item in (item for page in pages for item in page):
        if not isinstance(item, dict):
            raise MergeContextError("associated pull-request entry must be an object")
        base = item.get("base")
        user = item.get("user")
        if (
            item.get("state") == "closed"
            and isinstance(item.get("merged_at"), str)
            and isinstance(base, dict)
            and base.get("ref") == base_branch
            and is_pr_number(item.get("number"))
            and isinstance(user, dict)
            and isinstance(user.get("login"), str)
            and LOGIN_RE.fullmatch(user["login"])
        ):
            candidates.append(item)

    exact = [item for item in candidates if item.get("merge_commit_sha") == sha]
    selected = exact if exact else candidates
    if len(selected) != 1:
        raise MergeContextError(
            "expected exactly one merged pull request for "
            f"{sha} on {base_branch!r}; found {len(selected)}"
        )
    item = selected[0]
    return {"number": item["number"], "author": item["user"]["login"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pages", type=Path)
    parser.add_argument("sha")
    parser.add_argument("base_branch")
    args = parser.parse_args()
    try:
        pages = json.loads(args.pages.read_text(encoding="utf-8"))
        print(json.dumps(resolve(pages, args.sha, args.base_branch), sort_keys=True))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        MergeContextError,
    ) as error:
        print(f"merge-context resolution failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
