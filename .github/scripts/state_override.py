#!/usr/bin/env python3
"""Resolve the latest effective state-override label event fail-closed."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_EVENTS = 10_000
SUFFICIENT_PERMISSIONS = {"write", "maintain", "admin"}
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}|[A-Za-z0-9-]{0,33}\[bot\])$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class OverrideError(RuntimeError):
    pass


def permission_is_sufficient(permission: str) -> bool:
    return permission in SUFFICIENT_PERMISSIONS


def resolve_effective_event(
    pages: Any, label: str, expected_head_sha: str | None = None
) -> dict[str, Any]:
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise OverrideError("paginated issue events must be an array of pages")
    events = [event for page in pages for event in page]
    if len(events) > MAX_EVENTS:
        raise OverrideError(f"PR timeline exceeds the {MAX_EVENTS:,}-event audit bound")

    if expected_head_sha is not None and not SHA_RE.fullmatch(expected_head_sha):
        raise OverrideError("expected PR head must be a 40-character lowercase SHA")

    relevant: list[dict[str, Any]] = []
    head_index: int | None = None
    last_commit_sha: str | None = None
    head_change_indexes: list[int] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise OverrideError("issue event must be an object")
        action = event.get("event")
        if expected_head_sha is not None and action == "committed":
            sha = event.get("sha")
            if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
                raise OverrideError("committed timeline event has an invalid SHA")
            last_commit_sha = sha
            head_change_indexes.append(index)
            if sha == expected_head_sha:
                head_index = index
        elif expected_head_sha is not None and action == "head_ref_force_pushed":
            head_change_indexes.append(index)
        if action not in {"labeled", "unlabeled"}:
            continue
        event_label = event.get("label")
        if not isinstance(event_label, dict) or event_label.get("name") != label:
            continue
        if not isinstance(event.get("id"), int) or not isinstance(
            event.get("created_at"), str
        ):
            raise OverrideError("override event is missing sortable audit metadata")
        relevant.append({**event, "_timeline_index": index})

    relevant.sort(key=lambda event: (event["created_at"], event["id"]))
    effective: dict[str, Any] | None = None
    for event in relevant:
        effective = event if event["event"] == "labeled" else None
    if effective is None:
        raise OverrideError("no effective exact-label event could be attributed")

    if expected_head_sha is not None:
        if head_index is None or last_commit_sha != expected_head_sha:
            raise OverrideError("current PR head is not the latest committed timeline event")
        label_index = effective["_timeline_index"]
        if label_index <= head_index or any(
            index > label_index for index in head_change_indexes
        ):
            raise OverrideError(
                "state override label predates the current PR head; remove and reapply it"
            )

    actor = effective.get("actor")
    login = actor.get("login") if isinstance(actor, dict) else None
    if not isinstance(login, str) or not LOGIN_RE.fullmatch(login):
        raise OverrideError("effective label event has a missing/deleted actor")
    return {
        "actor": login,
        "event_id": effective["id"],
        "labeled_at": effective["created_at"],
        **({"head_sha": expected_head_sha} if expected_head_sha is not None else {}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("label")
    parser.add_argument("expected_head_sha")
    args = parser.parse_args()
    try:
        pages = json.loads(args.events.read_text(encoding="utf-8"))
        print(
            json.dumps(
                resolve_effective_event(pages, args.label, args.expected_head_sha),
                sort_keys=True,
            )
        )
    except (OSError, json.JSONDecodeError, OverrideError) as error:
        print(f"state override resolution failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
