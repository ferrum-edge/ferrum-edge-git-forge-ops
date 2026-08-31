#!/usr/bin/env python3
"""Resolve the latest effective state-override label event fail-closed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


MAX_EVENTS = 10_000
SUFFICIENT_PERMISSIONS = {"write", "maintain", "admin"}


class OverrideError(RuntimeError):
    pass


def permission_is_sufficient(permission: str) -> bool:
    return permission in SUFFICIENT_PERMISSIONS


def resolve_effective_event(pages: Any, label: str) -> dict[str, Any]:
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise OverrideError("paginated issue events must be an array of pages")
    events = [event for page in pages for event in page]
    if len(events) > MAX_EVENTS:
        raise OverrideError(f"PR timeline exceeds the {MAX_EVENTS:,}-event audit bound")

    relevant: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            raise OverrideError("issue event must be an object")
        if event.get("event") not in {"labeled", "unlabeled"}:
            continue
        event_label = event.get("label")
        if not isinstance(event_label, dict) or event_label.get("name") != label:
            continue
        if not isinstance(event.get("id"), int) or not isinstance(
            event.get("created_at"), str
        ):
            raise OverrideError("override event is missing sortable audit metadata")
        relevant.append(event)

    relevant.sort(key=lambda event: (event["created_at"], event["id"]))
    effective: dict[str, Any] | None = None
    for event in relevant:
        effective = event if event["event"] == "labeled" else None
    if effective is None:
        raise OverrideError("no effective exact-label event could be attributed")

    actor = effective.get("actor")
    login = actor.get("login") if isinstance(actor, dict) else None
    if not isinstance(login, str) or not login:
        raise OverrideError("effective label event has a missing/deleted actor")
    return {
        "actor": login,
        "event_id": effective["id"],
        "labeled_at": effective["created_at"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("label")
    args = parser.parse_args()
    try:
        pages = json.loads(args.events.read_text(encoding="utf-8"))
        print(json.dumps(resolve_effective_event(pages, args.label), sort_keys=True))
    except (OSError, json.JSONDecodeError, OverrideError) as error:
        print(f"state override resolution failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
