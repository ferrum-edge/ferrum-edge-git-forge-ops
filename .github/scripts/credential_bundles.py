#!/usr/bin/env python3
"""Extract and validate GitHub Environment credential bundle secrets."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


BUNDLE_NAME = re.compile(r"^FERRUM_CREDS_BUNDLE(?:_[1-9][0-9]*)?$")


class BundleError(RuntimeError):
    pass


def extract(source: Path, destination: Path) -> int:
    try:
        all_secrets = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError("GitHub secret inventory is not valid JSON") from error
    if not isinstance(all_secrets, dict):
        raise BundleError("GitHub secret inventory must be a JSON object")

    bundles: dict[str, str] = {}
    slot_count = 0
    for name, encoded in all_secrets.items():
        if not isinstance(name, str) or not name.startswith("FERRUM_CREDS_BUNDLE"):
            continue
        if not BUNDLE_NAME.fullmatch(name):
            raise BundleError(f"invalid reserved credential-bundle secret name: {name!r}")
        if not isinstance(encoded, str):
            raise BundleError(f"credential bundle {name} must be stored as a JSON string")
        try:
            bundle = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise BundleError(f"credential bundle {name} is not valid JSON") from error
        if not isinstance(bundle, dict) or not all(
            isinstance(slot, str) and isinstance(value, str)
            for slot, value in bundle.items()
        ):
            raise BundleError(f"credential bundle {name} must map string slots to strings")
        bundles[name] = encoded
        slot_count += len(bundle)

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(bundles, sort_keys=True, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    return slot_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        slot_count = extract(args.source, args.destination)
    except (BundleError, OSError) as error:
        print(f"credential bundle extraction failed: {error}", file=sys.stderr)
        return 1
    print(f"Loaded {slot_count} credential slot(s) into a private runner file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
