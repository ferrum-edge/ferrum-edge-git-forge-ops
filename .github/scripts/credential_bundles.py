#!/usr/bin/env python3
"""Collect the enumerated credential-bundle secrets into a private runner file.

The privileged workflows bind every `FERRUM_CREDS_BUNDLE[_N]` Environment
Secret to an environment variable of the same name. They deliberately do NOT
use `${{ toJSON(secrets) }}`: that hands the step the admin JWT signing key,
the state-writer App private key and the registry token as well, and since
GitHub's 2026-07-28 change a public-repository run that reads the whole secrets
context is held for manual approval.

Because the bindings are written out by hand, the number of shards is fixed.
`MAX_BUNDLE_SHARDS` below must stay equal to `MAX_BUNDLE_SHARDS` in
`src/secrets/bundle.rs`, and both must match the bindings in the four
privileged workflows; `.github/scripts/check_supply_chain.py` fails the build
when they drift.

Contract kept from the previous secrets-dump loader: a blank value means the
secret is unset, malformed JSON fails closed rather than degrading to an empty
bundle (which would make the binary re-allocate slots that already exist), the
destination is a fresh mode-0600 file, and no secret bytes reach the log.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path


BUNDLE_SECRET_PREFIX = "FERRUM_CREDS_BUNDLE"

# Keep in lockstep with MAX_BUNDLE_SHARDS in src/secrets/bundle.rs and with the
# FERRUM_CREDS_BUNDLE_<N> env bindings in the privileged workflows.
MAX_BUNDLE_SHARDS = 100

BUNDLE_NAME = re.compile(rf"^{BUNDLE_SECRET_PREFIX}(?:_[0-9]+)?$")


class BundleError(RuntimeError):
    pass


def bundle_names() -> list[str]:
    """The exact secret names the workflows bind, in shard order."""
    return [BUNDLE_SECRET_PREFIX] + [
        f"{BUNDLE_SECRET_PREFIX}_{shard}" for shard in range(1, MAX_BUNDLE_SHARDS)
    ]


def extract(environ: Mapping[str, str], destination: Path) -> int:
    expected = bundle_names()
    bound = set(expected)

    bundles: dict[str, str] = {}
    slot_count = 0
    for name in expected:
        encoded = environ.get(name, "")
        if not isinstance(encoded, str) or not encoded.strip():
            continue
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

    # A populated bundle secret nobody binds would be silently dropped here,
    # and the binary would then re-allocate every slot it holds. Fail instead,
    # naming the ceiling that has to move.
    for name, value in environ.items():
        if name in bound or not name.startswith(BUNDLE_SECRET_PREFIX):
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        if BUNDLE_NAME.fullmatch(name):
            raise BundleError(
                f"{name} is populated but outside the bound shard range: raise "
                f"MAX_BUNDLE_SHARDS (currently {MAX_BUNDLE_SHARDS}) here, in "
                "src/secrets/bundle.rs, and in the privileged workflow bindings together"
            )
        raise BundleError(f"invalid reserved credential-bundle secret name: {name!r}")

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
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        slot_count = extract(os.environ, args.destination)
    except (BundleError, OSError) as error:
        print(f"credential bundle extraction failed: {error}", file=sys.stderr)
        return 1
    print(f"Loaded {slot_count} credential slot(s) into a private runner file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
