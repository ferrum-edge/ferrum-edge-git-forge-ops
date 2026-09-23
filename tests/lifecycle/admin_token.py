#!/usr/bin/env python3
"""Mint an admin JWT for the lifecycle harness's own out-of-band edits.

Several scenarios need a *human admin* acting on the gateway directly: an
unmanaged row shared mode must not delete, a row edited behind the
repository's back so drift has something to find. Those edits must not come
from `gitforgeops`, or the scenario would be testing the tool against itself.

Standard library only, and deliberately minimal: it mints exactly the claims
`src/jwt.rs` documents, for a loopback gateway, from a secret that exists only
for the duration of one run.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time
import uuid


def segment(payload: dict) -> bytes:
    return base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--issuer", default="ferrum-edge")
    parser.add_argument("--role", default="admin")
    parser.add_argument("--subject", default="gitforgeops-lifecycle")
    parser.add_argument("--ttl", type=int, default=3600)
    args = parser.parse_args()

    now = int(time.time())
    signing_input = b".".join(
        (
            segment({"alg": "HS256", "typ": "JWT"}),
            segment(
                {
                    # The same claim set `src/jwt.rs` mints. A token missing
                    # `sub`, `nbf` or `jti` is rejected, and the rejection is
                    # a plain 401 that looks exactly like a wrong secret.
                    "iss": args.issuer,
                    "sub": args.subject,
                    "role": args.role,
                    "iat": now,
                    "nbf": now,
                    "exp": now + args.ttl,
                    "jti": uuid.uuid4().hex,
                }
            ),
        )
    )
    signature = base64.urlsafe_b64encode(
        hmac.new(args.secret.encode(), signing_input, hashlib.sha256).digest()
    ).rstrip(b"=")
    print((signing_input + b"." + signature).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
