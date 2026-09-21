#!/usr/bin/env python3
"""A deliberately boring upstream for the lifecycle suite.

`/status/<code>` answers with that code and `/echo` answers 200 with an empty
body. Standard library only, so the harness needs no container registry, no
pull, and no second supply-chain surface to pin — the only external artifact
the suite trusts is the gateway binary the allowlisted installer already
verifies by digest.

It never echoes a request header. A proxied credential arriving here and being
reflected into a log is precisely the accident the suite must not have.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        status = 200
        if self.path.startswith("/status/"):
            try:
                status = int(self.path.rsplit("/", 1)[1])
            except ValueError:
                status = 400
            if not 100 <= status <= 599:
                status = 400
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args) -> None:
        """Silence. The default logger prints the request line, and a bad
        proxy configuration can put a credential in a query string."""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if args.port_file:
        with open(args.port_file, "w", encoding="utf-8") as handle:
            handle.write(str(server.server_address[1]))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
