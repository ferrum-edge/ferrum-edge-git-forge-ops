#!/usr/bin/env python3
"""A fault-injecting reverse proxy for the admin API, for the lifecycle suite.

`partial-failure-recovery` asks whether the apply safeguards hold when the
admin API misbehaves: a write refused before it commits, a write that commits
and then answers 500, a connection dropped after the commit, a `/backup`
flagged `X-Data-Source: cached`. A real gateway does none of those on demand,
so this proxy sits between `gitforgeops` and the real gateway and does them
for exactly the requests a scenario names. Everything else is forwarded
unchanged, so every other answer is the real gateway's.

Standard library only, loopback only, and silent: it never logs a request
line or a header, because the requests it forwards carry the admin bearer
token. A fault that never fired is a scenario that certified nothing, so every
fault counts its hits and the scenario asserts them.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

# Refuse the request without forwarding it: nothing reaches the gateway.
REJECT = "reject"
# Forward it, let the gateway commit, then answer 500 instead of its response.
COMMIT_THEN_500 = "commit_then_500"
# Forward it, let the gateway commit, then close the connection unanswered.
COMMIT_THEN_DROP = "commit_then_drop"
# Forward it and return the gateway's answer flagged `X-Data-Source: cached`.
MARK_CACHED = "mark_cached"
ACTIONS = (REJECT, COMMIT_THEN_500, COMMIT_THEN_DROP, MARK_CACHED)

# Hop-by-hop headers are the proxy's own business, never forwarded.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

# An error envelope the client parses. A body that does not parse is treated
# as possibly concealing `applied:false` and is never retried, which would
# exercise a narrower path than a gateway's real 500 does.
_INJECTED_500 = b'{"error":"injected by the lifecycle fault proxy"}'


@dataclass
class Fault:
    """One misbehavior, for requests matching `method` and the `path` regex.

    `path` is matched (fullmatch) against the request path without its query.
    `times` bounds how many matching requests it applies to; `None` is every
    one. `after_commit` runs after the gateway answered and before the
    injected response, standing in for another writer racing the client.
    """

    method: str
    path: str
    action: str
    times: int | None = 1
    after_commit: Callable[[], None] | None = None
    hits: int = 0
    statuses: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown fault action {self.action!r}")
        self._pattern = re.compile(self.path)

    def matches(self, method: str, path: str) -> bool:
        if method != self.method or not self._pattern.fullmatch(path):
            return False
        return self.times is None or self.hits < self.times


def _loopback_http(target: str) -> tuple[str, int]:
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme != "http" or not parsed.hostname or parsed.port is None:
        raise ValueError("the fault proxy fronts only http:// to a literal loopback IP")
    if not ipaddress.ip_address(parsed.hostname).is_loopback:
        raise ValueError("the fault proxy fronts only http:// to a literal loopback IP")
    return parsed.hostname, parsed.port


class FaultProxy:
    """Run as a context manager; `url` is the admin URL to hand gitforgeops."""

    def __init__(self, target: str):
        self._target = _loopback_http(target)
        self._faults: list[Fault] = []
        self._lock = threading.Lock()
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            # One request per connection: a dropped connection can then never
            # be mistaken by the client for a stale pooled one it may replay.
            protocol_version = "HTTP/1.0"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                path = urllib.parse.urlsplit(self.path).path
                fault = proxy._claim(self.command, path)
                if fault is not None and fault.action == REJECT:
                    fault.statuses.append(500)
                    self._reply(500, [("Content-Type", "application/json")], _INJECTED_500)
                    return
                status, headers, payload = proxy._forward(
                    self.command, self.path, self.headers, body
                )
                if fault is None:
                    self._reply(status, headers, payload)
                    return
                fault.statuses.append(status)
                if fault.after_commit is not None:
                    fault.after_commit()
                if fault.action == COMMIT_THEN_500:
                    self._reply(500, [("Content-Type", "application/json")], _INJECTED_500)
                elif fault.action == COMMIT_THEN_DROP:
                    # Nothing written: the client sees the connection close
                    # before any response, after the gateway committed.
                    self.close_connection = True
                elif fault.action == MARK_CACHED:
                    kept = [(k, v) for k, v in headers if k.lower() != "x-data-source"]
                    self._reply(status, [*kept, ("X-Data-Source", "cached")], payload)

            def _reply(self, status: int, headers, payload: bytes) -> None:
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle  # noqa: N815

            def log_message(self, *_args) -> None:
                """Silence. Forwarded requests carry the admin bearer token."""

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def inject(self, fault: Fault) -> Fault:
        with self._lock:
            self._faults.append(fault)
        return fault

    def clear(self) -> None:
        with self._lock:
            self._faults.clear()

    def _claim(self, method: str, path: str) -> Fault | None:
        with self._lock:
            for fault in self._faults:
                if fault.matches(method, path):
                    fault.hits += 1
                    return fault
        return None

    def _forward(self, method: str, target: str, headers, body: bytes | None):
        host, port = self._target
        connection = http.client.HTTPConnection(host, port, timeout=30)
        try:
            forwarded = {
                name: value for name, value in headers.items() if name.lower() not in _HOP_BY_HOP
            }
            connection.request(method, target, body=body, headers=forwarded)
            response = connection.getresponse()
            payload = response.read()
            kept = [
                (name, value)
                for name, value in response.getheaders()
                if name.lower() not in _HOP_BY_HOP
            ]
            return response.status, kept, payload
        finally:
            connection.close()

    def __enter__(self) -> "FaultProxy":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
