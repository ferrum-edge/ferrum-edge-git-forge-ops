#!/usr/bin/env python3
"""Drive the customer lifecycle against a real gateway.

This is the half of the acceptance suite that unit tests cannot be: it starts
from a repository tree, runs the actual `gitforgeops` binary against an actual
Ferrum Edge admin API, and sends actual HTTP traffic through the routes it
created. Mocks prove the code does what the code says; this proves the product
does what the README says.

Two rules shape it.

**Nothing is inferred from an absence.** Every scenario ends by writing an
explicit `passed` / `failed` / `skipped` into the result record. A scenario
that raises leaves `failed` with its reason, and a scenario that never runs
keeps `not_run` from `lifecycle_result.py init`. The release gate reads that
record, and `skipped` never certifies anything.

**Evidence is redacted at the point of capture.** A failing lifecycle run is
the single most likely place for a live credential to reach a log: the values
are real, the gateway echoes request context, and the natural instinct is to
dump everything. `redact()` runs over every captured stream before it is
stored, keyed on the secrets this run actually created.

Run it through `run.sh`, which owns starting the gateway and the test upstream.
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / ".github" / "scripts"))
import lifecycle_result  # noqa: E402  (path set above)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fault_proxy  # noqa: E402  (path set above)


NAMESPACE = "ferrum"
ENVIRONMENT = "acceptance"
ROOT = Path(__file__).resolve().parents[2]
# The smallest MeshConfig `ferrum-edge validate -m mesh` accepts, shared with
# the unit suite so the two cannot disagree about what a legal fragment is.
MESH_FIXTURE = ROOT / "tests/fixtures/mesh-minimal/ferrum/mesh/minimal.yaml"


class ScenarioFailure(AssertionError):
    """A scenario's assertion did not hold."""


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        # The redirect handler parses Location/URI before redirect_request.
        # Keep every 3xx out of that handler, including malformed targets that
        # could reflect credentials in a parser exception. Return the original
        # status, headers and body without making another request.
        if 300 <= response.code < 400:
            return response
        return super().http_response(request, response)

    https_response = http_response


def _credential_target(target: str) -> str:
    """Check the exact URL before constructing a request with credentials."""
    message = (
        "lifecycle requests require https:// or http:// to a literal loopback "
        "IP (127.0.0.0/8 or [::1]), without embedded URL credentials; "
        "target withheld"
    )
    try:
        # urlsplit strips some controls; reject them before parsing so the
        # checked target cannot differ from the one the operator supplied.
        if any(ord(char) <= 32 or ord(char) == 127 for char in target):
            raise ValueError("control or whitespace in URL")
        parsed = urllib.parse.urlsplit(target)
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError("unusable URL")
        # Accessing port also rejects a malformed or out-of-range port.
        _ = parsed.port
        if parsed.scheme == "http":
            address = ipaddress.ip_address(parsed.hostname)
            # Keep the documented boundary stable across Python versions:
            # IPv4-mapped IPv6 loopback is not the permitted native ::1.
            if (
                "%" in parsed.hostname
                or not address.is_loopback
                or (address.version == 6 and address != ipaddress.IPv6Address("::1"))
            ):
                raise ValueError("non-loopback HTTP target")
        elif parsed.scheme != "https":
            raise ValueError("unsupported scheme")
    except ValueError:
        raise ScenarioFailure(message) from None
    return urllib.parse.urlunsplit(parsed)


def _safe_exchange(
    target: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
) -> tuple[int, str | None, str]:
    """The common admin and data-plane HTTP boundary, with no redirects."""
    target = _credential_target(target)
    # A proxy would turn literal-loopback cleartext into a remote credential
    # transmission. Use a fresh opener rather than urlopen's global opener.
    proxies = {} if urllib.parse.urlsplit(target).scheme == "http" else None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies), _NoRedirect())
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(target, data=data, method=method, headers=headers or {})
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            text = response.read().decode("utf-8", "replace")
            return response.code, response.headers.get("ETag"), text
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
        # Transport/parser errors can contain backend-controlled URLs or bytes.
        # Never expose their text or exception chain to scenario diagnostics.
        raise ScenarioFailure(
            "lifecycle HTTP exchange failed; target and backend details withheld"
        ) from None


class Harness:
    """Everything a scenario needs, and nothing it should not have."""

    def __init__(
        self,
        workdir: Path,
        gateway_url: str,
        proxy_url: str,
        upstream_url: str,
        binary: str,
        creds_file: str,
    ):
        self.workdir = workdir
        # The admin API. Writes configuration.
        self.gateway_url = _credential_target(gateway_url.rstrip("/"))
        # The data plane. Serves traffic. A different listener on a different
        # port — sending a route check at the admin API would get a 404 that
        # looks exactly like a routing failure.
        self.proxy_url = _credential_target(proxy_url.rstrip("/"))
        self.upstream_url = upstream_url.rstrip("/")
        self.binary = binary
        # The broker bundle the seeded `alloc=require` slot resolves from.
        # Passed in rather than inherited: `env()` strips every FERRUM_* it
        # did not set, so anything the child needs has to be supplied here.
        self.creds_file = creds_file
        # Every secret this run has seen, for `redact`. Populated as
        # credentials are allocated; never written to disk.
        self._secrets: set[str] = set()
        self.remember_secret(os.environ.get("GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN", ""))

    # -- redaction ---------------------------------------------------------

    def remember_secret(self, value: str) -> None:
        if value and len(value) >= 8:
            self._secrets.add(value)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        return text

    # -- running gitforgeops ----------------------------------------------

    def env(self, **overrides: str) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            # The child gets exactly what this harness gives it. An inherited
            # FERRUM_* from the operator's shell is how a "passing" run ends up
            # having tested a different gateway than the one it reports.
            if not key.startswith("FERRUM_") and not key.startswith("GITFORGEOPS_")
        }
        environment.update(
            {
                "FERRUM_ENV": ENVIRONMENT,
                "FERRUM_GATEWAY_MODE": "api",
                "FERRUM_GATEWAY_URL": self.gateway_url,
                "FERRUM_ADMIN_JWT_SECRET": os.environ["FERRUM_ADMIN_JWT_SECRET"],
                "FERRUM_VERIFY_BASE_URL": self.proxy_url,
                "FERRUM_CREDS_JSON_FILE": self.creds_file,
                # Loopback gateway: the CI/loopback gate permits cleartext here
                # and nowhere else.
                "FERRUM_ALLOW_INSECURE_HTTP": "true",
            }
        )
        environment.update(overrides)
        return environment

    def run(self, *args: str, expect: int | None = 0, **overrides: str):
        completed = subprocess.run(
            [self.binary, *args],
            cwd=str(self.workdir),
            env=self.env(**overrides),
            check=False,
            text=True,
            capture_output=True,
        )
        completed.stdout = self.redact(completed.stdout)
        completed.stderr = self.redact(completed.stderr)
        if expect is not None and completed.returncode != expect:
            raise ScenarioFailure(
                f"`gitforgeops {' '.join(args)}` exited {completed.returncode}, "
                f"expected {expect}\n--- stdout ---\n{completed.stdout}\n"
                f"--- stderr ---\n{completed.stderr}"
            )
        return completed

    # -- traffic -----------------------------------------------------------

    def request(self, path: str, headers: dict[str, str] | None = None) -> int:
        """A client request through the DATA plane."""
        status, _, _ = _safe_exchange(f"{self.proxy_url}{path}", headers=headers)
        return status

    def expect_status(self, path: str, status: int, headers=None, attempts: int = 10):
        """Poll until the route answers as expected, or fail with what it said.

        A freshly applied route takes a moment to become live, so this retries
        — boundedly. An unbounded wait turns a failing acceptance run into a
        hanging one, which is strictly worse: nobody gets a result at all.
        """
        seen = None
        for attempt in range(attempts):
            if attempt:
                time.sleep(0.5 * attempt)
            seen = self.request(path, headers)
            if seen == status:
                return
        raise ScenarioFailure(
            f"{path} answered {seen}, expected {status} after {attempts} attempts"
        )

    # -- repository tree ---------------------------------------------------

    def write(self, relative: str, contents: str) -> None:
        path = self.workdir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(contents).lstrip("\n"), encoding="utf-8")

    def remove(self, relative: str) -> None:
        (self.workdir / relative).unlink(missing_ok=True)

    def state(self) -> dict:
        path = self.workdir / ".state" / f"{ENVIRONMENT}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


# -- the repository the scenarios deploy ------------------------------------


def seed_repository(harness: Harness) -> None:
    """One gateway, one namespace, shared ownership — the quickstart profile."""
    harness.write(
        ".gitforgeops/config.yaml",
        """
        version: 1
        environments:
          acceptance:
            apply_strategy: incremental
            ownership:
              mode: shared
        default_environment: acceptance
        """,
    )
    harness.write(
        f"resources/{NAMESPACE}/upstreams/orders.yaml",
        f"""
        kind: Upstream
        spec:
          id: "orders-upstream"
          name: "Orders service"
          algorithm: round_robin
          targets:
            - host: "{harness.upstream_url.split('//')[1].split(':')[0]}"
              port: {harness.upstream_url.rsplit(':', 1)[1]}
              weight: 1
        """,
    )
    harness.write(
        f"resources/{NAMESPACE}/proxies/orders.yaml",
        f"""
        kind: Proxy
        spec:
          id: "orders-proxy"
          name: "Orders API"
          listen_path: "/orders"
          backend_scheme: http
          backend_host: "{harness.upstream_url.split('//')[1].split(':')[0]}"
          backend_port: {harness.upstream_url.rsplit(':', 1)[1]}
          strip_listen_path: true
        """,
    )
    harness.write(
        f"resources/{NAMESPACE}/plugins/orders-key-auth.yaml",
        """
        kind: PluginConfig
        spec:
          id: "orders-key-auth"
          plugin_name: "key_auth"
          scope: proxy
          proxy_id: "orders-proxy"
          enabled: true
          config:
            key_location: "header:X-API-Key"
        """,
    )
    harness.write(
        f"resources/{NAMESPACE}/consumers/orders-client.yaml",
        """
        kind: Consumer
        spec:
          id: "orders-client"
          username: "orders-client"
          credentials:
            keyauth:
              - key: "${gh-env-secret:alloc=require}"
        """,
    )


def ensure_deployed(harness: Harness) -> None:
    """Put the repository's desired state on the gateway, from any starting point.

    Scenarios run in sequence and mutate shared state — one of them deletes
    the proxy — and `LIFECYCLE_ONLY` runs any single one on its own. Either
    way, a scenario that assumes what ran before it is a scenario that reports
    on the previous scenario's leftovers. So each one that needs the tree
    deployed says so.

    `--allow-large-prune` because re-seeding after the delete scenario is a
    re-creation, and the guard's refusal is asserted where it belongs, in
    `modify-and-delete-in-order`.
    """
    seed_repository(harness)
    harness.run("apply", "--auto-approve", "--allow-large-prune")


# -- scenarios ---------------------------------------------------------------
#
# Each returns a detail string on success and raises `ScenarioFailure` on a
# real failure. Raising `NotImplementedError` records `skipped` with the
# reason, which never certifies anything.


def scenario_create_and_route(harness: Harness) -> str:
    seed_repository(harness)
    harness.run("validate")
    harness.run("apply", "--auto-approve")

    key = harness_key(harness)
    harness.expect_status("/orders/status/200", 200, {"X-API-Key": key})
    # Authentication must be ENFORCED, not merely present in the document.
    harness.expect_status("/orders/status/200", 401)
    return "upstream, proxy, scoped auth plugin and consumer serve authenticated traffic"


def scenario_reapply_is_a_no_op(harness: Harness) -> str:
    ensure_deployed(harness)
    before = harness.state()
    # exit 0 = in sync. Persistent false drift from credential normalization is
    # exactly what this catches.
    harness.run("diff", "--exit-on-drift")
    harness.run("apply", "--auto-approve")
    harness.run("diff", "--exit-on-drift")
    after = harness.state()
    if before.get("resources") != after.get("resources"):
        raise ScenarioFailure("a no-op apply changed the ownership ledger")
    return "re-apply produced no changes and no false drift"


def scenario_modify_and_delete_in_order(harness: Harness) -> str:
    ensure_deployed(harness)
    # An unmanaged row the repository never declared must survive shared mode.
    create_unmanaged_proxy(harness)

    harness.write(
        f"resources/{NAMESPACE}/proxies/orders.yaml",
        (harness.workdir / f"resources/{NAMESPACE}/proxies/orders.yaml")
        .read_text(encoding="utf-8")
        .replace('name: "Orders API"', 'name: "Orders API v2"'),
    )
    harness.run("apply", "--auto-approve")
    # The modification must actually have landed: a converged diff is the
    # evidence, not the apply's exit code.
    harness.run("diff", "--exit-on-drift")

    # Deleting the proxy must not orphan its scoped plugin, and must happen in
    # an order the gateway accepts.
    harness.remove(f"resources/{NAMESPACE}/proxies/orders.yaml")
    harness.remove(f"resources/{NAMESPACE}/plugins/orders-key-auth.yaml")

    # Two of four managed rows is over the 25% default, so the large-prune
    # guard must refuse first. Asserting that it fires is the point: a safety
    # gate nobody has watched refuse is a gate nobody knows works, and simply
    # passing --allow-large-prune here would have tested the deletion while
    # silently retiring the guard from the suite.
    refused = harness.run("apply", "--auto-approve", expect=1)
    if "large-prune" not in refused.stderr and "--allow-large-prune" not in refused.stderr:
        raise ScenarioFailure(
            "a deletion over the prune threshold was not refused by the "
            f"large-prune guard\n{refused.stderr}"
        )

    # Then the documented way through it.
    harness.run("apply", "--auto-approve", "--allow-large-prune")
    harness.expect_status("/orders/status/200", 404, attempts=5)

    if not unmanaged_proxy_exists(harness):
        raise ScenarioFailure(
            "shared mode deleted a resource this repository never declared"
        )
    return (
        "modify applied; the large-prune guard refused the deletion and "
        "--allow-large-prune carried it through in dependency order; the "
        "unmanaged row survived"
    )


def scenario_conditional_overwrite(harness: Harness) -> str:
    ensure_deployed(harness)

    # The gateway half: every kind incremental apply overwrites carries a
    # strong entity-tag. Apply refuses to overwrite a row without one.
    for path in (
        "/proxies/orders-proxy",
        "/upstreams/orders-upstream",
        "/plugins/config/orders-key-auth",
        "/consumers/orders-client/verification",
    ):
        status, etag, _ = _admin_exchange(harness, "GET", path)
        if status != 200 or not etag or not etag.startswith('"'):
            raise ScenarioFailure(
                f"GET {path} answered {status} without a strong tag; incremental "
                "apply refuses every overwrite of a row without a strong entity-tag"
            )

    # ...and a write carrying a superseded tag is refused, writing nothing.
    _, planned_tag, _ = _admin_exchange(harness, "GET", "/proxies/orders-proxy")
    mutate_proxy_out_of_band(harness)
    stale = out_of_band_proxy("A write planned before the out-of-band edit")
    status, _, _ = _admin_exchange(
        harness, "PUT", "/proxies/orders-proxy", stale, if_match=planned_tag
    )
    if status != 412:
        raise ScenarioFailure(
            f"a PUT carrying a superseded If-Match answered {status}, expected "
            "412; the gateway cannot fence a write planned from a stale read"
        )
    _, _, body = _admin_exchange(harness, "GET", "/proxies/orders-proxy")
    if json.loads(body).get("name") != OUT_OF_BAND_PROXY_NAME:
        raise ScenarioFailure("the refused conditional PUT changed the proxy anyway")

    # Hidden-only credential edits must invalidate the matching row tag too.
    status, consumer_tag, body = _admin_exchange(harness, "GET", "/consumers/orders-client/verification")
    if status != 200:
        raise ScenarioFailure("complete consumer verification is unavailable")
    consumer = json.loads(body)
    if consumer.get("credentials", {}).get("keyauth", [{}])[0].get("key") != harness_key(harness):
        raise ScenarioFailure("consumer verification did not return the exact stored key")
    original_credentials = consumer.get("credentials")
    if not isinstance(original_credentials, dict) or "custom_fixture" in original_credentials:
        raise ScenarioFailure("hidden credential fixture setup was not isolated")
    original_credentials = dict(original_credentials)
    consumer["credentials"]["custom_fixture"] = [{"opaque": "lifecycle-hidden-field"}]
    status, _, _ = _admin_exchange(harness, "PUT", "/consumers/orders-client", consumer, if_match=consumer_tag)
    if status != 200:
        raise ScenarioFailure("hidden-field setup failed")
    status, _, _ = _admin_exchange(harness, "PUT", "/consumers/orders-client", consumer, if_match=consumer_tag)
    if status != 412:
        raise ScenarioFailure("a hidden-only consumer change did not invalidate the row token")

    # Re-plan and converge through the client, preserving the hidden custom type.
    edit_resource(
        harness,
        "consumers/orders-client.yaml",
        'username: "orders-client"',
        'username: "orders-client"\n  acl_groups: ["orders"]',
    )
    edit_resource(
        harness,
        "upstreams/orders.yaml",
        'name: "Orders service"',
        'name: "Orders service v2"',
    )
    edit_resource(
        harness,
        "plugins/orders-key-auth.yaml",
        'plugin_name: "key_auth"',
        'plugin_name: "key_auth"\n  labels:\n    team: "orders"',
    )
    harness.run("apply", "--auto-approve")
    harness.expect_status("/orders/status/200", 200, {"X-API-Key": harness_key(harness)})
    status, _, body = _admin_exchange(harness, "GET", "/consumers/orders-client/verification")
    if status != 200 or json.loads(body)["credentials"].get("custom_fixture") != consumer["credentials"]["custom_fixture"]:
        raise ScenarioFailure("client update lost the hidden custom credential")
    # Remove isolated test setup before the following replacement scenario. This
    # endpoint is deliberately not a conditional deletion shortcut in the client.
    status, _, _ = _admin_exchange(harness, "DELETE", "/consumers/orders-client/credentials/custom_fixture")
    if status != 204:
        raise ScenarioFailure("hidden credential fixture cleanup failed")
    status, _, body = _admin_exchange(harness, "GET", "/consumers/orders-client/verification")
    if status != 200:
        raise ScenarioFailure("complete consumer verification after cleanup failed")
    cleaned_consumer = json.loads(body)
    if cleaned_consumer.get("credentials") != original_credentials:
        raise ScenarioFailure("hidden credential cleanup did not preserve stored credentials")
    harness.run("diff", "--exit-on-drift")
    return (
        "the gateway tags every overwritten kind and refuses a superseded If-Match "
        "with 412; apply re-planned over an out-of-band edit and updated a proxy, "
        "an upstream, a plugin config and a consumer through If-Match, converging "
        "with no drift"
    )


def scenario_conditional_full_replace(harness: Harness) -> str:
    ensure_deployed(harness)
    backend = urllib.parse.urlsplit(harness.upstream_url)
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Conditional lifecycle spec", "version": "1"},
        "paths": {"/status/200": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {
            "id": "conditional-spec-proxy", "listen_path": "/conditional-spec",
            "backend_host": backend.hostname, "backend_port": backend.port,
            "backend_scheme": "http",
        },
        "x-ferrum-upstream": {
            "id": "conditional-spec-upstream",
            "targets": [{"host": backend.hostname, "port": backend.port}],
        },
        "x-ferrum-plugins": [{
            "id": "conditional-spec-plugin", "plugin_name": "key_auth", "config": {},
        }],
    }
    status, _, _ = _admin_exchange(harness, "POST", "/api-specs", spec)
    if status != 201:
        raise ScenarioFailure("spec-owned graph fixture creation failed")
    public_key = (ROOT / "tests/lifecycle/conditional-trust-public.pem").read_text(encoding="ascii")
    trust = {
        "trust_domain": "conditional.fixture",
        "bundle": {"local": {
            "trust_domain": "conditional.fixture",
            "jwt_authorities": [{"key_id": "conditional-fixture", "public_key_pem": public_key}],
        }},
    }
    status, _, _ = _admin_exchange(harness, "POST", "/gateway-trust-bundles", trust)
    if status != 201:
        raise ScenarioFailure("trust-bundle fixture creation failed")
    status, token, body = _admin_exchange(harness, "GET", "/backup?conditional=true")
    if status != 200 or not token:
        raise ScenarioFailure("coherent namespace snapshot is unavailable")
    snapshot = json.loads(body)
    metadata = snapshot.get("conditional", {})
    if metadata.get("namespace_etag") != token or set(metadata.get("row_etags", {})) != {
        "proxies", "consumers", "upstreams", "plugin_configs"
    }:
        raise ScenarioFailure("conditional snapshot metadata is incomplete")
    restore = {key: snapshot[key] for key in (
        "version", "proxies", "consumers", "upstreams", "plugin_configs", "api_specs"
    )}
    if not snapshot["api_specs"]["items"] or len(snapshot["gateway_trust_bundles"]) != 1:
        raise ScenarioFailure("the conditional snapshot omitted seeded extra sections")
    for section in ("proxies", "upstreams", "plugin_configs"):
        if not any(row.get("api_spec_id") for row in snapshot[section]):
            raise ScenarioFailure("the conditional snapshot omitted part of the spec graph")
    # A -> B -> A changes the namespace revision even when row content reverts.
    status, row_token, proxy_body = _admin_exchange(harness, "GET", "/proxies/orders-proxy")
    if status != 200:
        raise ScenarioFailure("proxy setup read failed")
    original = json.loads(proxy_body)
    changed = dict(original, name="conditional ABA fixture")
    status, _, _ = _admin_exchange(harness, "PUT", "/proxies/orders-proxy", changed, if_match=row_token)
    if status != 200:
        raise ScenarioFailure("ABA mutation failed")
    _, current_row_token, _ = _admin_exchange(harness, "GET", "/proxies/orders-proxy")
    status, _, _ = _admin_exchange(harness, "PUT", "/proxies/orders-proxy", original, if_match=current_row_token)
    if status != 200:
        raise ScenarioFailure("ABA reversion failed")
    for path in ("/restore?confirm=true", "/restore?confirm=true&confirm_api_spec_deletion=true"):
        status, _, _ = _admin_exchange(harness, "POST", path, restore, if_match=token)
        if status != 412:
            raise ScenarioFailure("stale namespace restore, including confirmed deletion, was not refused")
    status, fresh, _ = _admin_exchange(harness, "GET", "/backup?conditional=true")
    if status != 200 or fresh == token:
        raise ScenarioFailure("ABA did not advance the namespace token")
    empty = {"version": "1", "proxies": [], "consumers": [], "upstreams": [], "plugin_configs": []}
    status, _, _ = _admin_exchange(
        harness, "POST", "/restore?confirm=true&confirm_api_spec_deletion=true", empty,
        if_match=fresh,
    )
    if status != 200:
        raise ScenarioFailure("conditional empty replacement failed")
    status, empty_token, body = _admin_exchange(harness, "GET", "/backup?conditional=true")
    if status != 200 or not empty_token:
        raise ScenarioFailure("empty namespace snapshot is unavailable")
    emptied = json.loads(body)
    if any(emptied[section] for section in ("proxies", "consumers", "upstreams", "plugin_configs")):
        raise ScenarioFailure("confirmed empty replacement left managed rows behind")
    if emptied["api_specs"]["items"] or emptied["gateway_trust_bundles"] != snapshot["gateway_trust_bundles"]:
        raise ScenarioFailure("confirmed spec deletion changed trust or left spec documents")
    status, _, _ = _admin_exchange(harness, "POST", "/restore?confirm=true", restore, if_match=empty_token)
    if status != 200:
        raise ScenarioFailure("conditional replacement of an empty namespace failed")
    # Exercise the actual client full-replacement path against these same server bytes.
    harness.write(".gitforgeops/config.yaml", f"""
        version: 1
        default_environment: acceptance
        environments:
          acceptance:
            apply_strategy: full_replace
            ownership:
              mode: exclusive
              namespaces: [{NAMESPACE}]
    """)
    harness.run("apply", "--auto-approve", "--allow-large-prune")
    harness.run("diff", "--exit-on-drift")
    status, _, body = _admin_exchange(harness, "GET", "/backup?conditional=true")
    after_client = json.loads(body)
    if status != 200 or after_client["api_specs"] != snapshot["api_specs"]:
        raise ScenarioFailure("client replacement did not preserve verbatim spec documents")
    if after_client["gateway_trust_bundles"] != snapshot["gateway_trust_bundles"]:
        raise ScenarioFailure("client replacement rewrote the live trust bundle")
    harness.run("apply", "--auto-approve", "--allow-large-prune", "--confirm-api-spec-deletion")
    status, _, body = _admin_exchange(harness, "GET", "/backup?conditional=true")
    final = json.loads(body)
    if status != 200 or final["api_specs"]["items"]:
        raise ScenarioFailure("client confirmed deletion left spec documents")
    if any(row.get("api_spec_id") for section in ("proxies", "upstreams", "plugin_configs") for row in final[section]):
        raise ScenarioFailure("client confirmed deletion left spec-owned rows")
    if final["gateway_trust_bundles"] != snapshot["gateway_trust_bundles"]:
        raise ScenarioFailure("client confirmed deletion rewrote live trust")
    trust_before_cleanup = final["gateway_trust_bundles"]
    fixture_rows = [
        row for row in trust_before_cleanup if row.get("trust_domain") == "conditional.fixture"
    ]
    if len(fixture_rows) != 1:
        raise ScenarioFailure("trust fixture lookup before cleanup was incomplete")
    status, _, _ = _admin_exchange(harness, "DELETE", f"/gateway-trust-bundles/{NAMESPACE}")
    if status != 204:
        raise ScenarioFailure("trust fixture cleanup failed")
    status, cleanup_token, body = _admin_exchange(harness, "GET", "/backup?conditional=true")
    if status != 200 or not cleanup_token:
        raise ScenarioFailure("complete snapshot after trust cleanup is unavailable")
    cleaned_snapshot = json.loads(body)
    if not isinstance(cleaned_snapshot.get("gateway_trust_bundles"), list):
        raise ScenarioFailure("complete snapshot after trust cleanup omitted trust bundles")
    remaining_trust = [
        row for row in trust_before_cleanup if row.get("trust_domain") != "conditional.fixture"
    ]
    if cleaned_snapshot["gateway_trust_bundles"] != remaining_trust:
        raise ScenarioFailure("trust cleanup did not remove only the fixture bundle")
    for section in ("version", "proxies", "consumers", "upstreams", "plugin_configs", "api_specs"):
        if cleaned_snapshot.get(section) != final.get(section):
            raise ScenarioFailure("trust cleanup changed unrelated backup sections")
    seed_repository(harness)
    return "coherent namespace If-Match enforced ABA, empty/spec deletion, spec graph and verbatim documents; trust survived and client converged"


def edit_resource(harness: Harness, relative: str, old: str, new: str) -> None:
    """Rewrite one seeded resource file, failing loudly if `old` is absent."""
    path = harness.workdir / f"resources/{NAMESPACE}/{relative}"
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise ScenarioFailure(f"the seeded {relative} no longer contains {old!r}")
    harness.write(f"resources/{NAMESPACE}/{relative}", text.replace(old, new))


def scenario_credentials_generate_and_rotate(harness: Harness) -> str:
    raise NotImplementedError(
        "needs a disposable GitHub Environment for the credential broker; run "
        "through tests/lifecycle/github_acceptance.md"
    )


def scenario_partial_failure_recovery(harness: Harness) -> str:
    # Register the consumer key for redaction even when this scenario runs
    # alone (`LIFECYCLE_ONLY`): failure details embed captured apply output.
    harness_key(harness)
    ensure_deployed(harness)
    try:
        with fault_proxy.FaultProxy(harness.gateway_url) as proxy:
            evidence = [
                _cached_backup_blocks_every_write(harness, proxy),
                _refused_write_keeps_completed_work(harness, proxy),
                _committed_create_answered_500_is_adopted(harness, proxy),
                _dropped_batch_is_verified_not_replayed(harness, proxy),
                _foreign_row_behind_a_dropped_create_stops_the_run(harness, proxy),
            ]
    finally:
        # A case that failed midway leaves its extra file behind, and the next
        # scenario's `ensure_deployed` re-seeds only the base tree. Removing
        # them lets that apply prune the rows the ledger owns; an unowned one
        # (the foreign row, if its case failed early) stays, as shared mode
        # requires, and the suite is already failed.
        for name in CASE_UPSTREAMS:
            harness.remove(f"resources/{NAMESPACE}/upstreams/{name}.yaml")
    # Every injected failure ends in the same place: the gateway holds exactly
    # what the repository declares, recovered by an ordinary re-run.
    ensure_deployed(harness)
    harness.run("diff", "--exit-on-drift")
    return "; ".join(evidence)


# The upstream files the cases add beside the seeded tree.
CASE_UPSTREAMS = ("retired", "shipping", "inventory", "catalog", "pricing", "billing")


def _through(proxy: fault_proxy.FaultProxy) -> dict[str, str]:
    """`gitforgeops` overrides that route the admin API through the proxy.

    The client keeps its default retry budget, so a regression that re-sent an
    ambiguous create under it would show up in the proxy's request log, which
    every case counts.
    """
    return {"FERRUM_GATEWAY_URL": proxy.url}


def _fired(fault: fault_proxy.Fault, what: str) -> None:
    """A fault that never fired leaves the scenario having tested nothing."""
    if isinstance(fault.error, ScenarioFailure):
        # Raised on the proxy's thread; the run it disturbed proves nothing.
        raise fault.error
    if fault.error is not None:
        # Any other type (NotImplementedError included, which the driver
        # would record as `skipped`) is a harness failure.
        raise ScenarioFailure(
            f"the injected fault's ({what}) after_commit hook raised "
            f"{type(fault.error).__name__}. This is a harness failure, not a "
            "finding about gitforgeops."
        )
    if fault.hits == 0:
        raise ScenarioFailure(
            f"the injected fault ({what}) never matched a request, so the "
            "safeguard it targets was not exercised. This is a harness failure, "
            "not a finding about gitforgeops."
        )


def _faulted_apply(harness: Harness, proxy, fault, what: str, expect: int | None):
    """`apply` through the proxy, judged only after the fault is known to have fired.

    The exit code is checked last: a fault that never matched, or whose hook
    failed, makes any exit code meaningless.
    """
    completed = harness.run("apply", "--auto-approve", expect=None, **_through(proxy))
    # The client may exit while a handler or its hook is still running.
    proxy.drain()
    seen = proxy.requests()
    proxy.clear()
    if proxy.failures:
        raise ScenarioFailure(
            f"the fault proxy itself failed ({', '.join(proxy.failures)}) during "
            f"the {what} run. This is a harness failure, not a finding about "
            "gitforgeops."
        )
    _fired(fault, what)
    if expect is not None and completed.returncode != expect:
        raise ScenarioFailure(
            f"`gitforgeops apply` with an injected {what} exited "
            f"{completed.returncode}, expected {expect}\n--- stdout ---\n"
            f"{completed.stdout}\n--- stderr ---\n{completed.stderr}"
        )
    return completed, seen


def _sent(seen: list[tuple[str, str]], method: str, path: str) -> int:
    """How many `method` requests for `path` (a fullmatch regex) the client sent."""
    pattern = re.compile(path)
    return sum(1 for m, p in seen if m == method and pattern.fullmatch(p))


def _expect_sent(seen, method: str, path: str, count: int, why: str) -> None:
    sent = _sent(seen, method, path)
    if sent != count:
        raise ScenarioFailure(f"apply sent {method} {path} {sent} time(s), expected {count}: {why}")


def _row(harness: Harness, path: str) -> dict | None:
    """The gateway's row at `path`, read directly (never through the proxy)."""
    status, _, body = _admin_exchange(harness, "GET", path)
    if status == 404:
        return None
    if status != 200:
        raise ScenarioFailure(
            f"the harness's own GET {path} answered {status}. This is a harness "
            "failure, not a finding about gitforgeops."
        )
    return json.loads(body)


def _name(harness: Harness, path: str) -> str | None:
    return (_row(harness, path) or {}).get("name")


def _owned(harness: Harness, kind: str, identifier: str) -> bool:
    """Is the row in the ownership ledger the last run left behind?

    Matches `state_key`'s raw form, which holds for ids without `%` or `:`
    (the ones this scenario uses); those two characters are encoded there.
    """
    suffix = f":{NAMESPACE}:{kind}:{identifier}"
    return any(key.endswith(suffix) for key in harness.state().get("resources", {}))


def _upstream(identifier: str, name: str, harness: Harness) -> str:
    backend = urllib.parse.urlsplit(harness.upstream_url)
    return f"""
        kind: Upstream
        spec:
          id: "{identifier}"
          name: "{name}"
          algorithm: round_robin
          targets:
            - host: "{backend.hostname}"
              port: {backend.port}
              weight: 1
        """


def _cached_backup_blocks_every_write(harness: Harness, proxy) -> str:
    ensure_deployed(harness)
    ledger = {key: harness.state().get(key) for key in ("resources", "pending_creates")}
    edit_resource(harness, "proxies/orders.yaml", 'name: "Orders API"', 'name: "Orders API (cached)"')
    fault = proxy.inject(
        fault_proxy.Fault("GET", r"/backup", fault_proxy.MARK_CACHED, times=None)
    )
    refused, seen = _faulted_apply(harness, proxy, fault, "cached /backup", expect=1)
    writes = sorted({f"{m} {p}" for m, p in seen if m != "GET"})
    if writes:
        raise ScenarioFailure(f"apply wrote after a cached /backup: {', '.join(writes)}")
    if "cached" not in refused.stderr:
        raise ScenarioFailure(
            "apply against a cached /backup failed without naming the cached "
            f"view\n{refused.stderr}"
        )
    if _name(harness, "/proxies/orders-proxy") != "Orders API":
        raise ScenarioFailure("a plan read from a cached /backup still changed the proxy")
    if {key: harness.state().get(key) for key in ledger} != ledger:
        raise ScenarioFailure("a refused cached-view apply changed the ownership ledger")
    harness.run("apply", "--auto-approve")
    if _name(harness, "/proxies/orders-proxy") != "Orders API (cached)":
        raise ScenarioFailure("the re-run after a cached view did not apply the change")
    return "a cached /backup blocked every write and the re-run applied it"


def _refused_write_keeps_completed_work(harness: Harness, proxy) -> str:
    # A fifth managed row to delete: one of five stays under the large-prune
    # threshold, so the deferral below is the delete-deferral rule, not the guard.
    ensure_deployed(harness)
    retired = f"resources/{NAMESPACE}/upstreams/retired.yaml"
    harness.write(retired, _upstream("retired-upstream", "Retired", harness))
    harness.run("apply", "--auto-approve")
    if not _owned(harness, "Upstream", "retired-upstream"):
        raise ScenarioFailure("setup: the row to retire was not recorded as managed")

    edit_resource(harness, "upstreams/orders.yaml", 'name: "Orders service"', 'name: "Orders service (refused)"')
    edit_resource(harness, "proxies/orders.yaml", 'name: "Orders API"', 'name: "Orders API (partial)"')
    # A create that succeeds beside the refusal: its ownership must be
    # recorded by the failing run itself, not left to the recovery run.
    added = f"resources/{NAMESPACE}/upstreams/shipping.yaml"
    harness.write(added, _upstream("shipping-upstream", "Shipping", harness))
    harness.remove(retired)
    fault = proxy.inject(
        fault_proxy.Fault("PUT", r"/upstreams/orders-upstream", fault_proxy.REJECT, times=None)
    )
    failed, seen = _faulted_apply(harness, proxy, fault, "refused upstream PUT", expect=None)
    _expect_sent(seen, "DELETE", r"/upstreams/retired-upstream", 0, "the delete must be deferred")
    if failed.returncode == 0:
        raise ScenarioFailure(f"apply reported success over a refused write\n{failed.stdout}")
    if _name(harness, "/upstreams/orders-upstream") != "Orders service":
        raise ScenarioFailure("a write the gateway refused is live anyway")
    if _name(harness, "/proxies/orders-proxy") != "Orders API (partial)":
        raise ScenarioFailure("an independent write that succeeded was not kept")
    if _row(harness, "/upstreams/retired-upstream") is None:
        raise ScenarioFailure("a delete ran in a namespace whose earlier write failed")
    if not _owned(harness, "Upstream", "retired-upstream"):
        raise ScenarioFailure("the deferred delete's row lost its ownership record")
    if _row(harness, "/upstreams/shipping-upstream") is None:
        raise ScenarioFailure("an independent create that should have succeeded is not live")
    if not _owned(harness, "Upstream", "shipping-upstream"):
        raise ScenarioFailure("a failing run did not record the create that succeeded in it")

    harness.run("apply", "--auto-approve")
    if _name(harness, "/upstreams/orders-upstream") != "Orders service (refused)":
        raise ScenarioFailure("the re-run did not apply the write that was refused")
    if _row(harness, "/upstreams/retired-upstream") is not None or _owned(
        harness, "Upstream", "retired-upstream"
    ):
        raise ScenarioFailure("the re-run did not carry out the deferred delete")
    harness.remove(added)
    harness.run("apply", "--auto-approve")
    return (
        "a refused write kept and recorded the independent writes that succeeded, "
        "deferred the namespace's delete with its ownership intact, and the re-run "
        "finished both"
    )


def _committed_create_answered_500_is_adopted(harness: Harness, proxy) -> str:
    # A Modify alongside the Add keeps the namespace mixed, so the create is a
    # single POST rather than a `/batch`.
    ensure_deployed(harness)
    inventory = f"resources/{NAMESPACE}/upstreams/inventory.yaml"
    harness.write(inventory, _upstream("inventory-upstream", "Inventory", harness))
    edit_resource(harness, "proxies/orders.yaml", 'name: "Orders API"', 'name: "Orders API (mixed)"')
    fault = proxy.inject(fault_proxy.Fault("POST", r"/upstreams", fault_proxy.COMMIT_THEN_500))
    applied, seen = _faulted_apply(harness, proxy, fault, "500 after a committed create", expect=0)
    _expect_sent(seen, "POST", r"/upstreams", 1, "an ambiguous create is never replayed")
    _expect_sent(seen, "PUT", r"/upstreams/inventory-upstream", 1, "one ownership assertion")
    if fault.statuses[0] not in (200, 201):
        raise ScenarioFailure(
            f"setup: the gateway answered the forwarded create {fault.statuses[0]}"
        )
    if "found the exact desired resource live" not in applied.stderr:
        raise ScenarioFailure(f"the committed create was not verified as such\n{applied.stderr}")
    if not _owned(harness, "Upstream", "inventory-upstream"):
        raise ScenarioFailure("a create that committed behind a 500 was not recorded as managed")
    if _name(harness, "/proxies/orders-proxy") != "Orders API (mixed)":
        raise ScenarioFailure("the rest of the run did not continue after a verified create")
    # The adopted row is the declared one, field for field.
    harness.run("diff", "--exit-on-drift")
    harness.remove(inventory)
    harness.run("apply", "--auto-approve")
    if _row(harness, "/upstreams/inventory-upstream") is not None:
        raise ScenarioFailure("removing the adopted row's file did not delete it")
    return (
        "a create that committed behind a 500 was verified against an "
        "authoritative backup, adopted without a replay and later pruned as managed"
    )


def _dropped_batch_is_verified_not_replayed(harness: Harness, proxy) -> str:
    # Only additions: a pure-add namespace goes through one `POST /batch`. Two
    # rows, so verifying or claiming only the first of a chunk cannot pass.
    ensure_deployed(harness)
    added = {
        "catalog-upstream": f"resources/{NAMESPACE}/upstreams/catalog.yaml",
        "pricing-upstream": f"resources/{NAMESPACE}/upstreams/pricing.yaml",
    }
    for identifier, relative in added.items():
        harness.write(relative, _upstream(identifier, identifier, harness))
    fault = proxy.inject(fault_proxy.Fault("POST", r"/batch", fault_proxy.COMMIT_THEN_DROP))
    applied, seen = _faulted_apply(
        harness, proxy, fault, "connection dropped after a committed /batch", expect=0
    )
    _expect_sent(seen, "POST", r"/batch", 1, "an ambiguous batch is never replayed")
    _expect_sent(seen, "POST", r"/upstreams", 0, "nor replayed as individual creates")
    for identifier in added:
        _expect_sent(seen, "PUT", f"/upstreams/{identifier}", 1, "one ownership assertion per row")
    if "without replaying the batch" not in applied.stderr:
        raise ScenarioFailure(f"the dropped batch was not verified as committed\n{applied.stderr}")
    for identifier in added:
        if not _owned(harness, "Upstream", identifier):
            raise ScenarioFailure(
                f"{identifier}, committed in a batch behind a dropped connection, was not recorded"
            )
    harness.run("diff", "--exit-on-drift")
    # Two of six managed rows is over the large-prune threshold; the guard is
    # asserted in `modify-and-delete-in-order`.
    for relative in added.values():
        harness.remove(relative)
    harness.run("apply", "--auto-approve", "--allow-large-prune")
    for identifier in added:
        if _row(harness, f"/upstreams/{identifier}") is not None:
            raise ScenarioFailure(f"removing {identifier}'s file did not delete the recorded row")
    return "a /batch whose answer was lost was verified live and recorded, never re-sent"


def _foreign_row_behind_a_dropped_create_stops_the_run(harness: Harness, proxy) -> str:
    ensure_deployed(harness)
    billing = f"resources/{NAMESPACE}/upstreams/billing.yaml"
    harness.write(billing, _upstream("billing-upstream", "Billing", harness))
    edit_resource(harness, "proxies/orders.yaml", 'name: "Orders API"', 'name: "Orders API (withheld)"')
    foreign = "Billing, as another writer left it"

    def another_writer() -> None:
        row = _row(harness, "/upstreams/billing-upstream")
        if row is None:
            raise ScenarioFailure("setup: the forwarded create did not commit")
        _admin(harness, "PUT", "/upstreams/billing-upstream", {**row, "name": foreign})

    fault = proxy.inject(
        fault_proxy.Fault(
            "POST", r"/upstreams", fault_proxy.COMMIT_THEN_DROP, after_commit=another_writer
        )
    )
    stopped, seen = _faulted_apply(
        harness, proxy, fault, "connection dropped, row changed by another writer", expect=1
    )
    _expect_sent(seen, "POST", r"/upstreams", 1, "an ambiguous create is never replayed")
    for method in ("PUT", "DELETE"):
        _expect_sent(seen, method, r"/upstreams/billing-upstream", 0, "the foreign row is left alone")
    _expect_sent(seen, "PUT", r"/proxies/orders-proxy", 0, "later writes are withheld")
    if "not the resource we sent" not in stopped.stderr:
        raise ScenarioFailure(
            f"an unprovable create did not stop the run as ambiguous\n{stopped.stderr}"
        )
    if _name(harness, "/upstreams/billing-upstream") != foreign:
        raise ScenarioFailure("apply overwrote a row it could not prove it wrote")
    if _owned(harness, "Upstream", "billing-upstream"):
        raise ScenarioFailure("apply claimed ownership of a row it could not prove it wrote")
    if _name(harness, "/proxies/orders-proxy") != "Orders API":
        raise ScenarioFailure("writes after the ambiguous create were not withheld")

    # The documented recovery: look at the diff, then re-run.
    harness.run("diff", "--exit-on-drift", expect=2)
    harness.run("apply", "--auto-approve")
    if _name(harness, "/proxies/orders-proxy") != "Orders API (withheld)":
        raise ScenarioFailure("the re-run did not apply the withheld write")
    harness.remove(billing)
    harness.run("apply", "--auto-approve")
    if _row(harness, "/upstreams/billing-upstream") is not None:
        raise ScenarioFailure("the recovered row was not managed: removing its file did not delete it")
    return (
        "a dropped create whose row another writer changed stopped the run "
        "without overwriting or claiming it, and diff then re-run recovered"
    )


def scenario_ledger_publication_failure(harness: Harness) -> str:
    raise NotImplementedError(
        "needs a disposable GitHub repository with a protected branch; run "
        "through tests/lifecycle/github_acceptance.md"
    )


def scenario_runner_interruption(harness: Harness) -> str:
    raise NotImplementedError(
        "needs a disposable GitHub repository; run through "
        "tests/lifecycle/github_acceptance.md"
    )


def scenario_scheduling_and_attribution(harness: Harness) -> str:
    raise NotImplementedError(
        "needs a disposable GitHub repository with environment approvals; run "
        "through tests/lifecycle/github_acceptance.md"
    )


def scenario_staged_promotion(harness: Harness) -> str:
    raise NotImplementedError(
        "needs a disposable GitHub repository with two approval-gated "
        "environments; run through tests/lifecycle/github_acceptance.md"
    )


def scenario_drift_monitoring(harness: Harness) -> str:
    ensure_deployed(harness)
    # In sync first. Without this the scenario would claim three outcomes and
    # have observed two.
    in_sync = harness.run("diff", "--exit-on-drift", expect=None)
    if in_sync.returncode != 0:
        raise ScenarioFailure(
            "a freshly applied gateway reported exit "
            f"{in_sync.returncode}, expected in sync (0)\n{in_sync.stdout}"
        )
    # Out-of-band change: the gateway now has a row the repository declares
    # differently. `--exit-on-drift` must say 2, and must not say 1.
    mutate_proxy_out_of_band(harness)
    completed = harness.run("diff", "--exit-on-drift", expect=None)
    if completed.returncode != 2:
        raise ScenarioFailure(
            "an out-of-band gateway change reported exit "
            f"{completed.returncode}, expected the drift code 2\n{completed.stdout}"
        )
    # A check that cannot reach the gateway is a *failed check*, not "no drift".
    unreachable = harness.run(
        "diff",
        "--exit-on-drift",
        expect=None,
        FERRUM_GATEWAY_URL="http://127.0.0.1:1",
    )
    if unreachable.returncode != 1:
        raise ScenarioFailure(
            "an unreachable gateway reported exit "
            f"{unreachable.returncode}, expected the failure code 1"
        )
    return "drift (2), in sync (0) and check-failed (1) are distinguishable"


def scenario_file_and_mesh_boundary(harness: Harness) -> str:
    # Only the tree is needed here, not a deployed gateway: the point is that
    # assembling a document is NOT deploying it.
    seed_repository(harness)
    fragment = f"resources/{NAMESPACE}/mesh/minimal.yaml"
    harness.write(fragment, MESH_FIXTURE.read_text(encoding="utf-8"))
    try:
        return _file_and_mesh_boundary(harness)
    finally:
        # Mesh is file-only; leave the api-mode tree the other scenarios use.
        harness.remove(fragment)


def _file_and_mesh_boundary(harness: Harness) -> str:
    assembled = harness.workdir / "assembled"
    output = assembled / "acceptance.yaml"
    mesh_output = assembled / "acceptance-mesh.yaml"
    file_mode = {
        "FERRUM_GATEWAY_MODE": "file",
        "FERRUM_MESH_FILE_OUTPUT_PATH": str(mesh_output),
    }

    # 1. Assembly: a commit-safe gateway document, and a SEPARATE mesh document.
    harness.run("export", "--output", str(output), **file_mode)
    if not output.is_file():
        raise ScenarioFailure("file-mode export wrote no document")
    text = output.read_text(encoding="utf-8")
    if "${gh-env-secret:" not in text:
        raise ScenarioFailure(
            "the exported document has no placeholder left, so it is not the "
            "commit-safe artifact export promises"
        )
    key = harness_key(harness)
    if key in text:
        raise ScenarioFailure("a credential value reached the exported document")
    if not mesh_output.is_file():
        raise ScenarioFailure("a declared MeshConfig produced no mesh document")
    mesh = mesh_output.read_text(encoding="utf-8")
    if "mesh:" not in mesh or "spiffe://cluster.local/ns/ferrum/sa/api" not in mesh:
        raise ScenarioFailure("the mesh document does not carry the declared workload")
    if "proxies:" in mesh or "workloads:" in text:
        raise ScenarioFailure(
            "the gateway and mesh documents were mixed; a mesh node rejects a "
            "document carrying gateway resources"
        )

    # 2. Materialization: the credential appears ONLY in a private file.
    materialized = assembled / "acceptance.materialized.yaml"
    harness.run("export", "--materialize", "--output", str(materialized), **file_mode)
    if key not in materialized.read_text(encoding="utf-8"):
        raise ScenarioFailure("materialization did not resolve the seeded credential")
    mode = materialized.stat().st_mode & 0o777
    if mode != 0o600:
        raise ScenarioFailure(
            f"the materialized document is mode {oct(mode)}; plaintext credentials "
            "must be written 0600"
        )
    if key in output.read_text(encoding="utf-8"):
        raise ScenarioFailure("materializing rewrote the commit-safe document")
    materialized.unlink()

    return (
        "file-mode assembly preserves placeholders and writes a separate mesh "
        "document; materialization is 0600 and never touches the committed "
        "artifact. Encrypted delivery needs a GitHub key and is covered by "
        "credentials-generate-and-rotate"
    )


# -- edge-contract-copies ------------------------------------------------------
#
# GitForgeOps carries its own copies of several Edge rules, and each is used
# against a live gateway. This scenario runs every copy against the gateway
# under test: the pinned release in lifecycle.yml, Edge `main` in the Edge Main
# Drift workflow, so a change on Edge `main` fails the drift check before it is
# released. The static half (the same copies against Edge's openapi.yaml) is
# tests/unit/edge_main_openapi_tests.rs.

CONTRACT_PROXY = "contract-trigger-proxy"
CONTRACT_PLUGIN = "contract-trigger-plugin"
# A post-transaction logging sink: not an authentication plugin (Edge refuses
# identity predicates on those), no response-header, body-limit or trailer
# policy (Edge refuses any trigger on those), and `{}` is a complete config.
CONTRACT_PLUGIN_NAME = "stdout_logging"
CONTRACT_CONSUMER = "contract-consumer"
CONTRACT_SPEC_PROXY = "contract-spec-proxy"
CONTRACT_MTLS_IDENTITY = "CN=contract-client"
_GET_LEAF = {"method": ["GET"]}
_GET = {"match": _GET_LEAF}
# `PluginTriggerNode` written positionally (`all`, `any`, `not`, `match`).
_GET_NODE_POSITIONAL = [None, None, None, _GET_LEAF]


def _contract_trigger_cases() -> list[tuple[str, dict, object]]:
    """`(position, valid trigger, the same trigger with that position positional)`.

    One case per position where `src/config/json_object.rs` requires a JSON
    object (`config::schema::PluginTrigger*`). The array is the object's
    fields in declaration order (serde's positional struct form), so with the
    object guard gone it would build exactly the valid trigger: only the guard
    can refuse it. Edge and GitForgeOps declare these fields in the same order.
    """
    cases: list[tuple[str, dict, object]] = [
        ("trigger", {"when": _GET}, [_GET]),
        ("trigger.when", {"when": _GET}, {"when": _GET_NODE_POSITIONAL}),
        ("all[]", {"when": {"all": [_GET]}}, {"when": {"all": [_GET_NODE_POSITIONAL]}}),
        ("any[]", {"when": {"any": [_GET]}}, {"when": {"any": [_GET_NODE_POSITIONAL]}}),
        ("not", {"when": {"not": _GET}}, {"when": {"not": _GET_NODE_POSITIONAL}}),
        ("match", {"when": _GET}, {"when": {"match": [["GET"]]}}),
    ]
    # (field, object form, positional form): string matches lead with
    # `exact`, field matches with `name`, identity matches with `presence`.
    leaves = (
        ("path", {"exact": ["/contract"]}, [["/contract"]]),
        ("host", {"exact": ["api.example.test"]}, [["api.example.test"]]),
        ("sni", {"exact": ["api.example.test"]}, [["api.example.test"]]),
        ("header", {"name": "x-contract"}, ["x-contract"]),
        ("query", {"name": "contract"}, ["contract"]),
        ("cookie", {"name": "contract"}, ["contract"]),
        ("consumer", {"presence": "present"}, ["present"]),
        ("external_identity", {"presence": "present"}, ["present"]),
        ("spiffe_id", {"presence": "present"}, ["present"]),
    )
    for name, valid, positional in leaves:
        cases.append(
            (
                f"match.{name}",
                {"when": {"match": {name: valid}}},
                {"when": {"match": {name: positional}}},
            )
        )
    for name, base in (("header", {"name": "x-contract"}), ("consumer", {})):
        cases.append(
            (
                f"match.{name}.value",
                {"when": {"match": {name: dict(base, value={"exact": ["contract"]})}}},
                {"when": {"match": {name: dict(base, value=[["contract"]])}}},
            )
        )
    return cases


def _contract_plugin(trigger: object) -> dict:
    return {
        "id": CONTRACT_PLUGIN,
        "plugin_name": CONTRACT_PLUGIN_NAME,
        "scope": "proxy",
        "proxy_id": CONTRACT_PROXY,
        "enabled": True,
        "config": {},
        "trigger": trigger,
    }


def _contract_proxy() -> dict:
    return {
        "id": CONTRACT_PROXY,
        "name": "Edge contract copies",
        "listen_path": "/contract-trigger",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 1,
    }


# `DELETE /plugins/config/{id}` requires the proxies that may reference it.
_CONTRACT_PLUGIN_PATH = f"/plugins/config/{CONTRACT_PLUGIN}?expected_proxy_ids={CONTRACT_PROXY}"


def _write_contract_trigger_files(harness: Harness, trigger: object) -> None:
    # JSON is YAML, and json.dumps cannot mis-indent a nested trigger.
    harness.write(
        f"resources/{NAMESPACE}/proxies/{CONTRACT_PROXY}.yaml",
        json.dumps({"kind": "Proxy", "spec": _contract_proxy()}),
    )
    harness.write(
        f"resources/{NAMESPACE}/plugins/{CONTRACT_PLUGIN}.yaml",
        json.dumps({"kind": "PluginConfig", "spec": _contract_plugin(trigger)}),
    )


def _json_object_rules(harness: Harness) -> str:
    """`json_object.rs`: Edge and gitforgeops refuse the positional form.

    At each position the object form must be accepted by both and the
    positional array form, which carries the same values, refused by both:
    Edge with `400`, gitforgeops with its own object-shape diagnostic (so the
    downstream validator cannot stand in for the copy). An Edge that accepts
    the array, or refuses the object, no longer matches the copy.
    """
    _admin(harness, "POST", "/proxies", dict(_contract_proxy(), namespace=NAMESPACE))
    findings = []
    try:
        for position, valid, positional in _contract_trigger_cases():
            status, _, body = _admin_exchange(
                harness, "POST", "/plugins/config", _contract_plugin(valid)
            )
            if status == 201:
                _admin(harness, "DELETE", _CONTRACT_PLUGIN_PATH)
            else:
                findings.append(
                    f"{position}: Edge answered {status} to the object form: {body[:300]}"
                )
            status, _, _ = _admin_exchange(
                harness, "POST", "/plugins/config", _contract_plugin(positional)
            )
            if status != 400:
                findings.append(f"{position}: Edge answered {status} to the positional form")
                if status in (200, 201):
                    _admin(harness, "DELETE", _CONTRACT_PLUGIN_PATH)
            _write_contract_trigger_files(harness, valid)
            accepted = harness.run("validate", expect=None)
            if accepted.returncode != 0:
                findings.append(
                    f"{position}: gitforgeops validate refused the object form "
                    f"(exit {accepted.returncode})\n{accepted.stdout}\n{accepted.stderr}"
                )
            _write_contract_trigger_files(harness, positional)
            refused = harness.run("validate", expect=None)
            if refused.returncode == 0 or "a JSON object" not in refused.stdout + refused.stderr:
                findings.append(
                    f"{position}: gitforgeops validate did not refuse the positional form as "
                    f"a non-object (exit {refused.returncode})\n{refused.stdout}\n{refused.stderr}"
                )
    finally:
        harness.remove(f"resources/{NAMESPACE}/proxies/{CONTRACT_PROXY}.yaml")
        harness.remove(f"resources/{NAMESPACE}/plugins/{CONTRACT_PLUGIN}.yaml")
        status = __admin(harness, "DELETE", _CONTRACT_PLUGIN_PATH)
        if status not in (200, 202, 204, 404):
            findings.append(f"cleanup: DELETE of the trigger plugin answered {status}")
        _admin(harness, "DELETE", f"/proxies/{CONTRACT_PROXY}")
    if findings:
        raise ScenarioFailure(
            "the JSON-object rules (src/config/json_object.rs) no longer match the gateway:\n"
            + "\n".join(findings)
        )
    return f"{len(_contract_trigger_cases())} JSON-object positions"


def _namespace_snapshot(harness: Harness) -> tuple[str, dict]:
    status, token, body = _admin_exchange(harness, "GET", "/backup?conditional=true")
    if status != 200 or not token:
        raise ScenarioFailure(f"coherent namespace snapshot is unavailable (HTTP {status})")
    return token, json.loads(body)


def _restore_body(snapshot: dict) -> dict:
    return {
        key: snapshot[key]
        for key in ("version", "proxies", "consumers", "upstreams", "plugin_configs", "api_specs")
        if key in snapshot
    }


def _expect_unchanged(harness: Harness, token: str, what: str) -> None:
    after, _ = _namespace_snapshot(harness)
    if after != token:
        raise ScenarioFailure(f"{what} changed the namespace; GitForgeOps reads it as a refusal")


def _restore_semantics(harness: Harness) -> str:
    """`api_target.rs` / `http_client.rs` restore handling against the gateway.

    GitForgeOps always sends `?confirm=true`, reads a `4xx` as a refusal that
    changed nothing, and reads a `409` carrying `api_specs_at_risk` /
    `confirmation_required` as the API-spec guard. Each holds here, and the
    namespace revision proves nothing was written.
    """
    token, snapshot = _namespace_snapshot(harness)
    body = _restore_body(snapshot)

    status, _, _ = _admin_exchange(harness, "POST", "/restore", body)
    if status != 400:
        raise ScenarioFailure(f"POST /restore without ?confirm=true answered {status}, expected 400")
    _expect_unchanged(harness, token, "an unconfirmed restore")

    # A batch-shaped row (no `id`) and a mistyped field: refused before the
    # namespace is cleared, conditionally and unconditionally.
    batch_shaped = dict(body, proxies=[*body["proxies"], {
        "name": "no id", "listen_path": "/contract-no-id", "backend_scheme": "http",
        "backend_host": "127.0.0.1", "backend_port": 1,
    }])
    mistyped = dict(body, proxies=[*body["proxies"], dict(
        _contract_proxy(), id="contract-mistyped", listen_path="/contract-mistyped",
        backend_port="not-a-port", namespace=NAMESPACE,
    )])
    for what, invalid, if_match in (
        ("a batch-shaped restore", batch_shaped, None),
        ("a conditional batch-shaped restore", batch_shaped, token),
        ("a mistyped restore", mistyped, None),
    ):
        status, _, _ = _admin_exchange(
            harness, "POST", "/restore?confirm=true", invalid, if_match=if_match
        )
        if status != 400:
            raise ScenarioFailure(f"{what} answered {status}, expected a 400 refusal")
        _expect_unchanged(harness, token, what)

    # The API-spec guard: a body without `api_specs` while the namespace holds
    # a spec.
    backend = urllib.parse.urlsplit(harness.upstream_url)
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Contract copies spec", "version": "1"},
        "paths": {"/status/200": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {
            "id": CONTRACT_SPEC_PROXY, "listen_path": "/contract-spec",
            "backend_host": backend.hostname, "backend_port": backend.port,
            "backend_scheme": "http",
        },
    }
    status, _, created = _admin_exchange(harness, "POST", "/api-specs", spec)
    if status != 201:
        raise ScenarioFailure(f"the harness's API-spec fixture was refused (HTTP {status})")
    spec_id = json.loads(created).get("id")
    try:
        guarded_token, guarded = _namespace_snapshot(harness)
        legacy = _restore_body(guarded)
        legacy.pop("api_specs", None)
        for section in ("proxies", "upstreams", "plugin_configs"):
            legacy[section] = [row for row in legacy[section] if not row.get("api_spec_id")]
        status, _, refusal = _admin_exchange(harness, "POST", "/restore?confirm=true", legacy)
        fields = json.loads(refusal) if status == 409 else {}
        if status != 409 or not {"api_specs_at_risk", "confirmation_required"} <= set(fields):
            raise ScenarioFailure(
                f"a restore that would delete an API spec answered {status} with fields "
                f"{sorted(fields)}; GitForgeOps expects 409 with api_specs_at_risk and "
                "confirmation_required"
            )
        _expect_unchanged(harness, guarded_token, "the API-spec guard")
    finally:
        if spec_id:
            _admin(harness, "DELETE", f"/api-specs/{spec_id}", expect=(200, 204))
    return "restore refusals (unconfirmed, batch-shaped, mistyped, API-spec guard) changed nothing"


def _backup_round_trip(harness: Harness) -> str:
    """`BackupSnapshot` (http_client.rs) and the conditional decode, end to end.

    The namespace gets a registry row first, so a gateway that adds it to
    `GET /backup` (ferrum-edge#7539's `namespace_registry`) shows it here:
    import must report no unsupported section, and a full replacement must
    carry the whole backup through `POST /restore` and converge.
    """
    description = "GitForgeOps lifecycle: Edge contract copies"
    status, _, _ = _admin_exchange(
        harness, "POST", "/namespaces", {"name": NAMESPACE, "description": description}
    )
    if status == 409:
        _admin(harness, "PUT", f"/namespaces/{NAMESPACE}", {"description": description})
    elif status != 201:
        raise ScenarioFailure(f"registering the namespace answered {status}")

    scratch = harness.workdir.parent
    tree = scratch / "contract-import"
    bundle = scratch / "contract-import-bundle.json"
    shutil.rmtree(tree, ignore_errors=True)
    bundle.unlink(missing_ok=True)
    try:
        imported = harness.run(
            "import", "--from-api", "--output-dir", str(tree),
            "--credential-bundle-output", str(bundle),
            "--allow-plaintext-plugin-config", "key_auth",
            FERRUM_NAMESPACE=NAMESPACE,
        )
    finally:
        shutil.rmtree(tree, ignore_errors=True)
        bundle.unlink(missing_ok=True)
    if "Unsupported backup section" in imported.stdout + imported.stderr:
        raise ScenarioFailure(
            "import found a GET /backup section this build does not model "
            "(http_client::BACKUP_TOP_LEVEL_FIELDS):\n" + imported.stdout + imported.stderr
        )

    harness.write(".gitforgeops/config.yaml", f"""
        version: 1
        default_environment: acceptance
        environments:
          acceptance:
            apply_strategy: full_replace
            ownership:
              mode: exclusive
              namespaces: [{NAMESPACE}]
    """)
    try:
        harness.run("apply", "--auto-approve", "--allow-large-prune")
        harness.run("diff", "--exit-on-drift")
    finally:
        seed_repository(harness)
    return "import and full replacement carried a registered namespace's backup"


def _contract_credentials(harness: Harness) -> dict[str, str]:
    """Seed the contract consumer's slots in the run's broker bundle."""
    values = {
        f"{NAMESPACE}/{CONTRACT_CONSUMER}/{slot}": _disposable_secret(harness)
        for slot in ("keyauth/key", "jwt/secret", "hmac_auth/secret", "basicauth/password")
    }
    return values


def _disposable_secret(harness: Harness) -> str:
    import secrets  # noqa: PLC0415 - only this scenario generates values

    value = secrets.token_urlsafe(36)
    harness.remember_secret(value)
    return value


_FINGERPRINT = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
# Where the export withholds the contract consumer's values (JSON pointers).
_CONTRACT_FINGERPRINT_SITES = {
    "/credentials/keyauth/0/key",
    "/credentials/jwt/0/secret",
    "/credentials/hmac_auth/0/secret",
    "/hidden_credentials_fingerprint",
}


def _viewer_export(harness: Harness, viewer: str, plaintext: list[str]) -> str:
    """Read `GET /config/export` as a viewer and check the contract consumer.

    Every stored secret must arrive as a fingerprint and none in plaintext:
    `diff` compares a fingerprinted site as unverified, so a gateway that
    leaked a value would still compare in sync.
    """
    minted = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tests/lifecycle/admin_token.py"),
         "--secret", viewer, "--role", "viewer"],
        check=True, capture_output=True, text=True,
    )
    token = minted.stdout.strip()
    harness.remember_secret(token)
    status, _, body = _safe_exchange(
        f"{harness.gateway_url}/config/export",
        headers={"Authorization": f"Bearer {token}", "X-Ferrum-Namespace": NAMESPACE},
    )
    if status != 200:
        raise ScenarioFailure(f"GET /config/export with a viewer token answered {status}")
    leaked = [index for index, value in enumerate(plaintext) if value and value in body]
    if leaked:
        raise ScenarioFailure(
            f"the viewer export carried {len(leaked)} stored secret value(s) in plaintext"
        )
    consumers = {row.get("id"): row for row in json.loads(body).get("consumers", [])}
    consumer = consumers.get(CONTRACT_CONSUMER)
    if consumer is None:
        raise ScenarioFailure("the viewer export omitted the contract consumer")
    credentials = consumer.get("credentials", {})
    shape = {kind: sorted(entry) for kind, entries in credentials.items() for entry in entries}
    expected = {"keyauth": ["key"], "jwt": ["secret"], "hmac_auth": ["secret"], "mtls_auth": ["identity"]}
    fingerprinted = [
        credentials.get("keyauth", [{}])[0].get("key", ""),
        credentials.get("jwt", [{}])[0].get("secret", ""),
        credentials.get("hmac_auth", [{}])[0].get("secret", ""),
        consumer.get("hidden_credentials_fingerprint", ""),
    ]
    if (
        shape != expected
        or not all(_FINGERPRINT.match(str(value)) for value in fingerprinted)
        or credentials["mtls_auth"][0]["identity"] != CONTRACT_MTLS_IDENTITY
    ):
        raise ScenarioFailure(
            f"the viewer export projected the contract consumer's credentials as {shape}; "
            "GitForgeOps expects one fingerprinted keyauth key, jwt and hmac_auth secret, the "
            "visible mtls identity, no basicauth, and a hidden_credentials_fingerprint"
        )
    return token


def _export_projection(harness: Harness) -> str:
    """`config_export.rs`'s closed Consumer projection against `GET /config/export`.

    A consumer with every credential type (basicauth is omitted by the export,
    mtls identities stay visible, the rest are fingerprinted) must compare in
    sync through the viewer-credential export. Its fingerprints must be in
    the recorded baseline and verify, a secret rotated on the gateway must be
    reported as a fingerprint change, and an out-of-band edit as drift.
    """
    viewer = os.environ.get("GITFORGEOPS_LIFECYCLE_VIEWER_SECRET", "")
    if not viewer:
        raise ScenarioFailure(
            "the gateway's viewer secret is unknown (GITFORGEOPS_LIFECYCLE_VIEWER_SECRET; with "
            "LIFECYCLE_GATEWAY_EXTERNAL=1 pass it as LIFECYCLE_VIEWER_SECRET); harness failure"
        )
    harness.remember_secret(viewer)
    creds_path = Path(harness.creds_file)
    original = creds_path.read_text(encoding="utf-8")
    creds = json.loads(original)
    seeded = _contract_credentials(harness)
    creds["FERRUM_CREDS_BUNDLE"].update(seeded)
    creds_path.write_text(json.dumps(creds), encoding="utf-8")
    consumer = f"resources/{NAMESPACE}/consumers/{CONTRACT_CONSUMER}.yaml"
    harness.write(consumer, f"""
        kind: Consumer
        spec:
          id: "{CONTRACT_CONSUMER}"
          username: "{CONTRACT_CONSUMER}"
          credentials:
            keyauth:
              - key: "${{gh-env-secret:alloc=require}}"
            jwt:
              - secret: "${{gh-env-secret:alloc=require}}"
            hmac_auth:
              - secret: "${{gh-env-secret:alloc=require}}"
            basicauth:
              - password: "${{gh-env-secret:alloc=require}}"
            mtls_auth:
              - identity: "{CONTRACT_MTLS_IDENTITY}"
    """)
    baseline = harness.workdir.parent / "contract-fingerprints.json"
    baseline.unlink(missing_ok=True)
    through_export = {"FERRUM_ADMIN_JWT_VIEWER_SECRET": viewer}
    try:
        harness.run("apply", "--auto-approve")
        _viewer_export(harness, viewer, [*seeded.values(), harness_key(harness)])
        first = harness.run("diff", "--exit-on-drift", expect=None, **through_export)
        if "GET /config/export" not in first.stdout + first.stderr:
            raise ScenarioFailure("diff with the viewer secret did not read GET /config/export")
        if first.returncode != 6:
            raise ScenarioFailure(
                f"the export comparison exited {first.returncode}, expected in sync with "
                f"unverified secrets (6)\n{first.stdout}\n{first.stderr}"
            )
        recorded = harness.run(
            "diff", "--exit-on-drift", "--write-fingerprint-baseline", str(baseline),
            expect=None, **through_export,
        )
        if recorded.returncode not in (0, 6) or not baseline.is_file():
            raise ScenarioFailure(
                f"recording the fingerprint baseline exited {recorded.returncode}\n"
                f"{recorded.stdout}\n{recorded.stderr}"
            )
        sites = (
            json.loads(baseline.read_text(encoding="utf-8"))
            .get("namespaces", {}).get(NAMESPACE, {}).get("resources", {})
            .get("Consumer", {}).get(CONTRACT_CONSUMER, {})
        )
        missing = sorted(_CONTRACT_FINGERPRINT_SITES - set(sites))
        if missing or not all(_FINGERPRINT.match(str(sites[site])) for site in sorted(sites)):
            raise ScenarioFailure(
                f"the fingerprint baseline does not cover the contract consumer's secrets "
                f"(missing {missing})"
            )
        harness.run(
            "diff", "--exit-on-drift", "--fingerprint-baseline", str(baseline),
            expect=0, **through_export,
        )
        mutate_proxy_out_of_band(harness)
        harness.run(
            "diff", "--exit-on-drift", "--fingerprint-baseline", str(baseline),
            expect=2, **through_export,
        )
        ensure_deployed(harness)
        _admin(
            harness, "PUT", f"/consumers/{CONTRACT_CONSUMER}/credentials/jwt",
            [{"secret": _disposable_secret(harness)}], expect=(200, 202, 204),
        )
        rotated = harness.run(
            "diff", "--exit-on-drift", "--fingerprint-baseline", str(baseline),
            expect=None, **through_export,
        )
        if rotated.returncode != 2 or "/credentials/jwt/0/secret" not in rotated.stdout:
            raise ScenarioFailure(
                f"a jwt secret rotated on the gateway exited {rotated.returncode}; GitForgeOps "
                "expects drift (2) naming /credentials/jwt/0/secret\n"
                f"{rotated.stdout}\n{rotated.stderr}"
            )
    finally:
        baseline.unlink(missing_ok=True)
        harness.remove(consumer)
        creds_path.write_text(original, encoding="utf-8")
        ensure_deployed(harness)
    return "the viewer export withheld every secret, and its fingerprints verified and caught a rotation"


def _schemeless_http_proxies() -> list[dict]:
    """HTTP-family proxies with no `backend_scheme`, one per dial shape."""
    return [
        {"id": "contract-scheme-443", "listen_path": "/contract-scheme-443",
         "backend_host": "127.0.0.1", "backend_port": 443},
        {"id": "contract-scheme-80", "listen_path": "/contract-scheme-80",
         "backend_host": "127.0.0.1", "backend_port": 80},
        {"id": "contract-scheme-upstream", "listen_path": "/contract-scheme-upstream",
         "upstream_id": "orders-upstream"},
    ]


CONTRACT_STREAM_PROXY = "contract-scheme-stream"


def _stream_proxy(scheme: str | None) -> dict:
    proxy = {"id": CONTRACT_STREAM_PROXY, "listen_port": 18923,
             "backend_host": "127.0.0.1", "backend_port": 1}
    if scheme:
        proxy["backend_scheme"] = scheme
    return proxy


def _backend_scheme_derivation(harness: Harness) -> str:
    """`normalize_proxy_backend_schemes` (assembler.rs) against Edge's own derivation.

    GitForgeOps fills an omitted HTTP-family scheme before sending, so no
    other scenario sees what Edge derives (`Proxy::effective_scheme`). Here
    Edge stores each proxy written WITHOUT a scheme, and `diff` must find it
    equal to the same proxy declared without one. A stream proxy without a
    scheme is left alone by GitForgeOps; Edge and `gitforgeops validate` must
    both refuse it, and both accept it with one.
    """
    files = []
    try:
        for proxy in _schemeless_http_proxies():
            relative = f"resources/{NAMESPACE}/proxies/{proxy['id']}.yaml"
            harness.write(relative, json.dumps({"kind": "Proxy", "spec": proxy}))
            files.append(relative)
        harness.run("apply", "--auto-approve")
        derived = {}
        for proxy in _schemeless_http_proxies():
            _admin(harness, "PUT", f"/proxies/{proxy['id']}", dict(proxy, namespace=NAMESPACE))
            status, _, body = _admin_exchange(harness, "GET", f"/proxies/{proxy['id']}")
            derived[proxy["id"]] = json.loads(body).get("backend_scheme") if status == 200 else status
        compared = harness.run("diff", "--exit-on-drift", expect=None)
        if compared.returncode != 0:
            raise ScenarioFailure(
                f"Edge derived {derived} for proxies written without backend_scheme, and diff "
                f"exited {compared.returncode} against the same proxies normalized by "
                f"GitForgeOps\n{compared.stdout}\n{compared.stderr}"
            )

        stream = f"resources/{NAMESPACE}/proxies/{CONTRACT_STREAM_PROXY}.yaml"
        files.append(stream)
        status, _, _ = _admin_exchange(harness, "POST", "/proxies", _stream_proxy(None))
        if status != 400:
            if status in (200, 201):
                _admin(harness, "DELETE", f"/proxies/{CONTRACT_STREAM_PROXY}")
            raise ScenarioFailure(f"a stream proxy without backend_scheme answered {status}, expected 400")
        _admin(harness, "POST", "/proxies", _stream_proxy("tcp"))
        _admin(harness, "DELETE", f"/proxies/{CONTRACT_STREAM_PROXY}")
        harness.write(stream, json.dumps({"kind": "Proxy", "spec": _stream_proxy("tcp")}))
        harness.run("validate")
        harness.write(stream, json.dumps({"kind": "Proxy", "spec": _stream_proxy(None)}))
        if harness.run("validate", expect=None).returncode == 0:
            raise ScenarioFailure("gitforgeops validate accepted a stream proxy without backend_scheme")
    finally:
        for relative in files:
            harness.remove(relative)
        ensure_deployed(harness)
    return f"Edge's derived backend schemes {sorted(set(map(str, derived.values())))} match GitForgeOps' normalization"


def scenario_edge_contract_copies(harness: Harness) -> str:
    ensure_deployed(harness)
    return "; ".join(
        (
            _json_object_rules(harness),
            _backend_scheme_derivation(harness),
            _restore_semantics(harness),
            _backup_round_trip(harness),
            _export_projection(harness),
        )
    )


SCENARIOS = {
    "create-and-route": scenario_create_and_route,
    "reapply-is-a-no-op": scenario_reapply_is_a_no_op,
    "modify-and-delete-in-order": scenario_modify_and_delete_in_order,
    "conditional-overwrite": scenario_conditional_overwrite,
    "conditional-full-replace": scenario_conditional_full_replace,
    "credentials-generate-and-rotate": scenario_credentials_generate_and_rotate,
    "partial-failure-recovery": scenario_partial_failure_recovery,
    "ledger-publication-failure": scenario_ledger_publication_failure,
    "runner-interruption": scenario_runner_interruption,
    "scheduling-and-attribution": scenario_scheduling_and_attribution,
    "staged-promotion": scenario_staged_promotion,
    "drift-monitoring": scenario_drift_monitoring,
    "file-and-mesh-boundary": scenario_file_and_mesh_boundary,
    "edge-contract-copies": scenario_edge_contract_copies,
}


# -- gateway helpers ---------------------------------------------------------


def harness_key(harness: Harness) -> str:
    """The consumer key this run seeded, remembered for redaction."""
    key = os.environ["GITFORGEOPS_LIFECYCLE_CONSUMER_KEY"]
    harness.remember_secret(key)
    return key


def _admin(
    harness: Harness,
    method: str,
    path: str,
    body: dict | None = None,
    expect: tuple[int, ...] = (200, 201, 204),
) -> int:
    """An out-of-band admin call, standing in for a human administrator.

    It ASSERTS its outcome. A silently failed admin call is the worst kind of
    harness bug: the scenario carries on and draws a confident, wrong
    conclusion from a gateway that was never touched — on one run this suite
    reported "shared mode deleted a resource this repository never declared"
    when in truth the resource had never been created.
    """
    status = __admin(harness, method, path, body)
    if status not in expect:
        raise ScenarioFailure(
            f"the harness's own out-of-band {method} {path} answered {status}, "
            f"expected one of {expect}. This is a harness failure, not a "
            "finding about gitforgeops."
        )
    return status


def __admin(harness: Harness, method: str, path: str, body: dict | None = None) -> int:
    status, _, _ = _admin_exchange(harness, method, path, body)
    return status


def _admin_exchange(
    harness: Harness,
    method: str,
    path: str,
    body: dict | None = None,
    if_match: str | None = None,
) -> tuple[int, str | None, str]:
    """An out-of-band admin call returning its status, `ETag` and body.

    For the conditional-write probe, whose outcomes (a 412 included) are the
    findings, so it asserts nothing itself. `if_match` is sent verbatim.
    """
    token = os.environ["GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN"]
    # Register the token actually supplied, including one changed since init.
    harness.remember_secret(token)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Ferrum-Namespace": NAMESPACE,
    }
    if if_match is not None:
        headers["If-Match"] = if_match
    return _safe_exchange(
        f"{harness.gateway_url}{path}", method=method, headers=headers, body=body
    )


def create_unmanaged_proxy(harness: Harness) -> None:
    _admin(
        harness,
        "POST",
        "/proxies",
        {
            "id": "admin-owned-proxy",
            "name": "Created by a human, not by this repository",
            "listen_path": "/admin-owned",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 1,
            "namespace": NAMESPACE,
        },
    )


def unmanaged_proxy_exists(harness: Harness) -> bool:
    # A plain read: 404 is a legitimate answer here, and is the finding.
    return __admin(harness, "GET", "/proxies/admin-owned-proxy") == 200


OUT_OF_BAND_PROXY_NAME = "Edited on the gateway, behind the repository's back"


def out_of_band_proxy(name: str) -> dict:
    """The orders proxy as an administrator rewrites it, outside the repository."""
    return {
        "id": "orders-proxy",
        "name": name,
        "listen_path": "/orders",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 1,
        "namespace": NAMESPACE,
    }


def mutate_proxy_out_of_band(harness: Harness) -> None:
    _admin(
        harness,
        "PUT",
        "/proxies/orders-proxy",
        out_of_band_proxy(OUT_OF_BAND_PROXY_NAME),
    )


# -- driver ------------------------------------------------------------------


def run_scenarios(harness: Harness, result_path: Path, only: list[str]) -> int:
    failures = 0
    for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
        if only and identifier not in only:
            continue
        scenario = SCENARIOS[identifier]
        try:
            detail = scenario(harness)
            status, detail = lifecycle_result.PASSED, detail
        except NotImplementedError as reason:
            status, detail = lifecycle_result.SKIPPED, str(reason)
        except ScenarioFailure as error:
            status, detail = lifecycle_result.FAILED, str(error)
            failures += 1
        except Exception as error:  # noqa: BLE001 - a crash is a failed scenario
            status = lifecycle_result.FAILED
            detail = f"{type(error).__name__}: {error}"
            failures += 1
        detail = harness.redact(detail)
        print(f"{status:<8} {identifier}: {detail.splitlines()[0] if detail else ''}")
        if status == lifecycle_result.FAILED:
            print(textwrap.indent(detail, "         "))
        result = lifecycle_result.load(result_path)
        lifecycle_result.save(
            result_path,
            lifecycle_result.record(result, identifier, status, detail.splitlines()[0] if detail else ""),
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--gateway-url", required=True, help="admin API base URL")
    parser.add_argument("--proxy-url", required=True, help="data-plane base URL")
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--binary", default="gitforgeops")
    parser.add_argument(
        "--creds-file",
        required=True,
        help="credential bundle the seeded alloc=require slot resolves from",
    )
    parser.add_argument(
        "--only", action="append", default=[], choices=lifecycle_result.REQUIRED_SCENARIO_IDS
    )
    args = parser.parse_args(argv)

    if shutil.which(args.binary) is None and not Path(args.binary).is_file():
        print(f"::error::{args.binary} is not on PATH", file=sys.stderr)
        return 1

    harness = Harness(
        workdir=Path(args.workdir),
        gateway_url=args.gateway_url,
        proxy_url=args.proxy_url,
        upstream_url=args.upstream_url,
        binary=args.binary,
        creds_file=args.creds_file,
    )
    harness.workdir.mkdir(parents=True, exist_ok=True)
    return 1 if run_scenarios(harness, Path(args.result), args.only) else 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
