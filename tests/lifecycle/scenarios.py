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
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / ".github" / "scripts"))
import lifecycle_result  # noqa: E402  (path set above)


NAMESPACE = "ferrum"
ENVIRONMENT = "acceptance"


class ScenarioFailure(AssertionError):
    """A scenario's assertion did not hold."""


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
        self.gateway_url = gateway_url.rstrip("/")
        # The data plane. Serves traffic. A different listener on a different
        # port — sending a route check at the admin API would get a 404 that
        # looks exactly like a routing failure.
        self.proxy_url = proxy_url.rstrip("/")
        self.upstream_url = upstream_url.rstrip("/")
        self.binary = binary
        # The broker bundle the seeded `alloc=require` slot resolves from.
        # Passed in rather than inherited: `env()` strips every FERRUM_* it
        # did not set, so anything the child needs has to be supplied here.
        self.creds_file = creds_file
        # Every secret this run has seen, for `redact`. Populated as
        # credentials are allocated; never written to disk.
        self._secrets: set[str] = set()

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
        request = urllib.request.Request(
            f"{self.proxy_url}{path}", headers=headers or {}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except urllib.error.URLError as error:
            raise ScenarioFailure(f"{path} was unreachable: {error.reason}") from error

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
    # An unmanaged row the repository never declared must survive shared mode.
    create_unmanaged_proxy(harness)

    harness.write(
        f"resources/{NAMESPACE}/proxies/orders.yaml",
        (harness.workdir / f"resources/{NAMESPACE}/proxies/orders.yaml")
        .read_text(encoding="utf-8")
        .replace('name: "Orders API"', 'name: "Orders API v2"'),
    )
    harness.run("apply", "--auto-approve")

    # Deleting the proxy must not orphan its scoped plugin, and must happen in
    # an order the gateway accepts.
    harness.remove(f"resources/{NAMESPACE}/proxies/orders.yaml")
    harness.remove(f"resources/{NAMESPACE}/plugins/orders-key-auth.yaml")
    harness.run("apply", "--auto-approve")

    if not unmanaged_proxy_exists(harness):
        raise ScenarioFailure(
            "shared mode deleted a resource this repository never declared"
        )
    return "modify and delete succeeded in dependency order; unmanaged row survived"


def scenario_credentials_generate_and_rotate(harness: Harness) -> str:
    raise NotImplementedError(
        "needs a disposable GitHub Environment for the credential broker; run "
        "through tests/lifecycle/github_acceptance.md"
    )


def scenario_partial_failure_recovery(harness: Harness) -> str:
    raise NotImplementedError(
        "needs the fault-injecting proxy in front of the admin API; see "
        "tests/lifecycle/README.md#injecting-failures"
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
    output = harness.workdir / "assembled" / "acceptance.yaml"
    harness.run(
        "export",
        "--output",
        str(output),
        FERRUM_GATEWAY_MODE="file",
    )
    if not output.is_file():
        raise ScenarioFailure("file-mode export wrote no document")
    text = output.read_text(encoding="utf-8")
    if "${gh-env-secret:" not in text:
        raise ScenarioFailure(
            "the exported document has no placeholder left, so it is not the "
            "commit-safe artifact export promises"
        )
    for secret in harness._secrets:  # noqa: SLF001 - the harness is the owner
        if secret in text:
            raise ScenarioFailure("a credential value reached the exported document")
    return "file-mode assembly preserves placeholders; assembly is not deployment"


SCENARIOS = {
    "create-and-route": scenario_create_and_route,
    "reapply-is-a-no-op": scenario_reapply_is_a_no_op,
    "modify-and-delete-in-order": scenario_modify_and_delete_in_order,
    "credentials-generate-and-rotate": scenario_credentials_generate_and_rotate,
    "partial-failure-recovery": scenario_partial_failure_recovery,
    "ledger-publication-failure": scenario_ledger_publication_failure,
    "runner-interruption": scenario_runner_interruption,
    "scheduling-and-attribution": scenario_scheduling_and_attribution,
    "staged-promotion": scenario_staged_promotion,
    "drift-monitoring": scenario_drift_monitoring,
    "file-and-mesh-boundary": scenario_file_and_mesh_boundary,
}


# -- gateway helpers ---------------------------------------------------------


def harness_key(harness: Harness) -> str:
    """The consumer key this run seeded, remembered for redaction."""
    key = os.environ["GITFORGEOPS_LIFECYCLE_CONSUMER_KEY"]
    harness.remember_secret(key)
    return key


def _admin(harness: Harness, method: str, path: str, body: dict | None = None) -> int:
    token = os.environ["GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN"]
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{harness.gateway_url}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Ferrum-Namespace": NAMESPACE,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


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
    return _admin(harness, "GET", "/proxies/admin-owned-proxy") == 200


def mutate_proxy_out_of_band(harness: Harness) -> None:
    _admin(
        harness,
        "PUT",
        "/proxies/orders-proxy",
        {
            "id": "orders-proxy",
            "name": "Edited on the gateway, behind the repository's back",
            "listen_path": "/orders",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 1,
            "namespace": NAMESPACE,
        },
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
            status, detail = lifecycle_result.FAILED, harness.redact(str(error))
            failures += 1
        except Exception as error:  # noqa: BLE001 - a crash is a failed scenario
            status = lifecycle_result.FAILED
            detail = harness.redact(f"{type(error).__name__}: {error}")
            failures += 1
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
