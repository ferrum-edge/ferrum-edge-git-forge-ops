"""The harness's own contract, exercised without a gateway.

The scenarios need a real Ferrum Edge to say anything about the product. The
*harness* does not, and three of its properties are load-bearing enough that a
gateway-less CI should still be proving them:

* a scenario that crashes is a FAILED scenario, not a lost one;
* a scenario that cannot run is SKIPPED, which never certifies anything;
* nothing the harness captures may carry a credential into a log or a record.
"""

import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import threading
import traceback
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.response import addinfourl


ROOT = Path(__file__).parents[3]

SPEC = importlib.util.spec_from_file_location(
    "lifecycle_result", ROOT / ".github/scripts/lifecycle_result.py"
)
lifecycle_result = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lifecycle_result
SPEC.loader.exec_module(lifecycle_result)

SCENARIO_SPEC = importlib.util.spec_from_file_location(
    "lifecycle_scenarios", ROOT / "tests/lifecycle/scenarios.py"
)
scenarios = importlib.util.module_from_spec(SCENARIO_SPEC)
sys.modules[SCENARIO_SPEC.name] = scenarios
SCENARIO_SPEC.loader.exec_module(scenarios)

SECRET = "an-actual-consumer-key-value-here"
# Cover the known statuses and any other redirect supported by the interpreter.
REDIRECT_CODES = tuple(
    sorted(
        {301, 302, 303, 307, 308}
        | {
            int(name.removeprefix("http_error_"))
            for name in dir(scenarios.urllib.request.HTTPRedirectHandler)
            if re.fullmatch(r"http_error_3\d{2}", name)
        }
    )
)


def harness(workdir: Path) -> "scenarios.Harness":
    return scenarios.Harness(
        workdir=workdir,
        gateway_url="http://127.0.0.1:18080",
        proxy_url="http://127.0.0.1:18081",
        upstream_url="http://127.0.0.1:18082",
        binary="gitforgeops",
        creds_file="/tmp/creds.json",
    )


@contextmanager
def loopback_server(status=200, location=None, body=b"{}", etag='"live-row"', uri=None):
    """Record actual HTTP requests without logging any test credentials."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self):
            length = int(self.headers.get("Content-Length", "0"))
            requests.append(
                (self.command, self.path, dict(self.headers), self.rfile.read(length))
            )
            # If a redirect is followed on this server, make it succeed so
            # the test can distinguish the redirected request from its origin.
            code = 200 if self.path == "/redirected" else status
            self.send_response(code)
            if location is not None and code != 200:
                self.send_header("Location", location)
            if uri is not None and code != 200:
                self.send_header("URI", uri)
            self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = respond
        do_POST = respond
        do_PUT = respond
        do_DELETE = respond

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


class TransportTests(unittest.TestCase):
    ENTRY_POINTS = ("admin-status", "admin-exchange", "traffic")

    def call(self, instance, entry_point):
        if entry_point == "admin-status":
            return getattr(scenarios, "__admin")(instance, "GET", "/probe")
        if entry_point == "admin-exchange":
            return scenarios._admin_exchange(instance, "GET", "/probe")[0]
        return instance.request("/probe", {"Authorization": f"Bearer {SECRET}"})

    def assert_failed_capture(self, instance, result_path, implementation, expected_detail):
        lifecycle_result.save(result_path, lifecycle_result.empty_result())
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.dict(scenarios.SCENARIOS, {"create-and-route": implementation}),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            failures = scenarios.run_scenarios(instance, result_path, ["create-and-route"])
        written = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(failures, 1)
        self.assertNotIn(SECRET, output.getvalue() + errors.getvalue() + json.dumps(written))
        entry = written["scenarios"]["create-and-route"]
        self.assertEqual(entry["status"], lifecycle_result.FAILED)
        self.assertEqual(entry["detail"], expected_detail)

    def assert_redirects_refused(self, same_origin):
        with tempfile.TemporaryDirectory() as directory, loopback_server() as target:
            target_url, target_requests = target
            location = "/redirected" if same_origin else f"{target_url}/redirected"
            instance = harness(Path(directory))
            with patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}):
                for code in REDIRECT_CODES:
                    with loopback_server(code, location) as origin:
                        origin_url, origin_requests = origin
                        instance.gateway_url = origin_url
                        instance.proxy_url = origin_url
                        for entry_point in self.ENTRY_POINTS:
                            with self.subTest(code=code, entry_point=entry_point):
                                origin_requests.clear()
                                self.assertEqual(self.call(instance, entry_point), code)
                                self.assertEqual(len(origin_requests), 1)
                                _, path, headers, _ = origin_requests[0]
                                self.assertEqual(path, "/probe")
                                self.assertEqual(headers["Authorization"], f"Bearer {SECRET}")
                                self.assertEqual(target_requests, [])

    def test_same_origin_redirects_never_receive_credentials(self):
        self.assert_redirects_refused(same_origin=True)

    def test_cross_origin_redirects_never_receive_credentials(self):
        self.assert_redirects_refused(same_origin=False)

    def test_malformed_redirect_headers_never_reach_a_parser_or_leak_into_capture(self):
        targets = (
            f"http://[{SECRET}]/",
            f"https://[{SECRET}]/",
            f"//[{SECRET}]/",
            f"file:///{SECRET}",
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
        ):
            root = Path(directory)
            instance = harness(root)
            # Non-redirect 3xx statuses must also bypass redirect processing.
            for code in (*REDIRECT_CODES, 300, 304, 399):
                for header in ("location", "uri"):
                    for target in targets:
                        with loopback_server(code, **{header: target}) as origin:
                            origin_url, requests = origin
                            instance.gateway_url = origin_url
                            instance.proxy_url = origin_url
                            for entry_point in self.ENTRY_POINTS:
                                with self.subTest(
                                    code=code, header=header, entry_point=entry_point
                                ):
                                    requests.clear()
                                    self.assertEqual(self.call(instance, entry_point), code)
                                    self.assertEqual(len(requests), 1)
                                    self.assertEqual(requests[0][1], "/probe")

                                    def refused(current):
                                        status = self.call(current, entry_point)
                                        raise scenarios.ScenarioFailure(
                                            f"redirect refused with status {status}"
                                        )

                                    requests.clear()
                                    self.assert_failed_capture(
                                        instance,
                                        root / "result.json",
                                        refused,
                                        f"redirect refused with status {code}",
                                    )
                                    self.assertEqual(len(requests), 1)
                                    self.assertEqual(requests[0][1], "/probe")

    def test_https_malformed_redirects_never_start_a_second_exchange(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
            patch.object(scenarios.urllib.request, "getproxies", return_value={}),
        ):
            instance = harness(Path(directory))
            instance.gateway_url = instance.proxy_url = "https://gateway.example"
            for code in REDIRECT_CODES:
                for header in ("Location", "URI"):
                    for entry_point in self.ENTRY_POINTS:
                        with self.subTest(code=code, header=header, entry_point=entry_point):
                            headers = Message()
                            headers[header] = f"http://[{SECRET}]/"
                            response = addinfourl(
                                io.BytesIO(b"{}"), headers, "https://gateway.example/probe", code
                            )
                            response.msg = "redirect"
                            with patch.object(
                                scenarios.urllib.request.HTTPSHandler,
                                "https_open",
                                return_value=response,
                            ) as exchange:
                                self.assertEqual(self.call(instance, entry_point), code)
                                exchange.assert_called_once()

    def test_transport_and_parser_errors_withhold_backend_controlled_details(self):
        reflected_url = f"http://[{SECRET}]/backend-controlled"
        errors = (
            scenarios.urllib.error.URLError(reflected_url),
            ValueError(reflected_url),
            OSError(reflected_url),
            scenarios.http.client.BadStatusLine(reflected_url),
        )
        expected = "lifecycle HTTP exchange failed; target and backend details withheld"
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
        ):
            root = Path(directory)
            instance = harness(root)
            for error in errors:
                for phase in ("open", "read"):
                    for entry_point in self.ENTRY_POINTS:
                        with self.subTest(
                            error=type(error).__name__, phase=phase, entry_point=entry_point
                        ):
                            with patch.object(scenarios.urllib.request, "build_opener") as opener:
                                if phase == "open":
                                    opener.return_value.open.side_effect = error
                                else:
                                    response = opener.return_value.open.return_value
                                    response.read.side_effect = error
                                with self.assertRaises(scenarios.ScenarioFailure) as failure:
                                    self.call(instance, entry_point)
                                self.assertEqual(str(failure.exception), expected)
                                trace = "".join(traceback.format_exception(failure.exception))
                                self.assertNotIn(SECRET, trace)
                                self.assertNotIn(reflected_url, trace)
                                self.assert_failed_capture(
                                    instance,
                                    root / "result.json",
                                    lambda current: self.call(current, entry_point),
                                    expected,
                                )

    def test_admin_redirects_never_forward_mutation_bodies(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            loopback_server() as target,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
        ):
            target_url, target_requests = target
            instance = harness(Path(directory))
            body = {"credentials": {"keyauth": [{"key": SECRET}]}}
            for code in REDIRECT_CODES:
                with loopback_server(code, f"{target_url}/redirected") as origin:
                    origin_url, origin_requests = origin
                    instance.gateway_url = origin_url
                    for method in ("POST", "PUT", "DELETE"):
                        for helper in (
                            getattr(scenarios, "__admin"),
                            scenarios._admin_exchange,
                        ):
                            with self.subTest(code=code, method=method, helper=helper.__name__):
                                origin_requests.clear()
                                result = helper(instance, method, "/consumers", body)
                                status = result[0] if isinstance(result, tuple) else result
                                self.assertEqual(status, code)
                                self.assertEqual(len(origin_requests), 1)
                                self.assertEqual(origin_requests[0][0], method)
                                self.assertEqual(json.loads(origin_requests[0][3]), body)
                                self.assertEqual(target_requests, [])

    def test_unsafe_targets_are_refused_before_request_construction(self):
        targets = (
            "http://localhost:18080",
            "http://gateway.example:18080",
            "http://192.0.2.1:18080",
            "http://[::ffff:127.0.0.1]:18080",
            "http://[::ffff:7f00:1]:18080",
            "http://127.0.0.1.example:18080",
            "http://2130706433:18080",
            "http://[::1%25interface]:18080",
            f"https://user:{SECRET}@gateway.example",
            "https://gateway.example:invalid",
            "http://127.0.0.1:18080\n",
            "ftp://127.0.0.1:18080",
        )
        with tempfile.TemporaryDirectory() as directory:
            instance = harness(Path(directory))
            with (
                patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
                patch.object(scenarios.urllib.request, "build_opener") as build_opener,
                patch.object(scenarios.urllib.request, "Request") as request,
            ):
                for target in targets:
                    instance.gateway_url = target
                    instance.proxy_url = target
                    for entry_point in self.ENTRY_POINTS:
                        with self.subTest(target=target, entry_point=entry_point):
                            with self.assertRaises(scenarios.ScenarioFailure) as failure:
                                self.call(instance, entry_point)
                            self.assertIn("literal loopback", str(failure.exception))
                            self.assertNotIn(SECRET, str(failure.exception))
                            build_opener.assert_not_called()
                            request.assert_not_called()

    def test_harness_preflight_refuses_unsafe_admin_and_traffic_urls(self):
        for field in ("gateway_url", "proxy_url"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                inputs = {
                    "workdir": Path(directory),
                    "gateway_url": "http://127.0.0.1:18080",
                    "proxy_url": "http://127.0.0.1:18081",
                    "upstream_url": "http://127.0.0.1:18082",
                    "binary": "gitforgeops",
                    "creds_file": "/tmp/creds.json",
                }
                inputs[field] = "http://gateway.example:18080"
                with self.assertRaises(scenarios.ScenarioFailure):
                    scenarios.Harness(**inputs)

    def test_plaintext_loopback_ignores_environment_and_global_opener_proxies(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            loopback_server() as proxy,
            loopback_server() as target,
        ):
            proxy_url, proxy_requests = proxy
            target_url, target_requests = target
            instance = harness(Path(directory))
            instance.gateway_url = target_url
            instance.proxy_url = target_url
            environment = {
                "GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET,
                "http_proxy": proxy_url,
                "HTTP_PROXY": proxy_url,
                "https_proxy": proxy_url,
                "HTTPS_PROXY": proxy_url,
                "all_proxy": proxy_url,
                "ALL_PROXY": proxy_url,
                "no_proxy": "",
                "NO_PROXY": "",
            }
            unsafe_opener = scenarios.urllib.request.build_opener(
                scenarios.urllib.request.ProxyHandler({"http": proxy_url})
            )
            with (
                patch.dict(os.environ, environment),
                patch.object(scenarios.urllib.request, "_opener", unsafe_opener),
                patch.object(scenarios.urllib.request, "proxy_bypass", return_value=False),
            ):
                for entry_point in self.ENTRY_POINTS:
                    with self.subTest(entry_point=entry_point):
                        target_requests.clear()
                        self.assertEqual(self.call(instance, entry_point), 200)
                        self.assertEqual(len(target_requests), 1)
                        self.assertEqual(
                            target_requests[0][2]["Authorization"], f"Bearer {SECRET}"
                        )
                        self.assertEqual(proxy_requests, [])

    def test_https_and_both_literal_loopback_families_are_permitted(self):
        for target in (
            "https://gateway.example:443/admin",
            "http://127.0.0.1:18080",
            "http://127.23.45.67:18080",
            "http://[::1]:18080",
        ):
            with self.subTest(target=target):
                self.assertEqual(scenarios._credential_target(target), target)
        with patch.object(scenarios.urllib.request, "build_opener") as build_opener:
            response = build_opener.return_value.open.return_value
            response.read.return_value = b"{}"
            response.code = 200
            response.headers.get.return_value = '"tls-row"'
            result = scenarios._safe_exchange(
                "https://gateway.example/probe", headers={"Authorization": f"Bearer {SECRET}"}
            )
            self.assertEqual(result, (200, '"tls-row"', "{}"))
            request = build_opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://gateway.example/probe")
            self.assertEqual(request.get_header("Authorization"), f"Bearer {SECRET}")

    def test_admin_exchange_preserves_conditional_metadata_and_error_body(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            loopback_server(412, body=b'{"error":"stale"}', etag='"current"') as target,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
        ):
            target_url, requests = target
            instance = harness(Path(directory))
            instance.gateway_url = target_url
            body = {"id": "orders-proxy", "namespace": scenarios.NAMESPACE}
            result = scenarios._admin_exchange(
                instance, "PUT", "/proxies/orders-proxy", body, if_match='"planned"'
            )
            self.assertEqual(result, (412, '"current"', '{"error":"stale"}'))
            self.assertEqual(len(requests), 1)
            method, path, headers, sent = requests[0]
            self.assertEqual((method, path), ("PUT", "/proxies/orders-proxy"))
            self.assertEqual(headers["If-Match"], '"planned"')
            self.assertEqual(headers["X-Ferrum-Namespace"], scenarios.NAMESPACE)
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(json.loads(sent), body)

    def test_status_only_admin_helper_still_returns_a_genuine_404(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            loopback_server(404) as target,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
        ):
            target_url, requests = target
            instance = harness(Path(directory))
            instance.gateway_url = target_url
            self.assertFalse(scenarios.unmanaged_proxy_exists(instance))
            self.assertEqual(len(requests), 1)


class RedactionTests(unittest.TestCase):
    def test_the_admin_token_is_remembered_before_any_exchange(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
        ):
            instance = harness(Path(directory))
            self.assertEqual(instance.redact(f"admin token {SECRET}"), "admin token [REDACTED]")

    def test_a_newly_supplied_admin_token_is_redacted_independently_of_transport_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for status in (
                lifecycle_result.PASSED,
                lifecycle_result.SKIPPED,
                lifecycle_result.FAILED,
            ):
                with self.subTest(status=status):
                    with patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": ""}):
                        instance = harness(root)
                    result_path = root / "result.json"
                    lifecycle_result.save(result_path, lifecycle_result.empty_result())

                    def reflected(current):
                        scenarios._admin_exchange(current, "GET", "/probe")
                        detail = f"gateway reflected admin token {SECRET}"
                        if status == lifecycle_result.SKIPPED:
                            raise NotImplementedError(detail)
                        if status == lifecycle_result.FAILED:
                            raise RuntimeError(detail)
                        return detail

                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        patch.dict(os.environ, {"GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN": SECRET}),
                        patch.object(scenarios, "_safe_exchange", return_value=(200, None, "{}")),
                        patch.dict(scenarios.SCENARIOS, {"create-and-route": reflected}),
                        redirect_stdout(output),
                        redirect_stderr(errors),
                    ):
                        failures = scenarios.run_scenarios(
                            instance, result_path, ["create-and-route"]
                        )
                    written = json.loads(result_path.read_text(encoding="utf-8"))
                    self.assertEqual(failures, int(status == lifecycle_result.FAILED))
                    entry = written["scenarios"]["create-and-route"]
                    self.assertEqual(entry["status"], status)
                    self.assertIn("[REDACTED]", entry["detail"])
                    self.assertNotIn(
                        SECRET, output.getvalue() + errors.getvalue() + json.dumps(written)
                    )

    def test_a_remembered_secret_never_survives_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = harness(Path(directory))
            instance.remember_secret(SECRET)
            self.assertEqual(
                instance.redact(f"Authorization failed for key {SECRET} on /orders"),
                "Authorization failed for key [REDACTED] on /orders",
            )

    def test_a_value_too_short_to_redact_is_never_remembered(self):
        # A needle shorter than 8 bytes cannot be substring-replaced without
        # mangling unrelated output — the same floor the validator scrubber
        # uses. Remembering one would corrupt every report that contains it.
        with tempfile.TemporaryDirectory() as directory:
            instance = harness(Path(directory))
            instance.remember_secret("abc")
            self.assertEqual(instance.redact("abc appears here"), "abc appears here")

    def test_a_failing_scenario_records_a_redacted_detail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "result.json"
            lifecycle_result.save(result_path, lifecycle_result.empty_result())

            instance = harness(root)
            instance.remember_secret(SECRET)
            original = scenarios.SCENARIOS["create-and-route"]

            def leaky(_harness):
                raise scenarios.ScenarioFailure(f"gateway rejected {SECRET}")

            scenarios.SCENARIOS["create-and-route"] = leaky
            try:
                failures = scenarios.run_scenarios(
                    instance, result_path, ["create-and-route"]
                )
            finally:
                scenarios.SCENARIOS["create-and-route"] = original

            written = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(failures, 1)
        entry = written["scenarios"]["create-and-route"]
        self.assertEqual(entry["status"], lifecycle_result.FAILED)
        self.assertNotIn(SECRET, json.dumps(written))
        self.assertIn("[REDACTED]", entry["detail"])


class StatusMappingTests(unittest.TestCase):
    def _run_one(self, identifier, implementation):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "result.json"
            lifecycle_result.save(result_path, lifecycle_result.empty_result())
            original = scenarios.SCENARIOS[identifier]
            scenarios.SCENARIOS[identifier] = implementation
            try:
                failures = scenarios.run_scenarios(
                    harness(root), result_path, [identifier]
                )
            finally:
                scenarios.SCENARIOS[identifier] = original
            written = json.loads(result_path.read_text(encoding="utf-8"))
        return failures, written["scenarios"][identifier]

    def test_a_crash_is_a_failed_scenario_not_a_lost_one(self):
        # A scenario that raises an unexpected exception must not vanish from
        # the record — an absent scenario and a failing one look identical to
        # anyone reading "no failures reported".
        def crashes(_harness):
            raise KeyError("orders-proxy")

        failures, entry = self._run_one("reapply-is-a-no-op", crashes)
        self.assertEqual(failures, 1)
        self.assertEqual(entry["status"], lifecycle_result.FAILED)
        self.assertIn("KeyError", entry["detail"])

    def test_an_unrunnable_scenario_is_skipped_and_says_why(self):
        def unrunnable(_harness):
            raise NotImplementedError("needs a disposable GitHub repository")

        failures, entry = self._run_one("runner-interruption", unrunnable)
        # Skipped is not a failure of the run...
        self.assertEqual(failures, 0)
        self.assertEqual(entry["status"], lifecycle_result.SKIPPED)
        self.assertIn("disposable GitHub repository", entry["detail"])
        # ...and it is still not a pass.
        self.assertNotIn(entry["status"], lifecycle_result.AUTHORIZING)

    def test_a_passing_scenario_records_its_own_evidence(self):
        failures, entry = self._run_one(
            "drift-monitoring", lambda _harness: "drift (2) is distinguishable"
        )
        self.assertEqual(failures, 0)
        self.assertEqual(entry["status"], lifecycle_result.PASSED)
        self.assertIn("distinguishable", entry["detail"])


class IsolationTests(unittest.TestCase):
    def test_the_child_environment_is_built_not_inherited(self):
        # An inherited FERRUM_* from the operator's shell is how a "passing"
        # run ends up having tested a different gateway than it reports.
        with tempfile.TemporaryDirectory() as directory:
            instance = harness(Path(directory))
            previous = dict(os.environ)
            os.environ["FERRUM_GATEWAY_URL"] = "https://production.example.com"
            os.environ["FERRUM_NAMESPACE"] = "somebody-elses"
            os.environ["FERRUM_ADMIN_JWT_SECRET"] = "x" * 48
            os.environ["GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH"] = "true"
            try:
                built = instance.env()
            finally:
                os.environ.clear()
                os.environ.update(previous)

        self.assertEqual(built["FERRUM_GATEWAY_URL"], "http://127.0.0.1:18080")
        # Traffic verification reaches the DATA plane, which is a different
        # listener — pointing it at the admin API would get a 404 that looks
        # exactly like a routing failure.
        self.assertEqual(built["FERRUM_VERIFY_BASE_URL"], "http://127.0.0.1:18081")
        self.assertNotIn("FERRUM_NAMESPACE", built)
        # Stripping every FERRUM_* means anything the child genuinely needs
        # has to be supplied here. The credential bundle was the one that got
        # forgotten, and the symptom — "required credential slot has no
        # value" — points at the repository rather than at the harness.
        self.assertEqual(built["FERRUM_CREDS_JSON_FILE"], "/tmp/creds.json")
        self.assertNotIn("GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH", built)
        self.assertEqual(built["FERRUM_ENV"], scenarios.ENVIRONMENT)

    def test_client_traffic_goes_to_the_data_plane_not_the_admin_api(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = harness(Path(directory))
            self.assertNotEqual(instance.gateway_url, instance.proxy_url)
        source = (ROOT / "tests/lifecycle/scenarios.py").read_text(encoding="utf-8")
        # `request` is the client path; `_admin` is the human-admin path.
        client = source[source.index("def request(") : source.index("def expect_status(")]
        self.assertIn("self.proxy_url", client)
        self.assertNotIn("self.gateway_url", client)
        admin = source[source.index("def _admin(") : source.index("def create_unmanaged_proxy(")]
        self.assertIn("harness.gateway_url", admin)
        self.assertNotIn("harness.proxy_url", admin)

    def test_every_scenario_that_needs_a_gateway_deploys_to_it_first(self):
        # Scenarios mutate shared state — one of them deletes the proxy — and
        # `LIFECYCLE_ONLY` runs any single one alone. A scenario that assumes
        # what ran before it reports on the previous scenario's leftovers.
        source = (ROOT / "tests/lifecycle/scenarios.py").read_text(encoding="utf-8")
        for identifier in (
            "reapply_is_a_no_op",
            "modify_and_delete_in_order",
            "conditional_overwrite",
            "drift_monitoring",
        ):
            with self.subTest(scenario=identifier):
                start = source.index(f"def scenario_{identifier}(")
                body = source[start : source.index("\n\n\ndef ", start)]
                self.assertIn("ensure_deployed(harness)", body)
        # `create-and-route` seeds and applies as its own subject, and
        # `file-and-mesh-boundary` deliberately needs only the tree.
        start = source.index("def scenario_file_and_mesh_boundary(")
        body = source[start : source.index("\n\n\nSCENARIOS", start)]
        self.assertIn("seed_repository(harness)", body)
        self.assertNotIn("ensure_deployed(harness)", body)

    def test_the_stale_write_probe_sends_if_match_to_the_admin_api(self):
        # `conditional-overwrite` certifies the gateway half of the guarantee:
        # a write carrying a superseded entity-tag must be refused. The probe
        # has to send that tag, to the admin API, or it certifies nothing.
        source = (ROOT / "tests/lifecycle/scenarios.py").read_text(encoding="utf-8")
        exchange = source[
            source.index("def _admin_exchange(") : source.index("def create_unmanaged_proxy(")
        ]
        self.assertIn('headers["If-Match"] = if_match', exchange)
        self.assertIn("harness.gateway_url", exchange)
        self.assertNotIn("harness.proxy_url", exchange)
        start = source.index("def scenario_conditional_overwrite(")
        body = source[start : source.index("\n\n\ndef ", start)]
        self.assertIn("if_match=", body)
        self.assertIn("!= 412", body)

    def test_out_of_band_admin_calls_assert_their_own_outcome(self):
        # A silently failed admin call is the worst kind of harness bug: the
        # scenario carries on and draws a confident, wrong conclusion from a
        # gateway that was never touched. One run reported "shared mode
        # deleted a resource this repository never declared" when the resource
        # had simply never been created.
        source = (ROOT / "tests/lifecycle/scenarios.py").read_text(encoding="utf-8")
        self.assertIn("This is a harness failure, not a", source)
        checked = source[source.index("def _admin(") : source.index("def __admin(")]
        self.assertIn("raise ScenarioFailure", checked)

    def test_the_admin_token_carries_the_claims_the_product_mints(self):
        # A token missing `sub`, `nbf` or `jti` is rejected with a plain 401
        # that looks exactly like a wrong secret.
        minted = (ROOT / "tests/lifecycle/admin_token.py").read_text(encoding="utf-8")
        claims = set(
            re.findall(r'"(iss|sub|role|iat|nbf|exp|jti)":', minted)
        )
        rust = (ROOT / "src/jwt.rs").read_text(encoding="utf-8")
        body = rust[rust.index("struct Claims {") : rust.index("\n}", rust.index("struct Claims {"))]
        required = {
            name
            for name in re.findall(r"^    (\w+): ", body, re.MULTILINE)
            # `aud` and `ns` are `skip_serializing_if` — emitted only when
            # configured, and a stray one is itself a rejection.
            if name not in {"aud", "ns"}
        }
        self.assertEqual(required, claims)

    def test_the_upstream_never_echoes_a_request_header(self):
        # A proxied credential arriving at the upstream and being reflected
        # into a log is precisely the accident the suite must not have.
        source = (ROOT / "tests/lifecycle/upstream.py").read_text(encoding="utf-8")
        self.assertIn("def log_message", source)
        self.assertNotIn("self.headers", source)


class RunbookTests(unittest.TestCase):
    def test_the_runner_fails_loudly_without_a_gateway(self):
        # A suite that silently certifies nothing is worse than one that is
        # red: the release gate would read a full sheet of `skipped`.
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn("did not answer GET /health", runner)
        self.assertIn("exit 1", runner)

    def test_the_gateway_command_is_discovered_not_guessed(self):
        # A hard-coded subcommand is wrong exactly once — the moment Ferrum
        # Edge renames or removes it — and "unrecognized subcommand" tells the
        # reader nothing about what to use instead. The runner reads the
        # build's own `--help`, and says what it found when nothing answers.
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn('"$BINARY" --help', runner)
        self.assertIn("/^Commands:/", runner)
        self.assertIn("for candidate in serve server run start gateway", runner)
        # No serving subcommand at all falls back to the bare binary, because
        # a gateway configured entirely through FERRUM_* is the shape the
        # `-m file` / `-m mesh` validation surface implies.
        self.assertIn('GATEWAY_CMD="$BINARY"', runner)
        self.assertIn("Subcommands this build offers", runner)

    def test_the_runner_hands_the_bundle_to_the_driver(self):
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn('--creds-file "$CREDS"', runner)

    def test_the_runner_seals_even_on_failure(self):
        # An UNSEALED record reads as "the suite was cancelled". A suite that
        # ran and found problems is a different, louder thing.
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        seal = runner.index('lifecycle_result.py" seal')
        status = runner.index("SCENARIO_STATUS=$?")
        self.assertLess(status, seal, "the seal must follow the scenario run")
        self.assertIn('exit "$SCENARIO_STATUS"', runner)

    def test_the_runner_redacts_the_gateway_log_before_printing_it(self):
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn("[REDACTED]", runner)
        self.assertIn("FERRUM_ADMIN_JWT_SECRET", runner)

    def test_the_sqlite_store_is_created_inside_the_throwaway_workdir(self):
        # `?mode=rwc` is load-bearing: sqlx opens a SQLite URL read-write but
        # will not create a missing file without it, and the failure reads
        # like a permissions problem rather than a missing flag.
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn("sqlite://$WORKDIR/ferrum.db?mode=rwc", runner)
        self.assertIn('rm -rf "$WORKDIR"', runner)

    def test_the_runner_removes_everything_it_created(self):
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup EXIT", runner)
        self.assertIn('rm -rf "$WORKDIR"', runner)


if __name__ == "__main__":
    unittest.main()
