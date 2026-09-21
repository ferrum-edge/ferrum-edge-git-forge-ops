"""The harness's own contract, exercised without a gateway.

The scenarios need a real Ferrum Edge to say anything about the product. The
*harness* does not, and three of its properties are load-bearing enough that a
gateway-less CI should still be proving them:

* a scenario that crashes is a FAILED scenario, not a lost one;
* a scenario that cannot run is SKIPPED, which never certifies anything;
* nothing the harness captures may carry a credential into a log or a record.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


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


def harness(workdir: Path) -> "scenarios.Harness":
    return scenarios.Harness(
        workdir=workdir,
        gateway_url="http://127.0.0.1:18080",
        proxy_url="http://127.0.0.1:18081",
        upstream_url="http://127.0.0.1:18082",
        binary="gitforgeops",
    )


class RedactionTests(unittest.TestCase):
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

    def test_the_runner_removes_everything_it_created(self):
        runner = (ROOT / "tests/lifecycle/run.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup EXIT", runner)
        self.assertIn('rm -rf "$WORKDIR"', runner)


if __name__ == "__main__":
    unittest.main()
