"""The release gate's one job: refuse to be satisfied by an absence.

A gate that only catches "the suite failed and we shipped anyway" catches the
loud case. These tests pin the quiet ones — never ran, ran for a different
revision, ran against a different gateway, was cancelled mid-run, or skipped a
scenario and reported no failures.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "lifecycle_result.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_result", SCRIPT)
lifecycle_result = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lifecycle_result
SPEC.loader.exec_module(lifecycle_result)

REVISION = "a" * 40
OTHER_REVISION = "b" * 40
GATEWAY = "c" * 64
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


def passing_result(**overrides):
    result = lifecycle_result.empty_result()
    for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
        lifecycle_result.record(result, identifier, lifecycle_result.PASSED, "ok")
    lifecycle_result.seal(result, REVISION, GATEWAY, NOW - timedelta(hours=1))
    result.update(overrides)
    return result


def reasons(result, revision=REVISION, gateway=GATEWAY, max_age=None, now=NOW):
    return lifecycle_result.blockers(
        result,
        revision,
        gateway,
        max_age or lifecycle_result.DEFAULT_MAX_AGE_HOURS,
        now,
    )


class CertificationTests(unittest.TestCase):
    def test_a_complete_passing_recent_result_certifies_the_revision(self):
        self.assertEqual(reasons(passing_result()), [])

    def test_a_result_for_another_revision_certifies_nothing(self):
        found = reasons(passing_result(), revision=OTHER_REVISION)
        self.assertTrue(any("certifies" in reason for reason in found), found)

    def test_a_result_from_another_gateway_build_certifies_nothing(self):
        found = reasons(passing_result(), gateway="d" * 64)
        self.assertTrue(
            any("gateway build" in reason for reason in found), found
        )

    def test_an_unsealed_result_is_a_cancelled_run(self):
        result = passing_result()
        result["gitforgeops_revision"] = None
        result["sealed_at"] = None
        found = reasons(result)
        self.assertTrue(any("did not finish" in reason for reason in found), found)

    def test_a_stale_result_certifies_nothing(self):
        result = passing_result()
        lifecycle_result.seal(result, REVISION, GATEWAY, NOW - timedelta(days=30))
        found = reasons(result)
        self.assertTrue(any("beyond the" in reason for reason in found), found)

    def test_a_skipped_scenario_is_not_a_passing_one(self):
        result = passing_result()
        lifecycle_result.record(
            result, "drift-monitoring", lifecycle_result.SKIPPED, "no gateway"
        )
        found = reasons(result)
        self.assertTrue(
            any(
                "drift-monitoring" in reason and "not a passing one" in reason
                for reason in found
            ),
            found,
        )

    def test_a_scenario_that_never_ran_is_not_a_passing_one(self):
        result = lifecycle_result.empty_result()
        lifecycle_result.seal(result, REVISION, GATEWAY, NOW)
        found = reasons(result)
        self.assertEqual(len(found), len(lifecycle_result.REQUIRED_SCENARIO_IDS))

    def test_an_absent_scenario_is_not_a_passing_one(self):
        # A result missing a key entirely — an older suite, or a truncated
        # write — must not read as "nothing to report here".
        result = passing_result()
        del result["scenarios"]["create-and-route"]
        found = reasons(result)
        self.assertTrue(
            any("absent from the result" in reason for reason in found), found
        )

    def test_only_passed_authorizes(self):
        self.assertEqual(
            lifecycle_result.AUTHORIZING, frozenset({lifecycle_result.PASSED})
        )
        for status in lifecycle_result.STATUSES:
            if status == lifecycle_result.PASSED:
                continue
            self.assertNotIn(status, lifecycle_result.AUTHORIZING)

    def test_a_missing_result_file_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(lifecycle_result.ResultError) as raised:
                lifecycle_result.load(Path(directory) / "absent.json")
        self.assertIn("absence of a result", str(raised.exception))

    def test_an_unknown_scenario_or_status_is_refused(self):
        result = lifecycle_result.empty_result()
        with self.assertRaises(lifecycle_result.ResultError):
            lifecycle_result.record(result, "invented", lifecycle_result.PASSED)
        with self.assertRaises(lifecycle_result.ResultError):
            lifecycle_result.record(result, "create-and-route", "probably_fine")


class CoverageTests(unittest.TestCase):
    """The declared scenarios are the product's promises, enumerated."""

    def test_every_acceptance_scenario_from_the_issue_is_declared(self):
        # One id per acceptance bullet in #263, plus the promotion path #268
        # asks this suite to exercise. Adding a fail-closed gate to `apply`
        # without adding a scenario here narrows what the suite certifies
        # without narrowing what ships.
        self.assertEqual(
            set(lifecycle_result.REQUIRED_SCENARIO_IDS),
            {
                "create-and-route",
                "reapply-is-a-no-op",
                "modify-and-delete-in-order",
                "credentials-generate-and-rotate",
                "partial-failure-recovery",
                "ledger-publication-failure",
                "runner-interruption",
                "scheduling-and-attribution",
                "staged-promotion",
                "drift-monitoring",
                "file-and-mesh-boundary",
            },
        )

    def test_the_driver_implements_every_declared_scenario(self):
        spec = importlib.util.spec_from_file_location(
            "lifecycle_scenarios", ROOT / "tests/lifecycle/scenarios.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            sorted(module.SCENARIOS), sorted(lifecycle_result.REQUIRED_SCENARIO_IDS)
        )

    def test_the_runbook_documents_every_declared_scenario(self):
        runbook = (ROOT / "tests/lifecycle/README.md").read_text(encoding="utf-8")
        for identifier, _ in lifecycle_result.REQUIRED_SCENARIOS:
            self.assertIn(identifier, runbook, identifier)


class RenderingTests(unittest.TestCase):
    def test_the_summary_names_the_revision_gateway_and_every_scenario(self):
        rendered = lifecycle_result.render(passing_result())
        self.assertIn(REVISION, rendered)
        self.assertIn(GATEWAY, rendered)
        for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
            self.assertIn(f"`{identifier}`", rendered)
        self.assertIn("none of them authorizes a release", rendered)

    def test_an_unsealed_result_renders_as_unsealed_rather_than_blank(self):
        rendered = lifecycle_result.render(lifecycle_result.empty_result())
        self.assertIn("UNSEALED", rendered)


class CliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_init_record_seal_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            self.assertEqual(self._run("init", "--result", str(path)).returncode, 0)

            # Unsealed and unrecorded: refused.
            blocked = self._run(
                "verify", "--result", str(path), "--revision", REVISION
            )
            self.assertEqual(blocked.returncode, 1)
            self.assertIn("::error::", blocked.stdout)

            for identifier in lifecycle_result.REQUIRED_SCENARIO_IDS:
                self.assertEqual(
                    self._run(
                        "record",
                        "--result", str(path),
                        "--scenario", identifier,
                        "--status", "passed",
                        "--detail", "ok",
                    ).returncode,
                    0,
                )
            self.assertEqual(
                self._run(
                    "seal",
                    "--result", str(path),
                    "--revision", REVISION,
                    "--gateway", GATEWAY,
                ).returncode,
                0,
            )
            ok = self._run(
                "verify",
                "--result", str(path),
                "--revision", REVISION,
                "--gateway", GATEWAY,
            )
            self.assertEqual(ok.returncode, 0, ok.stdout)
            self.assertIn("::notice::", ok.stdout)

            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["gitforgeops_revision"], REVISION)

    def test_verify_refuses_a_missing_file_rather_than_passing(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(
                "verify",
                "--result", str(Path(directory) / "absent.json"),
                "--revision", REVISION,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("absence of a result", result.stdout)


class ReleaseGateWiringTests(unittest.TestCase):
    """The gate has to be wired into publication, not merely shipped."""

    def setUp(self) -> None:
        self.release = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )

    def test_publication_verifies_the_lifecycle_result(self):
        self.assertIn("lifecycle_result.py verify", self.release)
        self.assertIn("--revision", self.release)

    def test_the_gate_runs_before_anything_is_published(self):
        gate = self.release.index("lifecycle_result.py verify")
        for later in ("docker/build-push-action@", "name: Build and push Docker image"):
            if later in self.release:
                self.assertLess(gate, self.release.index(later), later)

    def test_the_gate_waits_for_the_run_it_is_gating_on(self):
        # Both workflows start on the same push, so a single sample is always
        # too early — the release would be permanently red and the gate would
        # become something operators re-run past rather than read.
        self.assertIn("head_sha=${RELEASE_SHA}", self.release)
        self.assertIn("still running for", self.release)
        self.assertIn("sleep 30", self.release)

    def test_the_gate_distinguishes_not_yet_run_from_did_not_pass(self):
        # A finished run that did not certify is a different thing from one
        # that has not happened, and only one of them is fixed by waiting.
        self.assertIn("ran for ${RELEASE_SHA} and did not pass", self.release)
        self.assertIn("has not started for ${RELEASE_SHA} yet", self.release)
        self.assertIn("Fix the scenarios it reported, not the gate", self.release)

    def test_the_lifecycle_workflow_seals_and_publishes_its_result(self):
        workflow = (ROOT / ".github/workflows/lifecycle.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("tests/lifecycle/run.sh", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        # `!cancelled()` rather than `always()`: a cancelled run must leave an
        # unsealed record, which the gate reads as "did not finish".
        self.assertIn("!cancelled()", workflow)


if __name__ == "__main__":
    unittest.main()
