"""The monitoring outcome taxonomy.

The whole point of these tests is a single negative: nothing except a
completed, matching comparison may read as "this gateway is in sync". A check
that could not authenticate, an environment still waiting for a reviewer, a
cancelled runner and a file-mode environment each say something different
about coverage, and collapsing any of them into green is how a monitoring
setup comes to report on a gateway nobody is watching.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "drift_report.py"
SPEC = importlib.util.spec_from_file_location("drift_report", SCRIPT)
drift_report = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = drift_report
SPEC.loader.exec_module(drift_report)

WORKFLOW = ROOT / ".github/workflows/drift-check.yml"


def entry(environment="production", outcome=drift_report.IN_SYNC, **overrides):
    payload = {
        "environment": environment,
        "check_environment": overrides.pop(
            "check_environment", f"{environment}-monitor"
        ),
        "unattended": overrides.pop("unattended", True),
        "outcome": outcome,
        "detail": overrides.pop("detail", ""),
        "exit_code": overrides.pop("exit_code", None),
    }
    payload["approval_gated"] = (
        payload["check_environment"] == payload["environment"]
    )
    payload.update(overrides)
    return payload


class OutcomeTaxonomyTests(unittest.TestCase):
    def test_only_a_completed_matching_comparison_is_in_sync(self):
        self.assertEqual(
            drift_report.SUCCESSFUL_COMPARISON, frozenset({drift_report.IN_SYNC})
        )
        for outcome in drift_report.OUTCOMES:
            with self.subTest(outcome=outcome):
                if outcome == drift_report.IN_SYNC:
                    continue
                self.assertNotIn(outcome, drift_report.SUCCESSFUL_COMPARISON)

    def test_diff_exit_codes_map_to_gateway_statements_only(self):
        self.assertEqual(drift_report.outcome_for_exit_code(0), drift_report.IN_SYNC)
        self.assertEqual(drift_report.outcome_for_exit_code(2), drift_report.DRIFT)
        # Exit 1 covers authentication, connectivity, a cached
        # (non-authoritative) backup and configuration errors. None of them is
        # a statement about the gateway.
        for unknown in (1, 3, 101, 137):
            with self.subTest(exit_code=unknown):
                self.assertEqual(
                    drift_report.outcome_for_exit_code(unknown), drift_report.FAILED
                )

    def test_failure_skip_and_no_show_all_block_but_skip_does_not(self):
        self.assertEqual(
            drift_report.BLOCKING,
            frozenset(
                {drift_report.DRIFT, drift_report.FAILED, drift_report.NOT_COMPLETED}
            ),
        )
        # A file-mode environment is a configured absence of a live surface,
        # not a gap in coverage.
        self.assertNotIn(drift_report.SKIPPED, drift_report.BLOCKING)

    def test_unknown_outcome_is_refused(self):
        with self.assertRaises(ValueError):
            drift_report.record("prod", "prod-monitor", "probably_fine", False)


class SummaryTests(unittest.TestCase):
    def test_each_outcome_is_named_distinctly_in_the_summary(self):
        entries = [
            entry("a", drift_report.IN_SYNC),
            entry("b", drift_report.DRIFT),
            entry("c", drift_report.FAILED),
            entry("d", drift_report.SKIPPED),
            entry("e", drift_report.NOT_COMPLETED),
        ]
        text, status = drift_report.summarize(entries)
        for outcome in drift_report.OUTCOMES:
            self.assertIn(drift_report.LABELS[outcome][1], text)
        self.assertIn("1 of 5 environments were compared and matched", text)
        self.assertEqual(status, 1)

    def test_a_clean_run_reports_every_environment_compared(self):
        text, status = drift_report.summarize(
            [entry("a"), entry("b"), entry("c", drift_report.SKIPPED)]
        )
        self.assertEqual(status, 0)
        self.assertIn("2 of 3 environments were compared and matched", text)
        self.assertIn("configured absence, not a monitoring gap", text)

    def test_an_empty_run_is_not_a_clean_run(self):
        # A scheduled workflow whose matrix produced nothing has compared
        # nothing. Reporting success there is the exact failure mode this
        # module exists to prevent.
        text, status = drift_report.summarize([])
        self.assertEqual(status, 1)
        self.assertIn("not monitoring coverage", text)

    def test_an_approval_gated_no_show_explains_the_remedy(self):
        text, _ = drift_report.summarize(
            [
                entry(
                    "production",
                    drift_report.NOT_COMPLETED,
                    check_environment="production",
                    unattended=False,
                )
            ]
        )
        self.assertIn("withholds its secrets until a reviewer approves", text)
        self.assertIn("monitoring.unattended", text)

    def test_an_unattended_no_show_does_not_blame_approvals(self):
        text, _ = drift_report.summarize(
            [entry("production", drift_report.NOT_COMPLETED)]
        )
        self.assertNotIn("withholds its secrets", text)


class CliTests(unittest.TestCase):
    def test_record_then_summarize_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._record(
                root / "production.json",
                "--environment", "production",
                "--check-environment", "production-monitor",
                "--unattended",
                "--exit-code", "2",
            )
            self._record(
                root / "sandbox.json",
                "--environment", "sandbox",
                "--check-environment", "sandbox",
                "--outcome", "skipped",
                "--detail", "file mode has no live Admin API drift surface",
            )
            written = json.loads((root / "production.json").read_text())
            self.assertEqual(written["outcome"], drift_report.DRIFT)
            self.assertFalse(written["approval_gated"])

            summary = root / "summary.md"
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "summarize",
                    "--input", str(root),
                    "--summary", str(summary),
                ],
                check=False, text=True, capture_output=True,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Drift detected", result.stdout)
        self.assertIn("Skipped (file mode)", result.stdout)

    def test_record_needs_an_outcome_or_an_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "record",
                    "--environment", "production",
                    "--check-environment", "production",
                    "--output", str(Path(directory) / "out.json"),
                ],
                check=False, text=True, capture_output=True,
            )
        self.assertEqual(result.returncode, 2)

    @staticmethod
    def _record(output: Path, *args: str) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "record", *args, "--output", str(output)],
            check=False, text=True, capture_output=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr


class WorkflowWiringTests(unittest.TestCase):
    """The workflow has to actually use the taxonomy, not just ship it."""

    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_the_comparison_exit_code_is_captured_not_swallowed(self):
        # `set -e` plus a bare `gitforgeops diff --exit-on-drift` would turn
        # "drift" and "could not reach the gateway" into the same red job.
        self.assertIn("gitforgeops diff --exit-on-drift || status=$?", self.text)
        self.assertIn('echo "exit_code=$status" >> "$GITHUB_OUTPUT"', self.text)

    def test_file_mode_is_reported_as_skipped_rather_than_compared(self):
        self.assertIn("--outcome skipped", self.text)
        self.assertIn("no live Admin API drift surface", self.text)

    def test_a_matrix_entry_that_never_ran_is_reconstructed(self):
        self.assertIn("--outcome not_completed", self.text)
        self.assertIn("Reconstruct missing outcomes", self.text)

    def test_the_drift_job_binds_the_monitoring_environment(self):
        self.assertIn(
            "environment: ${{ matrix.scope.monitoring_environment }}", self.text
        )
        self.assertIn("--include-scopes", self.text)

    def test_monitoring_holds_no_write_or_broker_authority(self):
        for forbidden in (
            "FERRUM_GH_PROVISIONER_TOKEN",
            "GITFORGEOPS_STATE_APP_PRIVATE_KEY",
            "FERRUM_CREDS_BUNDLE",
            "SETTINGS_AUDIT_TOKEN",
        ):
            with self.subTest(secret=forbidden):
                self.assertNotIn(f"secrets.{forbidden}", self.text)
        self.assertNotIn("gitforgeops apply", self.text)
        self.assertNotIn("gitforgeops rotate", self.text)
        self.assertNotIn("--materialize", self.text)


if __name__ == "__main__":
    unittest.main()
