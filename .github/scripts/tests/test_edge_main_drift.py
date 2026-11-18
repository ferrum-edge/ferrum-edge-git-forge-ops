"""The Edge main early warning in validator-pin-canary.yml (ferrum-contracts#76).

It runs a gateway binary that is not in the reviewed digest allowlist, so the
job that runs it must stay read-only and away from the allowlist, and the only
job that writes anything must run no code and file one issue.
"""

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / ".github/scripts/check_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("check_supply_chain", SCRIPT)
check_supply_chain = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_supply_chain)

WORKFLOW = ROOT / ".github/workflows/validator-pin-canary.yml"
DAILY = "17 7 * * *"
WEEKLY = "17 6 * * 1"
IDENTITY = (
    "--certificate-identity https://github.com/ferrum-edge/ferrum-edge/"
    ".github/workflows/main-latest-image.yml@refs/heads/main"
)


class EdgeMainDriftTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.document = check_supply_chain.parse_workflow(self.text)
        self.jobs = self.document["jobs"]

    def test_the_canary_and_the_early_warning_run_on_their_own_triggers(self):
        triggers = self.document["on"]
        self.assertEqual([entry["cron"] for entry in triggers["schedule"]], [DAILY, WEEKLY])
        check = triggers["workflow_dispatch"]["inputs"]["check"]
        self.assertEqual(check["options"], ["validator-pin", "edge-main"])
        self.assertEqual(check["default"], "validator-pin")
        canary = " ".join(self.jobs["validator-pin-canary"]["if"].split())
        self.assertIn(f"github.event.schedule == '{DAILY}'", canary)
        self.assertIn("inputs.check == 'validator-pin'", canary)
        edge = " ".join(self.jobs["edge-main-drift"]["if"].split())
        self.assertIn(f"github.event.schedule == '{WEEKLY}'", edge)
        self.assertIn("inputs.check == 'edge-main'", edge)
        self.assertEqual(list(self.jobs), [
            "validator-pin-canary", "edge-main-drift", "edge-main-drift-issue",
        ])

    def test_the_job_that_runs_edge_main_is_read_only_and_off_the_allowlist(self):
        job = self.jobs["edge-main-drift"]
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("environment", job)
        self.assertNotIn("env", job)
        body = json.dumps(job)
        for forbidden in ("install-ferrum-edge.sh", "ferrum-edge-checksums.txt", "secrets", "actions/cache"):
            self.assertNotIn(forbidden, body)
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                self.assertEqual(step["with"]["persist-credentials"], "false")
        steps = {step.get("name"): step for step in job["steps"]}
        # Cosign comes from an allowed action's checksum manifest, never a
        # fallback download.
        cosign = steps["Install Cosign"]
        self.assertTrue(cosign["uses"].startswith("taiki-e/install-action@"))
        self.assertEqual(cosign["with"], {"tool": "cosign@3.1.4", "checksum": "true", "fallback": "none"})
        resolve = steps["Resolve the Ferrum Edge main image"]["run"]
        # The digest is verified before anything is pulled or copied from it.
        self.assertIn(IDENTITY, resolve)
        self.assertLess(resolve.index("cosign verify"), resolve.index("docker pull"))
        self.assertLess(resolve.index("cosign verify"), resolve.index("docker create"))
        # The lifecycle result never reaches the release gate's artifact names.
        lifecycle = steps["Run the lifecycle suite against Edge main"]
        self.assertEqual(
            lifecycle["env"]["LIFECYCLE_RESULT"],
            "${{ runner.temp }}/edge-main-lifecycle-result.json",
        )
        self.assertNotIn("upload-artifact", body)
        # The scenarios' gitforgeops resolves `ferrum-edge` on PATH, so the
        # Edge main binary goes first on it, or the suite tests nothing.
        self.assertIn(
            'PATH="$(dirname -- "$FERRUM_EDGE_BINARY_PATH"):$PATH" bash tests/lifecycle/run.sh',
            lifecycle["run"],
        )

    def test_only_the_issue_job_writes_and_it_runs_no_code(self):
        issue = self.jobs["edge-main-drift-issue"]
        self.assertEqual(issue["needs"], "edge-main-drift")
        self.assertEqual(issue["permissions"], {"contents": "read", "issues": "write"})
        condition = " ".join(issue["if"].split())
        # Any finished check reaches the issue, so a check that could not run
        # is filed as `error` (dsf F1); only a clean run closes the issue.
        self.assertIn("needs.edge-main-drift.result != 'cancelled'", condition)
        self.assertNotIn("needs.edge-main-drift.result == 'success'", condition)
        self.assertIn("github.event_name != 'pull_request'", condition)
        self.assertIn(
            "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
            condition,
        )
        self.assertTrue(all("uses" not in step for step in issue["steps"]))
        writers = [
            name for name, job in self.jobs.items()
            if any(value == "write" for value in job.get("permissions", {}).values())
        ]
        self.assertEqual(writers, ["validator-pin-canary", "edge-main-drift-issue"])
        run = issue["steps"][0]["run"]
        self.assertIn("labels=$label", run)
        self.assertIn("drift | error)", run)
        self.assertEqual(run.count("gh issue close"), 1)
        self.assertGreater(run.index("gh issue close"), run.index("\n  clean)"))
        # Only an issue this workflow wrote, found by its marker on every page.
        self.assertIn("--paginate", run)
        self.assertIn('startswith("<!-- edge-main-drift -->")', run)

    def test_a_check_that_could_not_run_is_reported_as_error(self):
        steps = {step.get("name"): step for step in self.jobs["edge-main-drift"]["steps"]}
        report = steps["Write the report"]
        self.assertEqual(report["if"], "${{ !cancelled() }}")
        for key, step_id in (
            ("SETUP_CHECKOUT", "checkout"),
            ("SETUP_COSIGN", "cosign"),
            ("SETUP_EDGE", "edge"),
            ("SETUP_TOOLCHAIN", "toolchain"),
            ("SETUP_INSTALL", "install"),
        ):
            self.assertEqual(report["env"][key], f"${{{{ steps.{step_id}.outcome }}}}")
        self.assertIn('[ -z "$failed_setup" ] || outcome=error', report["run"])

    def test_resolve_reads_main_after_the_image_and_tolerates_contracts_metadata(self):
        steps = {step.get("name"): step for step in self.jobs["edge-main-drift"]["steps"]}
        resolve = steps["Resolve the Ferrum Edge main image"]["run"]
        # dsf F4: main is read after the image's revision label, so a newer
        # image is never mistaken for a commit off main's history.
        main_read = resolve.index("git ls-remote https://github.com/ferrum-edge/ferrum-edge")
        self.assertLess(resolve.index("org.opencontainers.image.revision"), main_read)
        self.assertLess(main_read, resolve.index("compare/$commit...$main_head"))
        # dsf F2: a missing vocabulary becomes a report note, not an abort.
        self.assertIn('if catalog=$(curl -fsS "$vocabulary" 2>/dev/null) &&', resolve)
        self.assertIn("could not be read from ferrum-contracts main", resolve)
        # dsf F3: a failed compare call is reported as such.
        self.assertIn('--jq .status 2>/dev/null || true)', resolve)
        self.assertIn("the compare API call failed", resolve)
        self.assertIn('diverged) delta_note="not on this commit\'s history"', resolve)


if __name__ == "__main__":
    unittest.main()
