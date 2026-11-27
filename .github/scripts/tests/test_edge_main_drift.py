"""The Edge main early warning, edge-main-drift.yml (ferrum-contracts#76).

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

WORKFLOW = ROOT / ".github/workflows/edge-main-drift.yml"
CANARY = ROOT / ".github/workflows/validator-pin-canary.yml"
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

    def test_it_runs_weekly_on_dispatch_and_on_pull_requests_that_change_it(self):
        triggers = self.document["on"]
        self.assertEqual([entry["cron"] for entry in triggers["schedule"]], [WEEKLY])
        self.assertIn("workflow_dispatch", triggers)
        self.assertEqual(
            triggers["pull_request"]["paths"],
            [".github/workflows/edge-main-drift.yml", "tests/unit/edge_main_openapi_tests.rs"],
        )
        self.assertEqual(list(self.jobs), ["edge-main-drift", "edge-main-drift-issue"])
        self.assertNotIn("if", self.jobs["edge-main-drift"])
        # The protected checker's fences hold for the shipped file.
        self.assertEqual(check_supply_chain.edge_main_drift_violations(self.text), [])

    def test_the_validator_pin_canary_no_longer_carries_the_early_warning(self):
        canary = check_supply_chain.parse_workflow(CANARY.read_text(encoding="utf-8"))
        self.assertEqual(list(canary["jobs"]), ["validator-pin-canary"])
        self.assertNotIn("inputs.check", CANARY.read_text(encoding="utf-8"))

    def test_a_pull_request_run_fails_unless_clean(self):
        steps = {step.get("name"): step for step in self.jobs["edge-main-drift"]["steps"]}
        gate = steps["Fail a pull-request run that did not come back clean"]
        self.assertIn("github.event_name == 'pull_request'", gate["if"])
        self.assertEqual(gate["env"]["OUTCOME"], "${{ steps.report.outputs.outcome }}")
        self.assertIn('[ "$OUTCOME" != clean ]', gate["run"])

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
        self.assertEqual(writers, ["edge-main-drift-issue"])
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

    def test_the_openapi_comparison_runs_and_is_reported(self):
        steps = {step.get("name"): step for step in self.jobs["edge-main-drift"]["steps"]}
        compare = steps["Compare Edge main's openapi.yaml with what GitForgeOps emits"]
        self.assertEqual(compare["id"], "openapi")
        self.assertEqual(compare["continue-on-error"], "true")
        run = compare["run"]
        # Read at the image's own commit, never at a moving branch.
        self.assertIn("ferrum-edge/ferrum-edge/$EDGE_COMMIT/openapi.yaml", run)
        self.assertIn('EDGE_MAIN_OPENAPI="$spec" cargo test --locked --test unit_tests', run)
        # A filter that matched nothing would pass silently; the marker refuses it.
        self.assertIn("grep -q 'edge-main-openapi: compared'", run)
        report = steps["Write the report"]
        self.assertEqual(report["env"]["OPENAPI"], "${{ steps.openapi.outcome }}")
        self.assertIn('"$OPENAPI"', report["run"])


MINIMAL_EDGE_MAIN_DRIFT = """name: Edge Main Drift
on:
  schedule:
    - cron: '17 6 * * 1'
permissions:
  contents: read
jobs:
  edge-main-drift:
    runs-on: ubuntu-26.04
    timeout-minutes: 45
    permissions:
      contents: read
    steps:
      - run: echo check
  edge-main-drift-issue:
    needs: edge-main-drift
    if: >-
      !cancelled() && github.event_name != 'pull_request' &&
      github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-26.04
    timeout-minutes: 10
    permissions:
      contents: read
      issues: write
    steps:
      - run: echo issue
"""


class EdgeMainDriftWorkflowFenceTests(unittest.TestCase):
    """The protected checker's fences for the dedicated edge-main-drift.yml."""

    def test_the_workflow_is_allowlisted(self):
        self.assertIn("edge-main-drift.yml", check_supply_chain.KNOWN_WORKFLOWS)

    def test_a_fenced_workflow_passes(self):
        self.assertEqual(check_supply_chain.edge_main_drift_violations(MINIMAL_EDGE_MAIN_DRIFT), [])

    def test_each_weakening_is_refused(self):
        for name, before, after in (
            ("renamed", "name: Edge Main Drift", "name: Something Else"),
            ("writable check job", "    permissions:\n      contents: read\n    steps:\n      - run: echo check",
             "    permissions:\n      contents: write\n    steps:\n      - run: echo check"),
            ("issue job on pull requests", "github.event_name != 'pull_request' &&", ""),
            ("issue job off the default branch",
             "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)", "true"),
            ("issue job runs code", "      - run: echo issue",
             "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
            ("check job reads secrets", "      - run: echo check", "      - run: echo ${{ secrets.TOKEN }}"),
            ("check job installs the pinned validator", "      - run: echo check",
             "      - run: bash .github/scripts/install-ferrum-edge.sh"),
        ):
            with self.subTest(name=name):
                text = MINIMAL_EDGE_MAIN_DRIFT.replace(before, after, 1)
                self.assertNotEqual(text, MINIMAL_EDGE_MAIN_DRIFT)
                self.assertTrue(check_supply_chain.edge_main_drift_violations(text), name)


if __name__ == "__main__":
    unittest.main()
