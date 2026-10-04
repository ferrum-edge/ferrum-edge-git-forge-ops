"""Exercise the actual release shell with hosted gh, clock and sleep stubs."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

REQUIRED = [
    "Rust CI / rust-ci-check",
    "Security / security-cargo-audit",
    "Security / security-supply-chain-policy",
    "GitForgeOps State Guard / state-guard-reject-state-edits",
    "GitForgeOps PR Static Validation / gitforgeops-required-static-validation",
]
# Being added to the ruleset (GHSA-x5m2-4555-q4cr): tolerated while absent,
# but a reported result must pass.
ACCEPTED = ["GitForgeOps Supply-Chain Policy / trusted-supply-chain-policy"]

PASSING_CHECKS = [
    {
        "bucket": "pass",
        "name": "security-supply-chain-policy",
        "workflow": "Security",
        "required": True,
    },
    {
        "bucket": "pass",
        "name": "gitforgeops-required-static-validation",
        "workflow": "GitForgeOps PR Static Validation",
        "required": True,
    },
    {"bucket": "pass", "name": "rust-ci-check", "workflow": "Rust CI", "required": True},
    {
        "bucket": "pass",
        "name": "security-cargo-audit",
        "workflow": "Security",
        "required": True,
    },
    {
        "bucket": "pass",
        "name": "state-guard-reject-state-edits",
        "workflow": "GitForgeOps State Guard",
        "required": True,
    },
]
TRUSTED_POLICY_CHECK = {
    "bucket": "pass",
    "name": "trusted-supply-chain-policy",
    "workflow": "GitForgeOps Supply-Chain Policy",
    "required": False,
}

HEAD_SHA = "b" * 40
RELEASE_SHA = "a" * 40
REPO = "acme/template-copy"
MERGED_PR = {
    "id": 12345,
    "number": 452,
    "state": "closed",
    "merged": True,
    "base": {"ref": "main", "repo": {"full_name": REPO}},
    "head": {"sha": HEAD_SHA, "ref": "feature"},
    "merged_at": "2026-10-04T00:00:00Z",
    "merge_commit_sha": RELEASE_SHA,
}


def rules(*contexts: str) -> list[dict]:
    return [
        {
            "type": "required_status_checks",
            "parameters": {
                "required_status_checks": [
                    {"context": context.split(" / ")[-1], "integration_id": 15368}
                    for context in contexts
                ]
            },
        }
    ]


def passing_runs() -> list[dict]:
    return [
        {
            "id": 100 + index,
            "name": check["name"],
            "head_sha": HEAD_SHA,
            "app": {"id": 15368},
            "status": "completed",
            "conclusion": "success",
        }
        for index, check in enumerate(PASSING_CHECKS)
    ]


GATE = re.compile(
    r"--argjson required '(?P<required>\[.*?\])' "
    r"--argjson accepted '(?P<accepted>\[.*?\])'",
    re.S,
)


def gate() -> re.Match[str]:
    """Locate the jq gate the release job runs over `gh pr checks` output."""
    match = GATE.search(WORKFLOW.read_text(encoding="utf-8"))
    if match is None:
        raise AssertionError("release.yml no longer contains the required-check jq gate")
    return match


def gate_script() -> str:
    """Extract the actual commit-to-PR and check authorization shell step."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if "name: Verify the published commit passed every required check" in line
    )
    run = next(index for index in range(start, len(lines)) if lines[index].strip() == "run: |")
    indent = len(lines[run + 1]) - len(lines[run + 1].lstrip())
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    return "\n".join(body) + "\n"


STUB_GH = r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
with Path(os.environ["STUB_CALLS"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(arguments) + "\n")

scenario = json.loads(Path(os.environ["STUB_SCENARIO"]).read_text(encoding="utf-8"))
state_path = Path(os.environ["STUB_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
sample = min(state["sample"], len(scenario["checks"]) - 1)
checks = scenario["checks"][sample]
reported_checks = checks

if arguments[0] == "api":
    endpoint = arguments[1]
    if endpoint == f"repos/{os.environ['REPO']}/commits/{os.environ['RELEASE_SHA']}/pulls?per_page=100":
        mode = "PULLS"
        response = [[scenario["pr"]]]
    elif endpoint == f"repos/{os.environ['REPO']}/pulls/452":
        mode = "PR"
        response = scenario["pr"]
    elif endpoint == f"repos/{os.environ['REPO']}/rules/branches/main?per_page=100":
        mode = "RULES"
        response = scenario.get("rule_pages", [scenario["rules"]])
    elif endpoint == f"repos/{os.environ['REPO']}/commits/{scenario['pr']['head']['sha']}/check-runs?per_page=100&filter=all":
        mode = "RUNS"
        if "runs" in scenario:
            samples = scenario["runs"]
            records = samples[min(state["sample"], len(samples) - 1)]
        else:
            conclusions = {"pass": "success", "fail": "failure", "cancel": "cancelled", "skipping": "skipped"}
            records = [{
                "id": 100 + index,
                "name": check.get("name", "malformed"),
                "head_sha": scenario["pr"]["head"]["sha"],
                "app": {"id": 15368},
                "status": "queued" if check.get("bucket") == "pending" else "completed",
                "conclusion": conclusions.get(check.get("bucket")),
            } for index, check in enumerate(checks)]
        response = [{"total_count": len(records), "check_runs": records}]
    else:
        raise SystemExit(f"unexpected API endpoint: {endpoint}")
elif arguments[:2] == ["pr", "checks"]:
    required = "--required" in arguments
    mode = "REQUIRED" if required else "ALL"
    if required:
        checks = [check for check in checks if check.get("required", False)]
    response = [
        {key: check[key] for key in ("bucket", "name", "workflow") if key in check}
        for check in checks
    ]
else:
    raise SystemExit("unexpected gh invocation")

count = state["calls"].get(mode, 0)
state["calls"][mode] = count + 1
state["clock"] += scenario.get("api_seconds", 0)
state_path.write_text(json.dumps(state), encoding="utf-8")
responses = scenario.get("responses", {}).get(mode)
status = scenario.get("statuses", {}).get(mode, 0)
diagnostic = "lookup failed\n" if status else ""
if responses is not None:
    sys.stdout.write(responses[min(count, len(responses) - 1)])
elif mode in ("REQUIRED", "ALL") and not response and status == 0:
    # Real gh returns an error before JSON export for an empty rollup, or an
    # empty --required projection. Preserve stdout emptiness and exit code 1.
    modifier = "required " if required and reported_checks else ""
    diagnostic = f"no {modifier}checks reported on the '{scenario['pr']['head']['ref']}' branch\n"
    status = 1
else:
    print(json.dumps(response))
errors = scenario.get("errors", {}).get(mode)
if errors is not None:
    diagnostic = errors[min(count, len(errors) - 1)]
sys.stderr.write(diagnostic)
# gh JSON mode exports buckets without an outcome-based exit status.
# Lookup/export errors are separate, even with valid JSON stdout.
raise SystemExit(status)
"""

STUB_TIME = r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["STUB_STATE"])
state = json.loads(path.read_text(encoding="utf-8"))
if Path(sys.argv[0]).name == "date":
    assert sys.argv[1:] == ["+%s"]
    print(state["clock"])
else:
    with Path(os.environ["STUB_CALLS"]).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(["sleep", *sys.argv[1:]]) + "\n")
    state["sample"] += 1
    state["clock"] += int(os.environ.get("STUB_SLEEP_ADVANCE", sys.argv[1]))
    path.write_text(json.dumps(state), encoding="utf-8")
"""


class ReleaseGateListTests(unittest.TestCase):
    def test_the_workflow_lists_exactly_the_launch_checks(self) -> None:
        # Behavior tests run the workflow itself; pin the launch lists as well
        # so accidentally removing a mandatory check cannot make them pass.
        match = gate()
        self.assertEqual(json.loads(match.group("required")), REQUIRED)
        self.assertEqual(json.loads(match.group("accepted")), ACCEPTED)

    def test_the_wait_budget_fits_inside_step_and_job_timeouts(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        job = workflow.split("  authorize-release:", 1)[1].split("  docker:", 1)[0]
        step = job.split("name: Verify the published commit passed every required check", 1)[1]
        job_timeout = int(re.search(r"timeout-minutes: (\d+)", job).group(1)) * 60
        step_timeout = int(re.search(r"timeout-minutes: (\d+)", step).group(1)) * 60
        budget = int(re.search(r"deadline=\$\(\( \$\(date \+%s\) \+ (\d+) \)\)", gate_script()).group(1))
        self.assertEqual(budget, 900)
        self.assertLessEqual(budget + 5, step_timeout)
        # Preserve time for the existing forty lifecycle polls, plus evidence
        # download and verification. No production clock override is added.
        self.assertLess(step_timeout + 40 * 30, job_timeout)
        self.assertNotIn("STUB_", gate_script())
        self.assertIn('gh pr checks "$pr" --repo "$REPO" --required', gate_script())


@unittest.skipUnless(
    shutil.which("jq") and shutil.which("bash") and shutil.which("timeout"),
    "jq, bash and timeout are required to exercise the release gate",
)
class ReleaseGateTests(unittest.TestCase):
    def run_gate(
        self,
        checks: list[dict[str, str | bool]],
        *,
        required_status: int = 0,
        all_status: int = 0,
        required_response: str | None = None,
        all_response: str | None = None,
        samples: list[list[dict]] | None = None,
        run_samples: list[list[dict]] | None = None,
        settings: list[dict] | None = None,
        rule_pages: list[list[dict]] | None = None,
        responses: dict[str, list[str]] | None = None,
        statuses: dict[str, int] | None = None,
        errors: dict[str, list[str]] | None = None,
        sleep_advance: int | None = None,
        api_seconds: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text(STUB_GH, encoding="utf-8")
            (bin_dir / "gh").chmod(0o755)
            for name in ("sleep", "date"):
                (bin_dir / name).write_text(STUB_TIME, encoding="utf-8")
                (bin_dir / name).chmod(0o755)
            default_contexts = REQUIRED + [
                f"{check.get('workflow', '')} / {check.get('name', '')}"
                for sample in (samples if samples is not None else [checks])
                for check in sample
                if check.get("required", False)
            ]
            scenario = {
                "checks": samples if samples is not None else [checks],
                "pr": MERGED_PR,
                "rules": rules(*default_contexts) if settings is None else settings,
                "responses": dict(responses or {}),
                "statuses": {"REQUIRED": required_status, "ALL": all_status, **(statuses or {})},
                "errors": dict(errors or {}),
                "api_seconds": api_seconds,
            }
            if rule_pages is not None:
                scenario["rule_pages"] = rule_pages
            if run_samples is not None:
                scenario["runs"] = run_samples
            for mode, response in (("REQUIRED", required_response), ("ALL", all_response)):
                if response is not None:
                    scenario["responses"][mode] = [response]
            scenario_path = root / "scenario.json"
            scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
            state_path = root / "state.json"
            state_path.write_text(
                json.dumps({"clock": 0, "sample": 0, "calls": {}}), encoding="utf-8"
            )
            calls_path = root / "calls.jsonl"
            env = {
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "REPO": REPO,
                "RELEASE_SHA": RELEASE_SHA,
                "DEFAULT_BRANCH": "main",
                "GH_TOKEN": "unused",
                "STUB_SCENARIO": str(scenario_path),
                "STUB_STATE": str(state_path),
                "STUB_CALLS": str(calls_path),
            }
            if sleep_advance is not None:
                env["STUB_SLEEP_ADVANCE"] = str(sleep_advance)
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", gate_script()],
                cwd=root,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            calls = [
                json.loads(line) for line in calls_path.read_text(encoding="utf-8").splitlines()
            ]
            self.calls = calls
            self.sleeps = [call for call in calls if call[0] == "sleep"]
            required_call = [
                "pr",
                "checks",
                "452",
                "--repo",
                REPO,
                "--required",
                "--json",
                "bucket,name,workflow",
            ]
            all_call = [argument for argument in required_call if argument != "--required"]
            for call in calls:
                if call[:2] == ["pr", "checks"]:
                    self.assertIn(call, (required_call, all_call), result.stderr)
                elif call[0] == "api" and "/check-runs?" in call[1]:
                    self.assertIn(f"/commits/{HEAD_SHA}/", call[1], result.stderr)
                    self.assertEqual(call[2:], ["--paginate", "--slurp"], result.stderr)
                elif call[0] == "api" and "/rules/branches/" in call[1]:
                    self.assertEqual(call[1], f"repos/{REPO}/rules/branches/main?per_page=100")
                    self.assertEqual(call[2:], ["--paginate", "--slurp"], result.stderr)
            return result

    def assert_gate(self, checks, accepted: bool, **options) -> None:
        # A permanent absence or pending result times out in the hosted stub,
        # without changing the real workflow's deadline or sleeping in tests.
        result = self.run_gate(checks, sleep_advance=900, **options)
        self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_every_required_check_passing_is_accepted(self) -> None:
        self.assert_gate(PASSING_CHECKS, True)

    def test_a_missing_required_check_is_rejected(self) -> None:
        self.assert_gate(PASSING_CHECKS[1:], False)

    def test_a_failing_required_check_is_rejected(self) -> None:
        checks = [dict(check) for check in PASSING_CHECKS]
        checks[2]["bucket"] = "fail"
        self.assert_gate(checks, False)

    def test_pending_or_skipped_required_checks_are_rejected(self) -> None:
        for bucket in ("pending", "skipping", "cancel"):
            with self.subTest(bucket=bucket):
                checks = [dict(check) for check in PASSING_CHECKS]
                checks[2]["bucket"] = bucket
                self.assert_gate(checks, False)

    def test_extra_unrelated_checks_do_not_matter(self) -> None:
        for bucket in ("fail", "pending", "skipping", "cancel"):
            with self.subTest(bucket=bucket):
                checks = PASSING_CHECKS + [
                    {"bucket": bucket, "name": "coverage", "workflow": "Rust CI"}
                ]
                self.assert_gate(checks, True)

    def test_an_additional_ruleset_required_failure_is_rejected(self) -> None:
        checks = PASSING_CHECKS + [
            {"bucket": "fail", "name": "coverage", "workflow": "Rust CI", "required": True}
        ]
        self.assert_gate(checks, False)

    def test_the_trusted_policy_check_may_be_absent_before_the_ruleset_switch(self) -> None:
        # The ruleset gains `trusted-supply-chain-policy` in an operator step
        # after its workflow merges; until then `--required` does not list it.
        self.assert_gate(PASSING_CHECKS, True)
        self.assert_gate(PASSING_CHECKS + [TRUSTED_POLICY_CHECK], True)

    def test_a_passing_trusted_check_still_allows_unrelated_optional_failures(self) -> None:
        checks = PASSING_CHECKS + [
            TRUSTED_POLICY_CHECK,
            {"bucket": "fail", "name": "coverage", "workflow": "Rust CI"},
        ]
        self.assert_gate(checks, True)

    def test_a_reported_trusted_policy_check_must_pass(self) -> None:
        for bucket in ("fail", "pending", "skipping", "cancel"):
            with self.subTest(bucket=bucket):
                reported = dict(TRUSTED_POLICY_CHECK, bucket=bucket)
                # The stub excludes this optional record from --required.
                # Only the actual second gh invocation can reveal it.
                self.assert_gate(PASSING_CHECKS + [reported], False)

    def test_the_trusted_policy_check_is_verified_after_the_ruleset_switch(self) -> None:
        for bucket in ("pass", "fail", "pending"):
            with self.subTest(bucket=bucket):
                reported = dict(TRUSTED_POLICY_CHECK, bucket=bucket, required=True)
                self.assert_gate(PASSING_CHECKS + [reported], bucket == "pass")

    def test_the_trusted_policy_check_does_not_replace_the_retiring_one(self) -> None:
        # Expand step: the in-tree job still runs the workflow-script tests and
        # stays required until the retire step.
        without_old = [
            check for check in PASSING_CHECKS if check["name"] != "security-supply-chain-policy"
        ]
        self.assert_gate(without_old + [TRUSTED_POLICY_CHECK], False)

    def test_a_passing_duplicate_cannot_mask_a_failing_trusted_result(self) -> None:
        # Every reported result under the accepted context must pass, so a
        # second, passing check run with the same name changes nothing.
        failing = dict(TRUSTED_POLICY_CHECK, bucket="fail")
        for order in ([TRUSTED_POLICY_CHECK, failing], [failing, TRUSTED_POLICY_CHECK]):
            with self.subTest(order=[check["bucket"] for check in order]):
                self.assert_gate(PASSING_CHECKS + order, False)

    def test_check_lookup_errors_fail_closed_even_with_valid_json_stdout(self) -> None:
        for mode in ("required", "all"):
            for status in (1, 8):
                with self.subTest(mode=mode, status=status):
                    self.assert_gate(PASSING_CHECKS, False, **{f"{mode}_status": status})

    def test_invalid_check_responses_fail_closed(self) -> None:
        responses = (
            "",
            "not JSON",
            "null",
            "{}",
            "[]\n[]",
            "[null]",
            json.dumps([{"bucket": "pass", "workflow": "GitForgeOps Supply-Chain Policy"}]),
            json.dumps([dict(TRUSTED_POLICY_CHECK, bucket=None)]),
            json.dumps([dict(TRUSTED_POLICY_CHECK, workflow=42)]),
            json.dumps([dict(TRUSTED_POLICY_CHECK, name="")]),
            json.dumps([dict(TRUSTED_POLICY_CHECK, bucket="unknown")]),
        )
        for mode in ("required", "all"):
            for response in responses:
                with self.subTest(mode=mode, response=response):
                    self.assert_gate(PASSING_CHECKS, False, **{f"{mode}_response": response})
                    self.assertEqual(self.sleeps, [])

    def test_pending_required_checks_wait_then_pass_on_the_same_head(self) -> None:
        pending = [dict(check) for check in PASSING_CHECKS]
        pending[2]["bucket"] = "pending"
        result = self.run_gate(PASSING_CHECKS, samples=[pending, PASSING_CHECKS])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])
        pr_reads = [call for call in self.calls if call == ["api", f"repos/{REPO}/pulls/452"]]
        self.assertEqual(len(pr_reads), 4)

    def test_missing_required_checks_wait_then_pass(self) -> None:
        result = self.run_gate(PASSING_CHECKS, samples=[PASSING_CHECKS[1:], PASSING_CHECKS])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_empty_cli_errors_wait_then_pass(self) -> None:
        result = self.run_gate(PASSING_CHECKS, samples=[[], PASSING_CHECKS])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])
        self.assertIn("pending or missing", result.stdout)
        check_calls = [call for call in self.calls if call[:2] == ["pr", "checks"]]
        self.assertEqual(len(check_calls), 4)

    def test_no_required_cli_error_waits_then_passes(self) -> None:
        optional = [{"bucket": "pass", "name": "coverage", "workflow": "Rust CI"}]
        result = self.run_gate(PASSING_CHECKS, samples=[optional, PASSING_CHECKS])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_empty_cli_errors_time_out_instead_of_aborting_the_first_sample(self) -> None:
        optional = [{"bucket": "pass", "name": "coverage", "workflow": "Rust CI"}]
        for checks in ([], optional):
            with self.subTest(checks=checks):
                result = self.run_gate(checks, sleep_advance=900)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.sleeps, [["sleep", "15"]])
                self.assertIn("pending or missing", result.stdout)
                self.assertIn("Timed out", result.stderr)

    def test_an_empty_full_lookup_cannot_authorize_a_passing_required_lookup(self) -> None:
        result = self.run_gate(
            PASSING_CHECKS,
            all_status=1,
            all_response="",
            errors={"ALL": ["no checks reported on the 'feature' branch\n"]},
            sleep_advance=900,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "15"]])
        self.assertIn("Timed out", result.stderr)

    def test_empty_stdout_query_failures_are_not_treated_as_missing_checks(self) -> None:
        for mode in ("required", "all"):
            for diagnostic in ("HTTP 502: Bad Gateway\n", "GraphQL: Could not resolve PR\n"):
                with self.subTest(mode=mode, diagnostic=diagnostic):
                    result = self.run_gate(
                        [],
                        **{f"{mode}_status": 1, f"{mode}_response": ""},
                        errors={mode.upper(): [diagnostic]},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.sleeps, [])
                    self.assertIn(diagnostic.strip(), result.stderr)

    def test_empty_diagnostics_require_empty_stdout_and_exit_code_one(self) -> None:
        diagnostic = "no checks reported on the 'feature' branch\n"
        for mode in ("required", "all"):
            for status, response in ((1, "[]"), (2, ""), (8, ""), (124, "")):
                with self.subTest(mode=mode, status=status, response=response):
                    result = self.run_gate(
                        [],
                        **{f"{mode}_status": status, f"{mode}_response": response},
                        errors={mode.upper(): [diagnostic]},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.sleeps, [])

    def test_empty_diagnostics_must_match_the_verified_head_branch_and_lookup(self) -> None:
        for mode, diagnostic in (
            ("required", "no checks reported on the 'other' branch\n"),
            ("all", "no required checks reported on the 'feature' branch\n"),
            ("required", "no checks reported on the 'feature' branch\nHTTP 502\n"),
        ):
            with self.subTest(mode=mode, diagnostic=diagnostic):
                result = self.run_gate(
                    [],
                    **{f"{mode}_status": 1, f"{mode}_response": ""},
                    errors={mode.upper(): [diagnostic]},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.sleeps, [])

    def test_empty_cli_errors_require_valid_complete_same_head_evidence(self) -> None:
        history = [dict(passing_runs()[0], head_sha="c" * 40)]
        result = self.run_gate([], run_samples=[history])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [])
        incomplete = json.dumps([{"total_count": 1, "check_runs": []}])
        result = self.run_gate([], responses={"RUNS": [incomplete]})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [])

    def test_runs_arriving_after_an_empty_cli_sample_require_another_poll(self) -> None:
        optional = [{"bucket": "pass", "name": "coverage", "workflow": "Rust CI"}]
        for initial in ([], optional):
            with self.subTest(initial=initial):
                result = self.run_gate(
                    PASSING_CHECKS,
                    samples=[initial, PASSING_CHECKS],
                    run_samples=[passing_runs()],
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_empty_cli_errors_cannot_hide_a_newer_source_bound_failure(self) -> None:
        optional = [{"bucket": "pass", "name": "coverage", "workflow": "Rust CI"}]
        for initial in ([], optional):
            for conclusion in ("failure", "cancelled"):
                with self.subTest(initial=initial, conclusion=conclusion):
                    history = passing_runs()
                    history.append(dict(history[0], id=900, conclusion=conclusion))
                    result = self.run_gate(initial, run_samples=[history])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.sleeps, [])

    def test_empty_cli_errors_do_not_hide_evidence_api_failures(self) -> None:
        for mode in ("RULES", "RUNS"):
            with self.subTest(mode=mode):
                result = self.run_gate([], statuses={mode: 1})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.sleeps, [])

    def test_empty_cli_errors_do_not_allow_a_head_change(self) -> None:
        changed = dict(MERGED_PR, head={"sha": "c" * 40, "ref": "feature"})
        result = self.run_gate(
            [], responses={"PR": [json.dumps(MERGED_PR), json.dumps(changed)]}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [])
        self.assertIn("changed", result.stdout)

    def test_pending_required_checks_wait_then_fail_without_retrying_failure(self) -> None:
        for bucket in ("fail", "cancel", "skipping"):
            with self.subTest(bucket=bucket):
                pending = [dict(check) for check in PASSING_CHECKS]
                pending[2]["bucket"] = "pending"
                failed = [dict(check) for check in PASSING_CHECKS]
                failed[2]["bucket"] = bucket
                result = self.run_gate(PASSING_CHECKS, samples=[pending, failed, PASSING_CHECKS])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_terminal_failure_takes_precedence_over_other_pending_checks(self) -> None:
        checks = [dict(check) for check in PASSING_CHECKS]
        checks[2]["bucket"] = "pending"
        checks[3]["bucket"] = "fail"
        self.assert_gate(checks, False)
        self.assertEqual(self.sleeps, [])

    def test_malformed_response_after_a_pending_sample_fails_without_another_wait(self) -> None:
        pending = [dict(check) for check in PASSING_CHECKS]
        pending[2]["bucket"] = "pending"
        response = json.dumps([
            {key: check[key] for key in ("bucket", "name", "workflow")}
            for check in pending
        ])
        result = self.run_gate(
            PASSING_CHECKS, samples=[pending, PASSING_CHECKS],
            responses={"ALL": [response, "not JSON"]},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_pending_transitional_checks_wait_then_pass(self) -> None:
        pending = PASSING_CHECKS + [dict(TRUSTED_POLICY_CHECK, bucket="pending")]
        passing = PASSING_CHECKS + [TRUSTED_POLICY_CHECK]
        result = self.run_gate(PASSING_CHECKS, samples=[pending, passing])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_pending_transitional_checks_wait_then_fail(self) -> None:
        pending = PASSING_CHECKS + [dict(TRUSTED_POLICY_CHECK, bucket="pending")]
        failed = PASSING_CHECKS + [dict(TRUSTED_POLICY_CHECK, bucket="cancel")]
        result = self.run_gate(PASSING_CHECKS, samples=[pending, failed])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_pending_and_missing_checks_time_out(self) -> None:
        pending = [dict(check) for check in PASSING_CHECKS]
        pending[2]["bucket"] = "pending"
        for checks in (pending, PASSING_CHECKS[1:]):
            with self.subTest(checks=checks):
                result = self.run_gate(checks, sleep_advance=900)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Timed out", result.stderr)
                self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_total_budget_includes_api_time_and_caps_the_last_sleep(self) -> None:
        pending = [dict(check) for check in PASSING_CHECKS]
        pending[2]["bucket"] = "pending"
        # One association call and six polling calls consume 7 * 128 seconds.
        result = self.run_gate(pending, api_seconds=128)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "4"]])
        self.assertIn("Timed out", result.stderr)

    def test_no_pass_after_the_sampling_budget_expires(self) -> None:
        result = self.run_gate(PASSING_CHECKS, api_seconds=129)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [])
        self.assertIn("Timed out", result.stderr)

    def test_an_absent_trusted_policy_check_cannot_pass_once_required(self) -> None:
        result = self.run_gate(
            PASSING_CHECKS, settings=rules(*REQUIRED, *ACCEPTED), sleep_advance=900
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "15"]])
        self.assertIn("Timed out", result.stderr)

    def test_a_missing_required_trusted_check_waits_then_passes(self) -> None:
        trusted = dict(TRUSTED_POLICY_CHECK, required=True)
        result = self.run_gate(
            PASSING_CHECKS,
            settings=rules(*REQUIRED, *ACCEPTED),
            samples=[PASSING_CHECKS, PASSING_CHECKS + [trusted]],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_missing_required_contexts_on_page_two_cannot_pass_by_absence(self) -> None:
        first_page = rules(*REQUIRED) + [{"type": "deletion"}] * 99
        for context in (*ACCEPTED, "Rust CI / coverage"):
            with self.subTest(context=context):
                result = self.run_gate(
                    PASSING_CHECKS,
                    rule_pages=[first_page, rules(context)],
                    sleep_advance=900,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.sleeps, [["sleep", "15"]])
                self.assertIn("Timed out", result.stderr)

    def test_required_contexts_on_page_two_wait_then_pass(self) -> None:
        first_page = rules(*REQUIRED) + [{"type": "deletion"}] * 99
        extra = {"bucket": "pass", "name": "coverage", "workflow": "Rust CI"}
        for check in (TRUSTED_POLICY_CHECK, extra):
            with self.subTest(check=check):
                required = dict(check, required=True)
                context = f"{check['workflow']} / {check['name']}"
                result = self.run_gate(
                    PASSING_CHECKS,
                    rule_pages=[first_page, rules(context)],
                    samples=[PASSING_CHECKS, PASSING_CHECKS + [required]],
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_malformed_later_rule_pages_fail_immediately(self) -> None:
        for page in (None, {}, "not an array", [None], [{}], [{"type": 42}]):
            with self.subTest(page=page):
                response = json.dumps([rules(*REQUIRED), page])
                self.assert_gate(PASSING_CHECKS, False, responses={"RULES": [response]})
                self.assertEqual(self.sleeps, [])

    def test_later_required_settings_are_validated_and_source_bound(self) -> None:
        for context, app in ((ACCEPTED[0], 42), ("Rust CI / coverage", None)):
            with self.subTest(context=context, app=app):
                later = rules(context)
                later[0]["parameters"]["required_status_checks"][0]["integration_id"] = app
                self.assert_gate(PASSING_CHECKS, False, rule_pages=[rules(*REQUIRED), later])
                self.assertEqual(self.sleeps, [])
        for settings in (None, {}, [None], [{"context": "", "integration_id": 15368}]):
            with self.subTest(settings=settings):
                later = rules("Rust CI / coverage")
                later[0]["parameters"]["required_status_checks"] = settings
                self.assert_gate(PASSING_CHECKS, False, rule_pages=[rules(*REQUIRED), later])
                self.assertEqual(self.sleeps, [])

    def test_an_additional_app_binding_on_a_later_page_is_enforced(self) -> None:
        extra = {"bucket": "pass", "name": "coverage", "workflow": "Rust CI", "required": True}
        later = rules("Rust CI / coverage")
        later[0]["parameters"]["required_status_checks"][0]["integration_id"] = 42
        for app in (15368, 42):
            with self.subTest(app=app):
                history = passing_runs() + [
                    dict(passing_runs()[0], id=900, name="coverage", app={"id": app})
                ]
                self.assert_gate(
                    PASSING_CHECKS + [extra],
                    app == 42,
                    rule_pages=[rules(*REQUIRED), later],
                    run_samples=[history],
                )
                self.assertEqual(self.sleeps, [] if app == 42 else [["sleep", "15"]])

    def test_a_required_trusted_check_must_also_appear_in_the_required_lookup(self) -> None:
        result = self.run_gate(
            PASSING_CHECKS + [TRUSTED_POLICY_CHECK],
            settings=rules(*REQUIRED, *ACCEPTED),
            sleep_advance=900,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "15"]])
        self.assertIn("Timed out", result.stderr)

    def test_the_ruleset_is_rechecked_during_polling(self) -> None:
        pending = [dict(check) for check in PASSING_CHECKS]
        pending[2]["bucket"] = "pending"
        result = self.run_gate(
            PASSING_CHECKS,
            samples=[pending, PASSING_CHECKS],
            responses={"RULES": [
                json.dumps([rules(*REQUIRED)]), json.dumps([rules(*REQUIRED, *ACCEPTED)])
            ]},
            sleep_advance=450,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "15"], ["sleep", "15"]])
        self.assertIn("Timed out", result.stderr)

    def test_the_associated_head_is_verified_before_sampling_and_before_passing(self) -> None:
        changed = dict(MERGED_PR, head={"sha": "c" * 40})
        for responses in ([changed], [MERGED_PR, changed]):
            with self.subTest(read=len(responses)):
                result = self.run_gate(
                    PASSING_CHECKS, responses={"PR": [json.dumps(pr) for pr in responses]}
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.sleeps, [])
                self.assertIn("changed", result.stdout)

    def test_head_change_while_waiting_is_rejected(self) -> None:
        pending = [dict(check) for check in PASSING_CHECKS]
        pending[2]["bucket"] = "pending"
        changed = dict(MERGED_PR, head={"sha": "c" * 40})
        result = self.run_gate(
            PASSING_CHECKS,
            samples=[pending, PASSING_CHECKS],
            responses={"PR": [json.dumps(MERGED_PR), json.dumps(MERGED_PR), json.dumps(changed)]},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_changed_pr_identity_or_merge_association_is_rejected(self) -> None:
        changes = (
            {"id": 54321},
            {"number": 453},
            {"merged": False},
            {"state": "open"},
            {"merge_commit_sha": "c" * 40},
            {"merged_at": "2026-10-05T00:00:00Z"},
            {"base": {"ref": "other", "repo": {"full_name": REPO}}},
            {"base": {"ref": "main", "repo": {"full_name": "acme/other"}}},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assert_gate(
                    PASSING_CHECKS, False,
                    responses={"PR": [json.dumps(dict(MERGED_PR, **change))]},
                )
                self.assertEqual(self.sleeps, [])

    def test_malformed_or_api_error_evidence_never_retries(self) -> None:
        for mode in ("PULLS", "PR", "RULES", "RUNS"):
            for response in ("", "not JSON", "null", "{}", "[]", "[]\n[]"):
                with self.subTest(mode=mode, response=response):
                    self.assert_gate(PASSING_CHECKS, False, responses={mode: [response]})
                    self.assertEqual(self.sleeps, [])
            with self.subTest(mode=mode, api_error=True):
                self.assert_gate(PASSING_CHECKS, False, statuses={mode: 1})
                self.assertEqual(self.sleeps, [])

    def test_invalid_associations_fail_immediately(self) -> None:
        associations = (
            [[dict(MERGED_PR, head={"sha": "invalid"})]],
            [[dict(MERGED_PR, base={"ref": "other", "repo": {"full_name": REPO}})]],
            [[dict(MERGED_PR, base={"ref": "main", "repo": {"full_name": "acme/other"}})]],
            [[dict(MERGED_PR, id=None)]],
            [[MERGED_PR, dict(MERGED_PR, number=453, id=54321)]],
            [[MERGED_PR], [dict(MERGED_PR, head={"sha": "c" * 40})]],
        )
        for association in associations:
            with self.subTest(association=association):
                self.assert_gate(PASSING_CHECKS, False, responses={"PULLS": [json.dumps(association)]})
                self.assertEqual(self.sleeps, [])

    def test_missing_merge_association_retries_with_a_bound(self) -> None:
        result = self.run_gate(
            PASSING_CHECKS, responses={"PULLS": ["[[]]", json.dumps([[MERGED_PR]])]}
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "2"]])
        result = self.run_gate(PASSING_CHECKS, responses={"PULLS": ["[[]]"]})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sleeps, [["sleep", str(seconds)] for seconds in (2, 4, 6, 8)])

    def test_exact_merge_match_is_preferred_and_rebase_association_still_works(self) -> None:
        other = dict(MERGED_PR, id=54321, number=453, merge_commit_sha="c" * 40)
        result = self.run_gate(
            PASSING_CHECKS, responses={"PULLS": [json.dumps([[other, MERGED_PR]])]}
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rebased = dict(MERGED_PR, merge_commit_sha="c" * 40)
        result = self.run_gate(
            PASSING_CHECKS,
            responses={"PULLS": [json.dumps([[rebased]])], "PR": [json.dumps(rebased)]},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_an_old_success_cannot_hide_a_newer_queued_retry(self) -> None:
        history = passing_runs()
        retry = dict(history[2], id=900, status="queued", conclusion=None)
        succeeded = dict(retry, status="completed", conclusion="success")
        result = self.run_gate(PASSING_CHECKS, run_samples=[history + [retry], history + [succeeded]])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])

    def test_an_old_success_cannot_hide_a_newer_terminal_retry(self) -> None:
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral"):
            for reverse in (False, True):
                with self.subTest(conclusion=conclusion, reverse=reverse):
                    history = passing_runs()
                    history.append(dict(history[2], id=900, conclusion=conclusion))
                    if reverse:
                        history.reverse()
                    self.assert_gate(PASSING_CHECKS, False, run_samples=[history])
                    self.assertEqual(self.sleeps, [])

    def test_an_older_failure_does_not_hide_a_newer_success(self) -> None:
        history = passing_runs()
        history.append(dict(history[2], id=1, conclusion="failure"))
        self.assert_gate(PASSING_CHECKS, True, run_samples=[history])

    def test_newer_retry_evidence_on_another_page_cannot_be_hidden(self) -> None:
        history = passing_runs()
        retry = dict(history[2], id=900, conclusion="cancelled")
        response = json.dumps([
            {"total_count": 6, "check_runs": [retry]},
            {"total_count": 6, "check_runs": history},
        ])
        self.assert_gate(PASSING_CHECKS, False, responses={"RUNS": [response]})
        self.assertEqual(self.sleeps, [])

    def test_required_sources_cannot_be_replaced_by_another_app(self) -> None:
        settings = rules(*REQUIRED)
        settings[0]["parameters"]["required_status_checks"][0]["integration_id"] = 42
        self.assert_gate(PASSING_CHECKS, False, settings=settings)
        self.assertEqual(self.sleeps, [])
        history = passing_runs()
        history[2]["app"] = {"id": 42}
        self.assert_gate(PASSING_CHECKS, False, run_samples=[history])

    def test_unbound_or_missing_launch_required_settings_fail_immediately(self) -> None:
        for app in (None, -1, 0, "15368"):
            with self.subTest(app=app):
                settings = rules(*REQUIRED)
                settings[0]["parameters"]["required_status_checks"][0]["integration_id"] = app
                self.assert_gate(PASSING_CHECKS, False, settings=settings)
                self.assertEqual(self.sleeps, [])
        self.assert_gate(PASSING_CHECKS, False, settings=rules(*REQUIRED[1:]))
        self.assertEqual(self.sleeps, [])

    def test_foreign_app_success_cannot_hide_required_source_failure(self) -> None:
        history = passing_runs()
        history[2]["conclusion"] = "failure"
        history.append(dict(history[2], id=900, app={"id": 42}, conclusion="success"))
        self.assert_gate(PASSING_CHECKS, False, run_samples=[history])
        self.assertEqual(self.sleeps, [])

    def test_malformed_or_wrong_head_check_runs_fail_immediately(self) -> None:
        changes = (
            {"head_sha": "c" * 40},
            {"id": None},
            {"id": 1.5},
            {"app": {}},
            {"name": ""},
            {"status": "unknown"},
            {"status": "queued", "conclusion": "success"},
            {"conclusion": None},
            {"conclusion": "unknown"},
        )
        for change in changes:
            with self.subTest(change=change):
                history = passing_runs()
                history[2].update(change)
                self.assert_gate(PASSING_CHECKS, False, run_samples=[history])
                self.assertEqual(self.sleeps, [])

    def test_conflicting_check_run_identities_fail_immediately(self) -> None:
        history = passing_runs()
        history.append(dict(history[2], conclusion="failure"))
        self.assert_gate(PASSING_CHECKS, False, run_samples=[history])
        self.assertEqual(self.sleeps, [])

    def test_additional_required_contexts_are_also_source_bound_and_waited_for(self) -> None:
        extra = {"bucket": "pass", "name": "coverage", "workflow": "Rust CI", "required": True}
        self.assert_gate(PASSING_CHECKS + [extra], True, settings=rules(*REQUIRED, "Rust CI / coverage"))
        pending = dict(extra, bucket="pending")
        result = self.run_gate(
            PASSING_CHECKS,
            settings=rules(*REQUIRED, "Rust CI / coverage"),
            samples=[PASSING_CHECKS + [pending], PASSING_CHECKS + [extra]],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.sleeps, [["sleep", "15"]])


if __name__ == "__main__":
    unittest.main()
