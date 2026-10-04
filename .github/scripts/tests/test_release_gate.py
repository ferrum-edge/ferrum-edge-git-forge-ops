"""Exercise release authorization with the workflow shell and filtered gh output."""

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

GATE = re.compile(
    r"jq -e -s --argjson required '(?P<required>\[.*?\])' "
    r"--argjson accepted '(?P<accepted>\[.*?\])' "
    r"--slurpfile all_checks \"\$all_checks_file\" '(?P<program>.*?)' \"\$checks_file\"",
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

if arguments[0] == "api":
    print(json.dumps([[{
        "number": 452,
        "state": "closed",
        "base": {"ref": os.environ["DEFAULT_BRANCH"]},
        "merged_at": "2026-10-04T00:00:00Z",
        "merge_commit_sha": os.environ["RELEASE_SHA"],
    }]]))
elif arguments[:2] == ["pr", "checks"]:
    required = "--required" in arguments
    mode = "REQUIRED" if required else "ALL"
    response = os.environ.get(f"STUB_{mode}_RESPONSE")
    if response is not None:
        sys.stdout.write(Path(response).read_text(encoding="utf-8"))
    else:
        checks = json.loads(Path(os.environ["STUB_CHECKS"]).read_text(encoding="utf-8"))
        if required:
            checks = [check for check in checks if check.get("required", False)]
        print(json.dumps([
            {key: check[key] for key in ("bucket", "name", "workflow") if key in check}
            for check in checks
        ]))
    # gh's JSON mode exports buckets without an outcome-based exit status.
    # Lookup/export errors are represented separately, even with JSON stdout.
    raise SystemExit(int(os.environ[f"STUB_{mode}_STATUS"]))
else:
    raise SystemExit("unexpected gh invocation")
"""


class ReleaseGateListTests(unittest.TestCase):
    def test_the_workflow_lists_exactly_the_launch_checks(self) -> None:
        # Behavior tests run the workflow itself; pin the launch lists as well
        # so accidentally removing a mandatory check cannot make them pass.
        match = gate()
        self.assertEqual(json.loads(match.group("required")), REQUIRED)
        self.assertEqual(json.loads(match.group("accepted")), ACCEPTED)


@unittest.skipUnless(
    shutil.which("jq") and shutil.which("bash"),
    "jq and bash are required to exercise the release gate",
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
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text(STUB_GH, encoding="utf-8")
            (bin_dir / "gh").chmod(0o755)
            checks_path = root / "checks.json"
            checks_path.write_text(json.dumps(checks), encoding="utf-8")
            calls_path = root / "calls.jsonl"
            env = {
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "REPO": "acme/template-copy",
                "RELEASE_SHA": "a" * 40,
                "DEFAULT_BRANCH": "main",
                "GH_TOKEN": "unused",
                "STUB_CHECKS": str(checks_path),
                "STUB_CALLS": str(calls_path),
                "STUB_REQUIRED_STATUS": str(required_status),
                "STUB_ALL_STATUS": str(all_status),
            }
            for mode, response in (("REQUIRED", required_response), ("ALL", all_response)):
                if response is not None:
                    path = root / f"{mode.lower()}-response.json"
                    path.write_text(response, encoding="utf-8")
                    env[f"STUB_{mode}_RESPONSE"] = str(path)
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", gate_script()],
                cwd=root,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
            calls = [
                json.loads(line) for line in calls_path.read_text(encoding="utf-8").splitlines()
            ]
            required_call = [
                "pr",
                "checks",
                "452",
                "--repo",
                "acme/template-copy",
                "--required",
                "--json",
                "bucket,name,workflow",
            ]
            self.assertEqual(calls[1], required_call, result.stderr)
            if required_status == 0:
                all_call = [argument for argument in required_call if argument != "--required"]
                self.assertEqual(calls[2:], [all_call], result.stderr)
            else:
                self.assertEqual(len(calls), 2, result.stderr)
            return result

    def assert_gate(self, checks, accepted: bool, **options) -> None:
        result = self.run_gate(checks, **options)
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
        )
        for mode in ("required", "all"):
            for response in responses:
                with self.subTest(mode=mode, response=response):
                    self.assert_gate(PASSING_CHECKS, False, **{f"{mode}_response": response})


if __name__ == "__main__":
    unittest.main()
