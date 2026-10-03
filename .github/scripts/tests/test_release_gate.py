"""The release gate's jq program must accept exactly the launch-required checks."""

from __future__ import annotations

import json
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
    {"bucket": "pass", "name": "security-supply-chain-policy", "workflow": "Security"},
    {
        "bucket": "pass",
        "name": "gitforgeops-required-static-validation",
        "workflow": "GitForgeOps PR Static Validation",
    },
    {"bucket": "pass", "name": "rust-ci-check", "workflow": "Rust CI"},
    {"bucket": "pass", "name": "security-cargo-audit", "workflow": "Security"},
    {
        "bucket": "pass",
        "name": "state-guard-reject-state-edits",
        "workflow": "GitForgeOps State Guard",
    },
]
TRUSTED_POLICY_CHECK = {
    "bucket": "pass",
    "name": "trusted-supply-chain-policy",
    "workflow": "GitForgeOps Supply-Chain Policy",
}

GATE = re.compile(
    r"jq -e --argjson required '(?P<required>\[.*?\])' "
    r"--argjson accepted '(?P<accepted>\[.*?\])' '(?P<program>.*?)' \"\$checks_file\"",
    re.S,
)


def gate() -> re.Match[str]:
    """Locate the jq gate the release job runs over `gh pr checks` output."""
    match = GATE.search(WORKFLOW.read_text(encoding="utf-8"))
    if match is None:
        raise AssertionError("release.yml no longer contains the required-check jq gate")
    return match


def gate_program() -> str:
    return gate().group("program")


class ReleaseGateListTests(unittest.TestCase):
    def test_the_workflow_lists_exactly_the_launch_checks(self) -> None:
        # The gate's behavior tests below feed these constants to jq, so they
        # only prove something while the workflow carries the same lists.
        match = gate()
        self.assertEqual(json.loads(match.group("required")), REQUIRED)
        self.assertEqual(json.loads(match.group("accepted")), ACCEPTED)


@unittest.skipUnless(shutil.which("jq"), "jq is required to exercise the release gate")
class ReleaseGateTests(unittest.TestCase):
    def run_gate(self, checks: list[dict[str, str]]) -> int:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(checks, handle)
            path = handle.name
        try:
            result = subprocess.run(
                [
                    "jq",
                    "-e",
                    "--argjson",
                    "required",
                    json.dumps(REQUIRED),
                    "--argjson",
                    "accepted",
                    json.dumps(ACCEPTED),
                    gate_program(),
                    path,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            Path(path).unlink(missing_ok=True)
        return result.returncode

    def test_every_required_check_passing_is_accepted(self) -> None:
        self.assertEqual(self.run_gate(PASSING_CHECKS), 0)

    def test_a_missing_required_check_is_rejected(self) -> None:
        self.assertNotEqual(self.run_gate(PASSING_CHECKS[1:]), 0)

    def test_a_failing_required_check_is_rejected(self) -> None:
        checks = [dict(check) for check in PASSING_CHECKS]
        checks[2]["bucket"] = "fail"
        self.assertNotEqual(self.run_gate(checks), 0)

    def test_extra_unrelated_checks_do_not_matter(self) -> None:
        checks = PASSING_CHECKS + [{"bucket": "fail", "name": "coverage", "workflow": "Rust CI"}]
        self.assertEqual(self.run_gate(checks), 0)

    def test_the_trusted_policy_check_may_be_absent_before_the_ruleset_switch(self) -> None:
        # The ruleset gains `trusted-supply-chain-policy` in an operator step
        # after its workflow merges; until then `--required` does not list it.
        self.assertEqual(self.run_gate(PASSING_CHECKS), 0)
        self.assertEqual(self.run_gate(PASSING_CHECKS + [TRUSTED_POLICY_CHECK]), 0)

    def test_a_reported_trusted_policy_check_must_pass(self) -> None:
        for bucket in ("fail", "pending", "skipping", "cancel"):
            with self.subTest(bucket=bucket):
                reported = dict(TRUSTED_POLICY_CHECK, bucket=bucket)
                self.assertNotEqual(self.run_gate(PASSING_CHECKS + [reported]), 0)

    def test_the_trusted_policy_check_does_not_replace_the_retiring_one(self) -> None:
        # Expand step: the in-tree job still runs the workflow-script tests and
        # stays required until the retire step.
        without_old = [
            check for check in PASSING_CHECKS if check["name"] != "security-supply-chain-policy"
        ]
        self.assertNotEqual(self.run_gate(without_old + [TRUSTED_POLICY_CHECK]), 0)

    def test_a_passing_duplicate_cannot_mask_a_failing_trusted_result(self) -> None:
        # Every reported result under the accepted context must pass, so a
        # second, passing check run with the same name changes nothing.
        failing = dict(TRUSTED_POLICY_CHECK, bucket="fail")
        for order in ([TRUSTED_POLICY_CHECK, failing], [failing, TRUSTED_POLICY_CHECK]):
            with self.subTest(order=[check["bucket"] for check in order]):
                self.assertNotEqual(self.run_gate(PASSING_CHECKS + order), 0)


if __name__ == "__main__":
    unittest.main()
