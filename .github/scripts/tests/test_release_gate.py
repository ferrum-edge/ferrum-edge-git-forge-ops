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


def gate_program() -> str:
    """Extract the jq program the release gate runs over `gh pr checks` output."""
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r"jq -e --argjson required '\[.*?\]' '(?P<program>.*?)' \"\$checks_file\"",
        text,
        re.S,
    )
    if match is None:
        raise AssertionError("release.yml no longer contains the required-check jq gate")
    return match.group("program")


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


if __name__ == "__main__":
    unittest.main()
