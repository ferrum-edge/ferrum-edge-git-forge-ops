import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
CHECK = ROOT / ".github/scripts/check-validator-resource-labels.sh"


class ValidatorLabelsTests(unittest.TestCase):
    def run_check(self, code):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "ferrum-edge"
            binary.write_text(
                "#!/bin/sh\n"
                "[ \"$#\" -eq 7 ] || exit 91\n"
                "[ \"$1\" = validate ] && [ \"$2\" = -m ] || exit 92\n"
                "[ \"$3\" = file ] && [ \"$4\" = -s ] || exit 93\n"
                "[ -f \"$5\" ] && [ ! -s \"$5\" ] || exit 94\n"
                "[ \"$6\" = -c ] && [ -f \"$7\" ] || exit 95\n"
                "[ -z \"${FERRUM_MODE+x}\" ] || exit 96\n"
                "[ -z \"${FERRUM_NAMESPACE+x}\" ] || exit 97\n"
                "[ -z \"${GITHUB_TOKEN+x}\" ] || exit 98\n"
                "[ \"$(grep -c 'provisioned-by: ferrum-edge-git-forge-ops' \"$7\")\" "
                "-eq 4 ] || exit 99\n"
                "echo fixture-reached\n"
                "cat <<'EDGE_ERROR' >&2\n"
                "Validation error: Spec validation failed: unknown field `labels`, "
                "expected one of `id`, `username`, `namespace`, `custom_id`, "
                "`credentials`, `acl_groups`, `created_at`, `updated_at`\n"
                "EDGE_ERROR\n"
                f"exit {code}\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                FERRUM_MODE="mesh",
                FERRUM_NAMESPACE="foreign",
                GITHUB_TOKEN="synthetic-token-must-not-reach-validator",
            )
            return subprocess.run(
                ["bash", str(CHECK), str(binary)],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_acceptance_requires_successful_labeled_fixture_validation(self):
        result = self.run_check(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fixture-reached", result.stdout)
        self.assertIn("accepts resource labels on all four", result.stdout)

    def test_rejection_and_process_errors_fail_closed_with_original_diagnostic(self):
        for code in (1, 2, 137):
            with self.subTest(code=code):
                result = self.run_check(code)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("fixture-reached", result.stdout)
                self.assertIn("unknown field `labels`", result.stderr)
                self.assertIn("::error::Pinned Ferrum Edge validator", result.stdout)
                self.assertNotIn("accepts resource labels on all four", result.stdout)

    def test_missing_validator_fails_before_capability_check(self):
        result = subprocess.run(
            ["bash", str(CHECK)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("absolute path", result.stderr)

    def test_pairing_is_required_even_when_declarative_validation_is_skipped(self):
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text()
        pairing = workflow.split("\n  validator-pairing:\n", 1)[1].split(
            "\n  gitforgeops-required-static-validation:\n", 1
        )[0]
        self.assertNotIn("\n    if:", pairing)
        self.assertNotIn("continue-on-error:", pairing)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", pairing)
        self.assertIn("bash trusted-validator/.github/scripts/install-ferrum-edge.sh", pairing)
        self.assertIn("            .github/ferrum-edge-checksums.txt\n", pairing)
        self.assertLess(
            pairing.index("install-ferrum-edge.sh"),
            pairing.index("check-validator-resource-labels.sh"),
        )
        gate = workflow.split("\n  gitforgeops-required-static-validation:\n", 1)[1]
        self.assertIn("needs: [validator-pairing, scope, list-envs, validate]", gate)
        self.assertIn("PAIRING_RESULT: ${{ needs.validator-pairing.result }}", gate)
        self.assertLess(
            gate.index('[ "$PAIRING_RESULT" = success ] || {'),
            gate.index('if [ "$RELEVANT" != true ]; then'),
        )

    def test_canary_checks_capability_only_after_verified_install(self):
        workflow = (ROOT / ".github/workflows/validator-pin-canary.yml").read_text()
        verify = workflow.split("        id: verify\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertLess(
            verify.index("install-ferrum-edge.sh"),
            verify.index('if [ "$status" -eq 0 ]; then'),
        )
        self.assertIn('echo "pin_status=$status" >>"$GITHUB_OUTPUT"', verify)
        self.assertIn('"$RUNNER_TEMP/validator-canary/ferrum-edge" || status=$?', verify)
        self.assertIn("check-validator-resource-labels.sh", verify)
        self.assertLess(
            verify.index("check-validator-resource-labels.sh"),
            verify.index('echo "status=$status" >>"$GITHUB_OUTPUT"'),
        )
        self.assertIn("if: steps.verify.outputs.pin_status != '0'", workflow)
        self.assertIn("if: steps.verify.outputs.status == '0'", workflow)


if __name__ == "__main__":
    unittest.main()
