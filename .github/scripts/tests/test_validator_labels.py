import os
import re
import shutil
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
        self.assertIn(
            "bash trusted-validator/.github/scripts/check-validator-resource-labels.sh", pairing
        )
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

    def test_candidate_probe_and_fixture_cannot_approve_an_incompatible_validator(self):
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text()
        for job_name in ("validate", "validator-pairing"):
            with self.subTest(job=job_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for prefix in (root, root / "trusted-validator"):
                    (prefix / ".github/scripts").mkdir(parents=True)
                    (prefix / "tests/fixtures").mkdir(parents=True)
                shutil.copy2(CHECK, root / "trusted-validator/.github/scripts" / CHECK.name)
                fixture = "tests/fixtures/validator-resource-labels.yaml"
                shutil.copy2(ROOT / fixture, root / "trusted-validator" / fixture)
                (root / ".github/scripts" / CHECK.name).write_text(
                    "#!/bin/sh\necho candidate-probe-approved\nexit 0\n"
                )
                (root / fixture).write_text("version: '1'\n")
                binary = root / "ferrum-edge"
                binary.write_text(
                    "#!/bin/sh\n"
                    "if grep -q 'provisioned-by:' \"$7\"; then\n"
                    "  echo incompatible-labels >&2\n  exit 1\nfi\nexit 0\n"
                )
                binary.chmod(0o755)
                job = workflow.split(f"\n  {job_name}:\n", 1)[1]
                job = re.split(r"^  \S", job, maxsplit=1, flags=re.MULTILINE)[0]
                invocation = re.search(
                    r"^          bash (\S*check-validator-resource-labels\.sh) ",
                    job,
                    re.MULTILINE,
                )
                self.assertIsNotNone(invocation)
                result = subprocess.run(
                    ["bash", invocation.group(1), str(binary)],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("incompatible-labels", result.stderr)
                self.assertNotIn("candidate-probe-approved", result.stdout)

    def test_canary_checks_capability_only_after_verified_install(self):
        workflow = (ROOT / ".github/workflows/validator-pin-canary.yml").read_text()
        install = workflow.split("        id: install\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        verify = workflow.split("        id: verify\n", 1)[1].split(
            "\n      - name:", 1
        )[0]
        self.assertIn("install-ferrum-edge.sh", install)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", install)
        self.assertNotIn("check-validator-resource-labels.sh", install)
        self.assertNotIn("GITHUB_TOKEN", verify)
        self.assertIn("if: steps.install.outputs.status == '0'", verify)
        self.assertIn('"$RUNNER_TEMP/validator-canary/ferrum-edge" || status=$?', verify)
        self.assertIn("check-validator-resource-labels.sh", verify)
        self.assertIn("if: steps.install.outputs.status != '0'", workflow)
        self.assertIn(
            "if: steps.install.outputs.status == '0' && steps.verify.outputs.status == '0'",
            workflow,
        )


    def test_canary_reports_a_broken_pairing_even_when_the_refresh_fails(self):
        # Without a status function a step's `if:` is implicitly
        # `success() && ...`, so a failed install followed by a failed refresh
        # would skip both the tracking issue and the final failure.
        workflow = (ROOT / ".github/workflows/validator-pin-canary.yml").read_text()
        condition = (
            "if: ${{ !cancelled() && (steps.install.outputs.status != '0' || "
            "steps.verify.outputs.status != '0') }}"
        )
        for name in (
            "Open or update the tracking issue",
            "Fail when the validator pairing is invalid",
        ):
            with self.subTest(step=name):
                step = workflow.split(f"      - name: {name}\n", 1)[1].split(
                    "\n      - name:", 1
                )[0]
                self.assertIn(condition, step)


if __name__ == "__main__":
    unittest.main()
