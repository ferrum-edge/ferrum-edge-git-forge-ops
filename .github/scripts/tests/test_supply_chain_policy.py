import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "check_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("check_supply_chain", SCRIPT)
check_supply_chain = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_supply_chain
SPEC.loader.exec_module(check_supply_chain)


class SupplyChainPolicyTests(unittest.TestCase):
    def test_immutable_bootstrap_checker_accepts_the_current_policy(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r"name: Check out immutable policy bootstrap.*?ref: ([0-9a-f]{40})",
            workflow,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "security workflow must pin a bootstrap commit")
        bootstrap_sha = match.group(1)
        checked_out = (
            ROOT / "bootstrap-supply-chain/.github/scripts/check_supply_chain.py"
        )
        if checked_out.is_file() and not checked_out.is_symlink():
            bootstrap_source = checked_out.read_text(encoding="utf-8")
        else:
            shown = subprocess.run(
                [
                    "git",
                    "show",
                    f"{bootstrap_sha}:.github/scripts/check_supply_chain.py",
                ],
                cwd=ROOT,
                check=False,
                text=True,
                capture_output=True,
            )
            if shown.returncode != 0:
                self.skipTest("immutable bootstrap commit is unavailable in this checkout")
            bootstrap_source = shown.stdout

        with tempfile.TemporaryDirectory() as directory:
            checker = Path(directory) / "check_supply_chain.py"
            checker.write_text(bootstrap_source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(checker), "--root", str(ROOT)],
                cwd=ROOT,
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_root_override_checks_the_selected_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(check_supply_chain.action_files(root), [])
            nested = root / ".github" / "workflows"
            nested.mkdir(parents=True)
            action = nested / "sample.yml"
            action.write_text("name: sample\n", encoding="utf-8")
            self.assertEqual(check_supply_chain.action_files(root), [action])

    def test_security_policy_must_execute_the_default_branch_checker(self):
        secure = "\n".join(
            [
                "if: github.event_name == 'pull_request'",
                "ref: ${{ github.event.repository.default_branch }}",
                "path: trusted-supply-chain",
                "CANDIDATE_CHECKER=.github/scripts/check_supply_chain.py",
                "Candidate must retain the regular-file supply-chain checker.",
                "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py",
                "module.ROOT = candidate",
                'module.WORKFLOWS = candidate / ".github" / "workflows"',
                "module.ACTION_FILES = sorted(",
                "sys.argv = [str(checker)]",
                "raise SystemExit(module.main())",
            ]
        )
        self.assertEqual(
            check_supply_chain.trusted_supply_chain_policy_violations(secure), []
        )

        insecure = secure.replace(
            "ref: ${{ github.event.repository.default_branch }}",
            "ref: ${{ github.event.pull_request.base.sha }}",
        )
        violations = check_supply_chain.trusted_supply_chain_policy_violations(
            insecure
        )
        self.assertTrue(any("missing" in item for item in violations))
        self.assertTrue(any("unprotected PR base" in item for item in violations))

    def test_pr_trigger_must_rerun_on_retarget_and_target_main(self):
        secure = """on:
  pull_request:
    types: [opened, synchronize, reopened, edited]
    branches: [main]
"""
        self.assertEqual(
            check_supply_chain.pull_request_trigger_violations("secure.yml", secure),
            [],
        )
        insecure = """on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: ['**']
"""
        violations = check_supply_chain.pull_request_trigger_violations(
            "insecure.yml", insecure
        )
        self.assertTrue(any("base-retarget" in item for item in violations))
        self.assertTrue(any("protected main" in item for item in violations))

    def test_workflow_display_names_are_exact_contracts(self):
        self.assertEqual(
            check_supply_chain.workflow_name_violations(
                "validate-pr.yml",
                "name: GitForgeOps PR Static Validation\non: pull_request\n",
                "GitForgeOps PR Static Validation",
            ),
            [],
        )
        violations = check_supply_chain.workflow_name_violations(
            "validate-pr.yml",
            "name: Renamed\non: pull_request\n",
            "GitForgeOps PR Static Validation",
        )
        self.assertTrue(any("must remain exactly" in item for item in violations))

    def test_validator_token_must_be_scoped_to_the_installer_step(self):
        secure = """      - name: Download validator
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: .github/scripts/install-ferrum-edge.sh
      - name: Post review
        env:
          GITHUB_TOKEN: ${{ github.token }}
"""
        self.assertEqual(
            check_supply_chain.installer_step_auth_violations(
                "trusted-pr-review.yml", secure
            ),
            [],
        )
        insecure = secure.replace(
            "          GITHUB_TOKEN: ${{ github.token }}\n", "", 1
        )
        violations = check_supply_chain.installer_step_auth_violations(
            "trusted-pr-review.yml", insecure
        )
        self.assertTrue(any("every validator download step" in item for item in violations))

    def test_candidate_branch_classifier_fails_even_when_trusted_text_remains(self):
        text = """
ref: ${{ github.event.repository.default_branch }}
result=$(python3 trusted-scope/.github/scripts/changed_files.py
result=$(python3 .github/scripts/changed_files.py
"""
        violations = check_supply_chain.trusted_classifier_violations(
            "rust-ci.yml",
            text,
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("candidate-branch" in item for item in violations))

    def test_missing_default_branch_checkout_fails(self):
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("default branch" in item for item in violations))

    def test_unprotected_pr_base_cannot_supply_trusted_classifier(self):
        text = """
ref: ${{ github.event.repository.default_branch }}
ref: ${{ github.event.pull_request.base.sha }}
result=$(python3 trusted-scope/.github/scripts/changed_files.py
result='{"complete":false,"matches":true}'
"""
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            text,
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("unprotected PR base" in item for item in violations))

    def test_missing_trusted_helper_must_run_the_gate_fail_safe(self):
        text = """
ref: ${{ github.event.repository.default_branch }}
result=$(python3 trusted-scope/.github/scripts/changed_files.py
"""
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            text,
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("bootstrap fail-safe" in item for item in violations))

        secure = text + "\nresult='{\"complete\":false,\"matches\":true}'\n"
        self.assertEqual(
            check_supply_chain.trusted_classifier_violations(
                "validate-pr.yml",
                secure,
                "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
                1,
            ),
            [],
        )

    def test_digest_allowlist_accepts_multiple_commented_builds(self):
        text = (
            "# Reviewed SHA-256 allowlist.\n"
            "\n"
            + "a" * 64
            + "  ferrum-edge-linux-x86_64  # 2026-08-01T00:00:00Z release latest\n"
            + "b" * 64
            + "  ferrum-edge-linux-x86_64  # 2026-09-02T03:02:29Z release latest\n"
        )
        self.assertEqual(check_supply_chain.digest_allowlist_violations(text), [])
        self.assertEqual(
            check_supply_chain.allowlisted_validator_digests(text),
            ["a" * 64, "b" * 64],
        )

    def test_digest_allowlist_rejects_locator_pins_and_bad_records(self):
        for malformed in (
            "release-379454492 ferrum-edge-linux-x86_64 537268718 537268721 "
            + "c" * 64
            + "\n",
            "C" * 64 + "  ferrum-edge-linux-x86_64\n",
            "c" * 64 + "  ferrum-edge-macos-x86_64\n",
            "c" * 64 + "\n",
            "c" * 64 + "  ferrum-edge-linux-x86_64  537268718\n",
        ):
            with self.subTest(malformed=malformed.strip()):
                violations = check_supply_chain.digest_allowlist_violations(malformed)
                self.assertTrue(any("entry must be exactly" in item for item in violations))

    def test_digest_allowlist_must_approve_exactly_one_build_per_digest(self):
        empty = check_supply_chain.digest_allowlist_violations("# nothing yet\n")
        self.assertTrue(any("at least one" in item for item in empty))
        duplicated = ("d" * 64 + "  ferrum-edge-linux-x86_64\n") * 2
        self.assertTrue(
            any(
                "must not repeat" in item
                for item in check_supply_chain.digest_allowlist_violations(duplicated)
            )
        )

    def test_validator_may_not_be_repinned_by_a_mutable_locator(self):
        self.assertEqual(
            check_supply_chain.validator_locator_violations(
                ["run: bash .github/scripts/install-ferrum-edge.sh\n"]
            ),
            [],
        )
        digest_variable = check_supply_chain.validator_locator_violations(
            ["env:\n  FERRUM_EDGE_SHA256: ${{ vars.FERRUM_EDGE_SHA256 }}\n"]
        )
        self.assertTrue(any("mutable variable" in item for item in digest_variable))
        release_identity = check_supply_chain.validator_locator_violations(
            ["env:\n  RAW: ${{ vars.FERRUM_EDGE_VERSION || 'release-1' }}\n"]
        )
        self.assertTrue(any("release identity" in item for item in release_identity))

    def test_state_writer_token_must_follow_build_and_stay_ephemeral(self):
        secure = "\n".join(
            [
                "run: cargo install --path . --locked",
                "- name: Mint narrowly scoped state-writer token",
                "- name: Commit state update",
                "STATE_WRITER_TOKEN: ${{ steps.state-writer.outputs.token }}",
                "git config --local http.https://github.com/.extraheader",
                "git config --local --unset-all http.https://github.com/.extraheader",
            ]
        )
        self.assertEqual(
            check_supply_chain.state_writer_token_violations(
                "rotate.yml", secure, "- name: Commit state update"
            ),
            [],
        )

        insecure = secure.replace(
            "- name: Mint narrowly scoped state-writer token\n", ""
        ) + "\ntoken: ${{ steps.state-writer.outputs.token }}"
        violations = check_supply_chain.state_writer_token_violations(
            "rotate.yml", insecure, "- name: Commit state update"
        )
        self.assertTrue(any("persisted by checkout" in item for item in violations))
        self.assertTrue(any("minted after" in item for item in violations))


if __name__ == "__main__":
    unittest.main()
