import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "check_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("check_supply_chain", SCRIPT)
check_supply_chain = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_supply_chain
SPEC.loader.exec_module(check_supply_chain)


class SupplyChainPolicyTests(unittest.TestCase):
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
