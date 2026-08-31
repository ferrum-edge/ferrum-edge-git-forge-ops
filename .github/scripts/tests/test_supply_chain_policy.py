import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "check_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("check_supply_chain", SCRIPT)
check_supply_chain = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_supply_chain
SPEC.loader.exec_module(check_supply_chain)


class SupplyChainPolicyTests(unittest.TestCase):
    def test_candidate_branch_classifier_fails_even_when_trusted_text_remains(self):
        text = """
ref: ${{ github.event.pull_request.base.sha }}
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

    def test_missing_base_sha_checkout_fails(self):
        violations = check_supply_chain.trusted_classifier_violations(
            "validate-pr.yml",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        )
        self.assertTrue(any("base SHA" in item for item in violations))

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
