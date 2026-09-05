import importlib.util
import re
import shutil
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
    def test_trusted_policy_checker_has_no_stale_bootstrap_fallback(self):
        # A one-time commit-pinned bootstrap covered the window where `main`
        # did not yet carry this checker. `main` carries it now, so a fallback
        # can only substitute an OLDER policy for the protected one — exactly
        # what happens when a tree legitimately changes something the old
        # policy still demands.
        workflow = (ROOT / ".github/workflows/security.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("bootstrap-supply-chain", workflow)
        self.assertEqual(
            check_supply_chain.trusted_supply_chain_policy_violations(workflow), []
        )

        with_fallback = workflow.replace(
            "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py\n",
            "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py\n"
            "            if [ ! -f \"$CHECKER\" ]; then\n"
            "              CHECKER=bootstrap-supply-chain/.github/scripts/check_supply_chain.py\n"
            "            fi\n",
            1,
        )
        violations = check_supply_chain.trusted_supply_chain_policy_violations(
            with_fallback
        )
        self.assertTrue(
            any("only from the protected default branch" in item for item in violations),
            violations,
        )

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

    def test_every_whole_secrets_context_form_is_rejected(self):
        # `secrets.NAME` and `secrets['NAME']` were caught in validate-pr.yml,
        # but the whole-context forms — which hand over EVERY environment
        # secret at once — were allowed everywhere else, which is where the
        # privileged workflows actually used them.
        pattern = re.compile(r"\$\{\{[^}]*\bsecrets\b")
        for leak in (
            "${{ toJSON(secrets) }}",
            "${{ fromJSON(toJSON(secrets)) }}",
            "${{ secrets }}",
            "${{ secrets.FERRUM_GATEWAY_URL }}",
            "${{ secrets['FERRUM_GATEWAY_URL'] }}",
        ):
            self.assertRegex(leak, pattern, f"{leak} must be treated as a secret leak")
        for benign in (
            "# secrets never reach this job",
            "${{ github.token }}",
            "${{ vars.GITFORGEOPS_STATE_APP_ID }}",
        ):
            self.assertNotRegex(benign, pattern)

    def test_only_named_secret_references_survive_in_any_workflow(self):
        # validate-pr.yml must receive NO secrets; every other workflow may
        # read `secrets.<NAME>` and nothing broader.
        for leak in (
            "        run: echo '${{ toJSON(secrets) }}'",
            "        run: echo '${{ fromJSON(toJSON(secrets)) }}'",
            "        run: echo '${{ secrets }}'",
            "          URL: ${{ secrets['FERRUM_GATEWAY_URL'] }}",
            "          KEY: ${{ toJSON(secrets.FERRUM_GATEWAY_URL) }}${{ secrets }}",
        ):
            with self.subTest(leak=leak):
                self.assertTrue(
                    check_supply_chain.whole_secrets_context_violations(
                        "sample.yml", leak
                    ),
                    leak,
                )
        benign = "\n".join(
            [
                "# the whole secrets context never reaches this job",
                "          URL: ${{ secrets.FERRUM_GATEWAY_URL }}",
                "          KEY: ${{ secrets.FERRUM_ADMIN_JWT_SECRET }}",
                "          APP: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
                "          TOKEN: ${{ github.token }}",
                "        if: ${{ secrets.FERRUM_GATEWAY_URL != '' }}",
            ]
        )
        self.assertEqual(
            check_supply_chain.whole_secrets_context_violations("sample.yml", benign), []
        )
        self.assertTrue(
            check_supply_chain.whole_secrets_context_violations(
                "sample.yml", "    secrets: inherit\n"
            )
        )

    def test_no_workflow_dumps_the_whole_secrets_context(self):
        # Guard the wiring, not just the helper: a leak in a workflow that is
        # not validate-pr.yml used to pass the whole policy run.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rust-ci.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "    steps:",
                    "    steps:\n      - run: echo '${{ toJSON(secrets) }}'",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("only `secrets.<NAME>`" in item for item in violations), violations
        )

    def test_credential_bundle_shards_are_bound_by_name_up_to_the_rust_ceiling(self):
        limit, limit_violations = check_supply_chain.credential_shard_limit(ROOT)
        self.assertEqual(limit_violations, [])
        self.assertIsNotNone(limit)
        step = "\n".join(
            ["      - name: Load credential bundles", "        env:"]
            + [
                f"          {name}: ${{{{ secrets.{name} }}}}"
                for name in ["FERRUM_CREDS_BUNDLE"]
                + [f"FERRUM_CREDS_BUNDLE_{shard}" for shard in range(1, limit)]
            ]
        )
        self.assertEqual(
            check_supply_chain.credential_bundle_binding_violations(
                "sample.yml", step + "\n", limit
            ),
            [],
        )

        dropped = step.replace(
            f"          FERRUM_CREDS_BUNDLE_{limit - 1}: "
            f"${{{{ secrets.FERRUM_CREDS_BUNDLE_{limit - 1} }}}}\n",
            "",
        ).replace(
            f"\n          FERRUM_CREDS_BUNDLE_{limit - 1}: "
            f"${{{{ secrets.FERRUM_CREDS_BUNDLE_{limit - 1} }}}}",
            "",
        )
        violations = check_supply_chain.credential_bundle_binding_violations(
            "sample.yml", dropped + "\n", limit
        )
        self.assertTrue(
            any("missing or mismatched" in item for item in violations), violations
        )

        beyond = (
            step
            + f"\n          FERRUM_CREDS_BUNDLE_{limit}: "
            + f"${{{{ secrets.FERRUM_CREDS_BUNDLE_{limit} }}}}\n"
        )
        violations = check_supply_chain.credential_bundle_binding_violations(
            "sample.yml", beyond, limit
        )
        self.assertTrue(
            any("beyond MAX_BUNDLE_SHARDS" in item for item in violations), violations
        )

        self.assertTrue(
            check_supply_chain.credential_bundle_binding_violations(
                "sample.yml", "      - name: Something else\n", limit
            )
        )

    def test_shard_ceiling_must_agree_between_rust_and_the_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            loader = root / ".github/scripts/credential_bundles.py"
            text = loader.read_text(encoding="utf-8")
            limit = int(
                re.search(r"^MAX_BUNDLE_SHARDS = (\d+)$", text, re.MULTILINE).group(1)
            )
            loader.write_text(
                text.replace(
                    f"MAX_BUNDLE_SHARDS = {limit}",
                    f"MAX_BUNDLE_SHARDS = {limit + 1}",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("MAX_BUNDLE_SHARDS disagrees" in item for item in violations), violations
        )

    def test_privileged_workflows_must_bind_every_declared_shard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/apply-on-merge.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "          FERRUM_CREDS_BUNDLE_9: ${{ secrets.FERRUM_CREDS_BUNDLE_9 }}\n",
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any(
                "must bind every bundle shard secret" in item and "FERRUM_CREDS_BUNDLE_9" in item
                for item in violations
            ),
            violations,
        )

    def test_validate_pr_rejects_the_whole_secrets_context(self):
        # Guard the wiring, not just the regex: the real workflow text is run
        # through the same check the policy applies.
        workflow = (ROOT / ".github/workflows/validate-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotRegex(workflow, r"\$\{\{[^}]*\bsecrets\b")
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/validate-pr.yml"
            path.write_text(
                workflow.replace(
                    "    steps:",
                    "    steps:\n      - run: echo '${{ toJSON(secrets) }}'",
                    1,
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("must not receive any secrets" in item for item in violations),
            violations,
        )

    def test_state_guard_must_run_the_default_branch_definition(self):
        secure = """on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, labeled, unlabeled]
    branches: [main]
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.repository.default_branch }}
"""
        self.assertEqual(check_supply_chain.state_guard_trigger_violations(secure), [])

        head_loaded = secure.replace("  pull_request_target:", "  pull_request:")
        violations = check_supply_chain.state_guard_trigger_violations(head_loaded)
        self.assertTrue(
            any("pull_request_target trigger is missing" in item for item in violations),
            violations,
        )
        self.assertTrue(
            any("head-loaded pull_request trigger" in item for item in violations),
            violations,
        )

    def test_state_guard_must_never_check_out_the_pull_request(self):
        untrusted = """on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, labeled, unlabeled]
    branches: [main]
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.repository.default_branch }}
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v7
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        violations = check_supply_chain.state_guard_trigger_violations(untrusted)
        self.assertTrue(
            any("never check out" in item for item in violations), violations
        )
        self.assertTrue(
            any("exactly one checkout" in item for item in violations), violations
        )

    def test_every_rust_toolchain_step_must_pin_the_version(self):
        secure = """      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.98.0
      - name: Install Rust toolchain again
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.98.0
"""
        self.assertEqual(
            check_supply_chain.rust_toolchain_violations("rust-ci.yml", secure), []
        )

        # One pinned step used to satisfy the whole file.
        insecure = secure.replace(
            """      - name: Install Rust toolchain again
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
        with:
          toolchain: 1.98.0
""",
            """      - name: Install Rust toolchain again
        uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000
""",
        )
        violations = check_supply_chain.rust_toolchain_violations(
            "rust-ci.yml", insecure
        )
        self.assertTrue(
            any("every dtolnay/rust-toolchain step" in item for item in violations),
            violations,
        )

    def test_unconfigured_repository_skips_instead_of_failing_the_merge(self):
        secure = "\n".join(
            [
                "if [[ ! -f .gitforgeops/config.yaml ]]; then",
                'echo "envs=[]" >> "$GITHUB_OUTPUT"',
                "needs.list-envs.outputs.envs != '[]'",
            ]
        )
        self.assertEqual(check_supply_chain.unconfigured_repo_skip_violations(secure), [])

        hard_failing = secure + (
            "\necho \"::error::Repository configuration is required before binding a "
            "deployment environment.\"\n"
        )
        violations = check_supply_chain.unconfigured_repo_skip_violations(hard_failing)
        self.assertTrue(
            any("must not fail the merge" in item for item in violations), violations
        )

        without_skip = "needs.list-envs.outputs.envs != '[]'"
        violations = check_supply_chain.unconfigured_repo_skip_violations(without_skip)
        self.assertTrue(
            any("empty matrix" in item for item in violations), violations
        )

    def test_state_writer_app_must_be_proven_before_the_gateway_mutation(self):
        secure = "\n".join(
            [
                "- name: Require state-writer App credentials",
                "STATE_APP_ID: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
                "STATE_APP_PRIVATE_KEY: ${{ secrets.GITFORGEOPS_STATE_APP_PRIVATE_KEY }}",
                'if [ -z "$STATE_APP_ID" ] || [ -z "$STATE_APP_PRIVATE_KEY" ]; then',
                "- name: Mint narrowly scoped state-writer token",
                "app-id: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
            ]
        )
        self.assertEqual(
            check_supply_chain.state_writer_preflight_violations("rotate.yml", secure),
            [],
        )

        missing = secure.replace(
            "- name: Require state-writer App credentials\n", "", 1
        )
        violations = check_supply_chain.state_writer_preflight_violations(
            "rotate.yml", missing
        )
        self.assertTrue(
            any("before any gateway mutation" in item for item in violations),
            violations,
        )

        secret_app_id = secure.replace(
            "app-id: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
            "app-id: ${{ secrets.GITFORGEOPS_STATE_APP_ID }}",
        )
        violations = check_supply_chain.state_writer_preflight_violations(
            "rotate.yml", secret_app_id
        )
        self.assertTrue(
            any("must be read from vars" in item for item in violations), violations
        )

    def test_state_commits_must_not_suppress_required_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/rotate.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'in ${INPUT_ENVIRONMENT}"', 'in ${INPUT_ENVIRONMENT} [skip ci]"'
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("[skip ci]" in item for item in violations), violations
        )

    def test_resolved_credential_file_must_live_under_runner_temp(self):
        # A bare `mktemp` lands in a /tmp that self-hosted runners share
        # between jobs and never clean.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/drift-check.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'creds_file="${RUNNER_TEMP:-/tmp}/ferrum-creds-',
                    'creds_file="/tmp/ferrum-creds-',
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("under $RUNNER_TEMP" in item for item in violations), violations
        )

    def test_release_must_attest_every_published_image_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index("      - name: Publish signed Docker Hub build provenance")
            end = text.index("      - name: Bind image digest into build-input record")
            path.write_text(text[:start] + text[end:], encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("every published image name" in item for item in violations), violations
        )
        self.assertTrue(
            any("missing subject" in item for item in violations), violations
        )

    def test_release_push_trigger_ignores_ledger_commits_and_keeps_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace("      - '.state/**'\n", ""),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("ignore ledger-only commits" in item for item in violations), violations
        )

    def test_release_gate_must_name_upstream_rather_than_test_for_a_fork(self):
        # A "Use this template" copy is not a fork, so a fork test would let
        # every customer repository try to publish the upstream image.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "if: github.repository == 'ferrum-edge/ferrum-edge-git-forge-ops'"
                    " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'",
                    "if: github.event.repository.fork == false"
                    " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("never publishes" in item for item in violations), violations
        )
        self.assertTrue(
            any("does not distinguish a template copy" in item for item in violations),
            violations,
        )

    def test_release_gate_must_cover_both_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/release.yml"
            text = path.read_text(encoding="utf-8")
            gate = (
                "    if: github.repository == 'ferrum-edge/ferrum-edge-git-forge-ops'"
                " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'\n"
            )
            path.write_text(text.replace(gate, "", 1), encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("never publishes" in item for item in violations), violations
        )

    def test_settings_audit_is_dispatchable_behind_a_ref_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/settings-audit.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  workflow_dispatch:\n", ""
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("dispatchable audit is missing" in item for item in violations),
            violations,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/settings-audit.yml"
            text = path.read_text(encoding="utf-8")
            start = text.index("      - name: Require protected default branch")
            end = text.index("      - name: Check out protected default branch")
            path.write_text(text[:start] + text[end:] + text[start:end], encoding="utf-8")
            violations = self._violations(root)
        self.assertTrue(
            any("before the audit token is bound" in item for item in violations),
            violations,
        )

    def test_trusted_review_pins_the_triggering_workflow_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/trusted-pr-review.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "          EXPECTED_WORKFLOW_PATH: .github/workflows/validate-pr.yml\n",
                    "",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("EXPECTED_WORKFLOW_PATH" in item for item in violations), violations
        )

    def test_trusted_review_serializes_runs_for_one_reviewed_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            path = root / ".github/workflows/trusted-pr-review.yml"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  group: trusted-pr-review-${{ github.event.workflow_run.head_sha }}\n",
                    "  group: trusted-pr-review\n",
                ),
                encoding="utf-8",
            )
            violations = self._violations(root)
        self.assertTrue(
            any("trusted-pr-review-" in item for item in violations), violations
        )

    def test_mirrored_repository_is_a_clean_baseline(self):
        # Every mutation test above asserts the checker FAILS. That only proves
        # something if the unmutated mirror passes — otherwise a broken helper
        # would make them all green for the wrong reason.
        with tempfile.TemporaryDirectory() as directory:
            root = self._mirror_repo(Path(directory))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # -- helpers ------------------------------------------------------------

    def _mirror_repo(self, root: Path) -> Path:
        """Copy the policy-relevant tree so a test can mutate one file.

        The checker reads workflows, the Dockerfile, CODEOWNERS, the toolchain
        pin, and the validator checksum policy, so all of them come along.
        """
        for relative in (
            ".github/workflows",
            ".github/scripts/check_supply_chain.py",
            ".github/scripts/credential_bundles.py",
            ".github/scripts/install-ferrum-edge.sh",
            ".github/scripts/refresh-ferrum-edge-pin.sh",
            ".github/ferrum-edge-checksums.txt",
            ".github/CODEOWNERS",
            "Dockerfile",
            ".dockerignore",
            "rust-toolchain.toml",
            "src/secrets/bundle.rs",
        ):
            source = ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        return root

    def _violations(self, root: Path) -> list[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        return [
            line.strip().lstrip("- ")
            for line in result.stderr.splitlines()
            if line.startswith("  - ")
        ]


if __name__ == "__main__":
    unittest.main()
