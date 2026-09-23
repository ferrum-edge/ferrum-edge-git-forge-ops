"""The promotion gate: authorized, not merely ordered.

`needs:` proves two jobs ran in sequence. It proves nothing about what is
running on the gateway. These tests pin the conditions under which a
promoting job may proceed, and — more importantly — every condition under
which it must not.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "promotion_record.py"
SPEC = importlib.util.spec_from_file_location("promotion_record", SCRIPT)
promotion_record = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = promotion_record
SPEC.loader.exec_module(promotion_record)

WORKFLOW = ROOT / ".github/workflows/apply-on-merge.yml"
REVISION = "a" * 40
OTHER_REVISION = "b" * 40


def record(**overrides):
    payload = {
        "environment": "staging",
        "revision": REVISION,
        "apply_result": promotion_record.SUCCESS,
        "verify_result": promotion_record.SUCCESS,
        "run_id": "42",
        "actor": "dev",
    }
    payload.update(overrides)
    return promotion_record.write(**payload)


class AuthorizationTests(unittest.TestCase):
    def test_an_applied_and_verified_revision_authorizes_the_promotion(self):
        self.assertEqual(
            promotion_record.blockers(record(), "staging", REVISION), []
        )
        self.assertTrue(record()["authorized"])

    def test_a_missing_record_is_not_a_successful_promotion(self):
        # The job was never started, was cancelled before recording, or the
        # runner was lost. None of those is "staging is fine".
        reasons = promotion_record.blockers(None, "staging", REVISION)
        self.assertEqual(len(reasons), 1)
        self.assertIn("left no promotion record", reasons[0])
        self.assertIn("has not happened", reasons[0])

    def test_a_failed_apply_blocks(self):
        reasons = promotion_record.blockers(
            record(apply_result=promotion_record.FAILURE), "staging", REVISION
        )
        self.assertTrue(any("apply reported" in reason for reason in reasons))

    def test_configuration_acceptance_alone_does_not_authorize(self):
        # The gateway took the write and serves a 502. This is the entire
        # reason the traffic gate exists.
        reasons = promotion_record.blockers(
            record(verify_result=promotion_record.FAILURE), "staging", REVISION
        )
        self.assertTrue(
            any("traffic verification reported" in reason for reason in reasons)
        )
        self.assertTrue(
            any("not shown to be serving it" in reason for reason in reasons)
        )

    def test_an_unverifiable_predecessor_does_not_authorize(self):
        # File mode has no data plane, and an environment with no declared
        # check verified nothing. Both record something other than `success`
        # and neither may stand in for a passing traffic check.
        for result in (promotion_record.SKIPPED, promotion_record.NOT_RUN):
            with self.subTest(result=result):
                entry = record(verify_result=result)
                self.assertFalse(entry["authorized"])
                self.assertTrue(
                    promotion_record.blockers(entry, "staging", REVISION)
                )

    def test_a_cancelled_predecessor_does_not_authorize(self):
        entry = record(apply_result=promotion_record.CANCELLED)
        self.assertFalse(entry["authorized"])
        self.assertTrue(promotion_record.blockers(entry, "staging", REVISION))

    def test_only_success_authorizes(self):
        self.assertEqual(
            promotion_record.AUTHORIZING, frozenset({promotion_record.SUCCESS})
        )
        for result in promotion_record.RESULTS:
            if result == promotion_record.SUCCESS:
                continue
            self.assertNotIn(result, promotion_record.AUTHORIZING)

    def test_an_unknown_result_is_refused_rather_than_recorded(self):
        with self.assertRaises(ValueError):
            record(verify_result="probably_fine")


class RevisionBindingTests(unittest.TestCase):
    def test_a_promotion_authorizes_one_revision(self):
        # The protected branch moved between staging and production. The
        # approval was for a revision this job is no longer about to apply.
        reasons = promotion_record.blockers(record(), "staging", OTHER_REVISION)
        self.assertEqual(len(reasons), 1)
        self.assertIn("was applied at", reasons[0])
        self.assertIn("A promotion authorizes one revision", reasons[0])

    def test_a_rerun_of_an_older_workflow_cannot_promote(self):
        # Same mechanism, different cause: an old run's recorded revision no
        # longer matches the head the freshness guard fixed for this job.
        stale = record(revision=OTHER_REVISION)
        self.assertTrue(promotion_record.blockers(stale, "staging", REVISION))

    def test_a_different_overlay_is_not_a_different_revision(self):
        # Staging and production legitimately assemble different bytes,
        # because they select different overlays. What must match is the
        # commit the desired resources, policy, engine and workflows came
        # from — and that is what the record carries.
        self.assertEqual(record()["source_revision"], REVISION)
        self.assertNotIn("assembled", json.dumps(record()))


class LedgerCommitTests(unittest.TestCase):
    """The predecessor's own ledger commit moves the branch before we look.

    Every apply publishes `.state/<env>.json`, so the head the promoting job
    refreshes onto is never the revision staging recorded. An exact-SHA test
    therefore blocked every promotion; the rule is "same deployment inputs",
    judged by the freshness guard's own classifier.
    """

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self._temporary.name)
        for args in (
            ("init", "--quiet", "--initial-branch=main"),
            ("config", "user.email", "test@example.invalid"),
            ("config", "user.name", "Test"),
            ("config", "commit.gpgsign", "false"),
        ):
            self._git(*args)
        self.applied = self._commit({"resources/ferrum/proxies/orders.yaml": "a\n"})

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo),
            check=True,
            text=True,
            capture_output=True,
        ).stdout

    def _commit(self, files: dict[str, str]) -> str:
        for relative, content in files.items():
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        self._git("add", "-A")
        self._git("commit", "-m", "change", "--no-gpg-sign")
        return self._git("rev-parse", "HEAD").strip()

    def _reasons(self, revision: str) -> list[str]:
        return promotion_record.blockers(
            record(revision=self.applied), "staging", revision, self.repo
        )

    def test_the_predecessors_ledger_commit_does_not_block_its_own_promotion(self):
        head = self._commit({".state/staging.json": "{}\n"})
        self.assertNotEqual(head, self.applied)
        self.assertEqual(self._reasons(head), [])

    def test_documentation_and_tests_between_them_do_not_block(self):
        head = self._commit({"README.md": "docs\n", "tests/unit/x.rs": "// t\n"})
        self.assertEqual(self._reasons(head), [])

    def test_a_deployment_input_between_them_still_blocks(self):
        self._commit({".state/staging.json": "{}\n"})
        head = self._commit({"resources/ferrum/proxies/orders.yaml": "b\n"})
        reasons = self._reasons(head)
        self.assertEqual(len(reasons), 1)
        self.assertIn("deployment inputs changed", reasons[0])
        self.assertIn("resources/ferrum/proxies/orders.yaml", reasons[0])

    def test_a_revision_that_is_not_a_descendant_blocks(self):
        # A re-run of an older workflow: the record is from a revision the
        # branch has since moved past, so it is the *descendant* here.
        older = self.applied
        newer = self._commit({".state/staging.json": "{}\n"})
        reasons = promotion_record.blockers(
            record(revision=newer), "staging", older, self.repo
        )
        self.assertTrue(any("is not an ancestor" in reason for reason in reasons))

    def test_an_unknown_recorded_revision_blocks_rather_than_passing(self):
        reasons = promotion_record.blockers(
            record(revision="c" * 40), "staging", self.applied, self.repo
        )
        self.assertTrue(any("is not an ancestor" in reason for reason in reasons))

    def test_the_cli_compares_in_the_given_checkout(self):
        head = self._commit({".state/staging.json": "{}\n"})
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "staging.json").write_text(
                json.dumps(record(revision=self.applied)), encoding="utf-8"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "require",
                    "--environment", "staging",
                    "--revision", head,
                    "--records", directory,
                    "--repo", str(self.repo),
                ],
                check=False,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("only outside the deployment inputs", result.stdout)


class ProvenanceTests(unittest.TestCase):
    def test_the_record_carries_who_authorized_what(self):
        entry = record(run_id="99", actor="octocat", pull_request="7")
        self.assertEqual(entry["run_id"], "99")
        self.assertEqual(entry["actor"], "octocat")
        self.assertEqual(entry["pull_request"], "7")

    def test_the_summary_names_environment_revision_result_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "staging.json").write_text(
                json.dumps(record(pull_request="7")), encoding="utf-8"
            )
            (path / "production.json").write_text(
                json.dumps(
                    record(
                        environment="production",
                        verify_result=promotion_record.FAILURE,
                    )
                ),
                encoding="utf-8",
            )
            summary = promotion_record.summarize(path)
        self.assertIn("`staging`", summary)
        self.assertIn("`production`", summary)
        self.assertIn(REVISION[:12], summary)
        self.assertIn("PR #7", summary)
        self.assertIn("run 42", summary)
        self.assertIn("failure", summary)
        # And it says what the two columns mean, because "apply succeeded" is
        # the thing people mistake for "it works".
        self.assertIn("Apply is configuration acceptance", summary)

    def test_an_empty_summary_claims_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = promotion_record.summarize(Path(directory))
        self.assertIn("No environment recorded a promotion result", summary)


class CliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            check=False,
            text=True,
            capture_output=True,
        )

    def test_require_exits_zero_only_when_authorized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            written = self._run(
                "write",
                "--environment", "staging",
                "--revision", REVISION,
                "--apply-result", "success",
                "--verify-result", "success",
                "--run-id", "42",
                "--actor", "dev",
                "--output", str(path / "staging.json"),
            )
            self.assertEqual(written.returncode, 0, written.stderr)

            ok = self._run(
                "require",
                "--environment", "staging",
                "--revision", REVISION,
                "--records", str(path),
            )
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn("::notice::Promotion authorized", ok.stdout)

            moved = self._run(
                "require",
                "--environment", "staging",
                "--revision", OTHER_REVISION,
                "--records", str(path),
            )
        self.assertEqual(moved.returncode, 1)
        self.assertIn("::error::Promotion blocked", moved.stdout)

    def test_require_blocks_when_the_predecessor_left_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(
                "require",
                "--environment", "staging",
                "--revision", REVISION,
                "--records", directory,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("left no promotion record", result.stdout)


class WorkflowWiringTests(unittest.TestCase):
    """The workflow has to actually use the gate, not merely ship it."""

    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_independent_environments_keep_the_parallel_matrix(self):
        # The existing capability must survive untouched: an environment with
        # no `promotion.requires` deploys in parallel exactly as before.
        self.assertIn(
            "select(.promotion_requires == null) | .environment", self.text
        )
        self.assertIn(
            "environment: ${{ fromJson(needs.list-envs.outputs.envs) }}", self.text
        )
        self.assertIn("fail-fast: false", self.text)

    def test_the_promote_job_waits_for_the_independent_phase(self):
        self.assertIn("needs: [list-envs, apply]", self.text)
        self.assertIn("environment: ${{ matrix.scope.environment }}", self.text)

    def test_the_promote_job_requires_a_matching_authorized_record(self):
        self.assertIn("promotion_record.py require", self.text)
        self.assertIn('--environment "$REQUIRES"', self.text)
        # The comparison needs the checkout: without it only an exact SHA
        # matches, and the predecessor's ledger commit guarantees it never does.
        self.assertIn("--repo .", self.text)
        self.assertIn(
            'REVISION: ${{ steps.freshness.outputs.applied_sha }}', self.text
        )

    def test_the_gate_runs_before_anything_is_built_or_applied(self):
        gate = self.text.index("- name: Require an authorized promotion")
        for later in (
            "bash .github/scripts/install-ferrum-edge.sh",
            "gitforgeops apply --auto-approve",
        ):
            self.assertLess(gate, self.text.rindex(later), later)

    def test_each_environment_records_its_own_outcome(self):
        self.assertIn("promotion_record.py write", self.text)
        self.assertIn("--apply-result", self.text)
        self.assertIn("--verify-result", self.text)
        # File mode has no data plane; it must record `skipped`, which does
        # not authorize anything downstream.
        self.assertIn("verify=skipped", self.text)

    def test_the_promotion_is_reported_even_when_it_was_blocked(self):
        self.assertIn("promotion_record.py summarize", self.text)
        self.assertIn("promotion-summary:", self.text)

    def test_both_privileged_jobs_keep_the_freshness_guard(self):
        # The promote job fixes its revision the same way, so a
        # deployment-affecting merge during staging verification refuses it
        # rather than silently promoting the newer revision.
        self.assertEqual(
            self.text.count(
                "- name: Refresh protected branch and reject stale deployments"
            ),
            2,
        )
        self.assertEqual(
            self.text.count("deployment_scope.py classify"), 2
        )


if __name__ == "__main__":
    unittest.main()
