"""Regression tests for the apply scheduling/supersession boundary.

Each case builds a real git repository and replays the merge order that
produced the bug: an authorized apply for commit A queues behind an
environment approval, more commits land on `main`, and the guard has to decide
whether A's run may still reconcile the refreshed head.

The property under test is not "which paths match" but "no authorized desired
change is ever left with nothing to reconcile it". That holds exactly while
the set that supersedes a queued run equals the set that schedules a new one.
"""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = Path(__file__).parents[1] / "deployment_scope.py"
SPEC = importlib.util.spec_from_file_location("deployment_scope", SCRIPT)
deployment_scope = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deployment_scope
SPEC.loader.exec_module(deployment_scope)

APPLY_WORKFLOW = ROOT / ".github/workflows/apply-on-merge.yml"


class DeploymentScopeTests(unittest.TestCase):
    # -- the stranded-apply regression --------------------------------------

    def test_docs_only_merge_does_not_strand_a_queued_resource_apply(self):
        """Issue #261: A waits for approval, a README-only B merges, A applies.

        B does not match the apply trigger, so nothing else will ever
        reconcile A's resources. Refusing A here is a permanent silent loss of
        an authorized configuration change.
        """
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(repo, {"README.md": "docs\n"})
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertFalse(decision.superseded)
        self.assertEqual(decision.inert, ["README.md"])
        self.assertIn(
            "no deployment-affecting change",
            "".join(decision.messages(trigger, head, "main")),
        )

    def test_ledger_and_assembled_output_never_supersede(self):
        # The apply itself pushes these back to the protected branch, so the
        # run after it in the queue always sees them.
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(
                repo,
                {
                    ".state/production.json": '{"version":1}\n',
                    "assembled/production.yaml": "version: '1'\n",
                },
            )
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertFalse(decision.superseded)

    def test_tests_and_unrelated_workflows_are_inert(self):
        # `cargo install --path .` builds the binary target only, so a test
        # edit cannot change the executable this job runs. An unrelated
        # workflow file is not this job's procedure.
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(
                repo,
                {
                    "tests/unit/apply_tests.rs": "// new case\n",
                    ".github/workflows/release.yml": "name: Release\n",
                    "docs/github-launch-controls.md": "# controls\n",
                },
            )
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertFalse(decision.superseded)

    # -- what must still supersede ------------------------------------------

    def test_a_later_resource_merge_supersedes_and_has_its_own_run(self):
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(repo, {"resources/ferrum/proxies/b.yaml": "id: b\n"})
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertTrue(decision.superseded)
        self.assertEqual(decision.superseding, ["resources/ferrum/proxies/b.yaml"])
        self.assertTrue(self._schedules(["resources/ferrum/proxies/b.yaml"]))

    def test_policy_configuration_cannot_ride_an_older_approval(self):
        # A policy override is authorized against the triggering PR's head. A
        # newer `.gitforgeops/policies.yaml` would change which findings block
        # an apply that a different PR's label approved.
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(
                repo, {".gitforgeops/policies.yaml": "version: 1\nrules: {}\n"}
            )
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertTrue(decision.superseded)
        self.assertTrue(self._schedules([".gitforgeops/policies.yaml"]))

    def test_consumer_changes_cannot_shift_the_credential_recipient(self):
        # Credential delivery is addressed to the author of the TRIGGERING
        # merge. A later consumer merge introduces slots that author never
        # requested, so it must take its own run — with its own author.
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(
                repo,
                {
                    "resources/ferrum/consumers/c.yaml": (
                        "kind: Consumer\nspec:\n  id: c\n"
                    )
                },
            )
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertTrue(decision.superseded)
        self.assertTrue(self._schedules(["resources/ferrum/consumers/c.yaml"]))

    def test_executable_and_helper_changes_supersede(self):
        for path, content in (
            ("src/apply/api_target.rs", "// engine\n"),
            ("Cargo.lock", "# lock\n"),
            ("Cargo.toml", "[package]\n"),
            ("build.rs", "fn main() {}\n"),
            ("rust-toolchain.toml", "[toolchain]\n"),
            # rustup prefers the legacy file when both exist.
            ("rust-toolchain", "1.98.0\n"),
            (".github/scripts/credential_bundles.py", "# loader\n"),
            (".github/ferrum-edge-checksums.txt", "# pins\n"),
            (".github/workflows/apply-on-merge.yml", "name: GitForgeOps Apply\n"),
        ):
            with self.subTest(path=path):
                with self._repo() as repo:
                    trigger = self._commit(
                        repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"}
                    )
                    head = self._commit(repo, {path: content})
                    decision = deployment_scope.classify(trigger, head, repo)
                self.assertTrue(decision.superseded, path)
                self.assertTrue(self._schedules([path]), path)

    def test_a_superseding_change_is_always_accompanied_by_inert_noise(self):
        # A merge that touches both halves is superseding: the deployment-
        # affecting half decides, and the inert half never softens it.
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(
                repo,
                {"README.md": "docs\n", "src/main.rs": "fn main() {}\n"},
            )
            decision = deployment_scope.classify(trigger, head, repo)
        self.assertTrue(decision.superseded)
        self.assertEqual(decision.superseding, ["src/main.rs"])

    # -- the invariant itself -----------------------------------------------

    def test_every_superseding_path_schedules_a_replacement_apply(self):
        """No authorized change may be cancelled with nothing to replace it."""
        self.assertTrue(
            self._schedules(
                [
                    self._sample(path)
                    for path in deployment_scope.DEPLOYMENT_INPUT_PATHS
                ]
            )
        )

    def test_generated_output_is_not_a_trigger_or_a_deployment_input(self):
        trigger_paths = self._trigger_paths()
        for produced in deployment_scope.GENERATED_PATHS:
            self.assertNotIn(produced, trigger_paths)
            self.assertNotIn(produced, deployment_scope.DEPLOYMENT_INPUT_PATHS)

    def test_trigger_filter_matches_the_classifier_exactly(self):
        self.assertEqual(
            sorted(self._trigger_paths()),
            sorted(deployment_scope.DEPLOYMENT_INPUT_PATHS),
        )

    # -- attribution stays bound to the triggering merge ---------------------

    def test_apply_attributes_authorization_to_the_triggering_merge(self):
        workflow = APPLY_WORKFLOW.read_text(encoding="utf-8")
        # The PR number and author come from the merge commit that triggered
        # the run, never from `github.actor`.
        self.assertIn("GITFORGEOPS_ACTOR: ${{ steps.pr.outputs.author }}", workflow)
        self.assertIn(
            "GITFORGEOPS_PR_NUMBER: ${{ steps.pr.outputs.number }}", workflow
        )
        self.assertNotIn("GITFORGEOPS_ACTOR: ${{ github.actor }}", workflow)
        # ...while the revision recorded in the audit trail is the refreshed
        # head the guard actually let through.
        self.assertIn(
            "GITHUB_SHA: ${{ steps.freshness.outputs.applied_sha }}", workflow
        )
        # A recorded credential allocation is bound to the triggering merge,
        # which a re-run keeps; the applied head moves with every state commit.
        self.assertEqual(
            workflow.count("GITFORGEOPS_ALLOCATION_REVISION: ${{ github.sha }}"),
            workflow.count("run: gitforgeops apply"),
        )
        self.assertNotIn(
            "GITFORGEOPS_ALLOCATION_REVISION: ${{ steps.freshness", workflow
        )
        # And the guard runs the shared classifier rather than an ad-hoc diff,
        # piped from the triggering commit into an isolated interpreter.
        self.assertIn(
            'git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" | \\\n'
            "            python3 -I - classify \\\n",
            workflow,
        )

    # -- CLI ----------------------------------------------------------------

    def test_cli_exit_codes_and_annotations(self):
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            inert_head = self._commit(repo, {"README.md": "docs\n"})
            proceed = self._cli(repo, trigger, inert_head)
            self.assertEqual(proceed.returncode, 0, proceed.stdout + proceed.stderr)
            self.assertIn("::notice::", proceed.stdout)

            superseding_head = self._commit(
                repo, {"resources/ferrum/proxies/b.yaml": "id: b\n"}
            )
            refused = self._cli(repo, trigger, superseding_head)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("::error::Superseded deployment", refused.stdout)
        # The message has to tell the operator where the replacement is.
        self.assertIn("schedules its own", refused.stdout)
        self.assertIn(deployment_scope.RECOVERY_DOC, refused.stdout)

    def test_piped_classifier_ignores_modules_the_refreshed_head_supplies(self):
        # The guard pipes the trusted classifier into `python3 -I -` inside the
        # refreshed checkout. A plain `python3 -` searches that checkout first,
        # so a newer head could plant `argparse.py` and approve itself.
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            head = self._commit(
                repo,
                {
                    "resources/ferrum/proxies/b.yaml": "id: b\n",
                    "argparse.py": "print('shadowed')\nraise SystemExit(0)\n",
                },
            )
            source = SCRIPT.read_text(encoding="utf-8")
            shadowed = self._piped(repo, source, [], trigger, head)
            isolated = self._piped(repo, source, ["-I"], trigger, head)
        # The planted module really is reachable without isolation...
        self.assertEqual(shadowed.returncode, 0, shadowed.stderr)
        self.assertIn("shadowed", shadowed.stdout)
        # ...and `-I` runs the trusted classifier, which refuses the head.
        self.assertEqual(isolated.returncode, 1, isolated.stdout + isolated.stderr)
        self.assertNotIn("shadowed", isolated.stdout)
        self.assertIn("::error::Superseded deployment", isolated.stdout)

    def test_unchanged_head_is_reported_as_such(self):
        with self._repo() as repo:
            trigger = self._commit(repo, {"resources/ferrum/proxies/a.yaml": "id: a\n"})
            decision = deployment_scope.classify(trigger, trigger, repo)
        self.assertFalse(decision.superseded)
        self.assertEqual(decision.inert, [])
        self.assertIn(
            "is unchanged since triggering commit",
            "".join(decision.messages(trigger, trigger, "main")),
        )

    # -- helpers ------------------------------------------------------------

    def _sample(self, trigger_path: str) -> str:
        """A concrete file the trigger glob would match."""
        if trigger_path.endswith("/**"):
            return f"{trigger_path[:-len('/**')]}/sample.txt"
        return trigger_path

    def _trigger_paths(self) -> list[str]:
        text = APPLY_WORKFLOW.read_text(encoding="utf-8")
        start = text.index("    paths:\n") + len("    paths:\n")
        paths = []
        for line in text[start:].splitlines():
            if not line.startswith("      - "):
                break
            paths.append(line.removeprefix("      - ").strip().strip("'\""))
        return paths

    def _schedules(self, changed: list[str]) -> bool:
        """Would a push changing exactly these paths start an apply run?"""
        trigger_paths = self._trigger_paths()
        return all(
            any(self._matches(pattern, path) for pattern in trigger_paths)
            for path in changed
        )

    @staticmethod
    def _matches(pattern: str, path: str) -> bool:
        if pattern.endswith("/**"):
            return path.startswith(pattern[: -len("**")])
        return path == pattern

    def _repo(self):
        return _TemporaryRepo()

    def _commit(self, repo: Path, files: dict[str, str]) -> str:
        for relative, content in files.items():
            destination = repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-m", "change", "--no-gpg-sign")
        return self._git(repo, "rev-parse", "HEAD").strip()

    @staticmethod
    def _git(repo: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=str(repo),
            check=True,
            text=True,
            capture_output=True,
        ).stdout

    @staticmethod
    def _cli(repo: Path, trigger: str, head: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "classify",
                trigger,
                head,
                "--repo",
                str(repo),
            ],
            check=False,
            text=True,
            capture_output=True,
        )

    @staticmethod
    def _piped(
        repo: Path, source: str, flags: list[str], trigger: str, head: str
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *flags, "-", "classify", trigger, head],
            input=source,
            cwd=str(repo),
            check=False,
            text=True,
            capture_output=True,
        )


class _TemporaryRepo:
    """A throwaway git repository with one initial commit."""

    def __enter__(self) -> Path:
        self._temporary = tempfile.TemporaryDirectory()
        repo = Path(self._temporary.name)
        for args in (
            ("init", "--quiet", "--initial-branch=main"),
            ("config", "user.email", "test@example.invalid"),
            ("config", "user.name", "Test"),
            ("config", "commit.gpgsign", "false"),
        ):
            subprocess.run(
                ["git", *args], cwd=str(repo), check=True, capture_output=True
            )
        (repo / "README.md").write_text("start\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "-A"], cwd=str(repo), check=True, capture_output=True
        )
        subprocess.run(
            ["git", "commit", "-m", "init", "--no-gpg-sign"],
            cwd=str(repo),
            check=True,
            capture_output=True,
        )
        return repo

    def __exit__(self, *exc_info) -> None:
        self._temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
