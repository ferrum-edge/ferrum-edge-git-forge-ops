"""The downstream update contract, exercised against real git repositories.

Each case builds an "upstream" repository and a "customer" repository copied
from it at some baseline, lets both sides move, and checks what the update tool
does. The properties under test are the ones a customer has to be able to rely
on before they will ever run this against a repository that deploys:

* an upstream security fix reaches them,
* their resources, overlays, configuration, ownership ledger and generated
  output are never touched,
* a file both sides changed is reported, never overwritten, and does not
  silently advance the baseline.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).parents[3]
UMASK = os.umask(0)
os.umask(UMASK)
SCRIPT = Path(__file__).parents[1] / "template_update.py"
SPEC = importlib.util.spec_from_file_location("template_update", SCRIPT)
template_update = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = template_update
SPEC.loader.exec_module(template_update)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(repo), check=True, text=True, capture_output=True
    ).stdout


def write(root: Path, files: dict[str, str]) -> None:
    for relative, contents in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message, "--no-gpg-sign")
    return git(repo, "rev-parse", "HEAD").strip()


def init(root: Path) -> None:
    for args in (
        ("init", "--quiet", "--initial-branch=main"),
        ("config", "user.email", "test@example.invalid"),
        ("config", "user.name", "Test"),
        ("config", "commit.gpgsign", "false"),
        # `git commit` otherwise detaches `git maintenance run --auto`, which
        # can still be writing `.git/objects` when the directory is removed
        # (#374). Nothing may outlive the git command that started it.
        ("config", "maintenance.auto", "false"),
        ("config", "gc.auto", "0"),
        ("config", "core.fsmonitor", "false"),
    ):
        subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True)


# The shape of a realistic customer repository: upstream-managed engine and
# workflow files, plus the customer's own resources, overlays, configuration,
# policy and ownership ledger.
UPSTREAM_TREE = {
    "src/main.rs": "fn main() { println!(\"v1\"); }\n",
    "src/apply/api_target.rs": "// v1\n",
    ".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# v1\n",
    ".github/scripts/credential_bundles.py": "# v1\n",
    ".github/ferrum-edge-checksums.txt": "aaa111  ferrum-edge\n",
    "docs/github-launch-controls.md": "# controls v1\n",
    "Cargo.toml": '[package]\nname = "gitforgeops"\nversion = "0.1.0"\n',
    ".github/CODEOWNERS": "* @upstream-maintainer\n",
    "README.md": "# upstream readme\n",
}


CUSTOMER_TREE = {
    "resources/ferrum/proxies/orders.yaml": "kind: Proxy\nspec:\n  id: orders\n",
    "overlays/production/ferrum/proxies/orders.yaml": "kind: Proxy\nspec:\n  id: orders\n",
    ".gitforgeops/config.yaml": "version: 1\nenvironments:\n  production: {}\n",
    ".gitforgeops/policies.yaml": "version: 1\n",
    ".state/production.json": '{"environment":"production","resources":{}}\n',
    "assembled/production.yaml": "version: '1'\n",
    ".github/CODEOWNERS": "* @customer-maintainer\n",
}


class Fixture:
    """An upstream repository and a customer repository copied from it."""

    def __init__(self, temporary: Path) -> None:
        self.upstream = temporary / "upstream"
        self.customer = temporary / "customer"
        self.upstream.mkdir()
        self.customer.mkdir()

        init(self.upstream)
        write(self.upstream, UPSTREAM_TREE)
        self.baseline = commit(self.upstream, "upstream v1")

        # "Use this template": the files, not the history.
        write(self.customer, {**UPSTREAM_TREE, **CUSTOMER_TREE})
        template_update.Baseline(
            upstream=str(self.upstream), ref="main", commit=self.baseline
        ).write(self.customer)
        init(self.customer)
        commit(self.customer, "initial import from template")

    def upstream_change(self, files: dict[str, str], message: str) -> str:
        write(self.upstream, files)
        return commit(self.upstream, message)

    def customer_change(self, files: dict[str, str]) -> None:
        write(self.customer, files)
        commit(self.customer, "local change")

    def run(
        self, *args: str, upstream: str | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo-root",
                str(self.customer),
                *args,
                "--upstream",
                upstream or str(self.upstream),
            ],
            check=False,
            text=True,
            capture_output=True,
        )

    def read(self, relative: str) -> str:
        return (self.customer / relative).read_text(encoding="utf-8")


class TemplateUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self._temporary.name))

    def tearDown(self) -> None:
        self._temporary.cleanup()

    # -- an upstream fix reaches the customer -------------------------------

    def test_an_upstream_fix_is_adopted_and_the_baseline_advances(self):
        target = self.fixture.upstream_change(
            {
                "src/apply/api_target.rs": "// v2: the security fix\n",
                ".github/ferrum-edge-checksums.txt": "bbb222  ferrum-edge\n",
            },
            "upstream v2",
        )
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.fixture.read("src/apply/api_target.rs"), "// v2: the security fix\n"
        )
        self.assertEqual(
            self.fixture.read(".github/ferrum-edge-checksums.txt"),
            "bbb222  ferrum-edge\n",
        )
        baseline = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        self.assertEqual(baseline["commit"], target)

    def test_apply_prints_the_checks_to_re_run_before_deploying(self):
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "upstream v2")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        for command, _ in template_update.POST_ADOPTION_CHECKS:
            self.assertIn(command, result.stdout)

    def test_an_upstream_deletion_is_adopted_too(self):
        (self.fixture.upstream / "src/apply/api_target.rs").unlink()
        self.fixture.upstream_change({}, "upstream removed a file")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.fixture.customer / "src/apply/api_target.rs").exists())

    def test_upstream_mode_replaces_local_permission_and_special_bits(self):
        path = self.fixture.customer / "src/main.rs"
        upstream_path = self.fixture.upstream / "src/main.rs"
        upstream_path.chmod(0o755)
        self.fixture.upstream_change({}, "make upstream executable")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(path.stat().st_mode & 0o7777, 0o777 & ~UMASK)

        path.chmod(0o4755)
        upstream_path.write_text("fn main() { println!(\"v2\"); }\n", encoding="utf-8")
        self.fixture.upstream_change({}, "change executable upstream file")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(path.stat().st_mode & 0o7777, 0o777 & ~UMASK)

        upstream_path.chmod(0o644)
        upstream_path.write_text("fn main() { println!(\"v3\"); }\n", encoding="utf-8")
        self.fixture.upstream_change({}, "make upstream non-executable")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(path.stat().st_mode & 0o7777, 0o666 & ~UMASK)

    def test_only_the_owner_execute_bit_counts_as_a_mode_change(self):
        # Git records a file as executable by its owner bit alone, so a group
        # or other execute bit is not a local edit that blocks an upstream fix.
        (self.fixture.customer / "src/main.rs").chmod(0o645)
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), "// v2\n")

    def test_a_local_execute_bit_conflicts_unless_file_mode_is_off(self):
        (self.fixture.customer / "src/main.rs").chmod(0o755)
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        conflict = self.fixture.run("plan")
        self.assertEqual(conflict.returncode, 1, conflict.stdout + conflict.stderr)
        self.assertIn("CONFLICTS (1)", conflict.stdout)

        # With core.fileMode=false Git ignores the work tree's execute bit,
        # and so does the comparison.
        git(self.fixture.customer, "config", "core.fileMode", "false")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), "// v2\n")

    # -- customer-owned files and state survive -----------------------------

    def test_customer_resources_state_and_configuration_are_never_touched(self):
        # Upstream shipping its own copy of a customer-owned path must not
        # replace the customer's — this is the failure the whole fence exists
        # for, and it is also exactly how a stale ownership ledger would get
        # restored over a live one.
        self.fixture.upstream_change(
            {
                "src/main.rs": "// v2\n",
                "resources/ferrum/proxies/_example.yaml": "kind: Proxy\n",
                ".state/production.json": '{"environment":"upstream","resources":{}}\n',
                ".gitforgeops/config.yaml": "version: 1\nenvironments:\n  upstream: {}\n",
                ".github/CODEOWNERS": "* @upstream-maintainer\n",
            },
            "upstream v2 with customer-shaped paths",
        )
        before = {path: self.fixture.read(path) for path in CUSTOMER_TREE}
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path, contents in before.items():
            self.assertEqual(self.fixture.read(path), contents, path)

    def test_a_local_edit_upstream_did_not_touch_is_preserved_and_reported(self):
        self.fixture.customer_change({"docs/github-launch-controls.md": "# ours\n"})
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "upstream v2")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.fixture.read("docs/github-launch-controls.md"), "# ours\n"
        )
        self.assertIn("Preserved local edits", result.stdout)

    def test_the_customer_fence_is_applied_to_upstreams_own_tree(self):
        for owned in template_update.CUSTOMER_OWNED:
            with self.subTest(path=owned):
                self.assertTrue(template_update.is_customer_owned(owned))
                self.assertTrue(
                    template_update.is_customer_owned(f"{owned}/nested/file.yaml")
                )
        # And the ledger in particular, since restoring an obsolete one is the
        # specific recovery mistake the runbook warns against.
        self.assertTrue(template_update.is_customer_owned(".state/production.json"))
        self.assertFalse(template_update.is_customer_owned("src/main.rs"))

    # -- conflicts are visible, not resolved --------------------------------

    def test_a_file_changed_on_both_sides_is_a_reported_conflict(self):
        self.fixture.customer_change(
            {".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# ours\n"}
        )
        self.fixture.upstream_change(
            {
                ".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# v2\n"
            },
            "upstream v2",
        )
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("CONFLICTS (1)", result.stdout)
        self.assertIn("apply-on-merge.yml", result.stdout)
        # Not overwritten...
        self.assertEqual(
            self.fixture.read(".github/workflows/apply-on-merge.yml"),
            "name: GitForgeOps Apply\n# ours\n",
        )
        # ...and not recorded as adopted.
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["commit"],
            self.fixture.baseline,
        )
        self.assertIn("Baseline NOT advanced", result.stderr)

    def test_clean_files_still_adopt_alongside_a_conflict(self):
        self.fixture.customer_change(
            {".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# ours\n"}
        )
        self.fixture.upstream_change(
            {
                ".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# v2\n",
                "src/apply/api_target.rs": "// v2: the security fix\n",
            },
            "upstream v2",
        )
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 1)
        # The fix lands; the conflict is still the operator's to resolve.
        self.assertEqual(
            self.fixture.read("src/apply/api_target.rs"), "// v2: the security fix\n"
        )

    def test_plan_is_read_only_and_fails_on_a_conflict(self):
        self.fixture.customer_change(
            {".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# ours\n"}
        )
        self.fixture.upstream_change(
            {
                ".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# v2\n",
                "src/main.rs": "// v2\n",
            },
            "upstream v2",
        )
        before = self.fixture.read("src/main.rs")
        result = self.fixture.run("plan")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(self.fixture.read("src/main.rs"), before, "plan wrote a file")

    def test_status_reports_without_failing_on_a_conflict(self):
        self.fixture.customer_change(
            {".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# ours\n"}
        )
        self.fixture.upstream_change(
            {
                ".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# v2\n"
            },
            "upstream v2",
        )
        result = self.fixture.run("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CONFLICTS", result.stdout)

    # -- resolving a conflict by keeping the local file ----------------------

    def _readme_conflict(self) -> None:
        self.fixture.customer_change({"README.md": "# our team's readme\n"})
        self.fixture.upstream_change({"README.md": "# upstream readme v2\n"}, "v2")

    def test_keeping_the_local_file_resolves_the_conflict_and_advances(self):
        # The runbook tells operators to keep their own README. Without an
        # explicit way to say so, that conflict could never clear and the
        # baseline could never advance again.
        self._readme_conflict()
        result = self.fixture.run("apply", "--keep", "README.md")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Kept by decision (1)", result.stdout)
        self.assertEqual(self.fixture.read("README.md"), "# our team's readme\n")
        self.assertNotEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["commit"],
            self.fixture.baseline,
        )

    def test_keep_resolves_only_the_path_it_names(self):
        self._readme_conflict()
        self.fixture.customer_change(
            {".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# ours\n"}
        )
        self.fixture.upstream_change(
            {".github/workflows/apply-on-merge.yml": "name: GitForgeOps Apply\n# v3\n"},
            "v3",
        )
        result = self.fixture.run("apply", "--keep", "README.md")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("CONFLICTS (1)", result.stdout)
        self.assertIn("Baseline NOT advanced", result.stderr)

    def test_keep_refuses_a_path_that_is_not_in_conflict(self):
        # A typo, or a decision left over from an older update, must not read
        # as "resolved".
        self._readme_conflict()
        result = self.fixture.run("apply", "--keep", "README.MD")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not in conflict", result.stderr)
        self.assertEqual(self.fixture.read("README.md"), "# our team's readme\n")

    # -- finding the real baseline of a fresh copy ---------------------------

    def test_detect_baseline_finds_the_commit_a_copy_was_taken_from(self):
        # "Use this template" copies upstream's own baseline.json, which names
        # an older commit than the one actually copied.
        copied = self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        self.fixture.upstream_change({"src/main.rs": "// v3\n"}, "v3")
        self.fixture.customer_change({"src/main.rs": "// v2\n"})

        report = self.fixture.run("detect-baseline")
        self.assertEqual(report.returncode, 0, report.stdout + report.stderr)
        self.assertIn(f"exact match: this tree was copied from {copied}", report.stdout)
        self.assertIn("--write", report.stdout)
        # Reporting does not write.
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["commit"],
            self.fixture.baseline,
        )

        written = self.fixture.run("detect-baseline", "--write")
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["commit"],
            copied,
        )
        # And with the real baseline, v3 adopts cleanly instead of conflicting.
        adopted = self.fixture.run("apply")
        self.assertEqual(adopted.returncode, 0, adopted.stdout + adopted.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), "// v3\n")

    def test_an_inexact_match_is_reported_but_not_recorded_without_a_decision(self):
        self.fixture.customer_change({"src/main.rs": "// our own edit\n"})
        report = self.fixture.run("detect-baseline", "--write")
        self.assertEqual(report.returncode, 1, report.stdout)
        self.assertIn("closest upstream commit", report.stdout)
        accepted = self.fixture.run("detect-baseline", "--write", "--accept-closest")
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["commit"],
            self.fixture.baseline,
        )

    # -- idempotence and identification -------------------------------------

    def test_adopting_twice_is_a_no_op(self):
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "upstream v2")
        self.assertEqual(self.fixture.run("apply").returncode, 0)
        second = self.fixture.run("apply")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("already carries the target", second.stdout)

    def test_identify_answers_which_versions_are_installed(self):
        result = self.fixture.run_identify()
        payload = json.loads(result.stdout)
        self.assertEqual(payload["engine_version"], "0.1.0")
        self.assertEqual(
            payload["template_baseline"]["commit"], self.fixture.baseline
        )
        self.assertEqual(payload["validator_digests"], ["aaa111"])
        self.assertIn("gateway", payload["gateway_version"])

    def test_a_missing_baseline_fails_with_an_actionable_message(self):
        (self.fixture.customer / ".gitforgeops/baseline.json").unlink()
        result = self.fixture.run("status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("docs/template-updates.md", result.stderr)

    def test_an_unresolvable_target_names_the_revision(self):
        result = self.fixture.run("status", "--to", "v99.99.99")
        self.assertEqual(result.returncode, 1)
        self.assertIn("v99.99.99", result.stderr)

    def test_baseline_and_command_line_upstreams_reject_git_options(self):
        marker = self.fixture.customer.parent / "upstream-injection-marker"
        malicious_upstream = f"--upload-pack=touch {marker}"
        payload = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        payload["upstream"] = malicious_upstream
        write(
            self.fixture.customer,
            {".gitforgeops/baseline.json": json.dumps(payload)},
        )

        result = self.fixture.run("status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not a Git option", result.stderr)
        self.assertFalse(marker.exists())

    def test_baseline_commit_must_be_a_full_object_id(self):
        marker = self.fixture.customer.parent / "commit-injection-marker"
        payload = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        payload["commit"] = f"--upload-pack=touch {marker}"
        write(
            self.fixture.customer,
            {".gitforgeops/baseline.json": json.dumps(payload)},
        )

        result = self.fixture.run("status")

        self.assertEqual(result.returncode, 1)
        self.assertIn("full 40- or 64-character", result.stderr)
        self.assertFalse(marker.exists())

    def test_baseline_and_command_line_refs_reject_git_options(self):
        marker = self.fixture.customer.parent / "ref-injection-marker"
        malicious_ref = f"--upload-pack=touch {marker}"
        payload = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        payload["ref"] = malicious_ref
        write(
            self.fixture.customer,
            {".gitforgeops/baseline.json": json.dumps(payload)},
        )

        baseline_result = self.fixture.run("status")
        self.assertEqual(baseline_result.returncode, 1)
        self.assertIn("valid Git ref name", baseline_result.stderr)
        self.assertFalse(marker.exists())

        payload["ref"] = "main"
        write(
            self.fixture.customer,
            {".gitforgeops/baseline.json": json.dumps(payload)},
        )
        command_line_result = self.fixture.run("status", "--to", malicious_ref)
        self.assertEqual(command_line_result.returncode, 1)
        self.assertIn("valid Git ref name", command_line_result.stderr)
        self.assertFalse(marker.exists())

        detect_result = self.fixture.run("detect-baseline", "--to", malicious_ref)
        self.assertEqual(detect_result.returncode, 1)
        self.assertIn("valid Git ref name", detect_result.stderr)
        self.assertFalse(marker.exists())


class UrlUpstreamTests(unittest.TestCase):
    """An upstream named by URL, which is how the shipped default is named.

    `file://` takes the same route through the updater as the HTTPS upstream
    without contacting a server, and fetches into a different ref layout than
    a directory upstream once did (#361).
    """

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self._temporary.name))
        self.url = self.fixture.upstream.as_uri()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_plan_and_status_resolve_the_default_main_ref(self):
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        for command in ("plan", "status"):
            with self.subTest(command=command):
                result = self.fixture.run(command, upstream=self.url)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Adopt (1):", result.stdout)

    def test_apply_adopts_from_the_default_main_ref(self):
        target = self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        result = self.fixture.run("apply", upstream=self.url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), "// v2\n")
        baseline = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        self.assertEqual(
            (baseline["upstream"], baseline["ref"], baseline["commit"]),
            (self.url, "main", target),
        )

    def test_head_target_requires_an_explicit_revision(self):
        for ref in ("HEAD", "head", "FETCH_HEAD", "ORIG_HEAD", "CHERRY_PICK_HEAD", "origin/HEAD"):
            for command in ("plan", "apply", "detect-baseline"):
                with self.subTest(ref=ref, command=command):
                    result = self.fixture.run(command, "--to", ref, upstream=self.url)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f"target ref {ref} is ambiguous", result.stderr)

    def test_a_recorded_head_ref_requires_an_explicit_revision(self):
        payload = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        payload["ref"] = "HEAD"
        write(self.fixture.customer, {".gitforgeops/baseline.json": json.dumps(payload)})
        for command in ("plan", "apply", "detect-baseline"):
            with self.subTest(command=command):
                result = self.fixture.run(command, upstream=self.url)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("target ref HEAD is ambiguous", result.stderr)
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["ref"], "HEAD"
        )

    def test_a_bare_remote_name_requires_an_explicit_revision(self):
        # `origin` resolves through the copy's `refs/remotes/origin/HEAD`,
        # which is upstream's default branch rather than a named revision.
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        for ref in ("origin", "ORIGIN", "Origin"):
            for command in ("plan", "apply", "detect-baseline"):
                with self.subTest(ref=ref, command=command):
                    result = self.fixture.run(command, "--to", ref, upstream=self.url)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(f"target ref {ref} is ambiguous", result.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), UPSTREAM_TREE["src/main.rs"])

        payload = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        payload["ref"] = "origin"
        write(self.fixture.customer, {".gitforgeops/baseline.json": json.dumps(payload)})
        for command in ("plan", "apply", "detect-baseline"):
            with self.subTest(recorded="origin", command=command):
                result = self.fixture.run(command, upstream=self.url)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("target ref origin is ambiguous", result.stderr)
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["ref"], "origin"
        )

    def test_a_branch_really_named_origin_resolves_by_its_full_name(self):
        named = self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        git(self.fixture.upstream, "branch", "origin")
        self.fixture.upstream_change({"src/main.rs": "// v3\n"}, "v3")
        result = self.fixture.run("status", "--to", "refs/heads/origin", upstream=self.url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"target:   {named}", result.stdout)
        for ref in ("origin/main", "origins", "release/origin"):
            with self.subTest(ref=ref):
                self.assertEqual(template_update.validate_target_ref(ref, "target ref"), ref)

    def test_branch_names_that_merely_end_in_head_are_accepted(self):
        for ref in ("ahead", "release/overhead", "HEADS", "v1-HEAD"):
            with self.subTest(ref=ref):
                self.assertEqual(template_update.validate_target_ref(ref, "target ref"), ref)

    def test_detect_baseline_searches_the_default_main_ref(self):
        copied = self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        self.fixture.upstream_change({"src/main.rs": "// v3\n"}, "v3")
        self.fixture.customer_change({"src/main.rs": "// v2\n"})
        result = self.fixture.run("detect-baseline", upstream=self.url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"exact match: this tree was copied from {copied}", result.stdout)

    def test_tags_commit_ids_and_remote_tracking_names_still_resolve(self):
        tagged = self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")
        git(self.fixture.upstream, "tag", "v0.2.0")
        head = self.fixture.upstream_change({"src/main.rs": "// v3\n"}, "v3")
        for ref, expected in (
            ("v0.2.0", tagged),
            (tagged, tagged),
            ("main", head),
            ("origin/main", head),
        ):
            with self.subTest(ref=ref):
                result = self.fixture.run("status", "--to", ref, upstream=self.url)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"target:   {expected}", result.stdout)

    def test_the_upstream_copy_never_starts_background_maintenance(self):
        # A detached `git maintenance` or `gc --auto` started by the fetch can
        # still be writing objects/ when the temporary copy is removed.
        with tempfile.TemporaryDirectory() as workdir:
            mirror = template_update.prepare_mirror(self.url, ("main",), Path(workdir))
            for key, value in (
                ("gc.auto", "0"),
                ("maintenance.auto", "false"),
                ("core.fsmonitor", "false"),
                ("fetch.fsckObjects", "true"),
            ):
                with self.subTest(key=key):
                    self.assertEqual(git(mirror, "config", "--get", key).strip(), value)


class IgnoredRuntimeFileTests(unittest.TestCase):
    """Files Git ignores are not local edits to an upstream-managed path (#362)."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self._temporary.name))
        exclude = self.fixture.customer / ".git/info/exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text("__pycache__/\n*.py[cod]\n", encoding="utf-8")
        write(self.fixture.customer, {".gitignore": ".DS_Store\n"})

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _leave_runtime_files(self) -> None:
        customer = self.fixture.customer
        for relative, contents in (
            (".github/scripts/__pycache__/helper.cpython-314.pyc", b"synthetic cache"),
            (".github/scripts/stale.pyc", b"synthetic cache"),
            ("src/.DS_Store", b"\0\0\0\1Bud1"),
            ("docs/.DS_Store", b"\0\0\0\1Bud1"),
        ):
            path = customer / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            self.assertTrue(git(customer, "check-ignore", relative).strip(), relative)

    def test_ignored_caches_and_finder_files_keep_an_exact_match(self):
        self._leave_runtime_files()
        result = self.fixture.run("detect-baseline")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"exact match: this tree was copied from {self.fixture.baseline}",
            result.stdout,
        )

    def test_an_untracked_source_file_still_differs(self):
        self._leave_runtime_files()
        write(self.fixture.customer, {".github/scripts/local_helper.py": "print(1)\n"})
        result = self.fixture.run("detect-baseline")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 upstream-managed path(s) differ", result.stdout)

    def test_an_uncommitted_edit_to_a_tracked_file_still_differs(self):
        self._leave_runtime_files()
        write(self.fixture.customer, {".github/scripts/credential_bundles.py": "# ours\n"})
        result = self.fixture.run("detect-baseline")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 upstream-managed path(s) differ", result.stdout)

    def test_a_deleted_tracked_file_still_differs(self):
        self._leave_runtime_files()
        (self.fixture.customer / "src/apply/api_target.rs").unlink()
        result = self.fixture.run("detect-baseline")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 upstream-managed path(s) differ", result.stdout)

    def _outside_git(self):
        # Git stops looking for a repository at the fixture's own directory,
        # whatever happens to enclose the temporary directory.
        shutil.rmtree(self.fixture.customer / ".git")
        return mock.patch.dict(
            os.environ, {"GIT_CEILING_DIRECTORIES": str(self.fixture.customer.parent)}
        )

    def test_a_tree_outside_git_has_no_ignore_rules_to_apply(self):
        with self._outside_git():
            exact = self.fixture.run("detect-baseline")
            self.assertEqual(exact.returncode, 0, exact.stdout + exact.stderr)
            write(self.fixture.customer, {"src/.DS_Store": "finder\n"})
            extra = self.fixture.run("detect-baseline")
        self.assertEqual(extra.returncode, 1, extra.stdout + extra.stderr)
        self.assertIn("1 upstream-managed path(s) differ", extra.stdout)

    def test_the_git_probe_falls_back_to_a_walk_outside_a_repository(self):
        self._leave_runtime_files()
        with self._outside_git():
            paths = template_update._local_paths(self.fixture.customer)
        self.assertIn("src/main.rs", paths)
        self.assertIn("src/.DS_Store", paths)

    def test_detect_baseline_counts_a_local_link_without_following_it(self):
        path = self.fixture.customer / "src/main.rs"
        path.unlink()
        path.symlink_to("local-target.rs")
        result = self.fixture.run("detect-baseline")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 upstream-managed path(s) differ", result.stdout)

    def test_git_probe_errors_other_than_non_repository_fail_closed(self):
        # A repository Git refuses to open is not a tree outside Git: walking
        # it instead would count every ignored cache as a local edit.
        with mock.patch.dict(
            os.environ,
            {
                "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "LC_ALL": "C",
            },
        ):
            # Git older than the ownership check ignores the variable and
            # opens the repository, which leaves nothing here to test.
            probe = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(self.fixture.customer),
                check=False,
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                self.skipTest(
                    "this Git does not honour GIT_TEST_ASSUME_DIFFERENT_OWNER"
                )
            with self.assertRaisesRegex(
                template_update.UpdateError,
                "git rev-parse failed.*(?:dubious ownership|unsafe repository)",
            ):
                template_update._local_paths(self.fixture.customer)


class AbandonedTemporaryTests(unittest.TestCase):
    """What an interrupted atomic write leaves behind, and who may remove it."""

    NAME = ".helper.py.template-update-0123456789abcdef"

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self._temporary.name))
        self.scripts = self.fixture.customer / ".github/scripts"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _leave(self, relative: str, *, age: int = 3600) -> Path:
        path = self.fixture.customer / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("incomplete\n", encoding="utf-8")
        then = path.stat().st_mtime - age
        os.utime(path, (then, then))
        return path

    def test_read_only_commands_report_but_keep_it(self):
        temporary = self._leave(f".github/scripts/{self.NAME}")
        for command in ("plan", "status", "detect-baseline"):
            with self.subTest(command=command):
                result = self.fixture.run(command)
                self.assertIn(f"found .github/scripts/{self.NAME}", result.stderr)
                self.assertTrue(temporary.exists())

    def test_apply_removes_an_old_one(self):
        temporary = self._leave(f".github/scripts/{self.NAME}")
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"removed .github/scripts/{self.NAME}", result.stderr)
        self.assertFalse(os.path.lexists(temporary))

    def test_detect_baseline_write_removes_an_old_one(self):
        # Left in place it is an untracked file, so it spoils the exact match.
        temporary = self._leave(f"src/{self.NAME}")
        report = self.fixture.run("detect-baseline")
        self.assertEqual(report.returncode, 1, report.stdout + report.stderr)
        written = self.fixture.run("detect-baseline", "--write")
        self.assertEqual(written.returncode, 0, written.stdout + written.stderr)
        self.assertIn("exact match", written.stdout)
        self.assertFalse(os.path.lexists(temporary))

    def test_a_recent_one_may_belong_to_a_running_update_and_is_kept(self):
        temporary = self._leave(f".github/scripts/{self.NAME}", age=0)
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"left .github/scripts/{self.NAME} in place", result.stderr)
        self.assertTrue(temporary.exists())

    def test_only_a_regular_file_with_exactly_that_name_is_removed(self):
        outside = Path(self._temporary.name) / "outside.txt"
        outside.write_text("not ours\n", encoding="utf-8")
        then = outside.stat().st_mtime - 3600
        survivors = [
            self._leave(f".github/scripts/{name}")
            for name in (
                "helper.py.template-update-0123456789abcdef",
                ".helper.py.template-update-0123456789ABCDEF",
                ".helper.py.template-update-0123456789abcde",
                ".helper.py.template-update-0123456789abcdef0",
                ".helper.py.template-update-0123456789abcdef.bak",
                ".template-update-0123456789abcdef",
            )
        ]
        directory = self.scripts / ".dir.template-update-0123456789abcdef"
        directory.mkdir()
        os.utime(directory, (then, then))
        link = self.scripts / ".link.template-update-0123456789abcdef"
        link.symlink_to(outside)
        os.utime(link, (then, then), follow_symlinks=False)
        removed = self._leave(f".github/scripts/{self.NAME}")

        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(os.path.lexists(removed))
        for path in survivors:
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())
        self.assertTrue(directory.is_dir())
        self.assertTrue(link.is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), "not ours\n")

    # Managed files that sit directly in a directory the recursive walk never
    # enters: the repository root, `.github/` and `.gitforgeops/`.
    BESIDE_FILES = (
        ".Cargo.toml.template-update-0123456789abcdef",
        ".README.md.template-update-0123456789abcdef",
        ".github/.ferrum-edge-checksums.txt.template-update-0123456789abcdef",
        ".github/.dependabot.yml.template-update-0123456789abcdef",
        ".gitforgeops/.smoke.example.yaml.template-update-0123456789abcdef",
        ".gitforgeops/.baseline.json.template-update-0123456789abcdef",
    )

    def test_read_only_commands_report_one_beside_a_top_level_file(self):
        left = [self._leave(relative) for relative in self.BESIDE_FILES]
        for command in ("plan", "status", "detect-baseline"):
            with self.subTest(command=command):
                result = self.fixture.run(command)
                for relative in self.BESIDE_FILES:
                    self.assertIn(f"found {relative}", result.stderr)
        for path in left:
            self.assertTrue(path.is_file(), path)

    def test_apply_removes_an_old_one_beside_a_top_level_file(self):
        left = [self._leave(relative) for relative in self.BESIDE_FILES]
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for relative, path in zip(self.BESIDE_FILES, left):
            with self.subTest(path=relative):
                self.assertIn(f"removed {relative}", result.stderr)
                self.assertFalse(os.path.lexists(path))

    def test_detect_baseline_write_removes_an_old_one_beside_the_baseline(self):
        temporary = self._leave(".gitforgeops/.baseline.json.template-update-0123456789abcdef")
        written = self.fixture.run("detect-baseline", "--write")
        self.assertEqual(written.returncode, 0, written.stdout + written.stderr)
        self.assertFalse(os.path.lexists(temporary))

    def test_a_recent_one_beside_a_top_level_file_is_kept(self):
        temporary = self._leave(".Cargo.toml.template-update-0123456789abcdef", age=0)
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "left .Cargo.toml.template-update-0123456789abcdef in place", result.stderr
        )
        self.assertTrue(temporary.is_file())

    def test_beside_a_top_level_file_only_that_files_own_temporary_is_removed(self):
        # The directories holding top-level managed files also hold the
        # customer's own files, so only the name `write_local` gives one of
        # those managed files is touched, and nothing below them is walked.
        outside = Path(self._temporary.name) / "outside.txt"
        outside.write_text("not ours\n", encoding="utf-8")
        then = outside.stat().st_mtime - 3600
        survivors = [
            self._leave(relative)
            for relative in (
                ".notes.md.template-update-0123456789abcdef",
                ".gitforgeops/.config.yaml.template-update-0123456789abcdef",
                ".github/.CODEOWNERS.template-update-0123456789abcdef",
                "resources/.orders.yaml.template-update-0123456789abcdef",
                ".Cargo.toml.template-update-0123456789ABCDEF",
                "Cargo.toml.template-update-0123456789abcdef",
            )
        ]
        link = self.fixture.customer / ".README.md.template-update-fedcba9876543210"
        link.symlink_to(outside)
        os.utime(link, (then, then), follow_symlinks=False)
        directory = self.fixture.customer / ".Cargo.toml.template-update-fedcba9876543210"
        directory.mkdir()
        os.utime(directory, (then, then))

        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in survivors:
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())
                self.assertNotIn(path.name, result.stderr)
        self.assertTrue(link.is_symlink())
        self.assertTrue(directory.is_dir())
        self.assertEqual(outside.read_text(encoding="utf-8"), "not ours\n")

    def test_a_nested_clone_does_not_stop_plan_or_apply(self):
        nested = self.fixture.customer / "src/vendor/lib"
        nested.mkdir(parents=True)
        init(nested)
        write(nested, {"lib.rs": "// vendored\n"})
        commit(nested, "vendored")
        inside = self._leave(f"src/vendor/lib/.git/{self.NAME}")
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")

        for command in ("plan", "apply"):
            with self.subTest(command=command):
                result = self.fixture.run(command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), "// v2\n")
        self.assertTrue(inside.exists())

    def test_a_nested_clone_is_one_local_difference_to_detect_baseline(self):
        nested = self.fixture.customer / "src/vendor/lib"
        nested.mkdir(parents=True)
        init(nested)
        write(nested, {"lib.rs": "// vendored\n"})
        commit(nested, "vendored")
        result = self.fixture.run("detect-baseline")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 upstream-managed path(s) differ", result.stdout)


class ConfinementTests(unittest.TestCase):
    """Reads and writes stay on real files under the managed paths.

    Every refusal must leave the file outside untouched and the baseline where
    it was, so a refused update is never recorded as an adopted one.
    """

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self._temporary.name))
        self.outside = Path(self._temporary.name) / "outside"
        self.outside.mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_upstream_file_to_directory_transition_is_planned_and_applied(self):
        upstream_file = self.fixture.upstream / "docs/x"
        customer_file = self.fixture.customer / "docs/x"
        upstream_file.write_text("old\n", encoding="utf-8")
        customer_file.write_text("old\n", encoding="utf-8")
        baseline = commit(self.fixture.upstream, "add docs/x")
        template_update.Baseline(
            str(self.fixture.upstream), "main", baseline
        ).write(self.fixture.customer)
        upstream_file.unlink()
        (self.fixture.upstream / "docs/x").mkdir()
        (self.fixture.upstream / "docs/x/y").write_text("new\n", encoding="utf-8")
        target = commit(self.fixture.upstream, "turn docs/x into directory")

        plan = self.fixture.run("plan")
        self.assertEqual(plan.returncode, 0, plan.stdout + plan.stderr)
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The file is gone: its path is now the real directory upstream made it.
        self.assertFalse(customer_file.is_symlink())
        self.assertTrue(customer_file.is_dir())
        self.assertEqual(sorted(path.name for path in customer_file.iterdir()), ["y"])
        self.assertEqual((self.fixture.customer / "docs/x/y").read_text(), "new\n")
        recorded = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        self.assertEqual(recorded["commit"], target)

    def test_a_directory_waits_while_the_file_it_replaces_is_in_conflict(self):
        (self.fixture.upstream / "docs/x").write_text("old\n", encoding="utf-8")
        (self.fixture.customer / "docs/x").write_text("ours\n", encoding="utf-8")
        baseline = commit(self.fixture.upstream, "add docs/x")
        template_update.Baseline(
            str(self.fixture.upstream), "main", baseline
        ).write(self.fixture.customer)
        (self.fixture.upstream / "docs/x").unlink()
        target = self.fixture.upstream_change(
            {"docs/x/y": "new\n", "src/main.rs": "// v2\n"}, "docs/x becomes a directory"
        )

        plan = self.fixture.run("plan")
        self.assertEqual(plan.returncode, 1, plan.stdout + plan.stderr)
        self.assertIn("CONFLICTS (2)", plan.stdout)
        self.assertIn("docs/x/y — upstream adds it under docs/x", plan.stdout)
        self.assertIn("resolve docs/x first", plan.stdout)

        # Reported as a conflict, not a refusal half-way through the writes.
        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("refusing", result.stderr)
        self.assertIn("Baseline NOT advanced", result.stderr)
        self.assertEqual(self.fixture.read("docs/x"), "ours\n")
        self.assertEqual(self.fixture.read("src/main.rs"), "// v2\n")
        recorded = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        self.assertEqual(recorded["commit"], baseline)

        kept = self.fixture.run("apply", "--keep", "docs/x")
        self.assertEqual(kept.returncode, 1, kept.stdout + kept.stderr)
        self.assertIn("name this path with --keep as well", kept.stdout)

        # Keeping only the new file says why it waits: its parent is still
        # undecided, not a file anybody chose to keep.
        child = self.fixture.run("plan", "--keep", "docs/x/y")
        self.assertEqual(child.returncode, 1, child.stdout + child.stderr)
        self.assertIn("CONFLICTS (1)", child.stdout)
        self.assertIn(
            "docs/x/y — upstream adds it under docs/x, which upstream made a "
            "directory but which is in conflict here; not adopted, kept by --keep",
            child.stdout,
        )
        self.assertNotIn("stays a file", child.stdout)

        both = self.fixture.run("apply", "--keep", "docs/x", "--keep", "docs/x/y")
        self.assertEqual(both.returncode, 0, both.stdout + both.stderr)
        self.assertIn(
            "docs/x/y — upstream adds it under docs/x, which upstream made a "
            "directory but --keep keeps as a file here; not adopted, kept by --keep",
            both.stdout,
        )
        self.assertEqual(self.fixture.read("docs/x"), "ours\n")
        recorded = json.loads(self.fixture.read(".gitforgeops/baseline.json"))
        self.assertEqual(recorded["commit"], target)

    def assert_refused(self, result: subprocess.CompletedProcess, message: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("refusing", result.stderr)
        self.assertIn(message, result.stderr)
        self.assertEqual(
            json.loads(self.fixture.read(".gitforgeops/baseline.json"))["commit"],
            self.fixture.baseline,
        )

    def test_a_linked_file_is_refused_rather_than_written_through(self):
        outside = self.outside / "customer-owned.txt"
        original = self.fixture.read("src/main.rs")
        outside.write_text(original, encoding="utf-8")
        destination = self.fixture.customer / "src/main.rs"
        destination.unlink()
        destination.symlink_to(outside)
        self.fixture.upstream_change({"src/main.rs": "// upstream v2\n"}, "v2")

        for command in ("plan", "status", "apply"):
            with self.subTest(command=command):
                self.assert_refused(
                    self.fixture.run(command), "src/main.rs is a symbolic link"
                )
        self.assertEqual(outside.read_text(encoding="utf-8"), original)
        self.assertTrue(destination.is_symlink())

    def test_a_link_into_customer_owned_data_is_refused(self):
        # The same bytes as upstream's baseline copy, so a comparison made
        # through the link would read it as an untouched file to update.
        ledger = self.fixture.customer / ".state/production.json"
        docs = "docs/github-launch-controls.md"
        ledger.write_text(self.fixture.read(docs), encoding="utf-8")
        (self.fixture.customer / docs).unlink()
        (self.fixture.customer / docs).symlink_to("../.state/production.json")
        self.fixture.upstream_change({docs: "# controls v2\n"}, "v2")

        self.assert_refused(self.fixture.run("apply"), f"{docs} is a symbolic link")
        self.assertEqual(ledger.read_text(encoding="utf-8"), "# controls v1\n")

    def test_a_linked_parent_directory_is_refused(self):
        real = self.outside / "apply"
        real.mkdir()
        original = self.fixture.read("src/apply/api_target.rs")
        (real / "api_target.rs").write_text(original, encoding="utf-8")
        shutil.rmtree(self.fixture.customer / "src/apply")
        (self.fixture.customer / "src/apply").symlink_to(real, target_is_directory=True)
        self.fixture.upstream_change({"src/apply/api_target.rs": "// v2\n"}, "v2")

        self.assert_refused(self.fixture.run("apply"), "src/apply is a symbolic link")
        self.assertEqual((real / "api_target.rs").read_text(encoding="utf-8"), original)
        self.assertEqual(sorted(path.name for path in real.iterdir()), ["api_target.rs"])

    def test_a_dangling_link_at_an_added_path_is_refused(self):
        created = self.outside / "created-by-update.rs"
        (self.fixture.customer / "src/new.rs").symlink_to(created)
        self.fixture.upstream_change({"src/new.rs": "// new upstream file\n"}, "v2")

        self.assert_refused(self.fixture.run("apply"), "src/new.rs is a symbolic link")
        self.assertFalse(created.exists())

    def test_a_linked_file_upstream_deletes_is_refused(self):
        outside = self.outside / "kept.rs"
        outside.write_text(self.fixture.read("src/apply/api_target.rs"), encoding="utf-8")
        destination = self.fixture.customer / "src/apply/api_target.rs"
        destination.unlink()
        destination.symlink_to(outside)
        (self.fixture.upstream / "src/apply/api_target.rs").unlink()
        self.fixture.upstream_change({}, "upstream removed a file")

        self.assert_refused(
            self.fixture.run("apply"), "src/apply/api_target.rs is a symbolic link"
        )
        self.assertTrue(outside.exists())
        self.assertTrue(destination.is_symlink())

    def test_a_linked_baseline_record_is_refused(self):
        outside = self.outside / "baseline.json"
        recorded = self.fixture.customer / ".gitforgeops/baseline.json"
        original = recorded.read_text(encoding="utf-8")
        outside.write_text(original, encoding="utf-8")
        recorded.unlink()
        recorded.symlink_to(outside)
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")

        for command in ("identify", "apply"):
            with self.subTest(command=command):
                result = (
                    self.fixture.run_identify()
                    if command == "identify"
                    else self.fixture.run(command)
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(
                    ".gitforgeops/baseline.json is a symbolic link", result.stderr
                )
        self.assertEqual(outside.read_text(encoding="utf-8"), original)
        self.assertNotEqual(self.fixture.read("src/main.rs"), "// v2\n")

    def test_detect_baseline_counts_a_link_instead_of_reading_through_it(self):
        # The target holds upstream's exact bytes, so a comparison made through
        # the link would report an exact match and record the baseline.
        outside = self.outside / "main.rs"
        original = self.fixture.read("src/main.rs")
        outside.write_text(original, encoding="utf-8")
        destination = self.fixture.customer / "src/main.rs"
        destination.unlink()
        destination.symlink_to(outside)
        recorded = self.fixture.customer / ".gitforgeops/baseline.json"
        before = recorded.read_bytes()

        result = self.fixture.run("detect-baseline", "--write")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("1 upstream-managed path(s) differ", result.stdout)
        self.assertNotIn("exact match", result.stdout)
        self.assertEqual(recorded.read_bytes(), before)
        self.assertEqual(outside.read_text(encoding="utf-8"), original)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(os.readlink(destination), str(outside))

    def test_an_upstream_link_is_not_adopted_as_a_file(self):
        (self.fixture.upstream / "docs/link.md").symlink_to("github-launch-controls.md")
        self.fixture.upstream_change({}, "upstream ships a link")

        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("docs/link.md as a symbolic link", result.stderr)
        self.assertFalse(os.path.lexists(self.fixture.customer / "docs/link.md"))

    def test_a_hard_link_is_replaced_rather_than_written_through(self):
        outside = self.outside / "shared.rs"
        original = self.fixture.read("src/main.rs")
        outside.write_text(original, encoding="utf-8")
        destination = self.fixture.customer / "src/main.rs"
        destination.unlink()
        os.link(outside, destination)
        self.fixture.upstream_change({"src/main.rs": "// v2\n"}, "v2")

        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.fixture.read("src/main.rs"), "// v2\n")
        self.assertEqual(outside.read_text(encoding="utf-8"), original)
        self.assertNotEqual(destination.stat().st_ino, outside.stat().st_ino)

    def test_an_executable_upstream_file_arrives_executable(self):
        script = self.fixture.upstream / ".github/scripts/new_helper.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        script.chmod(0o755)
        self.fixture.upstream_change({}, "upstream adds a helper")

        result = self.fixture.run("apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        adopted = self.fixture.customer / ".github/scripts/new_helper.sh"
        self.assertEqual(adopted.read_text(encoding="utf-8"), "#!/bin/sh\n")
        self.assertTrue(adopted.stat().st_mode & 0o100)
        leftovers = [
            path.name
            for path in adopted.parent.iterdir()
            if "template-update" in path.name
        ]
        self.assertEqual(leftovers, [])

    def test_paths_that_do_not_normalize_inside_the_root_are_refused(self):
        root = self.fixture.customer
        for path in (
            "../outside/escaped.txt",
            "src/../../outside/escaped.txt",
            "/tmp/escaped.txt",
            "src//main.rs",
            "src/./main.rs",
            "",
        ):
            with self.subTest(path=path):
                with self.assertRaises(template_update.UpdateError):
                    template_update.write_local(root, path, b"escaped\n")
                with self.assertRaises(template_update.UpdateError):
                    template_update.read_local(root, path)
        self.assertEqual(list(self.outside.iterdir()), [])


class RepositoryContractTests(unittest.TestCase):
    """This repository is the upstream, so its own tree must match the lists."""

    def test_every_upstream_managed_path_exists_upstream(self):
        for path in template_update.UPSTREAM_MANAGED:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists(), path)

    def test_every_shipped_example_is_upstream_managed(self):
        # The examples are upstream's documentation of its own contract, and
        # each one is named individually rather than by directory because
        # `.gitforgeops/` also holds the customer's real config. A new example
        # that nobody adds here is one no customer ever receives.
        for example in sorted((ROOT / ".gitforgeops").glob("*.example.yaml")):
            relative = f".gitforgeops/{example.name}"
            with self.subTest(example=relative):
                self.assertIn(relative, template_update.UPSTREAM_MANAGED)

    def test_no_path_is_both_upstream_managed_and_customer_owned(self):
        for owned in template_update.CUSTOMER_OWNED:
            self.assertNotIn(owned, template_update.UPSTREAM_MANAGED)

    def test_the_ledger_and_generated_output_are_customer_owned(self):
        # An update that restored a `.state/` snapshot would hand a repository
        # an ownership ledger describing a gateway it no longer has.
        for path in (".state", "assembled"):
            self.assertIn(path, template_update.CUSTOMER_OWNED)

    def test_this_repository_records_its_own_baseline_shape(self):
        # Upstream's own copy is the template customers clone, so the file has
        # to be there for them to inherit.
        path = ROOT / template_update.BASELINE_PATH
        self.assertTrue(path.is_file(), f"{path} must ship with the template")
        payload = json.loads(path.read_text(encoding="utf-8"))
        for key in ("upstream", "ref", "commit"):
            self.assertIn(key, payload)

    def test_no_upstream_managed_path_is_a_link(self):
        # The updater refuses to adopt a link, so shipping one under a managed
        # path would stop every downstream update at that path.
        for prefix in template_update.UPSTREAM_MANAGED:
            base = ROOT / prefix
            found = [base] if base.is_symlink() else []
            if base.is_dir() and not base.is_symlink():
                for directory, names, files in os.walk(base):
                    found += [
                        Path(directory) / name
                        for name in names + files
                        if (Path(directory) / name).is_symlink()
                    ]
            with self.subTest(path=prefix):
                self.assertEqual(found, [])

    def test_the_runbook_documents_every_post_adoption_check(self):
        runbook = (ROOT / "docs/template-updates.md").read_text(encoding="utf-8")
        for command, _ in template_update.POST_ADOPTION_CHECKS:
            self.assertIn(command, runbook, command)


def _run_identify(self) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(self.customer), "identify"],
        check=False,
        text=True,
        capture_output=True,
    )


Fixture.run_identify = _run_identify


if __name__ == "__main__":
    unittest.main()
