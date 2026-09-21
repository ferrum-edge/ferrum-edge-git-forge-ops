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
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
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

    def run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo-root",
                str(self.customer),
                *args,
                "--upstream",
                str(self.upstream),
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


class RepositoryContractTests(unittest.TestCase):
    """This repository is the upstream, so its own tree must match the lists."""

    def test_every_upstream_managed_path_exists_upstream(self):
        for path in template_update.UPSTREAM_MANAGED:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists(), path)

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
