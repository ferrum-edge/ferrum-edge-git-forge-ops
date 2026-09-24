import importlib.util
import re
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "changed_files.py"
SPEC = importlib.util.spec_from_file_location("changed_files", SCRIPT)
assert SPEC and SPEC.loader
changed_files = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = changed_files
SPEC.loader.exec_module(changed_files)


class ChangedFilesTests(unittest.TestCase):
    def test_pr_workflows_use_head_stable_api_snapshots(self):
        workflows = {
            "state-guard.yml": (1, 2),
            "rust-ci.yml": (2, 2),
            "validate-pr.yml": (1, 1),
        }
        workflow_root = SCRIPT.parents[1] / "workflows"
        for name, (snapshot_count, head_binding_count) in workflows.items():
            with self.subTest(workflow=name):
                text = (workflow_root / name).read_text(encoding="utf-8")
                self.assertNotIn("github.event.pull_request.changed_files", text)
                self.assertEqual(
                    text.count('before=$(gh api "repos/${REPO}/pulls/${PR_NUMBER}")'),
                    snapshot_count,
                )
                self.assertEqual(
                    text.count('after=$(gh api "repos/${REPO}/pulls/${PR_NUMBER}")'),
                    snapshot_count,
                )
                self.assertEqual(
                    text.count(
                        "EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha }}"
                    ),
                    head_binding_count,
                )
                self.assertIn("ref: ${{ github.event.repository.default_branch }}", text)

    def test_current_and_previous_rename_paths_are_both_classified(self):
        pages = [
            [
                {
                    "filename": "docs/old-state.md",
                    "previous_filename": ".state/production.json",
                },
                {
                    "filename": "docs/old-source.md",
                    "previous_filename": "src/main.rs",
                },
            ],
            [{"filename": "resources/team/proxies/api.yaml"}],
        ]

        state = changed_files.analyze(pages, 3, "state")
        rust = changed_files.analyze(pages, 3, "rust")
        declarative = changed_files.analyze(pages, 3, "declarative")

        self.assertEqual(state["matched_paths"], [".state/production.json"])
        self.assertEqual(rust["matched_paths"], ["src/main.rs"])
        self.assertEqual(
            declarative["matched_paths"],
            [".state/production.json", "resources/team/proxies/api.yaml"],
        )
        self.assertTrue(state["complete"])

    def test_exact_state_path_is_protected_for_all_change_types(self):
        records = [
            {"filename": ".state", "status": "added"},
            {"filename": ".state", "status": "modified"},
            {"filename": ".state", "status": "removed"},
            {
                "filename": "old-state",
                "previous_filename": ".state",
                "status": "renamed",
            },
            {
                "filename": ".state",
                "previous_filename": "old-state",
                "status": "renamed",
            },
        ]
        # GitHub's file list does not expose the Git mode. Protect this name
        # regardless of whether the tree entry is a file or a symlink.
        for record in records:
            for area in ("state", "declarative"):
                with self.subTest(record=record, area=area):
                    result = changed_files.analyze([[record]], 1, area)
                    self.assertTrue(result["complete"])
                    self.assertTrue(result["matches"])
                    self.assertEqual(result["matched_paths"], [".state"])

    def test_state_scope_does_not_include_similarly_named_paths(self):
        for path in (".state-backup", ".state.json", "docs/.state"):
            for area in ("state", "declarative"):
                with self.subTest(path=path, area=area):
                    result = changed_files.analyze([[{"filename": path}]], 1, area)
                    self.assertFalse(result["matches"])

    def test_incomplete_state_and_validation_scope_fail_closed(self):
        for area in ("state", "declarative"):
            for path in (".state", "README.md"):
                with self.subTest(area=area, path=path):
                    result = changed_files.analyze([[{"filename": path}]], 2, area)
                    self.assertFalse(result["complete"])

    def test_incomplete_pagination_is_explicit(self):
        result = changed_files.analyze([[{"filename": "README.md"}]], 2, "rust")
        self.assertFalse(result["complete"])
        self.assertFalse(result["matches"])

    def test_exact_github_file_cap_is_always_treated_as_ambiguous(self):
        records = [
            {"filename": f"docs/file-{index}.md"}
            for index in range(changed_files.GITHUB_PULL_FILES_LIMIT)
        ]
        result = changed_files.analyze(
            [records], changed_files.GITHUB_PULL_FILES_LIMIT, "state"
        )
        self.assertEqual(result["observed_count"], 3_000)
        self.assertFalse(result["complete"])

    def test_rust_scope_includes_build_and_workspace_inputs(self):
        for path in (
            "build.rs",
            ".cargo/config.toml",
            "crates/helper/Cargo.toml",
            "benches/load.rs",
            "examples/demo.rs",
            "rust-toolchain",
            ".clippy.toml",
        ):
            with self.subTest(path=path):
                result = changed_files.analyze([[{"filename": path}]], 1, "rust")
                self.assertTrue(result["matches"])

    def test_rust_scope_includes_non_rust_files_the_unit_suite_reads(self):
        # `tests/unit` reads the quickstart guide and the example repository
        # configuration, and `src/doctor/github.rs` embeds the settings
        # auditor with `include_str!`. A PR that changes only one of them can
        # still break `cargo test`.
        for path in (
            "docs/quickstart.md",
            ".gitforgeops/config.example.yaml",
            ".gitforgeops/policies.example.yaml",
            ".gitforgeops/smoke.example.yaml",
            ".github/scripts/audit_settings.py",
        ):
            with self.subTest(path=path):
                result = changed_files.analyze([[{"filename": path}]], 1, "rust")
                self.assertTrue(result["matches"])
        for path in (
            "docs/other.md",
            ".gitforgeops/config.yaml",
            ".gitforgeops/policies.yaml",
            ".gitforgeops/nested/config.example.yaml",
            ".github/scripts/bootstrap_repo_settings.py",
            "resources/ferrum/proxies/_example.yaml",
        ):
            with self.subTest(path=path):
                result = changed_files.analyze([[{"filename": path}]], 1, "rust")
                self.assertFalse(result["matches"])

    def test_rust_ci_push_paths_stay_within_the_pr_rust_scope(self):
        text = (SCRIPT.parents[1] / "workflows" / "rust-ci.yml").read_text(
            encoding="utf-8"
        )
        block = re.search(
            r"^  push:\n(?:^    .*\n)*?^    paths:\n((?:^      .*\n)*)",
            text,
            re.MULTILINE,
        )
        self.assertIsNotNone(block)
        entries = re.findall(r"^      - '([^']+)'$", block.group(1), re.MULTILINE)
        self.assertIn("docs/quickstart.md", entries)
        self.assertIn(".gitforgeops/*.example.yaml", entries)
        self.assertIn(".github/scripts/audit_settings.py", entries)
        for entry in entries:
            # Instantiate the glob with a representative concrete path.
            sample = (
                entry.replace("**/", "nested/")
                .replace("**", "file.rs")
                .replace("*", "sample")
            )
            with self.subTest(entry=entry, sample=sample):
                result = changed_files.analyze([[{"filename": sample}]], 1, "rust")
                self.assertTrue(result["matches"])

    def test_malformed_page_and_previous_filename_fail_closed(self):
        cases = [
            {"files": []},
            [[{"filename": "new", "previous_filename": 7}]],
            [[{"status": "modified"}]],
        ]
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaises(
                changed_files.ChangedFilesError
            ):
                changed_files.analyze(pages, 1, "state")


if __name__ == "__main__":
    unittest.main()
