import importlib.util
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
            declarative["matched_paths"], ["resources/team/proxies/api.yaml"]
        )
        self.assertTrue(state["complete"])

    def test_incomplete_pagination_is_explicit(self):
        result = changed_files.analyze([[{"filename": "README.md"}]], 2, "rust")
        self.assertFalse(result["complete"])
        self.assertFalse(result["matches"])

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
