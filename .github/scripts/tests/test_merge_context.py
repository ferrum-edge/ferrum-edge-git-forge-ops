import importlib.util
import json
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "merge_context.py"
SPEC = importlib.util.spec_from_file_location("merge_context", SCRIPT)
assert SPEC and SPEC.loader
merge_context = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = merge_context
SPEC.loader.exec_module(merge_context)
SHA = "a" * 40
# Shared with `tests/unit/github_api_tests.rs`, which runs the same cases
# through the Rust copy of this rule (`github_override::select_merged_pr`).
SHARED_CASES = Path(__file__).resolve().parents[3] / "tests/fixtures/merge-context-cases.json"


def pull(number, author, *, merge_sha=SHA, base="main", state="closed", merged=True):
    return {
        "number": number,
        "state": state,
        "merged_at": "2026-08-30T00:00:00Z" if merged else None,
        "merge_commit_sha": merge_sha,
        "base": {"ref": base},
        "user": {"login": author},
    }


class MergeContextTests(unittest.TestCase):
    def test_exact_merge_commit_wins_over_indirect_associations(self):
        pages = [[pull(1, "indirect", merge_sha="b" * 40), pull(2, "author")]]
        self.assertEqual(
            merge_context.resolve(pages, SHA, "main"),
            {"number": 2, "author": "author"},
        )

    def test_single_rebase_style_association_is_accepted(self):
        pages = [[pull(3, "rebased", merge_sha="b" * 40)]]
        self.assertEqual(
            merge_context.resolve(pages, SHA, "main"),
            {"number": 3, "author": "rebased"},
        )

    def test_ambiguous_missing_and_unmerged_associations_fail_closed(self):
        cases = [
            [],
            [[pull(1, "one", merge_sha="b" * 40), pull(2, "two", merge_sha="c" * 40)]],
            [[pull(1, "open", state="open", merged=False)]],
        ]
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaises(
                merge_context.MergeContextError
            ):
                merge_context.resolve(pages, SHA, "main")

    def test_wrong_base_and_missing_author_are_rejected(self):
        missing_author = pull(2, "author")
        missing_author["user"] = None
        with self.assertRaises(merge_context.MergeContextError):
            merge_context.resolve(
                [[pull(1, "release", base="release"), missing_author]], SHA, "main"
            )

        with self.assertRaises(merge_context.MergeContextError):
            merge_context.resolve([[pull(3, "line\nbreak")]], SHA, "main")


class SharedCaseTests(unittest.TestCase):
    """`plan`/`apply` fall back to a Rust copy of `resolve` when no PR number is
    set. Both implementations answer the same shared cases, so the PR an
    override is evaluated on cannot depend on which one chose it."""

    def test_the_shared_cases_hold(self):
        cases = json.loads(SHARED_CASES.read_text(encoding="utf-8"))
        self.assertGreater(len(cases), 10)
        for case in cases:
            with self.subTest(case=case["name"]):
                try:
                    number = merge_context.resolve(
                        case["pages"], case["sha"], case["base"]
                    )["number"]
                except merge_context.MergeContextError:
                    number = None
                self.assertEqual(number, case["expected"])


if __name__ == "__main__":
    unittest.main()
