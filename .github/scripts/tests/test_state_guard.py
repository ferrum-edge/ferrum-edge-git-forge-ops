import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
WORKFLOW = ROOT / ".github/workflows/state-guard.yml"


def workflow_step(name):
    text = WORKFLOW.read_text(encoding="utf-8")
    section = text.split(f"      - name: {name}\n", 1)[1]
    section = section.split("\n      - name:", 1)[0]
    match = re.search(r"        run: \|\n((?:          .*\n|\n)+)", section)
    if match is None:
        raise AssertionError(f"missing run block for {name}")
    return textwrap.dedent(match.group(1))


def review(login, review_id, *, state="COMMENTED", body="gitforgeops-state-override",
           commit="a" * 40):
    return {
        "id": review_id,
        "user": {"login": login},
        "state": state,
        "body": body,
        "commit_id": commit,
    }


class StateGuardTests(unittest.TestCase):
    def test_exact_state_path_requires_fresh_override_with_helper_and_fallback(self):
        detect = workflow_step("Detect .state and descendant changes")
        authorize = workflow_step("Verify state-override authority")
        cases = [
            ([{"filename": ".state", "status": "added"}], 1, True),
            ([{"filename": ".state", "status": "modified"}], 1, True),
            (
                [{"filename": "old-state", "previous_filename": ".state"}],
                1,
                True,
            ),
            (
                [{"filename": ".state", "previous_filename": "old-state"}],
                1,
                True,
            ),
            ([{"filename": "README.md"}], 2, True),
            ([{"filename": ".state/production.json"}], 1, True),
            ([{"filename": ".state-backup"}], 1, False),
        ]
        for helper in (True, False):
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bin_dir = root / "bin"
                bin_dir.mkdir()
                gh = bin_dir / "gh"
                gh.write_text(
                    f"#!{sys.executable}\n"
                    + textwrap.dedent(
                        """\
                        import json
                        import os
                        import sys

                        route = sys.argv[2]
                        if route.endswith('/permission'):
                            login = route.split('/')[-2]
                            permissions = json.loads(os.environ.get('TEST_PERMISSIONS', '{}'))
                            print(permissions.get(login, os.environ['TEST_PERMISSION']))
                        elif '/files?' in route:
                            print(os.environ['TEST_PAGES'])
                        elif '/reviews?' in route:
                            print(os.environ['TEST_REVIEWS'])
                        else:
                            print(json.dumps({
                                'head': {'sha': os.environ['TEST_HEAD']},
                                'base': {'sha': 'b' * 40, 'ref': 'main'},
                                'changed_files': int(os.environ['TEST_COUNT']),
                                'labels': [
                                    {'name': name}
                                    for name in json.loads(os.environ['TEST_LABELS'])
                                ],
                            }))
                        """
                    ),
                    encoding="utf-8",
                )
                gh.chmod(0o755)
                if helper:
                    target = root / "trusted-guard/.github/scripts/changed_files.py"
                    target.parent.mkdir(parents=True)
                    shutil.copyfile(ROOT / ".github/scripts/changed_files.py", target)
                output = root / "output"
                env = {
                    **os.environ,
                    "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                    "GH_TOKEN": "test-only",
                    "REPO": "example/repo",
                    "PR_NUMBER": "1",
                    "EXPECTED_HEAD_SHA": "a" * 40,
                    "DEFAULT_BRANCH": "main",
                    "GITHUB_OUTPUT": str(output),
                    "OVERRIDE_LABEL": "gitforgeops/state-override",
                    "OVERRIDE_REVIEW": "gitforgeops-state-override",
                    "RUN_ID": "1",
                    "RUN_ATTEMPT": "1",
                    "TEST_HEAD": "a" * 40,
                    "TEST_PERMISSION": "write",
                    "TEST_LABELS": json.dumps(["gitforgeops/state-override"]),
                    "TEST_REVIEWS": json.dumps([[review("maintainer", 7)]]),
                }

                def run(script, **overrides):
                    output.write_text("", encoding="utf-8")
                    return subprocess.run(
                        ["bash", "-c", script],
                        cwd=root,
                        env={**env, **overrides},
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                for records, count, requires_override in cases:
                    with self.subTest(records=records, count=count):
                        env["TEST_PAGES"] = json.dumps([records])
                        env["TEST_COUNT"] = str(count)
                        result = run(detect)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            f"requires_override={str(requires_override).lower()}",
                            output.read_text(encoding="utf-8"),
                        )
                        if not requires_override:
                            continue
                        # Label presence alone, stale heads, and triage cannot
                        # authorize even an exact-root path or an unseen tail.
                        for overrides in (
                            {"TEST_REVIEWS": json.dumps([[]])},
                            {"TEST_PERMISSION": "triage"},
                            {"TEST_HEAD": "c" * 40},
                        ):
                            result = run(authorize, **overrides)
                            self.assertNotEqual(result.returncode, 0)
                        result = run(authorize)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            f"head_sha={'a' * 40}",
                            output.read_text(encoding="utf-8"),
                        )

    def test_recorded_override_rechecks_head_base_and_label_last(self):
        record = workflow_step("Record authorized override")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(
                    """\
                    import json
                    import os
                    import sys

                    expected = [
                        "api",
                        f"repos/{os.environ['REPO']}/pulls/{os.environ['PR_NUMBER']}",
                    ]
                    assert sys.argv[1:] == expected, sys.argv[1:]
                    if os.environ.get("TEST_API_FAILS") == "true":
                        sys.exit(1)
                    print(json.dumps({
                        'head': {'sha': os.environ['TEST_HEAD']},
                        'base': {'sha': 'b' * 40, 'ref': os.environ['TEST_BASE_REF']},
                        'labels': [
                            {'name': name}
                            for name in json.loads(os.environ['TEST_LABELS'])
                        ],
                    }))
                    """
                ),
                encoding="utf-8",
            )
            gh.chmod(0o755)
            summary = root / "summary"
            env = {
                **os.environ,
                "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                "GH_TOKEN": "test-only",
                "REPO": "example/repo",
                "PR_NUMBER": "1",
                "EXPECTED_HEAD_SHA": "a" * 40,
                "DEFAULT_BRANCH": "main",
                "OVERRIDE_LABEL": "gitforgeops/state-override",
                "ACTOR": "maintainer",
                "PERMISSION": "write",
                "REVIEW_ID": "7",
                "AUTHORIZED_HEAD": "a" * 40,
                "RUN_ID": "1",
                "RUN_ATTEMPT": "1",
                "GITHUB_STEP_SUMMARY": str(summary),
                "TEST_HEAD": "a" * 40,
                "TEST_BASE_REF": "main",
                "TEST_LABELS": json.dumps(["bug", "gitforgeops/state-override"]),
            }

            def run(**overrides):
                summary.write_text("", encoding="utf-8")
                return subprocess.run(
                    ["bash", "-c", record],
                    cwd=root,
                    env={**env, **overrides},
                    capture_output=True,
                    text=True,
                    check=False,
                )

            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "Authorized protected-state override", summary.read_text(encoding="utf-8")
            )

            for overrides in (
                {"TEST_HEAD": "c" * 40},
                {"TEST_BASE_REF": "release"},
                {"TEST_LABELS": json.dumps(["bug"])},
                {"TEST_LABELS": json.dumps([])},
                {"TEST_LABELS": json.dumps(["gitforgeops/state-override-lookalike"])},
                {"TEST_API_FAILS": "true"},
            ):
                with self.subTest(overrides=overrides):
                    result = run(**overrides)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(summary.read_text(encoding="utf-8"), "")
                    self.assertNotIn("::warning::Protected state scope", result.stdout)

    def test_override_authority_is_the_latest_review_of_the_current_head(self):
        authorize = workflow_step("Verify state-override authority")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            calls = root / "calls"
            gh = bin_dir / "gh"
            gh.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(
                    """\
                    import json
                    import os
                    import sys

                    route = sys.argv[2]
                    with open(os.environ['TEST_CALLS'], 'a', encoding='utf-8') as log:
                        log.write(route + '\\n')
                    if route.endswith('/permission'):
                        login = route.split('/')[-2]
                        print(json.loads(os.environ['TEST_PERMISSIONS']).get(login, 'none'))
                    elif '/reviews?' in route:
                        print(os.environ['TEST_REVIEWS'])
                    else:
                        print(json.dumps({
                            'head': {'sha': os.environ['TEST_HEAD']},
                            'labels': [
                                {'name': name}
                                for name in json.loads(os.environ['TEST_LABELS'])
                            ],
                        }))
                    """
                ),
                encoding="utf-8",
            )
            gh.chmod(0o755)
            output = root / "output"
            env = {
                **os.environ,
                "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                "GH_TOKEN": "test-only",
                "REPO": "example/repo",
                "PR_NUMBER": "1",
                "EXPECTED_HEAD_SHA": "a" * 40,
                "OVERRIDE_LABEL": "gitforgeops/state-override",
                "OVERRIDE_REVIEW": "gitforgeops-state-override",
                "RUN_ID": "1",
                "RUN_ATTEMPT": "1",
                "GITHUB_OUTPUT": str(output),
                "TEST_CALLS": str(calls),
                "TEST_HEAD": "a" * 40,
                "TEST_LABELS": json.dumps(["gitforgeops/state-override"]),
                "TEST_PERMISSIONS": json.dumps(
                    {"maintainer": "write", "admin-user": "admin", "triager": "triage"}
                ),
            }

            def run(pages):
                output.write_text("", encoding="utf-8")
                calls.write_text("", encoding="utf-8")
                return subprocess.run(
                    ["bash", "-c", authorize],
                    cwd=root,
                    env={**env, "TEST_REVIEWS": json.dumps(pages)},
                    capture_output=True,
                    text=True,
                    check=False,
                )

            authorized = [
                # Approve or comment, surrounding whitespace ignored.
                ([[review("maintainer", 7)]], "maintainer", "7"),
                ([[review("maintainer", 7, state="APPROVED")]], "maintainer", "7"),
                ([[review("maintainer", 7, body="  gitforgeops-state-override\n")]],
                 "maintainer", "7"),
                # A pending draft is not a later word.
                ([[review("maintainer", 7), review("maintainer", 8, state="PENDING",
                                                  body="")]], "maintainer", "7"),
                # A triage reviewer is skipped, not fatal; a later page counts.
                ([[review("triager", 5)], [review("admin-user", 9)]], "admin-user", "9"),
                # Another reviewer's later review does not revoke this one.
                ([[review("maintainer", 7), review("triager", 8, body="no")]],
                 "maintainer", "7"),
            ]
            for pages, actor, review_id in authorized:
                with self.subTest(pages=pages):
                    result = run(pages)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    recorded = output.read_text(encoding="utf-8")
                    self.assertIn(f"actor={actor}\n", recorded)
                    self.assertIn(f"review_id={review_id}\n", recorded)
                    self.assertIn(f"head_sha={'a' * 40}\n", recorded)

            refused = [
                [[]],
                [[review("maintainer", 7, commit="c" * 40)]],
                [[review("maintainer", 7, body="gitforgeops-state-override please")]],
                [[review("maintainer", 7, body="gitforgeops-override state")]],
                [[review("maintainer", 7, body=None)]],
                [[review("maintainer", 7, state="CHANGES_REQUESTED")]],
                [[review("maintainer", 7, state="DISMISSED")]],
                [[review("maintainer", 7), review("maintainer", 8, body="LGTM")]],
                [[review("maintainer", 7)], [review("maintainer", 8, state="DISMISSED")]],
                [[review("triager", 7)]],
                [[review("stranger", 7)]],
                [[review("bad login", 7)]],
                [[review("maintainer", "7; rm -rf /")]],
                [[{**review("maintainer", 7), "user": None}]],
                [["not a review"]],
                [review("maintainer", 7)],
                {"message": "Not Found"},
            ]
            for pages in refused:
                with self.subTest(pages=pages):
                    result = run(pages)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(output.read_text(encoding="utf-8"), "")

            for overrides in (
                {"TEST_HEAD": "c" * 40},
                {"TEST_LABELS": json.dumps([])},
                {"TEST_LABELS": json.dumps(["gitforgeops/state-override-lookalike"])},
            ):
                with self.subTest(overrides=overrides):
                    env.update(overrides)
                    try:
                        result = run([[review("maintainer", 7)]])
                    finally:
                        env["TEST_HEAD"] = "a" * 40
                        env["TEST_LABELS"] = json.dumps(["gitforgeops/state-override"])
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(output.read_text(encoding="utf-8"), "")
                    self.assertNotIn("/permission", calls.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
