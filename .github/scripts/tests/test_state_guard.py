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
                            print(os.environ['TEST_PERMISSION'])
                        elif '/files?' in route:
                            print(os.environ['TEST_PAGES'])
                        elif '--jq' in sys.argv:
                            print(os.environ['OVERRIDE_LABEL'])
                        else:
                            print(json.dumps({
                                'head': {'sha': os.environ['TEST_HEAD']},
                                'base': {'sha': 'b' * 40, 'ref': 'main'},
                                'changed_files': int(os.environ['TEST_COUNT']),
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
                    "EVENT_LABEL": "gitforgeops/state-override",
                    "EVENT_ACTOR": "maintainer",
                    "RUN_ID": "1",
                    "RUN_ATTEMPT": "1",
                    "TEST_HEAD": "a" * 40,
                    "TEST_PERMISSION": "write",
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
                            {"EVENT_ACTION": "synchronize"},
                            {"EVENT_ACTION": "labeled", "TEST_PERMISSION": "triage"},
                            {"EVENT_ACTION": "labeled", "TEST_HEAD": "c" * 40},
                        ):
                            result = run(authorize, **overrides)
                            self.assertNotEqual(result.returncode, 0)
                        result = run(authorize, EVENT_ACTION="labeled")
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            f"head_sha={'a' * 40}",
                            output.read_text(encoding="utf-8"),
                        )


if __name__ == "__main__":
    unittest.main()
