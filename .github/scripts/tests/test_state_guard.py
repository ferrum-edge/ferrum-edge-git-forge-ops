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
LABEL = "gitforgeops/state-override"
HEAD = "a" * 40


_RUN_BLOCK_RE = re.compile(r"        run: \|\n((?:          .*\n|\n)+)")


def workflow_step(name):
    text = WORKFLOW.read_text(encoding="utf-8")
    section = text.split(f"      - name: {name}\n", 1)[1]
    section = section.split("\n      - name:", 1)[0]
    match = _RUN_BLOCK_RE.search(section)
    if match is None:
        raise AssertionError(f"missing run block for {name}")
    return textwrap.dedent(match.group(1))


def review(login, review_id, *, state="COMMENTED", body="gitforgeops-state-override",
           commit=HEAD):
    return {
        "id": review_id,
        "user": {"login": login},
        "state": state,
        "body": body,
        "commit_id": commit,
    }


def labeled(login, label=LABEL, event="labeled"):
    return {"event": event, "label": {"name": label}, "actor": {"login": login}}


def unlabeled(login, label=LABEL):
    return labeled(login, label, "unlabeled")


def permission(legacy, role=None):
    value = {"permission": legacy}
    if role is not None:
        value["role_name"] = role
    return value


# A strict GitHub stub. Only the detect step's file listing may paginate with
# `--paginate`; every override read is a bare `gh api <route>`, and paged
# override routes must be numbered `?per_page=100&page=N`. Each call is logged.
GH_STUB = textwrap.dedent(
    """\
    import json
    import os
    import sys
    from urllib.parse import parse_qs

    args = sys.argv[1:]
    with open(os.environ['TEST_CALLS'], 'a', encoding='utf-8') as log:
        log.write(json.dumps(args) + '\\n')
    if os.environ.get('TEST_API_FAILS') == 'true':
        sys.exit(1)
    assert args[0] == 'api', args
    route = args[1]
    repo = 'repos/' + os.environ['REPO']
    pr = repo + '/pulls/' + os.environ['PR_NUMBER']
    if route == pr + '/files?per_page=100' and args[2:] == ['--paginate', '--slurp']:
        print(os.environ['TEST_PAGES'])
        sys.exit(0)
    assert len(args) == 2, args
    path, _, query = route.partition('?')


    def paged(name):
        fields = parse_qs(query, strict_parsing=True)
        assert sorted(fields) == ['page', 'per_page'], route
        assert fields['per_page'] == ['100'], route
        number = int(fields['page'][0])
        pages = json.loads(os.environ[name])
        print(json.dumps(pages[number - 1] if number <= len(pages) else []))


    if route == pr:
        print(json.dumps({
            'head': {'sha': os.environ['TEST_HEAD']},
            'base': {'sha': 'b' * 40, 'ref': os.environ.get('TEST_BASE_REF', 'main')},
            'changed_files': int(os.environ.get('TEST_COUNT', '1')),
            'labels': [{'name': name} for name in json.loads(os.environ['TEST_LABELS'])],
        }))
    elif path == repo + '/issues/' + os.environ['PR_NUMBER'] + '/events':
        paged('TEST_EVENTS')
    elif path == pr + '/reviews':
        paged('TEST_REVIEWS')
    elif path.startswith(repo + '/collaborators/') and path.endswith('/permission') and not query:
        login = path[len(repo + '/collaborators/'):-len('/permission')]
        permissions = json.loads(os.environ['TEST_PERMISSIONS'])
        if login not in permissions:
            # An App's bot account answers 404 here.
            sys.exit(1)
        print(json.dumps(permissions[login]))
    else:
        sys.exit('unexpected route ' + route)
    """
)


class GuardHarness:
    """A temporary workspace with the stub and the trusted-guard checkout."""

    def __init__(self, root, *, classifier=True, override_helper=True):
        self.root = root
        bin_dir = root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(f"#!{sys.executable}\n" + GH_STUB, encoding="utf-8")
        gh.chmod(0o755)
        scripts = root / "trusted-guard/.github/scripts"
        scripts.mkdir(parents=True)
        if classifier:
            shutil.copyfile(ROOT / ".github/scripts/changed_files.py", scripts / "changed_files.py")
        if override_helper:
            shutil.copyfile(
                ROOT / ".github/scripts/state_override.py", scripts / "state_override.py"
            )
        self.output = root / "output"
        self.summary = root / "summary"
        self.calls = root / "calls"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GH_TOKEN": "test-only",
            "REPO": "example/repo",
            "PR_NUMBER": "1",
            "EXPECTED_HEAD_SHA": HEAD,
            "DEFAULT_BRANCH": "main",
            "GITHUB_OUTPUT": str(self.output),
            "GITHUB_STEP_SUMMARY": str(self.summary),
            "OVERRIDE_LABEL": LABEL,
            "OVERRIDE_REVIEW": "gitforgeops-state-override",
            "RUN_ID": "1",
            "RUN_ATTEMPT": "1",
            "TEST_CALLS": str(self.calls),
            "TEST_HEAD": HEAD,
            "TEST_LABELS": json.dumps(["bug", LABEL]),
            "TEST_EVENTS": json.dumps([[labeled("maintainer")]]),
            "TEST_PERMISSIONS": json.dumps({"maintainer": permission("write", "write")}),
            "TEST_REVIEWS": json.dumps([[review("maintainer", 7)]]),
        }

    def run(self, script, **overrides):
        for path in (self.output, self.summary, self.calls):
            path.write_text("", encoding="utf-8")
        return subprocess.run(
            ["bash", "-c", script],
            cwd=self.root,
            env={**self.env, **overrides},
            capture_output=True,
            text=True,
            check=False,
        )

    def recorded_calls(self):
        return [
            json.loads(line)
            for line in self.calls.read_text(encoding="utf-8").splitlines()
        ]


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
        for classifier in (True, False):
            with self.subTest(classifier=classifier), tempfile.TemporaryDirectory() as temporary:
                guard = GuardHarness(Path(temporary), classifier=classifier)
                for records, count, requires_override in cases:
                    with self.subTest(records=records, count=count):
                        guard.env["TEST_PAGES"] = json.dumps([records])
                        guard.env["TEST_COUNT"] = str(count)
                        result = guard.run(detect)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            f"requires_override={str(requires_override).lower()}",
                            guard.output.read_text(encoding="utf-8"),
                        )
                        if not requires_override:
                            continue
                        # Label presence alone, stale heads, and triage cannot
                        # authorize even an exact-root path or an unseen tail.
                        for overrides in (
                            {"TEST_REVIEWS": json.dumps([[]])},
                            {"TEST_PERMISSIONS": json.dumps(
                                {"maintainer": permission("read", "triage")})},
                            {"TEST_HEAD": "c" * 40},
                        ):
                            result = guard.run(authorize, **overrides)
                            self.assertNotEqual(result.returncode, 0)
                        result = guard.run(authorize)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(
                            f"head_sha={HEAD}",
                            guard.output.read_text(encoding="utf-8"),
                        )

    def test_override_authority_is_the_labelers_latest_review_of_the_current_head(self):
        authorize = workflow_step("Verify state-override authority")
        with tempfile.TemporaryDirectory() as temporary:
            guard = GuardHarness(Path(temporary))
            guard.env["TEST_PERMISSIONS"] = json.dumps(
                {
                    "maintainer": permission("write", "write"),
                    "maintain-user": permission("write", "maintain"),
                    "admin-user": permission("admin", "admin"),
                    "custom-role": permission("admin", "security-reviewer"),
                    "legacy-only": permission("write"),
                    "triager": permission("read", "triage"),
                    "reader": permission("read", "read"),
                    "nobody": permission("none"),
                }
            )

            def run(events, reviews):
                return guard.run(
                    authorize,
                    TEST_EVENTS=json.dumps(events),
                    TEST_REVIEWS=json.dumps(reviews),
                )

            other = {"event": "labeled", "label": {"name": "bug"}, "actor": {"login": "x"}}
            authorized = [
                # Approve or comment, surrounding whitespace ignored.
                ([[labeled("maintainer")]], [[review("maintainer", 7)]],
                 "maintainer", "write", "7"),
                ([[labeled("maintainer")]], [[review("maintainer", 7, state="APPROVED")]],
                 "maintainer", "write", "7"),
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7, body="  gitforgeops-state-override\n")]],
                 "maintainer", "write", "7"),
                # A pending draft is not a later word.
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7), review("maintainer", 8, state="PENDING", body="")]],
                 "maintainer", "write", "7"),
                # role_name carries Maintain, which the legacy field reports as write.
                ([[labeled("maintain-user")]], [[review("maintain-user", 7)]],
                 "maintain-user", "maintain", "7"),
                ([[labeled("admin-user")]], [[review("admin-user", 9)]],
                 "admin-user", "admin", "9"),
                # A custom role falls back to the legacy base permission.
                ([[labeled("custom-role")]], [[review("custom-role", 9)]],
                 "custom-role", "admin", "9"),
                ([[labeled("legacy-only")]], [[review("legacy-only", 9)]],
                 "legacy-only", "write", "9"),
                # Another reviewer's later review does not revoke this one.
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7), review("triager", 8, body="no")]],
                 "maintainer", "write", "7"),
                # Evidence on later numbered pages is read, short pages included.
                ([[other], [labeled("maintainer")]],
                 [[review("triager", 5)], [review("maintainer", 7)]],
                 "maintainer", "write", "7"),
                # The latest add wins after a removal.
                ([[labeled("triager"), unlabeled("triager"), labeled("maintainer")]],
                 [[review("maintainer", 7)]], "maintainer", "write", "7"),
            ]
            for events, reviews, actor, granted, review_id in authorized:
                with self.subTest(events=events, reviews=reviews):
                    result = run(events, reviews)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    recorded = guard.output.read_text(encoding="utf-8")
                    self.assertIn(f"actor={actor}\n", recorded)
                    self.assertIn(f"permission={granted}\n", recorded)
                    self.assertIn(f"review_id={review_id}\n", recorded)
                    self.assertIn(f"head_sha={HEAD}\n", recorded)
                    calls = guard.recorded_calls()
                    self.assertTrue(all(len(call) == 2 for call in calls), calls)
                    # The decision ends with its own re-read of every source.
                    for route in ("/events?", "/reviews?", "/permission"):
                        self.assertTrue(any(route in call[1] for call in calls), calls)
                    self.assertEqual(
                        sum(1 for call in calls if call[1] == "repos/example/repo/pulls/1"),
                        2,
                        calls,
                    )

            refused = [
                ([[labeled("maintainer")]], [[]]),
                # The reviewer must be the account that last applied the label.
                ([[labeled("triager")]], [[review("maintainer", 7)]]),
                ([[labeled("maintainer")]], [[review("admin-user", 7)]]),
                ([[labeled("maintainer"), unlabeled("maintainer")]], [[review("maintainer", 7)]]),
                ([[]], [[review("maintainer", 7)]]),
                ([[labeled("maintainer", label="gitforgeops/state-override-lookalike")]],
                 [[review("maintainer", 7)]]),
                ([[labeled("maintainer")]], [[review("maintainer", 7, commit="c" * 40)]]),
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7, body="gitforgeops-state-override please")]]),
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7, body="gitforgeops-override state")]]),
                ([[labeled("maintainer")]], [[review("maintainer", 7, body=None)]]),
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7, state="CHANGES_REQUESTED")]]),
                ([[labeled("maintainer")]], [[review("maintainer", 7, state="DISMISSED")]]),
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7), review("maintainer", 8, body="LGTM")]]),
                ([[labeled("maintainer")]],
                 [[review("maintainer", 7)], [review("maintainer", 8, state="DISMISSED")]]),
                # Insufficient or unreadable permission.
                ([[labeled("triager")]], [[review("triager", 7)]]),
                ([[labeled("reader")]], [[review("reader", 7)]]),
                ([[labeled("nobody")]], [[review("nobody", 7)]]),
                ([[labeled("stranger")]], [[review("stranger", 7)]]),
                ([[labeled("app[bot]")]], [[review("app[bot]", 7)]]),
                # Malformed identities and records fail closed.
                ([[labeled("bad login")]], [[review("bad login", 7)]]),
                ([[labeled("x\nmaintainer")]], [[review("x\nmaintainer", 7)]]),
                ([[labeled("maintainer")]], [[review("maintainer", 7.5)]]),
                ([[labeled("maintainer")]], [[review("maintainer", 0)]]),
                ([[labeled("maintainer")]], [[review("maintainer", "7; rm -rf /")]]),
                ([[labeled("maintainer")]], [[{**review("maintainer", 7), "user": None}]]),
                ([[labeled("maintainer")]], [["not a review"]]),
                ([[labeled("maintainer")]], [review("maintainer", 7)]),
                ([[labeled("maintainer")]], [{"message": "Not Found"}]),
                ([["not an event"]], [[review("maintainer", 7)]]),
                ([{"message": "Not Found"}], [[review("maintainer", 7)]]),
                # No empty page within the cap: the history is not proven complete.
                ([[labeled("maintainer")]] * 20, [[review("maintainer", 7)]]),
                ([[labeled("maintainer")]], [[review("maintainer", 7)]] * 20),
            ]
            for events, reviews in refused:
                with self.subTest(events=events, reviews=reviews):
                    result = run(events, reviews)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(guard.output.read_text(encoding="utf-8"), "")
                    self.assertIn("::error::", result.stderr)

            for overrides in (
                {"TEST_HEAD": "c" * 40},
                {"TEST_BASE_REF": "release"},
                {"TEST_LABELS": json.dumps([])},
                {"TEST_LABELS": json.dumps(["gitforgeops/state-override-lookalike"])},
            ):
                with self.subTest(overrides=overrides):
                    result = guard.run(authorize, **overrides)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(guard.output.read_text(encoding="utf-8"), "")
                    self.assertFalse(
                        any("/permission" in call[1] for call in guard.recorded_calls())
                    )

    def test_authorize_fails_closed_without_the_trusted_helper(self):
        authorize = workflow_step("Verify state-override authority")
        with tempfile.TemporaryDirectory() as temporary:
            guard = GuardHarness(Path(temporary), override_helper=False)
            result = guard.run(authorize)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("helper is missing", result.stdout)
            self.assertEqual(guard.output.read_text(encoding="utf-8"), "")
            self.assertEqual(guard.recorded_calls(), [])

    def test_recorded_override_reruns_the_whole_decision_last(self):
        record = workflow_step("Record authorized override")
        with tempfile.TemporaryDirectory() as temporary:
            guard = GuardHarness(Path(temporary))
            guard.env.update(
                {
                    "ACTOR": "maintainer",
                    "REVIEW_ID": "7",
                    "AUTHORIZED_HEAD": HEAD,
                    "TEST_PERMISSIONS": json.dumps(
                        {
                            "maintainer": permission("write", "write"),
                            "admin-user": permission("admin", "admin"),
                        }
                    ),
                }
            )

            result = guard.run(record)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            summary = guard.summary.read_text(encoding="utf-8")
            self.assertIn("Authorized protected-state override", summary)
            self.assertIn("- Current permission: `write`", summary)
            self.assertIn("@maintainer (write) in review 7", result.stdout)
            # The final recheck re-reads the labeler, permission and reviews,
            # not only the pull request; every call is a bare numbered route.
            calls = guard.recorded_calls()
            self.assertTrue(all(len(call) == 2 for call in calls), calls)
            routes = [call[1] for call in calls]
            self.assertIn("repos/example/repo/collaborators/maintainer/permission", routes)
            self.assertIn("repos/example/repo/pulls/1/reviews?per_page=100&page=1", routes)
            self.assertIn("repos/example/repo/issues/1/events?per_page=100&page=1", routes)
            # Two PR reads by the helper, then the transitional inline re-read.
            self.assertEqual(routes.count("repos/example/repo/pulls/1"), 3, routes)
            self.assertEqual(routes[-1], "repos/example/repo/pulls/1", routes)

            # The report names the permission found now, not the one the
            # authorize step recorded (the step no longer reads PERMISSION).
            result = guard.run(
                record,
                PERMISSION="admin",
                TEST_PERMISSIONS=json.dumps({"maintainer": permission("write", "maintain")}),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            summary = guard.summary.read_text(encoding="utf-8")
            self.assertIn("- Current permission: `maintain`", summary)
            self.assertNotIn("admin", summary)
            self.assertIn("@maintainer (maintain) in review 7", result.stdout)

            for overrides in (
                {"TEST_HEAD": "c" * 40},
                {"TEST_BASE_REF": "release"},
                {"TEST_LABELS": json.dumps(["bug"])},
                {"TEST_LABELS": json.dumps([])},
                {"TEST_LABELS": json.dumps(["gitforgeops/state-override-lookalike"])},
                {"TEST_API_FAILS": "true"},
                # A later review revokes the recorded one.
                {"TEST_REVIEWS": json.dumps(
                    [[review("maintainer", 7), review("maintainer", 8, body="LGTM")]])},
                {"TEST_REVIEWS": json.dumps(
                    [[review("maintainer", 7)], [review("maintainer", 8, state="DISMISSED")]])},
                # A fresh authorizing review is not the one recorded.
                {"TEST_REVIEWS": json.dumps([[review("maintainer", 7), review("maintainer", 8)]])},
                # A demotion or a failed lookup after authorization.
                {"TEST_PERMISSIONS": json.dumps({"maintainer": permission("read", "triage")})},
                {"TEST_PERMISSIONS": json.dumps({})},
                # Someone else re-applied the label, even with their own review.
                {
                    "TEST_EVENTS": json.dumps(
                        [[labeled("maintainer"), unlabeled("admin-user"), labeled("admin-user")]]
                    ),
                    "TEST_REVIEWS": json.dumps(
                        [[review("maintainer", 7), review("admin-user", 9)]]
                    ),
                },
                {"TEST_EVENTS": json.dumps([[labeled("maintainer"), unlabeled("maintainer")]])},
                # The recorded evidence must match what the decision finds.
                {"ACTOR": "admin-user"},
                {"REVIEW_ID": "8"},
                {"AUTHORIZED_HEAD": "c" * 40},
                {"REVIEW_ID": "7\nactor=admin-user"},
            ):
                with self.subTest(overrides=overrides):
                    result = guard.run(record, **overrides)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(guard.summary.read_text(encoding="utf-8"), "")
                    self.assertNotIn("::warning::Protected state scope", result.stdout)

    def test_record_refuses_an_insufficient_reported_permission(self):
        # Defence in depth: whatever the helper prints must be a sufficient
        # permission before anything is reported.
        record = workflow_step("Record authorized override")
        for printed in ("", "read\n", "triage\n", "none\n", "write\nadmin\n", "Write\n"):
            with self.subTest(printed=printed), tempfile.TemporaryDirectory() as temporary:
                guard = GuardHarness(Path(temporary), override_helper=False)
                helper = guard.root / "trusted-guard/.github/scripts/state_override.py"
                helper.write_text(
                    f"import sys\nsys.stdout.write({printed!r})\n", encoding="utf-8"
                )
                guard.env.update(
                    {"ACTOR": "maintainer", "REVIEW_ID": "7", "AUTHORIZED_HEAD": HEAD}
                )
                result = guard.run(record)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(guard.summary.read_text(encoding="utf-8"), "")
                self.assertNotIn("::warning::Protected state scope", result.stdout)

    def test_transitional_inline_recheck_only_adds_refusals(self):
        # A helper that passes cannot outvote the inline head, base and label
        # checks, and those checks cannot pass a run the helper refused.
        record = workflow_step("Record authorized override")
        with tempfile.TemporaryDirectory() as temporary:
            guard = GuardHarness(Path(temporary), override_helper=False)
            helper = guard.root / "trusted-guard/.github/scripts/state_override.py"
            helper.write_text("import sys\nsys.stdout.write('write\\n')\n", encoding="utf-8")
            guard.env.update({"ACTOR": "maintainer", "REVIEW_ID": "7", "AUTHORIZED_HEAD": HEAD})
            result = guard.run(record)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for overrides in (
                {"TEST_HEAD": "c" * 40},
                {"TEST_BASE_REF": "release"},
                {"TEST_LABELS": json.dumps(["bug"])},
            ):
                with self.subTest(overrides=overrides):
                    result = guard.run(record, **overrides)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(guard.summary.read_text(encoding="utf-8"), "")

            helper.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
            result = guard.run(record)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(guard.summary.read_text(encoding="utf-8"), "")
            # The helper refused first; the inline block never ran.
            self.assertEqual(guard.recorded_calls(), [])

    def test_record_fails_closed_without_the_trusted_helper(self):
        record = workflow_step("Record authorized override")
        with tempfile.TemporaryDirectory() as temporary:
            guard = GuardHarness(Path(temporary), override_helper=False)
            guard.env.update(
                {"ACTOR": "maintainer", "REVIEW_ID": "7", "AUTHORIZED_HEAD": HEAD}
            )
            result = guard.run(record)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertEqual(guard.summary.read_text(encoding="utf-8"), "")
            self.assertNotIn("::warning::Protected state scope", result.stdout)


if __name__ == "__main__":
    unittest.main()
