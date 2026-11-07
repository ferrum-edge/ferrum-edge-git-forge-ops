import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "state_override.py"
SPEC = importlib.util.spec_from_file_location("state_override", SCRIPT)
assert SPEC and SPEC.loader
state_override = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = state_override
SPEC.loader.exec_module(state_override)

LABEL = "gitforgeops/state-override"
MARKER = "gitforgeops-state-override"
HEAD = "a" * 40
REPO = "repos/example/repo"
PR = f"{REPO}/pulls/1"

ENV = {
    "REPO": "example/repo",
    "PR_NUMBER": "1",
    "EXPECTED_HEAD_SHA": HEAD,
    "DEFAULT_BRANCH": "main",
    "OVERRIDE_LABEL": LABEL,
    "OVERRIDE_REVIEW": MARKER,
}


def review(login, review_id, *, state="COMMENTED", body=MARKER, commit=HEAD):
    return {
        "id": review_id,
        "user": {"login": login},
        "state": state,
        "body": body,
        "commit_id": commit,
    }


def labeled(login, label=LABEL, event="labeled"):
    return {"event": event, "label": {"name": label}, "actor": {"login": login}}


def pull_request(head=HEAD, labels=(LABEL,), base_ref="main", base_sha="b" * 40):
    return {
        "head": {"sha": head},
        "base": {"sha": base_sha, "ref": base_ref},
        "labels": [{"name": name} for name in labels],
    }


class FakeGitHub:
    """Serves fixed routes; `final` replaces sources once the PR is re-read.

    Every decision reads the pull request first and again to open its final
    pass, so the second PR read marks where the final re-read begins.
    """

    def __init__(self, *, pr=None, events=None, reviews=None, permissions=None, final=None):
        self.sources = {
            "pr": pr if pr is not None else pull_request(),
            "events": events if events is not None else [[labeled("maintainer")]],
            "reviews": reviews if reviews is not None else [[review("maintainer", 7)]],
            "permissions": permissions
            if permissions is not None
            else {"maintainer": {"permission": "write", "role_name": "write"}},
        }
        self.final = final or {}
        self.routes = []
        self.pr_reads = 0

    def source(self, name):
        if self.pr_reads >= 2 and name in self.final:
            return self.final[name]
        return self.sources[name]

    def __call__(self, route):
        self.routes.append(route)
        if route == PR:
            self.pr_reads += 1
            value = self.source("pr")
        elif route.startswith(f"{REPO}/issues/1/events?per_page=100&page="):
            value = self.page(self.source("events"), route)
        elif route.startswith(f"{PR}/reviews?per_page=100&page="):
            value = self.page(self.source("reviews"), route)
        elif route.startswith(f"{REPO}/collaborators/") and route.endswith("/permission"):
            login = route[len(f"{REPO}/collaborators/"):-len("/permission")]
            permissions = self.source("permissions")
            if login not in permissions:
                raise state_override.OverrideRefused(f"GitHub API request failed: {route}")
            value = permissions[login]
        else:
            raise AssertionError(f"unexpected route {route}")
        if isinstance(value, Exception):
            raise value
        return value

    @staticmethod
    def page(pages, route):
        number = int(route.rsplit("=", 1)[1])
        return pages[number - 1] if number <= len(pages) else []


def decide(github):
    return state_override.decide(github, state_override.context_from_env(ENV))


class NumberedPagesTests(unittest.TestCase):
    def test_reads_numbered_pages_until_an_empty_one(self):
        routes = []
        pages = [[1], [2, 3], [4]]

        def fetch(route):
            routes.append(route)
            number = int(route.rsplit("=", 1)[1])
            return pages[number - 1] if number <= len(pages) else []

        records = state_override.numbered_pages(fetch, f"{PR}/reviews", "review")
        self.assertEqual(records, [1, 2, 3, 4])
        # A short page is not the last; only the empty page ends the history.
        self.assertEqual(
            routes,
            [f"{PR}/reviews?per_page=100&page={number}" for number in (1, 2, 3, 4)],
        )

    def test_a_history_without_an_empty_page_within_the_cap_fails_closed(self):
        routes = []

        def fetch(route):
            routes.append(route)
            return [{"id": len(routes)}]

        with self.assertRaisesRegex(state_override.OverrideRefused, "pagination safety cap"):
            state_override.numbered_pages(fetch, f"{PR}/reviews", "review")
        self.assertEqual(len(routes), state_override.MAX_PAGES)

    def test_a_page_that_is_not_a_list_fails_closed(self):
        for page in ({"message": "Not Found"}, None, "[]"):
            with self.subTest(page=page), self.assertRaises(state_override.OverrideRefused):
                state_override.numbered_pages(lambda _route: page, f"{PR}/reviews", "review")

    def test_gh_is_called_with_the_route_alone(self):
        completed = subprocess.CompletedProcess(["gh"], 0, stdout="[]", stderr="")
        with mock.patch.object(
            state_override.subprocess, "run", return_value=completed
        ) as run:
            self.assertEqual(state_override.gh_api(f"{PR}/reviews?per_page=100&page=1"), [])
        argv = run.call_args.args[0]
        # No `--paginate`: a `Link` header is never followed.
        self.assertEqual(argv, ["gh", "api", f"{PR}/reviews?per_page=100&page=1"])

        for completed in (
            subprocess.CompletedProcess(["gh"], 1, stdout="", stderr="404"),
            subprocess.CompletedProcess(["gh"], 0, stdout="not json", stderr=""),
        ):
            with self.subTest(completed=completed), mock.patch.object(
                state_override.subprocess, "run", return_value=completed
            ), self.assertRaises(state_override.OverrideRefused):
                state_override.gh_api(PR)


class PermissionTests(unittest.TestCase):
    def test_role_name_is_preferred_when_it_is_a_built_in_rank(self):
        cases = [
            ({"permission": "write", "role_name": "maintain"}, "maintain"),
            ({"permission": "read", "role_name": "triage"}, "triage"),
            ({"permission": "admin", "role_name": "admin"}, "admin"),
            # A custom role falls back to the legacy base permission.
            ({"permission": "write", "role_name": "security-reviewer"}, "write"),
            ({"permission": "write", "role_name": None}, "write"),
            ({"permission": "write"}, "write"),
        ]
        for response, expected in cases:
            with self.subTest(response=response):
                self.assertEqual(state_override.effective_permission(response), expected)

    def test_malformed_permission_responses_fail_closed(self):
        for response in (
            {},
            {"permission": None},
            {"permission": "write", "role_name": 3},
            ["write"],
            "write",
        ):
            with self.subTest(response=response), self.assertRaises(
                state_override.OverrideRefused
            ):
                state_override.effective_permission(response)

    def test_only_write_maintain_and_admin_are_sufficient(self):
        for granted, sufficient in (
            ("admin", True),
            ("maintain", True),
            ("write", True),
            ("triage", False),
            ("read", False),
            ("none", False),
            ("Write", False),
            ("security-reviewer", False),
        ):
            with self.subTest(granted=granted):
                self.assertIs(state_override.is_sufficient(granted), sufficient)

    def test_a_maintain_labeler_authorizes_and_is_recorded_as_maintain(self):
        github = FakeGitHub(
            permissions={"maintainer": {"permission": "write", "role_name": "maintain"}}
        )
        evidence = decide(github)
        self.assertEqual(evidence.permission, "maintain")
        self.assertEqual(evidence.actor, "maintainer")


class LabelerAndReviewTests(unittest.TestCase):
    def test_the_latest_add_of_the_exact_label_names_the_labeler(self):
        cases = [
            ([labeled("a")], "a"),
            ([labeled("a"), labeled("b")], "b"),
            ([labeled("a"), labeled("b", event="unlabeled")], None),
            ([labeled("a"), labeled("a", event="unlabeled"), labeled("c")], "c"),
            ([labeled("a"), labeled("b", label="bug")], "a"),
            ([labeled("a", label=LABEL + "-lookalike")], None),
            ([{"event": "labeled", "label": {"name": LABEL}, "actor": None}], None),
            ([{"event": "assigned", "label": None}, labeled("a")], "a"),
            ([], None),
        ]
        for events, expected in cases:
            with self.subTest(events=events):
                self.assertEqual(state_override.override_labeler(events, LABEL), expected)

    def test_malformed_events_fail_closed(self):
        for event in (
            "labeled",
            {"label": {"name": LABEL}, "actor": {"login": "a"}},
            {"event": "labeled", "label": "gitforgeops/state-override"},
            {"event": "labeled", "label": {"name": LABEL}, "actor": {"login": 7}},
        ):
            with self.subTest(event=event), self.assertRaises(state_override.OverrideRefused):
                state_override.override_labeler([event], LABEL)

    def test_the_labelers_latest_submitted_review_decides(self):
        def authorized(records, head=HEAD):
            found = state_override.authorized_review(
                state_override.reviews(records), "maintainer", MARKER, head
            )
            return None if found is None else found.id

        self.assertEqual(authorized([review("maintainer", 7)]), 7)
        self.assertEqual(authorized([review("maintainer", 7, state="APPROVED")]), 7)
        self.assertEqual(authorized([review("maintainer", 7, body=f"\n {MARKER}\t")]), 7)
        self.assertEqual(
            authorized([review("maintainer", 7), review("maintainer", 8, state="PENDING")]), 7
        )
        self.assertEqual(authorized([review("maintainer", 7), review("other", 8, body="x")]), 7)
        self.assertIsNone(authorized([review("other", 7)]))
        self.assertIsNone(authorized([review("maintainer", 7), review("maintainer", 8, body="")]))
        self.assertIsNone(authorized([review("maintainer", 7, state="DISMISSED")]))
        self.assertIsNone(authorized([review("maintainer", 7, commit="c" * 40)]))
        self.assertIsNone(authorized([review("maintainer", 7, body=None)]))
        # Rust's `trim` keeps the U+001C..U+001F separators.
        self.assertIsNone(authorized([review("maintainer", 7, body=MARKER + "\x1f")]))
        self.assertIsNone(authorized([review("maintainer", 7)], head="not-a-revision"))

    def test_malformed_reviews_fail_closed(self):
        for record in (
            review("maintainer", 0),
            review("maintainer", 7.5),
            review("maintainer", True),
            review("maintainer", "7"),
            {**review("maintainer", 7), "state": None},
            {**review("maintainer", 7), "user": {"login": None}},
            "review",
        ):
            with self.subTest(record=record), self.assertRaises(state_override.OverrideRefused):
                state_override.reviews([record])


class DecisionTests(unittest.TestCase):
    def test_an_authorized_override_reads_every_source_twice(self):
        github = FakeGitHub(
            events=[[{"event": "labeled", "label": {"name": "bug"}, "actor": {"login": "x"}}],
                    [labeled("maintainer")]],
            reviews=[[review("other", 5)], [review("maintainer", 7)]],
        )
        evidence = decide(github)
        self.assertEqual(
            evidence,
            state_override.Evidence(actor="maintainer", permission="write", review_id=7, head=HEAD),
        )
        self.assertEqual(github.pr_reads, 2)
        for route in (
            f"{REPO}/issues/1/events?per_page=100&page=3",
            f"{PR}/reviews?per_page=100&page=3",
            f"{REPO}/collaborators/maintainer/permission",
        ):
            self.assertEqual(github.routes.count(route), 2, github.routes)

    def test_the_reviewer_must_be_the_labeler(self):
        github = FakeGitHub(
            events=[[labeled("triager")]],
            reviews=[[review("maintainer", 7)]],
            permissions={
                "triager": {"permission": "read", "role_name": "triage"},
                "maintainer": {"permission": "write", "role_name": "write"},
            },
        )
        with self.assertRaisesRegex(state_override.OverrideRefused, "triager"):
            decide(github)

        github = FakeGitHub(
            events=[[labeled("maintainer")]],
            reviews=[[review("admin-user", 7)]],
        )
        with self.assertRaises(state_override.OverrideRefused):
            decide(github)

    def test_evidence_that_changes_before_the_final_re_read_refuses(self):
        stale = {
            # A later review by the labeler revokes the override.
            "later review": {"reviews": [[review("maintainer", 7), review("maintainer", 8, body="LGTM")]]},
            "dismissed": {"reviews": [[review("maintainer", 7, state="DISMISSED")]]},
            # A fresh authorizing review is still a different review.
            "replaced review": {"reviews": [[review("maintainer", 7), review("maintainer", 8)]]},
            "review read fails": {
                "reviews": [state_override.OverrideRefused("GitHub API request failed")]
            },
            # A demotion, or a permission that can no longer be read.
            "demoted": {"permissions": {"maintainer": {"permission": "read", "role_name": "triage"}}},
            "permission lookup fails": {"permissions": {}},
            # Another account re-applied the label, or it was removed.
            "relabeled": {
                "events": [[labeled("maintainer"), labeled("other", event="unlabeled"), labeled("other")]]
            },
            "unlabeled": {"events": [[labeled("maintainer"), labeled("maintainer", event="unlabeled")]]},
            "event history overflows": {"events": [[labeled("maintainer")]] * 20},
            # The pull request itself moved.
            "pushed": {"pr": pull_request(head="c" * 40)},
            "retargeted": {"pr": pull_request(base_ref="release")},
            "base moved": {"pr": pull_request(base_sha="d" * 40)},
            "label added": {"pr": pull_request(labels=(LABEL, "bug"))},
            "label removed": {"pr": pull_request(labels=())},
            "pr read fails": {"pr": state_override.OverrideRefused("GitHub API request failed")},
        }
        for name, final in stale.items():
            with self.subTest(name):
                # Without the change the same sources authorize.
                decide(FakeGitHub())
                with self.assertRaisesRegex(state_override.OverrideRefused, "changed during"):
                    decide(FakeGitHub(final=final))

    def test_a_promotion_during_verification_keeps_the_verified_permission(self):
        github = FakeGitHub(
            final={"permissions": {"maintainer": {"permission": "admin", "role_name": "admin"}}}
        )
        # The final pass requires a sufficient permission, as Rust does; the
        # evidence records the permission verified first.
        self.assertEqual(decide(github).permission, "write")

    def test_initial_refusals_never_read_permission(self):
        for pr in (
            pull_request(head="c" * 40),
            pull_request(base_ref="release"),
            pull_request(labels=()),
            pull_request(labels=(LABEL + "-lookalike",)),
            {"head": {"sha": HEAD}},
            {"head": {"sha": HEAD}, "base": {"sha": "b" * 40, "ref": "main"}, "labels": None},
        ):
            with self.subTest(pr=pr):
                github = FakeGitHub(pr=pr)
                with self.assertRaises(state_override.OverrideRefused):
                    decide(github)
                self.assertFalse(any("/permission" in route for route in github.routes))

    def test_malformed_inputs_fail_closed_before_any_request(self):
        for name, value in (
            ("REPO", "example/repo/../other"),
            ("REPO", ""),
            ("PR_NUMBER", "1/../2"),
            ("PR_NUMBER", "01"),
            ("PR_NUMBER", "0"),
            ("EXPECTED_HEAD_SHA", "a" * 39),
            ("OVERRIDE_LABEL", ""),
            ("OVERRIDE_REVIEW", ""),
        ):
            with self.subTest(name=name, value=value):
                with self.assertRaises(state_override.OverrideRefused):
                    state_override.context_from_env({**ENV, name: value})


class CommandTests(unittest.TestCase):
    def run_main(self, command, github, environ):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(state_override.os.environ, environ, clear=True), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = state_override.main([command], fetch=github)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_authorize_prints_only_validated_outputs(self):
        code, stdout, stderr = self.run_main("authorize", FakeGitHub(), ENV)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(
            stdout,
            f"actor=maintainer\npermission=write\nreview_id=7\nhead_sha={HEAD}\n",
        )

        code, stdout, stderr = self.run_main(
            "authorize", FakeGitHub(reviews=[[]]), ENV
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("::error::"), stderr)

    def test_recheck_requires_the_recorded_evidence(self):
        recorded = {**ENV, "ACTOR": "maintainer", "REVIEW_ID": "7", "AUTHORIZED_HEAD": HEAD}
        code, stdout, stderr = self.run_main("recheck", FakeGitHub(), recorded)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stdout, "")

        for changes in (
            {"ACTOR": "other"},
            {"ACTOR": "x\nmaintainer"},
            {"REVIEW_ID": "8"},
            {"REVIEW_ID": "07"},
            {"REVIEW_ID": ""},
            {"AUTHORIZED_HEAD": "c" * 40},
        ):
            with self.subTest(changes=changes):
                code, stdout, stderr = self.run_main(
                    "recheck", FakeGitHub(), {**recorded, **changes}
                )
                self.assertEqual(code, 1)
                self.assertIn("::error::", stderr)

        # The recheck re-reads reviews and permission, not only the PR.
        for github in (
            FakeGitHub(reviews=[[review("maintainer", 7), review("maintainer", 8, body="no")]]),
            FakeGitHub(permissions={"maintainer": {"permission": "read", "role_name": "triage"}}),
            FakeGitHub(events=[[labeled("maintainer"), labeled("other")]]),
        ):
            with self.subTest(github=github.sources):
                code, _stdout, stderr = self.run_main("recheck", github, recorded)
                self.assertEqual(code, 1)
                self.assertIn("::error::", stderr)


if __name__ == "__main__":
    unittest.main()
