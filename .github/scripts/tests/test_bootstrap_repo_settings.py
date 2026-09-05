"""The repository bootstrap must be a faithful, idempotent, dry-run-first writer."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import io
import contextlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "bootstrap_repo_settings.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_repo_settings", SCRIPT)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bootstrap
SPEC.loader.exec_module(bootstrap)

# `bootstrap_repo_settings.py` imports its baseline constants from the auditor,
# so the writer and the scheduled check cannot drift apart. Reach the auditor
# through that same import rather than loading a second copy.
audit_settings = sys.modules["audit_settings"]

REPO = "acme/repo"
APP_ID = 99
REVIEWER_ID = 4242

CONFIG_YAML = """# gitforgeops repo configuration
version: 1

environments:
  staging:
    overlay: staging
    apply_strategy: incremental
    ownership:
      mode: shared
      drift_report: true

  production:
    overlay: production
    apply_strategy: full_replace
    ownership:
      mode: exclusive
      namespaces: [ferrum]

default_environment: staging
"""


class FakeApi:
    """Records writes instead of performing them; 404s anything unseeded."""

    def __init__(self, responses: dict, *, dry_run: bool = True) -> None:
        self.responses = responses
        self.dry_run = dry_run
        self.writes: list[tuple[str, str, dict | None]] = []
        self.reads: list[str] = []

    def get(self, path: str, *, paginate: bool = False):
        self.reads.append(path)
        if path not in self.responses:
            raise bootstrap.ApiError(404, f"gh: Not Found (HTTP 404) for {path}")
        value = self.responses[path]
        if isinstance(value, bootstrap.ApiError):
            raise value
        return copy.deepcopy(value)

    def write(self, method: str, path: str, body: dict | None = None):
        self.writes.append((method, path, body))
        return None


def namespace(**overrides) -> argparse.Namespace:
    values = {
        "repo": REPO,
        "apply": False,
        "state_writer_app_id": APP_ID,
        "environment": [],
        "reviewer": [],
        "reviewer_team": [],
        "release_tag_bypass": "app:1234",
        "template_repo": False,
        "config": "/nonexistent/config.yaml",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def configured_responses(
    *,
    app_id: int | None = APP_ID,
    template: bool = False,
    environments: tuple[str, ...] = (),
) -> dict:
    if app_id is None:
        main_bypass = [
            {
                "actor_type": "RepositoryRole",
                "actor_id": bootstrap.REPOSITORY_ADMIN_ROLE_ID,
                "bypass_mode": "pull_request",
            }
        ]
    else:
        main_bypass = [
            {"actor_type": "Integration", "actor_id": app_id, "bypass_mode": "always"}
        ]
    main = bootstrap.main_ruleset_body(main_bypass)
    # GitHub returns fields the baseline has no opinion about. They must not
    # register as drift, or every run would report an update.
    main = copy.deepcopy(main)
    main["id"] = 7
    main["source_type"] = "Repository"
    for rule in main["rules"]:
        if rule["type"] == "pull_request":
            rule["parameters"]["require_last_push_approval"] = False
            rule["parameters"]["allowed_merge_methods"] = ["merge", "squash"]
    tag = copy.deepcopy(
        bootstrap.release_tag_ruleset_body(
            [{"actor_type": "Integration", "actor_id": 1234, "bypass_mode": "always"}]
        )
    )
    tag["id"] = 8

    responses = {
        f"repos/{REPO}/actions/permissions": {
            "enabled": True,
            "allowed_actions": "selected",
            "sha_pinning_required": True,
        },
        f"repos/{REPO}/actions/permissions/selected-actions": {
            "github_owned_allowed": True,
            "verified_allowed": False,
            # Deliberately unsorted: the allowlist is a set, not a sequence.
            "patterns_allowed": list(reversed(sorted(bootstrap.ALLOWED_ACTION_PATTERNS))),
        },
        f"repos/{REPO}/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        f"repos/{REPO}": {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            }
        },
        f"repos/{REPO}/private-vulnerability-reporting": {"enabled": True},
        f"repos/{REPO}/vulnerability-alerts": None,
        f"repos/{REPO}/automated-security-fixes": {"enabled": True, "paused": False},
        f"repos/{REPO}/rulesets?per_page=100": [[{"id": 7}, {"id": 8}]],
        f"repos/{REPO}/rulesets/7": main,
        f"repos/{REPO}/rulesets/8": tag,
        "users/octocat": {"id": REVIEWER_ID, "login": "octocat"},
    }
    for label in bootstrap.OVERRIDE_LABELS:
        encoded = label["name"].replace("/", "%2F")
        responses[f"repos/{REPO}/labels/{encoded}"] = {
            "name": label["name"],
            "color": label["color"].lower(),
            "description": label["description"],
        }
    if app_id is not None:
        responses[f"repos/{REPO}/actions/variables/{bootstrap.STATE_APP_VARIABLE}"] = {
            "name": bootstrap.STATE_APP_VARIABLE,
            "value": str(app_id),
        }
    if template:
        responses[f"repos/{REPO}/actions/variables/{bootstrap.TEMPLATE_VARIABLE}"] = {
            "name": bootstrap.TEMPLATE_VARIABLE,
            "value": "true",
        }
    # Present on every configured repository, template included: it fences the
    # administration-read audit token to the protected branch, and holds no
    # reviewer because it deploys nothing.
    responses[
        f"repos/{REPO}/environments/{bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"
    ] = {
        "name": bootstrap.SETTINGS_AUDIT_ENVIRONMENT,
        "protection_rules": [],
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }
    for name in environments:
        responses[f"repos/{REPO}/environments/{name}"] = {
            "name": name,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {"type": "User", "reviewer": {"id": REVIEWER_ID, "login": "octocat"}}
                    ],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
    return responses


def actions(plan) -> dict[str, str]:
    return {step.target: step.action for step in plan.steps}


class ConfigReaderTests(unittest.TestCase):
    def test_environment_names_come_from_the_environments_block(self):
        self.assertEqual(
            bootstrap.environment_names_from_config(CONFIG_YAML),
            ["staging", "production"],
        )

    def test_nested_keys_and_other_top_level_blocks_are_ignored(self):
        self.assertNotIn(
            "ownership", bootstrap.environment_names_from_config(CONFIG_YAML)
        )
        self.assertEqual(
            bootstrap.environment_names_from_config(
                "version: 1\npolicies:\n  something:\n"
            ),
            [],
        )

    def test_resolve_environments_prefers_the_explicit_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(CONFIG_YAML, encoding="utf-8")
            self.assertEqual(
                bootstrap.resolve_environments(
                    namespace(config=str(config), environment=["sandbox", "sandbox"])
                ),
                ["sandbox"],
            )
            self.assertEqual(
                bootstrap.resolve_environments(namespace(config=str(config))),
                ["staging", "production"],
            )

    def test_a_missing_config_resolves_no_environments(self):
        self.assertEqual(bootstrap.resolve_environments(namespace()), [])


class IdempotencyTests(unittest.TestCase):
    def test_a_configured_repository_reports_everything_unchanged(self):
        api = FakeApi(configured_responses(environments=("production",)))
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(
                "version: 1\nenvironments:\n  production:\n    overlay: production\n",
                encoding="utf-8",
            )
            plan = bootstrap.build_plan(
                api, namespace(config=str(config), reviewer=["octocat"])
            )
        self.assertEqual(
            sorted({step.action for step in plan.steps}), [bootstrap.UNCHANGED]
        )
        self.assertEqual(api.writes, [])
        self.assertEqual([step.details for step in plan.steps if step.details], [])

    def test_an_unconfigured_repository_creates_or_updates_every_control(self):
        api = FakeApi({f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]})
        plan = bootstrap.build_plan(api, namespace())
        recorded = actions(plan)
        self.assertEqual(recorded["actions permissions"], bootstrap.UPDATE)
        self.assertEqual(recorded["third-party action allowlist"], bootstrap.UPDATE)
        self.assertEqual(recorded["workflow token defaults"], bootstrap.UPDATE)
        self.assertEqual(recorded["secret scanning"], bootstrap.UPDATE)
        self.assertEqual(
            recorded["private vulnerability reporting"], bootstrap.UPDATE
        )
        self.assertEqual(recorded["dependabot alerts"], bootstrap.UPDATE)
        self.assertEqual(recorded["dependabot security updates"], bootstrap.UPDATE)
        self.assertEqual(recorded["main ruleset"], bootstrap.CREATE)
        self.assertEqual(recorded["release-tags ruleset"], bootstrap.CREATE)
        self.assertEqual(
            recorded["label gitforgeops/policy-override"], bootstrap.CREATE
        )
        self.assertEqual(recorded["label gitforgeops/state-override"], bootstrap.CREATE)
        self.assertEqual(
            recorded[f"variable {bootstrap.STATE_APP_VARIABLE}"], bootstrap.CREATE
        )

    def test_controls_are_planned_in_the_documented_order(self):
        api = FakeApi(configured_responses())
        plan = bootstrap.build_plan(api, namespace())
        targets = [step.target for step in plan.steps]
        self.assertEqual(
            targets,
            [
                f"variable {bootstrap.STATE_APP_VARIABLE}",
                "actions permissions",
                "third-party action allowlist",
                "workflow token defaults",
                "secret scanning",
                "private vulnerability reporting",
                "dependabot alerts",
                "dependabot security updates",
                "main ruleset",
                "release-tags ruleset",
                "label gitforgeops/policy-override",
                "label gitforgeops/state-override",
                f"environment {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}",
            ],
        )


class PlanOutputTests(unittest.TestCase):
    def render(self, plan, *, dry_run=True) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            bootstrap.report(plan, dry_run=dry_run)
        return buffer.getvalue()

    def test_dry_run_output_names_the_action_and_the_difference(self):
        responses = configured_responses()
        responses[f"repos/{REPO}/actions/permissions"] = {
            "enabled": True,
            "allowed_actions": "all",
            "sha_pinning_required": False,
        }
        api = FakeApi(responses)
        plan = bootstrap.build_plan(api, namespace())
        rendered = self.render(plan)
        self.assertIn("UPDATE    actions permissions", rendered)
        self.assertIn('allowed_actions: "all" -> "selected"', rendered)
        self.assertIn("sha_pinning_required: false -> true", rendered)
        self.assertIn("UNCHANGED workflow token defaults", rendered)
        self.assertIn("Nothing was written. Re-run with --apply", rendered)
        self.assertIn(
            f"gh secret set SETTINGS_AUDIT_TOKEN --repo {REPO} "
            f"--env {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}",
            rendered,
        )
        self.assertNotIn(
            f"gh secret set SETTINGS_AUDIT_TOKEN --repo {REPO}\n", rendered
        )

    def test_ruleset_diff_names_the_missing_rule_and_the_stale_check_set(self):
        responses = configured_responses()
        ruleset = responses[f"repos/{REPO}/rulesets/7"]
        ruleset["rules"] = [
            rule for rule in ruleset["rules"] if rule["type"] != "commit_message_pattern"
        ]
        for rule in ruleset["rules"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"] = [
                    {"context": "rust-ci-check"}
                ]
        api = FakeApi(responses)
        plan = bootstrap.build_plan(api, namespace())
        detail = "\n".join(
            line
            for step in plan.steps
            if step.target == "main ruleset"
            for line in step.details
        )
        self.assertIn("rules.commit_message_pattern: <absent> -> present", detail)
        self.assertIn("rules.required_status_checks.required_status_checks", detail)
        for context in bootstrap.REQUIRED_STATUS_CHECKS:
            self.assertIn(context, detail)

    def test_the_remainder_never_carries_a_secret_value(self):
        api = FakeApi(configured_responses(environments=("production",)))
        plan = bootstrap.build_plan(
            api, namespace(environment=["production"], reviewer=["octocat"])
        )
        rendered = self.render(plan)
        self.assertIn(
            "gh secret set FERRUM_ADMIN_JWT_SECRET --repo acme/repo --env production",
            rendered,
        )
        self.assertIn("FERRUM_CREDS_BUNDLE[_N] are written by the credential broker", rendered)
        # No flag exists that could carry a secret in the first place.
        self.assertNotIn("--secret", rendered)


class BypassTests(unittest.TestCase):
    def test_the_state_writer_app_becomes_the_sole_always_mode_bypass(self):
        api = FakeApi(configured_responses())
        plan = bootstrap.build_plan(api, namespace())
        self.assertEqual(actions(plan)["main ruleset"], bootstrap.UNCHANGED)
        self.assertEqual(plan.warnings, [])

    def test_without_an_app_the_admin_role_is_used_and_the_audit_warning_is_printed(self):
        api = FakeApi(configured_responses(app_id=None))
        plan = bootstrap.build_plan(api, namespace(state_writer_app_id=None))
        self.assertEqual(actions(plan)["main ruleset"], bootstrap.UNCHANGED)
        rendered = "\n".join(plan.warnings)
        self.assertIn("Repository Admin role in pull_request mode", rendered)
        self.assertIn("gh pr merge --admin", rendered)
        self.assertIn("settings audit flags this", rendered)
        self.assertNotIn(
            f"variable {bootstrap.STATE_APP_VARIABLE}", actions(plan)
        )

    def test_switching_from_admin_to_the_app_is_reported_as_a_bypass_update(self):
        api = FakeApi(configured_responses(app_id=None))
        plan = bootstrap.build_plan(api, namespace())
        step = next(step for step in plan.steps if step.target == "main ruleset")
        self.assertEqual(step.action, bootstrap.UPDATE)
        self.assertTrue(
            any(line.startswith("bypass_actors:") for line in step.details), step.details
        )
        self.assertEqual(
            step.writes[0][:2], ("PUT", f"repos/{REPO}/rulesets/7")
        )
        self.assertEqual(
            step.writes[0][2]["bypass_actors"],
            [{"actor_type": "Integration", "actor_id": APP_ID, "bypass_mode": "always"}],
        )

    def test_an_admin_release_tag_bypass_warns_that_the_audit_rejects_it(self):
        api = FakeApi(configured_responses())
        plan = bootstrap.build_plan(api, namespace(release_tag_bypass="admin"))
        self.assertTrue(
            any("explicit App, team, or user" in warning for warning in plan.warnings),
            plan.warnings,
        )

    def test_bypass_actor_specs_are_parsed_and_validated(self):
        api = FakeApi({"users/octocat": {"id": REVIEWER_ID}, "orgs/acme/teams/plat": {"id": 7}})
        self.assertEqual(
            bootstrap.resolve_bypass_actor(api, "app:55"),
            {"actor_type": "Integration", "actor_id": 55, "bypass_mode": "always"},
        )
        self.assertEqual(
            bootstrap.resolve_bypass_actor(api, "user:octocat"),
            {"actor_type": "User", "actor_id": REVIEWER_ID, "bypass_mode": "always"},
        )
        self.assertEqual(
            bootstrap.resolve_bypass_actor(api, "team:acme/plat"),
            {"actor_type": "Team", "actor_id": 7, "bypass_mode": "always"},
        )
        for invalid in ("nonsense", "app:notanumber", "team:noslug"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(bootstrap.ApiError):
                    bootstrap.resolve_bypass_actor(api, invalid)


class TemplateModeTests(unittest.TestCase):
    def test_template_mode_sets_the_variable_and_creates_no_environment(self):
        api = FakeApi(configured_responses(app_id=None))
        plan = bootstrap.build_plan(
            api, namespace(state_writer_app_id=None, template_repo=True)
        )
        recorded = actions(plan)
        self.assertEqual(
            recorded[f"variable {bootstrap.TEMPLATE_VARIABLE}"], bootstrap.CREATE
        )
        self.assertEqual(
            [target for target in recorded if target.startswith("environment ")],
            [f"environment {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"],
        )
        # A template runs the settings audit, so it still gets the environment
        # that fences the audit token; the fixture already has it, so the plan
        # reports it unchanged rather than skipping it.
        self.assertEqual(
            recorded[f"environment {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"],
            bootstrap.UNCHANGED,
        )
        rendered = "\n".join(plan.notes)
        self.assertIn("deployment environments are not created", rendered)
        self.assertIn("skip the state-writer App bypass", rendered)
        self.assertIn("a template repository needs no other environment secrets", rendered)
        self.assertIn(
            f"gh secret set SETTINGS_AUDIT_TOKEN --repo {REPO} "
            f"--env {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}",
            rendered,
        )

    def test_template_mode_ignores_a_config_file_full_of_environments(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(CONFIG_YAML, encoding="utf-8")
            api = FakeApi(configured_responses(template=True))
            plan = bootstrap.build_plan(
                api, namespace(template_repo=True, config=str(config))
            )
        self.assertEqual(
            [
                step.target
                for step in plan.steps
                if step.target.startswith("environment ")
            ],
            [f"environment {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"],
        )
        self.assertEqual(
            actions(plan)[f"variable {bootstrap.TEMPLATE_VARIABLE}"],
            bootstrap.UNCHANGED,
        )

    def test_a_deployment_repository_turns_the_template_variable_back_off(self):
        api = FakeApi(configured_responses(template=True))
        plan = bootstrap.build_plan(api, namespace())
        step = next(
            step
            for step in plan.steps
            if step.target == f"variable {bootstrap.TEMPLATE_VARIABLE}"
        )
        self.assertEqual(step.action, bootstrap.UPDATE)
        self.assertEqual(step.writes[0][2]["value"], "false")

    def test_template_mode_and_explicit_environments_are_refused(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = bootstrap.main(
                ["--repo", REPO, "--template-repo", "--environment", "production"]
            )
        self.assertEqual(code, 1)
        self.assertIn("contradict each other", buffer.getvalue())


class EnvironmentTests(unittest.TestCase):
    def test_environments_are_created_from_config_yaml_with_reviewers(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(CONFIG_YAML, encoding="utf-8")
            api = FakeApi(configured_responses())
            plan = bootstrap.build_plan(
                api, namespace(config=str(config), reviewer=["octocat"])
            )
        created = [
            step
            for step in plan.steps
            if step.target.startswith("environment ")
            and step.target
            != f"environment {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"
        ]
        self.assertEqual(
            [step.target for step in created],
            ["environment staging", "environment production"],
        )
        for step in created:
            self.assertEqual(step.action, bootstrap.CREATE)
            method, path, body = step.writes[0]
            self.assertEqual(method, "PUT")
            self.assertTrue(path.startswith(f"repos/{REPO}/environments/"))
            self.assertTrue(body["prevent_self_review"])
            self.assertEqual(body["reviewers"], [{"type": "User", "id": REVIEWER_ID}])
            self.assertEqual(
                body["deployment_branch_policy"],
                {"protected_branches": True, "custom_branch_policies": False},
            )

    def test_an_environment_without_a_reviewer_is_blocked_not_silently_created(self):
        api = FakeApi(configured_responses())
        plan = bootstrap.build_plan(api, namespace(environment=["production"]))
        step = next(step for step in plan.steps if step.target == "environment production")
        self.assertEqual(step.action, bootstrap.BLOCKED)
        self.assertIn("--reviewer", step.summary)
        self.assertEqual(step.writes, [])
        self.assertTrue(plan.blocked)

    def test_existing_reviewers_survive_a_run_that_names_none(self):
        api = FakeApi(configured_responses(environments=("production",)))
        plan = bootstrap.build_plan(api, namespace(environment=["production"]))
        step = next(step for step in plan.steps if step.target == "environment production")
        self.assertEqual(step.action, bootstrap.UNCHANGED)

    def test_a_self_reviewable_or_unrestricted_environment_is_updated(self):
        responses = configured_responses(environments=("production",))
        detail = responses[f"repos/{REPO}/environments/production"]
        detail["protection_rules"][0]["prevent_self_review"] = False
        detail["deployment_branch_policy"] = {
            "protected_branches": False,
            "custom_branch_policies": True,
        }
        api = FakeApi(responses)
        plan = bootstrap.build_plan(
            api, namespace(environment=["production"], reviewer=["octocat"])
        )
        step = next(step for step in plan.steps if step.target == "environment production")
        self.assertEqual(step.action, bootstrap.UPDATE)
        joined = "\n".join(step.details)
        self.assertIn("prevent_self_review: false -> true", joined)
        self.assertIn("deployment_branch_policy.protected_branches: false -> true", joined)

    def test_no_environments_resolved_is_reported_as_a_note(self):
        api = FakeApi(configured_responses())
        plan = bootstrap.build_plan(api, namespace())
        self.assertTrue(
            any("No environments were resolved" in note for note in plan.notes),
            plan.notes,
        )


class AuditTokenEnvironmentTests(unittest.TestCase):
    """`SETTINGS_AUDIT_TOKEN` is fenced by an environment, not a repo secret."""

    def audit_step(self, plan):
        return next(
            step
            for step in plan.steps
            if step.target == f"environment {bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"
        )

    def test_an_unconfigured_repository_creates_it_with_a_branch_policy(self):
        api = FakeApi({f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]})
        step = self.audit_step(bootstrap.build_plan(api, namespace()))
        self.assertEqual(step.action, bootstrap.CREATE)
        method, path, body = step.writes[0]
        self.assertEqual(method, "PUT")
        self.assertEqual(
            path,
            f"repos/{REPO}/environments/{bootstrap.SETTINGS_AUDIT_ENVIRONMENT}",
        )
        self.assertEqual(body["reviewers"], [])
        self.assertEqual(
            body["deployment_branch_policy"],
            {"protected_branches": True, "custom_branch_policies": False},
        )

    def test_a_template_repository_gets_it_too(self):
        api = FakeApi({f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]})
        plan = bootstrap.build_plan(
            api, namespace(state_writer_app_id=None, template_repo=True)
        )
        self.assertEqual(self.audit_step(plan).action, bootstrap.CREATE)

    def test_an_unrestricted_audit_environment_is_updated(self):
        responses = configured_responses()
        responses[
            f"repos/{REPO}/environments/{bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"
        ]["deployment_branch_policy"] = {
            "protected_branches": False,
            "custom_branch_policies": True,
        }
        step = self.audit_step(bootstrap.build_plan(FakeApi(responses), namespace()))
        self.assertEqual(step.action, bootstrap.UPDATE)
        self.assertIn(
            "deployment_branch_policy.protected_branches: false -> true",
            "\n".join(step.details),
        )

    def test_a_reviewer_on_the_audit_environment_is_reported_and_removed(self):
        # A reviewer here holds every scheduled audit in "waiting for approval",
        # which is the silently-stopped audit the schedule exists to avoid.
        responses = configured_responses()
        responses[
            f"repos/{REPO}/environments/{bootstrap.SETTINGS_AUDIT_ENVIRONMENT}"
        ]["protection_rules"] = [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"id": REVIEWER_ID, "login": "octocat"}}
                ],
            }
        ]
        step = self.audit_step(bootstrap.build_plan(FakeApi(responses), namespace()))
        self.assertEqual(step.action, bootstrap.UPDATE)
        self.assertIn("reviewers: 1 -> 0", "\n".join(step.details))
        self.assertEqual(step.writes[0][2]["reviewers"], [])

    def test_a_colliding_deployment_environment_name_is_warned_about(self):
        api = FakeApi(configured_responses())
        plan = bootstrap.build_plan(
            api,
            namespace(
                environment=[bootstrap.SETTINGS_AUDIT_ENVIRONMENT],
                reviewer=["octocat"],
            ),
        )
        self.assertTrue(
            any("collides" in warning for warning in plan.warnings), plan.warnings
        )

    def test_the_audit_environment_name_is_shared_with_the_auditor(self):
        self.assertEqual(
            bootstrap.SETTINGS_AUDIT_ENVIRONMENT,
            audit_settings.SETTINGS_AUDIT_ENVIRONMENT,
        )


class WriteGuardTests(unittest.TestCase):
    def test_planning_alone_never_writes(self):
        api = FakeApi({f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]})
        bootstrap.build_plan(api, namespace())
        self.assertEqual(api.writes, [])

    def test_main_without_apply_performs_no_write(self):
        api = FakeApi({f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]})
        original = bootstrap.GitHubApi
        buffer = io.StringIO()
        try:
            bootstrap.GitHubApi = lambda **_: api
            with patch.dict("os.environ", {"GH_TOKEN": "x"}):
                with contextlib.redirect_stdout(buffer):
                    code = bootstrap.main(["--repo", REPO])
        finally:
            bootstrap.GitHubApi = original
        self.assertEqual(code, 0)
        self.assertEqual(api.writes, [])
        self.assertIn("(dry run)", buffer.getvalue())

    def test_a_dry_run_client_refuses_to_execute_writes(self):
        api = FakeApi(
            {f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]}
        )
        plan = bootstrap.build_plan(api, namespace())
        with self.assertRaises(ValueError):
            bootstrap.execute(api, plan)
        self.assertEqual(api.writes, [])

    def test_apply_executes_exactly_the_planned_writes(self):
        api = FakeApi(
            {f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]},
            dry_run=False,
        )
        plan = bootstrap.build_plan(api, namespace(apply=True))
        expected = [write for step in plan.steps for write in step.writes]
        bootstrap.execute(api, plan)
        self.assertEqual(api.writes, expected)
        self.assertTrue(api.writes)
        self.assertNotIn(bootstrap.FAILED, {step.action for step in plan.steps})

    def test_unchanged_steps_contribute_no_write_on_apply(self):
        api = FakeApi(configured_responses(), dry_run=False)
        plan = bootstrap.build_plan(api, namespace(apply=True))
        bootstrap.execute(api, plan)
        self.assertEqual(api.writes, [])

    def test_a_failed_write_is_reported_and_exits_non_zero(self):
        api = FakeApi(
            {f"repos/{REPO}": {}, f"repos/{REPO}/rulesets?per_page=100": [[]]},
            dry_run=False,
        )

        def refuse(method, path, body=None):
            raise bootstrap.ApiError(403, "gh: Forbidden (HTTP 403)")

        api.write = refuse
        plan = bootstrap.build_plan(api, namespace(apply=True))
        bootstrap.execute(api, plan)
        self.assertTrue(plan.blocked)
        self.assertTrue(
            any("HTTP 403" in line for step in plan.steps for line in step.details)
        )

    def test_a_malformed_repository_name_is_refused_before_any_call(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = bootstrap.main(["--repo", "not-a-repo"])
        self.assertEqual(code, 1)
        self.assertIn("owner/name", buffer.getvalue())


class SharedConstantTests(unittest.TestCase):
    def test_the_baseline_is_imported_from_the_auditor(self):
        import audit_settings

        self.assertIs(
            bootstrap.ALLOWED_ACTION_PATTERNS, audit_settings.ALLOWED_ACTION_PATTERNS
        )
        self.assertIs(
            bootstrap.REQUIRED_STATUS_CHECKS, audit_settings.REQUIRED_STATUS_CHECKS
        )
        self.assertIs(bootstrap.RELEASE_TAG_PATTERN, audit_settings.RELEASE_TAG_PATTERN)

    def test_the_ruleset_it_writes_satisfies_the_audit_it_ships_with(self):
        import audit_settings

        ruleset = bootstrap.main_ruleset_body(
            [{"actor_type": "Integration", "actor_id": APP_ID, "bypass_mode": "always"}]
        )
        audit = audit_settings.Audit()
        audit_settings.audit_main_ruleset(
            audit, ruleset, set(audit_settings.REQUIRED_STATUS_CHECKS), APP_ID
        )
        self.assertEqual(audit.violations, [])
        self.assertTrue(audit_settings.ruleset_targets_branch(ruleset, "main"))

        tag = bootstrap.release_tag_ruleset_body(
            [{"actor_type": "Integration", "actor_id": 1234, "bypass_mode": "always"}]
        )
        audit = audit_settings.Audit()
        audit_settings.audit_tag_ruleset(audit, tag)
        self.assertEqual(audit.violations, [])
        self.assertTrue(
            audit_settings.ruleset_targets_release_tags(
                tag, audit_settings.RELEASE_TAG_PATTERN
            )
        )


if __name__ == "__main__":
    unittest.main()
