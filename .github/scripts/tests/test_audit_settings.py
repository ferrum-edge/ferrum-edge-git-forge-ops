import importlib.util
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "audit_settings.py"
SPEC = importlib.util.spec_from_file_location("audit_settings", SCRIPT)
assert SPEC and SPEC.loader
audit_settings = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit_settings
SPEC.loader.exec_module(audit_settings)

REQUIRED_CHECKS = {
    "rust-ci-check",
    "security-cargo-audit",
    "security-supply-chain-policy",
    "state-guard-reject-state-edits",
    "gitforgeops-required-static-validation",
}


def secure_responses():
    return {
        "repos/acme/repo/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        "repos/acme/repo/actions/permissions": {
            "allowed_actions": "selected",
            "sha_pinning_required": True,
        },
        "repos/acme/repo/actions/permissions/selected-actions": {
            "github_owned_allowed": True,
            "verified_allowed": False,
            "patterns_allowed": sorted(audit_settings.ALLOWED_ACTION_PATTERNS),
        },
        "repos/acme/repo/rulesets?per_page=100": [[{"id": 7}, {"id": 8}]],
        "repos/acme/repo/rulesets/7": {
            "id": 7,
            "name": "protect main",
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "bypass_actors": [
                {"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"}
            ],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 1,
                        "require_code_owner_review": True,
                        "required_review_thread_resolution": True,
                        "dismiss_stale_reviews_on_push": True,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {"context": context} for context in sorted(REQUIRED_CHECKS)
                        ]
                    },
                },
            ],
        },
        "repos/acme/repo/rulesets/8": {
            "id": 8,
            "name": "protect releases",
            "target": "tag",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "bypass_actors": [
                {"actor_type": "Team", "actor_id": 42, "bypass_mode": "always"}
            ],
            "rules": [
                {"type": "creation"},
                {"type": "update"},
                {"type": "deletion"},
            ],
        },
        "repos/acme/repo/environments?per_page=100": [
            {
                "total_count": 2,
                "environments": [
                    {"name": "production"},
                    {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT},
                ],
            }
        ],
        "repos/acme/repo/environments/production": {
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": {"login": "maintainer"}}],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        },
        # Fences the administration-read audit token to the protected branch.
        # No reviewer: it deploys nothing, and one would stall every scheduled
        # run in "waiting for approval".
        f"repos/acme/repo/environments/{audit_settings.SETTINGS_AUDIT_ENVIRONMENT}": {
            "protection_rules": [],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        },
    }


class SettingsAuditTests(unittest.TestCase):
    def test_secure_baseline_passes(self):
        responses = secure_responses()
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        self.assertEqual(audit.violations, [])

    def test_insecure_actions_and_human_bypass_fail(self):
        responses = secure_responses()
        responses["repos/acme/repo/actions/permissions/workflow"] = {
            "default_workflow_permissions": "write",
            "can_approve_pull_request_reviews": True,
        }
        responses["repos/acme/repo/actions/permissions"] = {
            "allowed_actions": "all",
            "sha_pinning_required": False,
        }
        responses["repos/acme/repo/rulesets/7"]["bypass_actors"] = [
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"}
        ]
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        rendered = "\n".join(audit.violations)
        self.assertIn("default GITHUB_TOKEN", rendered)
        self.assertIn("approve pull requests", rendered)
        self.assertIn("allowed Actions policy", rendered)
        self.assertIn("full-SHA pinning", rendered)
        self.assertIn("configured state-writer App", rendered)

    def test_any_additional_main_bypass_mode_fails(self):
        responses = secure_responses()
        responses["repos/acme/repo/rulesets/7"]["bypass_actors"].append(
            {"actor_type": "Team", "actor_id": 42, "bypass_mode": "pull_request"}
        )
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        self.assertTrue(
            any("exactly one bypass actor in any mode" in item for item in audit.violations),
            audit.violations,
        )

    def test_broad_or_excluded_ruleset_targets_fail_closed(self):
        for target, include, exclude in (
            ("branch", ["~DEFAULT_BRANCH", "refs/heads/feature/*"], []),
            ("branch", ["~DEFAULT_BRANCH"], ["refs/heads/ma*"]),
            ("tag", ["refs/tags/v*", "refs/tags/release-*"], []),
            ("tag", ["refs/tags/v*"], ["refs/tags/v1.*"]),
        ):
            with self.subTest(target=target, include=include, exclude=exclude):
                responses = secure_responses()
                ruleset_id = "7" if target == "branch" else "8"
                responses[f"repos/acme/repo/rulesets/{ruleset_id}"]["conditions"][
                    "ref_name"
                ] = {"include": include, "exclude": exclude}
                with patch.object(
                    audit_settings,
                    "gh_json",
                    side_effect=lambda path, paginate=False: responses[path],
                ):
                    audit = audit_settings.run(
                        "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
                    )
                self.assertTrue(
                    any("expected exactly one active ruleset" in item for item in audit.violations),
                    audit.violations,
                )

    def test_missing_environment_controls_fail(self):
        responses = secure_responses()
        responses["repos/acme/repo/environments/production"] = {
            "protection_rules": [],
            "deployment_branch_policy": None,
        }
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        rendered = "\n".join(audit.violations)
        self.assertIn("require at least one reviewer", rendered)
        self.assertIn("prevent self-review", rendered)
        self.assertIn("restrict deployments", rendered)

    def test_custom_environment_policy_must_name_only_default_branch(self):
        for policy_names in (["main", "feature/*"], ["feature/*"]):
            with self.subTest(policy_names=policy_names):
                responses = secure_responses()
                responses["repos/acme/repo/environments/production"][
                    "deployment_branch_policy"
                ] = {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                }
                responses[
                    "repos/acme/repo/environments/production/deployment-branch-policies?per_page=100"
                ] = [
                    {
                        "branch_policies": [
                            {"name": name} for name in policy_names
                        ]
                    }
                ]
                with patch.object(
                    audit_settings,
                    "gh_json",
                    side_effect=lambda path, paginate=False: responses[path],
                ):
                    audit = audit_settings.run(
                        "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
                    )
                self.assertTrue(
                    any("restrict deployments" in item for item in audit.violations),
                    audit.violations,
                )

        responses = secure_responses()
        responses["repos/acme/repo/environments/production"][
            "deployment_branch_policy"
        ] = {"protected_branches": False, "custom_branch_policies": True}
        responses[
            "repos/acme/repo/environments/production/deployment-branch-policies?per_page=100"
        ] = [{"branch_policies": [{"name": "main"}]}]
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        self.assertEqual(audit.violations, [])

    def test_wrong_state_app_and_missing_tag_rule_fail(self):
        responses = secure_responses()
        responses["repos/acme/repo/rulesets/7"]["bypass_actors"][0]["actor_id"] = 100
        responses["repos/acme/repo/rulesets/8"]["rules"] = [
            {"type": "creation"},
            {"type": "deletion"},
        ]
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        rendered = "\n".join(audit.violations)
        self.assertIn("configured state-writer App", rendered)
        self.assertIn("missing required rule: update", rendered)

    def test_stale_reviews_loose_checks_and_broad_tag_bypass_fail(self):
        responses = secure_responses()
        main_rules = responses["repos/acme/repo/rulesets/7"]["rules"]
        next(
            rule for rule in main_rules if rule["type"] == "pull_request"
        )["parameters"]["dismiss_stale_reviews_on_push"] = False
        next(
            rule for rule in main_rules if rule["type"] == "required_status_checks"
        )["parameters"]["strict_required_status_checks_policy"] = False
        responses["repos/acme/repo/rulesets/8"]["bypass_actors"] = [
            {
                "actor_type": "RepositoryRole",
                "actor_id": 5,
                "bypass_mode": "always",
            }
        ]
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        rendered = "\n".join(audit.violations)
        self.assertIn("dismiss stale approvals", rendered)
        self.assertIn("latest main commit", rendered)
        self.assertIn("broad repository roles", rendered)

    def test_tag_ruleset_without_a_bypass_actor_fails(self):
        # `creation` with an empty bypass list means nobody can push a `v*`
        # tag, so release.yml's tag trigger can never fire. The doc
        # (docs/github-launch-controls.md section 2) states the same rule; keep
        # the two aligned.
        responses = secure_responses()
        responses["repos/acme/repo/rulesets/8"]["bypass_actors"] = []
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        rendered = "\n".join(audit.violations)
        self.assertIn("at least one bypass actor", rendered)
        # An empty list is vacuously "narrow", so only the new rule fires.
        self.assertNotIn("broad repository roles", rendered)

    def test_broad_verified_action_policy_and_extra_pattern_fail(self):
        responses = secure_responses()
        selected = responses[
            "repos/acme/repo/actions/permissions/selected-actions"
        ]
        selected["verified_allowed"] = True
        selected["patterns_allowed"].append("unreviewed/*")
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        rendered = "\n".join(audit.violations)
        self.assertIn("verified Marketplace", rendered)
        self.assertIn("exactly match", rendered)


class AuditTokenEnvironmentTests(unittest.TestCase):
    """`settings-audit` fences a read-only token; it is not a deployment target."""

    def run_audit(self, responses):
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            return audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )

    def test_a_reviewerless_audit_environment_passes(self):
        audit = self.run_audit(secure_responses())
        self.assertEqual(audit.violations, [])
        rendered = "\n".join(audit.evidence)
        self.assertIn("reviewer rules waived", rendered)

    def test_a_missing_audit_environment_fails(self):
        responses = secure_responses()
        responses["repos/acme/repo/environments?per_page=100"] = [
            {"total_count": 1, "environments": [{"name": "production"}]}
        ]
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                audit_settings.SETTINGS_AUDIT_ENVIRONMENT in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_the_audit_environment_still_needs_a_branch_policy(self):
        # The branch restriction is the entire reason the token moved here:
        # without it a dispatch from any ref would receive it again.
        responses = secure_responses()
        responses[
            f"repos/acme/repo/environments/{audit_settings.SETTINGS_AUDIT_ENVIRONMENT}"
        ] = {"protection_rules": [], "deployment_branch_policy": None}
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "restrict deployments" in item
                and audit_settings.SETTINGS_AUDIT_ENVIRONMENT in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_the_audit_environment_alone_is_not_a_deployment_environment(self):
        responses = secure_responses()
        responses["repos/acme/repo/environments?per_page=100"] = [
            {
                "total_count": 1,
                "environments": [
                    {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT}
                ],
            }
        ]
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "at least one protected environment" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_the_workflow_binds_the_environment_it_audits(self):
        workflow = (
            Path(__file__).parents[2] / "workflows" / "settings-audit.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"    environment: {audit_settings.SETTINGS_AUDIT_ENVIRONMENT}\n", workflow
        )


class TemplateRepositoryAuditTests(unittest.TestCase):
    """The upstream template has no state-writer App and no environments."""

    def template_responses(self):
        responses = secure_responses()
        # Solo-maintainer template: the admin role holds a pull-request-mode
        # bypass and there is no App to name.
        responses["repos/acme/repo/rulesets/7"]["bypass_actors"] = [
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "pull_request"}
        ]
        # A template has no deployment environment, but it still runs the
        # settings audit, so it still needs the audit-token environment.
        responses["repos/acme/repo/environments?per_page=100"] = [
            {
                "total_count": 1,
                "environments": [
                    {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT}
                ],
            }
        ]
        return responses

    def run_audit(self, responses, *, template_repo):
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            return audit_settings.run(
                "acme/repo",
                "main",
                REQUIRED_CHECKS,
                None if template_repo else 99,
                "refs/tags/v*",
                template_repo,
            )

    def test_template_mode_skips_bypass_and_environment_requirements(self):
        audit = self.run_audit(self.template_responses(), template_repo=True)
        self.assertEqual(audit.violations, [])
        rendered = "\n".join(audit.evidence)
        self.assertIn("state-writer App bypass", rendered)
        self.assertIn("protected-environment", rendered)

    def test_the_same_repository_fails_without_template_mode(self):
        audit = self.run_audit(self.template_responses(), template_repo=False)
        rendered = "\n".join(audit.violations)
        self.assertIn("configured state-writer App", rendered)
        self.assertIn("always mode", rendered)
        self.assertIn("at least one protected environment", rendered)

    def test_template_mode_still_audits_everything_else(self):
        responses = self.template_responses()
        responses["repos/acme/repo/actions/permissions"]["sha_pinning_required"] = False
        responses["repos/acme/repo/rulesets/8"]["bypass_actors"] = []
        next(
            rule
            for rule in responses["repos/acme/repo/rulesets/7"]["rules"]
            if rule["type"] == "required_status_checks"
        )["parameters"]["required_status_checks"] = [{"context": "rust-ci-check"}]
        audit = self.run_audit(responses, template_repo=True)
        rendered = "\n".join(audit.violations)
        self.assertIn("full-SHA pinning", rendered)
        self.assertIn("at least one bypass actor", rendered)
        self.assertIn("missing required status checks", rendered)

    def test_template_mode_still_audits_a_listed_environment(self):
        responses = self.template_responses()
        responses["repos/acme/repo/environments?per_page=100"] = [
            {
                "total_count": 2,
                "environments": [
                    {"name": "production"},
                    {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT},
                ],
            }
        ]
        responses["repos/acme/repo/environments/production"] = {
            "protection_rules": [],
            "deployment_branch_policy": None,
        }
        audit = self.run_audit(responses, template_repo=True)
        rendered = "\n".join(audit.violations)
        self.assertIn("require at least one reviewer", rendered)
        self.assertIn("prevent self-review", rendered)

    def test_template_mode_still_requires_the_audit_token_environment(self):
        # A template runs settings-audit.yml too, so the environment that
        # fences its administration-read token is not optional there.
        responses = self.template_responses()
        responses["repos/acme/repo/environments?per_page=100"] = [
            {"total_count": 0, "environments": []}
        ]
        audit = self.run_audit(responses, template_repo=True)
        self.assertTrue(
            any(
                audit_settings.SETTINGS_AUDIT_ENVIRONMENT in item
                for item in audit.violations
            ),
            audit.violations,
        )


class SharedConstantTests(unittest.TestCase):
    def test_required_status_checks_match_the_settings_audit_workflow(self):
        workflow = (
            Path(__file__).resolve().parents[3]
            / ".github"
            / "workflows"
            / "settings-audit.yml"
        ).read_text(encoding="utf-8")
        declared = set(
            re.findall(r"--required-check '([^']+)'", workflow)
        )
        self.assertEqual(declared, set(audit_settings.REQUIRED_STATUS_CHECKS))

    def test_release_tag_pattern_is_the_documented_default(self):
        self.assertEqual(audit_settings.RELEASE_TAG_PATTERN, "refs/tags/v*")


if __name__ == "__main__":
    unittest.main()
