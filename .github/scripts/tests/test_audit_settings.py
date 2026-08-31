import importlib.util
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
            {"total_count": 1, "environments": [{"name": "production"}]}
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


if __name__ == "__main__":
    unittest.main()
