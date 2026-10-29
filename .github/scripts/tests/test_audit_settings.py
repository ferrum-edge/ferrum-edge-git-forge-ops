import importlib.util
import re
import sys
import unittest
from datetime import datetime, timezone
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
        "repos/acme/repo/rulesets?per_page=100": [[{"id": 7}, {"id": 8}, {"id": 9}]],
        # The organization ruleset behind the `workflows` rule (#470). The
        # repository listing includes it; its bypass mirrors ruleset 7's.
        "repos/acme/repo/rulesets/9": {
            "id": 9,
            "name": "trusted required workflows",
            "source_type": "Organization",
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "bypass_actors": [
                {"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"}
            ],
            "rules": [{"type": "workflows", "parameters": {"workflows": []}}],
        },
        "repos/acme/repo/rulesets/7": {
            "id": 7,
            "name": "protect main",
            "source_type": "Repository",
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
                        "required_approving_review_count": 0,
                        "require_code_owner_review": False,
                        "required_review_thread_resolution": True,
                        "dismiss_stale_reviews_on_push": True,
                    },
                },
                {
                    "type": "commit_message_pattern",
                    "parameters": {
                        "name": "no skip-ci on main",
                        "operator": "contains",
                        "pattern": "[skip ci]",
                        "negate": True,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": False,
                        "required_status_checks": [
                            {
                                "context": context,
                                "integration_id": audit_settings.GITHUB_ACTIONS_APP_ID,
                            }
                            for context in sorted(REQUIRED_CHECKS)
                        ]
                    },
                },
            ],
        },
        "repos/acme/repo/rulesets/8": {
            "id": 8,
            "name": "protect releases",
            "source_type": "Repository",
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
        "repos/acme/repo": {"id": 1234, "owner": {"type": "Organization"}},
        # Effective rules for `main`, organization rulesets included (#470).
        "repos/acme/repo/rules/branches/main?per_page=100": [
            [
                {
                    "type": "workflows",
                    "ruleset_source_type": "Organization",
                    "ruleset_id": 9,
                    "parameters": {
                        "do_not_enforce_on_create": False,
                        "workflows": [
                            {
                                "repository_id": 1234,
                                "path": path,
                                "ref": "refs/heads/main",
                            }
                            for path in audit_settings.REQUIRED_RULESET_WORKFLOWS
                        ],
                    },
                }
            ]
        ],
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

    def test_reintroduced_approval_requirements_are_reported_as_drift(self):
        for field, value, diagnostic in (
            ("required_approving_review_count", 1, "approval submissions"),
            ("require_code_owner_review", True, "Code Owner approval"),
            ("require_last_push_approval", True, "require_last_push_approval"),
            (
                "require_extra_approval_for_unattributed_changes",
                True,
                "require_extra_approval_for_unattributed_changes",
            ),
        ):
            with self.subTest(field=field):
                responses = secure_responses()
                rules = responses["repos/acme/repo/rulesets/7"]["rules"]
                next(rule for rule in rules if rule["type"] == "pull_request")[
                    "parameters"
                ][field] = value
                with patch.object(
                    audit_settings,
                    "gh_json",
                    side_effect=lambda path, paginate=False: responses[path],
                ):
                    audit = audit_settings.run(
                        "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
                    )
                self.assertTrue(
                    any(diagnostic in item for item in audit.violations),
                    audit.violations,
                )

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

    def test_up_to_date_branch_requirement_is_accepted_either_way(self):
        for strict in (True, False):
            responses = secure_responses()
            next(
                rule
                for rule in responses["repos/acme/repo/rulesets/7"]["rules"]
                if rule["type"] == "required_status_checks"
            )["parameters"]["strict_required_status_checks_policy"] = strict
            with patch.object(
                audit_settings,
                "gh_json",
                side_effect=lambda path, paginate=False: responses[path],
            ):
                audit = audit_settings.run(
                    "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
                )
            self.assertEqual(audit.violations, [], (strict, audit.violations))

    def test_stale_reviews_and_broad_tag_bypass_fail(self):
        responses = secure_responses()
        main_rules = responses["repos/acme/repo/rulesets/7"]["rules"]
        next(
            rule for rule in main_rules if rule["type"] == "pull_request"
        )["parameters"]["dismiss_stale_reviews_on_push"] = False
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


def monitoring_responses():
    """`production` opted into unattended monitoring."""
    responses = secure_responses()
    responses["repos/acme/repo/environments?per_page=100"] = [
        {
            "total_count": 3,
            "environments": [
                {"name": "production"},
                {"name": "production-monitor"},
                {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT},
            ],
        }
    ]
    responses["repos/acme/repo/environments/production-monitor"] = {
        "protection_rules": [],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }
    responses[
        "repos/acme/repo/environments/production-monitor/deployment-branch-policies?per_page=100"
    ] = [{"branch_policies": [{"id": 17, "name": "main", "type": "branch"}]}]
    responses["repos/acme/repo/environments/production-monitor/secrets?per_page=100"] = [
        {
            "total_count": 2,
            "secrets": [
                {"name": "FERRUM_GATEWAY_URL"},
                {"name": "FERRUM_ADMIN_JWT_VIEWER_SECRET"},
            ],
        }
    ]
    responses[
        "repos/acme/repo/actions/workflows/drift-check.yml/runs?status=success&per_page=1"
    ] = {"workflow_runs": [{"updated_at": "2026-09-21T05:00:00Z"}]}
    return responses


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


class MonitoringEnvironmentTests(unittest.TestCase):
    """The narrow reviewer waiver for read-only drift monitoring."""

    def run_audit(self, responses, now=NOW, max_age_hours=None):
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            return audit_settings.run(
                "acme/repo",
                "main",
                REQUIRED_CHECKS,
                99,
                "refs/tags/v*",
                False,
                max_age_hours or audit_settings.MONITORING_MAX_AGE_HOURS,
                now,
            )

    def test_a_reviewerless_monitoring_environment_passes(self):
        audit = self.run_audit(monitoring_responses())
        self.assertEqual(audit.violations, [])
        rendered = "\n".join(audit.evidence)
        self.assertIn("read-only drift monitoring for 'production'", rendered)
        self.assertIn("holds no deployment/broker/state secret", rendered)

    def test_the_waiver_needs_a_real_deployment_environment_behind_it(self):
        # `anything-monitor` with no `anything` would be a way to mint an
        # unreviewed environment by naming it.
        responses = secure_responses()
        responses["repos/acme/repo/environments?per_page=100"] = [
            {
                "total_count": 3,
                "environments": [
                    {"name": "production"},
                    {"name": "ghost-monitor"},
                    {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT},
                ],
            }
        ]
        responses["repos/acme/repo/environments/ghost-monitor"] = {
            "protection_rules": [],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "'ghost-monitor' must require at least one reviewer" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_monitoring_may_not_hold_deployment_broker_or_state_secrets(self):
        for secret in (
            "FERRUM_ADMIN_JWT_SECRET",
            "GITFORGEOPS_STATE_APP_PRIVATE_KEY",
            "FERRUM_GH_PROVISIONER_TOKEN",
            "SETTINGS_AUDIT_TOKEN",
            "FERRUM_CREDS_BUNDLE",
            "FERRUM_CREDS_BUNDLE_3",
        ):
            with self.subTest(secret=secret):
                responses = monitoring_responses()
                responses[
                    "repos/acme/repo/environments/production-monitor/secrets?per_page=100"
                ] = [
                    {
                        "total_count": 1,
                        "secrets": [
                            {"name": "FERRUM_GATEWAY_URL"},
                            {"name": secret},
                        ],
                    }
                ]
                audit = self.run_audit(responses)
                self.assertTrue(
                    any(
                        "must not hold deployment, credential-broker" in item
                        and secret in item
                        for item in audit.violations
                    ),
                    audit.violations,
                )

    def _with_monitoring_secrets(self, *names):
        responses = monitoring_responses()
        responses[
            "repos/acme/repo/environments/production-monitor/secrets?per_page=100"
        ] = [
            {
                "total_count": len(names),
                "secrets": [{"name": name} for name in names],
            }
        ]
        return responses

    def test_monitoring_may_hold_the_viewer_capped_key(self):
        self.assertNotIn(
            audit_settings.MONITORING_VIEWER_JWT_SECRET,
            audit_settings.MONITORING_FORBIDDEN_SECRETS,
        )
        self.assertFalse(
            audit_settings.MONITORING_VIEWER_JWT_SECRET.startswith(
                audit_settings.MONITORING_FORBIDDEN_SECRET_PREFIXES
            )
        )
        audit = self.run_audit(
            self._with_monitoring_secrets(
                "FERRUM_GATEWAY_URL", "FERRUM_ADMIN_JWT_VIEWER_SECRET"
            )
        )
        self.assertEqual(audit.violations, [])
        self.assertEqual(audit.warnings, [])
        self.assertIn(
            "environment production-monitor: holds the viewer-capped "
            "FERRUM_ADMIN_JWT_VIEWER_SECRET",
            audit.evidence,
        )

    def test_monitoring_requires_the_viewer_key_name(self):
        for names in ((), ("FERRUM_GATEWAY_URL",), ("FERRUM_ADMIN_JWT_SECRET",)):
            with self.subTest(names=names):
                audit = self.run_audit(self._with_monitoring_secrets(*names))
                self.assertTrue(
                    any("must hold FERRUM_ADMIN_JWT_VIEWER_SECRET" in item for item in audit.violations),
                    audit.violations,
                )

    def test_monitoring_holding_both_keys_is_a_violation(self):
        audit = self.run_audit(
            self._with_monitoring_secrets(
                "FERRUM_GATEWAY_URL",
                "FERRUM_ADMIN_JWT_SECRET",
                "FERRUM_ADMIN_JWT_VIEWER_SECRET",
            )
        )
        self.assertTrue(
            any("must not hold" in item and "FERRUM_ADMIN_JWT_SECRET" in item for item in audit.violations),
            audit.violations,
        )
        self.assertEqual(audit.warnings, [])

    def test_monitoring_still_needs_its_branch_policy(self):
        responses = monitoring_responses()
        responses["repos/acme/repo/environments/production-monitor"] = {
            "protection_rules": [],
            "deployment_branch_policy": None,
        }
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "restrict deployments" in item and "production-monitor" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_monitoring_rejects_generic_protected_branches(self):
        responses = monitoring_responses()
        responses["repos/acme/repo/environments/production-monitor"] = {
            "protection_rules": [],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "production-monitor" in item and "exact 'main'" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_a_monitoring_environment_is_not_a_deployment_environment(self):
        # An orphaned `*-monitor` is neither waived nor counted: it loses the
        # reviewer waiver (its base does not exist) and it cannot stand in for
        # the protected deployment environment the baseline requires.
        self.assertFalse(
            audit_settings.is_monitoring_environment(
                "production-monitor", {"production-monitor", "settings-audit"}
            )
        )
        self.assertTrue(
            audit_settings.is_monitoring_environment(
                "production-monitor", {"production", "production-monitor"}
            )
        )
        responses = secure_responses()
        responses["repos/acme/repo/environments?per_page=100"] = [
            {
                "total_count": 2,
                "environments": [
                    {"name": "production-monitor"},
                    {"name": audit_settings.SETTINGS_AUDIT_ENVIRONMENT},
                ],
            }
        ]
        responses["repos/acme/repo/environments/production-monitor"] = {
            "protection_rules": [],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "'production-monitor' must require at least one reviewer" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_a_deployment_environment_still_needs_its_reviewer(self):
        responses = monitoring_responses()
        responses["repos/acme/repo/environments/production"] = {
            "protection_rules": [],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "'production' must require at least one reviewer" in item
                for item in audit.violations
            ),
            audit.violations,
        )


class MonitoringCoverageTests(unittest.TestCase):
    """A cron entry is not coverage; a completed run is."""

    def run_audit(self, responses, now=NOW):
        return MonitoringEnvironmentTests.run_audit(
            MonitoringEnvironmentTests(), responses, now
        )

    def test_a_recent_successful_run_is_the_evidence(self):
        audit = self.run_audit(monitoring_responses())
        self.assertEqual(audit.violations, [])
        self.assertTrue(
            any(
                "drift monitoring completed successfully 7h ago" in item
                for item in audit.evidence
            ),
            audit.evidence,
        )

    def test_a_schedule_that_stopped_running_fails(self):
        # GitHub disables scheduled workflows after 60 days of repository
        # inactivity, and the `cron:` line stays in the file either way.
        responses = monitoring_responses()
        responses[
            "repos/acme/repo/actions/workflows/drift-check.yml/runs?status=success&per_page=1"
        ] = {"workflow_runs": [{"updated_at": "2026-09-01T05:00:00Z"}]}
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "scheduled monitoring has stopped" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_a_workflow_that_never_succeeded_fails(self):
        responses = monitoring_responses()
        responses[
            "repos/acme/repo/actions/workflows/drift-check.yml/runs?status=success&per_page=1"
        ] = {"workflow_runs": []}
        audit = self.run_audit(responses)
        self.assertTrue(
            any(
                "has never completed successfully" in item
                for item in audit.violations
            ),
            audit.violations,
        )

    def test_an_unreadable_run_history_fails_closed(self):
        responses = monitoring_responses()
        key = (
            "repos/acme/repo/actions/workflows/drift-check.yml/runs"
            "?status=success&per_page=1"
        )

        def failing(path, paginate=False):
            if path == key:
                raise RuntimeError("403")
            return responses[path]

        with patch.object(audit_settings, "gh_json", side_effect=failing):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*",
                False, audit_settings.MONITORING_MAX_AGE_HOURS, NOW,
            )
        self.assertTrue(
            any("run history could not be read" in item for item in audit.violations),
            audit.violations,
        )

    def test_approval_gated_monitoring_claims_no_coverage(self):
        # No environment opted in, so there is nothing to have stopped — and
        # the evidence says plainly that monitoring waits for a reviewer.
        audit = self.run_audit(secure_responses())
        self.assertEqual(audit.violations, [])
        self.assertTrue(
            any(
                "drift monitoring is approval-gated" in item
                for item in audit.evidence
            ),
            audit.evidence,
        )


class TemplateRepositoryAuditTests(unittest.TestCase):
    """The upstream template has no state-writer App and no environments."""

    def template_responses(self):
        responses = secure_responses()
        # Solo-maintainer template: the admin role holds a pull-request-mode
        # bypass and there is no App to name.
        for ruleset in ("7", "9"):
            responses[f"repos/acme/repo/rulesets/{ruleset}"]["bypass_actors"] = [
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


class TrustedPolicyCheckTransitionTests(unittest.TestCase):
    """GHSA-x5m2-4555-q4cr: the protected-definition policy check is being added.

    `trusted-supply-chain-policy` joins the ruleset in an operator step after
    its workflow reaches the default branch, so the audit accepts a ruleset
    without it (with a warning) and still requires the in-tree job's context.
    """

    TRUSTED = "trusted-supply-chain-policy"
    AGENT_POLICY = "validate-trusted-policy"
    RETIRING = "security-supply-chain-policy"

    def audit_ruleset(
        self, contexts: set[str], unbound: frozenset[str] = frozenset()
    ) -> "audit_settings.Audit":
        ruleset = secure_responses()["repos/acme/repo/rulesets/7"]
        next(
            rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks"
        )["parameters"]["required_status_checks"] = [
            {"context": context}
            if context in unbound
            else {"context": context, "integration_id": audit_settings.GITHUB_ACTIONS_APP_ID}
            for context in sorted(contexts)
        ]
        audit = audit_settings.Audit()
        audit_settings.audit_main_ruleset(
            audit, ruleset, set(audit_settings.REQUIRED_STATUS_CHECKS), 99
        )
        return audit

    def test_the_skip_ci_commit_message_rule_is_required_unweakened(self):
        for mutate, label in (
            ("absent", "absent"),
            ("non-negated", "negate"),
            ("different-pattern", "pattern"),
        ):
            with self.subTest(mutate=mutate):
                ruleset = secure_responses()["repos/acme/repo/rulesets/7"]
                if mutate == "absent":
                    ruleset["rules"] = [
                        rule for rule in ruleset["rules"] if rule["type"] != "commit_message_pattern"
                    ]
                else:
                    params = next(
                        rule for rule in ruleset["rules"] if rule["type"] == "commit_message_pattern"
                    )["parameters"]
                    if mutate == "non-negated":
                        params["negate"] = False
                    else:
                        params["pattern"] = "[ci skip]"
                audit = audit_settings.Audit()
                audit_settings.audit_main_ruleset(
                    audit, ruleset, set(audit_settings.REQUIRED_STATUS_CHECKS), 99
                )
                rendered = "\n".join(audit.violations)
                self.assertIn("[skip ci]", rendered, label)

    def test_the_trusted_check_is_part_of_the_launch_baseline(self):
        self.assertIn(self.TRUSTED, audit_settings.REQUIRED_STATUS_CHECKS)
        self.assertIn(self.RETIRING, audit_settings.REQUIRED_STATUS_CHECKS)
        self.assertEqual(
            audit_settings.TRANSITIONAL_STATUS_CHECKS,
            (self.TRUSTED, "validate-trusted-policy"),
        )
        self.assertIn("validate-trusted-policy", audit_settings.REQUIRED_STATUS_CHECKS)
        self.assertIn("validate-trusted-policy", audit_settings.SOURCE_BOUND_STATUS_CHECKS)

    def test_a_ruleset_before_the_switch_passes_with_a_warning(self):
        audit = self.audit_ruleset(REQUIRED_CHECKS)
        self.assertEqual(audit.violations, [])
        self.assertEqual(len(audit.warnings), 2, audit.warnings)
        rendered = "\n".join(audit.warnings)
        self.assertIn(self.TRUSTED, rendered)
        self.assertIn(self.AGENT_POLICY, rendered)

    def test_a_ruleset_after_the_switch_passes_cleanly(self):
        audit = self.audit_ruleset(REQUIRED_CHECKS | {self.TRUSTED, self.AGENT_POLICY})
        self.assertEqual(audit.violations, [])
        self.assertEqual(audit.warnings, [])

    def test_the_retiring_context_is_still_required(self):
        # It still runs the workflow-script unit tests until the retire step.
        audit = self.audit_ruleset((REQUIRED_CHECKS - {self.RETIRING}) | {self.TRUSTED})
        rendered = "\n".join(audit.violations)
        self.assertIn("missing required status checks", rendered)
        self.assertIn(self.RETIRING, rendered)

    def test_the_trusted_check_must_be_bound_to_github_actions(self):
        # Unbound, a commit status a collaborator posts with their own token
        # satisfies the rule.
        for source in (None, 1):
            with self.subTest(source=source):
                ruleset = secure_responses()["repos/acme/repo/rulesets/7"]
                checks = [
                    {"context": context, "integration_id": audit_settings.GITHUB_ACTIONS_APP_ID}
                    for context in sorted(REQUIRED_CHECKS)
                ]
                checks.append(
                    {"context": self.TRUSTED}
                    if source is None
                    else {"context": self.TRUSTED, "integration_id": source}
                )
                next(
                    rule
                    for rule in ruleset["rules"]
                    if rule["type"] == "required_status_checks"
                )["parameters"]["required_status_checks"] = checks
                audit = audit_settings.Audit()
                audit_settings.audit_main_ruleset(
                    audit, ruleset, set(audit_settings.REQUIRED_STATUS_CHECKS), 99
                )
                rendered = "\n".join(audit.violations)
                self.assertIn("GitHub Actions app", rendered)
                self.assertIn(self.TRUSTED, rendered)

    def test_an_unbound_state_guard_fails_the_audit(self):
        # Its definition is protected too (pull_request_target), so an
        # own-token commit status is the only way to forge it.
        audit = self.audit_ruleset(
            REQUIRED_CHECKS | {self.TRUSTED, self.AGENT_POLICY},
            unbound=frozenset({"state-guard-reject-state-edits"}),
        )
        rendered = "\n".join(audit.violations)
        self.assertIn("'state-guard-reject-state-edits' to the GitHub Actions app", rendered)
        self.assertEqual(
            audit_settings.SOURCE_BOUND_STATUS_CHECKS,
            (
                "trusted-supply-chain-policy",
                "state-guard-reject-state-edits",
                "validate-trusted-policy",
            ),
        )

    def test_older_unbound_contexts_are_a_warning(self):
        audit = self.audit_ruleset(
            REQUIRED_CHECKS | {self.TRUSTED, self.AGENT_POLICY},
            unbound=frozenset({"rust-ci-check"}),
        )
        self.assertEqual(audit.violations, [])
        self.assertEqual(len(audit.warnings), 1, audit.warnings)
        self.assertIn("'rust-ci-check' from any source", audit.warnings[0])

    def test_only_the_transitional_context_is_softened(self):
        for context in sorted(REQUIRED_CHECKS):
            with self.subTest(context=context):
                audit = self.audit_ruleset(REQUIRED_CHECKS - {context})
                rendered = "\n".join(audit.violations)
                self.assertIn("missing required status checks", rendered)
                self.assertIn(context, rendered)


class RequiredWorkflowRuleTests(unittest.TestCase):
    """#470: the trusted policy must be required by workflow path, not name only."""

    RULES = "repos/acme/repo/rules/branches/main?per_page=100"

    def run_audit(self, responses):
        with patch.object(
            audit_settings,
            "gh_json",
            side_effect=lambda path, paginate=False: responses[path],
        ):
            return audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )

    def entries(self, responses):
        return responses[self.RULES][0][0]["parameters"]["workflows"]

    def test_every_required_check_workflow_is_a_required_workflow(self):
        # #632: a name-only context can be met by deleting its failing run and
        # posting a check, so every workflow that reports one is listed.
        spec = importlib.util.spec_from_file_location(
            "check_supply_chain_for_audit", SCRIPT.parent / "check_supply_chain.py"
        )
        assert spec and spec.loader
        check_supply_chain = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(check_supply_chain)

        self.assertEqual(
            sorted(audit_settings.REQUIRED_RULESET_WORKFLOWS),
            sorted(set(check_supply_chain.REQUIRED_CHECK_WORKFLOWS.values())),
        )
        self.assertEqual(
            len(set(audit_settings.REQUIRED_RULESET_WORKFLOWS)),
            len(audit_settings.REQUIRED_RULESET_WORKFLOWS),
        )
        for path in audit_settings.REQUIRED_RULESET_WORKFLOWS:
            self.assertTrue((Path(__file__).parents[3] / path).is_file(), path)

    def test_a_partial_rule_names_every_missing_workflow(self):
        responses = secure_responses()
        entries = self.entries(responses)
        del entries[1:3]
        audit = self.run_audit(responses)
        self.assertEqual(len(audit.violations), 1)
        self.assertIn("state-guard.yml", audit.violations[0])
        self.assertIn("agent-setup-policy.yml", audit.violations[0])
        self.assertNotIn("supply-chain-policy.yml", audit.violations[0])
        self.assertIn(
            "required workflow: .github/workflows/supply-chain-policy.yml "
            "at refs/heads/main",
            audit.evidence,
        )

    def test_the_organization_rule_is_evidence(self):
        audit = self.run_audit(secure_responses())
        self.assertEqual(audit.violations, [])
        self.assertIn(
            "required workflow: .github/workflows/supply-chain-policy.yml "
            "at refs/heads/main",
            audit.evidence,
        )

    def test_an_organization_ruleset_does_not_count_as_a_second_main_ruleset(self):
        # The repository listing includes parent rulesets by default; one that
        # targets `main` or the release tags must not trip the exactly-one
        # rules for the repository's own rulesets.
        responses = secure_responses()
        responses["repos/acme/repo/rulesets?per_page=100"] = [
            [{"id": 7}, {"id": 8}, {"id": 9}, {"id": 10}, {"id": 11}]
        ]
        for identifier, source in ((10, 7), (11, 8)):
            parent = dict(responses[f"repos/acme/repo/rulesets/{source}"])
            parent.update(id=identifier, source_type="Organization")
            responses[f"repos/acme/repo/rulesets/{identifier}"] = parent
        self.assertEqual(self.run_audit(responses).violations, [])

    def test_a_missing_rule_fails_an_organization_repository(self):
        responses = secure_responses()
        responses[self.RULES] = [[]]
        audit = self.run_audit(responses)
        self.assertEqual(len(audit.violations), 1)
        self.assertIn("supply-chain-policy.yml", audit.violations[0])
        self.assertIn("section 2a", audit.violations[0])

    def test_a_user_owned_repository_gets_a_residual_risk_warning(self):
        responses = secure_responses()
        responses[self.RULES] = [[]]
        responses["repos/acme/repo"]["owner"]["type"] = "User"
        audit = self.run_audit(responses)
        self.assertEqual(audit.violations, [])
        self.assertTrue(
            any("supply-chain-policy.yml" in warning for warning in audit.warnings)
        )

    def test_an_entry_must_name_this_repository_path_and_default_branch(self):
        for field, value in (
            ("repository_id", 4321),
            ("ref", "refs/heads/release"),
            ("path", ".github/workflows/security.yml"),
        ):
            with self.subTest(field=field):
                responses = secure_responses()
                self.entries(responses)[0][field] = value
                self.assertEqual(len(self.run_audit(responses).violations), 1)

    def bypass(self, responses, actors):
        responses["repos/acme/repo/rulesets/9"]["bypass_actors"] = actors

    def test_a_wider_bypass_on_the_organization_ruleset_does_not_count(self):
        for actors in (
            # The write role could skip the one rule a posted check cannot meet.
            [
                {"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"},
                {"actor_type": "RepositoryRole", "actor_id": 4, "bypass_mode": "pull_request"},
            ],
            # No state-writer App: ledger commits to `main` would be refused.
            [],
            # The App, but in another mode.
            [{"actor_type": "Integration", "actor_id": 99, "bypass_mode": "pull_request"}],
        ):
            with self.subTest(actors=actors):
                responses = secure_responses()
                self.bypass(responses, actors)
                audit = self.run_audit(responses)
                # The refused rule, then the requirement it no longer meets.
                self.assertEqual(len(audit.violations), 2)
                self.assertIn("bypass actors", audit.violations[0])
                self.assertIn("must require", audit.violations[1])

    def test_an_unreadable_defining_ruleset_does_not_count(self):
        for change in ("missing", "no-bypass-field"):
            with self.subTest(change=change):
                responses = secure_responses()
                if change == "missing":
                    responses["repos/acme/repo/rulesets?per_page=100"] = [
                        [{"id": 7}, {"id": 8}]
                    ]
                else:
                    del responses["repos/acme/repo/rulesets/9"]["bypass_actors"]
                audit = self.run_audit(responses)
                self.assertEqual(len(audit.violations), 2)
                self.assertIn("unreadable", audit.violations[0])
                self.assertIn("must require", audit.violations[1])

    def add_second_workflow_ruleset(self, responses, actors, paths):
        responses["repos/acme/repo/rulesets/12"] = dict(
            responses["repos/acme/repo/rulesets/9"], id=12, bypass_actors=actors
        )
        responses["repos/acme/repo/rulesets?per_page=100"][0].append({"id": 12})
        rule = {
            "type": "workflows",
            "ruleset_id": 12,
            "parameters": {
                "workflows": [
                    {"repository_id": 1234, "path": path, "ref": "refs/heads/main"}
                    for path in paths
                ]
            },
        }
        responses[self.RULES] = [responses[self.RULES][0] + [rule]]

    def test_every_effective_workflow_ruleset_must_mirror_the_main_bypass(self):
        # Rulesets apply together: a second rule without the state-writer App
        # bypass refuses ledger commits even though ruleset 9 admits the App,
        # and a wider one exempts actors from it. Either is a violation,
        # whatever workflow the second rule lists.
        for actors, paths in (
            ([], audit_settings.REQUIRED_RULESET_WORKFLOWS),
            ([], (".github/workflows/other.yml",)),
            (
                [
                    {"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"},
                    {"actor_type": "RepositoryRole", "actor_id": 4, "bypass_mode": "always"},
                ],
                audit_settings.REQUIRED_RULESET_WORKFLOWS,
            ),
        ):
            with self.subTest(actors=actors, paths=paths):
                responses = secure_responses()
                self.add_second_workflow_ruleset(responses, actors, paths)
                audit = self.run_audit(responses)
                self.assertEqual(len(audit.violations), 1)
                self.assertIn("ruleset 12", audit.violations[0])

    def test_a_second_mirrored_workflow_ruleset_passes(self):
        responses = secure_responses()
        self.add_second_workflow_ruleset(
            responses,
            [{"actor_type": "Integration", "actor_id": 99, "bypass_mode": "always"}],
            (".github/workflows/other.yml",),
        )
        self.assertEqual(self.run_audit(responses).violations, [])

    def test_the_rule_may_be_on_a_later_page(self):
        responses = secure_responses()
        responses[self.RULES] = [[{"type": "deletion"}], responses[self.RULES][0]]
        calls = []

        def answer(path, paginate=False):
            calls.append((path, paginate))
            return responses[path]

        with patch.object(audit_settings, "gh_json", side_effect=answer):
            audit = audit_settings.run(
                "acme/repo", "main", REQUIRED_CHECKS, 99, "refs/tags/v*"
            )
        self.assertEqual(audit.violations, [])
        self.assertIn((self.RULES, True), calls)

    def test_malformed_rules_and_a_missing_repository_id_fail_closed(self):
        responses = secure_responses()
        responses[self.RULES] = [[{"type": "workflows", "ruleset_id": 9, "parameters": None}]]
        self.assertEqual(len(self.run_audit(responses).violations), 1)
        responses = secure_responses()
        del responses["repos/acme/repo"]["id"]
        for entry in self.entries(responses):
            del entry["repository_id"]
        audit = self.run_audit(responses)
        self.assertEqual(len(audit.violations), 1)
        self.assertIn("repository id", audit.violations[0])

    def test_a_status_check_rule_naming_the_context_is_not_enough(self):
        responses = secure_responses()
        responses[self.RULES] = [
            [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [
                            {
                                "context": "trusted-supply-chain-policy",
                                "integration_id": audit_settings.GITHUB_ACTIONS_APP_ID,
                            }
                        ]
                    },
                }
            ]
        ]
        self.assertEqual(len(self.run_audit(responses).violations), 1)


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
