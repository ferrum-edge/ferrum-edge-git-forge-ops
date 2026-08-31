import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_agent_setup.py"
SPEC = importlib.util.spec_from_file_location("check_agent_setup", SCRIPT)
check_agent_setup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_agent_setup
SPEC.loader.exec_module(check_agent_setup)


class AgentSetupTests(unittest.TestCase):
    def test_repository_setup_is_consistent(self):
        self.assertEqual(check_agent_setup.collect_violations(check_agent_setup.ROOT), [])

    def test_detects_drift_across_skills_rules_and_continuations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = root / ".agents" / "skills" / "sample"
            claude = root / ".claude" / "skills" / "sample"
            rules = root / ".claude" / "rules"
            (agent / "scripts").mkdir(parents=True)
            (agent / "references").mkdir()
            claude.mkdir(parents=True)
            rules.mkdir(parents=True)
            (agent / "SKILL.md").write_text(
                "---\nname: wrong\n---\ndispatched worker\nFerrum Edge task\n",
                encoding="utf-8",
            )
            (agent / "scripts" / "dispatch-agent.sh").write_text(
                "#!/usr/bin/env bash\n", encoding="utf-8"
            )
            (agent / "references" / "agent-brief.md").write_text(
                "\n".join(check_agent_setup.MANDATORY_COMMANDS), encoding="utf-8"
            )
            (agent / "references" / "continuation-brief.md").write_text(
                "Rerun known flakes.\n", encoding="utf-8"
            )
            (claude / "SKILL.md").write_text(
                "---\nname: sample\n---\ndispatched worker\n"
                ".agents/skills/missing/scripts/dispatch-agent.sh\n"
                "Merge only when: checks are green.\n",
                encoding="utf-8",
            )
            (rules / "testing.md").write_text(
                "---\nname: wrong-kind\n---\n", encoding="utf-8"
            )
            (rules / "dangling.md").write_text(
                '---\npaths:\n  - "src/does_not_exist.rs"\n---\n', encoding="utf-8"
            )
            (claude / "linked.sh").symlink_to(agent / "scripts" / "dispatch-agent.sh")

            violations = check_agent_setup.collect_violations(root)

        joined = "\n".join(violations)
        self.assertIn("does not match directory", joined)
        self.assertIn("frontmatter is missing paths", joined)
        self.assertIn("referenced path does not exist", joined)
        self.assertIn("dispatcher is not executable", joined)
        self.assertIn("missing explicit user authorization for merging", joined)
        self.assertIn("path scope matches nothing", joined)
        self.assertIn("stale companion-repository marker 'known flakes'", joined)
        self.assertIn("setup content must not be a symlink", joined)
        self.assertIn("project branding is not adapted", joined)

    def test_allows_the_companion_gateway_name(self):
        self.assertIsNone(
            check_agent_setup.STALE_BRANDING.search("Companion to the Ferrum Edge gateway.")
        )

    def test_expands_every_braced_rule_path(self):
        self.assertEqual(
            check_agent_setup.expand_braces("tests/{unit,integration}/{a,b}.rs"),
            [
                "tests/unit/a.rs",
                "tests/unit/b.rs",
                "tests/integration/a.rs",
                "tests/integration/b.rs",
            ],
        )


if __name__ == "__main__":
    unittest.main()
