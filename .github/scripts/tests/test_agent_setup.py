import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_agent_setup.py"
SPEC = importlib.util.spec_from_file_location("check_agent_setup", SCRIPT)
check_agent_setup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_agent_setup
SPEC.loader.exec_module(check_agent_setup)


def skill_text(name: str, *, claude: bool = False) -> str:
    linked = (
        "Every dispatch uses a dedicated linked git worktree.\n" if claude else ""
    )
    return (
        f"---\nname: {name}\n---\n"
        "This dispatched worker cannot recurse.\n"
        f"{check_agent_setup.UNTRUSTED_DATA_GUARD} data.\n"
        f"{linked}"
        "Merge only when the user explicitly authorizes it.\n"
    )


def valid_launcher(name: str) -> str:
    lines = [
        "#!/usr/bin/env bash",
        'require_linked_worktree "$physical_root"',
    ]
    if name in check_agent_setup.CLAUDE_LAUNCHER_SKILLS:
        lines.extend(f"unset {variable}" for variable in check_agent_setup.CLAUDE_ENV_OVERRIDES)
        lines.append("--setting-sources ''")
    return "\n".join(lines) + "\n"


def write_valid_setup(
    root: Path, name: str = "sample", *, claude_mirror: bool | None = None
) -> Path:
    if claude_mirror is None:
        claude_mirror = name not in check_agent_setup.CLAUDE_MIRROR_EXCEPTIONS
    agent = root / ".agents" / "skills" / name
    references = agent / "references"
    scripts = agent / "scripts"
    references.mkdir(parents=True)
    scripts.mkdir()
    (agent / "SKILL.md").write_text(skill_text(name), encoding="utf-8")
    (references / "agent-brief.md").write_text(
        "\n".join(check_agent_setup.MANDATORY_COMMANDS), encoding="utf-8"
    )
    (references / "continuation-brief.md").write_text(
        "Continue the assigned work.\n", encoding="utf-8"
    )
    launcher = scripts / "dispatch-agent.sh"
    launcher.write_text(valid_launcher(name), encoding="utf-8")
    launcher.chmod(0o755)

    shared = root / ".agents" / "skills" / "_lib" / "resolve-agent-bin.sh"
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text("require_linked_worktree() { :; }\n", encoding="utf-8")
    (root / ".claude" / "rules").mkdir(parents=True, exist_ok=True)
    (root / ".claude" / "skills").mkdir(parents=True, exist_ok=True)
    if claude_mirror:
        mirror = root / ".claude" / "skills" / name
        mirror.mkdir()
        (mirror / "SKILL.md").write_text(
            skill_text(name, claude=True), encoding="utf-8"
        )
    workflow = root / ".github" / "workflows" / "agent-setup-ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on:\n"
        "  pull_request:\n"
        "    types: [opened, synchronize, reopened, edited]\n"
        "    branches: [main]\n"
        "ref: ${{ github.event.repository.default_branch }}\n"
        "validator=.agent-setup-base/.github/scripts/check_agent_setup.py\n"
        '[[ -f "$validator" ]]\n'
        "else\n"
        "validator=.github/scripts/check_agent_setup.py\n",
        encoding="utf-8",
    )
    return agent


class AgentSetupTests(unittest.TestCase):
    def test_repository_setup_is_consistent(self):
        self.assertEqual(check_agent_setup.collect_violations(check_agent_setup.ROOT), [])

    def test_valid_minimal_setup_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            (agent / "SKILL.md").write_text(
                skill_text("sample")
                + "[brief](references/agent-brief.md)\n"
                + ".agents/skills/sample/references/agent-brief.md.\n",
                encoding="utf-8",
            )
            self.assertEqual(check_agent_setup.collect_violations(root), [])

    def test_missing_agent_root_is_a_violation_not_an_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".claude" / "skills").mkdir(parents=True)
            (root / ".claude" / "rules").mkdir()
            workflow = root / ".github" / "workflows" / "agent-setup-ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("", encoding="utf-8")
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("missing agent skill root" in item for item in violations))

    def test_detects_missing_guards_frontmatter_dispatcher_and_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            (agent / "SKILL.md").write_text("---\n---\n", encoding="utf-8")
            (agent / "scripts" / "dispatch-agent.sh").unlink()
            (agent / "references" / "agent-brief.md").write_text(
                "cargo fmt --all\n", encoding="utf-8"
            )
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("missing YAML frontmatter", joined)
        self.assertIn("missing dispatched-worker recursion guard", joined)
        self.assertIn("missing untrusted-input guard", joined)
        self.assertIn("missing dispatcher", joined)
        self.assertIn("missing mandatory command", joined)

    def test_rejects_absolute_traversal_and_escaping_markdown_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            rules = root / ".claude" / "rules"
            (rules / "bad.md").write_text(
                "---\npaths:\n  - /tmp/absolute\n  - ../escape\n---\n",
                encoding="utf-8",
            )
            (agent / "references" / "notes.md").write_text(
                "[escape](../../../../../outside)\n"
                ".agents/skills/missing/scripts/dispatch-agent.sh\n",
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("invalid path scope '/tmp/absolute'", joined)
        self.assertIn("invalid path scope '../escape'", joined)
        self.assertIn("Markdown link escapes repository", joined)
        self.assertIn("referenced path does not exist", joined)

    def test_rejects_symlinked_skill_and_support_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            (root / ".agents" / "skills" / "linked").symlink_to(
                agent, target_is_directory=True
            )
            real_references = agent / "real-references"
            (agent / "references").rename(real_references)
            (agent / "references").symlink_to(real_references, target_is_directory=True)
            real_scripts = agent / "real-scripts"
            (agent / "scripts").rename(real_scripts)
            (agent / "scripts").symlink_to(real_scripts, target_is_directory=True)
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("agent skill directory must not be a symlink", joined)
        self.assertIn("references directory must not be a symlink", joined)
        self.assertIn("scripts directory must not be a symlink", joined)

    def test_requires_claude_mirror_except_for_claude_native_launchers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root, claude_mirror=False)
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("missing required Claude mirror" in item for item in violations))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root, "fable-agents", claude_mirror=False)
            self.assertEqual(check_agent_setup.collect_violations(root), [])

    def test_claude_launchers_must_clear_every_override_and_settings_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root, "opus-agents", claude_mirror=False)
            launcher = agent / "scripts" / "dispatch-agent.sh"
            launcher.write_text(
                valid_launcher("opus-agents")
                .replace("unset CLAUDE_CODE_USE_VERTEX\n", "")
                .replace("--setting-sources ''\n", ""),
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("inherited CLAUDE_CODE_USE_VERTEX is not cleared", joined)
        self.assertIn("user/project/local settings are not disabled", joined)

    def test_sol_compatibility_briefs_must_match_canonical_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root, "sol-agents")
            mirror = root / ".claude" / "skills" / "sol-agents"
            for brief_name in check_agent_setup.SOL_COMPAT_BRIEFS:
                canonical = agent / "references" / brief_name
                (mirror / brief_name).write_text(
                    canonical.read_text(encoding="utf-8"), encoding="utf-8"
                )
            self.assertEqual(check_agent_setup.collect_violations(root), [])

            (mirror / "continuation-brief.md").write_text(
                "stale instructions\n", encoding="utf-8"
            )
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(
            any("compatibility brief differs from canonical" in item for item in violations)
        )

    def test_workflow_rejects_unprotected_base_and_candidate_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            workflow = root / ".github" / "workflows" / "agent-setup-ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8")
                .replace(
                    "github.event.repository.default_branch",
                    "github.event.pull_request.base.sha",
                )
                .replace(
                    '[[ -f "$validator" ]]',
                    "using the candidate validator for bootstrap",
                ),
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("github.event.pull_request.base.sha", joined)
        self.assertIn("candidate validator for bootstrap", joined)

    def test_linked_worktree_helper_rejects_primary_and_accepts_linked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            linked = Path(directory) / "linked"
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "--allow-empty", "-m", "init"],
                check=True,
                env={
                    **os.environ,
                    "GIT_AUTHOR_NAME": "Test",
                    "GIT_AUTHOR_EMAIL": "test@example.invalid",
                    "GIT_COMMITTER_NAME": "Test",
                    "GIT_COMMITTER_EMAIL": "test@example.invalid",
                },
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "-C", str(root), "worktree", "add", "-q", "--detach", str(linked)],
                check=True,
            )
            command = (
                'source "$1"; require_linked_worktree "$2"'
            )
            primary = subprocess.run(
                ["bash", "-c", command, "bash", str(check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            worker = subprocess.run(
                ["bash", "-c", command, "bash", str(check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(primary.returncode, 0)
        self.assertIn("primary checkout", primary.stderr)
        self.assertEqual(worker.returncode, 0, worker.stderr)

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
