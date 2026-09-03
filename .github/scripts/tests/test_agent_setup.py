import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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
        'acquire_worktree_dispatch_lock "$physical_root"',
        check_agent_setup.RUN_DISPATCH_CALL,
    ]
    if name in check_agent_setup.CLAUDE_LAUNCHER_FLOOR:
        lines.append("resolve_agent_bin claude")
        lines.append(check_agent_setup.CLAUDE_ISOLATION_CALL)
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
        "\n".join(
            (
                check_agent_setup.IMPLEMENTER_UNTRUSTED_GUARD,
                *check_agent_setup.MANDATORY_COMMANDS,
                *check_agent_setup.BRIEF_INVARIANTS,
            )
        ),
        encoding="utf-8",
    )
    (references / "continuation-brief.md").write_text(
        f"Continue the assigned work. {check_agent_setup.CONTINUATION_UNTRUSTED_GUARD}.\n",
        encoding="utf-8",
    )
    launcher = scripts / "dispatch-agent.sh"
    launcher.write_text(valid_launcher(name), encoding="utf-8")
    launcher.chmod(0o755)

    shared = root / ".agents" / "skills" / "_lib" / "resolve-agent-bin.sh"
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text(
        "require_linked_worktree() { :; }\n"
        "acquire_worktree_dispatch_lock() { :; }\n"
        "run_dispatch_child() { :; }\n"
        "isolate_codex_provider() { unset CODEX_HOME; }\n"
        "isolate_opencode_provider() { unset OPENCODE_API_KEY; unset OPENCODE_AUTH_CONTENT; }\n"
        "isolate_claude_provider() { :; }\n"
        "isolate_cursor_provider() { :; }\n"
        "prepare_cursor_control_workspace() { :; }\n",
        encoding="utf-8",
    )
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
        "ref: ${{ github.event.repository.default_branch }}\n"
        "validator=.agent-setup-base/.github/scripts/check_agent_setup.py\n"
        '[[ -f "$validator" ]]\n'
        "else\n"
        "validator=.github/scripts/check_agent_setup.py\n"
        'python3 "$validator" --root "$GITHUB_WORKSPACE"\n'
        "python3 -m unittest discover -s .github/scripts/tests -p 'test_agent_setup.py'\n"
        "shellcheck --external-sources --source-path=SCRIPTDIR\n"
        "group: agent-setup-ci-${{ github.event.pull_request.number || github.ref }}\n"
        "cancel-in-progress: true\n",
        encoding="utf-8",
    )
    policy = root / ".github" / "workflows" / "agent-setup-policy.yml"
    policy.write_text(
        "on:\n"
        "  pull_request_target:\n"
        "    types:\n"
        "      - opened\n"
        "      - synchronize\n"
        "      - reopened\n"
        "      - edited\n"
        "repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
        "ref: ${{ github.event.pull_request.head.sha }}\n"
        "ref: ${{ github.event.repository.default_branch }}\n"
        "validator=.agent-setup-base/.github/scripts/check_agent_setup.py\n"
        '[[ -f "$validator" ]]\n'
        'python3 "$validator" --root "$GITHUB_WORKSPACE/.agent-setup-candidate"\n'
        "group: agent-setup-policy-${{ github.event.pull_request.number }}\n"
        "cancel-in-progress: true\n",
        encoding="utf-8",
    )
    codeowners = root / ".github" / "CODEOWNERS"
    codeowners.write_text(
        "\n".join(
            f"{path} {check_agent_setup.CODEOWNER}"
            for path in check_agent_setup.CODEOWNED_PATHS
        )
        + "\n",
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

    def test_rejects_missing_markdown_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            (agent / "references" / "notes.md").write_text(
                "[missing](missing.md)\n", encoding="utf-8"
            )
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(
            any("Markdown link target does not exist" in item for item in violations)
        )

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

    def test_rejects_symlinked_skill_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            agent_root = root / ".agents" / "skills"
            real_agent_root = root / ".agents" / "real-skills"
            agent_root.rename(real_agent_root)
            agent_root.symlink_to(real_agent_root, target_is_directory=True)
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("agent skill root must not be a symlink" in item for item in violations))

    def test_rejects_symlinked_shared_library_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            shared_dir = root / ".agents" / "skills" / "_lib"
            real_shared_dir = root / ".agents" / "real-lib"
            shared_dir.rename(real_shared_dir)
            shared_dir.symlink_to(real_shared_dir, target_is_directory=True)
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("shared library directory must not be a symlink", joined)
        self.assertIn("missing dispatch isolation helpers", joined)

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

    def test_rejects_unexpected_claude_mirror(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root, "fable-agents", claude_mirror=False)
            mirror = root / ".claude" / "skills" / "fable-agents"
            mirror.mkdir()
            (mirror / "SKILL.md").write_text(
                skill_text("fable-agents", claude=True), encoding="utf-8"
            )
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("unexpected Claude mirror" in item for item in violations))

    def test_claude_launchers_must_isolate_every_override_and_settings_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root, "opus-agents", claude_mirror=False)
            launcher = agent / "scripts" / "dispatch-agent.sh"
            launcher.write_text(
                valid_launcher("opus-agents")
                .replace(f"{check_agent_setup.CLAUDE_ISOLATION_CALL}\n", "")
                .replace("--setting-sources ''\n", ""),
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("inherited Claude provider variables are not isolated", joined)
        self.assertIn("user/project/local settings are not disabled", joined)

    def test_behavioral_launcher_detection_covers_new_provider_wrappers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            launcher = agent / "scripts" / "dispatch-agent.sh"
            launcher.write_text(
                valid_launcher("sample")
                + "resolve_agent_bin claude\n"
                + '"$claude_bin" -p\n',
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("Claude provider variables" in item for item in violations))

    def test_codex_opencode_and_cursor_launchers_require_provider_isolation(self):
        for provider in ("codex", "opencode", "cursor-agent"):
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                agent = write_valid_setup(root)
                launcher = agent / "scripts" / "dispatch-agent.sh"
                launcher.write_text(
                    valid_launcher("sample") + f"resolve_agent_bin {provider}\n",
                    encoding="utf-8",
                )
                violations = check_agent_setup.collect_violations(root)
            self.assertTrue(
                any(
                    (
                        "missing Cursor provider/project isolation"
                        if provider == "cursor-agent"
                        else f"missing {provider if provider == 'opencode' else 'Codex'} provider isolation"
                    )
                    in item
                    for item in violations
                )
            )

    def test_briefs_require_untrusted_guidance_and_repository_invariants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            implementer = agent / "references" / "agent-brief.md"
            continuation = agent / "references" / "continuation-brief.md"
            implementer.write_text(
                implementer.read_text(encoding="utf-8")
                .replace(check_agent_setup.IMPLEMENTER_UNTRUSTED_GUARD, "")
                .replace(check_agent_setup.BRIEF_INVARIANTS[0], ""),
                encoding="utf-8",
            )
            continuation.write_text("Continue.\n", encoding="utf-8")
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("missing untrusted-input guidance", joined)
        self.assertIn("missing repository invariant", joined)

    def test_dispatcher_requires_worktree_check_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            agent = write_valid_setup(root)
            launcher = agent / "scripts" / "dispatch-agent.sh"
            launcher.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn("does not enforce a linked worktree", joined)
        self.assertIn("does not lock its target worktree", joined)

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

    def test_ci_workflow_cannot_keep_markers_but_drop_validation_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            workflow = root / ".github" / "workflows" / "agent-setup-ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8")
                .replace('python3 "$validator" --root "$GITHUB_WORKSPACE"\n', "")
                .replace(
                    "python3 -m unittest discover -s .github/scripts/tests -p 'test_agent_setup.py'\n",
                    "",
                )
                .replace("shellcheck --external-sources --source-path=SCRIPTDIR\n", ""),
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        joined = "\n".join(violations)
        self.assertIn('python3 "$validator" --root "$GITHUB_WORKSPACE"', joined)
        self.assertIn("unittest discover", joined)
        self.assertIn("shellcheck --external-sources", joined)

    def test_codeowners_rejects_later_overriding_patterns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            codeowners = root / ".github/CODEOWNERS"
            codeowners.write_text(
                codeowners.read_text(encoding="utf-8") + "/.github/** @attacker\n",
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(
            any("must be the final rules" in violation for violation in violations)
        )

    def test_workflow_requires_policy_file_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            policy = root / ".github" / "workflows" / "agent-setup-policy.yml"
            policy.unlink()
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("missing agent setup workflow" in item for item in violations))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            policy = root / ".github" / "workflows" / "agent-setup-policy.yml"
            real_policy = policy.with_name("real-policy.yml")
            policy.rename(real_policy)
            policy.symlink_to(real_policy)
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("workflow must not be a symlink" in item for item in violations))

    def test_workflow_accepts_quoted_inline_types_and_rejects_branch_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_setup(root)
            workflow = root / ".github" / "workflows" / "agent-setup-ci.yml"
            text = workflow.read_text(encoding="utf-8").replace(
                "types: [opened, synchronize, reopened, edited]",
                "types: ['opened', \"synchronize\", reopened, edited]",
            )
            workflow.write_text(text, encoding="utf-8")
            self.assertEqual(check_agent_setup.collect_violations(root), [])

            workflow.write_text(
                text.replace(
                    "    types: ['opened', \"synchronize\", reopened, edited]\n",
                    "    types: ['opened', \"synchronize\", reopened, edited]\n    branches: [release]\n",
                ),
                encoding="utf-8",
            )
            violations = check_agent_setup.collect_violations(root)
        self.assertTrue(any("must cover non-main and stacked" in item for item in violations))

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_linked_worktree_helper_rejects_primary_controller_and_duplicate(self):
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
                cwd=directory,
            )
            controller = subprocess.run(
                ["bash", "-c", command, "bash", str(check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
                check=False,
                capture_output=True,
                text=True,
                cwd=linked,
            )

            lock_command = (
                'source "$1"; require_linked_worktree "$2"; '
                'acquire_worktree_dispatch_lock "$2"; printf "ready\\n"; sleep 30'
            )
            holder = subprocess.Popen(
                ["bash", "-c", lock_command, "bash", str(check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self.assertEqual(holder.stdout.readline(), "ready\n")
            duplicate = subprocess.run(
                ["bash", "-c", lock_command.replace('; printf "ready\\n"; sleep 30', ""), "bash", str(check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
                check=False,
                capture_output=True,
                text=True,
                cwd=directory,
            )
            os.killpg(holder.pid, signal.SIGTERM)
            try:
                holder.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(holder.pid, signal.SIGKILL)
                holder.communicate(timeout=5)
        self.assertNotEqual(primary.returncode, 0)
        self.assertIn("primary checkout", primary.stderr)
        self.assertEqual(worker.returncode, 0, worker.stderr)
        self.assertNotEqual(controller.returncode, 0)
        self.assertIn("controller checkout", controller.stderr)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("concurrent dispatch", duplicate.stderr)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_worktree_lock_recovers_stale_and_malformed_owners_atomically(self):
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
            helper = str(
                check_agent_setup.ROOT
                / ".agents/skills/_lib/resolve-agent-bin.sh"
            )
            acquire = (
                'set -e; source "$1"; acquire_worktree_dispatch_lock "$2"; '
                'printf "acquired\\n"; sleep 30'
            )
            holder = subprocess.Popen(
                ["bash", "-c", acquire, "bash", helper, str(linked)],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self.assertEqual(holder.stdout.readline(), "acquired\n")
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=5)
            holder.stdout.close()
            holder.stderr.close()

            recovered = subprocess.run(
                [
                    "bash",
                    "-c",
                    acquire.replace('; printf "acquired\\n"; sleep 30', ""),
                    "bash",
                    helper,
                    str(linked),
                ],
                cwd=directory,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)

            git_dir = Path(
                subprocess.check_output(
                    ["git", "-C", str(linked), "rev-parse", "--git-dir"],
                    text=True,
                ).strip()
            )
            if not git_dir.is_absolute():
                git_dir = linked / git_dir
            lock = git_dir / "gitforgeops-agent-dispatch.lock"
            lock.write_text("not-a-pid\n", encoding="utf-8")
            contenders = [
                subprocess.Popen(
                    ["bash", "-c", acquire, "bash", helper, str(linked)],
                    cwd=directory,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                for _ in range(2)
            ]
            outputs = [process.stdout.readline() for process in contenders]
            acquired = [index for index, output in enumerate(outputs) if output == "acquired\n"]
            self.assertEqual(len(acquired), 1, outputs)
            for index, process in enumerate(contenders):
                if index in acquired:
                    os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=5)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_pid_only_cancellation_reaches_worker_group_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            root = temp / "repo"
            linked = temp / "linked"
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
            helper = str(
                check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
            )
            worker = temp / "worker.py"
            worker.write_text(
                "import os\n"
                "import signal\n"
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "child = subprocess.Popen(['sleep', '300'])\n"
                "with open(os.environ['FAKE_GRANDCHILD'], 'w', encoding='utf-8') as output:\n"
                "    output.write(str(child.pid))\n"
                "def cancel(signum, _frame):\n"
                "    with open(os.environ['FAKE_MARKER'], 'w', encoding='utf-8') as output:\n"
                "        output.write(str(signum))\n"
                "    raise SystemExit(0)\n"
                "for name in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
                "    signal.signal(name, cancel)\n"
                "print('worker-ready', flush=True)\n"
                "while True:\n"
                "    time.sleep(1)\n",
                encoding="utf-8",
            )
            prompt = temp / "prompt.md"
            prompt.write_text("work\n", encoding="utf-8")
            command = (
                'source "$1"; acquire_worktree_dispatch_lock "$2"; '
                'run_dispatch_child "$3" "$4" "$5"'
            )
            for sent_signal, expected_status in (
                (signal.SIGHUP, 129),
                (signal.SIGINT, 130),
                (signal.SIGTERM, 143),
            ):
                marker = temp / f"terminated-{sent_signal.value}"
                grandchild_file = temp / f"grandchild-{sent_signal.value}"
                launcher = subprocess.Popen(
                    [
                        "bash",
                        "-c",
                        command,
                        "bash",
                        helper,
                        str(linked),
                        str(prompt),
                        sys.executable,
                        str(worker),
                    ],
                    cwd=temp,
                    env={
                        **os.environ,
                        "FAKE_MARKER": str(marker),
                        "FAKE_GRANDCHILD": str(grandchild_file),
                    },
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                self.assertEqual(launcher.stdout.readline(), "worker-ready\n")
                grandchild = int(grandchild_file.read_text(encoding="utf-8"))
                os.kill(launcher.pid, sent_signal)
                stdout, stderr = launcher.communicate(timeout=5)
                self.assertEqual(launcher.returncode, expected_status, stdout + stderr)
                self.assertEqual(
                    marker.read_text(encoding="utf-8"), str(sent_signal.value)
                )
                for _ in range(50):
                    state = subprocess.run(
                        ["ps", "-o", "stat=", "-p", str(grandchild)],
                        check=False,
                        capture_output=True,
                        text=True,
                    ).stdout.strip()
                    if not state or "Z" in state:
                        break
                    time.sleep(0.02)
                self.assertTrue(
                    not state or "Z" in state,
                    f"grandchild {grandchild} survived {sent_signal.name}: {state}",
                )

                reacquire = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'source "$1"; acquire_worktree_dispatch_lock "$2"',
                        "bash",
                        helper,
                        str(linked),
                    ],
                    cwd=temp,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(reacquire.returncode, 0, reacquire.stderr)

            git_dir = Path(
                subprocess.check_output(
                    ["git", "-C", str(linked), "rev-parse", "--git-dir"],
                    text=True,
                ).strip()
            )
            if not git_dir.is_absolute():
                git_dir = linked / git_dir
            owner = Path(f"{git_dir / 'gitforgeops-agent-dispatch.lock'}.owner")
            self.assertFalse(owner.exists(), "lock owner sidecar must be cleaned")

    def test_dispatch_child_preserves_worker_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            prompt = Path(directory) / "prompt.md"
            prompt.write_text("work\n", encoding="utf-8")
            helper = str(
                check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; run_dispatch_child "$2" bash -c "exit 7"',
                    "bash",
                    helper,
                    str(prompt),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 7, result.stderr)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_cursor_launcher_uses_clean_control_workspace_and_scrubs_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            root = temp / "repo"
            linked = temp / "linked"
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
            fake_cursor = temp / "cursor-agent"
            fake_cursor.write_text(
                "#!/usr/bin/env bash\n"
                "prompt=$(cat)\n"
                "if { : >&9; } 2>/dev/null; then fd9=open; else fd9=closed; fi\n"
                "{\n"
                "  printf 'cwd=%s\\n' \"$PWD\"\n"
                "  printf 'arg=%s\\n' \"$@\"\n"
                "  printf 'api-key=%s\\n' \"${CURSOR_API_KEY:+present}\"\n"
                "  printf 'endpoint=%s\\n' \"${CURSOR_API_ENDPOINT-unset}\"\n"
                "  printf 'config=%s\\n' \"${CURSOR_CONFIG_DIR-unset}\"\n"
                "  printf 'credential-store=%s\\n' \"${AGENT_CLI_CREDENTIAL_STORE-unset}\"\n"
                "  printf 'fd9=%s\\n' \"$fd9\"\n"
                "  printf 'prompt=%s\\n' \"$prompt\"\n"
                "} > \"$FAKE_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_cursor.chmod(0o755)
            prompt = temp / "prompt.md"
            prompt.write_text("Review only.\n", encoding="utf-8")
            capture = temp / "capture.txt"
            temp_root = temp / "tmp"
            temp_root.mkdir()
            launcher = (
                check_agent_setup.ROOT
                / ".agents/skills/composer-agents/scripts/dispatch-agent.sh"
            )
            result = subprocess.run(
                [
                    "bash",
                    str(launcher),
                    "--worktree",
                    str(linked),
                    "--prompt-file",
                    str(prompt),
                    "--effort",
                    "high",
                ],
                cwd=temp,
                env={
                    **os.environ,
                    "CURSOR_AGENT_BIN": str(fake_cursor),
                    "CURSOR_API_KEY": "not-printed",
                    "CURSOR_API_ENDPOINT": "https://attacker.invalid",
                    "CURSOR_CONFIG_DIR": str(temp / "attacker-config"),
                    "FAKE_CAPTURE": str(capture),
                    "TMPDIR": str(temp_root),
                },
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            captured = capture.read_text(encoding="utf-8")
            cwd = next(
                line.removeprefix("cwd=")
                for line in captured.splitlines()
                if line.startswith("cwd=")
            )
            self.assertNotEqual(cwd, str(linked))
            self.assertTrue(cwd.startswith(str(temp_root)))
            self.assertFalse(Path(cwd).exists(), "control workspace must be removed")
            self.assertNotIn("arg=--sandbox", captured)
            self.assertNotIn("arg=enabled", captured)
            self.assertIn("arg=--add-dir", captured)
            self.assertIn(f"arg={linked.resolve()}", captured)
            self.assertIn(f"arg={cwd}", captured)
            self.assertIn("api-key=present", captured)
            self.assertIn("endpoint=unset", captured)
            self.assertIn("config=unset", captured)
            self.assertIn("credential-store=memory", captured)
            self.assertIn("fd9=closed", captured)
            self.assertIn("prompt=Review only.", captured)
            self.assertNotIn("not-printed", captured)

    def test_claude_provider_scrubber_covers_future_and_foundry_overrides(self):
        helper = str(
            check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
        )
        command = (
            'source "$1"; '
            "export ANTHROPIC_DEFAULT_FABLE_MODEL=attacker "
            "ANTHROPIC_FOUNDRY_BASE_URL=https://attacker.invalid "
            "CLAUDE_CODE_USE_FOUNDRY=1 CLAUDE_CONFIG_DIR=/tmp/attacker "
            "MAX_THINKING_TOKENS=1; "
            "isolate_claude_provider; "
            '[[ -z "${ANTHROPIC_DEFAULT_FABLE_MODEL-}" && '
            '-z "${ANTHROPIC_FOUNDRY_BASE_URL-}" && '
            '-z "${CLAUDE_CODE_USE_FOUNDRY-}" && '
            '-z "${CLAUDE_CONFIG_DIR-}" && '
            '-z "${MAX_THINKING_TOKENS-}" ]]'
        )
        result = subprocess.run(
            ["bash", "-c", command, "bash", helper],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_codex_and_opencode_provider_scrubbers_clear_auth_overrides(self):
        helper = str(
            check_agent_setup.ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
        )
        command = (
            'source "$1"; '
            "export CODEX_HOME=/tmp/attacker OPENAI_API_KEY=attacker; "
            "isolate_codex_provider; "
            '[[ -z "${CODEX_HOME-}" && -z "${OPENAI_API_KEY-}" ]] || exit 3; '
            "export OPENCODE_API_KEY=attacker OPENCODE_AUTH_CONTENT=attacker; "
            "isolate_opencode_provider; "
            '[[ -z "${OPENCODE_API_KEY-}" && -z "${OPENCODE_AUTH_CONTENT-}" ]]'
        )
        result = subprocess.run(
            ["bash", "-c", command, "bash", helper],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

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

    def test_rejects_unbounded_rule_path_brace_expansion(self):
        pattern = "rules/" + "{a,b}" * 7 + ".md"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / ".claude/rules/explosive.md"
            rule.parent.mkdir(parents=True)
            rule.write_text("rule\n", encoding="utf-8")
            violations = check_agent_setup.validate_rule_paths(root, rule, [pattern])
        self.assertEqual(len(violations), 1)
        self.assertIn("brace expansion exceeds 64 paths", violations[0])


if __name__ == "__main__":
    unittest.main()
