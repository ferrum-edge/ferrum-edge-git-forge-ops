"""Behavioral tests for the agent dispatch launchers and their shared helpers.

These exercise `.agents/skills/_lib/resolve-agent-bin.sh` and the launchers
themselves (linked-worktree enforcement, the worktree dispatch lock, signal
forwarding, provider scrubbing, opencode `--pure` probing). They make no model
requests.
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def init_repo_with_linked_worktree(root: Path, linked: Path) -> None:
    """A one-commit repository at `root` plus a detached worktree at `linked`."""
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    # `git commit` otherwise detaches `git maintenance run --auto`, which can
    # still be writing `.git/objects` when the directory is removed (#374).
    # Nothing may outlive the git command that started it.
    for key, value in (
        ("maintenance.auto", "false"),
        ("gc.auto", "0"),
        ("core.fsmonitor", "false"),
    ):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
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



class AgentLauncherTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_linked_worktree_helper_rejects_primary_controller_and_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            linked = Path(directory) / "linked"
            init_repo_with_linked_worktree(root, linked)
            command = (
                'source "$1"; require_linked_worktree "$2"'
            )
            primary = subprocess.run(
                ["bash", "-c", command, "bash", str(ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            worker = subprocess.run(
                ["bash", "-c", command, "bash", str(ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
                check=False,
                capture_output=True,
                text=True,
                cwd=directory,
            )
            controller = subprocess.run(
                ["bash", "-c", command, "bash", str(ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
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
                ["bash", "-c", lock_command, "bash", str(ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self.assertEqual(holder.stdout.readline(), "ready\n")
            duplicate = subprocess.run(
                ["bash", "-c", lock_command.replace('; printf "ready\\n"; sleep 30', ""), "bash", str(ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"), str(linked)],
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
            init_repo_with_linked_worktree(root, linked)
            helper = str(
                ROOT
                / ".agents/skills/_lib/resolve-agent-bin.sh"
            )
            acquire = (
                'set -e; source "$1"; acquire_worktree_dispatch_lock "$2"; '
                'printf "acquired\\n"; IFS= read -r release'
            )
            # Block in a shell builtin with an open stdin pipe. With `sleep`,
            # SIGTERM can reach bash after the readiness printf but before it
            # forks the child; that new child misses the group signal and
            # delays the shell's cleanup trap for the entire sleep duration.
            holder = subprocess.Popen(
                ["bash", "-c", acquire, "bash", helper, str(linked)],
                cwd=directory,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self.assertEqual(holder.stdout.readline(), "acquired\n")
            os.killpg(holder.pid, signal.SIGKILL)
            holder.wait(timeout=5)
            holder.stdin.close()
            holder.stdout.close()
            holder.stderr.close()

            recovered = subprocess.run(
                [
                    "bash",
                    "-c",
                    acquire.replace('; printf "acquired\\n"; IFS= read -r release', ""),
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
                    stdin=subprocess.PIPE,
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
            init_repo_with_linked_worktree(root, linked)
            helper = str(
                ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
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
                ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
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
    def test_antigravity_launcher_passes_prompt_on_argv_in_a_linked_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            root = temp / "repo"
            linked = temp / "linked"
            init_repo_with_linked_worktree(root, linked)
            fake_agy = temp / "agy"
            fake_agy.write_text(
                "#!/usr/bin/env bash\n"
                "if { : >&9; } 2>/dev/null; then fd9=open; else fd9=closed; fi\n"
                "{\n"
                "  printf 'cwd=%s\\n' \"$PWD\"\n"
                "  printf 'arg=%s\\n' \"$@\"\n"
                "  printf 'api-key=%s\\n' \"${GEMINI_API_KEY:+present}\"\n"
                "  printf 'adc=%s\\n' \"${AGY_ADC_AUTH-unset}\"\n"
                "  printf 'fd9=%s\\n' \"$fd9\"\n"
                "} > \"$FAKE_CAPTURE\"\n",
                encoding="utf-8",
            )
            fake_agy.chmod(0o755)
            prompt = temp / "prompt.md"
            prompt.write_text("Review only.\n", encoding="utf-8")
            capture = temp / "capture.txt"
            launcher = (
                ROOT
                / ".agents/skills/antigravity-neon-agents/scripts/dispatch-agent.sh"
            )

            def launch(worktree: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        "bash",
                        str(launcher),
                        "--worktree",
                        str(worktree),
                        "--prompt-file",
                        str(prompt),
                        "--effort",
                        "xhigh",
                    ],
                    cwd=temp,
                    env={
                        **os.environ,
                        "AGY_BIN": str(fake_agy),
                        "GEMINI_API_KEY": "not-printed",
                        "AGY_ADC_AUTH": "1",
                        "FAKE_CAPTURE": str(capture),
                    },
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

            result = launch(root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("dedicated linked git worktree", result.stderr)
            self.assertFalse(capture.exists(), "the primary checkout must be refused")

            result = launch(linked)
            self.assertEqual(result.returncode, 0, result.stderr)
            captured = capture.read_text(encoding="utf-8")
            self.assertIn(f"cwd={linked.resolve()}", captured)
            self.assertIn("arg=gemini-4-neon", captured)
            self.assertIn("arg=xhigh", captured)
            self.assertIn("arg=--disable-slash-commands", captured)
            self.assertNotIn("arg=--sandbox", captured)
            self.assertIn("arg=--print=Review only.", captured)
            self.assertIn("api-key=present", captured)
            self.assertIn("adc=1", captured)
            self.assertIn("fd9=closed", captured)
            self.assertNotIn("not-printed", captured + result.stderr)

    def test_claude_provider_scrubber_covers_future_and_foundry_overrides(self):
        helper = str(
            ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
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
            ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
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

    OPENCODE_LAUNCHERS = (
        "deepseek-flash-agents",
        "qwen-agents",
    )
    UNSUPPORTED_HELP = "FLAGS\n  --standalone  private server\n  --purely  no"

    def opencode_launcher_fixture(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        temp = Path(directory.name)
        init_repo_with_linked_worktree(temp / "repo", temp / "linked")
        (temp / "tmp").mkdir()
        fake = temp / "opencode"
        fake.write_text(
            "#!/usr/bin/env bash\n"
            "hang() { sleep 300 & printf '%s\\n' \"$!\" \"$$\" >> \"$FAKE_PIDS\"; wait; }\n"
            'if [[ "$1" == "--version" ]]; then\n'
            '  [[ "$FAKE_PROBE" == hang-version ]] && hang\n'
            '  printf "opencode v9.9.9\\n"; exit 0\n'
            "fi\n"
            'if [[ "$1 $2" == "run --help" ]]; then\n'
            '  case "$FAKE_PROBE" in\n'
            "    pure) printf 'Options:\\n      --pure  run without external plugins  [boolean]\\n' ;;\n"
            '    unsupported|hang-version) printf "%s\\n" "$FAKE_HELP" ;;\n'
            "    hang-help) hang ;;\n"
            "    *) exit 1 ;;\n"
            "  esac\n"
            "  exit 0\n"
            "fi\n"
            "prompt=$(cat)\n"
            "{ printf 'spawn\\n'; printf 'arg=%s\\n' \"$@\"; "
            "printf 'prompt=%s\\n' \"$prompt\"; } >> \"$FAKE_CAPTURE\"\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        (temp / "prompt.md").write_text("Review only.\n", encoding="utf-8")
        return temp

    def run_opencode_launcher(
        self,
        skill: str,
        probe: str,
        *,
        temp: Path | None = None,
        help_text: str = UNSUPPORTED_HELP,
    ) -> tuple[subprocess.CompletedProcess[str], str, Path]:
        temp = temp or self.opencode_launcher_fixture()
        capture = temp / "capture.txt"
        capture.unlink(missing_ok=True)
        launcher = (
            ROOT / f".agents/skills/{skill}/scripts/dispatch-agent.sh"
        )
        result = subprocess.run(
            [
                "bash",
                str(launcher),
                "--worktree",
                str(temp / "linked"),
                "--prompt-file",
                str(temp / "prompt.md"),
            ],
            cwd=temp,
            env={
                **os.environ,
                "OPENCODE_BIN": str(temp / "opencode"),
                "ALIBABA_TOKEN_PLAN_API_KEY": "not-printed",
                "FAKE_PROBE": probe,
                "FAKE_HELP": help_text,
                "FAKE_CAPTURE": str(capture),
                "FAKE_PIDS": str(temp / "pids.txt"),
                "TMPDIR": str(temp / "tmp"),
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        captured = capture.read_text(encoding="utf-8") if capture.exists() else ""
        return result, captured, temp / "opencode"

    def test_opencode_launchers_dispatch_with_pure_when_supported(self):
        for skill in self.OPENCODE_LAUNCHERS:
            with self.subTest(skill=skill):
                result, captured, _ = self.run_opencode_launcher(skill, "pure")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("spawn", captured)
                args = [
                    line.removeprefix("arg=")
                    for line in captured.splitlines()
                    if line.startswith("arg=")
                ]
                self.assertEqual(args[:2], ["run", "--pure"])
                self.assertIn("--auto", args)
                self.assertIn("prompt=Review only.", captured)

    def test_opencode_launchers_refuse_without_pure_before_spawning(self):
        for skill in self.OPENCODE_LAUNCHERS:
            with self.subTest(skill=skill):
                result, captured, fake = self.run_opencode_launcher(skill, "unsupported")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(captured, "")
                self.assertIn(
                    f'opencode v9.9.9 at {fake} does not support "opencode run --pure"',
                    result.stderr,
                )
                self.assertIn("v1.3.4 or later", result.stderr)

    def test_opencode_launchers_ignore_pure_mentioned_outside_an_option_declaration(self):
        for help_text in (
            "FLAGS\n  --standalone  replaces --pure",
            "Note: --pure was removed in 2.0; use --standalone",
            "FLAGS\n  --standalone   Run with a private server (formerly --pure)",
            "  --pure is no longer supported",
            "  --pure-mode  something else",
        ):
            with self.subTest(help_text=help_text):
                result, captured, _ = self.run_opencode_launcher(
                    "deepseek-flash-agents", "unsupported", help_text=help_text
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(captured, "")
                self.assertIn('does not support "opencode run --pure"', result.stderr)

    def test_opencode_help_parser_accepts_option_declarations_only(self):
        helper = str(
            ROOT / ".agents/skills/_lib/resolve-agent-bin.sh"
        )
        for line, declared in (
            ("      --pure                 run without external plugins  [boolean]", True),
            ("  -p, --pure  run without external plugins", True),
            ("  --pure, -P\trun without external plugins", True),
            ("  --pure", True),
            ("  --standalone  replaces --pure", False),
            ("  --model, -m string  Model to use (not --pure)", False),
            ("  --pure is no longer supported", False),
            ("  --purely  no", False),
        ):
            with self.subTest(line=line):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        'set -euo pipefail; source "$1"; opencode_help_declares_pure "$2"',
                        "bash",
                        helper,
                        f"Options:\n{line}\n",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0 if declared else 1, result.stderr)

    def test_opencode_launchers_treat_a_failed_probe_as_unsupported(self):
        for skill in self.OPENCODE_LAUNCHERS:
            with self.subTest(skill=skill):
                result, captured, _ = self.run_opencode_launcher(skill, "fail")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(captured, "")
                self.assertIn('does not support "opencode run --pure"', result.stderr)

    def test_opencode_launchers_kill_hanging_probes_and_release_the_lock(self):
        for probe in ("hang-help", "hang-version"):
            with self.subTest(probe=probe):
                temp = self.opencode_launcher_fixture()
                started = time.monotonic()
                result, captured, _ = self.run_opencode_launcher(
                    "deepseek-flash-agents", probe, temp=temp
                )
                self.assertLess(time.monotonic() - started, 30)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(captured, "")
                self.assertIn("did not finish within", result.stderr)
                self.assertIn('does not support "opencode run --pure"', result.stderr)
                pids = (temp / "pids.txt").read_text(encoding="utf-8").split()
                self.assertTrue(pids)
                for pid in pids:
                    with self.assertRaises(ProcessLookupError, msg=f"pid {pid} survived"):
                        os.kill(int(pid), 0)
                self.assertEqual(list((temp / "tmp").iterdir()), [])
                # The refusal released the worktree lock: the next dispatch runs.
                result, captured, _ = self.run_opencode_launcher(
                    "deepseek-flash-agents", "pure", temp=temp
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("spawn", captured)


if __name__ == "__main__":
    unittest.main()
