"""Exercise the real launcher with a fake agy executable; no model requests."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


LAUNCHER = Path(__file__).with_name("dispatch-agent.sh")
EFFORTS = ("low", "medium", "high", "xhigh")


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="antigravity-dispatch-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        primary = self.root / "primary"
        self.primary = primary
        primary.mkdir()
        subprocess.run(["git", "init", "--quiet", str(primary)], check=True)
        subprocess.run(
            ["git", "-C", str(primary), "-c", "user.name=Antigravity tests",
             "-c", "user.email=antigravity-tests@example.invalid",
             "-c", "commit.gpgsign=false",
             "commit", "--quiet", "--allow-empty", "-m", "Initialize fixture"],
            check=True,
        )
        self.worktree = self.root / "worker with spaces"
        subprocess.run(
            ["git", "-C", str(primary), "worktree", "add", "--quiet", "--detach",
             str(self.worktree), "HEAD"], check=True,
        )
        self.prompt = self.root / "prompt with spaces.txt"
        self.prompt_text = "-Implement the scoped task.\nKeep literal $(text) and `text`.\n"
        self.prompt.write_text(self.prompt_text)
        self.mock = self.root / "fake agy"
        self.mock.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys, time\n"
            "gate = os.environ.get('AGY_TEST_GATE')\n"
            "if gate:\n"
            "    open(gate + '.started', 'w').close()\n"
            "    deadline = time.monotonic() + 30\n"
            "    while not os.path.exists(gate) and time.monotonic() < deadline:\n"
            "        time.sleep(0.05)\n"
            "print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd(), "
            "'stdin': sys.stdin.read()}))\n"
            "sys.exit(int(os.environ.get('AGY_TEST_EXIT_CODE', '0')))\n"
        )
        self.mock.chmod(0o700)

    def command(self, *flags, worktree=None, prompt=None):
        return [
            "bash",
            str(LAUNCHER),
            "--worktree",
            str(worktree or self.worktree),
            "--prompt-file",
            str(prompt or self.prompt),
            *flags,
        ]

    def environment(self, status=0, **extra):
        env = os.environ.copy()
        env.pop("AGY_TEST_GATE", None)
        env.update(AGY_BIN=str(self.mock), AGY_TEST_EXIT_CODE=str(status), **extra)
        return env

    def launch(self, *flags, worktree=None, prompt=None, status=0):
        # The launcher runs from outside any checkout, as a controller in a
        # different worktree would; it refuses its own controller checkout.
        return subprocess.run(
            self.command(*flags, worktree=worktree, prompt=prompt),
            cwd=self.root, env=self.environment(status), capture_output=True, text=True,
            timeout=15,
        )

    def test_model_effort_and_prompt(self):
        for effort in EFFORTS:
            with self.subTest(effort=effort):
                result = self.launch("--effort", effort)
                self.assertEqual(result.returncode, 0, result.stderr)
                call = json.loads(result.stdout)
                args = call["args"]
                self.assertEqual(args[args.index("--model") + 1], "gemini-4-neon")
                self.assertEqual(args[args.index("--effort") + 1], effort)
                self.assertIn("--dangerously-skip-permissions", args)
                self.assertIn("--disable-slash-commands", args)
                self.assertNotIn("--sandbox", args)
                self.assertEqual(args[args.index("--output-format") + 1], "stream-json")
                # The prompt is attached to --print so a leading "-" is not
                # parsed as a flag, and is passed byte-for-byte minus the
                # trailing newline that $(<file) strips.
                self.assertEqual(args[-1], "--print=" + self.prompt_text.rstrip("\n"))
                self.assertEqual(Path(call["cwd"]).resolve(), self.worktree.resolve())
                self.assertIn(f"effort={effort}", result.stderr)

    def test_default_effort_is_high(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(result.stdout)["args"]
        self.assertEqual(args[args.index("--effort") + 1], "high")

    def test_rejects_unpublished_efforts_without_clamping(self):
        for effort in ("max", "ultra", "minimal", ""):
            with self.subTest(effort=effort):
                result = self.launch("--effort", effort)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid effort", result.stderr)

    def test_rejects_fast_and_model_override(self):
        for flags in (("--fast",), ("--model", "gemini-4-carbon")):
            with self.subTest(flags=flags):
                result = self.launch(*flags)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_requires_worktree_root_and_nonempty_prompt(self):
        sub = self.worktree / "sub"
        sub.mkdir()
        result = self.launch(worktree=sub)
        self.assertEqual(result.returncode, 2)
        self.assertIn("worktree root", result.stderr)
        empty = self.root / "empty.txt"
        empty.write_text(" \n")
        result = self.launch(prompt=empty)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Prompt file is empty", result.stderr)

    def test_requires_a_linked_worktree(self):
        result = self.launch(worktree=self.primary)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("dedicated linked git worktree", result.stderr)

    def test_refuses_concurrent_dispatch_into_one_worktree(self):
        gate = self.root / "gate"
        first = subprocess.Popen(
            self.command(), cwd=self.root, env=self.environment(AGY_TEST_GATE=str(gate)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: first.poll() is None and first.kill())
        started = Path(f"{gate}.started")
        deadline = time.monotonic() + 15
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(started.exists(), "first worker never started")
        second = self.launch()
        self.assertEqual(second.returncode, 2)
        self.assertEqual(second.stdout, "")
        self.assertIn("Refusing concurrent dispatch", second.stderr)
        gate.touch()
        stdout, stderr = first.communicate(timeout=15)
        self.assertEqual(first.returncode, 0, stderr)
        # The lock is released on exit: the next dispatch runs.
        self.assertEqual(self.launch().returncode, 0)

    def test_propagates_cli_exit_status(self):
        result = self.launch(status=7)
        self.assertEqual(result.returncode, 7)


if __name__ == "__main__":
    unittest.main()
