#!/usr/bin/env python3
"""Validate repository-local agent skills and Claude rules."""

from __future__ import annotations

import re
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FRONTMATTER_NAME = re.compile(r"\A---\n(?P<body>.*?)\n---\n", re.DOTALL)
NAME_LINE = re.compile(r"^name:\s*([A-Za-z0-9._-]+)\s*$", re.MULTILINE)
AGENT_REFERENCE = re.compile(r"\.agents/skills/([A-Za-z0-9._-]+)(/[A-Za-z0-9._/-]+)?")
STALE_BRANDING = re.compile(r"Ferrum Edge(?! Git Forge Ops)")
MANDATORY_COMMANDS = (
    "cargo fmt --all",
    "cargo clippy --all-targets -- -D warnings",
    "cargo test --test unit_tests",
)
STALE_MARKERS = (
    "-p ferrum-edge",
    "--bin ferrum-edge",
    "docs/configuration.md",
    "ferrum.conf",
    "tests/integration/",
    "tests/functional/",
    "tests/conformance/",
    "openapi.yaml",
    "PR #2048",
    "backend_accepts_then_rst_returns_502__grpc_to_grpc",
    "h3_native_grpc_server_streaming_preserves_frames_and_trailers",
    "Known historical Ferrum Edge Git Forge Ops flakes",
    "no-local-builds",
    "opencode-agents",
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error


def frontmatter_name(path: Path, text: str) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    match = FRONTMATTER_NAME.search(text)
    if match is None:
        return None, [f"{path}: missing YAML frontmatter"]
    name = NAME_LINE.search(match.group("body"))
    if name is None:
        errors.append(f"{path}: frontmatter is missing a simple name field")
        return None, errors
    return name.group(1), errors


def collect_violations(root: Path) -> list[str]:
    violations: list[str] = []
    agent_skills = root / ".agents" / "skills"
    claude_skills = root / ".claude" / "skills"
    claude_rules = root / ".claude" / "rules"

    skill_files = sorted(agent_skills.glob("*/SKILL.md")) + sorted(
        claude_skills.glob("*/SKILL.md")
    )
    if not skill_files:
        return ["no repository-local agent skills were found"]

    for skill in skill_files:
        text = read_text(skill)
        name, errors = frontmatter_name(skill.relative_to(root), text)
        violations.extend(errors)
        if name is not None and name != skill.parent.name:
            violations.append(
                f"{skill.relative_to(root)}: skill name {name!r} does not match directory {skill.parent.name!r}"
            )
        if "dispatched worker" not in text:
            violations.append(
                f"{skill.relative_to(root)}: missing dispatched-worker recursion guard"
            )
        if "Merge only when" in text and re.search(
            r"user\b.{0,24}\bauthoriz", text, re.IGNORECASE | re.DOTALL
        ) is None:
            violations.append(
                f"{skill.relative_to(root)}: merge rule lacks explicit user authorization"
            )
        for marker in STALE_MARKERS:
            if marker in text:
                violations.append(
                    f"{skill.relative_to(root)}: stale companion-repository marker {marker!r}"
                )

    for rule in sorted(claude_rules.glob("*.md")):
        text = read_text(rule)
        match = FRONTMATTER_NAME.search(text)
        if match is None:
            violations.append(f"{rule.relative_to(root)}: missing YAML frontmatter")
        elif not re.search(r"^paths:\s*$", match.group("body"), re.MULTILINE):
            violations.append(f"{rule.relative_to(root)}: frontmatter is missing paths")
        for marker in STALE_MARKERS:
            if marker in text:
                violations.append(
                    f"{rule.relative_to(root)}: stale companion-repository marker {marker!r}"
                )

    for brief in sorted(agent_skills.glob("*/references/agent-brief.md")) + [
        claude_skills / "sol-agents" / "agent-brief.md"
    ]:
        if not brief.is_file():
            violations.append(f"{brief.relative_to(root)}: missing implementer brief")
            continue
        text = read_text(brief)
        for command in MANDATORY_COMMANDS:
            if command not in text:
                violations.append(
                    f"{brief.relative_to(root)}: missing mandatory command {command!r}"
                )
        for marker in STALE_MARKERS:
            if marker in text:
                violations.append(
                    f"{brief.relative_to(root)}: stale companion-repository marker {marker!r}"
                )

    for skill in sorted(claude_skills.glob("*/SKILL.md")):
        text = read_text(skill)
        for match in AGENT_REFERENCE.finditer(text):
            suffix = match.group(2) or ""
            if "*" in suffix:
                continue
            referenced = agent_skills / match.group(1) / suffix.lstrip("/")
            if not referenced.exists():
                violations.append(
                    f"{skill.relative_to(root)}: referenced path does not exist: "
                    f"{referenced.relative_to(root)}"
                )

    for skill_dir in sorted(path for path in agent_skills.iterdir() if path.is_dir()):
        if skill_dir.name == "_lib":
            continue
        launcher = skill_dir / "scripts" / "dispatch-agent.sh"
        if not launcher.is_file():
            violations.append(f"{launcher.relative_to(root)}: missing dispatcher")
        elif not launcher.stat().st_mode & stat.S_IXUSR:
            violations.append(f"{launcher.relative_to(root)}: dispatcher is not executable")

    opus_launcher = agent_skills / "opus-agents" / "scripts" / "dispatch-agent.sh"
    if opus_launcher.is_file():
        opus_text = read_text(opus_launcher)
        for variable in ("ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL"):
            if f"unset {variable}" not in opus_text:
                violations.append(
                    f"{opus_launcher.relative_to(root)}: inherited {variable} is not cleared"
                )

    for directory in (agent_skills, root / ".claude"):
        for path in sorted(candidate for candidate in directory.rglob("*") if candidate.is_file()):
            if STALE_BRANDING.search(read_text(path)):
                violations.append(
                    f"{path.relative_to(root)}: human-facing project branding is not adapted"
                )

    return violations


def main() -> int:
    try:
        violations = collect_violations(ROOT)
    except RuntimeError as error:
        print(f"agent setup validation failed: {error}", file=sys.stderr)
        return 2
    if violations:
        for violation in violations:
            print(f"agent setup violation: {violation}", file=sys.stderr)
        return 1
    print("Agent skills, dispatchers, references, and Claude rules are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
