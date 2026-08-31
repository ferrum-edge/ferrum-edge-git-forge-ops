#!/usr/bin/env python3
"""Validate repository-local agent skills and Claude rules."""

from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FRONTMATTER = re.compile(r"\A---\n(?P<body>.*?)\n---\n", re.DOTALL)
NAME_LINE = re.compile(r"^name:\s*([A-Za-z0-9._-]+)\s*$", re.MULTILINE)
AGENT_REFERENCE = re.compile(r"\.agents/skills/([A-Za-z0-9._-]+)(/[A-Za-z0-9._/-]+)?")
MERGE_AUTHORIZATION = re.compile(
    r"user\b.{0,64}\b(?:authoriz|approv|confirm)", re.IGNORECASE | re.DOTALL
)
STALE_BRANDING = re.compile(
    r"\bFerrum Edge (?=(?:repository|codebase|task|issue|PR|implementer|worker|agent))",
    re.IGNORECASE,
)
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
    "repository-known flakes",
    "known flakes",
    "no-local-builds",
    "opencode-agents",
)
TEXT_SUFFIXES = {".json", ".md", ".py", ".sh", ".toml", ".yaml", ".yml"}
CLAUDE_ENV_OVERRIDES = (
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "CLAUDE_CODE_SUBAGENT_MODEL",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error


def frontmatter_name(path: Path, text: str) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    match = FRONTMATTER.search(text)
    if match is None:
        return None, [f"{path}: missing YAML frontmatter"]
    name = NAME_LINE.search(match.group("body"))
    if name is None:
        errors.append(f"{path}: frontmatter is missing a simple name field")
        return None, errors
    return name.group(1), errors


def frontmatter_paths(body: str) -> list[str]:
    paths: list[str] = []
    in_paths = False
    for line in body.splitlines():
        if re.fullmatch(r"paths:\s*", line):
            in_paths = True
            continue
        if not in_paths:
            continue
        if line and not line[0].isspace():
            break
        item = re.fullmatch(r"\s+-\s+(.+?)\s*", line)
        if item is not None:
            paths.append(item.group(1).strip("'\""))
    return paths


def expand_braces(pattern: str) -> list[str]:
    match = re.search(r"\{([^{}]+)\}", pattern)
    if match is None:
        return [pattern]
    expanded: list[str] = []
    for option in match.group(1).split(","):
        replacement = pattern[: match.start()] + option + pattern[match.end() :]
        expanded.extend(expand_braces(replacement))
    return expanded


def validate_rule_paths(root: Path, rule: Path, patterns: list[str]) -> list[str]:
    violations: list[str] = []
    for pattern in patterns:
        if not pattern or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            violations.append(f"{rule.relative_to(root)}: invalid path scope {pattern!r}")
            continue
        for expanded in expand_braces(pattern):
            if not any(root.glob(expanded)):
                violations.append(
                    f"{rule.relative_to(root)}: path scope matches nothing: {expanded!r}"
                )
    return violations


def text_files(directories: tuple[Path, ...]) -> list[Path]:
    found: set[Path] = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.suffix.lower() in TEXT_SUFFIXES:
                found.add(path)
    return sorted(found)


def collect_violations(root: Path) -> list[str]:
    root = root.resolve()
    violations: list[str] = []
    agent_skills = root / ".agents" / "skills"
    claude_root = root / ".claude"
    claude_skills = claude_root / "skills"
    claude_rules = claude_root / "rules"

    skill_files = sorted(agent_skills.glob("*/SKILL.md")) + sorted(
        claude_skills.glob("*/SKILL.md")
    )
    if not skill_files:
        return ["no repository-local agent skills were found"]

    for skill in skill_files:
        relative = skill.relative_to(root)
        if skill.is_symlink():
            violations.append(f"{relative}: skill file must not be a symlink")
            continue
        text = read_text(skill)
        name, errors = frontmatter_name(relative, text)
        violations.extend(errors)
        if name is not None and name != skill.parent.name:
            violations.append(
                f"{relative}: skill name {name!r} does not match directory {skill.parent.name!r}"
            )
        if "dispatched worker" not in text:
            violations.append(f"{relative}: missing dispatched-worker recursion guard")
        if MERGE_AUTHORIZATION.search(text) is None:
            violations.append(f"{relative}: missing explicit user authorization for merging")
        for match in AGENT_REFERENCE.finditer(text):
            suffix = match.group(2) or ""
            referenced = agent_skills / match.group(1) / suffix.lstrip("/")
            if not referenced.exists():
                violations.append(
                    f"{relative}: referenced path does not exist: {referenced.relative_to(root)}"
                )

    for rule in sorted(claude_rules.glob("*.md")):
        relative = rule.relative_to(root)
        if rule.is_symlink():
            violations.append(f"{relative}: rule file must not be a symlink")
            continue
        text = read_text(rule)
        match = FRONTMATTER.search(text)
        if match is None:
            violations.append(f"{relative}: missing YAML frontmatter")
            continue
        paths = frontmatter_paths(match.group("body"))
        if not paths:
            violations.append(f"{relative}: frontmatter is missing paths")
        else:
            violations.extend(validate_rule_paths(root, rule, paths))

    briefs = sorted(agent_skills.glob("*/references/agent-brief.md")) + [
        claude_skills / "sol-agents" / "agent-brief.md"
    ]
    for brief in briefs:
        relative = brief.relative_to(root)
        if brief.is_symlink():
            violations.append(f"{relative}: implementer brief must not be a symlink")
            continue
        if not brief.is_file():
            violations.append(f"{relative}: missing implementer brief")
            continue
        text = read_text(brief)
        for command in MANDATORY_COMMANDS:
            if command not in text:
                violations.append(f"{relative}: missing mandatory command {command!r}")

    for skill_dir in sorted(path for path in agent_skills.iterdir() if path.is_dir()):
        if skill_dir.name == "_lib":
            continue
        launcher = skill_dir / "scripts" / "dispatch-agent.sh"
        relative = launcher.relative_to(root)
        if launcher.is_symlink():
            violations.append(f"{relative}: dispatcher must not be a symlink")
        elif not launcher.is_file():
            violations.append(f"{relative}: missing dispatcher")
        elif not launcher.stat().st_mode & stat.S_IXUSR:
            violations.append(f"{relative}: dispatcher is not executable")

    for launcher in sorted(agent_skills.glob("*/scripts/dispatch-agent.sh")):
        if launcher.is_symlink() or not launcher.is_file():
            continue
        launcher_text = read_text(launcher)
        if 'exec "$claude_bin"' not in launcher_text:
            continue
        for variable in CLAUDE_ENV_OVERRIDES:
            if f"unset {variable}" not in launcher_text:
                violations.append(
                    f"{launcher.relative_to(root)}: inherited {variable} is not cleared"
                )

    for path in text_files((agent_skills, claude_root)):
        relative = path.relative_to(root)
        if path.is_symlink():
            violations.append(f"{relative}: setup content must not be a symlink")
            continue
        text = read_text(path)
        for marker in STALE_MARKERS:
            if marker in text:
                violations.append(
                    f"{relative}: stale companion-repository marker {marker!r}"
                )
        if STALE_BRANDING.search(text):
            violations.append(f"{relative}: human-facing project branding is not adapted")

    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        violations = collect_violations(args.root)
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
