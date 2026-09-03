#!/usr/bin/env python3
"""Run cargo-audit and enforce reviewed, expiring dependency-risk exceptions."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable


MAX_REVIEW_HORIZON_DAYS = 120
REVIEW_WARNING_WINDOW_DAYS = 21
REQUIRED_TEXT_FIELDS = (
    "kind",
    "package",
    "version",
    "source",
    "owner",
    "review_by",
    "rationale",
    "upstream",
)
REQUIRED_LIST_FIELDS = ("affected_call_paths", "compensating_controls")

# cargo-audit buckets that fail the build. Everything else (unmaintained,
# notice, ...) is reported as a non-fatal GitHub annotation: an advisory that
# only says "this crate is no longer maintained" must not turn every open pull
# request red before a human can write a reviewed exception for it.
BLOCKING_KINDS = frozenset({"vulnerability", "unsound", "yanked"})

# Reachability verifiers are selected by the exception's own `reachability`
# field, or by (kind, advisory, package) for the entries that predate it.
# Version is deliberately NOT part of the selector: a patch bump of the
# vulnerable crate must not silently switch the verifier off.
AGE_ENCRYPTION_ONLY = "age-encryption-only"
IMPLICIT_REACHABILITY: dict[tuple[str, str, str], str] = {
    ("vulnerability", "RUSTSEC-2023-0071", "rsa"): AGE_ENCRYPTION_ONLY,
}
# Packages whose exceptions must always resolve to a verifier. An rsa
# exception the gate cannot machine-check is a policy error, never a pass.
VERIFIER_REQUIRED_PACKAGES = frozenset({"rsa"})

EXPECTED_RSA_TREE = re.compile(
    r"^rsa v0\.9\.\d+\n"
    r"└── age v0\.12\.\d+\n"
    r"    └── gitforgeops v\d+\.\d+\.\d+ \([^\n]+\)\n?$"
)
AGE_VERSION_REQUIREMENT = re.compile(r"^0\.12(?:\.\d+)?$")
REQUIRED_AGE_FEATURES = frozenset({"ssh", "armor"})
REVIEWED_AGE_MODULE = Path("src/secrets/delivery.rs")
ALLOWED_AGE_REFERENCES = {
    "age::Encryptor",
    "age::Recipient",
    "age::armor::ArmoredWriter",
    "age::armor::Format",
    "age::ssh::Recipient",
}
AGE_REFERENCE = re.compile(r"\bage(?:::[A-Za-z_][A-Za-z0-9_]*)+")
CARGO_TREE_NO_MATCH = "did not match any packages"

_RAW_STRING_START = re.compile(r'b?r(?P<hashes>#*)"')
_CHAR_LITERAL = re.compile(r"b?'(?:\\.|[^\\'\n])'")


class PolicyError(ValueError):
    """Raised when the checked-in exception policy is malformed."""


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_ident_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def strip_rust_comments_and_strings(text: str) -> str:
    """Blank out comments, string literals, and character literals.

    Removed spans become spaces (newlines preserved) so line structure and the
    surrounding statement text survive. A `// age::Decryptor` note, a doc
    comment, or a "age::Decryptor" string is documentation, not a call, and
    must not trip the API allowlist.
    """
    out: list[str] = []
    index = 0
    length = len(text)

    def blank(span: str) -> None:
        out.append("".join("\n" if char == "\n" else " " for char in span))

    while index < length:
        char = text[index]
        preceded_by_ident = index > 0 and _is_ident_char(text[index - 1])

        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end == -1 else end
            blank(text[index:end])
            index = end
            continue

        if text.startswith("/*", index):
            start = index
            depth = 0
            while index < length:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                    if depth == 0:
                        break
                else:
                    index += 1
            blank(text[start:index])
            continue

        if char in ("r", "b") and not preceded_by_ident:
            raw = _RAW_STRING_START.match(text, index)
            if raw:
                terminator = '"' + raw.group("hashes")
                end = text.find(terminator, raw.end())
                end = length if end == -1 else end + len(terminator)
                blank(text[index:end])
                index = end
                continue

        if char == '"' or (
            char == "b" and text.startswith('b"', index) and not preceded_by_ident
        ):
            start = index
            index += 2 if char == "b" else 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            blank(text[start:index])
            continue

        if char in ("'", "b") and not preceded_by_ident:
            literal = _CHAR_LITERAL.match(text, index)
            if literal:
                blank(literal.group(0))
                index = literal.end()
                continue

        out.append(char)
        index += 1

    return "".join(out)


def _finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(finding["kind"]),
        str(finding.get("advisory") or ""),
        str(finding["package"]),
        str(finding["version"]),
        str(finding["source"]),
    )


def collect_findings(report: dict[str, Any]) -> list[dict[str, str | None]]:
    """Flatten cargo-audit's vulnerability and warning buckets."""
    findings: list[dict[str, str | None]] = []

    vulnerability_section = report.get("vulnerabilities", {})
    if not isinstance(vulnerability_section, dict):
        raise PolicyError("cargo-audit report has a malformed vulnerabilities object")
    vulnerabilities = vulnerability_section.get("list", [])
    if not isinstance(vulnerabilities, list):
        raise PolicyError("cargo-audit report has a malformed vulnerabilities.list")
    for item in vulnerabilities:
        try:
            findings.append(
                {
                    "kind": "vulnerability",
                    "advisory": item["advisory"]["id"],
                    "package": item["package"]["name"],
                    "version": item["package"]["version"],
                    "source": item["package"]["source"],
                }
            )
        except (KeyError, TypeError) as exc:
            raise PolicyError("cargo-audit returned a malformed vulnerability") from exc

    reported_count = vulnerability_section.get("count")
    if reported_count is not None and reported_count != len(vulnerabilities):
        raise PolicyError(
            f"cargo-audit reported {reported_count} vulnerabilities but this gate "
            f"parsed {len(vulnerabilities)}; the report shape changed"
        )

    warnings = report.get("warnings", {})
    if not isinstance(warnings, dict):
        raise PolicyError("cargo-audit report has a malformed warnings object")
    for warning_kind, entries in warnings.items():
        if not isinstance(entries, list):
            raise PolicyError(f"cargo-audit warning bucket {warning_kind!r} is not a list")
        for item in entries:
            try:
                advisory = item.get("advisory")
                findings.append(
                    {
                        "kind": str(warning_kind),
                        "advisory": advisory.get("id") if advisory else None,
                        "package": item["package"]["name"],
                        "version": item["package"]["version"],
                        "source": item["package"]["source"],
                    }
                )
            except (KeyError, TypeError) as exc:
                raise PolicyError(
                    f"cargo-audit returned a malformed {warning_kind!r} warning"
                ) from exc

    return findings


def load_policy(
    path: Path, today: dt.date
) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read audit policy {path}: {exc}") from exc

    if raw.get("schema_version") != 1:
        raise PolicyError("audit policy schema_version must be 1")
    exceptions = raw.get("exceptions")
    if not isinstance(exceptions, list):
        raise PolicyError("audit policy exceptions must be a list")

    indexed: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for index, exception in enumerate(exceptions):
        label = f"exceptions[{index}]"
        if not isinstance(exception, dict):
            raise PolicyError(f"{label} must be an object")
        for field in REQUIRED_TEXT_FIELDS:
            if not _nonempty_text(exception.get(field)):
                raise PolicyError(f"{label}.{field} must be non-empty text")
        for field in REQUIRED_LIST_FIELDS:
            values = exception.get(field)
            if not isinstance(values, list) or not values or not all(
                _nonempty_text(value) for value in values
            ):
                raise PolicyError(f"{label}.{field} must be a non-empty text list")

        kind = exception["kind"]
        advisory = exception.get("advisory")
        if kind != "yanked" and not _nonempty_text(advisory):
            raise PolicyError(f"{label}.advisory is required for {kind!r} findings")
        if kind == "yanked" and advisory not in (None, ""):
            raise PolicyError(f"{label}.advisory must be null for yanked packages")

        if "reachability" in exception and not _nonempty_text(exception["reachability"]):
            raise PolicyError(f"{label}.reachability must be non-empty text when present")

        try:
            review_by = dt.date.fromisoformat(exception["review_by"])
        except ValueError as exc:
            raise PolicyError(f"{label}.review_by must use YYYY-MM-DD") from exc
        if review_by < today:
            raise PolicyError(
                f"{label} expired on {review_by.isoformat()}; remove or re-review it"
            )
        horizon = (review_by - today).days
        if horizon > MAX_REVIEW_HORIZON_DAYS:
            raise PolicyError(
                f"{label}.review_by is {horizon} days away; maximum is "
                f"{MAX_REVIEW_HORIZON_DAYS}"
            )

        key = _finding_key(exception)
        if key in indexed:
            raise PolicyError(f"duplicate audit exception for {key}")
        indexed[key] = exception

    return indexed


def review_deadline_warnings(
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]], today: dt.date
) -> list[str]:
    """Warn before an exception expires; expiry itself is a hard, repo-wide stop."""
    annotations: list[str] = []
    for key in sorted(policy):
        exception = policy[key]
        try:
            review_by = dt.date.fromisoformat(str(exception["review_by"]))
        except (KeyError, ValueError):  # pragma: no cover - load_policy validated it
            continue
        remaining = (review_by - today).days
        if remaining > REVIEW_WARNING_WINDOW_DAYS:
            continue
        advisory = f" ({exception['advisory']})" if exception.get("advisory") else ""
        annotations.append(
            f"::warning::cargo-audit exception for {exception['package']} "
            f"{exception['version']}{advisory} is due for re-review by "
            f"{review_by.isoformat()} ({remaining} day(s) left, owner "
            f"{exception['owner']}); once it expires every pull request, push, and "
            "scheduled security run fails"
        )
    return annotations


def evaluate(
    report: dict[str, Any],
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]],
) -> tuple[
    list[dict[str, str | None]],
    list[dict[str, str | None]],
    list[tuple[str, str, str, str, str]],
    list[dict[str, str | None]],
]:
    findings = collect_findings(report)
    reviewed: list[dict[str, str | None]] = []
    blocked: list[dict[str, str | None]] = []
    informational: list[dict[str, str | None]] = []
    used: set[tuple[str, str, str, str, str]] = set()

    for finding in findings:
        key = _finding_key(finding)
        if key in policy:
            reviewed.append(finding)
            used.add(key)
        elif str(finding["kind"]) in BLOCKING_KINDS:
            blocked.append(finding)
        else:
            informational.append(finding)

    stale = sorted(set(policy) - used)
    return reviewed, blocked, stale, informational


def _read_dependency_tree(
    package: str, version: str, source_root: Path, dependency_tree_path: Path | None
) -> str:
    if dependency_tree_path is not None:
        try:
            return dependency_tree_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(
                f"cannot inspect dependency tree {dependency_tree_path}: {exc}"
            ) from exc

    spec = f"{package}@{version}"
    try:
        result = subprocess.run(
            [
                "cargo",
                "tree",
                "--color",
                "never",
                "--locked",
                "--target",
                "all",
                "-i",
                spec,
            ],
            cwd=source_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise PolicyError(
            f"could not inspect the {package} dependency path: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        if CARGO_TREE_NO_MATCH in detail:
            raise PolicyError(
                f"stale exception: {spec} is no longer in the dependency graph. "
                "Remove the entry from .github/cargo-audit-policy.json (or update "
                "its version if the dependency was upgraded rather than dropped)."
            )
        raise PolicyError(f"cargo tree failed while checking the {package} path: {detail}")
    return result.stdout


def verify_age_encryption_only(
    exception: dict[str, Any], source_root: Path, dependency_tree_path: Path | None
) -> None:
    """Fail closed if the RSA exception outlives its encryption-only premise."""
    manifest_path = source_root / "Cargo.toml"
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot inspect {manifest_path}: {exc}") from exc
    age_dependency = manifest.get("dependencies", {}).get("age")
    if not isinstance(age_dependency, dict):
        raise PolicyError("RSA exception requires age to use an explicit dependency table")
    version = age_dependency.get("version")
    features = age_dependency.get("features")
    if (
        not isinstance(version, str)
        or not AGE_VERSION_REQUIREMENT.fullmatch(version)
        or not isinstance(features, list)
        or set(features) != REQUIRED_AGE_FEATURES
    ):
        raise PolicyError(
            "RSA exception requires an age 0.12 requirement with exactly the "
            "ssh and armor features"
        )

    source_dir = source_root / "src"
    if not source_dir.is_dir():
        raise PolicyError(f"RSA exception source directory is missing: {source_dir}")
    for path in sorted(source_dir.rglob("*.rs")):
        try:
            raw_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(f"cannot inspect {path}: {exc}") from exc
        # Comments and string literals are prose, not reachable calls.
        text = strip_rust_comments_and_strings(raw_text)
        relative = path.relative_to(source_root)
        references = set(AGE_REFERENCE.findall(text))
        if references and relative != REVIEWED_AGE_MODULE:
            raise PolicyError(
                f"RSA exception permits age calls only in {REVIEWED_AGE_MODULE}; "
                f"found {relative}"
            )
        for reference in sorted(references):
            allowed = any(
                reference == prefix or reference.startswith(f"{prefix}::")
                for prefix in ALLOWED_AGE_REFERENCES
            )
            if not allowed:
                raise PolicyError(
                    f"RSA exception encountered an unreviewed age API reference: "
                    f"{reference}"
                )
        age_use_statements = re.findall(
            r"^\s*use\s+(?:::)?age(?:\s|::).*?;\s*$", text, re.MULTILINE
        )
        if age_use_statements and (
            relative != REVIEWED_AGE_MODULE
            or [statement.strip() for statement in age_use_statements]
            != ["use age::ssh::Recipient;"]
        ):
            raise PolicyError(
                "RSA exception permits only the reviewed age::ssh::Recipient import"
            )
        if re.search(r"\bextern\s+crate\s+age\b|\bage\s*::\s*\{", text):
            raise PolicyError("RSA exception forbids alternate age import forms")

    dependency_tree = _read_dependency_tree(
        str(exception["package"]),
        str(exception["version"]),
        source_root,
        dependency_tree_path,
    )
    if not EXPECTED_RSA_TREE.fullmatch(dependency_tree):
        raise PolicyError(
            "RSA exception dependency path changed; expected only "
            "gitforgeops -> age 0.12.x -> rsa 0.9.x"
        )


REACHABILITY_VERIFIERS: dict[
    str, Callable[[dict[str, Any], Path, Path | None], None]
] = {
    AGE_ENCRYPTION_ONLY: verify_age_encryption_only,
}


def _reachability_verifier_name(
    key: tuple[str, str, str, str, str], exception: dict[str, Any]
) -> str | None:
    declared = exception.get("reachability")
    if declared is not None:
        return str(declared).strip()
    kind, advisory, package, _version, _source = key
    return IMPLICIT_REACHABILITY.get((kind, advisory, package))


def verify_exception_reachability(
    policy: dict[tuple[str, str, str, str, str], dict[str, Any]],
    source_root: Path,
    dependency_tree_path: Path | None,
) -> None:
    """Run every exception's reachability verifier, or refuse to accept it."""
    for key in sorted(policy):
        exception = policy[key]
        package = key[2]
        name = _reachability_verifier_name(key, exception)
        if name is None:
            if package in VERIFIER_REQUIRED_PACKAGES:
                raise PolicyError(
                    f"exception for {package} {key[3]} has no reachability verifier; "
                    f'set "reachability" to one of '
                    f"{sorted(REACHABILITY_VERIFIERS)} or remove the exception"
                )
            continue
        verifier = REACHABILITY_VERIFIERS.get(name)
        if verifier is None:
            raise PolicyError(
                f"exception for {package} {key[3]} requests unknown reachability "
                f"verifier {name!r}; known verifiers are "
                f"{sorted(REACHABILITY_VERIFIERS)}"
            )
        verifier(exception, source_root, dependency_tree_path)


def _format_finding(finding: dict[str, str | None]) -> str:
    advisory = f" {finding['advisory']}" if finding.get("advisory") else ""
    return (
        f"{finding['kind']}{advisory}: "
        f"{finding['package']} {finding['version']}"
    )


def run_cargo_audit(source_root: Path) -> tuple[dict[str, Any], int]:
    try:
        result = subprocess.run(
            ["cargo", "audit", "--json", "--deny", "unsound", "--deny", "yanked"],
            cwd=source_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise PolicyError(f"could not execute cargo audit: {exc}") from exc

    try:
        return json.loads(result.stdout), result.returncode
    except json.JSONDecodeError as exc:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise PolicyError(f"cargo audit did not return JSON: {detail}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(".github/cargo-audit-policy.json"),
        help="checked-in exception policy",
    )
    parser.add_argument(
        "--audit-json",
        type=Path,
        help="read a saved cargo-audit JSON report instead of invoking cargo audit",
    )
    parser.add_argument(
        "--audit-exit-status",
        type=int,
        default=0,
        help="cargo-audit exit status to assume alongside --audit-json (tests)",
    )
    parser.add_argument(
        "--today",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        help="policy evaluation date (YYYY-MM-DD; intended for tests)",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("."),
        help="repository root whose exception reachability premises must be verified",
    )
    parser.add_argument(
        "--dependency-tree",
        type=Path,
        help="read a saved cargo-tree result instead of invoking cargo tree (tests)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_root = args.source_root.resolve()
    try:
        policy = load_policy(args.policy, args.today)
        verify_exception_reachability(policy, source_root, args.dependency_tree)
        if args.audit_json:
            report = json.loads(args.audit_json.read_text(encoding="utf-8"))
            audit_status = args.audit_exit_status
        else:
            report, audit_status = run_cargo_audit(source_root)
        reviewed, blocked, stale, informational = evaluate(report, policy)
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(f"cargo-audit policy error: {exc}", file=sys.stderr)
        return 2

    for annotation in review_deadline_warnings(policy, args.today):
        print(annotation)

    for finding in reviewed:
        exception = policy[_finding_key(finding)]
        print(
            f"REVIEWED until {exception['review_by']} by {exception['owner']}: "
            f"{_format_finding(finding)}"
        )
    for finding in informational:
        advisory = finding.get("advisory") or "no advisory id"
        print(
            f"::warning::cargo-audit {finding['kind']} {advisory} affects "
            f"{finding['package']} {finding['version']} (reported, not blocking)"
        )

    parsed_findings = len(reviewed) + len(blocked) + len(informational)
    if audit_status == 1 and parsed_findings == 0:
        print(
            "cargo audit reported findings this gate could not parse",
            file=sys.stderr,
        )
        return 2
    if audit_status not in (0, 1):
        print(f"cargo audit failed operationally with exit {audit_status}", file=sys.stderr)
        return 2

    if blocked:
        print("Unreviewed cargo-audit findings:", file=sys.stderr)
        for finding in blocked:
            print(f"  - {_format_finding(finding)}", file=sys.stderr)
    if stale:
        print("Stale cargo-audit exceptions (finding no longer present):", file=sys.stderr)
        for key in stale:
            print(f"  - {key}", file=sys.stderr)
    if blocked or stale:
        return 1

    print(
        f"cargo-audit policy passed: {len(reviewed)} reviewed exception(s), "
        f"{len(informational)} non-blocking advisory warning(s), "
        "no unreviewed vulnerability/unsound/yanked findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
