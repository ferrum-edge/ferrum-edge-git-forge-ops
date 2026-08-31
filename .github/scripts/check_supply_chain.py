#!/usr/bin/env python3
"""Enforce immutable executable dependencies in CI and container builds."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_FILES = sorted(
    {
        *WORKFLOWS.glob("*.yml"),
        *WORKFLOWS.glob("*.yaml"),
        *(ROOT / ".github" / "actions").glob("**/action.yml"),
        *(ROOT / ".github" / "actions").glob("**/action.yaml"),
    }
)
ACTION_SHA = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", re.MULTILINE)
FROM = re.compile(r"^FROM\s+([^\s]+)", re.MULTILINE | re.IGNORECASE)


def trusted_classifier_violations(
    workflow: str, text: str, trusted_invocation: str, expected_count: int
) -> list[str]:
    violations: list[str] = []
    if text.count(trusted_invocation) != expected_count:
        violations.append(
            f"{workflow}: path scope must run exactly {expected_count} base-SHA trusted classifier invocation(s)"
        )
    if "ref: ${{ github.event.pull_request.base.sha }}" not in text:
        violations.append(
            f"{workflow}: trusted classifier checkout must pin the PR base SHA"
        )
    if "result=$(python3 .github/scripts/changed_files.py" in text:
        violations.append(
            f"{workflow}: path scope must not invoke the candidate-branch classifier"
        )
    return violations


def state_writer_token_violations(
    workflow: str, text: str, commit_step: str
) -> list[str]:
    violations: list[str] = []
    if "token: ${{ steps.state-writer.outputs.token }}" in text:
        violations.append(
            f"{workflow}: state-writer token must not be persisted by checkout"
        )
    install_index = text.rfind("run: cargo install --path . --locked")
    mint_index = text.find("- name: Mint narrowly scoped state-writer token")
    commit_index = text.find(commit_step)
    if not (install_index >= 0 and install_index < mint_index < commit_index):
        violations.append(
            f"{workflow}: state-writer token must be minted after untrusted builds and immediately before state persistence"
        )
    for required in (
        "STATE_WRITER_TOKEN: ${{ steps.state-writer.outputs.token }}",
        "git config --local http.https://github.com/.extraheader",
        "git config --local --unset-all http.https://github.com/.extraheader",
    ):
        if required not in text:
            violations.append(
                f"{workflow}: ephemeral push authentication is missing {required!r}"
            )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write-manifest",
        type=Path,
        help="write the exact reviewed build inputs after policy validation",
    )
    args = parser.parse_args()
    violations: list[str] = []
    action_pins: dict[str, list[str]] = {}
    for workflow in ACTION_FILES:
        text = workflow.read_text(encoding="utf-8")
        references = [reference.strip("'\"") for reference in USES.findall(text)]
        action_pins[str(workflow.relative_to(ROOT))] = references
        for reference in references:
            if reference.startswith("./"):
                continue
            if not ACTION_SHA.fullmatch(reference):
                violations.append(
                    f"{workflow.relative_to(ROOT)}: action is not pinned to a 40-hex commit: {reference}"
                )
        if "ubuntu-latest" in text:
            violations.append(
                f"{workflow.relative_to(ROOT)}: runner image must use an explicit Ubuntu release"
            )
        if "dtolnay/rust-toolchain" in text and "toolchain: 1.98.0" not in text:
            violations.append(
                f"{workflow.relative_to(ROOT)}: Rust action must select exact toolchain 1.98.0"
            )
        if "ferrum-edge-linux-x86_64" in text:
            violations.append(
                f"{workflow.relative_to(ROOT)}: download must go through install-ferrum-edge.sh"
            )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for image in FROM.findall(dockerfile):
        if "@sha256:" not in image:
            violations.append(f"Dockerfile: base image is not digest-pinned: {image}")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    if ".git" not in dockerignore:
        violations.append(".dockerignore must exclude .git from untrusted Docker builds")
    docker_instructions = "\n".join(
        line for line in dockerfile.splitlines() if not line.lstrip().startswith("#")
    )
    if re.search(r"\b(?:apt-get|apk|dnf|yum)\b", docker_instructions):
        violations.append(
            "Dockerfile: release stages must not install from mutable package repositories"
        )
    if "cargo build --release --locked" not in docker_instructions:
        violations.append("Dockerfile: Cargo release build must enforce Cargo.lock")

    rust_ci = (WORKFLOWS / "rust-ci.yml").read_text(encoding="utf-8")
    if "tool: cargo-llvm-cov@0.9.0" not in rust_ci:
        violations.append("rust-ci.yml: cargo-llvm-cov must use exact version 0.9.0")

    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    if "provenance: mode=max" not in release or "sbom: true" not in release:
        violations.append("release.yml: image provenance and SBOM must both be enabled")
    if "actions/attest-build-provenance@" not in release:
        violations.append("release.yml: signed GitHub build provenance is missing")
    for required in (
        "authorize-release:",
        "needs: authorize-release",
        "release commit must map to exactly one merged PR",
        'gh pr checks "$pr" --repo "$REPO" --required',
        "GitForgeOps PR Static Validation / required-static-validation",
    ):
        if required not in release:
            violations.append(
                f"release.yml: missing checked-merge publication gate {required!r}"
            )

    apply_workflow = (WORKFLOWS / "apply-on-merge.yml").read_text(encoding="utf-8")
    if "vars.FERRUM_GATEWAY_MODE != 'file'" in apply_workflow:
        violations.append("apply-on-merge.yml: inequality routing can send unknown modes to API")
    for required in (
        "case \"$mode\" in",
        "steps.deployment-mode.outputs.mode == 'api'",
        "steps.deployment-mode.outputs.mode == 'file'",
        ".github/scripts/merge_context.py",
    ):
        if required not in apply_workflow:
            violations.append(
                f"apply-on-merge.yml: explicit validated mode mapping is missing {required!r}"
            )

    for privileged_workflow in (
        "apply-on-merge.yml",
        "drift-check.yml",
        "materialize-file.yml",
        "rotate.yml",
    ):
        text = (WORKFLOWS / privileged_workflow).read_text(encoding="utf-8")
        if ".github/scripts/credential_bundles.py" not in text:
            violations.append(
                f"{privileged_workflow}: credential bundles must use the fail-closed loader"
            )
        if "except json.JSONDecodeError" in text:
            violations.append(
                f"{privileged_workflow}: malformed credential bundles must not fail open"
            )

    for rename_sensitive_workflow, trusted_invocation, expected_count in (
        (
            "rust-ci.yml",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            2,
        ),
        (
            "state-guard.yml",
            "helper=trusted-guard/.github/scripts/changed_files.py",
            1,
        ),
        (
            "validate-pr.yml",
            "result=$(python3 trusted-scope/.github/scripts/changed_files.py",
            1,
        ),
    ):
        text = (WORKFLOWS / rename_sensitive_workflow).read_text(encoding="utf-8")
        violations.extend(
            trusted_classifier_violations(
                rename_sensitive_workflow,
                text,
                trusted_invocation,
                expected_count,
            )
        )
    state_guard = (WORKFLOWS / "state-guard.yml").read_text(encoding="utf-8")
    if 'result=$(python3 "$helper"' not in state_guard:
        violations.append(
            "state-guard.yml: classifier execution must use the trusted helper variable"
        )

    for state_workflow, commit_step in (
        ("apply-on-merge.yml", "- name: Commit state + assembled (if changed)"),
        ("rotate.yml", "- name: Commit state update"),
    ):
        text = (WORKFLOWS / state_workflow).read_text(encoding="utf-8")
        violations.extend(
            state_writer_token_violations(state_workflow, text, commit_step)
        )

    static_review = (WORKFLOWS / "validate-pr.yml").read_text(encoding="utf-8")
    if re.search(r"^ {4}environment\s*:", static_review, re.MULTILINE):
        violations.append("validate-pr.yml: PR-built code must not bind an Environment")
    if re.search(r"\$\{\{[^}]*\bsecrets(?:\.|\[)", static_review):
        violations.append("validate-pr.yml: PR-built code must not receive any secrets")
    if re.search(r"^\s+paths\s*:", static_review, re.MULTILINE):
        violations.append(
            "validate-pr.yml: a path-filtered workflow cannot provide a stable required check"
        )
    for required in (
        "trusted-scope/.github/scripts/changed_files.py",
        "ref: ${{ github.event.pull_request.base.sha }}",
        "required-static-validation:",
        "if: always()",
    ):
        if required not in static_review:
            violations.append(
                f"validate-pr.yml: missing stable validation gate control {required!r}"
            )

    trusted_review = (WORKFLOWS / "trusted-pr-review.yml").read_text(
        encoding="utf-8"
    )
    for required in (
        "workflow_run.conclusion == 'success'",
        "steps.metadata.outputs.privileged == 'true'",
        "Add trusted environment and policy configuration",
        "FERRUM_NAMESPACE: ${{ matrix.namespace }}",
        "--include-scopes",
        "--require-live",
        "pr_input.py targets",
        "pr_input.py verify",
        "Verify trusted binary digest",
        "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
        "select(.base.ref == $base)",
        "current_base=$(jq -r '.base.ref'",
    ):
        if required not in trusted_review:
            violations.append(
                f"trusted-pr-review.yml: missing privileged-boundary guard {required!r}"
            )

    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(
        encoding="utf-8"
    )
    owned_patterns = {
        line.split()[0]
        for line in codeowners.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and line.split()
    }
    for required_pattern in (
        "/.github/workflows/",
        "/.github/scripts/",
        "/.github/cargo-audit-policy.json",
        "/.github/ferrum-edge-checksums.txt",
        "/.gitforgeops/",
        "/.state/",
        "/Cargo.toml",
        "/Cargo.lock",
        "/rust-toolchain.toml",
        "/src/",
    ):
        if required_pattern not in owned_patterns:
            violations.append(
                f"CODEOWNERS: launch-critical path is not explicitly owned: {required_pattern}"
            )

    for manual_workflow in ("materialize-file.yml", "rotate.yml"):
        text = (WORKFLOWS / manual_workflow).read_text(encoding="utf-8")
        for required in (
            "Require protected default branch",
            "SOURCE_REF",
            "EXPECTED_REF",
            "Environment must be a single safe path component",
            "Environment is not declared by the protected main configuration",
        ):
            if required not in text:
                violations.append(
                    f"{manual_workflow}: missing manual-dispatch guard {required!r}"
                )

    toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    if 'channel = "1.98.0"' not in toolchain:
        violations.append("rust-toolchain.toml: channel must be pinned to 1.98.0")

    installer = (ROOT / ".github" / "scripts" / "install-ferrum-edge.sh").read_text(
        encoding="utf-8"
    )
    for required in (
        "ferrum-edge-checksums.txt",
        "expected_sha256",
        "published_sha256",
        "actual_sha256",
    ):
        if required not in installer:
            violations.append(
                f"install-ferrum-edge.sh: missing {required} checksum comparison"
            )
    if "FERRUM_EDGE_SHA256" in "\n".join(
        workflow.read_text(encoding="utf-8") for workflow in ACTION_FILES
    ):
        violations.append(
            "workflows must not replace the checked-in validator digest with a mutable variable"
        )

    checksum_policy = ROOT / ".github" / "ferrum-edge-checksums.txt"
    pins = [
        line.split()
        for line in checksum_policy.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not pins or any(
        len(pin) != 3
        or pin[1] != "ferrum-edge-linux-x86_64"
        or not re.fullmatch(r"[0-9a-f]{64}", pin[2])
        for pin in pins
    ):
        violations.append("ferrum-edge-checksums.txt contains a malformed release pin")

    if violations:
        print("Supply-chain policy violations:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1
    if args.write_manifest:
        manifest = {
            "schema_version": 1,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "runner_image": "ubuntu-24.04",
            "rust_toolchain": "1.98.0",
            "actions": action_pins,
            "docker_bases": FROM.findall(dockerfile),
            "ferrum_edge_binaries": [
                {"version": pin[0], "asset": pin[1], "sha256": pin[2]}
                for pin in pins
            ],
        }
        args.write_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print("All Actions, Rust, validator, and container inputs are immutably pinned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
