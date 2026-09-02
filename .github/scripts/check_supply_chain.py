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
ACTION_SHA = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", re.MULTILINE)
FROM = re.compile(r"^FROM\s+([^\s]+)", re.MULTILINE | re.IGNORECASE)


def action_files(root: Path) -> list[Path]:
    workflows = root / ".github" / "workflows"
    return sorted(
        {
            *workflows.glob("*.yml"),
            *workflows.glob("*.yaml"),
            *(root / ".github" / "actions").glob("**/action.yml"),
            *(root / ".github" / "actions").glob("**/action.yaml"),
        }
    )


def trusted_classifier_violations(
    workflow: str, text: str, trusted_invocation: str, expected_count: int
) -> list[str]:
    violations: list[str] = []
    if text.count(trusted_invocation) != expected_count:
        violations.append(
            f"{workflow}: path scope must run exactly {expected_count} default-branch trusted classifier invocation(s)"
        )
    if "ref: ${{ github.event.repository.default_branch }}" not in text:
        violations.append(
            f"{workflow}: trusted classifier checkout must use the protected default branch"
        )
    if "ref: ${{ github.event.pull_request.base.sha }}" in text:
        violations.append(
            f"{workflow}: unprotected PR base SHA must not supply trusted classifier code"
        )
    if "result=$(python3 .github/scripts/changed_files.py" in text:
        violations.append(
            f"{workflow}: path scope must not invoke the candidate-branch classifier"
        )
    if "trusted-scope/" in trusted_invocation:
        fail_safe = "result='{\"complete\":false,\"matches\":true}'"
        if text.count(fail_safe) != expected_count:
            violations.append(
                f"{workflow}: every trusted classifier invocation needs a bootstrap fail-safe"
            )
    return violations


def pull_request_trigger_violations(
    workflow: str, text: str, trigger: str = "pull_request"
) -> list[str]:
    violations: list[str] = []
    match = re.search(
        rf"^  {re.escape(trigger)}:\s*$\n(?P<body>(?:^    .*\n)*)",
        text,
        re.MULTILINE,
    )
    if match is None:
        return [f"{workflow}: {trigger} trigger is missing"]
    body = match.group("body")
    if not re.search(r"^    types: \[[^\n]*\bedited\b", body, re.MULTILINE):
        violations.append(
            f"{workflow}: {trigger} trigger must rerun on base-retarget edits"
        )
    if "    branches: [main]" not in body:
        violations.append(
            f"{workflow}: {trigger} trigger must target only protected main"
        )
    return violations


def state_guard_trigger_violations(text: str) -> list[str]:
    """The ownership-ledger guard must run the definition `main` reviewed.

    Under `on: pull_request` the workflow file itself comes from the pull
    request's head, so one commit could both forge `.state/<env>.json` and
    delete the guard that rejects it, and the check would report success.
    `pull_request_target` always loads the definition from the default branch.

    That trigger is only safe while the job never materializes PR-authored
    bytes, so the two halves are enforced together: the trigger, and the
    absence of any checkout of the pull request's head.
    """
    violations = pull_request_trigger_violations(
        "state-guard.yml", text, "pull_request_target"
    )
    if re.search(r"^  pull_request:\s*$", text, re.MULTILINE):
        violations.append(
            "state-guard.yml: the guard must not also accept the head-loaded pull_request trigger"
        )
    for untrusted_ref in (
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.repo",
    ):
        if f"ref: ${{{{ {untrusted_ref} }}}}" in text:
            violations.append(
                f"state-guard.yml: pull_request_target must never check out {untrusted_ref}"
            )
    checkouts = re.findall(r"^\s*(?:-\s*)?uses:\s*actions/checkout@", text, re.MULTILINE)
    if len(checkouts) != 1:
        violations.append(
            "state-guard.yml: exactly one checkout is permitted, and it must name the default branch"
        )
    return violations


def rust_toolchain_violations(workflow: str, text: str) -> list[str]:
    """Every `dtolnay/rust-toolchain` step must select the exact toolchain.

    Checking that `toolchain: 1.98.0` appears *somewhere* in the file let a
    second Rust step — or a copied step that lost its `with:` block — install
    the action's floating default while the first step's pin kept the workflow
    green. Match per step instead.
    """
    for step in re.split(r"\n(?=\s*-\s+(?:name|uses):)", text):
        if "dtolnay/rust-toolchain@" not in step:
            continue
        if not re.search(r"^\s*toolchain:\s*1\.98\.0\s*$", step, re.MULTILINE):
            return [
                f"{workflow}: every dtolnay/rust-toolchain step must select exact toolchain 1.98.0"
            ]
    return []


def unconfigured_repo_skip_violations(text: str) -> list[str]:
    """`apply-on-merge.yml` must SKIP, not fail, on an unconfigured repository.

    This workflow fires on every push to `main`, including the merge that first
    adds `.gitforgeops/config.example.yaml` to a repo nobody has configured yet.
    Hard-failing there turns `main` red for a state that is simply not set up.
    An empty matrix carries the same guarantee — the `apply` job is gated on a
    non-empty matrix, so no GitHub Environment is bound and the synthetic local
    `default` environment is never applied — without the red workflow.

    Workflows a human explicitly starts keep failing loudly; there the absent
    configuration contradicts a stated intent.
    """
    violations: list[str] = []
    for required in (
        'if [[ ! -f .gitforgeops/config.yaml ]]; then',
        'echo "envs=[]" >> "$GITHUB_OUTPUT"',
        "needs.list-envs.outputs.envs != '[]'",
    ):
        if required not in text:
            violations.append(
                f"apply-on-merge.yml: an unconfigured repository must skip via an empty matrix, missing {required!r}"
            )
    if (
        "Repository configuration is required before binding a deployment environment."
        in text
    ):
        violations.append(
            "apply-on-merge.yml: a push-triggered apply must not fail the merge on absent repository configuration"
        )
    return violations


def state_writer_preflight_violations(workflow: str, text: str) -> list[str]:
    """The state-writer App must be proven present BEFORE the gateway mutation.

    The token itself is minted late on purpose (see
    `state_writer_token_violations`), which means an environment missing the App
    credentials would mutate the gateway and only then fail to record what it
    did. Shared mode reads the missing ledger entries as "never managed" and
    stops reconciling those resources.
    """
    violations: list[str] = []
    preflight = text.find("- name: Require state-writer App credentials")
    if preflight < 0:
        return [
            f"{workflow}: the state-writer App must be verified before any gateway mutation"
        ]
    mint = text.find("- name: Mint narrowly scoped state-writer token")
    if not 0 <= preflight < mint:
        violations.append(
            f"{workflow}: the state-writer preflight must precede the token mint"
        )
    for required in (
        "STATE_APP_ID: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
        "STATE_APP_PRIVATE_KEY: ${{ secrets.GITFORGEOPS_STATE_APP_PRIVATE_KEY }}",
        'if [ -z "$STATE_APP_ID" ] || [ -z "$STATE_APP_PRIVATE_KEY" ]; then',
    ):
        if required not in text:
            violations.append(
                f"{workflow}: state-writer preflight is missing {required!r}"
            )
    # The App ID is public metadata, not a credential. Reading it from `vars`
    # in one workflow and `secrets` in another is how the settings audit and
    # the workflows drifted apart: the audit proves the ruleset bypass is THIS
    # App by comparing against `vars.GITFORGEOPS_STATE_APP_ID`, and a secret it
    # cannot read is a comparison it cannot make.
    if "secrets.GITFORGEOPS_STATE_APP_ID" in text:
        violations.append(
            f"{workflow}: the state-writer App ID must be read from vars, matching the settings audit"
        )
    if "app-id: ${{ vars.GITFORGEOPS_STATE_APP_ID }}" not in text:
        violations.append(
            f"{workflow}: the state-writer token mint must use vars.GITFORGEOPS_STATE_APP_ID"
        )
    return violations


def workflow_name_violations(workflow: str, text: str, expected: str) -> list[str]:
    if text.startswith(f"name: {expected}\n"):
        return []
    return [f"{workflow}: workflow name must remain exactly {expected!r}"]


def installer_step_auth_violations(workflow: str, text: str) -> list[str]:
    installer_steps = [
        step
        for step in text.split("\n      - name: ")
        if "install-ferrum-edge.sh" in step
    ]
    if any("GITHUB_TOKEN: ${{ github.token }}" not in step for step in installer_steps):
        return [
            f"{workflow}: every validator download step must use the authenticated GitHub asset API"
        ]
    return []


def trusted_supply_chain_policy_violations(text: str) -> list[str]:
    required = (
        "if: github.event_name == 'pull_request'",
        "ref: ${{ github.event.repository.default_branch }}",
        "path: trusted-supply-chain",
        "CANDIDATE_CHECKER=.github/scripts/check_supply_chain.py",
        "Candidate must retain the regular-file supply-chain checker.",
        "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py",
        "module.ROOT = candidate",
        'module.WORKFLOWS = candidate / ".github" / "workflows"',
        "module.ACTION_FILES = sorted(",
        "sys.argv = [str(checker)]",
        "raise SystemExit(module.main())",
    )
    violations = [
        f"security.yml: trusted supply-chain policy runner is missing {item!r}"
        for item in required
        if item not in text
    ]
    if text.count("CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py") != 1:
        violations.append(
            "security.yml: the protected default-branch policy checker must be selected exactly once"
        )
    if "path: trusted-supply-chain" in text and (
        "ref: ${{ github.event.pull_request.base.sha }}" in text
    ):
        violations.append(
            "security.yml: an unprotected PR base SHA must not supply the policy checker"
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root to inspect (checker code may live in a trusted checkout)",
    )
    parser.add_argument(
        "--write-manifest",
        type=Path,
        help="write the exact reviewed build inputs after policy validation",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    workflows = root / ".github" / "workflows"
    checked_action_files = action_files(root)
    violations: list[str] = []
    candidate_checker = root / ".github" / "scripts" / "check_supply_chain.py"
    if candidate_checker.is_symlink() or not candidate_checker.is_file():
        violations.append(
            ".github/scripts/check_supply_chain.py must remain a regular protected policy file"
        )
    action_pins: dict[str, list[str]] = {}
    for workflow in checked_action_files:
        text = workflow.read_text(encoding="utf-8")
        references = [reference.strip("'\"") for reference in USES.findall(text)]
        action_pins[str(workflow.relative_to(root))] = references
        for reference in references:
            if reference.startswith("./"):
                continue
            if not ACTION_SHA.fullmatch(reference):
                violations.append(
                    f"{workflow.relative_to(root)}: action is not pinned to a 40-hex commit: {reference}"
                )
        if "ubuntu-latest" in text:
            violations.append(
                f"{workflow.relative_to(root)}: runner image must use an explicit Ubuntu release"
            )
        violations.extend(
            rust_toolchain_violations(str(workflow.relative_to(root)), text)
        )
        if "ferrum-edge-linux-x86_64" in text:
            violations.append(
                f"{workflow.relative_to(root)}: download must go through install-ferrum-edge.sh"
            )

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    for image in FROM.findall(dockerfile):
        if "@sha256:" not in image:
            violations.append(f"Dockerfile: base image is not digest-pinned: {image}")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
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

    rust_ci = (workflows / "rust-ci.yml").read_text(encoding="utf-8")
    if "tool: cargo-llvm-cov@0.9.0" not in rust_ci:
        violations.append("rust-ci.yml: cargo-llvm-cov must use exact version 0.9.0")

    for workflow_name, expected_name in (
        ("rust-ci.yml", "Rust CI"),
        ("security.yml", "Security"),
        ("state-guard.yml", "GitForgeOps State Guard"),
        ("validate-pr.yml", "GitForgeOps PR Static Validation"),
    ):
        workflow_text = (workflows / workflow_name).read_text(encoding="utf-8")
        violations.extend(
            workflow_name_violations(workflow_name, workflow_text, expected_name)
        )

    release = (workflows / "release.yml").read_text(encoding="utf-8")
    if "provenance: mode=max" not in release or "sbom: true" not in release:
        violations.append("release.yml: image provenance and SBOM must both be enabled")
    # One manifest digest is pushed to both registries, but an attestation is
    # bound to its `subject-name`: a consumer verifying `docker.io/<image>`
    # finds nothing unless that name is attested too.
    if release.count("uses: actions/attest-build-provenance@") != 2:
        violations.append(
            "release.yml: every published image name needs signed build provenance (GHCR and Docker Hub)"
        )
    for required in (
        "subject-name: ghcr.io/${{ github.repository }}",
        "subject-name: ${{ vars.DOCKERHUB_IMAGE || 'ferrumedge/ferrum-edge-git-forge-ops' }}",
    ):
        if required not in release:
            violations.append(
                f"release.yml: build provenance is missing subject {required!r}"
            )
    # The ledger commits that `apply-on-merge.yml` and `rotate.yml` push to
    # `main` contain no build input. They used to carry `[skip ci]`, which
    # suppressed the required checks along with everything else; excluding the
    # paths from the image build is the narrower control.
    release_push = re.search(
        r"^  push:\s*$\n(?P<body>(?:^    .*\n|^      .*\n)*)", release, re.MULTILINE
    )
    release_push_body = release_push.group("body") if release_push else ""
    for ignored in ("- '.state/**'", "- 'assembled/**'"):
        if ignored not in release_push_body:
            violations.append(
                f"release.yml: push trigger must ignore ledger-only commits ({ignored})"
            )
    if "tags: ['v*']" not in release_push_body:
        violations.append("release.yml: push trigger must keep publishing release tags")
    for required in (
        "authorize-release:",
        "needs: authorize-release",
        "release commit must map to exactly one merged PR",
        "Release merge association is not yet available and unambiguous",
        'gh pr checks "$pr" --repo "$REPO" --required',
        "GitForgeOps PR Static Validation / gitforgeops-required-static-validation",
    ):
        if required not in release:
            violations.append(
                f"release.yml: missing checked-merge publication gate {required!r}"
            )

    apply_workflow = (workflows / "apply-on-merge.yml").read_text(encoding="utf-8")
    if "vars.FERRUM_GATEWAY_MODE != 'file'" in apply_workflow:
        violations.append("apply-on-merge.yml: inequality routing can send unknown modes to API")
    for required in (
        "case \"$mode\" in",
        "steps.deployment-mode.outputs.mode == 'api'",
        "steps.deployment-mode.outputs.mode == 'file'",
        ".github/scripts/merge_context.py",
        "if ! gh api",
    ):
        if required not in apply_workflow:
            violations.append(
                f"apply-on-merge.yml: explicit validated mode mapping is missing {required!r}"
            )
    violations.extend(unconfigured_repo_skip_violations(apply_workflow))

    for privileged_workflow in (
        "apply-on-merge.yml",
        "drift-check.yml",
        "materialize-file.yml",
        "rotate.yml",
    ):
        text = (workflows / privileged_workflow).read_text(encoding="utf-8")
        if (
            privileged_workflow != "apply-on-merge.yml"
            and "Repository configuration is required before binding a deployment environment."
            not in text
        ):
            violations.append(
                f"{privileged_workflow}: must fail before environment binding when repo config is absent"
            )
        if ".github/scripts/credential_bundles.py" not in text:
            violations.append(
                f"{privileged_workflow}: credential bundles must use the fail-closed loader"
            )
        if "except json.JSONDecodeError" in text:
            violations.append(
                f"{privileged_workflow}: malformed credential bundles must not fail open"
            )
        # `${{ toJSON(secrets) }}` spills every environment secret to disk.
        # $RUNNER_TEMP is wiped with the workspace; a bare `mktemp` lands in a
        # /tmp that self-hosted runners share between jobs and never clean.
        if 'all_secrets=$(mktemp -p "${RUNNER_TEMP:-/tmp}")' not in text:
            violations.append(
                f"{privileged_workflow}: the whole-secrets spill must be created under $RUNNER_TEMP"
            )
        if "[skip ci]" in text:
            violations.append(
                f"{privileged_workflow}: state commits must not suppress required checks with [skip ci]"
            )

    for state_writer_workflow in ("apply-on-merge.yml", "rotate.yml"):
        violations.extend(
            state_writer_preflight_violations(
                state_writer_workflow,
                (workflows / state_writer_workflow).read_text(encoding="utf-8"),
            )
        )

    settings_audit = (workflows / "settings-audit.yml").read_text(encoding="utf-8")
    # GitHub disables scheduled workflows after 60 days of repository
    # inactivity, and an audit that has silently stopped reports no drift at
    # all. Manual dispatch is the recovery path, and it may select any ref, so
    # it carries the same protected-branch preflight the other manual workflows
    # use before the administration-read token is bound.
    for required in (
        "  workflow_dispatch:",
        "- name: Require protected default branch",
        "SOURCE_REF: ${{ github.ref }}",
        "EXPECTED_REF: refs/heads/${{ github.event.repository.default_branch }}",
        "STATE_WRITER_APP_ID: ${{ vars.GITFORGEOPS_STATE_APP_ID }}",
    ):
        if required not in settings_audit:
            violations.append(
                f"settings-audit.yml: dispatchable audit is missing {required!r}"
            )
    if settings_audit.find("- name: Require protected default branch") > settings_audit.find(
        "GH_TOKEN: ${{ secrets.SETTINGS_AUDIT_TOKEN }}"
    ):
        violations.append(
            "settings-audit.yml: the ref preflight must run before the audit token is bound"
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
        text = (workflows / rename_sensitive_workflow).read_text(encoding="utf-8")
        violations.extend(
            trusted_classifier_violations(
                rename_sensitive_workflow,
                text,
                trusted_invocation,
                expected_count,
            )
        )

    for pr_workflow in (
        "rust-ci.yml",
        "security.yml",
        "validate-pr.yml",
    ):
        text = (workflows / pr_workflow).read_text(encoding="utf-8")
        violations.extend(pull_request_trigger_violations(pr_workflow, text))
    violations.extend(
        state_guard_trigger_violations(
            (workflows / "state-guard.yml").read_text(encoding="utf-8")
        )
    )
    violations.extend(
        trusted_supply_chain_policy_violations(
            (workflows / "security.yml").read_text(encoding="utf-8")
        )
    )
    state_guard = (workflows / "state-guard.yml").read_text(encoding="utf-8")
    if 'result=$(python3 "$helper"' not in state_guard:
        violations.append(
            "state-guard.yml: classifier execution must use the trusted helper variable"
        )

    for state_workflow, commit_step in (
        ("apply-on-merge.yml", "- name: Commit state + assembled (if changed)"),
        ("rotate.yml", "- name: Commit state update"),
    ):
        text = (workflows / state_workflow).read_text(encoding="utf-8")
        violations.extend(
            state_writer_token_violations(state_workflow, text, commit_step)
        )

    static_review = (workflows / "validate-pr.yml").read_text(encoding="utf-8")
    if re.search(r"^ {4}environment\s*:", static_review, re.MULTILINE):
        violations.append("validate-pr.yml: PR-built code must not bind an Environment")
    # Match the whole `secrets` context, not just `secrets.NAME` /
    # `secrets['NAME']`. `${{ toJSON(secrets) }}`,
    # `${{ fromJSON(toJSON(secrets)) }}` and a bare `${{ secrets }}` hand over
    # every environment secret at once and are exactly what the privileged
    # workflows use to load credential bundles — the form most worth catching
    # in the workflow that must never receive one.
    if re.search(r"\$\{\{[^}]*\bsecrets\b", static_review):
        violations.append("validate-pr.yml: PR-built code must not receive any secrets")
    if re.search(r"^\s+paths\s*:", static_review, re.MULTILINE):
        violations.append(
            "validate-pr.yml: a path-filtered workflow cannot provide a stable required check"
        )
    for required in (
        "trusted-scope/.github/scripts/changed_files.py",
        "ref: ${{ github.event.repository.default_branch }}",
        "gitforgeops-required-static-validation:",
        "if: always()",
    ):
        if required not in static_review:
            violations.append(
                f"validate-pr.yml: missing stable validation gate control {required!r}"
            )
    if "pull-requests: read" not in static_review:
        violations.append(
            "validate-pr.yml: Pull Requests API access requires pull-requests: read"
        )

    trusted_review = (workflows / "trusted-pr-review.yml").read_text(
        encoding="utf-8"
    )
    prepare_permissions = """  prepare:
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'pull_request'
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      pull-requests: read
"""
    if prepare_permissions not in trusted_review:
        violations.append(
            "trusted-pr-review.yml: prepare job requires explicit pull-requests: read"
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
        "PR association is not yet available and unambiguous",
        # `workflow_run.workflows:` matches the workflow's DISPLAY name, which
        # any workflow file may claim. Resolve the triggering run and require
        # its definition path, so a renamed or newly added workflow cannot feed
        # this privileged job a head SHA of its choosing.
        "EXPECTED_WORKFLOW_PATH: .github/workflows/validate-pr.yml",
        'run_path=$(gh api "repos/${REPO}/actions/runs/${RUN_ID}" --jq \'.path\')',
        '[ "$run_path" = "$EXPECTED_WORKFLOW_PATH" ]',
        # Two deliveries for one reviewed commit must not race each other for
        # the environment approval and the PR comment.
        "group: trusted-pr-review-${{ github.event.workflow_run.head_sha }}",
        "cancel-in-progress: true",
    ):
        if required not in trusted_review:
            violations.append(
                f"trusted-pr-review.yml: missing privileged-boundary guard {required!r}"
            )

    codeowners = (root / ".github" / "CODEOWNERS").read_text(
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
        text = (workflows / manual_workflow).read_text(encoding="utf-8")
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

    toolchain = (root / "rust-toolchain.toml").read_text(encoding="utf-8")
    if 'channel = "1.98.0"' not in toolchain:
        violations.append("rust-toolchain.toml: channel must be pinned to 1.98.0")

    installer = (root / ".github" / "scripts" / "install-ferrum-edge.sh").read_text(
        encoding="utf-8"
    )
    for required in (
        "ferrum-edge-checksums.txt",
        "expected_sha256",
        "published_sha256",
        "actual_sha256",
        "Authorization: Bearer",
    ):
        if required not in installer:
            violations.append(
                f"install-ferrum-edge.sh: missing required validator installer control {required!r}"
            )
    for workflow_name in (
        "apply-on-merge.yml",
        "drift-check.yml",
        "trusted-pr-review.yml",
        "validate-pr.yml",
    ):
        workflow_text = (root / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        violations.extend(
            installer_step_auth_violations(workflow_name, workflow_text)
        )
    if "FERRUM_EDGE_SHA256" in "\n".join(
        workflow.read_text(encoding="utf-8") for workflow in checked_action_files
    ):
        violations.append(
            "workflows must not replace the checked-in validator digest with a mutable variable"
        )

    checksum_policy = root / ".github" / "ferrum-edge-checksums.txt"
    pins = [
        line.split()
        for line in checksum_policy.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not pins or any(
        len(pin) != 5
        or not re.fullmatch(r"release-[1-9][0-9]*", pin[0])
        or pin[1] != "ferrum-edge-linux-x86_64"
        or not re.fullmatch(r"[1-9][0-9]*", pin[2])
        or not re.fullmatch(r"[1-9][0-9]*", pin[3])
        or not re.fullmatch(r"[0-9a-f]{64}", pin[4])
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
                {
                    "release_identity": pin[0],
                    "asset": pin[1],
                    "asset_id": int(pin[2]),
                    "checksum_asset_id": int(pin[3]),
                    "sha256": pin[4],
                }
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
