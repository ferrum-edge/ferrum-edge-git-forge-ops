#!/usr/bin/env python3
"""Enforce immutable executable dependencies in CI and container builds.

The workflow rules read workflow text, never what a command computes when it
runs. Guarded steps are pinned exactly, and GITHUB_ENV, GITHUB_PATH and
BASH_ENV are banned outside the one pinned credential hand-off. A program a
step invokes (the binary, a helper script, or Bash evaluating computed text)
can still write $GITHUB_ENV; that is out of scope here and is left to review
of every workflow change.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTION_SHA = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", re.MULTILINE)
FROM = re.compile(r"^FROM\b[ \t]*([^\s]+)", re.MULTILINE | re.IGNORECASE)
VALIDATOR_ASSET = "ferrum-edge-linux-x86_64"
DIGEST_ENTRY = re.compile(r"([0-9a-f]{64})\s+" + re.escape(VALIDATOR_ASSET))
MIN_RUST_TOOLCHAIN = (1, 99, 0)
RUST_TOOLCHAIN_CHANNEL = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII
)
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
# Closing delimiters inside single-quoted expression literals are data, even
# in shell comments. GitHub expands expressions before Bash reads the script.
WORKFLOW_EXPRESSION = re.compile(
    r"\$\{\{((?:'(?:[^']|'')*'|(?!\}\})[^'])*)\}\}", re.DOTALL
)
# GitHub resolves contexts and secret names without regard to case:
# `${{ secrets.ferrum_admin_jwt_secret }}` and `${{ SECRETS.FERRUM_ADMIN_JWT_SECRET }}`
# both read FERRUM_ADMIN_JWT_SECRET. Every secret-name match below is therefore
# case-insensitive, and `secret_name_case_violations` requires the canonical
# spelling so a reviewer reading the workflow sees the name the policy sees.
NAMED_SECRET = re.compile(r"\bsecrets\.[A-Za-z_][A-Za-z0-9_]*", re.IGNORECASE)
WHOLE_SECRETS = re.compile(r"\bsecrets\b", re.IGNORECASE)
SECRET_REFERENCE = re.compile(r"\bsecrets\.[A-Za-z_][A-Za-z0-9_]*\b", re.IGNORECASE)
CANONICAL_SECRET_REFERENCE = re.compile(r"secrets\.[A-Z_][A-Z0-9_]*")
BUNDLE_SECRET_PREFIX = "FERRUM_CREDS_BUNDLE"
BUNDLE_BINDING = re.compile(
    r"^\s+(" + BUNDLE_SECRET_PREFIX + r"(?:_\d+)?)\s*:\s*\$\{\{\s*secrets\.("
    + BUNDLE_SECRET_PREFIX
    + r"(?:_\d+)?)\s*\}\}\s*$",
    re.MULTILINE,
)
RUST_SHARD_LIMIT = re.compile(
    r"^pub const MAX_BUNDLE_SHARDS\s*:\s*u32\s*=\s*(\d+)\s*;", re.MULTILINE
)
LOADER_SHARD_LIMIT = re.compile(r"^MAX_BUNDLE_SHARDS\s*=\s*(\d+)\s*$", re.MULTILINE)
BUNDLE_LOADER_STEP = "Load credential bundles"
# Every workflow that binds a GitHub Environment holding gateway credentials.
PRIVILEGED_WORKFLOWS = (
    "apply-on-merge.yml",
    "drift-check.yml",
    "materialize-file.yml",
    "rotate.yml",
)
# Workflows whose operation requires credential values. This list must be
# independent of candidate-controlled secret bindings: otherwise deleting every
# binding would also delete the evidence that the fail-closed loader is needed.
# `drift-check.yml` is deliberately absent because unresolved broker leaves are
# excluded from its live comparison per leaf.
CREDENTIAL_BUNDLE_WORKFLOWS = (
    "apply-on-merge.yml",
    "materialize-file.yml",
    "rotate.yml",
)
BUNDLE_SECRET_BINDING = "secrets.FERRUM_CREDS_BUNDLE"
# Scheduled monitoring runs unattended in an environment with no required
# reviewer, so the fence is what that job can reach at all: read the gateway,
# nothing else.
MONITORING_WORKFLOW = "drift-check.yml"
MONITORING_FORBIDDEN_SECRETS = (
    # Write-equivalent gateway authority; monitoring uses the viewer key.
    "FERRUM_ADMIN_JWT_SECRET",
    # Writes GitHub Environment Secrets — the credential broker's authority.
    "FERRUM_GH_PROVISIONER_TOKEN",
    # Mints a Contents: write token for the ownership ledger.
    "GITFORGEOPS_STATE_APP_PRIVATE_KEY",
    # Reads repository administration settings.
    "SETTINGS_AUDIT_TOKEN",
    # Credential values, which a comparison does not need.
    "FERRUM_CREDS_BUNDLE",
)
# `diff` is the only gateway operation monitoring may perform. `apply`,
# `rotate` and `export --materialize` all mutate something.
MONITORING_ALLOWED_COMMAND = "gitforgeops diff --exit-on-drift"
ADMIN_JWT_SECRET_BINDING = (
    "FERRUM_ADMIN_JWT_SECRET: ${{ secrets.FERRUM_ADMIN_JWT_SECRET }}"
)
# The optional claim settings the README documents as per-environment secrets.
# They are only optional to *configure* — once configured they must reach the
# process, or the run mints a token the gateway rejects.
ADMIN_JWT_OPTIONAL_SETTINGS = (
    "FERRUM_ADMIN_JWT_ISSUER",
    "FERRUM_ADMIN_JWT_ROLE",
    "FERRUM_ADMIN_JWT_AUDIENCE",
    "FERRUM_ADMIN_JWT_TTL_SECS",
)
# Every workflow that reaches the admin REST API. `materialize-file.yml` is
# absent on purpose: it refuses to run outside file mode and never opens an
# admin connection, so it binds no JWT material at all.
ADMIN_API_WORKFLOWS = (
    "apply-on-merge.yml",
    "drift-check.yml",
    "rotate.yml",
    "trusted-pr-review.yml",
)
# Ferrum Edge's second signing key. The gateway authorizes every token signed
# with it as `viewer` whatever the token claims, and `gitforgeops diff` reads
# `GET /config/export` with it when it is set (never touching the admin key).
# Least privilege runs both ways: only scheduled monitoring compares without
# writing, so only `drift-check.yml` may bind it. `plan`, `review` and `apply`
# need `/backup` and cannot use it, and a reconciling job has no reason to hold
# a second gateway key.
VIEWER_JWT_SECRET = "FERRUM_ADMIN_JWT_VIEWER_SECRET"
VIEWER_JWT_SECRET_BINDING = (
    "FERRUM_ADMIN_JWT_VIEWER_SECRET: ${{ secrets.FERRUM_ADMIN_JWT_VIEWER_SECRET }}"
)
VIEWER_JWT_SECRET_REFERENCE = re.compile(
    r"\bsecrets\.FERRUM_ADMIN_JWT_VIEWER_SECRET\b", re.IGNORECASE
)
VIEWER_JWT_WORKFLOW_PATHS = (f".github/workflows/{MONITORING_WORKFLOW}",)
# The viewer key's tokens carry the configured issuer, audience and TTL; the
# role claim is always `viewer`, so `FERRUM_ADMIN_JWT_ROLE` does not apply.
VIEWER_JWT_OPTIONAL_SETTINGS = (
    "FERRUM_ADMIN_JWT_ISSUER",
    "FERRUM_ADMIN_JWT_AUDIENCE",
    "FERRUM_ADMIN_JWT_TTL_SECS",
)
# The protected checker already accepted the viewer binding before the
# workflow switched (#440). Monitoring must now hold only that signing key.
MONITORING_JWT_SECRET_BINDINGS = (VIEWER_JWT_SECRET_BINDING,)
PROBE_CONSUMERS_ENV = "FERRUM_VERIFY_PROBE_CONSUMERS"
PROBE_BOUND_ENV = "FERRUM_VERIFY_PROBE_CONSUMERS_BOUND"
PROBE_CONSUMERS_VALUE = "${{ vars.FERRUM_VERIFY_PROBE_CONSUMERS }}"
PROBE_RUNTIME_ENVIRONMENTS = {
    "apply": "${{ matrix.environment }}",
    "promote": "${{ matrix.scope.environment }}",
}
PROBE_WORKFLOW_STEPS = {
    ".github/workflows/apply-on-merge.yml": (
        ("apply", "Validate", {
            "FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["apply"],
            PROBE_CONSUMERS_ENV: PROBE_CONSUMERS_VALUE,
            PROBE_BOUND_ENV: "true",
        }),
        ("apply", "Apply", {"FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["apply"]}),
        ("apply", "Apply (file mode)", {"FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["apply"]}),
        ("apply", "Verify traffic", {
            "FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["apply"],
            PROBE_CONSUMERS_ENV: PROBE_CONSUMERS_VALUE,
        }),
        ("promote", "Validate", {
            "FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["promote"],
            PROBE_CONSUMERS_ENV: PROBE_CONSUMERS_VALUE,
            PROBE_BOUND_ENV: "true",
        }),
        ("promote", "Apply", {"FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["promote"]}),
        ("promote", "Apply (file mode)", {"FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["promote"]}),
        ("promote", "Verify traffic", {
            "FERRUM_ENV": PROBE_RUNTIME_ENVIRONMENTS["promote"],
            PROBE_CONSUMERS_ENV: PROBE_CONSUMERS_VALUE,
        }),
    ),
    ".github/workflows/trusted-pr-review.yml": (
        ("live-review", "Post trusted live review", {
            PROBE_CONSUMERS_ENV: PROBE_CONSUMERS_VALUE,
            PROBE_BOUND_ENV: "true",
        }),
    ),
}
# These jobs validate inside the same Environment before either publication
# mode mutates it. Pin the flow as well as the bindings: a skipped/nonblocking
# Validate or an Apply using always()/failure() loses that ordering guarantee.
PROBE_APPLY_JOB_GATES = {
    "apply": (
        ["list-envs"],
        "needs.list-envs.outputs.envs != '[]' && needs.list-envs.outputs.envs != ''",
    ),
    "promote": (
        ["list-envs", "apply"],
        "needs.list-envs.outputs.promotions != '[]' && needs.list-envs.outputs.promotions != ''",
    ),
}
PROBE_APPLY_STEP_GATES = {
    "Apply": "steps.deployment-mode.outputs.mode == 'api'",
    "Apply (file mode)": "steps.deployment-mode.outputs.mode == 'file'",
}
# Verify may read FERRUM_ENV for its notice, but may not override that binding
# or add CLI environment/namespace selectors, so its script is pinned exactly
# (`pinned_run_matches` explains the one tolerance: comment lines).
PROBE_VERIFY_RUN = (
    "set -euo pipefail",
    'if [ -z "$APPLIED_CREDS_FILE" ] || [ ! -s "$APPLIED_CREDS_FILE" ]; then',
    'echo "::error::The apply step left no finalized credential bundle, '
    'so traffic cannot be verified against what it deployed."',
    "exit 1",
    "fi",
    "status=0",
    'FERRUM_CREDS_JSON_FILE="$APPLIED_CREDS_FILE" gitforgeops verify || status=$?',
    'case "$status" in',
    "0)",
    'echo "result=passed" >> "$GITHUB_OUTPUT"',
    ";;",
    "5)",
    'echo "result=skipped" >> "$GITHUB_OUTPUT"',
    'echo "::notice::Traffic verification skipped: .gitforgeops/smoke.yaml declares '
    'no checks for $FERRUM_ENV. Nothing was verified; this environment authorizes no promotion."',
    ";;",
    "*)",
    'exit "$status"',
    ";;",
    "esac",
)
# The one permitted env-file write is the credential-file hand-off in each
# "Load credential bundles" step. Pin the complete script, not only its echo:
# rebinding creds_file to a multiline value would inject more variables
# through an otherwise unchanged echo. Apply also hands the path of its
# finalized bundle to Verify traffic, as a step output rather than an env file.
CREDENTIAL_HANDOFF_RUN = (
    "set -euo pipefail",
    'creds_file="${RUNNER_TEMP:-/tmp}/ferrum-creds-${GITHUB_RUN_ID}-${GITHUB_JOB}-$$.json"',
    'python3 .github/scripts/credential_bundles.py "$creds_file"',
    'echo "FERRUM_CREDS_JSON_FILE=$creds_file" >> "$GITHUB_ENV"',
)
APPLY_CREDENTIAL_HANDOFF_RUN = CREDENTIAL_HANDOFF_RUN + (
    'applied_file="${RUNNER_TEMP:-/tmp}/ferrum-creds-applied-${GITHUB_RUN_ID}-${GITHUB_JOB}-$$.json"',
    'rm -f "$applied_file"',
    'echo "applied_file=$applied_file" >> "$GITHUB_OUTPUT"',
)
CREDENTIAL_HANDOFF_SHAPES = {
    ".github/workflows/apply-on-merge.yml": APPLY_CREDENTIAL_HANDOFF_RUN,
    ".github/workflows/materialize-file.yml": CREDENTIAL_HANDOFF_RUN,
    ".github/workflows/rotate.yml": CREDENTIAL_HANDOFF_RUN,
}
# Apply writes its finalized bundle, and Verify traffic trusts it, only at the
# path the apply hand-off cleared first. GitHub refuses a duplicate step id, so
# pinning the hand-off's id and both readers ties the path to that hand-off.
APPLY_CREDENTIAL_HANDOFF_ID = "load-bundles"
APPLIED_BUNDLE_VALUE = "${{ steps.load-bundles.outputs.applied_file }}"
APPLIED_BUNDLE_BINDINGS = {
    "Apply": "FERRUM_CREDS_JSON_OUTPUT_FILE",
    "Verify traffic": "APPLIED_CREDS_FILE",
}
# The runner values the hand-off's file name is built from. A workflow or job
# env that rebinds one (to a multiline value, say) changes what the pinned echo
# writes, so neither scope may name them.
CREDENTIAL_HANDOFF_DRIVERS = ("RUNNER_TEMP", "GITHUB_RUN_ID", "GITHUB_JOB")
# GitHub renders a `run:` interpolation before Bash reads the script, so no
# text rule sees the rendered value. In the Environment-bound workflows each
# job may interpolate only these: environment names the binary and the
# enumerator validate as safe path components, and full commit SHAs. Pass any
# other value through step `env:`, where it stays data.
RUN_EXPRESSIONS = {
    ".github/workflows/apply-on-merge.yml": {
        "apply": ("matrix.environment",),
        "promote": ("matrix.scope.environment",),
    },
    ".github/workflows/trusted-pr-review.yml": {
        "prepare": ("steps.metadata.outputs.head_sha", "steps.metadata.outputs.trusted_sha"),
        "live-review": ("needs.prepare.outputs.head_sha",),
    },
    ".github/workflows/drift-check.yml": {},
    ".github/workflows/materialize-file.yml": {},
    ".github/workflows/rotate.yml": {},
}
# A pinned run value is only as safe as its producer, so the wiring is pinned
# too: each job output a later job interpolates, each matrix, and the lines of
# the step that writes the value. Rewiring one to event data (a branch name, a
# title, an API field) fails here instead of reaching `run:` unseen.
RUN_EXPRESSION_JOB_OUTPUTS = {
    ".github/workflows/apply-on-merge.yml": {
        "list-envs": {
            "envs": "${{ steps.list.outputs.envs }}",
            "promotions": "${{ steps.list.outputs.promotions }}",
        },
    },
    ".github/workflows/trusted-pr-review.yml": {
        "prepare": {
            "head_sha": "${{ steps.metadata.outputs.head_sha }}",
            "trusted_sha": "${{ steps.metadata.outputs.trusted_sha }}",
        },
    },
}
RUN_EXPRESSION_MATRICES = {
    "apply": {"environment": "${{ fromJson(needs.list-envs.outputs.envs) }}"},
    "promote": {"scope": "${{ fromJson(needs.list-envs.outputs.promotions) }}"},
}
# The enumerator step, whole. An entry holding a newline is one command over
# several lines (a quoted jq program): its lines match consecutively, with no
# comment lines dropped inside it.
APPLY_ENVIRONMENT_LIST_RUN = (
    "set -euo pipefail",
    "if [[ ! -f .gitforgeops/config.yaml ]]; then",
    'echo "::notice::No .gitforgeops/config.yaml on the protected branch; skipping apply. '
    'See docs/github-launch-controls.md to configure deployment environments."',
    'echo "envs=[]" >> "$GITHUB_OUTPUT"',
    'echo "promotions=[]" >> "$GITHUB_OUTPUT"',
    "exit 0",
    "fi",
    "scopes=$(gitforgeops envs --format json --include-scopes | jq -c .)",
    "jq -e '\n"
    'type == "array" and\n'
    "all(.[];\n"
    '(.environment | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"))\n'
    'and ((.promotion_requires // "x") | test("^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")))\n'
    "' <<< \"$scopes\" >/dev/null || {",
    'echo "::error::Every environment must be a single safe path component."',
    "exit 1",
    "}",
    "envs=$(jq -c '[.[] | select(.promotion_requires == null) | .environment]' <<< \"$scopes\")",
    "promotions=$(jq -c '[.[] | select(.promotion_requires != null)\n"
    "| {environment, requires: .promotion_requires}]' <<< \"$scopes\")",
    'echo "envs=$envs" >> "$GITHUB_OUTPUT"',
    'echo "promotions=$promotions" >> "$GITHUB_OUTPUT"',
)
# Trusted review's metadata step does much more, so only the lines that
# produce the two SHAs are pinned: the event SHA is bound from the event,
# checked as 40 hex digits first, and never reassigned; the trusted SHA comes
# from `git rev-parse`; and each output is written by its one echo.
REVIEW_EVENT_HEAD_SHA = "${{ github.event.workflow_run.head_sha }}"
REVIEW_METADATA_PREAMBLE = (
    "set -euo pipefail",
    '[[ "$EVENT_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid head SHA" >&2; exit 1; }',
)
REVIEW_TRUSTED_SHA_ASSIGNMENT = "trusted_sha=$(git -C trusted rev-parse HEAD)"
REVIEW_METADATA_LINES = {
    "head_sha": ('echo "head_sha=$EVENT_HEAD_SHA"',),
    "trusted_sha": ('echo "trusted_sha=$trusted_sha"', REVIEW_TRUSTED_SHA_ASSIGNMENT),
}
# Outside its two guarded Apply steps, apply-on-merge.yml may invoke the binary
# only on these lines: the enumerator, Validate and Verify traffic.
READ_ONLY_GITFORGEOPS_LINES = (
    "scopes=$(gitforgeops envs --format json --include-scopes | jq -c .)",
    "gitforgeops validate",
    'FERRUM_CREDS_JSON_FILE="$APPLIED_CREDS_FILE" gitforgeops verify || status=$?',
)
# The only other apply-on-merge.yml scalars that may spell the binary: the
# `name:` of the workflow, a job or a step, which GitHub displays and never runs.
GITFORGEOPS_DISPLAY_NAMES = ("GitForgeOps Apply", "Build gitforgeops", "Install gitforgeops")

# The revision a recorded credential allocation is bound to, which lets the
# retry of a failed apply keep the slots it already wrote. It must be the
# triggering merge: the applied head moves when the failed attempt pushes its
# state commit, so a retry bound to that head would refuse its own slots.
ALLOCATION_REVISION_BINDING = "GITFORGEOPS_ALLOCATION_REVISION: ${{ github.sha }}"
APPLY_COMMAND = "run: gitforgeops apply"
STEP_SPLIT = re.compile(r"\n(?=\s*-\s+(?:name|uses):)")
STEP_NAME = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$", re.MULTILINE)
# Keep this as a set so each reviewed Dependabot bump can allow both pins before
# switching the workflow, then retire the previous pin in a follow-up PR.
CARGO_AUDIT_ACTIONS = frozenset(
    {
        # v2.87.22 retains v2.87.20's action source and cargo-audit manifest.
        "taiki-e/install-action@83ac0ad63c0167e6f06796fab0fce28db1bf3db0",
    }
)
SECURITY_PUSH_POLICY_PATHS = (
    ".github/actions/**",
    ".github/cargo-audit-policy.json",
    ".github/ferrum-edge-checksums.txt",
    ".github/CODEOWNERS",
)
# The administration-read settings-audit token lives in its own environment, so
# a dispatch from an unprotected ref cannot receive it. Kept in step with
# audit_settings.SETTINGS_AUDIT_ENVIRONMENT and bootstrap_repo_settings.py.
SETTINGS_AUDIT_ENVIRONMENT_BINDING = "\n    environment: settings-audit\n"
SETTINGS_AUDIT_TOKEN_REFERENCE = "secrets.SETTINGS_AUDIT_TOKEN"
FRESH_HEAD_STEP = "Refresh protected branch and reject stale deployments"
# The checkout that feeds a privileged reconcile has to name the branch, not
# the triggering event's commit, and has to carry enough history for the
# ancestry test below to be answerable.
FRESH_HEAD_CHECKOUT = (
    "ref: ${{ github.event.repository.default_branch }}",
    "fetch-depth: 0",
    "persist-credentials: false",
)
# The guard itself: re-fetch under the lock, move onto the branch head, print
# both revisions, and fail closed when the triggering commit is no longer part
# of the branch.
FRESH_HEAD_CONTROLS = (
    "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
    "TRIGGER_SHA: ${{ github.sha }}",
    "git fetch --no-tags --force origin",
    'fresh_head=$(git rev-parse "refs/remotes/origin/${DEFAULT_BRANCH}")',
    'git checkout --force -B "$DEFAULT_BRANCH" "refs/remotes/origin/${DEFAULT_BRANCH}"',
    'echo "Triggering commit: $TRIGGER_SHA"',
    'echo "Protected ${DEFAULT_BRANCH} HEAD: $fresh_head"',
    'git cat-file -e "${TRIGGER_SHA}^{commit}"',
    'git merge-base --is-ancestor "$TRIGGER_SHA" "$fresh_head"',
)
# The guard must decide supersession through the shared classifier rather than
# an ad-hoc diff, so the paths that refuse a queued apply stay exactly the paths
# that schedule a replacement one.
#
# Every reconciling job in every `FRESH_HEAD_WORKFLOWS` entry carries it, not
# only apply's. Rotation waits on the same `ferrum-apply-<env>` lock and then
# builds and runs the refreshed head with the same credentials; ancestry alone
# let a later merge spend the dispatched run's environment approval. Strict
# `fresh_head == TRIGGER_SHA` is not the rule either: apply's own ledger commit
# moves the branch while a rotation waits, and the classifier already treats
# that output as inert.
#
# Spelled as a family of families, because a half-present implementation is the
# dangerous case: the classifier invoked without its branch argument silently
# changes what the guard refuses and what its message tells the operator to do.
# The literal-pathspec family this replaces was the bug — it rejected every
# difference, including a merge that schedules no apply of its own, so a queued
# deployment could be cancelled with nothing left to reconcile it.
#
# The classifier is extracted from the triggering commit rather than run from
# the refreshed checkout, so a newer head cannot replace the program deciding
# whether it may ride the older authorization. The checkout-executed form is
# retired: it let the refreshed head approve its own helper changes.
#
# Each family is matched as one uninterrupted run of script lines, not as
# lines found anywhere in the step, so nothing can be spliced between the
# extraction and the interpreter.
#
# The classifier is piped into the interpreter, leaving no destination to
# redirect. The retired temp-file family went through a mutable path, and a
# line such as `trusted_classifier=/dev/null` slipped between the `mktemp` and
# the extraction discarded the trusted copy and ran an empty program that
# approved every revision (#357). `-I` keeps the working directory — the
# refreshed checkout being judged — off the classifier's import path; a plain
# `python3 -` would import a head-supplied `argparse.py` first.
TRIGGER_CLASSIFIER_STDIN = (
    'git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" | \\',
    "python3 -I - classify \\",
    '"$TRIGGER_SHA" "$fresh_head" --branch "$DEFAULT_BRANCH"',
)
APPLY_REVISION_BINDINGS = (TRIGGER_CLASSIFIER_STDIN,)
# A piped classifier is only a binding under `pipefail`: without it a failed
# extraction feeds `python3 -` an empty program, which exits 0 and approves the
# revision. So the guard must turn it on first and never touch shell options
# again.
PIPED_BINDING_PRELUDE = "        run: |\n          set -euo pipefail\n"
SHELL_OPTION_COMMAND = re.compile(r"\b(?:set|shopt|eval)\b")
DEPLOYMENT_SCOPE_SCRIPT = Path(".github/scripts/deployment_scope.py")
DEPLOYMENT_INPUT_TUPLE = re.compile(
    r"^DEPLOYMENT_INPUT_PATHS:[^=]*=\s*\((?P<body>.*?)\)\s*$",
    re.MULTILINE | re.DOTALL,
)
GENERATED_PATH_TUPLE = re.compile(
    r"^GENERATED_PATHS:[^=]*=\s*\((?P<body>.*?)\)\s*$",
    re.MULTILINE | re.DOTALL,
)
QUOTED = re.compile(r"""["']([^"']+)["']""")
PUSH_PATHS_BLOCK = re.compile(
    r"^  push:\s*$\n(?:^    (?!paths:).*\n)*^    paths:\s*$\n"
    r"(?P<body>(?:^      - .*\n)*)",
    re.MULTILINE,
)
# The job-level markers that prove the environment lock is already held, and
# every step that must not run before the freshness guard.
#
# `lock` is expressed as patterns rather than one literal binding: what matters
# is that the job binds *an* Environment and serializes on the shared
# `ferrum-apply-<env>` group, not which expression names the environment. A
# workflow with two privileged jobs legitimately spells them differently.
ENVIRONMENT_BINDING = re.compile(r"^    environment: \$\{\{ .+ \}\}$", re.MULTILINE)
APPLY_CONCURRENCY_GROUP = re.compile(
    r"^      group: ferrum-apply-\$\{\{ .+ \}\}$", re.MULTILINE
)
FRESH_HEAD_WORKFLOWS = {
    "apply-on-merge.yml": {
        "gateway": (
            "bash .github/scripts/install-ferrum-edge.sh",
            "run: cargo install --path . --locked",
            "- name: Load credential bundles",
            "run: gitforgeops apply --auto-approve",
        ),
    },
    "rotate.yml": {
        "gateway": (
            "run: cargo install --path . --locked",
            "- name: Load credential bundles",
            "gitforgeops rotate \\",
        ),
    },
}


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


WORKFLOW_SUFFIXES = (".yml", ".yaml")


def workflow_extension_violations(root: Path) -> list[str]:
    """Every file in `.github/workflows/` must end in exactly `.yml` or `.yaml`.

    The rules judge what `action_files` globs, and the glob is case-sensitive
    on the Linux runner, so a workflow spelled `x.YML` or `x.Yaml` would skip
    every rule here. Any other name in that directory is refused as well
    rather than guessed at: nothing but reviewed workflows belongs there.
    Subdirectories are not workflows and are left alone.
    """
    workflows = root / ".github" / "workflows"
    if workflows.is_symlink() or not workflows.is_dir():
        return []
    return [
        f"{path.relative_to(root).as_posix()}: a workflow file must end in exactly "
        "`.yml` or `.yaml`; any other spelling would skip every supply-chain rule"
        for path in sorted(workflows.iterdir())
        if (path.is_symlink() or not path.is_dir())
        and not path.name.endswith(WORKFLOW_SUFFIXES)
    ]


def mentions_secret(text: str, reference: str) -> bool:
    """Case-insensitive substring test for a `secrets.<NAME>` reference.

    A substring, not a whole word, so `secrets.FERRUM_CREDS_BUNDLE` still
    matches every `_N` shard.
    """
    return reference.lower() in text.lower()


def secret_name_case_violations(workflow: str, text: str) -> list[str]:
    """Every `secrets.<NAME>` reference must use the canonical upper-case name.

    GitHub would resolve a lower- or mixed-case spelling to the same secret, so
    the spelling is not a different secret; it is a way to read past a
    case-sensitive search. The policy's own matches are case-insensitive too.
    """
    violations: list[str] = []
    seen: set[str] = set()
    for match in SECRET_REFERENCE.finditer(text):
        reference = match.group(0)
        if CANONICAL_SECRET_REFERENCE.fullmatch(reference) or reference in seen:
            continue
        seen.add(reference)
        violations.append(
            f"{workflow}: secret references must be spelled `secrets.<UPPER_CASE_NAME>`; "
            f"found {reference!r}"
        )
    return violations


def whole_secrets_context_violations(workflow: str, text: str) -> list[str]:
    """Every `secrets` reference must name exactly one secret.

    `${{ toJSON(secrets) }}`, `${{ fromJSON(toJSON(secrets)) }}` and a bare
    `${{ secrets }}` hand a step every secret the environment holds — the admin
    JWT signing key, the state-writer App private key and the registry token
    alongside the credential bundles — to read a handful of values. Since
    GitHub's 2026-07-28 change, a public-repository run that reads the whole
    secrets context is also held for manual approval before it may start, so
    the privileged workflows silently stop reconciling.

    `secrets['NAME']` is rejected with them: it is one variable substitution
    away from an indexed walk over the whole context, and no workflow here
    needs a dynamic secret name.
    """
    violations: list[str] = []
    seen: set[str] = set()
    for expression in EXPRESSION.finditer(text):
        if not WHOLE_SECRETS.search(NAMED_SECRET.sub("", expression.group(1))):
            continue
        leak = " ".join(expression.group(0).split())
        if leak in seen:
            continue
        seen.add(leak)
        violations.append(
            f"{workflow}: only `secrets.<NAME>` may be referenced, not {leak!r}"
        )
    if re.search(r"^\s*secrets\s*:\s*inherit\s*$", text, re.MULTILINE):
        violations.append(
            f"{workflow}: a called workflow must not inherit the whole secrets context"
        )
    return violations


def credential_shard_limit(root: Path) -> tuple[int | None, list[str]]:
    """Read the bundle-shard ceiling from Rust and from the loader, and pair them.

    The workflows bind each `FERRUM_CREDS_BUNDLE[_N]` secret by name because
    there is no safe way to enumerate the `secrets` context, so the shard count
    is a constant that lives in three places at once. Returns the agreed limit,
    or `None` when the sources disagree (the violations say which).
    """
    violations: list[str] = []
    limits: dict[str, int | None] = {}
    for label, relative, pattern in (
        ("src/secrets/bundle.rs", Path("src/secrets/bundle.rs"), RUST_SHARD_LIMIT),
        (
            ".github/scripts/credential_bundles.py",
            Path(".github/scripts/credential_bundles.py"),
            LOADER_SHARD_LIMIT,
        ),
    ):
        path = root / relative
        match = (
            pattern.search(path.read_text(encoding="utf-8")) if path.is_file() else None
        )
        limits[label] = int(match.group(1)) if match else None
        if limits[label] is None:
            violations.append(f"{label}: MAX_BUNDLE_SHARDS must be declared here")
    rust_limit = limits["src/secrets/bundle.rs"]
    loader_limit = limits[".github/scripts/credential_bundles.py"]
    if rust_limit is not None and loader_limit is not None and rust_limit != loader_limit:
        violations.append(
            f"MAX_BUNDLE_SHARDS disagrees: src/secrets/bundle.rs says {rust_limit}, "
            f".github/scripts/credential_bundles.py says {loader_limit}"
        )
        return None, violations
    if rust_limit is not None and rust_limit < 1:
        violations.append("MAX_BUNDLE_SHARDS must allow at least one bundle shard")
        return None, violations
    return (rust_limit if rust_limit == loader_limit else None), violations


def import_shard_ceiling_violations(root: Path) -> list[str]:
    """Keep import packing on the same named-shard ceiling as allocation."""
    path = root / "src/import/mod.rs"
    source = path.read_text(encoding="utf-8") if path.is_file() else ""
    start = source.find("fn render_migration_bundles(")
    end = source.find("\nfn ", start + 1) if start >= 0 else -1
    packing = source[start:end if end >= 0 else None] if start >= 0 else ""
    if not re.search(
        r'if\s+shard\s*>=\s*MAX_BUNDLE_SHARDS\s*\{\s*'
        r'return\s+Err\(shard_ceiling_error\(slot,\s*"import"\)\);\s*\}',
        packing,
    ):
        return [
            "src/import/mod.rs: migration packing must refuse shard >= "
            "MAX_BUNDLE_SHARDS with the shared shard_ceiling_error"
        ]
    return []


def named_step(text: str, step_name: str) -> str | None:
    marker = f"      - name: {step_name}\n"
    start = text.find(marker)
    if start < 0:
        return None
    end = text.find("\n      - name: ", start + len(marker))
    return text[start:] if end < 0 else text[start:end]


def credential_bundle_binding_violations(
    workflow: str, text: str, limit: int | None
) -> list[str]:
    """The bundle loader must receive exactly the shards the ceiling allows.

    A missing binding is a shard the loader never sees, so the binary reads the
    slots it holds as unallocated and mints duplicates. A binding past the
    ceiling is a shard the allocator refuses to create, so it can only be dead
    configuration that suggests capacity the Rust side will not use.
    """
    step = named_step(text, BUNDLE_LOADER_STEP)
    if step is None:
        return [f"{workflow}: a {BUNDLE_LOADER_STEP!r} step is required"]
    if limit is None:
        return []
    expected = [BUNDLE_SECRET_PREFIX] + [
        f"{BUNDLE_SECRET_PREFIX}_{shard}" for shard in range(1, limit)
    ]
    bound = dict(BUNDLE_BINDING.findall(step))
    violations: list[str] = []
    missing = [name for name in expected if bound.get(name) != name]
    if missing:
        violations.append(
            f"{workflow}: {BUNDLE_LOADER_STEP!r} must bind every bundle shard secret to an "
            f"env var of the same name; missing or mismatched: {', '.join(missing)}"
        )
    extra = sorted(set(bound) - set(expected))
    if extra:
        violations.append(
            f"{workflow}: {BUNDLE_LOADER_STEP!r} binds shards beyond MAX_BUNDLE_SHARDS "
            f"({limit}): {', '.join(extra)}"
        )
    return violations


def admin_jwt_binding_violations(workflow: str, text: str) -> list[str]:
    """A step that mints an admin JWT must receive every documented claim setting.

    GitHub Environment Secrets are not process environment variables. The README
    documents `FERRUM_ADMIN_JWT_ISSUER`, `_ROLE`, `_AUDIENCE` and `_TTL_SECS` as
    per-environment secrets, but binding only `FERRUM_ADMIN_JWT_SECRET` meant the
    workflows always minted the default issuer and role, no audience, and a
    3600s TTL. A gateway configured with a custom issuer or audience, or a
    `FERRUM_ADMIN_JWT_MAX_TTL` under an hour, answered 401 to every call — while
    a local run with the same values exported succeeded.

    Blank stays "unset": the Rust env parser treats empty and whitespace-only
    values as absent, so binding all four is safe on an environment that
    configures none of them.
    """
    violations: list[str] = []
    for step in STEP_SPLIT.split(text):
        name_match = STEP_NAME.search(step)
        name = name_match.group(1) if name_match else "<unnamed step>"
        for binding, secret, settings in (
            (ADMIN_JWT_SECRET_BINDING, "FERRUM_ADMIN_JWT_SECRET", ADMIN_JWT_OPTIONAL_SETTINGS),
            (VIEWER_JWT_SECRET_BINDING, VIEWER_JWT_SECRET, VIEWER_JWT_OPTIONAL_SETTINGS),
        ):
            if not mentions_secret(step, binding):
                continue
            missing = [
                setting
                for setting in settings
                if f"{setting}: ${{{{ secrets.{setting} }}}}" not in step
            ]
            if missing:
                violations.append(
                    f"{workflow}: step {name!r} binds {secret} but not "
                    f"{', '.join(missing)}; a documented per-environment secret that "
                    "never reaches the process is a 401 the operator cannot explain"
                )
    return violations


def admin_api_jwt_bindings(workflow: str) -> tuple[str, ...]:
    """The signing-key bindings that satisfy one admin-API workflow.

    Monitoring must authenticate with the viewer key; every other admin-API
    workflow needs the admin key.
    """
    if workflow == MONITORING_WORKFLOW:
        return MONITORING_JWT_SECRET_BINDINGS
    return (ADMIN_JWT_SECRET_BINDING,)


def viewer_jwt_scope_violations(workflow: str, text: str) -> list[str]:
    """Only scheduled monitoring may hold the viewer-capped signing key.

    `workflow` is the path relative to the repository root, so a composite
    action or a second file named like the monitoring workflow is refused too.
    """
    if workflow in VIEWER_JWT_WORKFLOW_PATHS or not VIEWER_JWT_SECRET_REFERENCE.search(text):
        return []
    return [
        f"{workflow}: only {MONITORING_WORKFLOW} may bind {VIEWER_JWT_SECRET}; "
        "plan, review and apply read GET /backup and cannot use it, and a job "
        "that does not compare must not hold a second gateway key"
    ]


def allocation_revision_binding_violations(workflow: str, text: str) -> list[str]:
    """Every apply step must bind the allocation revision to the triggering merge.

    A recorded allocation newer than the last clean apply is exempt from the
    revived-slot refusal only for the apply that recorded it, identified by
    `GITFORGEOPS_ALLOCATION_REVISION`. Unbound, the binary falls back to the
    checked-out commit — the refreshed head, which a failed attempt's state
    commit moves — and a re-run refuses the slots its first attempt allocated.
    """
    violations: list[str] = []
    for step in STEP_SPLIT.split(text):
        if APPLY_COMMAND not in step or ALLOCATION_REVISION_BINDING in step:
            continue
        name_match = STEP_NAME.search(step)
        name = name_match.group(1) if name_match else "<unnamed step>"
        violations.append(
            f"{workflow}: step {name!r} must bind {ALLOCATION_REVISION_BINDING!r}; "
            "the applied head moves between attempts, so a retry could not "
            "recognize the credential slots its failed attempt allocated"
        )
    return violations


def stale_deployment_guard_violations(
    workflow: str, text: str, contract: dict
) -> list[str]:
    """A privileged reconcile must read the branch head it actually holds the lock for.

    The concurrency group serializes applies per environment, but
    `actions/checkout` selects the commit that TRIGGERED the run. A merge queued
    behind a running apply therefore reconciles from a `.state/<env>.json` that
    predates the ledger the earlier run publishes — shared mode reads the rows it
    never saw as "never managed" and quietly stops reconciling them — and a
    re-run of an old workflow replays an old desired snapshot over newer
    configuration.

    So an environment-bound job must, after the lock is held and before it
    builds a binary or touches the gateway: check out the protected branch with
    enough history to test ancestry, re-fetch it, move onto its current head,
    print both revisions, and fail closed unless the triggering commit is still
    an ancestor of that head.

    Evaluated **per job**. Measured across a whole file the rule only reads
    correctly while a workflow has exactly one privileged job: `named_step`
    would check the first guard and leave a second job's unchecked, and the
    ordering comparisons would relate steps that never run in the same runner.
    A staged promotion needs a second such job, and it needs its own guard.
    """
    violations: list[str] = []
    # A *reconciling* job is one that holds the lock: it binds a GitHub
    # Environment and serializes on the shared `ferrum-apply-<env>` group.
    # Defining the set that way rather than "jobs that already have a guard"
    # is what makes a missing guard visible — a job identified by the guard it
    # carries cannot be reported for not carrying one.
    reconciling = [
        (name, body)
        for name, body in workflow_jobs(text)
        if ENVIRONMENT_BINDING.search(body) and APPLY_CONCURRENCY_GROUP.search(body)
    ]
    if not reconciling:
        return [
            f"{workflow}: no environment-bound, ferrum-apply-serialized job exists, "
            "so nothing reconciles under the lock the freshness guard depends on"
        ]

    for job, body in reconciling:
        label = f"{workflow}: job {job!r}"
        marker = f"      - name: {FRESH_HEAD_STEP}\n"
        if marker not in body:
            violations.append(
                f"{label}: a {FRESH_HEAD_STEP!r} step must refresh the protected "
                "branch and reject a stale deployment before any gateway step"
            )
            continue
        guard_index = body.index(marker)

        # The privileged checkout is whichever `actions/checkout` precedes the
        # guard in this job. Naming it by step title would force every job to
        # reuse one label; what matters is the three properties.
        checkout = _checkout_before(body, guard_index)
        if checkout is None:
            violations.append(
                f"{label}: a checkout of the protected branch must precede "
                f"{FRESH_HEAD_STEP!r}"
            )
        else:
            for required in FRESH_HEAD_CHECKOUT:
                if required not in checkout:
                    violations.append(
                        f"{label}: the checkout before {FRESH_HEAD_STEP!r} must name "
                        "the protected branch with enough history to test ancestry; "
                        f"missing {required!r}"
                    )

        guard = named_step(body, FRESH_HEAD_STEP) or ""
        for required in FRESH_HEAD_CONTROLS:
            if required not in guard:
                violations.append(f"{label}: {FRESH_HEAD_STEP!r} is missing {required!r}")

        # Unconditional: a job that holds the lock and refreshes onto a newer
        # head must prove that head is the revision its approval covers. Gating
        # this on one workflow name is what left rotation binding by ancestry
        # alone.
        violations.extend(_revision_binding_violations(label, guard))

        for marker in contract["gateway"]:
            # Present AND after the guard. "After" alone would let the step be
            # deleted outright, and a reconciling job that never loads the
            # credential bundle or never builds the binary is not a safer job
            # — it is a differently broken one.
            #
            # `rfind` within the job: an enumerator job builds the binary too,
            # and it is this job's copy that has to come from the refreshed head.
            marker_index = body.rfind(marker)
            if not 0 <= guard_index < marker_index:
                violations.append(
                    f"{label}: {marker!r} must be present and must not run before "
                    "the freshness guard; the binary, the desired state and the "
                    "ledger all come from the refreshed protected head"
                )
    return violations


def _revision_binding_violations(label: str, guard: str) -> list[str]:
    """The guard must run one recognized classifier binding, uninterrupted."""
    lines = [line.strip() for line in guard.splitlines()]
    satisfied = [
        family for family in APPLY_REVISION_BINDINGS if _contains_run(lines, family)
    ]
    if not satisfied:
        # Report the closest family so the message names something
        # actionable rather than every alternative at once.
        closest = max(
            APPLY_REVISION_BINDINGS,
            key=lambda family: sum(1 for item in family if item in lines),
        )
        missing = [item for item in closest if item not in lines]
        detail = (
            f"closest is missing {', '.join(repr(item) for item in missing)}"
            if missing
            else "closest has every line, but not as one uninterrupted sequence"
        )
        return [
            f"{label}: {FRESH_HEAD_STEP!r} must bind PR attribution and "
            "environment approval to unchanged executable and desired inputs; "
            f"no recognized implementation is complete ({detail})"
        ]

    prelude = guard.find(PIPED_BINDING_PRELUDE)
    if prelude < 0:
        return [
            f"{label}: {FRESH_HEAD_STEP!r} pipes the trusted classifier, so its "
            "script must open with 'set -euo pipefail'; otherwise a failed "
            "extraction runs an empty program that approves the revision"
        ]
    changed = [
        line.strip()
        for line in guard[prelude + len(PIPED_BINDING_PRELUDE):].splitlines()
        if not line.strip().startswith("#") and SHELL_OPTION_COMMAND.search(line)
    ]
    if changed:
        return [
            f"{label}: {FRESH_HEAD_STEP!r} pipes the trusted classifier, so it "
            "must not change shell options after 'set -euo pipefail'; found "
            f"{changed[0]!r}"
        ]
    return []


def _contains_run(lines: list[str], family: tuple[str, ...]) -> bool:
    """Whether `family` appears as consecutive lines of `lines`."""
    width = len(family)
    return any(
        tuple(lines[index:index + width]) == family
        for index in range(len(lines) - width + 1)
    )


def _checkout_before(body: str, guard_index: int) -> str | None:
    """The last `actions/checkout` step in this job before the guard."""
    matches = [
        match
        for match in re.finditer(r"^      - (?:name:.*|uses: actions/checkout@)", body, re.MULTILINE)
        if match.start() < guard_index
    ]
    for match in reversed(matches):
        end = body.find("\n      - ", match.end())
        step = body[match.start():] if end < 0 else body[match.start():end]
        if "uses: actions/checkout@" in step:
            return step
    return None


def deployment_scope_violations(root: Path, apply_workflow: str) -> list[str]:
    """Scheduling and supersession must be the same set of paths.

    `apply-on-merge.yml` only runs for pushes that touch its `paths:` filter,
    and its freshness guard refuses to reconcile a refreshed head that changed a
    deployment input since the triggering merge. When those two sets differ in
    the wrong direction a merge can cancel an authorized apply without
    scheduling anything to replace it — a README-only push used to strand a
    queued configuration change permanently, with the guard telling the operator
    to wait for an apply run that would never exist.

    Equality removes the failure by construction: a path that supersedes always
    schedules a replacement, and a path that schedules nothing can never
    supersede. `.state/**` and `assembled/**` must be in neither — as deployment
    inputs they would reject every queued run, and as triggers the ledger commit
    each apply pushes would re-trigger the workflow that wrote it.
    """
    violations: list[str] = []
    script = root / DEPLOYMENT_SCOPE_SCRIPT
    if not script.is_file():
        return [
            f"{DEPLOYMENT_SCOPE_SCRIPT}: the shared deployment-scope classifier "
            "must exist; apply scheduling and supersession are defined by it"
        ]
    source = script.read_text(encoding="utf-8")
    declared = DEPLOYMENT_INPUT_TUPLE.search(source)
    if declared is None:
        return [
            f"{DEPLOYMENT_SCOPE_SCRIPT}: DEPLOYMENT_INPUT_PATHS must be declared here"
        ]
    scope_paths = QUOTED.findall(declared.group("body"))
    generated = GENERATED_PATH_TUPLE.search(source)
    generated_paths = QUOTED.findall(generated.group("body")) if generated else []
    if not generated_paths:
        violations.append(
            f"{DEPLOYMENT_SCOPE_SCRIPT}: GENERATED_PATHS must name the ledger and "
            "assembled output this workflow writes back to the protected branch"
        )
    for produced in generated_paths:
        if produced in scope_paths:
            violations.append(
                f"{DEPLOYMENT_SCOPE_SCRIPT}: {produced!r} is written by the apply "
                "itself and must not be a deployment input"
            )

    trigger = PUSH_PATHS_BLOCK.search(apply_workflow)
    if trigger is None:
        return violations + [
            "apply-on-merge.yml: a push trigger with an explicit paths filter is "
            "required; an unfiltered trigger re-runs on its own ledger commit"
        ]
    trigger_paths = [
        line.strip().lstrip("- ").strip().strip("'\"")
        for line in trigger.group("body").splitlines()
        if line.strip()
    ]
    for produced in generated_paths:
        if produced in trigger_paths:
            violations.append(
                f"apply-on-merge.yml: {produced!r} must not trigger the workflow "
                "that writes it; the ledger commit would re-trigger the apply"
            )
    missing = sorted(set(scope_paths) - set(trigger_paths))
    extra = sorted(set(trigger_paths) - set(scope_paths))
    if missing:
        violations.append(
            "apply-on-merge.yml: every deployment input must schedule its own "
            "apply or it supersedes a queued run with no replacement; the push "
            f"trigger is missing {', '.join(repr(item) for item in missing)}"
        )
    if extra:
        violations.append(
            "apply-on-merge.yml: the push trigger schedules applies for "
            f"{', '.join(repr(item) for item in extra)}, which "
            f"{DEPLOYMENT_SCOPE_SCRIPT} does not treat as a deployment input; "
            "add them to DEPLOYMENT_INPUT_PATHS or drop them from the trigger"
        )
    return violations


def monitoring_workflow_violations(text: str) -> list[str]:
    """Unattended monitoring must be able to read a gateway and nothing else.

    A scheduled drift check bound to an approval-gated deployment environment
    never runs: GitHub withholds the environment's secrets until a reviewer
    approves the job, so a nightly run parks in "waiting for approval" and
    inspects nothing. Moving the check into its own environment with no
    required reviewer is what makes it unattended — and that is only
    acceptable while the job's reachable authority is a gateway *read*.

    So the fence is enforced here, statically, on top of the environment-level
    secret-name audit: no credential-broker token, no state-writer key, no
    administration-read token, no credential bundle, no write permission, and
    no `gitforgeops` subcommand other than `diff`.
    """
    violations: list[str] = []
    for secret in MONITORING_FORBIDDEN_SECRETS:
        if mentions_secret(text, f"secrets.{secret}"):
            violations.append(
                f"{MONITORING_WORKFLOW}: unattended monitoring may not reach "
                f"{secret!r}; it runs in an environment with no required "
                "reviewer, so its authority must stop at reading the gateway"
            )
    for command in re.findall(r"gitforgeops [a-z-]+[^\n]*", text):
        subcommand = command.split()[1]
        if subcommand in {"envs", "version"}:
            # Enumeration runs in the unprivileged job that binds no
            # environment at all.
            continue
        if not command.startswith(MONITORING_ALLOWED_COMMAND):
            violations.append(
                f"{MONITORING_WORKFLOW}: monitoring may only run "
                f"{MONITORING_ALLOWED_COMMAND!r}; found {command!r}"
            )
    if MONITORING_ALLOWED_COMMAND not in text:
        violations.append(
            f"{MONITORING_WORKFLOW}: the drift job must run "
            f"{MONITORING_ALLOWED_COMMAND!r}"
        )
    write_permission = re.compile(
        r"^\s+(?:contents|packages|id-token|actions|pull-requests|deployments|"
        r"issues|statuses|checks|security-events):\s*write\s*$",
        re.MULTILINE,
    )
    if write_permission.search(text):
        violations.append(
            f"{MONITORING_WORKFLOW}: monitoring must hold no write permission"
        )
    # The outcome taxonomy is the other half of the ask: a check that failed,
    # was skipped, or never ran must not read as a gateway that matched.
    if ".github/scripts/drift_report.py" not in text:
        violations.append(
            f"{MONITORING_WORKFLOW}: outcomes must be classified by "
            "drift_report.py so a failed, skipped or never-started check "
            "cannot be reported as in sync"
        )
    return violations


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
    # Deliveries for one head (opened plus one `labeled` per label) start out
    # of order, so any shared concurrency group — per PR or per head,
    # cancelling in progress or not — can cancel the newest check suite and
    # leave the required check cancelled beside an older success (#407).
    if declares_concurrency(text):
        violations.append(
            "state-guard.yml: the guard must not declare a concurrency group; "
            "a cancelled newest run leaves the required check cancelled"
        )
    return violations


_YAML_ESCAPED_LINE_BREAK = re.compile(r"\\\r?\n[ \t]*")
_YAML_HEX_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")
_CONCURRENCY_WORD = re.compile(r"concurrency", re.IGNORECASE)


def _decode_yaml_escape(match: re.Match[str]) -> str:
    code = int(next(group for group in match.groups() if group is not None), 16)
    return chr(code) if code <= sys.maxunicode else ""


def declares_concurrency(text: str) -> bool:
    """Whether a workflow could declare `concurrency` at any mapping level.

    A key-shaped regex misses too many YAML spellings of the same key: quoted
    (`"concurrency":`), inside a flow mapping (`{runs-on: x, concurrency: g}`),
    an explicit key (`? concurrency` with `: g` on the next line), behind a tag
    or anchor, or spelled with double-quoted escapes (`"\\x63oncurrency"`).
    Rather than parse YAML, this fails closed: after dropping full-line
    comments and decoding double-quoted escapes, the word may not appear at
    all, in any case. A run script or trailing comment that merely mentions it
    is refused too; reword it.
    """
    return _CONCURRENCY_WORD.search(decoded_workflow_content(text)) is not None


def decoded_workflow_content(text: str) -> str:
    """A workflow without full-line comments, double-quoted escapes decoded.

    Not a YAML parser. It is the fail-closed reading the word-level rules use:
    a key or value spelled with `\\x`/`\\u`/`\\U` escapes or an escaped line
    break reads the same as its plain spelling.
    """
    content = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    content = _YAML_ESCAPED_LINE_BREAK.sub("", content)
    return _YAML_HEX_ESCAPE.sub(_decode_yaml_escape, content)


# The last step before the guard reports an authorized override re-reads the
# pull request, so an override label removed, a head pushed, or a base
# retargeted while the run was in flight fails that run instead of leaving a
# success behind it.
STATE_GUARD_RECORD_STEP = "Record authorized override"
STATE_GUARD_RECORD_IF = (
    "${{ steps.detect.outputs.requires_override == 'true' "
    "&& steps.authorize.outcome == 'success' }}"
)
STATE_GUARD_FINAL_RECHECK = (
    'final=$(gh api "repos/${REPO}/pulls/${PR_NUMBER}")',
    "final_head=$(jq -r '.head.sha' <<< \"$final\")",
    "final_ref=$(jq -r '.base.ref' <<< \"$final\")",
    "final_labels=$(jq -r '.labels[].name' <<< \"$final\")",
    '[ "$final_head" = "$EXPECTED_HEAD_SHA" ] || {',
    '[ "$final_ref" = "$DEFAULT_BRANCH" ] || {',
    'grep -Fxq "$OVERRIDE_LABEL" <<< "$final_labels" || {',
)


def state_guard_override_recheck_violations(text: str) -> list[str]:
    """An authorized override must be re-confirmed right before it reports."""
    step = named_step(text, STATE_GUARD_RECORD_STEP)
    if step is None:
        return [f"state-guard.yml: the {STATE_GUARD_RECORD_STEP!r} step is missing"]
    active_step = "\n".join(
        "" if line.lstrip().startswith("#") else line for line in step.splitlines()
    )
    violations: list[str] = []
    if "set -euo pipefail" not in active_step:
        violations.append(
            f"state-guard.yml: {STATE_GUARD_RECORD_STEP!r} must run under set -euo pipefail"
        )
    if re.search(r"^\s*continue-on-error\s*:", active_step, re.MULTILINE):
        violations.append(
            f"state-guard.yml: {STATE_GUARD_RECORD_STEP!r} must not use continue-on-error"
        )
    conditions = re.findall(r"^\s*if:\s*(.*?)\s*$", active_step, re.MULTILINE)
    if conditions != [STATE_GUARD_RECORD_IF]:
        violations.append(
            f"state-guard.yml: {STATE_GUARD_RECORD_STEP!r} must keep its if: condition pinned"
        )
    positions = []
    for required in STATE_GUARD_FINAL_RECHECK:
        position = active_step.find(required)
        if position < 0:
            violations.append(
                f"state-guard.yml: {STATE_GUARD_RECORD_STEP!r} must re-read the pull "
                f"request before reporting success; missing {required!r}"
            )
        positions.append(position)
    for report in ("::warning::", '>> "$GITHUB_STEP_SUMMARY"'):
        position = active_step.find(report)
        if position >= 0 and any(position < check for check in positions):
            violations.append(
                f"state-guard.yml: {STATE_GUARD_RECORD_STEP!r} must finish its final "
                "pull-request recheck before reporting the override"
            )
            break
    return violations


def rust_toolchain_violations(workflow: str, text: str, channel: str) -> list[str]:
    """Every `dtolnay/rust-toolchain` step must select the exact toolchain.

    Checking that the repository's channel appears *somewhere* in the file
    lets a second Rust step — or a copied step that lost its `with:` block —
    install the action's floating default while the first step's pin keeps the
    workflow green. Match every step against the repository pin instead.
    """
    for step in STEP_SPLIT.split(text):
        if "dtolnay/rust-toolchain@" not in step:
            continue
        if not re.search(
            rf"^\s*toolchain:\s*{re.escape(channel)}\s*$", step, re.MULTILINE
        ):
            return [
                f"{workflow}: every dtolnay/rust-toolchain step must select exact toolchain {channel}"
            ]
    return []


def cargo_toolchain_violations(workflow: str, text: str, channel: str) -> list[str]:
    """Keep explicit cargo toolchain overrides aligned with the repo channel."""
    for match in re.finditer(r"\bcargo\s+\+(\d+\.\d+\.\d+)(?=\s|$)", text):
        if match.group(1) != channel:
            return [
                f"{workflow}: explicit cargo toolchain overrides must match "
                f"rust-toolchain.toml channel {channel}"
            ]
    return []


def read_rust_toolchain_channel(path: Path) -> str | None:
    """Read the single pinned channel used by workflows and release provenance."""
    if path.with_name("rust-toolchain").exists():
        return None
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return None
    if set(document) != {"toolchain"}:
        return None
    toolchain = document["toolchain"]
    if not isinstance(toolchain, dict) or not set(toolchain).issubset(
        {"channel", "components", "targets", "profile"}
    ):
        return None
    channel = toolchain.get("channel")
    match = RUST_TOOLCHAIN_CHANNEL.fullmatch(channel) if isinstance(channel, str) else None
    if match is None:
        return None
    if tuple(int(part) for part in match.groups()) < MIN_RUST_TOOLCHAIN:
        return None
    return channel


def dockerfile_instructions(text: str) -> list[str] | None:
    """Return Dockerfile logical instructions, refusing ambiguous syntax.

    Docker parses continuations before instructions. Ambiguous heredoc and
    parser-directive syntax is refused rather than interpreted approximately.
    """
    # Docker's parser splits only at LF and trims only a CR immediately before
    # it. Other Unicode and control whitespace can change where its parser sees
    # continuations, so reject those bytes instead of guessing.
    forbidden_whitespace = (
        "\u00a0\u1680"
        + "".join(chr(codepoint) for codepoint in range(0x2000, 0x2010))
        + "\u2028\u2029\u202f\u205f\u3000\ufeff\x0b\x0c\x1c\x1d\x1e\x1f\x85"
    )
    if any(character in text for character in forbidden_whitespace):
        return None

    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    if "<<" in text:
        # Heredoc recognition is shell-lexer-sensitive. Dockerfiles in this
        # repository do not need heredocs, so refuse ambiguous inputs.
        return None
    if any(line.endswith("\\\\") for line in lines):
        return None

    for line in lines:
        directive = re.match(r"^[ \t]*#[ \t]*(syntax|escape|check)[ \t]*=", line, re.I)
        if directive is None:
            continue
        return None

    instructions: list[str] = []
    supported_instructions = {
        "ADD",
        "ARG",
        "CMD",
        "COPY",
        "ENTRYPOINT",
        "ENV",
        "EXPOSE",
        "FROM",
        "HEALTHCHECK",
        "LABEL",
        "MAINTAINER",
        "ONBUILD",
        "RUN",
        "SHELL",
        "STOPSIGNAL",
        "USER",
        "VOLUME",
        "WORKDIR",
    }
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        stripped = line.lstrip(" \t")
        if not stripped or stripped.startswith("#"):
            continue

        logical = stripped.rstrip(" \t")
        while True:
            if not re.search(r"(?<!\\)\\[ \t]*$|^\\[ \t]*$", logical):
                break
            logical = re.sub(r"\\[ \t]*$", "", logical)
            if index >= len(lines):
                return None
            continuation = lines[index]
            index += 1
            continuation = continuation.lstrip(" \t")
            if not continuation or continuation.startswith("#"):
                continue
            logical += " " + continuation.rstrip(" \t")

        instruction = re.match(r"^([A-Za-z]+)(?:\s+(.*))?$", logical)
        if instruction is None or instruction.group(1).upper() not in supported_instructions:
            return None
        instructions.append(logical)

    return instructions


def docker_builder_toolchain_violations(text: str, channel: str) -> list[str]:
    """Require every Rust FROM image and the sole builder stage to use channel."""
    instructions = dockerfile_instructions(text)
    if instructions is None:
        return ["Dockerfile: could not parse Dockerfile instructions"]

    violations: list[str] = []
    # Independently inspect every physical FROM-looking line. This superset
    # scan ensures a parser discrepancy cannot hide a real Docker stage.
    physical_froms = []
    for physical_line in text.split("\n"):
        if physical_line.endswith("\r"):
            physical_line = physical_line[:-1]
        candidate = physical_line.lstrip(" \t")
        if re.match(r"^FROM\b", candidate, re.IGNORECASE):
            physical_froms.append(candidate)

    def check_from(arguments: str) -> tuple[str, str | None] | None:
        if arguments.endswith("\\"):
            return None
        match = re.fullmatch(
            r"(?:--platform=\S+[ \t]+)?(\S+)(?:[ \t]+AS[ \t]+([A-Za-z0-9_.-]+))?",
            arguments,
            re.IGNORECASE,
        )
        if match is None or "$" in match.group(1):
            return None
        return match.group(1), match.group(2)

    checked_physical_froms: list[tuple[str, str | None]] = []
    for line in physical_froms:
        parsed = re.match(r"^FROM[ \t]+(.*)$", line, re.IGNORECASE)
        checked = check_from(parsed.group(1)) if parsed else None
        if checked is None:
            return ["Dockerfile: could not parse FROM instruction"]
        checked_physical_froms.append(checked)

    checked_logical_froms: list[tuple[str, str | None]] = []
    builder_count = 0
    for instruction in instructions:
        parsed_instruction = re.match(r"^([A-Za-z]+)(?:\s+(.*))?$", instruction)
        if parsed_instruction is None:
            return ["Dockerfile: could not parse Dockerfile instructions"]
        if parsed_instruction.group(1).upper() != "FROM":
            continue
        arguments = parsed_instruction.group(2) or ""
        match = check_from(arguments)
        if match is None:
            return ["Dockerfile: could not parse FROM instruction"]

        image, stage_name = match
        checked_logical_froms.append(match)
        if stage_name and stage_name.lower() == "builder":
            builder_count += 1

    builder_uses_rust = False
    rust_image_found = False
    # Physical lines can be shell text or heredoc data. They still must not
    # contain a Rust image on a different channel. Logical instructions are
    # also checked because a continued FROM can hide its image from the
    # physical-line scan.
    for image, stage_name in checked_logical_froms + checked_physical_froms:
        image_name = image.rsplit("/", 1)[-1]
        if not (image_name.startswith("rust:") or image_name.startswith("rust@")):
            continue
        rust_image_found = True
        if stage_name and stage_name.lower() == "builder":
            builder_uses_rust = True
        tagged = image_name.startswith("rust:")
        tag_and_digest = image_name[len("rust:") :] if tagged else ""
        tag = tag_and_digest.split("@", 1)[0]
        if not tagged or not re.fullmatch(
            rf"{re.escape(channel)}(?:-[A-Za-z0-9_.-]+)?", tag
        ):
            violations.append(
                "Dockerfile: every Rust base image version must match "
                f"rust-toolchain.toml channel {channel}"
            )

    if builder_count != 1:
        violations.append("Dockerfile: expected exactly one stage named builder")
    if not rust_image_found or not builder_uses_rust:
        violations.append("Dockerfile: builder stage must use a Rust base image")
    return violations


def rust_ci_test_scope_violations(text: str) -> list[str]:
    """Rust CI must execute the library target unfiltered, beside the suite.

    Inline `#[cfg(test)]` modules compile under clippy's `--all-targets` but
    only run under `cargo test --lib`. A name filter on that command once
    skipped every library test but one, and coverage measured only the
    aggregated binary. Exact lines keep a filtered or dropped invocation
    from satisfying the gate.
    """
    violations: list[str] = []
    test_lines = [
        line.strip()
        for line in policy_step(workflow_job(text, "rust-ci-check"), "cargo test")
    ]
    for command in ("cargo test --test unit_tests", "cargo test --lib"):
        if command not in test_lines:
            violations.append(
                f"rust-ci.yml: the cargo test step must run `{command}` unfiltered"
            )
    coverage = [
        line.strip()
        for line in policy_step(workflow_job(text, "coverage"), "cargo llvm-cov")
    ]
    if "run: cargo llvm-cov --lib --test unit_tests --lcov --output-path lcov.info" not in coverage:
        violations.append(
            "rust-ci.yml: coverage must measure the library target and the aggregated suite"
        )
    return violations


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
    if mentions_secret(text, "secrets.GITFORGEOPS_STATE_APP_ID"):
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


def untrusted_pr_installer_violations(text: str) -> list[str]:
    """Keep the PR token out of scripts supplied by the candidate checkout.

    The validator download step hands `GITHUB_TOKEN` to the installer so the
    release-asset API call is authenticated. Running that installer from the
    pull request's own checkout would hand the token to a script the pull
    request wrote, so the code comes from the protected default branch.

    The *allowlist* deliberately still comes from the candidate. A pull
    request that refreshes the validator pin has to be validated against the
    allowlist it is adding, or the pin could never be refreshed without first
    merging an unvalidated change. The residual risk is bounded: the trusted
    installer still requires the publisher's own checksum file to match the
    bytes it downloaded from `ferrum-edge/ferrum-edge`, so a hostile allowlist
    can at most approve a *different genuine upstream build* rather than
    attacker-supplied bytes, and this job holds no secret beyond a read-only
    token and already runs the pull request's own Cargo build scripts. Every
    privileged consumer (`trusted-pr-review.yml`, `apply-on-merge.yml`) uses
    the trusted allowlist instead.
    """
    violations: list[str] = []

    checkout = named_step(text, "Check out trusted validator installer")
    if checkout is None:
        violations.append(
            "validate-pr.yml: the validator installer must come from a protected "
            "default-branch checkout"
        )
    else:
        for required in (
            "ref: ${{ github.event.repository.default_branch }}",
            "path: trusted-validator",
        ):
            if required not in checkout:
                violations.append(
                    f"validate-pr.yml: trusted validator checkout is missing {required!r}"
                )

    install = named_step(text, "Download verified ferrum-edge binary")
    if install is None:
        violations.append("validate-pr.yml: the validator download step is missing")
        return violations

    # Collapse YAML line continuations so the assertion reads the argv the
    # step actually runs rather than the way it happens to be wrapped. A
    # prose mention of the allowlist in a comment cannot satisfy it.
    command = " ".join(install.replace("\\\n", " ").split())
    if not re.search(
        r"bash trusted-validator/\.github/scripts/install-ferrum-edge\.sh "
        r"\S+ \.github/ferrum-edge-checksums\.txt",
        command,
    ):
        violations.append(
            "validate-pr.yml: the trusted installer must run with the candidate's "
            "reviewed digest allowlist as its second argument"
        )
    if "bash .github/scripts/install-ferrum-edge.sh" in text:
        violations.append(
            "validate-pr.yml: candidate-checkout installer must not receive the GitHub token"
        )
    return violations


def workflow_job(text: str, job: str) -> str:
    """Read one conventionally indented job; duplicate/missing jobs fail closed."""
    matches = list(re.finditer(rf"^  {re.escape(job)}:\n", text, re.MULTILINE))
    if len(matches) != 1:
        return ""
    return re.split(
        r"^  \S|^\S", text[matches[0].end():], maxsplit=1, flags=re.MULTILINE
    )[0]


def policy_step(job: str, name: str) -> list[str]:
    """Require one real step, excluding comments and adjacent unnamed steps.

    These security steps intentionally have a narrow, reviewed shape. Exact
    lines prevent a commented invocation, conditional, alternate shell, early
    exit or swallowed failure from satisfying the executable contract.
    """
    steps = [
        step
        for step in re.split(r"^      - ", job, flags=re.MULTILINE)[1:]
        if step.startswith(f"name: {name}\n")
    ]
    if len(steps) != 1:
        return []
    return [
        line.split("#", 1)[0].rstrip()
        for line in steps[0].splitlines()
        if line.split("#", 1)[0].strip()
    ]


def trusted_validator_probe_violations(text: str) -> list[str]:
    """Candidate digests must pass trusted code AND its script-relative fixture."""
    violations: list[str] = []
    for job_name, checkout_name, install_name in (
        (
            "validate",
            "Check out trusted validator installer",
            "Download verified ferrum-edge binary",
        ),
        (
            "validator-pairing",
            "Check out trusted pairing installer",
            "Download pairing validator",
        ),
    ):
        job = workflow_job(text, job_name)
        prefix = f"validate-pr.yml: {job_name}"
        checkout = policy_step(job, checkout_name)
        if (
            len(checkout) != 6
            or not checkout[1].startswith("        uses: actions/checkout@")
            or checkout[2:] != [
                "        with:",
                "          ref: ${{ github.event.repository.default_branch }}",
                "          path: trusted-validator",
                "          persist-credentials: false",
            ]
        ):
            violations.append(
                f"{prefix} requires an unconditional protected default-branch checkout"
            )
        install = policy_step(job, install_name)
        if install != [
            f"name: {install_name}",
            "        env:",
            "          GITHUB_TOKEN: ${{ github.token }}",
            "        run: |",
            "          bash trusted-validator/.github/scripts/install-ferrum-edge.sh \\",
            '            "$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge" \\',
            "            .github/ferrum-edge-checksums.txt",
        ]:
            violations.append(
                f"{prefix} must install with trusted code and the candidate allowlist"
            )
        probe_name = "Require resource-label compatibility"
        if policy_step(job, probe_name) != [
            f"name: {probe_name}",
            "        run: |",
            "          bash trusted-validator/.github/scripts/check-validator-resource-labels.sh \\",
            '            "$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"',
        ]:
            violations.append(
                f"{prefix} must run the trusted resource-label probe without a bypass or token"
            )
        if not (
            0 <= job.find(f"- name: {checkout_name}")
            < job.find(f"- name: {install_name}")
            < job.find(f"- name: {probe_name}")
        ):
            violations.append(f"{prefix} must check out, install, then probe the validator")
    return violations


def cargo_audit_install_violations(text: str) -> list[str]:
    """Pin the installer and manifest-backed tool; never restore an executable."""
    job = workflow_job(text, "security-cargo-audit")
    violations: list[str] = []
    install_step = policy_step(job, "Install cargo-audit")
    allowed_action_lines = {f"        uses: {action}" for action in CARGO_AUDIT_ACTIONS}
    if (
        len(install_step) != 6
        or install_step[0] != "name: Install cargo-audit"
        or install_step[1] not in allowed_action_lines
        or install_step[2:] != [
            "        with:",
            "          tool: cargo-audit@0.22.1",
            "          checksum: true",
            "          fallback: none",
        ]
    ):
        violations.append(
            "security.yml: cargo-audit 0.22.1 must use the reviewed install-action "
            "with checksums, no fallback, and no conditional or failure bypass"
        )
    if any("cache" in reference.lower() for reference in USES.findall(job)):
        violations.append("security.yml: cargo-audit must not restore the old executable cache")
    if re.search(r"\bcargo\s+(?:install|binstall)\b", job):
        violations.append("security.yml: cargo-audit must not use a registry install fallback")
    if not (
        0 <= job.find("- name: Install cargo-audit")
        < job.find("- name: Enforce cargo audit policy")
    ):
        violations.append("security.yml: install cargo-audit before enforcing its policy")
    return violations


def security_push_trigger_violations(text: str) -> list[str]:
    """Keep post-merge checks for policy-only changes, independently of PRs."""
    match = re.search(r"^  push:\n((?:^    .*\n)*)", text, re.MULTILINE)
    if match is None:
        return ["security.yml: push trigger is missing"]
    body = match.group(1)
    violations: list[str] = []
    if "    branches: [main]\n" not in body:
        violations.append("security.yml: push trigger must target protected main")
    paths = re.search(r"^    paths:\n((?:^      - .*\n)*)", body, re.MULTILINE)
    entries = (
        [] if paths is None else [
            line[8:].split("#", 1)[0].strip().strip("'\"")
            for line in paths.group(1).splitlines()
        ]
    )
    for path in SECURITY_PUSH_POLICY_PATHS:
        if path not in entries:
            violations.append(f"security.yml: push paths must explicitly include {path}")
    if "paths-ignore:" in body or any(entry.startswith("!") for entry in entries):
        violations.append("security.yml: push paths must not exclude policy inputs")
    return violations


# The exact triggers `security.yml` may carry. `security-cargo-audit` and
# `security-supply-chain-policy` are required contexts defined by the pull
# request's own copy of this workflow, and every pinned job switches on
# `github.event_name`. An added trigger — `workflow_dispatch:` above all —
# would run that candidate copy outside `pull_request`, take the `else` branch
# and post a second result under a required check name from a run no rule
# reviewed. So the trigger list is part of the pinned shape.
SECURITY_TRIGGERS = ("pull_request", "push", "schedule")
SECURITY_PULL_REQUEST_SHAPE = {
    "types": ["opened", "synchronize", "reopened", "edited"],
    "branches": ["main"],
}
SECURITY_PUSH_BRANCHES = ["main"]


def security_trigger_violations(text: str) -> list[str]:
    """`security.yml` may run on exactly the reviewed triggers.

    Read from the strict workflow reader, so the checked list is the one the
    runner acts on. The required `security-cargo-audit` and
    `security-supply-chain-policy` jobs switch on `github.event_name`, so an
    extra trigger would run the candidate's own copy of the workflow on an
    event this policy never reviewed and post another check run under the
    required name. Pin the key set, the pull request types and branch, and the
    push branch.
    """
    try:
        document = parse_workflow(text)
    except WorkflowSyntaxError as error:
        return [
            "security.yml: the trigger list must be in the YAML subset the "
            f"policy reads: {error}"
        ]
    candidates = [value for key, value in document.items() if key.casefold() == "on"]
    if len(candidates) != 1 or not isinstance(candidates[0], dict):
        return ["security.yml: the workflow must declare exactly one `on:` mapping"]
    triggers = candidates[0]
    violations: list[str] = []
    for found in triggers:
        if found.casefold() not in {name.casefold() for name in SECURITY_TRIGGERS}:
            violations.append(
                f"security.yml: the trigger {found!r} is not reviewed; the only "
                f"reviewed triggers are {', '.join(SECURITY_TRIGGERS)}"
            )
    spelled = {found.casefold(): found for found in triggers}
    for name in SECURITY_TRIGGERS:
        if name.casefold() not in spelled:
            violations.append(f"security.yml: the reviewed trigger {name!r} is missing")
    pull_request = triggers.get(spelled.get("pull_request", ""))
    if pull_request is not None and pull_request != SECURITY_PULL_REQUEST_SHAPE:
        violations.append(
            "security.yml: pull_request must keep its reviewed types and branch; "
            f"expected {SECURITY_PULL_REQUEST_SHAPE!r}, found {pull_request!r}"
        )
    push = triggers.get(spelled.get("push", ""))
    if isinstance(push, dict) and push.get("branches") != SECURITY_PUSH_BRANCHES:
        violations.append(
            "security.yml: push must keep its reviewed branch; "
            f"expected {SECURITY_PUSH_BRANCHES!r}, found {push.get('branches')!r}"
        )
    return violations


def allowlisted_validator_digests(text: str) -> list[str]:
    """Return every approved validator digest, in file order."""
    digests: list[str] = []
    for line in text.splitlines():
        record = line.split("#", 1)[0].strip()
        match = DIGEST_ENTRY.fullmatch(record) if record else None
        if match is not None:
            digests.append(match.group(1))
    return digests


def digest_allowlist_violations(text: str) -> list[str]:
    """The validator is pinned by content, so the allowlist must stay exact.

    One `<sha256>  <asset>` record per approved build, comments allowed, and no
    locator fields: a new version tag is a new candidate, but the pin remains
    the digest. Tags name the candidate; content is the trust anchor.
    """
    violations: list[str] = []
    digests: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        record = line.split("#", 1)[0].strip()
        if not record:
            continue
        match = DIGEST_ENTRY.fullmatch(record)
        if match is None:
            violations.append(
                f"ferrum-edge-checksums.txt:{number}: entry must be exactly "
                f"'<64 lowercase hex sha256>  {VALIDATOR_ASSET}' plus an optional '# comment'"
            )
            continue
        digests.append(match.group(1))
    if not digests:
        violations.append(
            "ferrum-edge-checksums.txt must approve at least one validator digest"
        )
    if len(set(digests)) != len(digests):
        violations.append(
            "ferrum-edge-checksums.txt must not repeat an approved validator digest"
        )
    return violations


def validator_locator_violations(texts: list[str]) -> list[str]:
    """Reject any attempt to re-pin the validator by a mutable locator."""
    joined = "\n".join(texts)
    violations: list[str] = []
    if "FERRUM_EDGE_SHA256" in joined:
        violations.append(
            "workflows must not replace the checked-in validator digest with a mutable variable"
        )
    if "FERRUM_EDGE_VERSION" in joined:
        violations.append(
            "workflows must not select the validator by release identity; the reviewed digest allowlist is the pin"
        )
    return violations


# The runner executes inside the candidate checkout. Without `-I`, `python3 -`
# puts that directory first on `sys.path`, so a candidate root module named
# after anything the runner or the checker imports (`pathlib.py`,
# `importlib/`, `argparse.py`) runs before the trusted policy and can exit 0.
# Isolated mode drops the working directory and the user site directory and
# ignores every `PYTHON*` environment variable.
TRUSTED_POLICY_RUNNER = 'python3 -I - "$CHECKER" "$GITHUB_WORKSPACE"'
TRUSTED_POLICY_RUNNER_ARGUMENTS = '"$CHECKER" "$GITHUB_WORKSPACE"'
# `-I` already ignores these, but naming one in the policy workflow is still
# an attempt to move the interpreter's import path or start-up code onto
# candidate files, and the reviewed workflow has no use for any of them.
TRUSTED_POLICY_FORBIDDEN_ENV = re.compile(r"\bPYTHON(?:PATH|STARTUP|HOME)\b")


def trusted_supply_chain_policy_violations(text: str) -> list[str]:
    """`security.yml` must run `main`'s checker, isolated, against the candidate.

    This is a substring contract over the candidate's own copy of
    `security.yml`, enforced by the run that copy defines. It catches an honest
    regression and a shadowed import; it cannot stop a pull request that
    rewrites the job itself. `supply-chain-policy.yml` is the workflow whose
    definition the pull request does not supply (see
    `supply_chain_policy_workflow_violations`). This job stays, unchanged,
    until the ruleset requires that workflow's check instead (see
    docs/github-launch-controls.md).
    """
    required = (
        "if: github.event_name == 'pull_request'",
        "ref: ${{ github.event.repository.default_branch }}",
        "path: trusted-supply-chain",
        "CANDIDATE_CHECKER=.github/scripts/check_supply_chain.py",
        "Candidate must retain the regular-file supply-chain checker.",
        "CHECKER=trusted-supply-chain/.github/scripts/check_supply_chain.py",
        TRUSTED_POLICY_RUNNER,
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
    # Exactly one invocation, and it is the isolated one: a second, plain
    # `python3 -` run of the same checker would reopen the import path.
    if text.count(TRUSTED_POLICY_RUNNER_ARGUMENTS) != 1:
        violations.append(
            "security.yml: the trusted policy checker must be invoked exactly once, "
            f"as {TRUSTED_POLICY_RUNNER!r}"
        )
    forbidden = sorted(set(TRUSTED_POLICY_FORBIDDEN_ENV.findall(text)))
    if forbidden:
        violations.append(
            "security.yml: the policy workflow must not set "
            f"{', '.join(forbidden)}; the trusted checker's interpreter takes no "
            "import path or start-up code from the environment"
        )
    # The one-time pinned bootstrap covered the window where `main` did not yet
    # carry this checker. Now that it does, any fallback can only substitute an
    # older policy for the protected one — which is how a policy change that
    # the current tree depends on gets silently un-enforced.
    if "bootstrap-supply-chain" in text:
        violations.append(
            "security.yml: the trusted policy checker must come only from the protected default branch"
        )
    if "path: trusted-supply-chain" in text and (
        "ref: ${{ github.event.pull_request.base.sha }}" in text
    ):
        violations.append(
            "security.yml: an unprotected PR base SHA must not supply the policy checker"
        )
    return violations


# GHSA-x5m2-4555-q4cr. The supply-chain verdict comes from a
# `pull_request_target` workflow, which GitHub always loads from the protected
# default branch: the pull request under review cannot edit the job that
# judges it. It can propose a new shape for LATER pull requests, and that
# proposal is held to the shape below by the protected checker before merge.
SUPPLY_CHAIN_POLICY_WORKFLOW = "supply-chain-policy.yml"
SUPPLY_CHAIN_POLICY_PATH = f".github/workflows/{SUPPLY_CHAIN_POLICY_WORKFLOW}"
SUPPLY_CHAIN_POLICY_JOB = "trusted-supply-chain-policy"
# The checker runs from the protected checkout, isolated, with the candidate
# as `--root`. The working directory is the workspace, never the candidate.
SUPPLY_CHAIN_POLICY_INVOCATION = (
    "python3 -I base/.github/scripts/check_supply_chain.py --root candidate"
)
PINNED_ACTION_COMMIT = "<40-hex commit>"
# Every non-comment line of the workflow, in order, with trailing comments
# dropped. Exact rather than substring: an added key — `env:` (bash reads
# `BASH_ENV` before the first command), `defaults:` (a working directory
# inside the candidate), `if:` (a skipped required job reports success), a
# second trigger, a write permission, `secrets`, an environment, another step —
# is a different line list. The action commit is the only free part, so
# Dependabot can still bump it; the repository-wide rule requires 40 hex.
# Deliberate trade-off: any 40-hex commit is accepted here, including one
# GitHub resolves through a fork of `actions/checkout`, so a commit change to
# this file needs the same exact-head review as any other workflow change.
SUPPLY_CHAIN_POLICY_SHAPE = (
    "name: GitForgeOps Supply-Chain Policy",
    "on:",
    "  pull_request_target:",
    "    types: [opened, synchronize, reopened, edited]",
    "    branches: [main]",
    "permissions:",
    "  contents: read",
    "concurrency:",
    "  group: trusted-supply-chain-policy-${{ github.event.pull_request.number }}",
    "  cancel-in-progress: true",
    "jobs:",
    f"  {SUPPLY_CHAIN_POLICY_JOB}:",
    "    runs-on: ubuntu-24.04",
    "    timeout-minutes: 10",
    "    steps:",
    "      - name: Check out protected supply-chain policy",
    f"        uses: actions/checkout@{PINNED_ACTION_COMMIT}",
    "        with:",
    "          ref: ${{ github.event.repository.default_branch }}",
    "          path: base",
    "          persist-credentials: false",
    "      - name: Check out candidate as policy data",
    f"        uses: actions/checkout@{PINNED_ACTION_COMMIT}",
    "        with:",
    "          repository: ${{ github.event.pull_request.head.repo.full_name }}",
    "          ref: ${{ github.event.pull_request.head.sha }}",
    "          path: candidate",
    "          persist-credentials: false",
    "      - name: Judge candidate with protected supply-chain policy",
    f"        run: {SUPPLY_CHAIN_POLICY_INVOCATION}",
)
_PINNED_USES = re.compile(r"^(\s*(?:-\s+)?uses:\s*[^@\s]+)@[0-9a-f]{40}$")
# YAML starts a comment at a `#` preceded by whitespace. A `#` glued to a
# value is part of it, so it is kept and the line no longer matches. A
# lookbehind rather than `\s+#`: a long run of blanks with no `#` must not
# backtrack quadratically on candidate input.
_TRAILING_COMMENT = re.compile(r"(?<=[ \t])#.*$")


def policy_workflow_shape(text: str) -> list[str]:
    """The non-comment lines of a workflow, with action commits normalized."""
    shape: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = _TRAILING_COMMENT.sub("", line).rstrip()
        shape.append(_PINNED_USES.sub(rf"\1@{PINNED_ACTION_COMMIT}", line))
    return shape


def supply_chain_policy_shape_violations(text: str) -> list[str]:
    """The trusted policy workflow must keep exactly its reviewed shape."""
    shape = policy_workflow_shape(text)
    expected = list(SUPPLY_CHAIN_POLICY_SHAPE)
    if shape == expected:
        return []
    index = next(
        (
            position
            for position, (found, wanted) in enumerate(zip(shape, expected))
            if found != wanted
        ),
        min(len(shape), len(expected)),
    )
    wanted = expected[index].strip() if index < len(expected) else "<end of file>"
    found = shape[index].strip() if index < len(shape) else "<end of file>"
    return [
        f"{SUPPLY_CHAIN_POLICY_WORKFLOW}: the trusted policy workflow must keep its "
        "pinned shape (pull_request_target only, contents: read, no secrets or "
        "environment, the candidate checked out as data, and exactly "
        f"{SUPPLY_CHAIN_POLICY_INVOCATION!r}); non-comment line {index + 1} "
        f"should be {wanted!r}, found {found!r}"
    ]


def supply_chain_policy_workflow_violations(root: Path) -> list[str]:
    """The `pull_request_target` policy workflow must exist and keep its shape."""
    path = root / SUPPLY_CHAIN_POLICY_PATH
    if path.is_symlink() or not path.is_file():
        return [
            f"{SUPPLY_CHAIN_POLICY_WORKFLOW}: the trusted supply-chain policy "
            "workflow must remain a regular file"
        ]
    return supply_chain_policy_shape_violations(path.read_text(encoding="utf-8"))


def candidate_tree_violations(root: Path) -> list[str]:
    """Every path in the judged tree must be a plain file, a directory, or a
    symlink that stays inside the tree.

    The policy job lays the protected checkout out beside the candidate
    (`base/` next to `candidate/`), and every other workflow runs the same
    tree at the workspace root. A link that is absolute or climbs above the
    tree root therefore reads one file here and a different one everywhere
    else: `.github/scripts` pointing at the workspace's `base/.github/scripts`
    shows this check the protected scripts while later runs execute the pull
    request's own copy. A relative target is followed component by component
    from the link's directory: it may not pass through another link (the
    kernel would take `..` of that link's target, not of its name), and it may
    not climb above the tree root, even to come back in, so `../candidate/x`
    cannot re-enter this layout through the directory name. The resolved
    target is checked too, for chains of links. Every path
    component is visited without following a link, and nothing is read until
    the walk passes. Devices, FIFOs and sockets are refused, since reading
    one can hang or exhaust the job. `.git` directories are the checkout's own
    metadata and are skipped.

    `root` is taken as given, before any resolution, so a root that is itself
    a symlink is refused rather than silently followed.
    """
    if root.is_symlink() or not root.is_dir():
        return [f"{root}: the tree under review must be a real directory"]
    real_root = Path(os.path.realpath(root))
    violations: list[str] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(directory)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not (name == ".git" and not (here / name).is_symlink())
        )
        for name in sorted(dirnames + filenames):
            path = here / name
            relative = path.relative_to(root).as_posix()
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                through = None if os.path.isabs(target) else _link_traversal(root, path, target)
                resolved = Path(os.path.realpath(path))
                if through is not None:
                    violations.append(
                        f"{relative}: symlink target passes through another "
                        f"symlink ({through}); only a direct path inside the tree "
                        "resolves the same everywhere"
                    )
                elif (
                    os.path.isabs(target)
                    or _link_climbs(root, path, target)
                    or not (resolved == real_root or resolved.is_relative_to(real_root))
                ):
                    violations.append(
                        f"{relative}: symlink leaves the tree under review "
                        f"({target!r}); it would resolve differently in the "
                        "policy job and in the workflows that run this tree"
                    )
                elif not os.path.exists(path):
                    violations.append(
                        f"{relative}: symlink does not resolve ({target!r})"
                    )
            elif not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                violations.append(
                    f"{relative}: only regular files, directories and in-tree "
                    "symlinks may be reviewed; this is a special file"
                )
    return violations


def _link_climbs(root: Path, path: Path, target: str) -> bool:
    """Whether a relative link target climbs above the tree root, even to return."""
    parts = list(path.parent.relative_to(root).parts)
    for component in target.split("/"):
        if component == "..":
            if not parts:
                return True
            parts.pop()
        elif component not in ("", "."):
            parts.append(component)
    return False


def _link_traversal(root: Path, path: Path, target: str) -> str | None:
    """The first intermediate component of a link target that is itself a link.

    Each prefix of the target, followed from the link's directory, is
    `lstat`-ed; only the final component may be a link (a chain, which the
    walk judges on its own). With no link in between, the text names exactly
    the path the kernel resolves, in every checkout layout.
    """
    parts = list(path.parent.relative_to(root).parts)
    components = [part for part in target.split("/") if part not in ("", ".")]
    for component in components[:-1]:
        if component == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(component)
        prefix = root.joinpath(*parts)
        try:
            if stat.S_ISLNK(os.lstat(prefix).st_mode):
                return "/".join(parts)
        except OSError:
            return None
    return None


# ---------------------------------------------------------------------------
# Strict workflow reader
# ---------------------------------------------------------------------------
# GHSA-x5m2-4555-q4cr. Rules that pattern-match YAML text stay evadable: YAML
# spells one key or value many ways (an indented root, explicit `? key`,
# anchors, aliases, tags, merge keys, flow mappings). So every workflow under
# `.github/workflows/` must be written in a small, unambiguous subset of YAML
# that this stdlib-only reader turns into dicts, lists and strings, and the
# check-name, permission and action-pin rules read that structure. Anything
# outside the subset is a violation reported before any rule runs: a spelling
# this reader does not know cannot carry a meaning past it. A local action a
# workflow runs is held to the same subset (see Local actions).
#
# The subset:
# - top-level keys at column 0, indentation by spaces only, block mappings and
#   block sequences (a sequence nested under a key is indented below it);
# - keys are plain `[A-Za-z0-9_-]+` and unique within their mapping;
# - scalars are plain, single-quoted or double-quoted, each on one line;
# - a block scalar (`|` or `>`, optional `-`/`+`) only as the value of a key in
#   `BLOCK_SCALAR_KEYS`, and a folded one (`>`) only under `FOLDED_SCALAR_KEYS`;
# - a one-line flow sequence of scalars only as the value of a key in
#   `FLOW_SEQUENCE_KEYS` (`branches: [main]`); never a flow mapping;
# - nowhere: anchors, aliases, tags, explicit keys, merge keys, directives,
#   document markers other than one leading `---`, tabs outside block
#   scalars, a byte-order mark, control characters or Unicode line breaks.


class WorkflowSyntaxError(ValueError):
    """A workflow uses YAML outside the subset the policy can read."""


BLOCK_SCALAR_KEYS = frozenset(
    {"run", "script", "body", "description", "if", "path", "restore-keys", "images", "tags"}
)
# A folded scalar (`>`, `>-`, `>+`) only as the value of these keys. YAML keeps
# a line break around a blank or more-indented line of a folded scalar, and
# this reader joins every line with one space, so for `run:` the policy would
# read one shell line where bash runs several: `echo ok #`, a blank line, then
# an env-file write is a comment here and a command on the runner. An `if:`
# expression reads the same either way and runs no shell.
FOLDED_SCALAR_KEYS = frozenset({"if"})
FLOW_SEQUENCE_KEYS = frozenset(
    {
        "branches",
        "branches-ignore",
        "tags",
        "tags-ignore",
        "paths",
        "paths-ignore",
        "types",
        "needs",
        "workflows",
    }
)
_WORKFLOW_KEY = re.compile(r"([A-Za-z0-9_-]+):(?: +(.*))?")
_FORBIDDEN_WORKFLOW_CHARACTER = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ﻿]"
)
_BLOCK_SCALAR_HEADERS = frozenset({"|", "|-", "|+", ">", ">-", ">+"})
# Characters that would begin something other than a plain scalar.
_PLAIN_START = frozenset("&*!|>{}[],#'\"%@`")
_DOUBLE_QUOTED_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": " ",
    "P": " ",
}
_HEX_ESCAPE_WIDTHS = {"x": 2, "u": 4, "U": 8}
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _cut_comment(text: str) -> str:
    """Drop a comment: YAML starts one at a `#` that follows a space."""
    position = text.find(" #")
    return (text if position < 0 else text[:position]).rstrip(" ")


class _WorkflowReader:
    def __init__(self, text: str) -> None:
        forbidden = _FORBIDDEN_WORKFLOW_CHARACTER.search(text)
        if forbidden is not None:
            line = text.count("\n", 0, forbidden.start()) + 1
            raise WorkflowSyntaxError(
                f"line {line}: character U+{ord(forbidden.group()):04X} is not "
                "allowed (byte-order mark, control character or line separator)"
            )
        self.lines = text.split("\n")
        self.index = 0

    def fail(self, message: str) -> None:
        raise WorkflowSyntaxError(f"line {self.index + 1}: {message}")

    def next_indent(self) -> int | None:
        """Skip blank and comment lines; the next line's indentation."""
        while self.index < len(self.lines):
            line = self.lines[self.index]
            content = line.lstrip(" ")
            if not content or content.startswith("#"):
                self.index += 1
                continue
            if "\t" in line:
                self.fail("tabs are only allowed inside block scalars")
            return len(line) - len(content)
        return None

    def document(self) -> dict:
        indent = self.next_indent()
        if indent == 0 and self.lines[self.index].rstrip(" ") == "---":
            self.index += 1
            indent = self.next_indent()
        if indent is None:
            return {}
        if indent != 0:
            self.fail("the top-level mapping must start at column 0")
        root = self.mapping(0)
        if self.next_indent() is not None:
            self.fail("unexpected content after the top-level mapping")
        return root

    def block_node(self, indent: int):
        content = self.lines[self.index][indent:].rstrip(" ")
        if content == "-" or content.startswith("- "):
            return self.sequence(indent)
        return self.mapping(indent)

    def mapping(self, indent: int) -> dict:
        result: dict = {}
        while True:
            current = self.next_indent()
            if current is None or current < indent:
                return result
            if current > indent:
                self.fail("unexpected indentation")
            content = self.lines[self.index][indent:].rstrip(" ")
            match = _WORKFLOW_KEY.fullmatch(content)
            if match is None:
                self.fail(
                    "expected a plain `key:`; quoted, explicit (`?`), anchored, "
                    "tagged, aliased and merge keys are not supported"
                )
            key = match.group(1)
            if key in result:
                self.fail(f"duplicate key {key!r}")
            result[key] = self.value(key, match.group(2) or "", indent)

    def value(self, key: str, rest: str, indent: int):
        """The value of the key on the current line; leaves the reader after it."""
        if not rest or rest.startswith("#"):
            self.index += 1
            nested = self.next_indent()
            if nested is None or nested <= indent:
                return None
            return self.block_node(nested)
        if rest[0] in "|>":
            if key not in BLOCK_SCALAR_KEYS:
                self.fail(f"a block scalar is not accepted as the value of {key!r}")
            if _cut_comment(rest) not in _BLOCK_SCALAR_HEADERS:
                self.fail("a block scalar header must be one of | |- |+ > >- >+")
            if rest[0] == ">" and key not in FOLDED_SCALAR_KEYS:
                self.fail(
                    f"a folded block scalar (`>`) is not accepted as the value of {key!r}; "
                    "use a literal block scalar (`|`)"
                )
            self.index += 1
            return self.block_scalar(indent, folded=rest[0] == ">")
        if rest[0] == "[":
            if key not in FLOW_SEQUENCE_KEYS:
                self.fail(f"a flow sequence is not accepted as the value of {key!r}")
            result = self.flow_sequence(rest)
        else:
            result = self.scalar(rest)
        self.index += 1
        nested = self.next_indent()
        if nested is not None and nested > indent:
            self.fail("a value may not continue on the next line")
        return result

    def sequence(self, indent: int) -> list:
        items: list = []
        while True:
            current = self.next_indent()
            if current is None or current < indent:
                return items
            if current > indent:
                self.fail("unexpected indentation")
            line = self.lines[self.index].rstrip(" ")
            content = line[indent:]
            if content != "-" and not content.startswith("- "):
                return items
            rest = content[1:].lstrip(" ")
            if not rest or rest.startswith("#"):
                self.index += 1
                nested = self.next_indent()
                items.append(
                    self.block_node(nested) if nested is not None and nested > indent else None
                )
                continue
            if rest == "-" or rest.startswith("- "):
                self.fail("nested compact sequences are not supported")
            if _WORKFLOW_KEY.fullmatch(rest):
                # A compact mapping: read it as a mapping at its first key's column.
                column = len(line) - len(rest)
                self.lines[self.index] = " " * column + rest
                items.append(self.mapping(column))
                continue
            if rest[0] in "|>[":
                self.fail("a sequence item must be a scalar or a mapping")
            items.append(self.scalar(rest))
            self.index += 1
            nested = self.next_indent()
            if nested is not None and nested > indent:
                self.fail("a value may not continue on the next line")

    def scalar(self, text: str) -> str:
        if text[0] in "'\"":
            value, end = self.quoted(text)
            remainder = text[end:]
            if remainder and not (
                remainder[0] == " " and remainder.lstrip(" ")[:1] in ("", "#")
            ):
                self.fail("unexpected text after a quoted scalar")
            return value
        value = _cut_comment(text)
        self.check_plain(value)
        return value

    def check_plain(self, value: str) -> None:
        if (
            not value
            or value[0] in _PLAIN_START
            or (value[0] in "-?:" and value[1:2] in ("", " "))
        ):
            self.fail(
                f"{value[:20]!r} does not start a plain scalar; anchors, aliases, "
                "tags and flow mappings are not supported"
            )
        if ": " in value or value.endswith(":"):
            self.fail("a plain scalar may not contain ': '; quote it")

    def quoted(self, text: str) -> tuple[str, int]:
        quote = text[0]
        out: list[str] = []
        position = 1
        while position < len(text):
            character = text[position]
            if quote == "'":
                if character == "'":
                    if text[position + 1:position + 2] == "'":
                        out.append("'")
                        position += 2
                        continue
                    return "".join(out), position + 1
                out.append(character)
                position += 1
                continue
            if character == '"':
                return "".join(out), position + 1
            if character != "\\":
                out.append(character)
                position += 1
                continue
            code = text[position + 1:position + 2]
            if code in _HEX_ESCAPE_WIDTHS:
                digits = text[position + 2:position + 2 + _HEX_ESCAPE_WIDTHS[code]]
                if len(digits) != _HEX_ESCAPE_WIDTHS[code] or not set(digits) <= _HEX_DIGITS:
                    self.fail("malformed escape in a double-quoted scalar")
                point = int(digits, 16)
                if point > 0x10FFFF or 0xD800 <= point <= 0xDFFF:
                    self.fail("escape names no Unicode scalar value")
                out.append(chr(point))
                position += 2 + len(digits)
                continue
            if code not in _DOUBLE_QUOTED_ESCAPES:
                self.fail("unsupported escape in a double-quoted scalar")
            out.append(_DOUBLE_QUOTED_ESCAPES[code])
            position += 2
        self.fail("a quoted scalar must close on its own line")
        raise AssertionError("unreachable")

    def flow_sequence(self, text: str) -> list[str]:
        """A one-line `[a, 'b', "c"]` of scalars; nothing nested."""
        items: list[str] = []
        position = self.skip_spaces(text, 1)
        if text[position:position + 1] == "]":
            position += 1
        else:
            while True:
                position = self.skip_spaces(text, position)
                if position < len(text) and text[position] in "'\"":
                    value, end = self.quoted(text[position:])
                    position += end
                else:
                    end = position
                    while end < len(text) and text[end] not in ",]":
                        end += 1
                    value = text[position:end].rstrip(" ")
                    if any(mark in value for mark in "[]{}") or " #" in value:
                        self.fail("a flow sequence item must be a plain or quoted scalar")
                    self.check_plain(value)
                    position = end
                items.append(value)
                position = self.skip_spaces(text, position)
                if position >= len(text):
                    self.fail("a flow sequence must close on its own line")
                if text[position] == ",":
                    position += 1
                    continue
                if text[position] != "]":
                    self.fail("expected ',' or ']' in a flow sequence")
                position += 1
                break
        remainder = text[position:]
        if remainder and not (
            remainder[0] == " " and remainder.lstrip(" ")[:1] in ("", "#")
        ):
            self.fail("unexpected text after a flow sequence")
        return items

    @staticmethod
    def skip_spaces(text: str, position: int) -> int:
        while text[position:position + 1] == " ":
            position += 1
        return position

    def block_scalar(self, indent: int, folded: bool) -> str:
        lines: list[str] = []
        content_indent: int | None = None
        while self.index < len(self.lines):
            line = self.lines[self.index]
            # YAML counts only spaces and tabs as blank; other Unicode
            # spaces are content.
            if not line.strip(" \t"):
                lines.append("")
                self.index += 1
                continue
            current = len(line) - len(line.lstrip(" "))
            if content_indent is None:
                if current <= indent:
                    break
                content_indent = current
            if current < content_indent:
                break
            lines.append(line[content_indent:])
            self.index += 1
        while lines and not lines[-1]:
            lines.pop()
        return (" " if folded else "\n").join(lines)


def parse_workflow(text: str) -> dict:
    """Read a workflow written in the policy's YAML subset, or raise."""
    return _WorkflowReader(text).document()


def _values_for_key(node, name: str):
    """Every value stored under `name` (any case), anywhere in a document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.casefold() == name:
                yield value
            yield from _values_for_key(value, name)
    elif isinstance(node, list):
        for item in node:
            yield from _values_for_key(item, name)


def workflow_action_references(document: dict) -> list[str]:
    """Every `uses:` value in a parsed workflow (steps and reusable jobs)."""
    return [
        value if isinstance(value, str) else repr(value)
        for value in _values_for_key(document, "uses")
    ]


# -- Workflow text fences: env-file channels and guarded bindings -------------
#
# These rules read workflow text: the parsed tree, with YAML comments dropped
# and quoted scalars decoded as GitHub decodes them. They pin the guarded steps
# exactly and ban the env-file channels everywhere else. They do not interpret
# what a command computes. A program a step invokes (the binary, a helper
# script, or Bash itself evaluating computed text such as `base64 -d | bash` or
# `eval "$text"`) can still write $GITHUB_ENV or rebind a variable, and no text
# rule can prove otherwise. Review of every workflow change, which the
# protected-definition check makes unavoidable, is the control for that.
# Within that scope the rules are exact pins and bans, with no shell lexer or
# expression renderer (#476).

# Env-file channels and shell startup files, in any scalar or key. Each binds a
# variable that a later step inherits without naming it there. The runner
# keeps every file-command file of a step in `_runner_file_commands`, named by
# command prefix plus one shared suffix, so `set_env_` and `add_path_` (and
# `save_state_`) spell GITHUB_ENV and GITHUB_PATH by another name. GITHUB_STATE
# names the `save_state_` file, and no step here needs it.
_FILE_CHANNEL = re.compile(
    r"github_env|github_path|github_state|bash_env"
    r"|_runner_file_commands|set_env_|add_path_|save_state_"
    r"|\bgithub\s*(?:\.\s*(?:env|path|output)\b|\[\s*(?:env|path|output)\s*\])"
)
# A redirect or `tee` into any other GitHub file channel. Steps may write only
# their outputs and the job summary.
_GITHUB_FILE_WRITE = re.compile(
    r"(?:>>?|>\||\btee\b[^\n;&|]*)\s*\$\{?github_(?!output\b|step_summary\b)[a-z0-9_]+"
)
# The output and summary files may be named only as a whole, unmodified
# expansion: an append (`>>`) or `tee -a` target, or the summary as a
# `--summary` argument. Any other use, such as `${GITHUB_OUTPUT/set_output_/x}`,
# `${GITHUB_OUTPUT%/*}` or `$(dirname "$GITHUB_OUTPUT")`, can derive the path of
# another file-command file from it.
_OUTPUT_FILE = re.compile(r"github_output|github_step_summary")
_PLAIN_OUTPUT_TARGET = re.compile(
    r"(?:>>[ \t]*|\btee[ \t]+-a[ \t]+)\$(?:\{(?:github_output|github_step_summary)\}"
    r"|(?:github_output|github_step_summary)\b)(?=[\s;&|)]|\Z)"
    r"|--summary[ \t]+\$(?:\{github_step_summary\}|github_step_summary\b)(?=[\s;&|)]|\Z)"
)
# Indirect expansion computes the name it reads; no text rule sees that name.
_INDIRECT_EXPANSION = re.compile(r"\$\{!")
# Keys of an `env:` mapping (any case) that change what a shell or the loader
# runs before a step's own script, or name a file destination GitHub would
# otherwise supply. `sh` reads ENV and Bash BASH_ENV; Bash imports a
# `BASH_FUNC_<name>%%` value as a function that shadows the command, and runs
# PS4 under SHELLOPTS/BASHOPTS xtrace; the dynamic loader's `LD_*` variables
# (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, ...) load other code into every
# dynamically linked program, so the whole prefix is refused.
_ENV_DESTINATION_KEYS = frozenset({
    "env", "bash_env", "shellopts", "bashopts", "ps4",
    "github_output", "github_step_summary", "github_state",
})
_ENV_DESTINATION_PREFIXES = ("bash_func_", "ld_")
_NAMED_GITHUB = re.compile(r"\bgithub\s*\.\s*[A-Za-z_][A-Za-z0-9_-]*", re.IGNORECASE)
_INDEXED_GITHUB = re.compile(
    r"\bgithub(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_-]*)*\s*\[", re.IGNORECASE
)
# Stands in for a `run:` interpolation when judging what it adjoins.
_RUN_SENTINEL = "\ue000"
_BUNDLE_SHARD_NAME = re.compile(BUNDLE_SECRET_PREFIX + r"(?:_[1-9][0-9]*)?")
# `gitforgeops):` is the commit subject `chore(gitforgeops):`; any other `)`
# after the name, as in `$(command -v gitforgeops) apply`, still counts.
_GITFORGEOPS_WORD = re.compile(r"(?<![\w.-])gitforgeops(?![\w/\[-])(?!\):)")


# Bash ANSI-C quoting spells a character by its code: `$'\x67'itforgeops` is
# `gitforgeops` and `$'GITHUB_\x45NV'` is `GITHUB_ENV`. Reading that needs a
# quote-state lexer, which #476 removed: outside quotes Bash reads
# `GITH\UB_ENV` as `GITHUB_ENV`, so decoding escapes outside a real `$'...'`
# span hides names that plain stripping finds. ANSI-C quoting is therefore not
# supported in workflows or the local actions they run: a scalar holding `$'`
# is refused, and `_scan_text` only strips quotes and backslashes.
_ANSI_C_QUOTING_REFUSAL = (
    "ANSI-C quoting (`$'...'`) is not supported in workflows or the local actions "
    "they run; it spells names by character code that no text rule decodes"
)


def _uses_ansi_c_quoting(text: str) -> bool:
    """Whether Bash can read `$'` in `text` once line continuations are joined."""
    return "$'" in text.replace("\\\n", "")


def _scan_text(text: str) -> str:
    """Casefolded text with quotes, escapes and line continuations removed.

    Bash reads `GITHUB_""ENV`, `GITHUB_E\\NV`, `$'GITHUB_ENV'` and a name split
    by a backslash-newline as the same word, so every text rule judges this
    form. Escapes are stripped, never decoded; a scalar that uses ANSI-C
    quoting is refused instead (`_uses_ansi_c_quoting`). A name computed by
    expansion (`GITHUB_E${x}NV`) is program behavior.
    """
    text = text.replace("\\\n", "").replace("$'", "'").replace('$"', '"')
    return text.translate(str.maketrans("", "", "'\"\\")).casefold()


def pinned_run_matches(script: str, shape: tuple[str, ...]) -> bool:
    """Whether a `run:` script is exactly a pinned shape, apart from comment lines.

    Lines are compared without surrounding spaces and tabs. Between entries,
    blank lines and lines starting with `#` are dropped. That is sound only
    because every entry is a complete command: no entry opens a quote,
    here-document or continuation that a later entry closes, so a dropped line
    always sits where Bash reads a new command, and a `#` line there is a
    comment. An entry spanning several lines (one holding a newline) matches
    its lines consecutively, with nothing dropped inside it. A comment holding
    an expression is refused: GitHub renders it before Bash sees the `#`.
    """
    lines = [line.strip(" \t") for line in script.split("\n")]
    index = 0

    def skip_comments() -> bool:
        nonlocal index
        while index < len(lines) and (not lines[index] or lines[index].startswith("#")):
            if "${{" in lines[index]:
                return False
            index += 1
        return True

    for entry in shape:
        expected = entry.split("\n")
        if not skip_comments() or lines[index:index + len(expected)] != expected:
            return False
        index += len(expected)
    return skip_comments() and index == len(lines)


def _script_lines(script: str) -> list[str]:
    """A script's lines without surrounding spaces and tabs, blank and `#` lines dropped."""
    return [
        line for line in (line.strip(" \t") for line in script.split("\n"))
        if line and not line.startswith("#")
    ]


def _env_scopes(node: dict) -> list:
    return [value for key, value in node.items() if key.casefold() == "env"]


def _credential_handoff_refusal(workflow: str, document: dict, job: dict, step: dict) -> str | None:
    """Why a bundle-loader step is not the pinned hand-off, or None when it is."""
    shape = CREDENTIAL_HANDOFF_SHAPES.get(workflow)
    if shape is None:
        return "this workflow has no credential hand-off"
    if any(key in step for key in ("uses", "shell", "working-directory")):
        return "the hand-off runs the default shell in the workspace"
    if shape is APPLY_CREDENTIAL_HANDOFF_RUN and step.get("id") != APPLY_CREDENTIAL_HANDOFF_ID:
        return (
            f"the apply hand-off keeps id {APPLY_CREDENTIAL_HANDOFF_ID}, "
            "which Apply and Verify traffic read"
        )
    if any(key.casefold() == "defaults" for node in (document, job) for key in node):
        return "inherited run defaults may not change the hand-off's shell"
    environment = step.get("env")
    if not isinstance(environment, dict) or not all(
        isinstance(name, str) and _BUNDLE_SHARD_NAME.fullmatch(name)
        and value == f"${{{{ secrets.{name} }}}}"
        for name, value in environment.items()
    ):
        return "the hand-off env binds only credential-bundle shards, each to its own secret"
    drivers = {name.casefold() for name in CREDENTIAL_HANDOFF_DRIVERS}
    for scope in _env_scopes(document) + _env_scopes(job):
        if not isinstance(scope, dict) or drivers.intersection(key.casefold() for key in scope):
            return "workflow and job env may not bind " + ", ".join(CREDENTIAL_HANDOFF_DRIVERS)
    if not isinstance(step.get("run"), str) or not pinned_run_matches(step["run"], shape):
        return "the hand-off script must match its pinned shape"
    return None


def workflow_channel_violations(workflow: str, document: dict) -> list[str]:
    """No workflow may write or rebind an env-file channel, except the pinned hand-off.

    Every key and scalar of every workflow is judged in `_scan_text` form, and
    shell comments count: GITHUB_ENV, GITHUB_PATH, GITHUB_STATE and BASH_ENV
    through quotes, backslashes and line continuations (a name computed by
    expansion is program behavior), the runner's file-command file names, the
    `github.env`/`github.path` contexts, a redirect or `tee` into any
    `$GITHUB_*` file other than GITHUB_OUTPUT and GITHUB_STEP_SUMMARY, any use
    of those two other than as a plain append or `tee -a` target (or the
    summary as a `--summary` argument), indirect expansion, and ANSI-C
    quoting (`$'`), which spells a name by character code. An `env:`
    mapping may not be computed, nor bind a shell startup or loader variable
    (`_ENV_DESTINATION_KEYS`, `BASH_FUNC_*`, `LD_*`) or a GitHub file
    destination.
    Expressions may reach the `github` context only through named dot
    properties, since an index or a whole-context conversion can compute a
    channel name, and a `run:` interpolation may not adjoin a name character
    once quotes are removed, where its rendered value would complete a name no
    rule saw spelled. The one exception is the `run:` of a credential hand-off
    that matches its pin.
    """
    violations: list[str] = []
    handoffs: dict[int, str | None] = {}
    jobs = document.get("jobs")
    for job in jobs.values() if isinstance(jobs, dict) else ():
        steps = job.get("steps") if isinstance(job, dict) else None
        for step in steps if isinstance(steps, list) else ():
            if isinstance(step, dict) and step.get("name") == BUNDLE_LOADER_STEP:
                handoffs[id(step)] = _credential_handoff_refusal(workflow, document, job, step)

    def check(value: str, key: str, label: str, handoff: str | None) -> None:
        scan = _scan_text(value)
        if (
            _FILE_CHANNEL.search(scan)
            or _GITHUB_FILE_WRITE.search(scan)
            or _OUTPUT_FILE.search(_PLAIN_OUTPUT_TARGET.sub("", scan))
        ):
            violations.append(
                f"{label}: GITHUB_ENV, GITHUB_PATH, GITHUB_STATE, BASH_ENV, runner "
                "file-command names, writes to other GitHub file channels, and "
                "GITHUB_OUTPUT or GITHUB_STEP_SUMMARY other than as a plain `>>` or "
                "`tee -a` target are forbidden outside the pinned credential hand-off"
                + (f" ({handoff})" if handoff else "")
            )
        if _INDIRECT_EXPANSION.search(scan):
            violations.append(
                f"{label}: indirect expansion (`${{!name}}`) is forbidden; it reads a "
                "name no rule saw spelled"
            )
        if _uses_ansi_c_quoting(value):
            violations.append(f"{label}: {_ANSI_C_QUOTING_REFUSAL}")
        if "${{" in WORKFLOW_EXPRESSION.sub("", value):
            violations.append(f"{label}: unrecognized GitHub expression syntax is forbidden")
        expressions = list(WORKFLOW_EXPRESSION.finditer(value))
        bodies = [match.group(1) for match in expressions]
        if key.casefold() == "if" and not bodies:
            bodies = [value]  # `if:` is an expression without delimiters.
        if any(
            re.search(r"\bgithub\b", _NAMED_GITHUB.sub("", body), re.IGNORECASE)
            or _INDEXED_GITHUB.search(body)
            for body in bodies
        ):
            violations.append(
                f"{label}: computed/indexed or whole GitHub context access is forbidden; "
                "use named dot properties"
            )
        # Judge neighbours with quotes and escapes removed, as Bash joins
        # `"${{ a }}""${{ b }}"` into one word; each interpolation is a
        # sentinel, which also counts as a name character beside another.
        spliced = _scan_text(WORKFLOW_EXPRESSION.sub(_RUN_SENTINEL, value))
        if key.casefold() == "run" and re.search(
            f"[a-z0-9_${{}}{_RUN_SENTINEL}]{_RUN_SENTINEL}|{_RUN_SENTINEL}[a-z0-9_{{}}]",
            spliced,
        ):
            violations.append(
                f"{label}: a run interpolation may not adjoin a name character; "
                "GitHub renders it before Bash reads the name"
            )

    def visit(node, path: str, parent: str = "") -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]", parent)
            return
        if isinstance(node, str):
            check(node, parent, f"{workflow}: {path}", None)
            return
        if not isinstance(node, dict):
            return
        refusal = handoffs.get(id(node))
        for key, value in node.items():
            label = f"{workflow}: {path}.{key}"
            if _FILE_CHANNEL.search(_scan_text(key)):
                violations.append(f"{label}: binding a GitHub env-file channel is forbidden")
            if parent.casefold() == "env" and (
                key.casefold() in _ENV_DESTINATION_KEYS
                or key.casefold().startswith(_ENV_DESTINATION_PREFIXES)
            ):
                violations.append(
                    f"{label}: binding a shell startup or loader variable (ENV, BASH_ENV, "
                    "BASH_FUNC_*, SHELLOPTS, BASHOPTS, PS4, LD_*) "
                    "or a GitHub file destination is forbidden"
                )
            if key.casefold() == "env" and not isinstance(value, dict):
                violations.append(f"{label}: dynamic env sources are forbidden")
            if isinstance(value, str):
                if key == "run" and id(node) in handoffs and refusal is None:
                    continue  # The pinned hand-off: its write is the permitted one.
                check(value, key, label, refusal if id(node) in handoffs else None)
            else:
                visit(value, f"{path}.{key}", key)

    visit(document, "workflow")
    return violations


# A container image's own `ENV` (LD_PRELOAD, BASH_ENV, ...) applies to every
# step of its job, as `options:` would, so the image is pinned like an action.
_DIGEST_PINNED_IMAGE = re.compile(r"[^\s@${}]+@sha256:[0-9a-f]{64}")


def container_options_violations(workflow: str, document: dict) -> list[str]:
    """Job and service containers are digest-pinned, take no `options:` and are not computed.

    `options` is a `docker create` command line: `-e`, `--env` and
    `--env-file` bind the startup and loader variables an `env:` mapping may
    not (`LD_PRELOAD`, `SHELLOPTS`, `PS4`, ...) for every step of a container
    job, and no other option is needed by any workflow here. An image's own
    `ENV` has the same reach, so the image is pinned by `@sha256:` digest. A
    computed container or service mapping could carry either unseen.
    """
    violations: list[str] = []
    jobs = document.get("jobs")
    for job_name, job in jobs.items() if isinstance(jobs, dict) else ():
        if not isinstance(job, dict):
            continue
        containers: list[tuple[str, object]] = []
        for key, value in job.items():
            path = f"jobs.{job_name}.{key}"
            if key.casefold() == "container":
                containers.append((path, value))
            elif key.casefold() == "services":
                if isinstance(value, dict):
                    containers.extend(
                        (f"{path}.{name}", service) for name, service in value.items()
                    )
                else:
                    containers.append((path, value))
        for path, container in containers:
            if isinstance(container, dict):
                if any(key.casefold() == "options" for key in container):
                    violations.append(
                        f"{workflow}: {path}.options: container options are forbidden; "
                        "`-e`/`--env`/`--env-file` bind startup and loader variables "
                        "for every step"
                    )
                images = [value for key, value in container.items() if key.casefold() == "image"]
                image = images[0] if len(images) == 1 else None
            elif isinstance(container, str) and "${{" not in container:
                image = container
            else:
                violations.append(
                    f"{workflow}: {path}: a container or service must be a literal "
                    "image or mapping, never computed"
                )
                continue
            if not isinstance(image, str) or _DIGEST_PINNED_IMAGE.fullmatch(image) is None:
                violations.append(
                    f"{workflow}: {path}: a container or service image must be pinned by "
                    "digest (`@sha256:<64 hex>`); its own ENV applies to every step"
                )
    return violations


def run_expression_violations(workflow: str, document: dict) -> list[str]:
    """Environment-bound jobs interpolate into `run:` only the pinned values.

    `run_expression_source_violations` pins where those values come from.
    """
    if workflow not in RUN_EXPRESSIONS:
        return []
    violations: list[str] = []
    jobs = document.get("jobs")
    for job_name, job in jobs.items() if isinstance(jobs, dict) else ():
        allowed = RUN_EXPRESSIONS[workflow].get(job_name, ())
        steps = job.get("steps") if isinstance(job, dict) else None
        for index, step in enumerate(steps if isinstance(steps, list) else ()):
            script = step.get("run") if isinstance(step, dict) else None
            if not isinstance(script, str):
                continue
            for match in WORKFLOW_EXPRESSION.finditer(script):
                if match.group(1).strip() not in allowed:
                    violations.append(
                        f"{workflow}: jobs.{job_name}.steps[{index}].run: interpolation "
                        f"{match.group(1).strip()!r} is not pinned for this job; pass the "
                        "value through step env instead"
                    )
    return violations


def _producer_step(job: dict, step_id: str):
    """The one step of `job` with id `step_id` in any case, or None.

    Ids are compared casefolded, so `id: Metadata` beside `id: metadata` is
    two candidates and neither is taken for the producer.
    """
    steps = job.get("steps")
    found = [
        step for step in (steps if isinstance(steps, list) else [])
        if isinstance(step, dict) and isinstance(step.get("id"), str)
        and step["id"].casefold() == step_id.casefold()
    ]
    return found[0] if len(found) == 1 else None


def _metadata_line_violations(label: str, script: str) -> list[str]:
    """The metadata step writes the SHAs only through its pinned lines."""
    violations: list[str] = []
    if tuple(_script_lines(script)[:len(REVIEW_METADATA_PREAMBLE)]) != REVIEW_METADATA_PREAMBLE:
        violations.append(f"{label}: the event head SHA must be checked as 40 hex digits first")
    lines = [line.strip(" \t") for line in _scan_text(script).split("\n")]
    if re.search(r"event_head_sha", re.sub(
        r"\$(?:event_head_sha\b|\{event_head_sha\})", "", "\n".join(lines)
    )):
        violations.append(f"{label}: EVENT_HEAD_SHA may only be read, never reassigned")
    for name, allowed in REVIEW_METADATA_LINES.items():
        permitted = {_scan_text(line) for line in allowed}
        reads = re.compile(r"\$(?:" + name + r"\b|\{" + name + r"\})")
        named = [
            line for line in lines
            if re.search(r"\b" + name + r"\b", reads.sub("", line))
        ]
        if any(line not in permitted for line in named):
            violations.append(f"{label}: {name} may only be produced by its pinned lines")
    if lines.count(_scan_text(REVIEW_TRUSTED_SHA_ASSIGNMENT)) != 1:
        violations.append(f"{label}: trusted_sha must be assigned once, from git rev-parse")
    return violations


def run_expression_source_violations(workflow: str, document: dict) -> list[str]:
    """Each pinned run value keeps its pinned producer."""
    violations: list[str] = []
    jobs = document.get("jobs")
    jobs = jobs if isinstance(jobs, dict) else {}
    for job_name, outputs in RUN_EXPRESSION_JOB_OUTPUTS.get(workflow, {}).items():
        job = jobs.get(job_name)
        declared = job.get("outputs") if isinstance(job, dict) else None
        declared = declared if isinstance(declared, dict) else {}
        for name, expected in outputs.items():
            spellings = [key for key in declared if key.casefold() == name]
            if spellings != [name] or declared[name] != expected:
                violations.append(
                    f"{workflow}: jobs.{job_name}.outputs.{name} must be exactly {expected}"
                )
    if workflow == ".github/workflows/apply-on-merge.yml":
        for job_name, matrix in RUN_EXPRESSION_MATRICES.items():
            job = jobs.get(job_name)
            strategy = job.get("strategy") if isinstance(job, dict) else None
            if not isinstance(strategy, dict) or strategy.get("matrix") != matrix:
                violations.append(
                    f"{workflow}: jobs.{job_name}.strategy.matrix must be exactly {matrix}"
                )
        producers = (("list-envs", "list", APPLY_ENVIRONMENT_LIST_RUN),)
    elif workflow == ".github/workflows/trusted-pr-review.yml":
        producers = (("prepare", "metadata", None),)
    else:
        producers = ()
    for job_name, step_id, shape in producers:
        job = jobs.get(job_name)
        step = _producer_step(job, step_id) if isinstance(job, dict) else None
        label = f"{workflow}: job {job_name!r}, step {step_id!r}"
        if step is None or not isinstance(step.get("run"), str):
            violations.append(f"{label} must exist exactly once and produce the pinned values")
            continue
        if (
            any(key in step for key in ("uses", "shell", "working-directory"))
            or any(key.casefold() == "defaults" for node in (document, job) for key in node)
        ):
            violations.append(f"{label} runs the default shell in the workspace")
        if shape is not None:
            if not pinned_run_matches(step["run"], shape):
                violations.append(f"{label} must match its pinned script")
            continue
        environment = step.get("env")
        if not isinstance(environment, dict) or (
            environment.get("EVENT_HEAD_SHA") != REVIEW_EVENT_HEAD_SHA
        ):
            violations.append(f"{label} must bind EVENT_HEAD_SHA: {REVIEW_EVENT_HEAD_SHA}")
        violations.extend(_metadata_line_violations(label, step["run"]))
    return violations


def guarded_environment_violations(
    workflow: str, document: dict, required_steps: tuple, protected: tuple[str, ...]
) -> list[str]:
    """Require step-local bindings and refuse every other mention of a protected name.

    Each required step must exist once with a literal `env:` mapping holding
    its exact bindings. A protected name may appear nowhere else: not as a key
    in any other mapping (workflow or job env, another step, `with:`), and not
    in any scalar, in `_scan_text` form, including run scripts and their
    comments, and no scalar may use ANSI-C quoting. Verify traffic may read
    FERRUM_ENV only through its pinned script. Dynamic env maps and env-file
    writes, the other ways to bind a name without spelling it, are
    `workflow_channel_violations`.
    """
    violations: list[str] = []
    allowed: dict[int, dict] = {}
    jobs = document.get("jobs")
    for job_name, step_name, bindings in required_steps:
        job = jobs.get(job_name) if isinstance(jobs, dict) else None
        steps = job.get("steps") if isinstance(job, dict) else None
        found = (
            [step for step in steps if isinstance(step, dict) and step.get("name") == step_name]
            if isinstance(steps, list) else []
        )
        label = f"{workflow}: job {job_name!r}, step {step_name!r}"
        if len(found) != 1:
            violations.append(f"{label} must exist exactly once with protected env bindings")
            continue
        environment = found[0].get("env")
        if not isinstance(environment, dict):
            violations.append(f"{label} must have a literal env mapping")
            continue
        allowed[id(environment)] = bindings
        for variable, expected in bindings.items():
            if environment.get(variable) != expected:
                violations.append(f"{label} must bind exactly {variable}: {expected}")

    protected_names = {name.casefold() for name in protected}
    protected_reference = re.compile(
        r"\b(?:" + "|".join(re.escape(name) for name in sorted(protected_names)) + r")\b"
    )

    def check(value: str, label: str, verify_run: bool = False) -> None:
        if _uses_ansi_c_quoting(value):
            violations.append(f"{label}: {_ANSI_C_QUOTING_REFUSAL}")
        scan = _scan_text(value)
        if verify_run:
            scan = re.sub(r"\bferrum_env\b", "", scan)
        if protected_reference.search(scan):
            violations.append(
                f"{label}: protected variable references/rebinding outside step env are forbidden"
            )

    def visit(node, path: str) -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                if isinstance(item, str):
                    check(item, f"{workflow}: {path}[{index}]")
                else:
                    visit(item, f"{path}[{index}]")
            return
        if not isinstance(node, dict):
            return
        permitted = allowed.get(id(node), {})
        for key, value in node.items():
            label = f"{workflow}: {path}.{key}"
            if key.casefold() in protected_names and key not in permitted:
                violations.append(
                    f"{label}: protected variable may only be bound in its required step env"
                )
            if isinstance(value, str) and key not in permitted:
                check(value, label, verify_run=(
                    workflow == ".github/workflows/apply-on-merge.yml" and key == "run"
                    and node.get("name") == "Verify traffic"
                    and pinned_run_matches(value, PROBE_VERIFY_RUN)
                ))
            elif isinstance(value, (dict, list)):
                visit(value, f"{path}.{key}")

    visit(document, "workflow")
    return violations


def _workflow_condition(value) -> str | None:
    """Compare a pinned expression with optional delimiters and whitespace."""
    if not isinstance(value, str):
        return None
    expression = EXPRESSION.fullmatch(value.strip())
    body = expression.group(1) if expression else value
    return re.sub(
        r"'(?:[^']|'')*'|\s+",
        lambda match: match.group(0) if match.group(0).startswith("'") else "",
        body,
    )


def probe_validation_gate_violations(workflow: str, document: dict) -> list[str]:
    """A successful bound Validate must precede every recognized Apply call."""
    if workflow != ".github/workflows/apply-on-merge.yml":
        return []
    violations: list[str] = []
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return [f"{workflow}: bound Validate/Apply jobs must exist"]
    allowed_mutations: set[int] = set()
    for job_name, (expected_needs, condition) in PROBE_APPLY_JOB_GATES.items():
        job = jobs.get(job_name)
        label = f"{workflow}: job {job_name!r}"
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            violations.append(f"{label}: bound Validate/Apply steps must exist")
            continue
        needs = job.get("needs")
        if isinstance(needs, str):
            needs = [needs]
        if (
            needs != expected_needs
            or _workflow_condition(job.get("if")) != _workflow_condition(condition)
        ):
            violations.append(
                f"{label}: Validate/Apply job flow must retain its blocking dependencies and gate"
            )
        if job.get("continue-on-error", "false") != "false":
            violations.append(
                f"{label}: Validate failure must propagate; job continue-on-error is forbidden"
            )
        # A default shell can swallow the exit code; a default directory can
        # validate a different resource tree. Neither is needed by these jobs.
        if "defaults" in document or "defaults" in job:
            violations.append(
                f"{label}: inherited run defaults may not change Validate/Apply execution"
            )
        steps = job["steps"]
        if job.get("environment") != PROBE_RUNTIME_ENVIRONMENTS[job_name]:
            violations.append(
                f"{label}: GitHub Environment must match the pinned runtime FERRUM_ENV binding"
            )
        verifications = [
            step for step in steps
            if isinstance(step, dict) and step.get("name") == "Verify traffic"
        ]
        if len(verifications) != 1:
            violations.append(f"{label}: exactly one Verify traffic must retain its runtime scope")
        else:
            verify = verifications[0]
            script = verify.get("run")
            if (
                not isinstance(script, str)
                or not pinned_run_matches(script, PROBE_VERIFY_RUN)
                or any(key in verify for key in ("uses", "shell", "working-directory"))
            ):
                violations.append(
                    f"{label}: Verify traffic must retain the pinned command and runtime scope"
                )
        for step_name, variable in APPLIED_BUNDLE_BINDINGS.items():
            bound = [
                step for step in steps
                if isinstance(step, dict) and step.get("name") == step_name
            ]
            environment = bound[0].get("env") if len(bound) == 1 else None
            value = environment.get(variable) if isinstance(environment, dict) else None
            if value != APPLIED_BUNDLE_VALUE:
                violations.append(
                    f"{label}: {step_name!r} must bind exactly {variable}: {APPLIED_BUNDLE_VALUE}"
                )
        # The readers above trust this id; only a step with the loader's name
        # is held to the pinned hand-off, so the id may not move to another.
        loader = _producer_step(job, APPLY_CREDENTIAL_HANDOFF_ID)
        if loader is None or loader.get("name") != BUNDLE_LOADER_STEP:
            violations.append(
                f"{label}: exactly one step may have id {APPLY_CREDENTIAL_HANDOFF_ID}, "
                f"and it must be named {BUNDLE_LOADER_STEP!r}"
            )
        validations = [
            index
            for index, step in enumerate(steps)
            if isinstance(step, dict) and step.get("name") == "Validate"
        ]
        if len(validations) != 1:
            violations.append(f"{label}: exactly one blocking Validate must precede Apply")
            continue
        validation_index = validations[0]
        validation = steps[validation_index]
        if (
            validation.get("run") != "gitforgeops validate"
            or any(key in validation for key in ("if", "uses", "shell", "working-directory"))
            or validation.get("continue-on-error", "false") != "false"
        ):
            violations.append(
                f"{label}: Validate must run gitforgeops validate unconditionally and propagate failure"
            )
        for step_name, step_condition in PROBE_APPLY_STEP_GATES.items():
            mutations = [
                (index, step)
                for index, step in enumerate(steps)
                if isinstance(step, dict) and step.get("name") == step_name
            ]
            if len(mutations) != 1:
                violations.append(f"{label}: {step_name!r} must exist exactly once after Validate")
                continue
            index, step = mutations[0]
            allowed_mutations.add(id(step))
            if (
                index <= validation_index
                or step.get("run") != "gitforgeops apply --auto-approve"
                or any(key in step for key in ("uses", "shell", "working-directory"))
                or _workflow_condition(step.get("if")) != _workflow_condition(step_condition)
            ):
                violations.append(
                    f"{label}: {step_name!r} must run after successful Validate with its mode gate"
                )
    # Added or renamed inline mutations must not escape the guarded pair. A
    # name Bash computes at run time is program behavior, outside these text
    # rules.
    violations.extend(gitforgeops_scalar_violations(workflow, document, allowed_mutations))
    return violations


def gitforgeops_scalar_violations(label: str, document, guarded: set[int]) -> list[str]:
    """Outside the `guarded` steps, every scalar names the binary only as pinned.

    Every scalar counts, not only `run:`: a step's or a default's `shell:`
    runs the script through its command, and an action input can be executed
    by the action. A `run:` line naming the binary must be one of the pinned
    read-only lines; any other scalar may name it only as a pinned display
    name, which runs nothing. Only the `name:` of the workflow (or local
    action), a job or a step is a display name; an action input or env value
    called `name` is not. No scalar may use ANSI-C quoting, which spells the
    name by character code.
    """
    violations: list[str] = []
    read_only = {_scan_text(line) for line in READ_ONLY_GITFORGEOPS_LINES}
    display_names = {_scan_text(name) for name in GITFORGEOPS_DISPLAY_NAMES}
    titled = [document]
    jobs = document.get("jobs") if isinstance(document, dict) else None
    titled.extend(jobs.values() if isinstance(jobs, dict) else ())
    runs = document.get("runs") if isinstance(document, dict) else None
    for parent in [*titled[1:], runs]:
        steps = parent.get("steps") if isinstance(parent, dict) else None
        titled.extend(steps if isinstance(steps, list) else ())
    titled_ids = {id(node) for node in titled if isinstance(node, dict)}

    def permitted(key: str, scan: str, owner: int | None) -> bool:
        if key == "name" and owner in titled_ids and scan.strip(" \t") in display_names:
            return True
        return key == "run" and all(
            not _GITFORGEOPS_WORD.search(line) or line.strip(" \t") in read_only
            for line in scan.split("\n")
        )

    def visit(node, path: str, key: str = "", owner: int | None = None) -> None:
        if isinstance(node, dict):
            if id(node) in guarded:
                return
            for child, value in node.items():
                visit(value, f"{path}.{child}", child, id(node))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]", key)
        elif isinstance(node, str):
            if _uses_ansi_c_quoting(node):
                violations.append(f"{label}: {path}: {_ANSI_C_QUOTING_REFUSAL}")
            scan = _scan_text(node)
            if _GITFORGEOPS_WORD.search(scan) and not permitted(key, scan, owner):
                violations.append(
                    f"{label}: {path}: mutations may only run in the guarded Apply steps; "
                    "elsewhere gitforgeops may appear only on the pinned envs, validate "
                    "and verify run lines and as a pinned display name"
                )

    visit(document, "workflow")
    return violations


def protected_environment_names(workflow: str) -> tuple[str, ...]:
    """The variables `workflow` may bind only in its required step env."""
    protected: tuple[str, ...] = ()
    if workflow in PROBE_WORKFLOW_STEPS:
        protected += (PROBE_CONSUMERS_ENV, PROBE_BOUND_ENV)
    if workflow == ".github/workflows/apply-on-merge.yml":
        # These jobs publish the environment's complete scope. An ad-hoc
        # namespace filter can exempt slots from Validate's authorization.
        protected += ("FERRUM_ENV", "FERRUM_NAMESPACE")
    if workflow == f".github/workflows/{MONITORING_WORKFLOW}":
        protected += (VIEWER_JWT_SECRET, "FERRUM_ADMIN_JWT_SECRET")
    return protected


def probe_consumer_binding_violations(workflow: str, document: dict) -> list[str]:
    """The operator-held probe allowlist cannot be replaced by candidate data."""
    if workflow not in PROBE_WORKFLOW_STEPS:
        return []
    return guarded_environment_violations(
        workflow,
        document,
        PROBE_WORKFLOW_STEPS[workflow],
        protected_environment_names(workflow),
    ) + probe_validation_gate_violations(workflow, document)


def monitoring_jwt_binding_violations(workflow: str, document: dict) -> list[str]:
    """Monitoring binds the viewer key and cannot reintroduce the admin key."""
    if workflow != f".github/workflows/{MONITORING_WORKFLOW}":
        return []
    bindings = {VIEWER_JWT_SECRET: "${{ secrets.FERRUM_ADMIN_JWT_VIEWER_SECRET }}"}
    bindings.update({
        setting: f"${{{{ secrets.{setting} }}}}" for setting in VIEWER_JWT_OPTIONAL_SETTINGS
    })
    return guarded_environment_violations(
        workflow,
        document,
        (("drift", "Check drift", bindings),),
        protected_environment_names(workflow),
    )


# -- Local actions --------------------------------------------------------------
#
# A step's `uses: ./path` runs an action from the checked-out tree, which no
# commit pin covers, so the text fences must read what it runs. Every local
# reference must therefore name, by a plain path, a composite action under
# `.github/actions/` (where `action_files` pins its own `uses:`) that the
# strict reader parses; anything else is refused rather than guessed at. That
# includes a local reusable workflow (`jobs.<id>.uses: ./...`), which would
# carry none of its caller's pins, and a path into another checkout (`trusted/`),
# which the judged tree does not hold. Each action a workflow reaches, directly
# or through another local action, is judged by that workflow's fences.
LOCAL_ACTION_ROOT = (".github", "actions")
LOCAL_ACTION_FILES = ("action.yml", "action.yaml")
_LOCAL_ACTION_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+")


def resolve_local_action(root: Path, reference: str) -> tuple[str, dict | None, str | None]:
    """The action file a `./` reference runs and its parsed document, or a refusal."""
    parts = reference[2:].removesuffix("/").split("/")
    if (
        len(parts) < 3
        or tuple(parts[:2]) != LOCAL_ACTION_ROOT
        or any(
            part in (".", "..") or not _LOCAL_ACTION_COMPONENT.fullmatch(part)
            for part in parts
        )
    ):
        return reference, None, "must name a directory below ./.github/actions/ by a plain path"
    directory = root.joinpath(*parts)
    found = [
        directory / name for name in LOCAL_ACTION_FILES
        if (directory / name).is_symlink() or (directory / name).exists()
    ]
    if len(found) != 1:
        return reference, None, "must resolve to exactly one action.yml or action.yaml"
    path = found[0]
    relative = "/".join((*parts, path.name))
    expected = Path(os.path.realpath(root)).joinpath(*parts, path.name)
    if Path(os.path.realpath(path)) != expected or not path.is_file():
        return relative, None, "must be a regular file reached through no symbolic link"
    try:
        document = parse_workflow(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, WorkflowSyntaxError) as error:
        return relative, None, f"is outside the YAML subset the policy reads: {error}"
    runs = document.get("runs")
    if (
        not isinstance(runs, dict)
        or runs.get("using") != "composite"
        or not isinstance(runs.get("steps"), list)
    ):
        return relative, None, "must be a composite action (runs.using: composite) with steps"
    return relative, document, None


# A local action is judged as the tree carries it, and the runner reads it from
# the workspace when the step runs. A checkout of another revision over the
# workspace root before that step would run an action no rule judged. The
# protected default branch was judged when it merged, so that ref is allowed;
# any other ref or repository, or a path that may be the root, is not.
# A `git checkout` in a `run:` script is program behavior, outside these rules.
JUDGED_CHECKOUT_REFS = ("${{ github.event.repository.default_branch }}",)
JUDGED_CHECKOUT_REPOSITORIES = ("${{ github.repository }}",)
# A plain relative path whose components do not start with `.`: never the root,
# `..`, or a dot directory such as `.github`.
_CHECKOUT_SUBDIRECTORY = re.compile(
    r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*/?"
)


def _replaces_workspace(step) -> bool:
    """Whether a step checks an unjudged revision out over the workspace root."""
    if not isinstance(step, dict):
        return False
    uses = [value for key, value in step.items() if key.casefold() == "uses"]
    if not any(
        isinstance(value, str) and value.casefold().startswith("actions/checkout@")
        for value in uses
    ):
        return False
    inputs = [value for key, value in step.items() if key.casefold() == "with"]
    if not inputs:
        return False
    if len(inputs) != 1 or not isinstance(inputs[0], dict):
        return True

    def given(name: str) -> list:
        return [value for key, value in inputs[0].items() if key.casefold() == name]

    paths, refs, repositories = given("path"), given("ref"), given("repository")
    subdirectory = (
        len(paths) == 1
        and isinstance(paths[0], str)
        and _CHECKOUT_SUBDIRECTORY.fullmatch(paths[0]) is not None
    )
    if subdirectory:
        return False  # The workspace's own actions are untouched.
    return (
        len(refs) > 1
        or len(repositories) > 1
        or any(ref not in JUDGED_CHECKOUT_REFS for ref in refs)
        or any(name not in JUDGED_CHECKOUT_REPOSITORIES for name in repositories)
    )


def workspace_checkout_violations(workflow: str, document: dict) -> list[str]:
    """No job runs a local action after checking out an unjudged revision at the root."""
    violations: list[str] = []
    jobs = document.get("jobs")
    for job_name, job in jobs.items() if isinstance(jobs, dict) else ():
        steps = job.get("steps") if isinstance(job, dict) else None
        replaced: str | None = None
        for index, step in enumerate(steps if isinstance(steps, list) else ()):
            local = isinstance(step, dict) and any(
                key.casefold() == "uses" and isinstance(value, str) and value.startswith("./")
                for key, value in step.items()
            )
            if local and replaced is not None:
                violations.append(
                    f"{workflow}: jobs.{job_name}.steps[{index}]: a local action may not run "
                    f"after {replaced} checks another revision out over the workspace root; "
                    "check it out into a subdirectory instead"
                )
            if replaced is None and _replaces_workspace(step):
                replaced = f"jobs.{job_name}.steps[{index}]"
    return violations


def local_action_fence_violations(workflow: str, label: str, action: dict) -> list[str]:
    """The text fences of `workflow`, applied to a local action it runs."""
    violations = workflow_channel_violations(label, action)
    runs = action.get("runs")
    steps = runs.get("steps") if isinstance(runs, dict) else None
    for index, step in enumerate(steps if isinstance(steps, list) else ()):
        if _replaces_workspace(step):
            violations.append(
                f"{label}: runs.steps[{index}]: a local action may not check another "
                "revision out over the workspace root, where later local actions are read"
            )
    protected = protected_environment_names(workflow)
    if protected:
        violations.extend(guarded_environment_violations(label, action, (), protected))
    if workflow in RUN_EXPRESSIONS and any(
        isinstance(script, str) and "${{" in script for script in _values_for_key(action, "run")
    ):
        violations.append(
            f"{label}: an action an Environment-bound workflow runs may not interpolate "
            "into run:; pass the value through step env instead"
        )
    if workflow == ".github/workflows/apply-on-merge.yml":
        violations.extend(gitforgeops_scalar_violations(label, action, set()))
    return violations


def local_action_violations(
    root: Path, workflow: str, document: dict, cache: dict | None = None
) -> list[str]:
    """Every local action `workflow` reaches resolves and passes its fences."""
    cache = {} if cache is None else cache
    violations: list[str] = []
    pending = [
        (workflow, reference) for reference in workflow_action_references(document)
        if reference.startswith("./")
    ]
    seen: set[str] = set()
    while pending:
        source, reference = pending.pop(0)
        if reference in seen:
            continue
        seen.add(reference)
        if reference not in cache:
            cache[reference] = resolve_local_action(root, reference)
        relative, action, refusal = cache[reference]
        if action is None:
            violations.append(f"{source}: local action {reference!r} {refusal}")
            continue
        violations.extend(
            local_action_fence_violations(workflow, f"{relative} (run by {workflow})", action)
        )
        pending.extend(
            (relative, nested) for nested in workflow_action_references(action)
            if nested.startswith("./")
        )
    return violations


# Every launch-required status check context, with the one workflow whose job
# of the same key reports it. These are `audit_settings.REQUIRED_STATUS_CHECKS`,
# which `bootstrap_repo_settings.py` writes into the `main` ruleset; a test keeps
# the two in step, because this checker imports nothing from the tree it judges.
REQUIRED_CHECK_WORKFLOWS = {
    "rust-ci-check": ".github/workflows/rust-ci.yml",
    "security-cargo-audit": ".github/workflows/security.yml",
    "security-supply-chain-policy": ".github/workflows/security.yml",
    SUPPLY_CHAIN_POLICY_JOB: SUPPLY_CHAIN_POLICY_PATH,
    "state-guard-reject-state-edits": ".github/workflows/state-guard.yml",
    "gitforgeops-required-static-validation": ".github/workflows/validate-pr.yml",
}


def _impersonated_check(workflow: str, job_id: str, spelled: str) -> str | None:
    """The required context `spelled` names, unless this is that context's own job."""
    context = spelled.strip().casefold()
    home = REQUIRED_CHECK_WORKFLOWS.get(context)
    if home is None or (workflow == home and job_id == context):
        return None
    return context


def policy_check_impersonation_violations(workflow: str, document: dict) -> list[str]:
    """Only a required check's own job may report its context.

    A ruleset requires a check by name, and a check run is named by its job's
    key or its `name:`. A candidate's `pull_request` workflows run its own
    definitions, so a job keyed or named like a required one would put a
    second, candidate-defined result under the required name. For
    `trusted-supply-chain-policy` and `state-guard-reject-state-edits`, which
    come from `pull_request_target` workflows the pull request cannot edit,
    that second result would come from code no protected definition reviewed.
    Read from the parsed workflow: no job key and no job `name:` may equal a
    context in `REQUIRED_CHECK_WORKFLOWS` (in any case, ignoring surrounding
    whitespace) except the job keyed by that context in its own workflow, and
    no job `name:` may be computed with `${{ }}`. A matrix suffix or a reusable
    workflow's `caller / callee` form can never equal a context.

    This is defense in depth. How branch protection resolves two check runs
    with one name is not established (docs/github-launch-controls.md).

    `workflow` is the path relative to the repository root.
    """
    violations: list[str] = []
    for jobs in (value for key, value in document.items() if key.casefold() == "jobs"):
        if jobs is None:
            continue
        if not isinstance(jobs, dict):
            violations.append(f"{workflow}: `jobs` must be a mapping of jobs")
            continue
        for job_id, job in jobs.items():
            label = f"{workflow}: job {job_id!r}"
            claimed = [_impersonated_check(workflow, job_id, job_id)]
            if not isinstance(job, dict):
                violations.append(f"{label}: a job must be a mapping")
                job = {}
            for key, name in job.items():
                if key.casefold() != "name" or name is None:
                    continue
                if not isinstance(name, str):
                    violations.append(f"{label}: a job display name must be one string")
                elif "${{" in name:
                    violations.append(
                        f"{label}: a job display name must be a literal, so no "
                        "workflow can compute a required check name; "
                        f"found {name!r}"
                    )
                else:
                    claimed.append(_impersonated_check(workflow, job_id, name))
            for context in dict.fromkeys(item for item in claimed if item is not None):
                home = REQUIRED_CHECK_WORKFLOWS[context].rsplit("/", 1)[-1]
                violations.append(
                    f"{label}: only job {context!r} of {home} may define the "
                    f"{context!r} check"
                )
    return violations


# Workflows that may grant a token the right to create check runs or commit
# statuses. Empty: with either, a job could report any context name it
# computes at run time, which no static rule can see.
STATUS_WRITE_ALLOWED: frozenset[str] = frozenset()


def status_write_permission_violations(workflow: str, document: dict) -> list[str]:
    """No workflow may let its token create check runs or commit statuses.

    Read from the parsed workflow, at every `permissions:` (workflow and job
    level): a string must be `read-all`, and a mapping may give `checks` and
    `statuses` (any case) only `read` or `none`. `write-all` grants both.
    Workflows in `STATUS_WRITE_ALLOWED` (none) are exempt.
    """
    if workflow in STATUS_WRITE_ALLOWED:
        return []
    violations: list[str] = []
    for permissions in _values_for_key(document, "permissions"):
        if permissions is None:
            continue
        if isinstance(permissions, str):
            if permissions.strip().casefold() != "read-all":
                violations.append(
                    f"{workflow}: permissions: {permissions!r} may grant checks or "
                    "statuses write; use read-all or a mapping"
                )
            continue
        if not isinstance(permissions, dict):
            violations.append(f"{workflow}: permissions must be read-all or a mapping")
            continue
        for scope, level in permissions.items():
            if scope.casefold() not in ("checks", "statuses"):
                continue
            if not (isinstance(level, str) and level.strip().casefold() in ("read", "none")):
                violations.append(
                    f"{workflow}: {scope.casefold()} may only be read; a token that "
                    "writes check runs or commit statuses can report a required "
                    f"check under any name; found {scope}: {level!r}"
                )
    return violations


CARGO_AUDIT_JOB = "security-cargo-audit"
# Stands in for the toolchain, which `rust_toolchain_violations` pins per step.
PINNED_RUST_TOOLCHAIN = "<rust toolchain>"
# The parsed `security-cargo-audit` job. It is a required check defined by the
# pull request itself, so substrings anywhere in the file prove nothing: `true`
# with the trusted command commented out below it, an `exit 0` or `|| true`
# around it, a skipped or failure-tolerant step, an added step or a job-level
# `env:`/`defaults:` (`BASH_ENV`, another shell) all keep every substring and
# report success. Exact rather than substring, like
# `SUPPLY_CHAIN_POLICY_SHAPE`: only action commits (the repository-wide rule
# and `CARGO_AUDIT_ACTIONS` judge them) and the toolchain are free.
CARGO_AUDIT_JOB_SHAPE = {
    "runs-on": "ubuntu-24.04",
    "permissions": {"contents": "read"},
    "steps": [
        {
            "uses": f"actions/checkout@{PINNED_ACTION_COMMIT}",
            "with": {"persist-credentials": "false"},
        },
        {
            "name": "Check out trusted cargo-audit policy",
            "if": "github.event_name == 'pull_request'",
            "uses": f"actions/checkout@{PINNED_ACTION_COMMIT}",
            "with": {
                "ref": "${{ github.event.repository.default_branch }}",
                "path": "trusted-cargo-audit",
                "persist-credentials": "false",
            },
        },
        {
            "name": "Install Rust toolchain",
            "uses": f"dtolnay/rust-toolchain@{PINNED_ACTION_COMMIT}",
            "with": {"toolchain": PINNED_RUST_TOOLCHAIN},
        },
        {
            "name": "Install cargo-audit",
            "uses": f"taiki-e/install-action@{PINNED_ACTION_COMMIT}",
            "with": {"tool": "cargo-audit@0.22.1", "checksum": "true", "fallback": "none"},
        },
        {
            "name": "Test audit policy gate",
            "env": {"EVENT_NAME": "${{ github.event_name }}"},
            "run": "\n".join(
                (
                    'if [ "$EVENT_NAME" = pull_request ]; then',
                    "  python3 trusted-cargo-audit/.github/scripts/tests/test_check_cargo_audit.py",
                    "else",
                    "  python3 .github/scripts/tests/test_check_cargo_audit.py",
                    "fi",
                )
            ),
        },
        {
            "name": "Enforce cargo audit policy",
            "env": {"EVENT_NAME": "${{ github.event_name }}"},
            "run": "\n".join(
                (
                    'if [ "$EVENT_NAME" = pull_request ]; then',
                    "  python3 trusted-cargo-audit/.github/scripts/check_cargo_audit.py \\",
                    "    --policy trusted-cargo-audit/.github/cargo-audit-policy.json \\",
                    '    --source-root "$GITHUB_WORKSPACE"',
                    "else",
                    "  python3 .github/scripts/check_cargo_audit.py",
                    "fi",
                )
            ),
        },
    ],
}
_PINNED_USES_VALUE = re.compile(r"([^@\s]+)@[0-9a-f]{40}")
# Workflow-level keys that reach every job's shell.
_SHELL_REACHING_WORKFLOW_KEYS = ("env", "defaults")


def _normalized_cargo_audit_step(step):
    """A parsed step with its action commit and toolchain made placeholders."""
    if not isinstance(step, dict):
        return step
    uses = step.get("uses")
    match = _PINNED_USES_VALUE.fullmatch(uses) if isinstance(uses, str) else None
    if match is None:
        return step
    step = {**step, "uses": f"{match.group(1)}@{PINNED_ACTION_COMMIT}"}
    with_inputs = step.get("with")
    if (
        match.group(1) == "dtolnay/rust-toolchain"
        and isinstance(with_inputs, dict)
        and "toolchain" in with_inputs
    ):
        step["with"] = {**with_inputs, "toolchain": PINNED_RUST_TOOLCHAIN}
    return step


def cargo_audit_job_shape_violations(text: str) -> list[str]:
    """The required `security-cargo-audit` job must keep its reviewed, parsed shape.

    Read from the strict workflow reader, so a comment is never a command and
    a command is never hidden in a comment. Workflow-level `env:` and
    `defaults:` are refused too: they reach this job's shell without appearing
    in it.
    """
    try:
        document = parse_workflow(text)
    except WorkflowSyntaxError as error:
        return [
            "security.yml: the cargo-audit gate must be in the YAML subset the "
            f"policy reads: {error}"
        ]
    violations = [
        f"security.yml: workflow-level {key!r} reaches the required {CARGO_AUDIT_JOB!r} "
        "job's shell (a startup file, another shell or working directory); the "
        "workflow must not set it"
        for key in document
        if key.casefold() in _SHELL_REACHING_WORKFLOW_KEYS
    ]
    jobs = document.get("jobs")
    job = jobs.get(CARGO_AUDIT_JOB) if isinstance(jobs, dict) else None
    if not isinstance(job, dict):
        violations.append(f"security.yml: the required {CARGO_AUDIT_JOB!r} job is missing")
        return violations
    for key in sorted(set(job) | set(CARGO_AUDIT_JOB_SHAPE)):
        if key != "steps" and job.get(key) != CARGO_AUDIT_JOB_SHAPE.get(key):
            violations.append(
                f"security.yml: {CARGO_AUDIT_JOB} must keep its reviewed job keys; "
                f"{key!r} should be {CARGO_AUDIT_JOB_SHAPE.get(key)!r}, "
                f"found {job.get(key)!r}"
            )
    steps = job.get("steps")
    found_steps = (
        [_normalized_cargo_audit_step(step) for step in steps]
        if isinstance(steps, list)
        else []
    )
    expected_steps = CARGO_AUDIT_JOB_SHAPE["steps"]
    for index in range(max(len(found_steps), len(expected_steps))):
        found = found_steps[index] if index < len(found_steps) else "<end of steps>"
        wanted = expected_steps[index] if index < len(expected_steps) else "<end of steps>"
        if found != wanted:
            violations.append(
                f"security.yml: {CARGO_AUDIT_JOB} must keep its reviewed steps (the "
                "trusted checker, its tests and exception policy on pull requests; "
                "no commented-out, skipped, swallowed or added command); step "
                f"{index + 1} should be {wanted!r}, found {found!r}"
            )
            break
    return violations


def trusted_cargo_audit_policy_violations(text: str) -> list[str]:
    """The dependency gate must run `main`'s checker against `main`'s exceptions.

    Under `on: pull_request` this workflow file is itself supplied by the pull
    request's head, so without this assertion one commit could add a
    cargo-audit exception *and* delete the trusted checkout that stops the
    exception from counting — and the gate would report success. The trusted
    supply-chain runner reads the candidate's copy of `security.yml`, which is
    the only place an assertion about it can be enforced. The parsed job is
    pinned by `cargo_audit_job_shape_violations`; the substring checks below
    keep their specific messages.

    Push and schedule runs keep executing the tree's own checker: there is no
    untrusted author there, and pinning them to the default branch would stop
    a merged policy change from ever taking effect.
    """
    violations = cargo_audit_job_shape_violations(text)

    checkout = named_step(text, "Check out trusted cargo-audit policy")
    if checkout is None:
        violations.append(
            "security.yml: the cargo-audit gate must check out the protected default branch"
        )
    else:
        for required in (
            "if: github.event_name == 'pull_request'",
            "ref: ${{ github.event.repository.default_branch }}",
            "path: trusted-cargo-audit",
        ):
            if required not in checkout:
                violations.append(
                    f"security.yml: trusted cargo-audit checkout is missing {required!r}"
                )

    for required in (
        "python3 trusted-cargo-audit/.github/scripts/tests/test_check_cargo_audit.py",
        "python3 trusted-cargo-audit/.github/scripts/check_cargo_audit.py",
        "--policy trusted-cargo-audit/.github/cargo-audit-policy.json",
        '--source-root "$GITHUB_WORKSPACE"',
    ):
        if required not in text:
            violations.append(
                f"security.yml: trusted cargo-audit policy runner is missing {required!r}"
            )

    # The findings must still be computed against the candidate's own
    # dependency graph; only the checker and the exception list are pinned.
    if "--policy .github/cargo-audit-policy.json" in text:
        violations.append(
            "security.yml: a pull request must not supply its own cargo-audit exception policy"
        )
    return violations


MINT_STEP = "- name: Mint narrowly scoped state-writer token"


def workflow_jobs(text: str) -> list[tuple[str, str]]:
    """Every job under `jobs:`, with its own body.

    Scoped to the `jobs:` mapping rather than every two-space key in the file.
    A bare indentation match also collects `on:`'s triggers — `push`,
    `schedule` — as "jobs", and a per-job security rule that silently runs
    against a trigger block is a rule nobody can reason about.
    """
    start = re.search(r"^jobs:\s*$", text, re.MULTILINE)
    if start is None:
        return []
    section = re.split(
        r"^(?!#)\S", text[start.end():], maxsplit=1, flags=re.MULTILINE
    )[0]
    jobs: list[tuple[str, str]] = []
    for match in re.finditer(
        r"^  (?P<name>[A-Za-z0-9_-]+):\n", section, re.MULTILINE
    ):
        # A job's body ends at the next line indented two spaces or less that
        # is not a comment. Bounding it at the next *recognized* header instead
        # would fold a job whose header this parser does not recognize (a
        # quoted key, a trailing comment) into the preceding job, hiding it
        # from the per-job checks that count what each job does.
        body = re.split(
            r"^ {0,2}(?!#)\S", section[match.end():], maxsplit=1, flags=re.MULTILINE
        )[0]
        jobs.append((match.group("name"), body))
    return jobs


def privileged_jobs(text: str) -> list[tuple[str, str]]:
    """Every job that mints the state-writer token, with its own body.

    The install-before-mint-before-commit rule is about ONE job's step
    sequence. Measured across a whole file it silently stops meaning anything
    as soon as a workflow has two privileged jobs: `rfind` picks up the second
    job's build and `find` the first job's mint, and the ordering test compares
    steps that never run in the same runner.

    Returning the jobs lets the rule be applied where it is true — in each of
    them — which is both the correct reading and a strictly stronger one.
    """
    return [(name, body) for name, body in workflow_jobs(text) if MINT_STEP in body]


def state_writer_token_violations(
    workflow: str, text: str, commit_step: str
) -> list[str]:
    violations: list[str] = []
    if "token: ${{ steps.state-writer.outputs.token }}" in text:
        violations.append(
            f"{workflow}: state-writer token must not be persisted by checkout"
        )
    jobs = privileged_jobs(text)
    assigned_mints = sum(body.count(MINT_STEP) for _, body in jobs)
    if assigned_mints != text.count(MINT_STEP):
        violations.append(
            f"{workflow}: every state-writer token mint must belong to a validated job"
        )
    if not jobs:
        violations.append(
            f"{workflow}: no job mints the state-writer token, so the ownership "
            "ledger is never published"
        )
    for name, body in jobs:
        install_index = body.rfind("run: cargo install --path . --locked")
        mint_index = body.find(MINT_STEP)
        commit_index = body.find(commit_step)
        if not (install_index >= 0 and install_index < mint_index < commit_index):
            violations.append(
                f"{workflow}: job {name!r}: state-writer token must be minted after "
                "untrusted builds and immediately before state persistence"
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


STATE_PUSH_RETRY_REQUIRED = (
    "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
    'git push origin "HEAD:$DEFAULT_BRANCH"',
    'git fetch origin "$DEFAULT_BRANCH"',
    'git rebase "origin/$DEFAULT_BRANCH"',
)
STATE_PUSH_RETRY_FORBIDDEN = (
    "git fetch origin main",
    "origin/main",
)


def state_push_retry_violations(workflow: str, text: str, commit_step: str) -> list[str]:
    """State commits must rebase and push against the repository default branch.

    The freshness guard already parameterises checkout and ancestry on
    ``DEFAULT_BRANCH``; hardcoding ``origin/main`` in the post-mutation push
    retry loop breaks on forks whose default branch is not literally ``main``.
    """
    violations: list[str] = []
    commit_index = text.find(commit_step)
    if commit_index < 0:
        return [f"{workflow}: a {commit_step!r} step is required"]
    commit_block = text[commit_index:]
    next_step = re.search(r"\n      - (?:name|uses):", commit_block[1:])
    if next_step is not None:
        commit_block = commit_block[: next_step.start() + 1]
    for forbidden in STATE_PUSH_RETRY_FORBIDDEN:
        if forbidden in commit_block:
            violations.append(
                f"{workflow}: {commit_step!r} must not hardcode {forbidden!r}; "
                "use the repository default branch"
            )
    for required in STATE_PUSH_RETRY_REQUIRED:
        if required not in commit_block:
            violations.append(
                f"{workflow}: {commit_step!r} is missing default-branch push retry "
                f"control {required!r}"
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
    # Before any read: a link out of the tree, or a special file, would make
    # every later rule judge something other than what the tree carries. The
    # root is judged as given, so a root that is itself a link is refused.
    tree_violations = candidate_tree_violations(Path(os.path.abspath(args.root)))
    if tree_violations:
        print("Supply-chain policy violations:", file=sys.stderr)
        for violation in tree_violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1
    root = args.root.resolve()
    workflows = root / ".github" / "workflows"
    checked_action_files = action_files(root)
    # Every workflow must be spelled so the rules find it, and be in the YAML
    # subset the structural rules read, before any rule runs
    # (GHSA-x5m2-4555-q4cr).
    workflow_documents: dict[str, dict] = {}
    syntax_violations = workflow_extension_violations(root)
    for workflow in checked_action_files:
        if workflow.parent != workflows:
            continue
        relative = workflow.relative_to(root).as_posix()
        try:
            workflow_documents[relative] = parse_workflow(
                workflow.read_text(encoding="utf-8")
            )
        except WorkflowSyntaxError as error:
            syntax_violations.append(
                f"{relative}: workflow is outside the YAML subset the policy reads "
                f"(see check_supply_chain.py, Strict workflow reader): {error}"
            )
    if syntax_violations:
        print("Supply-chain policy violations:", file=sys.stderr)
        for violation in syntax_violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1
    violations: list[str] = []
    toolchain_path = root / "rust-toolchain.toml"
    rust_channel = read_rust_toolchain_channel(toolchain_path)
    if rust_channel is None:
        minimum_rust_toolchain = ".".join(str(part) for part in MIN_RUST_TOOLCHAIN)
        violations.append(
            "rust-toolchain.toml: expected [toolchain].channel to be a stable "
            f"X.Y.Z channel at or above {minimum_rust_toolchain}, "
            "with no legacy rust-toolchain file"
        )
    candidate_checker = root / ".github" / "scripts" / "check_supply_chain.py"
    if candidate_checker.is_symlink() or not candidate_checker.is_file():
        violations.append(
            ".github/scripts/check_supply_chain.py must remain a regular protected policy file"
        )
    action_pins: dict[str, list[str]] = {}
    local_actions: dict = {}
    for workflow in checked_action_files:
        text = workflow.read_text(encoding="utf-8")
        document = workflow_documents.get(workflow.relative_to(root).as_posix())
        if document is not None:
            references = workflow_action_references(document)
        else:
            # A local action: its `uses:` are read from the parsed file, as the
            # runner reads them, never from a text scan a spelling can evade.
            try:
                references = workflow_action_references(parse_workflow(text))
            except WorkflowSyntaxError as error:
                references = []
                violations.append(
                    f"{workflow.relative_to(root)}: action is outside the YAML subset "
                    f"the policy reads, so its action pins cannot be read: {error}"
                )
        action_pins[str(workflow.relative_to(root))] = references
        for reference in references:
            if reference.startswith("./"):
                continue  # Judged by local_action_violations.
            if not ACTION_SHA.fullmatch(reference):
                violations.append(
                    f"{workflow.relative_to(root)}: action is not pinned to a 40-hex commit: {reference}"
                )
        if "ubuntu-latest" in text:
            violations.append(
                f"{workflow.relative_to(root)}: runner image must use an explicit Ubuntu release"
            )
        violations.extend(
            rust_toolchain_violations(
                str(workflow.relative_to(root)), text, rust_channel or "<invalid>"
            )
        )
        violations.extend(
            cargo_toolchain_violations(
                str(workflow.relative_to(root)), text, rust_channel or "<invalid>"
            )
        )
        violations.extend(
            whole_secrets_context_violations(str(workflow.relative_to(root)), text)
        )
        violations.extend(
            secret_name_case_violations(str(workflow.relative_to(root)), text)
        )
        violations.extend(
            admin_jwt_binding_violations(str(workflow.relative_to(root)), text)
        )
        violations.extend(
            viewer_jwt_scope_violations(workflow.relative_to(root).as_posix(), text)
        )
        if document is not None:
            violations.extend(
                workflow_channel_violations(workflow.relative_to(root).as_posix(), document)
            )
            violations.extend(
                run_expression_violations(workflow.relative_to(root).as_posix(), document)
            )
            violations.extend(
                run_expression_source_violations(workflow.relative_to(root).as_posix(), document)
            )
            violations.extend(
                probe_consumer_binding_violations(
                    workflow.relative_to(root).as_posix(), document
                )
            )
            violations.extend(
                monitoring_jwt_binding_violations(
                    workflow.relative_to(root).as_posix(), document
                )
            )
            violations.extend(
                policy_check_impersonation_violations(
                    workflow.relative_to(root).as_posix(), document
                )
            )
            violations.extend(
                status_write_permission_violations(
                    workflow.relative_to(root).as_posix(), document
                )
            )
            violations.extend(
                local_action_violations(
                    root, workflow.relative_to(root).as_posix(), document, local_actions
                )
            )
            violations.extend(
                workspace_checkout_violations(workflow.relative_to(root).as_posix(), document)
            )
            violations.extend(
                container_options_violations(workflow.relative_to(root).as_posix(), document)
            )
        if "ferrum-edge-linux-x86_64" in text:
            violations.append(
                f"{workflow.relative_to(root)}: download must go through install-ferrum-edge.sh"
            )

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    if rust_channel is not None:
        violations.extend(docker_builder_toolchain_violations(dockerfile, rust_channel))
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
    violations.extend(rust_ci_test_scope_violations(rust_ci))

    for workflow_name, expected_name in (
        ("rust-ci.yml", "Rust CI"),
        ("security.yml", "Security"),
        ("state-guard.yml", "GitForgeOps State Guard"),
        ("validate-pr.yml", "GitForgeOps PR Static Validation"),
        ("validator-pin-canary.yml", "GitForgeOps Validator Pin Canary"),
        ("base-image-pin-canary.yml", "GitForgeOps Base Image Pin Canary"),
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
        "subject-name: docker.io/${{ vars.DOCKERHUB_IMAGE || 'ferrumedge/ferrum-edge-git-forge-ops' }}",
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
    # This repository is a template customers copy. A copy is not a fork, so
    # `github.event.repository.fork == false` is true on it, and gating on that
    # would have every customer repository attempt a Docker Hub publish to the
    # upstream namespace on its first push to `main`. Both release jobs must
    # name the upstream repository, or an explicit opt-in variable.
    release_gate = (
        "if: github.repository == 'ferrum-edge/ferrum-edge-git-forge-ops'"
        " || vars.GITFORGEOPS_RELEASE_ENABLED == 'true'"
    )
    if release.count(release_gate) != 2:
        violations.append(
            "release.yml: both release jobs must be gated on the upstream repository "
            "or GITFORGEOPS_RELEASE_ENABLED, so a template copy never publishes"
        )
    if re.search(r"^\s*if: .*repository\.fork", release, re.MULTILINE):
        violations.append(
            "release.yml: a fork test does not distinguish a template copy from upstream"
        )
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
    violations.extend(
        allocation_revision_binding_violations("apply-on-merge.yml", apply_workflow)
    )

    shard_limit, shard_limit_violations = credential_shard_limit(root)
    violations.extend(shard_limit_violations)
    violations.extend(import_shard_ceiling_violations(root))

    for privileged_workflow in PRIVILEGED_WORKFLOWS:
        text = (workflows / privileged_workflow).read_text(encoding="utf-8")
        if (
            privileged_workflow != "apply-on-merge.yml"
            and "Repository configuration is required before binding a deployment environment."
            not in text
        ):
            violations.append(
                f"{privileged_workflow}: must fail before environment binding when repo config is absent"
            )
        # Credential-consuming operations must retain this contract even when
        # a candidate removes every secret reference. Other privileged
        # workflows become covered if they start binding credential bundles.
        if (
            privileged_workflow in CREDENTIAL_BUNDLE_WORKFLOWS
            or mentions_secret(text, BUNDLE_SECRET_BINDING)
        ):
            if ".github/scripts/credential_bundles.py" not in text:
                violations.append(
                    f"{privileged_workflow}: credential bundles must use the fail-closed loader"
                )
            if "except json.JSONDecodeError" in text:
                violations.append(
                    f"{privileged_workflow}: malformed credential bundles must not fail open"
                )
            # The loader reads enumerated env bindings, so every shard the Rust
            # allocator may create has to be bound here by name. Cross-checked
            # against MAX_BUNDLE_SHARDS on both sides.
            violations.extend(
                credential_bundle_binding_violations(
                    privileged_workflow, text, shard_limit
                )
            )
            # $RUNNER_TEMP is wiped with the workspace; a bare `mktemp` lands in
            # a /tmp that self-hosted runners share between jobs and never clean.
            if '"${RUNNER_TEMP:-/tmp}/ferrum-creds-' not in text:
                violations.append(
                    f"{privileged_workflow}: the resolved credential file must live under $RUNNER_TEMP"
                )
        if "[skip ci]" in text:
            violations.append(
                f"{privileged_workflow}: state commits must not suppress required checks with [skip ci]"
            )

    monitoring_text = (workflows / MONITORING_WORKFLOW).read_text(encoding="utf-8")
    violations.extend(monitoring_workflow_violations(monitoring_text))

    for state_writer_workflow in ("apply-on-merge.yml", "rotate.yml"):
        violations.extend(
            state_writer_preflight_violations(
                state_writer_workflow,
                (workflows / state_writer_workflow).read_text(encoding="utf-8"),
            )
        )

    # The per-step rule above only fires where the secret is bound. Name the
    # admin-API workflows too, so silently dropping the whole JWT block from one
    # of them — which would fail authentication rather than fall back to a
    # default — is caught here rather than at 2am against a live gateway.
    for admin_api_workflow in ADMIN_API_WORKFLOWS:
        text = (workflows / admin_api_workflow).read_text(encoding="utf-8")
        accepted = admin_api_jwt_bindings(admin_api_workflow)
        if not any(binding in text for binding in accepted):
            violations.append(
                f"{admin_api_workflow}: an admin-API workflow must bind "
                f"{' or '.join(repr(binding) for binding in accepted)} from the "
                "selected GitHub Environment"
            )

    for fresh_head_workflow, contract in FRESH_HEAD_WORKFLOWS.items():
        violations.extend(
            stale_deployment_guard_violations(
                fresh_head_workflow,
                (workflows / fresh_head_workflow).read_text(encoding="utf-8"),
                contract,
            )
        )

    violations.extend(
        deployment_scope_violations(
            root, (workflows / "apply-on-merge.yml").read_text(encoding="utf-8")
        )
    )

    settings_audit = (workflows / "settings-audit.yml").read_text(encoding="utf-8")
    # The audit token reads repository administration settings. As a repository
    # secret it was released to whatever workflow definition a dispatched ref
    # carried, so any branch a write-access collaborator can push was a path to
    # it. A dedicated environment whose deployment-branch policy admits only the
    # protected default branch is the non-bypassable fence: GitHub refuses to
    # release the secret to a job on any other ref, before a step runs. The
    # in-file ref preflight stays as the readable half of the same rule.
    if SETTINGS_AUDIT_ENVIRONMENT_BINDING not in settings_audit:
        violations.append(
            "settings-audit.yml: the audit job must bind "
            f"{SETTINGS_AUDIT_ENVIRONMENT_BINDING.strip()!r} so the "
            "administration-read token is fenced to the protected default branch"
        )
    for workflow in checked_action_files:
        if workflow.name == "settings-audit.yml":
            continue
        if mentions_secret(workflow.read_text(encoding="utf-8"), SETTINGS_AUDIT_TOKEN_REFERENCE):
            violations.append(
                f"{workflow.relative_to(root)}: the administration-read audit token "
                "may be read only by the environment-bound settings audit"
            )
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
    security_workflow = (workflows / "security.yml").read_text(encoding="utf-8")
    violations.extend(trusted_supply_chain_policy_violations(security_workflow))
    violations.extend(supply_chain_policy_workflow_violations(root))
    violations.extend(trusted_cargo_audit_policy_violations(security_workflow))
    violations.extend(cargo_audit_install_violations(security_workflow))
    violations.extend(security_push_trigger_violations(security_workflow))
    violations.extend(security_trigger_violations(security_workflow))
    state_guard = (workflows / "state-guard.yml").read_text(encoding="utf-8")
    if 'result=$(python3 "$helper"' not in state_guard:
        violations.append(
            "state-guard.yml: classifier execution must use the trusted helper variable"
        )
    violations.extend(state_guard_override_recheck_violations(state_guard))

    for state_workflow, commit_step in (
        ("apply-on-merge.yml", "- name: Commit state + assembled (if changed)"),
        ("rotate.yml", "- name: Commit state update"),
    ):
        text = (workflows / state_workflow).read_text(encoding="utf-8")
        violations.extend(
            state_writer_token_violations(state_workflow, text, commit_step)
        )
        violations.extend(
            state_push_retry_violations(state_workflow, text, commit_step)
        )

    static_review = (workflows / "validate-pr.yml").read_text(encoding="utf-8")
    violations.extend(trusted_validator_probe_violations(static_review))
    if re.search(r"^ {4}environment\s*:", static_review, re.MULTILINE):
        violations.append("validate-pr.yml: PR-built code must not bind an Environment")
    # Match the whole `secrets` context, not just `secrets.NAME` /
    # `secrets['NAME']`. `${{ toJSON(secrets) }}`,
    # `${{ fromJSON(toJSON(secrets)) }}` and a bare `${{ secrets }}` hand over
    # every environment secret at once and are exactly what the privileged
    # workflows use to load credential bundles — the form most worth catching
    # in the workflow that must never receive one.
    if re.search(r"\$\{\{[^}]*\bsecrets\b", static_review, re.IGNORECASE):
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
        "/.github/actions/",
        "/.github/scripts/",
        "/.github/ferrum-edge-checksums.txt",
        "/.gitforgeops/",
        "/.state",
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

    for script_name in ("install-ferrum-edge.sh", "refresh-ferrum-edge-pin.sh"):
        script = root / ".github" / "scripts" / script_name
        if script.is_symlink() or not script.is_file():
            violations.append(
                f"{script_name} must remain a regular protected script"
            )
    installer = (root / ".github" / "scripts" / "install-ferrum-edge.sh").read_text(
        encoding="utf-8"
    )
    for required in (
        "ferrum-edge-checksums.txt",
        "allowed_digests",
        "published_sha256",
        "actual_sha256",
        "Authorization: Bearer",
        "--proto '=https'",
        "--tlsv1.2",
        "--fail",
        '"$releases_api/latest"',
        "select(.prerelease | not)",
        '"$releases_api?per_page=5"',
        "select(.name == $name)",
        "install -m 0755",
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
        "validator-pin-canary.yml",
    ):
        workflow_text = (root / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        violations.extend(
            installer_step_auth_violations(workflow_name, workflow_text)
        )
        if workflow_name == "validate-pr.yml":
            violations.extend(untrusted_pr_installer_violations(workflow_text))
    violations.extend(
        validator_locator_violations(
            [workflow.read_text(encoding="utf-8") for workflow in checked_action_files]
        )
    )

    canary = (workflows / "validator-pin-canary.yml").read_text(encoding="utf-8")
    for required in (
        "  schedule:",
        "  workflow_dispatch:",
        "Require protected default branch",
        "EXPECTED_REF: refs/heads/${{ github.event.repository.default_branch }}",
        "issues: write",
        ".github/scripts/refresh-ferrum-edge-pin.sh",
        "gh issue create",
    ):
        if required not in canary:
            violations.append(
                f"validator-pin-canary.yml: missing stale-pin canary control {required!r}"
            )

    checksum_policy = root / ".github" / "ferrum-edge-checksums.txt"
    if checksum_policy.is_symlink() or not checksum_policy.is_file():
        violations.append(
            "ferrum-edge-checksums.txt must remain a regular protected policy file"
        )
        allowlist_text = ""
    else:
        allowlist_text = checksum_policy.read_text(encoding="utf-8")
        violations.extend(digest_allowlist_violations(allowlist_text))
    approved_digests = allowlisted_validator_digests(allowlist_text)

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
            "rust_toolchain": rust_channel,
            "actions": action_pins,
            "docker_bases": FROM.findall(dockerfile),
            "ferrum_edge_binaries": [
                {"asset": VALIDATOR_ASSET, "sha256": digest}
                for digest in approved_digests
            ],
        }
        args.write_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print("All Actions, Rust, validator, and container inputs are immutably pinned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
