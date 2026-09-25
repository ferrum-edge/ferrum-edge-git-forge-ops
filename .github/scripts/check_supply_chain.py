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
VALIDATOR_ASSET = "ferrum-edge-linux-x86_64"
DIGEST_ENTRY = re.compile(r"([0-9a-f]{64})\s+" + re.escape(VALIDATOR_ASSET))
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
NAMED_SECRET = re.compile(r"\bsecrets\.[A-Za-z_][A-Za-z0-9_]*")
WHOLE_SECRETS = re.compile(r"\bsecrets\b")
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
STEP_SPLIT = re.compile(r"\n(?=\s*-\s+(?:name|uses):)")
STEP_NAME = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$", re.MULTILINE)
CARGO_AUDIT_ACTION = "taiki-e/install-action@9534c84618278caac52cb373bb164ed464dbd8af"
SECURITY_PUSH_POLICY_PATHS = (
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
APPLY_REVISION_BINDINGS = (
    (
        'git show "${TRIGGER_SHA}:.github/scripts/deployment_scope.py" | \\',
        "python3 - classify \\",
        '"$TRIGGER_SHA" "$fresh_head" --branch "$DEFAULT_BRANCH"',
    ),
)
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
        if ADMIN_JWT_SECRET_BINDING not in step:
            continue
        name_match = STEP_NAME.search(step)
        name = name_match.group(1) if name_match else "<unnamed step>"
        missing = [
            setting
            for setting in ADMIN_JWT_OPTIONAL_SETTINGS
            if f"{setting}: ${{{{ secrets.{setting} }}}}" not in step
        ]
        if missing:
            violations.append(
                f"{workflow}: step {name!r} binds FERRUM_ADMIN_JWT_SECRET but not "
                f"{', '.join(missing)}; a documented per-environment secret that "
                "never reaches the process is a 401 the operator cannot explain"
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

        if workflow == "apply-on-merge.yml":
            satisfied = any(
                all(required in guard for required in family)
                for family in APPLY_REVISION_BINDINGS
            )
            if not satisfied:
                # Report the closest family so the message names something
                # actionable rather than every alternative at once.
                closest = max(
                    APPLY_REVISION_BINDINGS,
                    key=lambda family: sum(1 for item in family if item in guard),
                )
                missing = [item for item in closest if item not in guard]
                violations.append(
                    f"{label}: {FRESH_HEAD_STEP!r} must bind PR attribution to "
                    "unchanged executable and desired inputs; no recognized "
                    "implementation is complete (closest is missing "
                    f"{', '.join(repr(item) for item in missing)})"
                )

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
        if f"secrets.{secret}" in text:
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
    return violations


def rust_toolchain_violations(workflow: str, text: str) -> list[str]:
    """Every `dtolnay/rust-toolchain` step must select the exact toolchain.

    Checking that `toolchain: 1.98.0` appears *somewhere* in the file let a
    second Rust step — or a copied step that lost its `with:` block — install
    the action's floating default while the first step's pin kept the workflow
    green. Match per step instead.
    """
    for step in STEP_SPLIT.split(text):
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
    if policy_step(job, "Install cargo-audit") != [
        "name: Install cargo-audit",
        f"        uses: {CARGO_AUDIT_ACTION}",
        "        with:",
        "          tool: cargo-audit@0.22.1",
        "          checksum: true",
        "          fallback: none",
    ]:
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


def trusted_cargo_audit_policy_violations(text: str) -> list[str]:
    """The dependency gate must run `main`'s checker against `main`'s exceptions.

    Under `on: pull_request` this workflow file is itself supplied by the pull
    request's head, so without this assertion one commit could add a
    cargo-audit exception *and* delete the trusted checkout that stops the
    exception from counting — and the gate would report success. The trusted
    supply-chain runner reads the candidate's copy of `security.yml`, which is
    the only place an assertion about it can be enforced.

    Push and schedule runs keep executing the tree's own checker: there is no
    untrusted author there, and pinning them to the default branch would stop
    a merged policy change from ever taking effect.
    """
    violations: list[str] = []

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
        violations.extend(
            whole_secrets_context_violations(str(workflow.relative_to(root)), text)
        )
        violations.extend(
            admin_jwt_binding_violations(str(workflow.relative_to(root)), text)
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
            or BUNDLE_SECRET_BINDING in text
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

    violations.extend(
        monitoring_workflow_violations(
            (workflows / MONITORING_WORKFLOW).read_text(encoding="utf-8")
        )
    )

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
        if ADMIN_JWT_SECRET_BINDING not in text:
            violations.append(
                f"{admin_api_workflow}: an admin-API workflow must bind "
                f"{ADMIN_JWT_SECRET_BINDING!r} from the selected GitHub Environment"
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
        if SETTINGS_AUDIT_TOKEN_REFERENCE in workflow.read_text(encoding="utf-8"):
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
    violations.extend(trusted_cargo_audit_policy_violations(security_workflow))
    violations.extend(cargo_audit_install_violations(security_workflow))
    violations.extend(security_push_trigger_violations(security_workflow))
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

    toolchain = (root / "rust-toolchain.toml").read_text(encoding="utf-8")
    if 'channel = "1.98.0"' not in toolchain:
        violations.append("rust-toolchain.toml: channel must be pinned to 1.98.0")

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
            "rust_toolchain": "1.98.0",
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
