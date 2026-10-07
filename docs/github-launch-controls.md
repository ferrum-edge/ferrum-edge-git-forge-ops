# GitHub launch controls

Workflow files enforce what they can inside the repository. Branch rulesets,
environment reviewers and the repository's Actions policy live in GitHub
settings, and merging a pull request cannot turn them on. Configure this
baseline before you connect production credentials.

This document is the specification for that baseline.
`.github/scripts/bootstrap_repo_settings.py` applies sections 1-5 through the
REST API, and `.github/scripts/audit_settings.py` re-checks them on a schedule.
The bootstrap script imports its constants from the audit script, so the writer
and the auditor cannot drift apart. Read this document to understand what each
control buys, or to configure it by hand.

The script is idempotent. Without `--apply` it only prints the plan:

```bash
export GH_TOKEN=$(gh auth token)            # an account with admin on the repo
python3 .github/scripts/bootstrap_repo_settings.py --repo owner/repo           # plan
python3 .github/scripts/bootstrap_repo_settings.py --repo owner/repo --apply   # write
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--state-writer-app-id ID` | Makes the §1 App the `main` ruleset's only bypass and sets `GITFORGEOPS_STATE_APP_ID`. Without it the bypass is the Repository Admin role in pull-request mode, which the settings audit rejects. |
| `--release-tag-bypass SPEC` | Who may push a `v*` tag: `app:<id>`, `user:<login>` or `team:<org/slug>`. The default, `admin`, is a repository role, which the audit rejects. |
| `--environment NAME` | Environment to protect (repeatable). Default: the environments in `.gitforgeops/config.yaml`. |
| `--reviewer LOGIN`, `--reviewer-team org/slug` | Required deployment reviewers (repeatable). |
| `--template-repo` | Template mode; see below. |

The script never accepts or prints a secret value. It finishes by listing the
`gh secret set` commands you still need to run.

For the order of operations, follow the [quickstart](quickstart.md). It takes
one gateway, one namespace and one environment from an empty template to a
first apply, and links back here for the rest.

## Template repositories

The upstream repository is the template customers copy. A template has no
deployment environment and no state-writer App, because nothing on it applies
to a gateway or commits an ownership ledger.

Set repository variable `GITFORGEOPS_TEMPLATE_REPO=true` there (or pass
`--template-repo` to the bootstrap script, which sets it). `settings-audit.yml`
then runs the audit with `--template-repo`, which drops exactly two checks and
names both in its evidence output:

- the state-writer App bypass on the default-branch ruleset (§1);
- the "at least one protected environment" requirement (§3).

Everything else stays enforced, including every environment that *is* listed.
A deployment repository must leave the variable unset. The bootstrap script
sets it back to `false` if it finds it set there.

## 0. Do this before you merge

Sections 1-5 are prerequisites, not follow-ups. Two workflows fail closed and
stay red on `main` until the settings behind them exist:

| Workflow | Red until | Section |
| --- | --- | --- |
| `Release` | the `main` ruleset declares required checks. Until then `gh pr checks --required` exits non-zero with "no required checks reported", so every push to `main` fails the publication gate. | [§2](#2-protect-main-with-an-active-ruleset) |
| `GitHub Settings Audit` | the `settings-audit` environment exists and holds `SETTINGS_AUDIT_TOKEN`, repository variable `GITFORGEOPS_STATE_APP_ID` is set (or `GITFORGEOPS_TEMPLATE_REPO=true` on a template), and the `main` ruleset binds `state-guard-reject-state-edits` (and, once required, `trusted-supply-chain-policy`) to the GitHub Actions app | [§1](#1-create-the-state-writer-github-app), [§2](#switching-the-supply-chain-policy-check), [§5](#5-enable-settings-drift-monitoring) |

Neither workflow may assume a control it cannot verify. Configure §1-§5 first
and neither goes red.

Two workflows stay quiet on an unconfigured repository, because nothing has
asked them to do anything yet:

- `GitForgeOps Apply` runs on every qualifying push to `main`. Without
  `.gitforgeops/config.yaml` it emits an empty environment matrix and a
  `::notice::`, and binds no GitHub Environment.
- `GitForgeOps Trusted PR Live Review` resolves no live-review targets and
  skips its Environment-bound job.

Workflows an operator starts on purpose (`rotate`, `materialize-file`) and the
scheduled `drift-check` fail loudly when the configuration is missing.

## 1. Create the state-writer GitHub App

`apply-on-merge.yml` and `rotate.yml` commit `.state/<env>.json` after a
gateway mutation. A protected `main` rejects a direct push by
`github-actions[bot]`, so the workflows mint a short-lived installation token
for a dedicated App instead.

The guard has no concurrency group, so every delivery runs to completion and
cannot cancel another delivery. A manual cancellation or runner failure can
still interrupt a run. This avoids the same-head cancellation seen on #407,
where branch protection read the newest check suite. The guard is also safe if
protection requires every suite's latest run to pass: each run is bound to its
delivered head, and an authorized run re-reads the head, base and label just
before reporting success. `check_supply_chain.py` enforces the
`pull_request_target` trigger, a single default-branch checkout with no PR
checkout, the absence of a concurrency declaration, and the final override
revalidation.

Create and install a GitHub App with:

- repository access limited to this repository;
- **Contents: read and write** as its only write permission;
- no webhook subscription unless your organization needs one for other reasons.

Add the App as the only always-on bypass actor in the `main` ruleset (§2). Then
record its identity in exactly two places:

- Repository **variable** `GITFORGEOPS_STATE_APP_ID`: the numeric App ID. It is
  public metadata, not a credential. `apply-on-merge.yml` and `rotate.yml` use
  it to mint the token, and the settings audit checks that the ruleset's bypass
  actor is this App. `check_supply_chain.py` rejects
  `secrets.GITFORGEOPS_STATE_APP_ID`.
- Environment **secret** `GITFORGEOPS_STATE_APP_PRIVATE_KEY`, in every
  deployment environment. This one is a credential.

`apply-on-merge.yml` and `rotate.yml` check that both exist *before* they touch
the gateway, so a missing App cannot let an apply land unrecorded. The token
itself is minted late, just before the ledger commit, by the commit-pinned
`actions/create-github-app-token` action, which revokes it when the job ends.

Do not substitute a maintainer PAT or an administrator-role bypass. That gives
the state path the authority of a human account, and the settings audit
rejects it.

### Protecting the ledger path

The required `state-guard-reject-state-edits` check protects the path `.state`
and everything under it, including old and new rename paths, whatever the file
type. A PR may change it only after a fresh `gitforgeops/state-override`
`labeled` event for the current head, by an actor with current write, maintain
or admin permission. The same authorization is required when the file list
cannot be fully enumerated. Keep both `/.state` and `/.state/` in CODEOWNERS;
the trusted static-validation classifier must cover both as well.

At runtime, `.state` must be a real directory and state and lock entries must
be regular files. Symlinks and intermediate environment paths are refused, even
with a state override. A missing state file is fine for a first apply. Run from
an isolated trusted checkout: these metadata checks cannot stop a concurrent
local process from swapping entries while they are in use.

## 2. Protect `main` with an active ruleset

Create one active branch ruleset that targets exactly the default branch, with
no other include or exclude patterns. It must:

- require pull requests, with zero required approvals and no Code Owner,
  last-push or unattributed-change approval requirement;
- require all review conversations to be resolved;
- dismiss stale approvals when new commits are pushed;
- require branches to be up to date with `main` before merging;
- block deletion and non-fast-forward updates;
- reject `[skip ci]` in commit messages (a `commit_message_pattern` rule with
  `negate: true`). That marker suppresses every workflow, required checks
  included; `release.yml` uses `paths-ignore` for ledger commits instead;
- require at least these GitHub Actions job names. Ruleset contexts use the job
  name, not the `Workflow / job` label shown on a PR:
  - `rust-ci-check`
  - `security-cargo-audit`
  - `security-supply-chain-policy`
  - `trusted-supply-chain-policy` (being added; see
    [Switching the supply-chain policy check](#switching-the-supply-chain-policy-check))
  - `state-guard-reject-state-edits`
  - `gitforgeops-required-static-validation`
- have exactly one bypass actor in any mode: the state-writer App, as an
  always-on bypass. Pull-request-only human or team bypasses are not allowed.

Review happens outside the ruleset. Whoever merges reviews every changed file
at the exact head being merged, confirms hosted CI passed, and resolves every
actionable thread. `.github/CODEOWNERS` routes reviews; it is not an approval
gate. The bootstrap script and settings audit both keep the approval count at
zero, so a later settings refresh does not bring the requirement back. No
administrator bypass is needed to merge.

Protect release tags (`v*`) with a tag ruleset that has the `creation`,
`update` and `deletion` rules and **at least one** bypass actor. Each bypass
must be an explicit App, team or user in always-on mode, never a broad
repository role. Release publishing goes through that bypass list: with the
`creation` rule and no bypass actor, nobody can push a `v*` tag. The audit
therefore treats an empty bypass list as a misconfiguration.

The release workflow also checks that a tag's commit is reachable from the
protected default branch. Tag protection stops a branch-controlled workflow
from removing that check before secrets are used.

### Switching the supply-chain policy check

The supply-chain verdict is moving from `security-supply-chain-policy` (in
`security.yml`, whose definition the pull request under review supplies) to
`trusted-supply-chain-policy` (in `supply-chain-policy.yml`, which
`pull_request_target` always loads from the protected branch; see
[section 4](#4-restrict-github-actions)). It lands in three steps:

1. **Expand (merged).** `supply-chain-policy.yml` is on `main`.
   `bootstrap_repo_settings.py` writes both contexts. `audit_settings.py`
   still requires `security-supply-chain-policy` and reports a missing
   `trusted-supply-chain-policy` as a `WARN`, not a failure. It does fail
   while `state-guard-reject-state-edits` is not bound to the GitHub Actions
   app. The release gate requires a reported `trusted-supply-chain-policy`
   result to pass.
2. **Ruleset switch (operator).** Add `trusted-supply-chain-policy` to the
   `main` ruleset and bind the required contexts to GitHub Actions, as
   described below.
3. **Retire (a later pull request).** The workflow-script unit tests move out
   of `security-supply-chain-policy`, the candidate-run policy runner is
   removed, and the audit, bootstrap and release gate require only the new
   context. That pull request says when to remove the old context from the
   ruleset.

Take step 2 after step 1 has merged, as an administrator:

1. Confirm `.github/workflows/supply-chain-policy.yml` is on `main`. A new
   `pull_request_target` workflow does not run on the pull request that adds
   it, because GitHub loads it from the base branch.
2. Open a pull request from a branch created from `main` **after** that merge
   (a branch from before it lacks the workflow file, so the check fails).
   Confirm that `GitForgeOps Supply-Chain Policy / trusted-supply-chain-policy`
   appears and passes.
3. Add the context **without removing `security-supply-chain-policy`**. That
   job still runs the workflow-script unit tests until the retire step. Bind it
   to the GitHub Actions app: a required context with no source accepts a
   commit status of that name from anyone with write access, posted with their
   own token. Either:
   - from an up-to-date checkout of `main`, re-run the bootstrap with the same
     flags you used before (it rewrites the whole `main` ruleset). It writes
     every required context bound to GitHub Actions (`integration_id` 15368).
     Check that the plan's only `main ruleset` change is to
     `rules.required_status_checks.required_status_checks`: it adds
     `trusted-supply-chain-policy (app 15368)` and moves any existing
     `(any source)` context to `(app 15368)`. Then apply:

     ```bash
     python3 .github/scripts/bootstrap_repo_settings.py --repo owner/repo \
       --state-writer-app-id ID            # plan; add your other flags
     python3 .github/scripts/bootstrap_repo_settings.py --repo owner/repo \
       --state-writer-app-id ID --apply    # write
     ```

   - or, by hand: **Settings → Rules → Rulesets → main → Require status checks
     to pass → Add checks**, enter `trusted-supply-chain-policy`, choose GitHub
     Actions as the source, and save. Set GitHub Actions as the source of the
     other required checks as well.
4. Confirm the ruleset lists both contexts, each with integration 15368:

   ```bash
   gh api repos/owner/repo/rulesets --jq '.[] | select(.target == "branch") | .id' |
     xargs -I{} gh api repos/owner/repo/rulesets/{} \
       --jq '.rules[] | select(.type == "required_status_checks")
             | .parameters.required_status_checks[] | "\(.context) \(.integration_id)"'
   ```

   Then dispatch `GitHub Settings Audit` from `main`. The
   `trusted-supply-chain-policy` warning must be gone. The audit fails if
   `trusted-supply-chain-policy` or `state-guard-reject-state-edits` is
   required from any source other than GitHub Actions, and warns for each
   other context that is not yet bound. The scheduled audit therefore goes
   red as soon as step 1 merges, until this step binds
   `state-guard-reject-state-edits`.
5. Pull requests whose branch predates the merge do not carry
   `supply-chain-policy.yml`, so the new check **fails** on them ("must remain
   a regular file"). Re-running it does not help: update the branch from
   `main`. Pull requests branched after the merge report the check on their
   next `opened`, `synchronize`, `reopened` or `edited` event.

## 3. Protect every deployment environment

**Check your plan first.** On a private repository, GitHub Environments and
their secrets need Pro, Team or Enterprise, and the required reviewer this
section sets needs Enterprise (Free, Pro and Team offer required reviewers on
public repositories only). The bootstrap script warns when the repository is
private, reports an environment GitHub refuses as `FAILED`, and exits non-zero.
The §5 audit then reports each environment without a reviewer. See
[GitHub plan requirements](../README.md#github-plan-requirements) for the
public-versus-private trade-off.

Before enabling any environment-bound workflow, copy
`.gitforgeops/config.example.yaml` to `.gitforgeops/config.yaml`, replace the
examples with your real deployment environments, and commit it. Without it no
privileged workflow binds an environment, but they get there in two ways:

- `apply-on-merge.yml` **skips**: the matrix is empty, so the `apply` job never
  starts.
- `trusted-pr-review.yml` **skips**: it resolves no live-review targets.
- `rotate.yml`, `materialize-file.yml` and `drift-check.yml` **fail** in a
  preflight job that runs before the Environment-bound job.

The synthetic local `default` environment is never eligible for trusted live
review.

**Delete every GitHub Environment that `.gitforgeops/config.yaml` does not
declare**, including the `default` environment GitHub creates on some
repositories. Two exceptions: `settings-audit` (§5) and any `<env>-monitor`
environment created for unattended drift monitoring (§3.1). The settings audit
lists every environment through `GET /repos/{repo}/environments` and holds each
one to the rules below, so one forgotten unprotected environment keeps the
audit red. An unused environment is also a place to store credentials that no
workflow guard covers.

`settings-audit` is exempt from the reviewer and self-review rules only,
because it deploys nothing. A reviewer there would park every scheduled audit
in "waiting for approval". Its branch policy *is* audited, and it does not
count as a protected environment.

For every environment in `.gitforgeops/config.yaml` (the bootstrap script
creates each one when given `--reviewer` or `--reviewer-team`):

- require at least one reviewer;
- prevent self-review;
- disallow administrator bypass, where the plan exposes that setting;
- restrict deployment branches to protected branches, or to an exact custom
  policy for `main`;
- keep gateway, TLS, credential-broker and state-App secrets only in that
  environment;
- set its `FERRUM_GATEWAY_URL` secret to an **`https://`** URL.

These rules protect `apply`, `rotate`, `materialize`, drift checks and trusted
PR live review. The manual workflows also check
`github.ref == refs/heads/main`, but the environment branch policy is the
boundary that cannot be bypassed: a workflow file on an unprotected branch
could simply delete an in-file condition.

**Credential bundles are bound by name.** No workflow reads the whole `secrets`
context. `${{ toJSON(secrets) }}` would also hand the bundle loader the admin
JWT signing key and the state-writer App private key, and GitHub holds
public-repository runs that read it for manual approval. Instead the
`Load credential bundles` step of `apply-on-merge.yml`, `materialize-file.yml`
and `rotate.yml` binds `FERRUM_CREDS_BUNDLE` through `FERRUM_CREDS_BUNDLE_15`.
That caps an environment at `MAX_BUNDLE_SHARDS` = 16 shards (about 7,000
credential slots). A shard beyond that would be written but never read back, so
`apply` and `rotate` refuse to create one. To raise the cap, change
`MAX_BUNDLE_SHARDS` in both `src/secrets/bundle.rs` and
`.github/scripts/credential_bundles.py`, and extend those bindings;
`check_supply_chain.py` fails the build if they disagree.

### 3.1 Unattended drift monitoring

`drift-check.yml` runs nightly and reads the gateway with
`gitforgeops diff --exit-on-drift`. Bound to a deployment environment, it
inherits that environment's required reviewer, and
[GitHub withholds an approval-gated environment's secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#environment-secrets)
until a human approves the job. So the nightly run waits for approval and
inspects nothing.

That is the approval boundary working as configured. To monitor without a
human, an environment can opt into a second, reviewer-free environment that
holds gateway read material only:

```yaml
environments:
  production:
    overlay: production
    ownership:
      mode: shared
    monitoring:
      unattended: true      # -> binds the `production-monitor` environment
```

`gitforgeops envs --format json --include-scopes` then reports
`monitoring_environment: production-monitor`, and the drift job binds that.
Without the opt-in, monitoring stays on the deployment environment and the
check reports `Not completed` with the reason, never anything like "in sync".

The bootstrap script creates each `<env>-monitor` with no reviewer and a custom
deployment policy that matches only the exact default branch. That policy is
what stops a workflow dispatched from another protected ref from receiving the
signing secret. The script also prints the `gh secret set` commands for the
read material a comparison needs.

**What a monitoring environment may hold.** Three independent fences apply,
because no human stands in front of it:

- `audit_settings.py` waives the reviewer rule only for `<env>-monitor` where
  `<env>` is itself a listed environment, and only while it holds none of
  `GITFORGEOPS_STATE_APP_PRIVATE_KEY`, `FERRUM_GH_PROVISIONER_TOKEN`,
  `SETTINGS_AUDIT_TOKEN`, `FERRUM_ADMIN_JWT_SECRET` or `FERRUM_CREDS_BUNDLE[_N]`.
  It requires the viewer key name `FERRUM_ADMIN_JWT_VIEWER_SECRET`, checks secret
  **names** only and never requests a value.
- `repo_config.rs` refuses a deployment environment name that ends in the
  reserved suffix.
- `check_supply_chain.py` refuses a `drift-check.yml` that binds any of those
  secrets, holds a write permission, or runs any `gitforgeops` subcommand
  other than `diff`.

The credential bundle is deliberately left out. `diff` excludes unresolved
broker leaves from the live comparison one leaf at a time, so the rest of the
document is still compared in full.

**The bundled check uses the viewer key.** `drift-check.yml` reads
`GET /config/export` with `FERRUM_ADMIN_JWT_VIEWER_SECRET`. Ferrum Edge v0.9.9+
caps tokens signed with that key at `viewer` whatever they claim. The checker
requires the exact step-local viewer binding and issuer/audience/TTL settings,
and rejects the admin key in monitoring. Only this workflow may bind the viewer
key; `plan`, `review`, `apply` and `rotate` need the admin credential.

Unless the gateway also sets `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`, the viewer
key reads every namespace. Repository namespace scopes and gateway viewer
namespace restrictions still apply. The workflow does not pass
`--accept-unverified-secrets` and does not automatically store fingerprint
baselines. A comparison with no drift but unverified secrets exits `6` and is
reported as `In sync, secrets unverified`: a warning, never "in sync", and not
a failure. Explicit CLI acceptance retains its documented limits.

**Human deployment step (#440).** Before deploying the viewer-only workflow,
a repository administrator must provision the gateway's distinct viewer key as
`FERRUM_ADMIN_JWT_VIEWER_SECRET` in every API environment selected by
`matrix.scope.monitoring_environment`: `<env>-monitor` when
`monitoring.unattended` is true, otherwise the deployment environment itself.
Use GitHub **Settings → Environments → selected environment → Environment
secrets**. After the workflow switch, remove `FERRUM_ADMIN_JWT_SECRET` from each
`<env>-monitor`; deployment environments retain it for apply, trusted review and
rotate. The audit now refuses the admin name in monitoring and requires the
viewer name. This is a manual secret-entry operation, never a script that reads,
prints or copies secret values. See [Scheduled monitoring](reference.md#scheduled-monitoring).

### 3.2 Monitoring outcomes

The scheduled check reports six outcomes. Only `In sync` says a gateway was
compared and matched:

| Outcome | Meaning |
| --- | --- |
| `In sync` | the gateway was read and matches the repository |
| `In sync, secrets unverified` | `diff` exit `6`: no drift in an alerted category, but fingerprinted secrets were not verified because the viewer credential cannot compute their fingerprints; a warning, not a failure |
| `Drift detected` | the gateway was read and differs |
| `Check failed` | authentication, connectivity, a cached (non-authoritative) export, a whole value fingerprinted around a secret, or a configuration error — **nothing is known about the gateway** |
| `Skipped (file mode)` | no live Admin API to compare against; a configured absence, not a gap |
| `Not completed` | the comparison never ran: approval pending, cancelled, or the runner was lost |

`drift_report.py` classifies each result and writes the table to the job
summary. `Drift detected`, `Check failed` and `Not completed` fail the
workflow; `Skipped` and `In sync, secrets unverified` do not. The latter is
listed as a warning in the summary and emitted as a `::warning::` annotation, so
a successful run with it still counts as monitoring evidence for the settings
audit, while drift in an alerted category
still fails the run. A matrix entry that produced no record is shown as
`Not completed`, so an environment waiting for approval still appears in the
table.

### The gateway URL must be `https://`

Every environment-bound workflow sends an admin JWT in an `Authorization`
header, and `apply` sends resolved consumer credentials in the request body.
Over cleartext, anything on the path can read both. gitforgeops therefore
refuses a non-`https://` `FERRUM_GATEWAY_URL` at startup, before any HTTP
client exists. Other schemes (`ftp://`, `file://`, `ws://`) and URLs with
embedded `user:password@` credentials are always refused.

Two development-only switches exist. **Both are refused under `GITHUB_ACTIONS`
unless the gateway host is loopback** (`localhost`, `127.0.0.0/8`, `::1`):

- `FERRUM_ALLOW_INSECURE_HTTP=true` allows a cleartext `http://` gateway.
- `FERRUM_TLS_NO_VERIFY=true` keeps TLS but accepts any certificate, so an
  interceptor looks the same as the gateway.

Neither belongs in a GitHub Environment. If a gateway uses a private CA, put
that CA in the environment's `FERRUM_GATEWAY_CA_CERT` secret (base64 PEM)
instead; gitforgeops then trusts that CA only. Both switches print a loud
stderr warning when they take effect, so seeing one in a job log means it
reached CI and should be removed.

### Scheduling and supersession are one list

`apply-on-merge.yml` runs only for pushes that match its `paths:` filter. Its
freshness guard refuses to reconcile a newer protected head that changed a
deployment input since the triggering merge. Both use the same list,
`DEPLOYMENT_INPUT_PATHS` in
[`.github/scripts/deployment_scope.py`](../.github/scripts/deployment_scope.py),
and `check_supply_chain.py` fails the build if they drift apart.

The workflow runs that classifier from the triggering commit, not from the
newer checkout it is judging, so a newer helper change cannot approve itself
under the waiting run's older approval. The trusted copy is piped from
`git show` into `python3 -I -` under `set -euo pipefail`, never written to a
file:

- there is no destination a later line could redirect (to `/dev/null`, say,
  which Python would run as an empty program that approves everything);
- a failed extraction fails the step;
- `-I` keeps a head-supplied module such as `argparse.py` off the import path.

`check_supply_chain.py` accepts only that exact form.

`rotate.yml` runs the same guard with the same classifier. Rotation waits on
the same `ferrum-apply-<env>` lock and then builds and runs the refreshed head
with the gateway, broker and state-writer credentials, so its environment
approval must also cover only the revision it was dispatched from. It is not
held to strict equality: apply's own ledger commit moves the branch while a
rotation waits, and the classifier treats that output as inert. A rotation
refused this way is not rescheduled; dispatch it again from the current head.

Using one list means an approval-gated deployment is not cancelled by accident.
While a merge waits for its reviewer, other merges land on `main`:

- A merge that changes a deployment input (resources, overlays,
  `.gitforgeops/`, engine source, helper scripts, the validator pin, or this
  workflow) **supersedes** the waiting run. It also schedules its own apply,
  which reconciles everything queued before it.
- A merge that changes nothing else (documentation, tests, an unrelated
  workflow) leaves the waiting run alone. It schedules no replacement, so it
  may cancel nothing.

`.state/**` and `assembled/**` are in neither list. The apply writes them, so
they must not reject a queued run or re-trigger the workflow.

To recover a run that was already superseded, see
[Recovering a superseded apply](../README.md#recovering-a-superseded-apply).

## 4. Restrict GitHub Actions

In **Settings → Actions → General**:

- set default workflow permissions to **Read repository contents**;
- disable **Allow GitHub Actions to create and approve pull requests**;
- allow GitHub-owned actions, leave "verified creators" off, and set the
  third-party patterns to exactly:
  - `aquasecurity/setup-trivy@*`
  - `aquasecurity/trivy-action@*`
  - `docker/build-push-action@*`
  - `docker/login-action@*`
  - `docker/metadata-action@*`
  - `docker/setup-buildx-action@*`
  - `docker/setup-qemu-action@*`
  - `dtolnay/rust-toolchain@*`
  - `taiki-e/install-action@*`
- enable **Require actions to be pinned to a full-length commit SHA**.

The patterns end in `@*` only because the settings API allowlist works per
repository. Every actual `uses:` reference must still carry a full 40-hex
commit SHA.

`.github/scripts/check_supply_chain.py` backs this up in CI. It fails on
tag-based action references, floating runner images, unpinned container bases,
missing Rust version pins and disabled release attestations. It also rejects
any workflow expression that reaches the whole `secrets` context
(`toJSON(secrets)`, a bare `${{ secrets }}`, `secrets: inherit`); the
credential broker only ever needs the `FERRUM_CREDS_BUNDLE[_N]` shards, bound
by name.

The `security-supply-chain-policy` check runs the **protected branch's** copy
of the checker against the candidate tree, under `python3 -I` so that no module
in the candidate checkout can load before the trusted policy. A pull request
therefore cannot weaken the policy by editing the checker: its edits take
effect only after merge. The protected base judges each candidate, and a
checker change takes effect only after it merges. Use a checker-first,
binding-second sequence: land the checker change under the currently trusted
policy, then submit the workflow binding change after the new checker is on
`main`. Prefer expand/contract pairs (accept both shapes, migrate, then reject
the old one). If the checker-first change cannot pass the trusted check, park
it until a policy-compatible sequence is available; do not merge past a red
required check. The next run on `main` uses the new policy.

The workflow binding rules read workflow text, never what a command
computes. They pin the guarded steps exactly: the Verify traffic script and the
credential-file hand-off in each `Load credential bundles` step must match
their pinned lines (comment lines are ignored unless they hold an expression).
Outside that hand-off, every workflow is banned from spelling `GITHUB_ENV`,
`GITHUB_PATH`, `GITHUB_STATE` or `BASH_ENV`, the runner's file-command file
names (`set_env_`, `add_path_`, `save_state_`, `_runner_file_commands`), the
`github.env`/`github.path` contexts, indirect expansion (`${!name}`), or a
redirect or `tee` into any GitHub file channel other than `GITHUB_OUTPUT` and
`GITHUB_STEP_SUMMARY`. Those two may appear only as a plain `>>` or `tee -a`
target (and the summary as a `--summary` argument), never inside a parameter
expansion or `dirname` that could derive another file-command path. Quotes,
backslashes and line continuations are removed before matching, never
decoded, and shell comments count: `GITH\UB_ENV` reads as `GITHUB_ENV`, as
Bash reads it outside quotes. Bash ANSI-C quoting (`$'...'`) is not supported
in any workflow or the local actions it runs: it spells a name by character
code (`$'GITHUB_\x45NV'`, `$'\x67'itforgeops`), and judging it would need a
quote-state lexer, so any scalar holding `$'` is refused, even in a comment or
as a plain quoted `$`. A name Bash computes by expansion is still program
behavior (below). A `run:` interpolation may not adjoin a name character, with
quotes removed. Every `run:` interpolation must be allowlisted (below); the
Environment-bound workflows may interpolate only a per-job allowlist. Each of
those per-job values is pinned to its producer: the job outputs and matrices
that carry it must be exactly the reviewed expressions, the environment enumerator
step is pinned whole (including its safe-name `jq` guard), and trusted review's
metadata step must check the event head SHA as 40 hex digits first, never
reassign it, take the trusted SHA from `git rev-parse`, and write each SHA
output only through its pinned `echo`. Apply's hand-off keeps
`id: load-bundles`, only the `Load credential bundles` step in each job may
carry that id (compared without regard to case, like every producer id), and
Apply and Verify traffic read the finalized bundle path only from that step's
output. An `env:` mapping at any level may not bind, in any case, `ENV`,
`BASH_ENV`, `BASH_FUNC_*`, `SHELLOPTS`, `BASHOPTS`, `PS4` or any `LD_*` loader
variable (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, ...), each of which
changes what a later step's shell or loader runs before its script. A job
container or service container may not set `options:`, a `docker create`
command line whose `-e`, `--env` or `--env-file` would bind the same variables
for every step of the job, and may not be computed. Its image must be pinned by
digest (`@sha256:<64 hex>`), because an image's own `ENV` reaches every step
the same way. In `apply-on-merge.yml`, every scalar outside the guarded Apply
steps is read for the binary, not only `run:`: a step's or a default's
`shell:` and an action input count, a `run:` line may name it only as a pinned
`envs`, `validate` or `verify` line, and any other scalar only as a pinned
display name. A display name is the `name:` of
the workflow (or local action), a job or a step; an action input or env value
called `name` is not one.

GitHub renders a `run:` interpolation before the shell parses the script, so
its value becomes shell source that no text rule reads. Env, matrix, input,
job- and step-output and event values can all carry text computed or chosen
elsewhere: `env.A` set by `fromJSON(...)` or `format(...)`, a matrix entry, a
job output, a `with:` input, a pull request title or branch name. So in every
workflow, and every local action a workflow runs, a `run:` interpolation must
be exactly one of a short allowlist of values GitHub or the runner sets from a
closed alphabet: `github.event_name`, `github.sha`, `github.run_id`,
`github.run_attempt`, `runner.os` and `runner.arch`, spelled exactly so. The
Environment-bound workflows allow only their per-job pinned values instead, and
their local actions allow none. Everything else is refused, including `env.*`,
`matrix.*`, `inputs.*`, `vars.*`, `secrets.*`, `steps.*.outputs.*`,
`needs.*.outputs.*`, `github.event.*`, `github.head_ref`, `github.ref_name`,
and any function call, literal or operator. Quotes around the interpolation
change nothing, and one in a shell comment counts. Every key named `run` is
read wherever it sits, so a composite action's `runs.steps` count. Pass any
other value through step `env:` and read it in the script as a quoted
variable:

```yaml
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "$TITLE"
```

The shell is held to the same rule. A step's `shell:`, and the
`defaults.run.shell` a workflow or job gives its steps, names the command each
script runs with, so a rendered value there picks an interpreter no text rule
read. No `shell:` value may hold an expression, in any workflow or local
action (an action input named `shell` included), and `defaults:` and its
`run:` must be mappings, never computed values.

A local action (`uses: ./...`) carries no commit pin, so the checker reads what
it runs. Every local reference must name, by a plain path, a composite action
under `.github/actions/` with exactly one `action.yml` or `action.yaml`, reached
through no symbolic link and written in the same YAML subset as workflows.
Anything else is refused: another action type, a path into another checkout, a
missing or unparsable file, and a local reusable workflow
(`jobs.<id>.uses: ./...`), which would carry none of its caller's pins. Each
local action a workflow reaches, directly or through another local action, is
judged by that workflow's fences: the env-file channel and startup-key bans,
its protected names, the `run:` interpolation allowlist above (no
interpolation at all when the workflow is Environment-bound), and in
`apply-on-merge.yml` the binary pin above. Every
action file under `.github/actions/`, reached or not, must be in that subset,
and its remote `uses:` are pinned to 40-hex commits from the parsed file, in
any key case.

A local action is judged as the tree carries it, but the runner reads it from
the workspace when its step runs. So no job may run a local action after an
`actions/checkout` step that checks another revision out over the workspace
root: a `ref` other than `${{ github.event.repository.default_branch }}`
(judged when it merged) or a `repository` other than `${{ github.repository }}`,
with no `path` or one that is not a plain subdirectory (`.`, `.github`, `..`,
an absolute or computed path). A local action may not make such a checkout at
all, since a later local action would run from it. Check another revision out
into a subdirectory instead. A `git checkout` in a `run:` script is program
behavior, outside these rules.

`.github/actions/**` is a deployment input (it schedules and supersedes
`apply-on-merge.yml` like `.github/scripts/**`), a `security.yml` push path and
code-owned in `CODEOWNERS`; the checker requires all three.

Program-level writes are out of scope. A program a step invokes (the binary, a
helper script, or Bash evaluating computed text such as `base64 -d | bash` or
`eval "$text"`) can still write `$GITHUB_ENV` or rebind a variable, and no text
rule can prove otherwise. That includes a file-command path the step discovers
rather than derives from a spelled name: a glob over the runner's temp directory
(`"$RUNNER_TEMP"/*/set_e*`), `/proc/$$/fd`, or the environment read back through
`env | sed`. Review of every workflow change is the control for that.

These text rules can refuse legitimate workflow text: a redirect or `tee` into
`$GITHUB_WORKSPACE/...`, any name containing `GITHUB_ENV`, `GITHUB_PATH` or a
file-command prefix (`GITHUB_ENVIRONMENT`, say), an interpolation glued to a
name (`v${{ matrix.version }}`), any `run:` interpolation outside the
allowlist (`echo "${{ matrix.os }}"`), indexed or whole `github` context access
(`toJSON(github)`, `github.event.commits[0]`), a shell comment naming a
protected variable or channel, and Bash ANSI-C quoting (`$'`). For example,
`grep -cx $'.*: test$'` is refused; write it as `grep -cx '.*: test'` instead.
A plain single-quoted pattern ending in `$` is refused the same way, because
`$` meets the closing quote: `grep -c ': test$'` holds `$'`. Rephrase such
text, or pass the value through step `env:`.

Review and merge tighter guard logic into the protected branch first. If the
workflow binding form must change, do that in a subsequent pull request judged
by that trusted checker. New checker logic requires fresh exact-head review;
a green verdict from the previous protected checker does not validate it.

That is not a complete boundary on its own. The check runs under
`pull_request`, so GitHub executes the pull request's own copy of
`security.yml`. The trusted checker inspects that copy with substring rules,
and it is the job that copy defines which runs those rules. A pull request that
changes workflow definitions can therefore still influence what this check
reports.

`trusted-supply-chain-policy` (`supply-chain-policy.yml`) is the check whose
definition the pull request does not supply. It runs on `pull_request_target`,
so GitHub always loads the workflow from the protected default branch. It
checks out the protected branch into `base/` and the pull request's head into
`candidate/` as data, with no persisted credentials, and runs only
`python3 -I base/.github/scripts/check_supply_chain.py --root candidate`, with
a 10-minute timeout. The job holds `contents: read`, no secrets and no
environment, and nothing from the candidate executes. A pull request that
edits `supply-chain-policy.yml` is judged by the protected copy, and its edit
takes effect only after merge.

What the checker enforces for this check:

- **Shape.** Every non-comment line of `supply-chain-policy.yml` is pinned.
  The `actions/checkout` commit is the one free part, so Dependabot can bump
  it. Any 40-hex commit is accepted there, including one GitHub resolves
  through a fork of `actions/checkout`, so a change to that commit needs the
  same exact-head review as any other workflow change.
- **The tree it reads.** Before reading anything, it walks the whole candidate
  without following links. It follows each relative link target component by
  component from the link's directory, and refuses any symlink that is
  absolute, whose target passes through another symlink, whose target climbs
  above the tree root (even if it comes back in), that resolves outside the
  tree, or that does not resolve. It also refuses any device, FIFO or socket.
  With no link in between, a target's text names the path the kernel
  resolves, in every checkout layout. Because `base/` sits beside `candidate/`, a link into `base/`
  would show this check protected files while every other workflow, which
  runs the tree at the workspace root, executes the pull request's own copy.
  Links that stay inside the tree are allowed. A `--root` that is itself a
  link is refused.
- **Workflow syntax.** Every file in `.github/workflows/` must end in exactly
  `.yml` or `.yaml`; the rules find workflows by a case-sensitive glob, so a
  `.YML` or `.Yaml` file would skip all of them. Every workflow must be
  written in a small YAML subset, read by a strict standard-library reader
  before any rule runs. A file outside it fails the check on its own. The
  subset:
  - top-level keys at column 0, space indentation only, block mappings and
    block sequences, and plain `[A-Za-z0-9_-]+` keys, unique per mapping;
  - plain, single-quoted or double-quoted scalars on one line;
  - literal block scalars (`|`) only for `run`, `script`, `body`,
    `description`, `if`, `path`, `restore-keys`, `images` and `tags`, and
    folded ones (`>`, `>-`, `>+`) only for `if`. YAML keeps line breaks
    around blank and more-indented lines of a folded scalar, and the reader
    joins its lines with spaces, so a folded `run:` would show the rules one
    shell line where Bash runs several: a trailing `#` would hide the next
    command from the policy;
  - one-line flow sequences of scalars only for `branches`, `tags`, `paths`
    (and their `-ignore` forms), `types`, `needs` and `workflows`.

  Anchors, aliases, tags, explicit (`?`) keys, merge keys, quoted keys, flow
  mappings, directives, document markers after a leading `---`, tabs outside
  block scalars, a byte-order mark, control characters and Unicode line
  breaks are all refused. YAML spells one key many ways. The rules below read
  the parsed structure, so a spelling the reader does not accept cannot carry
  a meaning past it.
- **The check name.** No job may have a key or `name:` equal to a required
  context (in any case, ignoring surrounding whitespace) except the job keyed
  by that context in its own workflow: `trusted-supply-chain-policy` in
  `supply-chain-policy.yml`, `state-guard-reject-state-edits` in
  `state-guard.yml`, and likewise `rust-ci-check`, `security-cargo-audit`,
  `security-supply-chain-policy` and `gitforgeops-required-static-validation`
  (`REQUIRED_CHECK_WORKFLOWS`, kept equal to the bootstrap's
  `REQUIRED_STATUS_CHECKS` by a test). No job's `name:` may be computed with
  `${{ }}`. Mentioning a context in a script, a step title or an action input
  is fine, since none of those names a check run.

  This rule is defense in depth, not the boundary. How branch protection
  resolves two check runs with the same name from the same app (the newest
  wins, any failure blocks, or every run must pass) has not been verified. A
  follow-up issue will run that experiment in a sandbox repository and, if a
  duplicate can satisfy the rule, enforce the context by workflow path as
  well. The GitHub Actions app binding does not help here, since a
  candidate's own `pull_request` job also reports through that app; until
  then exact-head review of every workflow change carries the guarantee.
- **The cargo-audit gate.** `security-cargo-audit` is required but defined by
  the pull request's own `security.yml`, so substrings anywhere in that file
  prove nothing: the trusted command can sit in a comment under a `true`, or
  behind `exit 0` or `|| true`. The parsed job is pinned instead: its keys,
  every step in order, and the exact `run:` scripts that run the protected
  branch's cargo-audit checker, its tests and its exception list. Only the
  action commits and the Rust toolchain (pinned by their own rules) are free.
  A workflow-level `env:` or `defaults:` in `security.yml` is refused, since
  either reaches the job's shell without appearing in it. The pinned shape
  also fixes `runs-on: ubuntu-24.04`, and `security.yml`'s `on:` triggers are
  pinned to the reviewed events (the `pull_request` types and branch, the
  `push` branch and the `schedule`): a runner-image bump or an added trigger
  such as `workflow_dispatch` — which could post a second
  `security-cargo-audit` result from a candidate copy run outside
  `pull_request` — needs a checker PR first, the same two-PR pattern as the
  action pins.
- **Status forgery.** At every `permissions:` in every workflow, `checks` and
  `statuses` may only be `read` or `none`, and a string grant must be
  `read-all` (`write-all` grants both). With write access, a job could post
  a result under any context it computes at run time, which no static rule
  can see. The allow-list (`STATUS_WRITE_ALLOWED`) is empty.
- **Ruleset source.** The bootstrap binds every required context to the GitHub
  Actions app (`integration_id` 15368). The audit fails when
  `trusted-supply-chain-policy` or `state-guard-reject-state-edits` lacks
  that binding: both come from `pull_request_target` workflows a pull request
  cannot edit, so an own-token commit status is the remaining way to forge
  them. It warns for the other contexts, whose job definitions the pull
  request supplies anyway.

Until the `main` ruleset requires `trusted-supply-chain-policy`
([Switching the supply-chain policy check](#switching-the-supply-chain-policy-check)),
a green `security-supply-chain-policy` is trustworthy only together with
exact-head review of every change under `.github/workflows/`.

### The release gate

`release.yml`'s `authorize-release` job publishes only a commit that maps to
exactly one merged pull request whose launch-required checks passed on its
head, each bound to the GitHub Actions app: `rust-ci-check`,
`security-cargo-audit`, `security-supply-chain-policy`,
`state-guard-reject-state-edits` and `gitforgeops-required-static-validation`,
plus `trusted-supply-chain-policy` once it is reported or required. The job
checks out the release commit and runs `.github/scripts/release_gate.py` from
it (#473).

The gate's code comes from the release commit, which the checker judged on its
pull request. So the checker pins what a pull request must not be able to
weaken:

- **Invocation.** The gate step runs exactly
  `python3 -I .github/scripts/release_gate.py`, binds only `GH_TOKEN`, `REPO`,
  `RELEASE_SHA` and `DEFAULT_BRANCH`, keeps `timeout-minutes: 16`, and carries
  no `shell`, `working-directory`, `if` or `continue-on-error`. The workflow
  and job set no `env` or `defaults`. It is the job's second step, right after
  a plain `actions/checkout` of the release commit with only
  `persist-credentials: false`, and the helper must exist.
- **Launch lists, app and budget.** `REQUIRED_CHECKS`, `ACCEPTED_CHECKS`,
  `ACTIONS_APP_ID` and `BUDGET_SECONDS` are each assigned their pinned value
  once at module level, never rebound, and read.
- **Imports and references.** The helper imports only `json`, `os`, `re`,
  `subprocess`, `sys`, `time` and `urllib.parse`, plus
  `from __future__ import annotations` and `from typing import Callable`,
  unaliased. Each imported name is bound only by its import and used only as
  one listed reference: `json.JSONDecoder`, `os.environ`, `re.compile`,
  `subprocess.run`, `subprocess.TimeoutExpired`, `sys.stdout`, `sys.stderr`
  (and their `write`), `time.monotonic`, `time.sleep`, `urllib.parse.quote`
  and bare `Callable`. Nothing may follow a reference, so the helper cannot
  walk from an allowed module to another one, such as `re.enum.sys`.
- **Environment and commands.** `os.environ` is read only as
  `dict(os.environ)`. Each `subprocess.run` call passes exactly
  `env=self.subprocess_env`. The pin covers only that expression: today the
  helper sets it to `None` in production, so `gh` inherits the process
  environment unchanged, and tests that inject an environment pass its copy,
  but exact-head review, not the checker, keeps that value. Calls use a literal `gh api` or `gh pr checks`
  argument list and only `capture_output`, `check`, `env` and `timeout`. Any
  other `gh` subcommand, such as `alias` or `extension`, is refused.
- **Builtins and names.** No `eval`, `exec`, `open`, `getattr`, `help` or
  similar dynamic builtin, dunder name other than the exact `__name__` in the
  required main guard, dunder attribute, frame/generator/traceback attribute,
  or class pattern. No string literal names a `GITHUB_*` runner variable or
  env-file channel, even when built from several literals with `+`, an f-string
  or `"".join`. The file ends with the standard `main()` guard.

These pins catch drift in the lists, app id and budget, and selected forms of
accidental reach, including direct frame-related attribute access and dunder
names. They are drift detection, not a sandbox: names or values computed
indirectly may be invisible to them, and they do not prove the helper's control
flow. A rewritten helper could simply report success. Exact-head review of
every change to the helper is the control against a deliberate rewrite.
`.github/scripts/tests/test_release_gate.py` runs every release-gate scenario
against the helper with a stub `gh`.

The switch followed the checker-first rule above. The checker learned the
helper before `release.yml` ran it, so the pull request that moved the release
commit's checkout ahead of the gate step and replaced the inline script was
judged by a protected checker that already knew the helper.

### Repository security features

The bootstrap script also turns on **secret scanning**, **secret-scanning push
protection**, **private vulnerability reporting**, and Dependabot
**vulnerability alerts** and **automated security updates**. The scheduled
audit does not read these back. They are free on public repositories, and push
protection is what stops a gateway JWT secret from reaching a commit at all.
To set them by hand, use Settings → Advanced Security and Settings → Code
security.

## 5. Enable settings-drift monitoring

Create a GitHub Environment named **`settings-audit`** with deployment branches
limited to **protected branches** (or an exact custom rule for `main`) and
**no required reviewer**. Create a fine-grained PAT or read-only GitHub App
token with **Administration: read**, and store it as a secret *of that
environment*:

```bash
gh secret set SETTINGS_AUDIT_TOKEN --repo owner/repo --env settings-audit
```

Do not make it a repository secret. GitHub releases a repository secret to
whatever workflow file a dispatched ref carries, so any branch a collaborator
can push would reach the token. `settings-audit.yml` binds
`environment: settings-audit`, and GitHub refuses to release that environment's
secrets to a job from a ref the branch policy does not admit. The workflow's
"Require protected default branch" step is the readable, fail-loud half of the
same rule.

The environment has no reviewer on purpose: it deploys nothing, and a reviewer
would hold every weekly run in "waiting for approval". `audit_settings.py`
waives the reviewer and self-review rules for this name, still audits its
branch policy, and does not count it as a protected environment.
`bootstrap_repo_settings.py` creates it on every repository, templates
included.

`settings-audit.yml` runs only from the default branch. It checks:

- Actions permissions;
- the active `main` and release-tag rulesets, including required checks and
  the exact state-writer App bypass;
- that the `settings-audit` environment exists;
- every environment's reviewer, self-review and branch policy;
- gateway monitoring coverage, once any environment opts into unattended drift
  monitoring (below).

It runs weekly and on `workflow_dispatch`. GitHub silently disables scheduled
workflows after 60 days without repository activity, and a stopped audit looks
the same as a clean one. On a quiet repository, dispatch it by hand now and
then or re-enable the schedule in the Actions tab. A dispatch may select any
ref, so the first step refuses anything but the protected default branch before
the token reaches a step.

### Gateway monitoring coverage is audited, not assumed

A `cron:` line in `drift-check.yml` does not prove a gateway is watched. GitHub
may have disabled the schedule, someone may have switched it off, or it may
fail every night against an unreachable gateway. The workflow file looks the
same in every case.

So the audit reads the newest *successful* run of `drift-check.yml` and fails
when it is older than `--monitoring-max-age-hours` (default 48: two nightly
periods, enough slack for one missed run). An unreadable run history fails
closed.

This check applies only once at least one `<env>-monitor` environment exists.
Until then the audit reports:

```
PASS: drift monitoring is approval-gated: no environment declares
      `monitoring.unattended`, so scheduled checks wait for a reviewer and no
      unattended coverage is claimed
```

That line states what is *not* covered; it is not a green tick for monitoring.

### Running the audit locally

You can run the same audit without exposing the token to Actions:

```bash
GH_TOKEN=<administration-read-token> python3 .github/scripts/audit_settings.py \
  --repo owner/repo \
  --branch main \
  --state-writer-app-id 123456 \
  --required-check 'rust-ci-check' \
  --required-check 'security-cargo-audit' \
  --required-check 'security-supply-chain-policy' \
  --required-check 'trusted-supply-chain-policy' \
  --required-check 'state-guard-reject-state-edits' \
  --required-check 'gitforgeops-required-static-validation'
```

`--required-check` may be omitted; those six contexts are the default. Until
the [ruleset switch](#switching-the-supply-chain-policy-check), a ruleset
without `trusted-supply-chain-policy` is reported as a `WARN`, not a failure.
On a template repository, pass `--template-repo` instead of
`--state-writer-app-id` (one of the two is required).

The audit fails closed on missing token scope, API errors, pagination or
response-shape changes, missing controls, and any always-on bypass that is not
an App.

## 6. Keep the validator digest allowlist fresh

The `ferrum-edge` validator is pinned by **content**, not by a URL or version.
`.github/ferrum-edge-checksums.txt` lists the approved SHA-256 digests.
`.github/scripts/install-ferrum-edge.sh` takes the newest published release
from GitHub's `/releases/latest` endpoint (which skips drafts and
prereleases), checks the publisher's checksum, and refuses to make the bytes
executable unless the digest is on the list. There is no
`FERRUM_EDGE_VERSION` variable, and `check_supply_chain.py` fails CI if a
workflow adds one.

Because the pin tracks content, it goes stale whenever upstream publishes a new
version. `validator-pin-canary.yml` runs the installer daily from the default
branch (and on `workflow_dispatch`) and needs no configuration:

- On a stale pin it opens or updates one tracking issue, *Refresh the pinned
  ferrum-edge validator digest*, with the exact allowlist line to commit and the
  command that regenerates it.
- Once the allowlist covers the current release again, it closes that issue.
- It holds `contents: read` and `issues: write`, and never touches a deployment
  environment or gateway credential.

To refresh, review the upstream build and run:

```bash
bash .github/scripts/refresh-ferrum-edge-pin.sh --append
```

Commit the new line through a normal reviewed PR and **keep the previous
line**. The installer accepts any allowlisted digest, so PRs still running the
older binary stay green.

Like `drift-check.yml` and `settings-audit.yml`, the canary's schedule stops
after 60 days without repository activity. Re-enable it from the Actions tab if
the repository goes quiet.

## 7. Verify the trust split

After merging the workflow changes and configuring the controls:

1. Open a same-repository resource PR. `GitForgeOps PR Static Validation`
   must have no environment binding and no gateway secrets.
2. Confirm `GitForgeOps Trusted PR Live Review` starts from `workflow_run`,
   requires environment approval, prints the trusted source SHA and target
   namespace, intersects each environment's protected ownership/filter scope,
   uses protected-branch environment and policy files, and posts the live
   comparison with `FERRUM_NAMESPACE` set. A mistyped namespace filter fails
   `validate`, `plan` and `diff` (exit 1); the bundled workflows set the filter
   to a protected-branch resource namespace. Make the gateway unreachable and
   confirm the trusted job fails rather than posting a skipped comparison as a
   success.
3. Open a fork PR. It must get static validation only. The trusted prepare job
   may resolve metadata, but every artifact, build and Environment step is
   skipped because the head repository differs.
4. Add a test `build.rs` that reads gateway variables. It may run only in the
   secretless static job and must be absent from the sanitized artifact.
5. Add a PR-authored environment remap, or an explicit resource namespace
   outside the protected-branch namespace directories. It must get static
   review only and must not produce a gateway request for that namespace.
6. Add a symlink, traversal path, executable YAML, oversized file, unexpected
   artifact file or hash mismatch. The trusted review must stop before its
   first gateway request.
7. Apply and rotate once. Check that the commits are attributed to the
   state-writer App and that an ordinary direct push to `main` is rejected.
   Confirm apply refuses a missing or ambiguous merge-to-PR association before
   allocating a credential or touching the gateway.
