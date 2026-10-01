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
| `GitHub Settings Audit` | the `settings-audit` environment exists and holds `SETTINGS_AUDIT_TOKEN`, and repository variable `GITFORGEOPS_STATE_APP_ID` is set (or `GITFORGEOPS_TEMPLATE_REPO=true` on a template) | [§1](#1-create-the-state-writer-github-app), [§5](#5-enable-settings-drift-monitoring) |

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
  `SETTINGS_AUDIT_TOKEN` or `FERRUM_CREDS_BUNDLE[_N]`. It checks secret
  **names** only and never requests a value.
- `repo_config.rs` refuses a deployment environment name that ends in the
  reserved suffix.
- `check_supply_chain.py` refuses a `drift-check.yml` that binds any of those
  secrets, holds a write permission, or runs any `gitforgeops` subcommand
  other than `diff`.

The credential bundle is deliberately left out. `diff` excludes unresolved
broker leaves from the live comparison one leaf at a time, so the rest of the
document is still compared in full.

**Limitation: the bundled check still holds a write-capable key.**
`drift-check.yml` runs `diff` against `GET /backup`, which requires the `admin`
role, with the environment's `FERRUM_ADMIN_JWT_SECRET`. Ferrum Edge signs admin
tokens with a *symmetric* secret, so that key can mint any role. Leave the
monitoring environment's `FERRUM_ADMIN_JWT_ROLE` unset (it defaults to `admin`)
and treat its signing secret as gateway-write-equivalent: fenced to the default
branch and holding no GitHub-side authority, but not read-limited at the
gateway. If that trade-off is not acceptable, leave `monitoring.unattended` off
and read the approval-gated `Not completed` result for what it is.

Ferrum Edge v0.9.9 closes the gateway side: a token signed with its
`FERRUM_ADMIN_JWT_VIEWER_SECRET` is authorized as `viewer` whatever it claims,
and `GET /config/export` serves a fingerprinted snapshot to that role.
`gitforgeops diff` already reads that way when `FERRUM_ADMIN_JWT_VIEWER_SECRET`
is set (see
[Reading with a viewer-capped credential](../README.md#reading-with-a-viewer-capped-credential)).
Moving the monitoring environment to it means binding that secret in
`drift-check.yml` instead of the admin one, and updating the trusted
supply-chain checker and settings audit to require it; that is a separate,
policy-reviewed change. Unless the gateway also sets
`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`, the viewer key reads every namespace.

### 3.2 Monitoring outcomes

The scheduled check reports five outcomes. Only `In sync` says a gateway was
compared and matched:

| Outcome | Meaning |
| --- | --- |
| `In sync` | the gateway was read and matches the repository |
| `Drift detected` | the gateway was read and differs |
| `Check failed` | authentication, connectivity, a cached (non-authoritative) backup, or a configuration error — **nothing is known about the gateway** |
| `Skipped (file mode)` | no live Admin API to compare against; a configured absence, not a gap |
| `Not completed` | the comparison never ran: approval pending, cancelled, or the runner was lost |

`drift_report.py` classifies each result and writes the table to the job
summary. `Drift detected`, `Check failed` and `Not completed` fail the
workflow; `Skipped` does not. A matrix entry that produced no record is shown
as `Not completed`, so an environment waiting for approval still appears in the
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

The `security-supply-chain-policy` check always runs the **protected branch's**
copy of the checker against the candidate tree, so a pull request cannot weaken
the policy that judges it. The cost: a PR that changes the checker *and* the
workflow shape it governs fails its own policy check once, because the old
policy judges the new shape. Prefer expand/contract pairs (accept both shapes,
migrate, then reject the old one). The baseline ruleset has no human bypass,
so merging past that red required check takes a deliberate admin decision.
The next run on `main` uses the new policy.

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
  --required-check 'state-guard-reject-state-edits' \
  --required-check 'gitforgeops-required-static-validation'
```

`--required-check` may be omitted; those five contexts are the default. On a
template repository, pass `--template-repo` instead of `--state-writer-app-id`
(one of the two is required).

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
