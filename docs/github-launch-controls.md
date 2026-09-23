# GitHub launch controls

The workflow files enforce what can be enforced inside the repository. Branch
rulesets, environment reviewers, and repository Actions policy live in GitHub
settings and cannot be activated by merging a pull request. Configure this
baseline before connecting production credentials.

This document is the specification for that baseline, and it is what
`.github/scripts/bootstrap_repo_settings.py` applies: sections 1-5 describe, in
prose, the same controls the script writes through the REST API. Run the script
to get there quickly and repeatably — it is idempotent and prints a plan without
writing unless `--apply` is passed — and read this document to understand what
each control buys, or to configure it by hand. `.github/scripts/audit_settings.py`
then re-checks the result on a schedule. All three share their constants, so the
writer, the description, and the auditor cannot drift apart.

```bash
export GH_TOKEN=$(gh auth token)            # an account with admin on the repo
python3 .github/scripts/bootstrap_repo_settings.py --repo owner/repo           # plan
python3 .github/scripts/bootstrap_repo_settings.py --repo owner/repo --apply   # write
```

Secrets are the one thing the script will not touch: it neither accepts nor
prints a secret value, and finishes by listing the `gh secret set` commands left
to run.

For the order of operations rather than the control-by-control specification,
[`docs/quickstart.md`](quickstart.md) walks one gateway, one namespace and one
declared environment from an empty template to a first successful apply. It
applies a subset of this baseline and links back here for the rest.

## Template repositories

The upstream repository is the template customers copy, and a template has no
deployment environment and no state-writer App, because nothing on it ever
applies to a gateway or commits an ownership ledger. Set repository variable
`GITFORGEOPS_TEMPLATE_REPO=true` there (or pass `--template-repo` to the
bootstrap script, which sets it) and `settings-audit.yml` runs the audit with
`--template-repo`: exactly two checks are dropped — the state-writer App bypass
on the default-branch ruleset (section 1) and the "at least one protected
environment" requirement (section 3) — and the audit names both in its own
evidence output. Everything else stays enforced, including every environment
that *is* listed. A deployment repository must leave the variable unset; the
bootstrap script turns it back off if it finds it set there.

## 0. Do this before you merge

Sections 1-5 are prerequisites, not follow-ups. Two workflows are fail-closed
by design and will report red on `main` until the settings behind them exist:

| Workflow | Red until | Section |
| --- | --- | --- |
| `Release` | the `main` ruleset declares required checks — `gh pr checks --required` exits non-zero with "no required checks reported", so every push to `main` fails the publication gate | [§2](#2-protect-main-with-an-active-ruleset) |
| `GitHub Settings Audit` | the `settings-audit` environment exists and holds `SETTINGS_AUDIT_TOKEN`, plus repository variable `GITFORGEOPS_STATE_APP_ID` (or `GITFORGEOPS_TEMPLATE_REPO=true` on a template) | [§1](#1-create-the-state-writer-github-app), [§5](#5-enable-settings-drift-monitoring) |

That is the intended behaviour: neither workflow may assume a control it
cannot verify. Configure §1-§5 first and neither is ever red.

Two things deliberately do *not* fail on an unconfigured repository, because
nobody asked them to do anything yet:

- `GitForgeOps Apply` runs on every push to `main`. With no
  `.gitforgeops/config.yaml` it emits an empty environment matrix and a
  `::notice::`, so the merge that first adds `.gitforgeops/config.example.yaml`
  does not turn `main` red. No GitHub Environment is bound either way.
- `GitForgeOps Trusted PR Live Review` resolves no live-review targets and
  skips its Environment-bound job entirely.

Everything an operator explicitly starts — `rotate`, `materialize-file`, and
the scheduled `drift-check` — still fails loudly when the configuration is
missing, because there the absence contradicts a stated intent.

## 1. Create the state-writer GitHub App

`apply-on-merge.yml` and `rotate.yml` must commit `.state/<env>.json` after a
gateway mutation. A protected `main` branch correctly rejects a direct push by
`github-actions[bot]`, so the workflows mint a short-lived installation token
for a dedicated App instead.

The required `state-guard-reject-state-edits` check protects both the exact
Git path `.state` and every descendant, including current and previous rename
paths regardless of file type. A repair requires a fresh
`gitforgeops/state-override` label event for the current head by an actor with
current write, maintain, or admin permission. Incomplete file enumeration also
requires that authorization. Keep both `/.state` and `/.state/` in CODEOWNERS;
the trusted static-validation classifier must include both scopes as well.

The runtime independently requires `.state` to be a real directory and state
and lock entries to be regular files. Symlinks and intermediate environment
paths are refused even after a state override. Missing state still supports
first apply. Use an isolated trusted checkout: the metadata checks do not
prevent a concurrent local process from replacing checked entries during use.

Create and install a GitHub App with:

- repository access limited to this repository;
- **Contents: read and write** as its only write permission;
- no webhook subscription unless your organization separately needs one.

Add the App as the sole always-on bypass actor in the `main` ruleset, then
record its identity in exactly two places:

- repository **variable** `GITFORGEOPS_STATE_APP_ID` — the numeric App ID. It
  is public metadata, not a credential, and every consumer reads it from here:
  `apply-on-merge.yml` and `rotate.yml` mint the installation token with it,
  and the settings audit compares it against the ruleset's bypass actor to
  prove the bypass is *this* App rather than merely some integration. Storing
  it as a secret in one place and a variable in another is how those two
  drifted apart; `check_supply_chain.py` now rejects
  `secrets.GITFORGEOPS_STATE_APP_ID`.
- environment **secret** `GITFORGEOPS_STATE_APP_PRIVATE_KEY` — in every
  deployment environment. This one is a credential.

`apply-on-merge.yml` and `rotate.yml` check that both are present *before* they
touch the gateway. The token itself is still minted late (after the untrusted
build, immediately before the ledger commit), but the preflight means a missing
App can no longer let an apply land on the gateway with nothing recording it.

The official `actions/create-github-app-token` action is commit-pinned and
revokes each installation token when the job finishes. Do not substitute a
maintainer PAT or an administrator-role bypass: that grants the state path the
same broad authority as a human account and the settings audit rejects it.

## 2. Protect `main` with an active ruleset

Create one active branch ruleset targeting exactly the default branch, with no
additional include or exclusion patterns. It must:

- require pull requests, with zero required approval submissions and no Code
  Owner, last-push, or unattributed-change approval requirement;
- require the root orchestrator to review every changed file at the exact head
  being merged and verify the issue, cross-repository contracts, and hosted CI;
- require all review conversations to be resolved;
- dismiss stale approvals when reviewable commits are pushed;
- require branches to be tested against the latest `main` commit;
- block deletion and non-fast-forward updates;
- reject `[skip ci]` in commit messages (a `commit_message_pattern` rule with
  `negate: true`), because that marker suppresses every workflow including the
  required checks; `release.yml` uses `paths-ignore` for ledger commits instead;
- require, at minimum, these exact GitHub Actions job names (ruleset contexts
  use the job name, not the `Workflow / job` PR display label):
  - `rust-ci-check`
  - `security-cargo-audit`
  - `security-supply-chain-policy`
  - `state-guard-reject-state-edits`
  - `gitforgeops-required-static-validation`
- contain exactly one bypass actor in any mode: the state-writer GitHub App,
  configured as an always-on bypass. Pull-request-only human/team bypasses are
  not permitted.

The root orchestrator may merge a correct PR after exact-head review, passing
hosted CI, and resolution of every actionable review thread. A separate GitHub
approval submission from the maintainer or a Code Owner is not required.
`.github/CODEOWNERS` records ownership for review routing; it is not an approval
gate. The bootstrap and settings audit preserve this policy so a later settings
refresh does not reinstate the approval requirement. Use the ordinary protected
merge path; no administrator bypass is needed to satisfy review requirements.
The state-writer App is still required for state commits: `apply-on-merge.yml`
and `rotate.yml` fail their preflight without `GITFORGEOPS_STATE_APP_ID` and
`GITFORGEOPS_STATE_APP_PRIVATE_KEY`.

Protect release tags (`v*`) with a tag ruleset that carries the `creation`,
`update`, and `deletion` rules, and that names **at least one** bypass actor —
each one an explicit App, team, or user in always-on mode, never a broad
repository role. The bypass list is what release publishing runs through: with
the `creation` rule and no bypass actor at all, nobody can push a `v*` tag and
the tag half of `release.yml` can never fire, so `audit_settings.py` treats an
empty bypass list as a misconfiguration rather than as maximum strictness.

The release workflow also checks that a tag commit is reachable from the
protected default branch;
tag protection ensures a branch-controlled workflow cannot remove that check
before secrets are used.

## 3. Protect every deployment environment

Plan check first: on a private repository, GitHub Environments and their
secrets need Pro, Team, or Enterprise, and the required reviewer this section
sets needs Enterprise (Free, Pro, and Team offer required reviewers to public
repositories only). The bootstrap script warns when the repository is private,
reports an environment GitHub refuses as `FAILED`, and exits non-zero; the audit
in §5 then reports each reviewer-less environment. The README's
[GitHub plan requirements](../README.md#github-plan-requirements) lays out the
public-versus-private trade-off; pick the shape before continuing.

Before enabling any environment-bound workflow, copy
`.gitforgeops/config.example.yaml` to `.gitforgeops/config.yaml`, replace its
example entries with the real deployment environments, and commit that file.

Without it, no privileged workflow ever binds an environment — but they reach
that outcome by two different routes, and the difference matters when you are
reading a red or a green run:

- `apply-on-merge.yml` **skips**: the enumerator emits an empty matrix, so the
  Environment-bound `apply` job never starts.
- `trusted-pr-review.yml` **skips**: it resolves no live-review targets, so its
  Environment-bound job never starts.
- `rotate.yml`, `materialize-file.yml`, and `drift-check.yml` **fail** in a
  preflight job that runs before the Environment-bound job.

The synthetic local `default` environment is never eligible for trusted live
review in any of those paths.

Delete every GitHub Environment that `.gitforgeops/config.yaml` does not
declare — with two exceptions, `settings-audit` (§5) and a
`<env>-monitor` environment created by opting an environment into unattended
drift monitoring (§3.1). Delete the rest, including the `default` environment
GitHub creates on some repositories. The settings audit walks
`GET /repos/{repo}/environments` and holds *every* listed environment to the
reviewer and branch-policy rules below, so one forgotten unprotected
environment keeps the audit red forever. An environment nothing deploys to is
also a standing invitation to store credentials somewhere no workflow guard
covers.

`settings-audit` is exempt from the reviewer and self-review rules alone, and
only because it deploys nothing: a required reviewer there would park every
scheduled audit in "waiting for approval", which is precisely the silently
stopped audit §5 is designed to avoid. Its branch policy *is* audited, and it
does not count towards the at-least-one-protected-environment requirement.

For every environment listed in `.gitforgeops/config.yaml` — the bootstrap
script reads that file and creates each one when given `--reviewer LOGIN` or
`--reviewer-team org/slug`:

- require at least one authorized reviewer;
- prevent self-review;
- disallow administrator bypass of environment protection where the repository
  plan exposes that setting;
- restrict deployment branches to protected branches, or add an exact custom
  policy for `main`;
- store gateway, TLS, credential-broker, and state-App secrets only in that
  environment;
- set that environment's `FERRUM_GATEWAY_URL` secret to an **`https://`** URL.

These rules secure `apply`, `rotate`, `materialize`, drift checks, and trusted
PR live review. The manual workflows also check `github.ref == refs/heads/main`,
but environment branch policy is the non-bypassable boundary because a workflow
definition on an unprotected branch could remove an in-file condition.

Credential-broker bundles are the one secret family the workflows enumerate.
No workflow reads the whole `secrets` context — `${{ toJSON(secrets) }}` would
hand a bundle-loading step the admin JWT signing key and the state-writer App
private key as well, and GitHub holds public-repository runs that read it for
manual approval. Instead each privileged workflow binds
`FERRUM_CREDS_BUNDLE` … `FERRUM_CREDS_BUNDLE_15` by name, which caps an
environment at `MAX_BUNDLE_SHARDS` = 16 shards (~7,000 credential slots). A
shard beyond that would be written but never read back, so `apply` and
`rotate` refuse to create one. Raising the ceiling means editing
`MAX_BUNDLE_SHARDS` in `src/secrets/bundle.rs` and
`.github/scripts/credential_bundles.py` and extending the bindings in all four
workflows; `.github/scripts/check_supply_chain.py` fails the build if they
disagree.

### 3.1 Unattended drift monitoring

`drift-check.yml` runs nightly and reads the gateway with
`gitforgeops diff --exit-on-drift`. Bound to a deployment environment, it
inherits that environment's required reviewer — and
[GitHub withholds an approval-gated environment's secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#environment-secrets)
until a human approves the job. The nightly run therefore parks in "waiting for
approval" and inspects nothing.

That is the approval boundary working exactly as configured, not a bypass. It
is still a bad monitoring experience, so an environment may opt into a second,
reviewer-free environment that holds gateway **read** material only:

```yaml
environments:
  production:
    overlay: production
    ownership:
      mode: shared
    monitoring:
      unattended: true      # -> binds the `production-monitor` environment
```

`gitforgeops envs --include-scopes` then reports
`monitoring_environment: production-monitor`, and that is what the drift job
binds. Left out (or `false`), monitoring stays on the deployment environment
and the check reports `Not completed` with the reason — never anything
resembling "in sync".

The bootstrap script creates each `<env>-monitor` with no reviewer, protected
branches only, and prints the `gh secret set` commands for exactly the read
material a comparison needs.

**What the monitoring environment may hold.** `audit_settings.py` grants the
reviewer waiver only to `<env>-monitor` where `<env>` is itself a listed
environment, and only while the environment holds none of
`GITFORGEOPS_STATE_APP_PRIVATE_KEY`, `FERRUM_GH_PROVISIONER_TOKEN`,
`SETTINGS_AUDIT_TOKEN` or `FERRUM_CREDS_BUNDLE[_N]` — read by **name**; no
secret value is ever requested. `repo_config.rs` refuses to name a deployment
environment into the suffix, and `check_supply_chain.py` separately refuses a
`drift-check.yml` that binds any of those secrets, holds a write permission, or
runs a `gitforgeops` subcommand other than `diff`. Three independent fences,
because the environment has no human in front of it.

The credential bundle is deliberately *not* in that list of things monitoring
gets. A comparison does not need credential values: `diff` excludes
still-unresolved broker leaves from the live comparison per leaf, so the rest
of the document is compared in full and the secrets simply stay out of the
unattended environment.

**Open dependency: a genuinely read-only gateway credential.** Ferrum Edge
signs admin tokens with a *symmetric* secret and `GET /backup` requires the
`admin` role, so there is today no token this workflow can hold that reads
configuration but cannot write it. Set the monitoring environment's
`FERRUM_ADMIN_JWT_ROLE` to the least-privileged role your gateway accepts for
`/backup`, and treat the signing secret there as gateway-write-equivalent:
fenced to the protected default branch, holding no GitHub-side authority, but
not read-limited at the gateway. Closing that gap needs a Ferrum Edge
capability (a read-only admin role, or separately issued read tokens); until it
lands, an operator who is not willing to accept that trade-off should leave
`monitoring.unattended` off and read the approval-gated `Not completed`
outcome for what it is.

### 3.2 Monitoring outcomes

The scheduled check reports five distinct outcomes, and only one of them says a
gateway was compared and matched:

| Outcome | Meaning |
| --- | --- |
| `In sync` | the gateway was read and matches the repository |
| `Drift detected` | the gateway was read and differs |
| `Check failed` | authentication, connectivity, a cached (non-authoritative) backup, or a configuration error — **nothing is known about the gateway** |
| `Skipped (file mode)` | no live Admin API to compare against; a configured absence, not a gap |
| `Not completed` | the comparison never ran: approval pending, cancelled, or the runner was lost |

`drift_report.py` does the classification and renders the table into the run's
job summary. `Drift detected`, `Check failed` and `Not completed` all fail the
workflow; `Skipped` does not. A matrix entry that produced no record at all is
reconstructed as `Not completed` rather than omitted, so an environment held at
"waiting for approval" appears in the table instead of vanishing from it.

### The gateway URL must be `https://`

Every environment-bound workflow mints an admin JWT into an `Authorization`
header, and `apply` puts resolved consumer credentials in the request body. A
cleartext gateway hands both to anything on the path, so gitforgeops refuses a
non-`https://` `FERRUM_GATEWAY_URL` at startup, before any HTTP client exists —
the run fails once rather than leaking request by request. Other schemes
(`ftp://`, `file://`, `ws://`) and URLs embedding `user:password@` credentials
are refused outright, with no opt-in.

Two dev-only escape hatches exist, and **both are refused under
`GITHUB_ACTIONS` unless the gateway host is loopback** (`localhost`,
`127.0.0.0/8`, `::1`):

- `FERRUM_ALLOW_INSECURE_HTTP=true` — permits a cleartext `http://` gateway.
- `FERRUM_TLS_NO_VERIFY=true` — keeps TLS but accepts any certificate, which
  makes an interceptor indistinguishable from the gateway.

Neither belongs in a GitHub Environment. If a deployment gateway presents a
certificate from a private CA, put that CA in the environment's
`FERRUM_GATEWAY_CA_CERT` secret (base64 PEM) instead of disabling the check;
gitforgeops then trusts that CA alone. Both switches print a loud stderr banner
when they take effect locally, so a warning in a job log means one of them
reached CI and should be removed from wherever it was set.

### Scheduling and supersession are one list

`apply-on-merge.yml` runs only for pushes that touch its `paths:` filter, and
its freshness guard refuses to reconcile a refreshed protected head that
changed a deployment input since the triggering merge. Those two sets are the
same list — `DEPLOYMENT_INPUT_PATHS` in
[`.github/scripts/deployment_scope.py`](../.github/scripts/deployment_scope.py)
— and `check_supply_chain.py` fails the build when they drift apart.
The workflow executes that classifier from the triggering commit, not from the
refreshed checkout it is evaluating. A newer helper change therefore cannot
approve itself under the waiting run's older environment authorization.

Equality is what keeps an approval-gated deployment from being cancelled by
accident. While a merge waits for its environment's required reviewer, other
merges land on `main`:

- A merge that changes a deployment input (resources, overlays,
  `.gitforgeops/`, the engine source, the helper scripts, the validator pin, or
  this workflow) **supersedes** the waiting run — and schedules an apply of its
  own, which reconciles its revision together with everything queued behind it.
- A merge that changes nothing else — documentation, tests, an unrelated
  workflow — leaves the waiting run alone, because it would schedule no
  replacement and therefore may cancel nothing.

`.state/**` and `assembled/**` belong to neither half: the apply writes them,
so they must not reject a queued run, and they must not trigger the workflow
that produced them.

Operator recovery for an already-superseded run is documented in
[Recovering a superseded apply](../README.md#recovering-a-superseded-apply).

## 4. Restrict GitHub Actions

In **Settings → Actions → General**:

- set default workflow permissions to **Read repository contents**;
- disable **Allow GitHub Actions to create and approve pull requests**;
- allow GitHub-owned Actions, disallow the blanket "verified creators" switch,
  and set the third-party patterns to exactly:
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

### Repository security features

The bootstrap script also enables, in the same pass, four settings the scheduled
audit does not currently read back: **secret scanning**, **secret-scanning push
protection**, **private vulnerability reporting**, and Dependabot's
**vulnerability alerts** plus **automated security updates**. They are cheap,
they are free on public repositories, and push protection in particular is the
control that stops a gateway JWT secret from reaching a commit in the first
place. Settings → Advanced Security, and Settings → Code security, if you would
rather click.

The repository patterns end in `@*` only because the settings API allowlist is
repository-oriented. Every actual `uses:` reference is still required to carry
a full 40-hex commit SHA by both repository policy and CI.

Repository policy is backed by `.github/scripts/check_supply_chain.py`, which
fails CI on tag-based action references, floating runner releases, unpinned
container bases, missing Rust version pins, or disabled release attestations.

It also rejects any workflow expression that reaches the whole `secrets`
context (`toJSON(secrets)`, a bare `${{ secrets }}`, `secrets: inherit`).
GitHub holds public-repository runs that read the whole context for manual
approval, and the credential broker never needs more than the
`FERRUM_CREDS_BUNDLE[_N]` shards, which the privileged workflows bind by name.

The `security-supply-chain-policy` check always runs the **protected
branch's** copy of the checker against the candidate tree, so a pull request
cannot weaken the policy that judges it. The flip side: a pull request that
changes the checker *and* the workflow shape it governs fails its own policy
check exactly once, because the old policy is judging the new shape. Prefer
landing such changes as expand/contract pairs (accept both shapes, migrate,
then reject the old shape). When that is impractical, a maintainer reviews
the red check, confirms every violation is the intended migration, and merges
with a ruleset bypass; the next run on `main` judges with the new policy.

## 5. Enable settings-drift monitoring

Create a GitHub Environment named **`settings-audit`** with deployment
branches limited to **protected branches** (or an exact custom rule for `main`)
and **no required reviewer**. Then create a fine-grained PAT or read-only GitHub
App token with **Administration: read** and store it as a secret *of that
environment*:

```bash
gh secret set SETTINGS_AUDIT_TOKEN --repo owner/repo --env settings-audit
```

It is deliberately **not** a repository secret. A repository secret is released
to whatever workflow definition a dispatched ref carries, so any branch a
write-access collaborator can push was a path to an administration-read token.
`settings-audit.yml` binds `environment: settings-audit`, and GitHub refuses to
release that environment's secrets to a job running from a ref the branch policy
does not admit — before a single step executes. The in-file
"Require protected default branch" preflight stays as the readable, fail-loud
half of the same rule.

The environment carries no reviewer on purpose: it deploys nothing, and a
required reviewer would hold every weekly run in "waiting for approval" —
producing exactly the silently stopped audit described below.
`audit_settings.py` waives the reviewer and self-review rules for this one name,
still audits its branch policy, and does not let it satisfy the
at-least-one-protected-environment requirement. `bootstrap_repo_settings.py`
creates it on every repository, template copies included.

`settings-audit.yml` runs only from the default branch and verifies Actions
permissions, the active `main` and release tag rulesets, required checks, the
exact state-writer App bypass, the presence of the `settings-audit` environment,
every environment's reviewer/self-review/branch policy, and — for a repository
that opted into unattended drift monitoring — the *gateway* monitoring coverage
described next.

### Gateway monitoring coverage is audited, not assumed

A `cron:` line in `drift-check.yml` is not evidence that a gateway is being
watched. The schedule can be disabled by GitHub after 60 days of repository
inactivity, switched off in the Actions tab, or fail every night against an
unreachable gateway, and the workflow file looks identical in each case.

So the audit reads the *newest successful run* of `drift-check.yml` through the
Actions API and fails when it is older than `--monitoring-max-age-hours`
(default 48 — two nightly periods, enough slack for one missed or queued run).
An unreadable run history fails closed rather than passing silently.

This check only applies once at least one `<env>-monitor` environment exists.
A repository that has not opted in is reported, accurately, as:

```
PASS: drift monitoring is approval-gated: no environment declares
      `monitoring.unattended`, so scheduled checks wait for a reviewer and no
      unattended coverage is claimed
```

which is a statement about what is *not* covered, not a green tick for
monitoring that is not happening.

It runs weekly on a schedule **and** on `workflow_dispatch`. The manual trigger
is not a convenience: GitHub disables a scheduled workflow after 60 days with
no repository activity, and it does so silently. A settings audit that has been
switched off reports no drift, which is indistinguishable from no drift
existing — so on a quiet repository, dispatch it by hand periodically, or
re-enable the schedule from the Actions tab. A dispatch may select any ref, so
the job's first step refuses to run from anything but the protected default
branch, before the administration-read token is bound to a step.

You can run the same audit locally without exposing the token to Actions:

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

`--required-check` may be omitted entirely; the five contexts above are the
built-in default. On a template repository, swap `--state-writer-app-id` for
`--template-repo` (the two are mutually exclusive: the flag is required unless
template mode is on).

The audit is intentionally fail-closed on missing token scope, API errors,
pagination/response-shape changes, missing controls, or a non-App always-on
bypass.

## 6. Keep the validator digest allowlist fresh

The `ferrum-edge` validator is pinned by **content**, not by a locator. Upstream
publishes production artifacts only for version tags. Assets on a given tag are
immutable; a new version tag is a new candidate. GitHub's `/releases/latest`
endpoint returns the newest non-draft, non-prerelease release. Nothing on the
GitHub side selects a validator version: `.github/ferrum-edge-checksums.txt`
lists the approved SHA-256 digests, and `.github/scripts/install-ferrum-edge.sh`
refuses to make downloaded bytes executable unless the digest is on that list.
There is no `FERRUM_EDGE_VERSION` variable to set, and `check_supply_chain.py`
fails CI if a workflow reintroduces one.

Because the pin tracks content, it goes stale whenever upstream publishes a new
version tag — on upstream's schedule, not yours. `validator-pin-canary.yml` runs
the installer daily from the default branch (plus `workflow_dispatch`), and
needs no configuration:

- On a stale pin it opens, or updates, exactly one tracking issue titled
  *Refresh the pinned ferrum-edge validator digest*. The body carries the exact
  allowlist line to commit and the command that regenerates it.
- Once the allowlist covers the current version release again, the canary
  closes that issue.
- It holds `contents: read` plus `issues: write` and never touches a deployment
  environment or a gateway credential.

To refresh, review the upstream build and run:

```bash
bash .github/scripts/refresh-ferrum-edge-pin.sh --append
```

Commit the new line through exact-head root review and **keep the previous
line**: pull requests already running the older binary stay green, and the
installer accepts any allowlisted digest.

GitHub disables scheduled workflows after 60 days without repository activity.
The canary shares that fate with `drift-check.yml` and `settings-audit.yml`; if
the repository goes quiet, re-enable the schedules from the Actions tab.

## 7. Verify the trust split

After merging the workflow changes and configuring the controls:

1. Open a same-repository resource PR. `GitForgeOps PR Static Validation`
   must have no environment binding and no gateway secrets.
2. Confirm `GitForgeOps Trusted PR Live Review` starts from `workflow_run`,
   requires environment approval, prints the trusted source SHA and target
   namespace, intersects each environment's protected ownership/filter scope,
   uses protected-branch environment/policy files, and posts the live
   comparison with `FERRUM_NAMESPACE` set. A mistyped namespace filter now
   fails `validate` / `plan` / `diff` closed (exit 1) instead of succeeding
   against an empty desired set; the bundled workflows set the filter to a
   protected-branch resource namespace. Make the gateway unreachable and
   confirm the trusted job fails rather than posting a successful skipped
   comparison.
3. Open a fork PR. It must receive static validation only; the trusted prepare
   job may resolve metadata, but every artifact/build/Environment step is
   skipped because the head repository differs.
4. Add a test `build.rs` that reads gateway variables. It may run only in the
   secretless static job and must be absent from the sanitized artifact.
5. Add a PR-authored environment remap or explicit resource namespace outside
   the protected-branch namespace directories. It must receive static review
   only and must not produce a gateway request for that namespace.
6. Add a symlink, traversal path, executable YAML, oversized file, unexpected
   artifact file, or hash mismatch. The trusted review must stop before its
   first gateway request.
7. Apply and rotate once. Verify commits are attributed to the state-writer App
   and that an ordinary direct push to `main` is rejected. Confirm apply refuses
   an absent or ambiguous merge-to-PR association before allocating a
   credential or touching the gateway.
