# GitHub launch controls

The workflow files enforce what can be enforced inside the repository. Branch
rulesets, environment reviewers, and repository Actions policy live in GitHub
settings and cannot be activated by merging a pull request. Configure this
baseline before connecting production credentials.

## 0. Do this before you merge

Sections 1-5 are prerequisites, not follow-ups. Two workflows are fail-closed
by design and will report red on `main` until the settings behind them exist:

| Workflow | Red until | Section |
| --- | --- | --- |
| `Release` | the `main` ruleset declares required checks — `gh pr checks --required` exits non-zero with "no required checks reported", so every push to `main` fails the publication gate | [§2](#2-protect-main-with-an-active-ruleset) |
| `GitHub Settings Audit` | `SETTINGS_AUDIT_TOKEN` and repository variable `GITFORGEOPS_STATE_APP_ID` exist | [§1](#1-create-the-state-writer-github-app), [§5](#5-enable-settings-drift-monitoring) |

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

- require pull requests and at least one approval;
- require Code Owner review (`.github/CODEOWNERS` owns workflows, state,
  reconciliation, credential code, Cargo metadata, and container inputs);
- require all review conversations to be resolved;
- dismiss stale approvals when reviewable commits are pushed;
- require branches to be tested against the latest `main` commit;
- block deletion and non-fast-forward updates;
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

Protect release tags (`v*`) with a tag ruleset that carries the `creation`,
`update`, and `deletion` rules, and that names **at least one** bypass actor —
each one an explicit App, team, or user in always-on mode, never a broad
repository role. The bypass list is what release publishing runs through: with
the `creation` rule and no bypass actor at all, nobody can push a `v*` tag and
the tag half of `release.yml` can never fire, so `audit_settings.py` treats an
empty bypass list as a misconfiguration rather than as maximum strictness.

The release workflow also checks that a tag commit is reachable from `main`;
tag protection ensures a branch-controlled workflow cannot remove that check
before secrets are used.

## 3. Protect every deployment environment

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
declare — including the `default` environment GitHub creates on some
repositories. The settings audit walks `GET /repos/{repo}/environments` and
holds *every* listed environment to the reviewer and branch-policy rules below,
so one forgotten unprotected environment keeps the audit red forever. An
environment nothing deploys to is also a standing invitation to store
credentials somewhere no workflow guard covers.

For every environment listed in `.gitforgeops/config.yaml`:

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

## 4. Restrict GitHub Actions

In **Settings → Actions → General**:

- set default workflow permissions to **Read repository contents**;
- disable **Allow GitHub Actions to create and approve pull requests**;
- allow GitHub-owned Actions, disallow the blanket "verified creators" switch,
  and set the third-party patterns to exactly:
  - `aquasecurity/trivy-action@*`
  - `docker/build-push-action@*`
  - `docker/login-action@*`
  - `docker/metadata-action@*`
  - `docker/setup-buildx-action@*`
  - `docker/setup-qemu-action@*`
  - `dtolnay/rust-toolchain@*`
  - `taiki-e/install-action@*`
- enable **Require actions to be pinned to a full-length commit SHA**.

The repository patterns end in `@*` only because the settings API allowlist is
repository-oriented. Every actual `uses:` reference is still required to carry
a full 40-hex commit SHA by both repository policy and CI.

Repository policy is backed by `.github/scripts/check_supply_chain.py`, which
fails CI on tag-based action references, floating runner releases, unpinned
container bases, missing Rust version pins, or disabled release attestations.

## 5. Enable settings-drift monitoring

Create a fine-grained PAT or read-only GitHub App token with
**Administration: read** and store it as repository secret
`SETTINGS_AUDIT_TOKEN`. `settings-audit.yml` runs only from the default branch
and verifies Actions permissions, the active `main` and release tag rulesets,
required checks, the exact state-writer App bypass, and every environment's
reviewer/self-review/branch policy.

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

The audit is intentionally fail-closed on missing token scope, API errors,
pagination/response-shape changes, missing controls, or a non-App always-on
bypass.

## 6. Keep the validator digest allowlist fresh

The `ferrum-edge` validator is pinned by **content**, not by a locator. Upstream
publishes one rolling `latest` release and deletes plus re-uploads its assets on
every build, so release ids, asset ids and tags all move. Nothing on the GitHub
side selects a validator version: `.github/ferrum-edge-checksums.txt` lists the
approved SHA-256 digests, and `.github/scripts/install-ferrum-edge.sh` refuses to
make downloaded bytes executable unless the digest is on that list. There is no
`FERRUM_EDGE_VERSION` variable to set, and `check_supply_chain.py` fails CI if a
workflow reintroduces one.

Because the pin tracks content, it goes stale whenever upstream rebuilds — on
upstream's schedule, not yours. `validator-pin-canary.yml` runs the installer
daily from the default branch (plus `workflow_dispatch`), and needs no
configuration:

- On a stale pin it opens, or updates, exactly one tracking issue titled
  *Refresh the pinned ferrum-edge validator digest*. The body carries the exact
  allowlist line to commit and the command that regenerates it.
- Once the allowlist covers the current build again, the canary closes that
  issue.
- It holds `contents: read` plus `issues: write` and never touches a deployment
  environment or a gateway credential.

To refresh, review the upstream build and run:

```bash
bash .github/scripts/refresh-ferrum-edge-pin.sh --append
```

Commit the new line through normal CODEOWNER review and **keep the previous
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
   comparison with `FERRUM_NAMESPACE` set. Make the gateway unreachable and
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
