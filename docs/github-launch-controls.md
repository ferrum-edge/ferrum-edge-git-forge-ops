# GitHub launch controls

The workflow files enforce what can be enforced inside the repository. Branch
rulesets, environment reviewers, and repository Actions policy live in GitHub
settings and cannot be activated by merging a pull request. Configure this
baseline before connecting production credentials.

## 1. Create the state-writer GitHub App

`apply-on-merge.yml` and `rotate.yml` must commit `.state/<env>.json` after a
gateway mutation. A protected `main` branch correctly rejects a direct push by
`github-actions[bot]`, so the workflows mint a short-lived installation token
for a dedicated App instead.

Create and install a GitHub App with:

- repository access limited to this repository;
- **Contents: read and write** as its only write permission;
- no webhook subscription unless your organization separately needs one.

Add the App as the sole always-on bypass actor in the `main` ruleset. Add its
credentials to every deployment environment:

- `GITFORGEOPS_STATE_APP_ID`
- `GITFORGEOPS_STATE_APP_PRIVATE_KEY`

Also set repository variable `GITFORGEOPS_STATE_APP_ID` to the same numeric App
ID so the settings audit can prove the bypass is this App, rather than merely
accepting any integration actor.

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

Protect release tags (`v*`) with a tag ruleset that prevents update and
deletion and restricts creation to explicit release users, teams, or Apps—not
a broad repository-role bypass. The release
workflow also checks that a tag commit is reachable from `main`; tag protection
ensures a branch-controlled workflow cannot remove that check before secrets
are used.

## 3. Protect every deployment environment

Before enabling any environment-bound workflow, copy
`.gitforgeops/config.example.yaml` to `.gitforgeops/config.yaml`, replace its
example entries with the real deployment environments, and commit that file.
The privileged workflows fail before binding an environment when the protected
branch has no repository configuration, and the synthetic local `default`
environment is never eligible for trusted live review.

For every environment listed in `.gitforgeops/config.yaml`:

- require at least one authorized reviewer;
- prevent self-review;
- disallow administrator bypass of environment protection where the repository
  plan exposes that setting;
- restrict deployment branches to protected branches, or add an exact custom
  policy for `main`;
- store gateway, TLS, credential-broker, and state-App secrets only in that
  environment.

These rules secure `apply`, `rotate`, `materialize`, drift checks, and trusted
PR live review. The manual workflows also check `github.ref == refs/heads/main`,
but environment branch policy is the non-bypassable boundary because a workflow
definition on an unprotected branch could remove an in-file condition.

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
`SETTINGS_AUDIT_TOKEN`. The scheduled `settings-audit.yml` runs only from the
default branch and verifies Actions permissions, the active `main` and release
tag rulesets, required checks, the exact state-writer App bypass, and every
environment's reviewer/self-review/branch policy.

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

## 6. Verify the trust split

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
