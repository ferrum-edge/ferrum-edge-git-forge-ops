# Quickstart: one gateway, one namespace, one environment

Release baseline: [v0.1.0](../release/README.md). Treat this setup as a
supported pairing only when the [upstream record](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/baseline.json) `status` is
`supported`. The record then gives the exact source revision and the
validator/gateway pairing. Start your repository at that revision with the
[immutable adoption commands](../release/README.md#adopt-the-immutable-sourcetemplate-revision).
GitHub's **Use this template** button copies the current default branch, which
may be ahead of the supported baseline.

This is the smallest setup that actually deploys: one API-mode gateway, one
namespace, shared ownership, one deployment environment, and the security
controls the bundled workflows require. At the end you have a proxy serving
authenticated traffic, a broker-allocated consumer credential delivered to you
encrypted, and an ownership ledger committed to `main` by the state-writer App.

Every file in this guide is copied verbatim from
[`tests/fixtures/quickstart/`](../tests/fixtures/quickstart/).
`tests/unit/quickstart_tests.rs` loads, overlays and audits that fixture and
checks it byte-for-byte against this page, so a change that breaks the
copy-paste fails that test first.

This page is the order of operations. Details are linked where they matter.

---

## 0. Before you start

### Decide the repository shape first

| | Public repository | Private repository |
| --- | --- | --- |
| GitHub Environments + environment secrets | Free and up | **Pro, Team or Enterprise** |
| Required reviewers on an environment | Free, Pro, Team, Enterprise | **Enterprise only** |

[GitHub's environment documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#required-reviewers)
is the authority. On a plan without required reviewers, the environment steps
below fail with GitHub's own error, `bootstrap_repo_settings.py` exits
non-zero, and the settings audit reports every environment without a reviewer.
Pick the shape before you provision anything. See
[GitHub plan requirements](../README.md#github-plan-requirements).

### Decide who approves what

There are two different approvals:

| Approval | Who | Required here? |
| --- | --- | --- |
| **Pull request review** | any collaborator | **No.** The `main` ruleset sets `required_approving_review_count: 0`. A pull request is required; an approving review is not. A solo maintainer merges their own PR once the required checks pass. |
| **Environment approval** | a *required reviewer* on the deployment environment, who is not the person that triggered the run | **Yes**, and this one needs a second human. |

Plan around the second row. The baseline sets `prevent_self_review: true`, so
the account that merged the pull request cannot approve the apply it
triggered. **A single-person repository cannot satisfy both halves.** Name a
second maintainer as the environment reviewer, or accept that every apply
waits for someone who is not you.

There is no supported solo bypass. The Repository Admin bypass actor you may
see on the `main` ruleset is a different control: the bootstrap script uses it
only when no state-writer App ID is given, and the settings audit reports it as
a violation until you replace it with the App. It does not affect environment
approvals.

### What this profile does and does not give you

| | api mode (this guide) | local CLI only | file / mesh output |
| --- | --- | --- | --- |
| Reconciles a running gateway | yes, through the admin REST API | no — you run commands by hand | no: it writes a document, it does not deploy one |
| Needs `.gitforgeops/config.yaml` | **yes** | no | **yes**, for the workflows |
| Ownership ledger in `.state/` | yes, committed by CI | not unless you run apply yourself | yes |
| Drift detection | yes (`drift-check.yml`) | on demand (`gitforgeops diff`) | no live surface to compare |
| Credential broker | yes | yes, with a local bundle | yes, plus a separate materialize step |

**Assembling a file is not deploying it.** In file mode, `apply` writes and
commits `assembled/<env>.yaml` (plus `assembled/<env>-mesh.yaml` when the
repository declares mesh fragments). Getting those documents onto a fleet is
your own delivery step.

The sample configuration leaves `monitoring.unattended` unset, so the nightly
drift check waits for the environment's required reviewer before it can read
the gateway. To run it unattended, set `monitoring.unattended: true`; the
bootstrap script then creates a separate `<env>-monitor` environment for the
check to bind. Set its secrets as described in
[launch controls §3.1](github-launch-controls.md#31-unattended-drift-monitoring).
Its admin JWT signing secret can write to the gateway even though the workflow
only reads, so read the
[caveat](../README.md#unattended-monitoring-and-when-it-is-approval-gated)
first. You can also run `gitforgeops diff --exit-on-drift` yourself at any
time.

### Prerequisites

- `gh` authenticated as an account with **admin** on the repository.
- Admin access to a running Ferrum Edge gateway: its `https://` admin URL and
  its JWT signing secret.
- A second human who will be the environment's required reviewer (see above).

---

## 1. Create the repository from the template

For the supported pairing, create the copy from the exact source SHA with the
[release instructions](../release/README.md#adopt-the-immutable-sourcetemplate-revision).
Before a release is supported, a throwaway setup may use **Use this
template**. Do not fork: a fork carries neither repository settings nor
secrets.

Check that workflows are enabled under **Actions → General**. GitHub disables
*scheduled* workflows after 60 days without repository activity, so check
again if the repository goes quiet.

At this point there is no `.gitforgeops/config.yaml` and no deployment
environment. That is expected, and the workflows react like this:

| Workflow | With no config |
| --- | --- |
| `GitForgeOps Apply` | **skips**: empty environment matrix, a `::notice::`, green |
| `GitForgeOps Trusted PR Live Review` | **skips**: no live-review targets |
| `GitForgeOps Drift Check` | **fails** its preflight |
| `rotate`, `materialize-file` | **fail**: you started them, so missing configuration contradicts your intent |

---

## 2. Create the state-writer GitHub App

`apply-on-merge.yml` and `rotate.yml` commit `.state/<env>.json` back to a
protected `main`, which rejects a direct push by `github-actions[bot]`. They
use a short-lived installation token for a dedicated App instead.

Create it under Settings → Developer settings → GitHub Apps → **New GitHub
App**, with **Contents: read and write** as its only write permission, no
webhook, and repository access limited to this repository. Install it, note the
numeric **App ID**, and generate a private key.

```bash
gh variable set GITFORGEOPS_STATE_APP_ID --repo OWNER/REPO --body 123456
```

The App ID is a repository **variable** (public metadata, read by both the
workflows and the settings audit). The private key is an environment
**secret**, set in step 5. Details:
[launch controls §1](github-launch-controls.md#1-create-the-state-writer-github-app).

---

## 3. Apply the settings baseline

`bootstrap_repo_settings.py` writes the rulesets, Actions policy, security
features, labels, the `settings-audit` environment and your deployment
environment. It is idempotent, only prints a plan unless `--apply` is passed,
and never accepts or prints a secret value.

```bash
export GH_TOKEN=$(gh auth token)

python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO \
  --state-writer-app-id 123456 \
  --environment production \
  --reviewer SECOND-MAINTAINER            # plan

python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO \
  --state-writer-app-id 123456 \
  --environment production \
  --reviewer SECOND-MAINTAINER --apply    # write
```

It ends by listing the `gh secret set` commands you run in step 5. Before
setting any secrets, confirm the applied plan contains
`CREATE environment production` or `UPDATE environment production`
(`UNCHANGED environment production` on a later re-run). Without that line the
deployment environment is not set up, even if the script succeeded.

`--reviewer` is the environment's required reviewer from §0. Without it the
environment step reports `BLOCKED` instead of creating an environment nobody
has to approve. `--environment production` is needed because the script
normally discovers environments from `.gitforgeops/config.yaml`, which you
commit in step 4.

The release-tag ruleset's bypass defaults to the Repository Admin role, which
the settings audit rejects. Once you have an App, user or team that publishes
releases, re-run with `--release-tag-bypass app:<id>`, `user:<login>` or
`team:<org/slug>`.

---

## 4. Commit the repository configuration

**GitHub Actions deploys nothing without this file.** Local CLI use does not
need it: `gitforgeops validate`, `diff` and `plan` fall back to a synthetic
local `default` environment configured only by `FERRUM_*` variables. The
workflows do need it. Without `.gitforgeops/config.yaml`, `apply-on-merge.yml`
emits an empty matrix and deploys nothing, and `drift-check.yml` fails its
enumeration preflight. The synthetic `default` is never a trusted workflow
target.

`.gitforgeops/config.yaml`:

```yaml
version: 1

environments:
  production:
    # -> overlays/production/. The directory must exist, even if empty.
    overlay: production
    # Shared is the safer default: the repository manages only what it has
    # already applied, and anything else on the gateway is reported as
    # unmanaged and left alone.
    apply_strategy: incremental
    ownership:
      mode: shared

default_environment: production
```

The environment name must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`, because
it becomes a GitHub Actions matrix value, an `environment:` binding and a
`.state/<name>.json` path. It must also equal the GitHub Environment name the
bootstrap script created.

Never put a URL, secret name or credential in this file.

Make sure the overlay directory exists (the template ships it with a
`.gitkeep`):

```bash
mkdir -p overlays/production/ferrum/proxies
```

If a configured overlay directory is missing, every command for that
environment fails up front, naming the environment and the file that selected
it.

---

## 5. Set the environment secrets

```bash
gh secret set FERRUM_GATEWAY_URL        --repo OWNER/REPO --env production
gh secret set FERRUM_ADMIN_JWT_SECRET   --repo OWNER/REPO --env production
gh secret set GITFORGEOPS_STATE_APP_PRIVATE_KEY --repo OWNER/REPO --env production \
  < app-private-key.pem
gh secret set FERRUM_GH_PROVISIONER_TOKEN --repo OWNER/REPO --env production
gh secret set SETTINGS_AUDIT_TOKEN      --repo OWNER/REPO --env settings-audit
```

| Secret | Environment | Why |
| --- | --- | --- |
| `FERRUM_GATEWAY_URL` | `production` | must be `https://`. `http://` needs an explicit opt-in and is always refused in Actions for a non-loopback host. |
| `FERRUM_ADMIN_JWT_SECRET` | `production` | the gateway's own signing secret (at least 32 characters) |
| `GITFORGEOPS_STATE_APP_PRIVATE_KEY` | `production` | PEM key of the App from step 2 |
| `FERRUM_GH_PROVISIONER_TOKEN` | `production` | writes the credential-broker bundle secrets; needed as soon as a consumer uses `alloc=generate` |
| `SETTINGS_AUDIT_TOKEN` | `settings-audit` | fine-grained PAT or App token with **Administration: read** |

Four more are optional, but must match the gateway if it sets them:
`FERRUM_ADMIN_JWT_ISSUER` (default `ferrum-edge`), `FERRUM_ADMIN_JWT_ROLE`
(default `admin`), `FERRUM_ADMIN_JWT_AUDIENCE` (set only if the gateway
configures an audience) and `FERRUM_ADMIN_JWT_TTL_SECS` (default `3600`). A
mismatch here is the usual cause of a 401 partway through an apply.

Do **not** set `FERRUM_CREDS_BUNDLE[_N]`. The broker writes it on the first
apply that resolves an `alloc=generate` placeholder. You only seed it by hand
when adopting an existing gateway.

---

## 6. Write the resources

Everything lives in one namespace, `ferrum`, taken from the directory name. No
file sets a `namespace:` field.

`resources/ferrum/upstreams/orders.yaml`:

```yaml
kind: Upstream
spec:
  id: "orders-upstream"
  name: "Orders service"
  algorithm: round_robin
  targets:
    - host: "orders.internal"
      port: 8080
      weight: 1
```

`resources/ferrum/proxies/orders.yaml`:

```yaml
kind: Proxy
spec:
  id: "orders-proxy"
  name: "Orders API"
  listen_path: "/orders"
  backend_scheme: https
  backend_host: "orders.internal"
  backend_port: 8080
  strip_listen_path: true
```

`resources/ferrum/plugins/orders-key-auth.yaml`:

```yaml
kind: PluginConfig
spec:
  id: "orders-key-auth"
  plugin_name: "key_auth"
  # Scoped to one proxy: a global config of the same plugin_name would be
  # replaced by this one for that proxy.
  scope: proxy
  proxy_id: "orders-proxy"
  enabled: true
  config:
    key_location: "header:X-API-Key"
```

`resources/ferrum/consumers/orders-client.yaml`:

```yaml
kind: Consumer
spec:
  id: "orders-client"
  username: "orders-client"
  credentials:
    # The broker allocates this on the first apply and delivers it,
    # age-encrypted, to the pull request's author. Never write a literal
    # secret here: `apply` refuses the document before it reads a bundle.
    #
    # Slot: ferrum/orders-client/keyauth/key
    keyauth:
      - key: "${gh-env-secret:alloc=generate}"
```

An overlay that changes one key for production,
`overlays/production/ferrum/proxies/orders.yaml`:

```yaml
# Overlays deep-merge onto the resource of the same kind and id. Only the keys
# named here change; everything else comes from resources/.
kind: Proxy
spec:
  id: "orders-proxy"
  backend_host: "orders.prod.internal"
```

Delete the `_example.yaml` files the template ships under `resources/` once
your own resources are in place.

### Upload your SSH public key first

Credential delivery age-encrypts the generated key to an SSH public key on
your GitHub account, fetched from `GET /users/<you>/keys`. With no key on the
account there is nothing to encrypt to, and the slot is reported as
`NOT DELIVERED`. Add a key before the first apply and keep the matching private
key: you decrypt with `age -d -i ~/.ssh/id_ed25519`.

---

## 7. Check locally, then open the pull request

### Set up the local tools

Install Rust and build this repository with `cargo build`, then run the CLI as
`./target/debug/gitforgeops` (or install it with `cargo install --path .`).
`validate` calls a separate Ferrum Edge validator. Use the approved Ferrum Edge
v0.9.7 binary (SHA-256
`c26ba4c059be2d78f4044a3768ebfed5be4e7eb5640620fa93ea9199776b0902`), either on
`PATH` as `ferrum-edge` or selected with
`FERRUM_EDGE_BINARY_PATH=/path/to/ferrum-edge`. The bundled workflows check
this digest against `.github/ferrum-edge-checksums.txt` before use.

Install `age` to decrypt the delivered credential in step 8, and install
`python3` for the bootstrap script in step 3. To skip local validation, skip
the commands below and wait for `gitforgeops-required-static-validation` and
`rust-ci-check` on your pull request (`rust-ci-check` runs formatting, clippy
and unit tests when Rust inputs change).

```bash
./target/debug/gitforgeops validate                      # assembles and shells out to ferrum-edge validate
./target/debug/gitforgeops --env production plan         # validation + diff + breaking/security/policy + blockers
```

`plan` needs gateway credentials to compare against live state. Without them
it still reports every *offline* blocker (literal credentials, required
credential slots, schema, policy, security) and exits 1 if there are any.

Run `gitforgeops doctor` for local checks and GitHub metadata, then
`gitforgeops doctor --scope all --env production` once production gateway
credentials are available, for the read-only gateway checks. See
[README: Setup doctor](../README.md#setup-doctor). Doctor does not replace
`validate` (the gateway schema check) or `plan` (the live diff and
apply-blocker report).

Open the pull request. You should see:

- **`gitforgeops-required-static-validation`**: secretless assembly and schema
  validation, with no gateway contact.
- **`rust-ci-check`**, **`security-*`** and **`state-guard-reject-state-edits`**:
  the other required checks.
- **`GitForgeOps Trusted PR Live Review`**, waiting for the environment
  reviewer. Once approved, it posts a review comment listing the resources that
  would be added, the credential slots awaiting allocation, and the verdict.

Merge it. The required checks must pass; no approving review is required.

---

## 8. Approve the apply, and watch what lands

The merge triggers `GitForgeOps Apply`. It binds the `production` environment,
so it waits for approval until your required reviewer (someone other than
whoever merged) releases it.

Once approved, a successful run prints, among other lines:

```
Triggering commit: 4f2c…
Protected main HEAD: 4f2c…
...
Allocated 1 credential slot(s):
  ferrum/orders-client/keyauth/key -> @you (ssh SHA256:…)
Applied: 4 created, 0 updated, 0 deleted, 0 deletes deferred, 0 unmanaged skipped, 0 spec-owned skipped
convergence: mode=cp, 1 data-plane node(s), 0 mesh node(s) connected; oldest last_sync_at …
...
Pushed state on attempt 1.
```

Then check three things:

1. **A new commit on `main`** authored by `gitforgeops[bot]`,
   `chore(gitforgeops): state update for production`, touching only
   `.state/production.json`.
2. **A comment on your merged pull request** with an age-encrypted blob.
   Save it and decrypt it:
   ```bash
   age -d -i ~/.ssh/id_ed25519 < delivered.age
   ```
3. **Real traffic** with that key:
   ```bash
   curl -i https://your-gateway/orders -H "X-API-Key: <decrypted value>"
   curl -i https://your-gateway/orders            # expect 401 without it
   ```

If the second call succeeds, the scoped auth plugin is not attached. Check
that the plugin's `proxy_id` matches the proxy's `id`.

### Confirm the loop is closed

```bash
gitforgeops --env production diff --exit-on-drift   # exit 0: in sync
```

Re-running the apply must also change nothing. If it does, part of the
document normalizes differently from how the gateway stores it; open an issue
rather than working around it.

---

## Growing this: staging and production

Two environments run as **two independent matrix jobs**, each with its own
approval, its own concurrency group, and its own `.state/<env>.json`:

```yaml
version: 1

environments:
  staging:
    overlay: staging
    apply_strategy: incremental
    ownership:
      mode: shared

  production:
    overlay: production
    apply_strategy: incremental
    ownership:
      mode: shared

default_environment: staging
```

Both jobs start from the same merge with `fail-fast: false`, and **production
does not wait for staging**. A staging failure does not stop production.
Production is not promoted from staging; it reconciles the same source
revision with its own overlay.

For a real promotion path (staging applies, representative traffic is
verified, and only then is production authorized for the same revision), set
`promotion.requires: staging` on production and declare staging's checks in
`.gitforgeops/smoke.yaml`. See [Staged promotion](../README.md#staged-promotion).

---

## When something is wrong

| Symptom | Cause | Fix |
| --- | --- | --- |
| `GitForgeOps Apply` is green but deployed nothing | no `.gitforgeops/config.yaml` on `main` | step 4 — this is the skip, not a failure |
| `GitForgeOps Drift Check` fails its preflight | same | step 4 |
| Apply stuck at "waiting for approval" | the environment's required reviewer has not released it, and it cannot be the person who merged | §0, "Decide who approves what" |
| 401 from the gateway | a JWT claim does not match the gateway's configuration | step 5 — check all four of issuer, role, audience, TTL |
| `Superseded deployment` | a later merge changed a deployment input | [Recovering a superseded apply](../README.md#recovering-a-superseded-apply) |
| Settings audit red on a repository you intend to keep as a template | it is being audited as a deployment repository | set repository variable `GITFORGEOPS_TEMPLATE_REPO=true` |
| Credential delivered to the wrong person | the apply that allocated it was triggered by someone else's merge | rotate the slot with `rotate.yml` |

---

## Where to go next

- [GitHub launch controls](github-launch-controls.md) — the full settings
  baseline this quickstart applies a subset of.
- [Ownership modes](../README.md#ownership-modes) — when `shared` stops being
  the right answer.
- [Credential broker](../README.md#credential-broker-gh-env-secret-placeholders)
  — slots, sharding, rotation, and the hazard of reordering a credential array.
- [Adopting an existing gateway](../README.md#adopting-an-existing-gateway) —
  `import`, for a gateway that already has configuration on it.
- [Policy framework](../README.md#policy-framework-gitforgeopspoliciesyaml) —
  enforceable standards, all disabled by default.
