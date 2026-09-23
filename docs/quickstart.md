# Quickstart: one gateway, one namespace, one environment

The smallest setup that actually deploys: a single API-mode gateway, a single
namespace, shared ownership, one declared deployment environment, and the
security controls the bundled workflows require. Follow it end to end and you
finish with a proxy serving authenticated traffic, a broker-allocated consumer
credential delivered to you encrypted, and an ownership ledger committed to
`main` by the state-writer App.

Every file in this guide is the literal content of
[`tests/fixtures/quickstart/`](../tests/fixtures/quickstart/), which
`tests/unit/quickstart_tests.rs` loads, overlays and audits on every build. A
change that would break this copy-paste breaks that test first.

Detailed explanations live elsewhere and are linked where they matter; this
page is the order of operations.

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
non-zero, and the settings audit reports every reviewer-less environment. Pick
the shape before you provision anything. See
[GitHub plan requirements](../README.md#github-plan-requirements).

### Decide who approves what

Two different approvals, often confused:

| Approval | Who | Required here? |
| --- | --- | --- |
| **Pull request review** | any collaborator | **No.** The `main` ruleset sets `required_approving_review_count: 0`. A pull request is required; an approving review is not. A solo maintainer merges their own PR once the required checks pass. |
| **Environment approval** | a *required reviewer* on the deployment environment, who is not the person that triggered the run | **Yes**, and this one needs a second human. |

That second row is the one to plan around. The baseline sets
`prevent_self_review: true`, so the account that merged the pull request cannot
approve the apply it triggered. **A single-person repository cannot satisfy
both halves.** Name a second maintainer as the environment reviewer, or accept
that every apply waits for someone who is not you.

There is no supported "solo bypass" for that. The Repository Admin bypass actor
you may have seen is a *different* control — it is the fallback the bootstrap
uses on the `main` ruleset when no state-writer App exists yet, and the settings
audit reports it as a violation until you replace it with the App. It has
nothing to do with environment approvals and does not remove them.

### What this profile does and does not give you

| | api mode (this guide) | local CLI only | file / mesh output |
| --- | --- | --- | --- |
| Reconciles a running gateway | yes, through the admin REST API | no — you run commands by hand | no: it writes a document, it does not deploy one |
| Needs `.gitforgeops/config.yaml` | **yes** | no | **yes**, for the workflows |
| Ownership ledger in `.state/` | yes, committed by CI | not unless you run apply yourself | yes |
| Drift detection | yes (`drift-check.yml`) | on demand (`gitforgeops diff`) | no live surface to compare |
| Credential broker | yes | yes, with a local bundle | yes, plus a separate materialize step |

One consequence worth stating plainly: **assembling a file is not deploying
it.** In file mode `apply` writes `assembled/<env>.yaml` (and
`assembled/<env>-mesh.yaml` when the repository declares mesh fragments) and
commits it. Getting those documents onto a fleet is your own delivery step.

The sample configuration leaves `monitoring.unattended` unset, so scheduled
drift monitoring is approval-gated: its nightly run waits for the deployment
environment's required reviewer before it can read the gateway. To opt into
unattended checks, set `monitoring.unattended: true`; bootstrap creates and
binds a separate `<env>-monitor` environment. Set its secrets as described in
[launch controls §3.1](github-launch-controls.md#31-unattended-drift-monitoring).
The monitoring environment's admin JWT signing secret is write-equivalent at
the gateway, even though the workflow runs read-only commands. See the
[documented caveat](../README.md#unattended-monitoring-and-when-it-is-approval-gated)
before enabling it. You can also dispatch `gitforgeops diff --exit-on-drift`
yourself.

### Prerequisites

- `gh` authenticated as an account with **admin** on the repository.
- Admin access to a running Ferrum Edge gateway: its `https://` admin URL and
  its JWT signing secret.
- A second human who will be the environment's required reviewer (see above).

---

## 1. Create the repository from the template

Use the **Use this template** button, not a fork: a fork inherits neither
repository settings nor the ability to hold your own secrets cleanly.

Then, in **Actions → General**, enable workflows. A brand-new copy starts
enabled; GitHub disables *schedules* after 60 days of repository inactivity, so
check back if the repository goes quiet.

At this point you have a **template**: no `.gitforgeops/config.yaml`, no
deployment environment. Two workflows are supposed to be quiet about that, and
two are supposed to be loud:

| Workflow | With no config |
| --- | --- |
| `GitForgeOps Apply` | **skips** — empty environment matrix, a `::notice::`, green |
| `GitForgeOps Trusted PR Live Review` | **skips** — no live-review targets |
| `GitForgeOps Drift Check` | **fails** its preflight |
| `rotate`, `materialize-file` | **fail** — you started them, so absent configuration contradicts your intent |

An unconfigured repository skipping is intentional. An unconfigured repository
*failing* the workflows a human started is also intentional. Neither is a bug
to work around.

---

## 2. Create the state-writer GitHub App

`apply-on-merge.yml` and `rotate.yml` commit `.state/<env>.json` back to a
protected `main`. A direct push by `github-actions[bot]` is correctly rejected,
so they mint a short-lived installation token for a dedicated App instead.

Create it under Settings → Developer settings → GitHub Apps → **New GitHub
App**, with **Contents: read and write** as its only write permission, no
webhook, and repository access limited to this repository. Install it, note the
numeric **App ID**, and generate a private key.

```bash
gh variable set GITFORGEOPS_STATE_APP_ID --repo OWNER/REPO --body 123456
```

The App ID is a repository **variable** — public metadata, read identically by
the workflows and by the settings audit. The private key is an environment
**secret**, set in step 5.

Full reasoning: [launch controls §1](github-launch-controls.md#1-create-the-state-writer-github-app).

---

## 3. Apply the settings baseline

`bootstrap_repo_settings.py` writes the branch ruleset, Actions policy, labels,
the `settings-audit` environment, and your deployment environment. It is
idempotent, prints a plan without writing unless `--apply` is passed, and never
accepts or prints a secret value.

```bash
export GH_TOKEN=$(gh auth token)

python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO \
  --state-writer-app-id 123456 \
  --reviewer SECOND-MAINTAINER            # plan

python3 .github/scripts/bootstrap_repo_settings.py --repo OWNER/REPO \
  --state-writer-app-id 123456 \
  --reviewer SECOND-MAINTAINER --apply    # write
```

It finishes by listing the exact `gh secret set` commands left for you. Run
those in step 5.

`--reviewer` is the environment's required reviewer from §0. Without it, the
environment step reports `BLOCKED` rather than creating an environment nobody
has to approve.

---

## 4. Commit the repository configuration

**This file is what makes GitHub Actions deployment work at all.** Local CLI
use does not need it — `gitforgeops validate`, `diff` and `plan` fall back to a
synthetic local `default` environment driven purely by `FERRUM_*` variables.
The workflows do not: with no `.gitforgeops/config.yaml`, `apply-on-merge.yml`
emits an empty matrix and deploys nothing, and `drift-check.yml` fails its
enumeration preflight. The synthetic local default is never a trusted workflow
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

The environment name must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$` — it becomes
a GitHub Actions matrix value, an `environment:` binding, and a
`.state/<name>.json` path — and it must equal the GitHub Environment name the
bootstrap created.

No URL, no secret name, no credential ever goes in this file.

Create the overlay directory even though this first example does not override
anything yet:

```bash
mkdir -p overlays/production/ferrum/proxies
```

A configured overlay that is not in the tree fails every command for that
environment, up front, naming the environment and the file that selected it.

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
| `FERRUM_GATEWAY_URL` | `production` | must be `https://`; `http://` is refused unless you opt in, and never on a non-loopback host in Actions |
| `FERRUM_ADMIN_JWT_SECRET` | `production` | ≥ 32 characters, the gateway's own signing secret |
| `GITFORGEOPS_STATE_APP_PRIVATE_KEY` | `production` | PEM key of the App from step 2 |
| `FERRUM_GH_PROVISIONER_TOKEN` | `production` | writes the credential-broker bundle secrets; needed the moment a consumer uses `alloc=generate` |
| `SETTINGS_AUDIT_TOKEN` | `settings-audit` | fine-grained PAT or App token with **Administration: read** |

Four more are optional to configure and mandatory to match if your gateway
configures them: `FERRUM_ADMIN_JWT_ISSUER`, `FERRUM_ADMIN_JWT_ROLE`,
`FERRUM_ADMIN_JWT_AUDIENCE`, `FERRUM_ADMIN_JWT_TTL_SECS`. An unset one means
"use the documented default", not "send nothing" — and a gateway with no
audience rejects a token that carries one. Mismatches here are the usual cause
of a 401 halfway through an apply.

`FERRUM_CREDS_BUNDLE[_N]` is **not** on this list. The broker writes it on the
first apply that resolves an `alloc=generate` placeholder; you only seed it by
hand when adopting an existing gateway.

---

## 6. Write the resources

One namespace, `ferrum`, inferred from the directory. Nothing declares a
`namespace:` field.

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

And an overlay that changes one key for production —
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

Credential delivery age-encrypts the generated key to the SSH public key on
your GitHub account, fetched from `GET /users/<you>/keys`. With no key on the
account, delivery has nowhere to go. Add one before the first apply, and keep
the matching private key handy — you decrypt with
`age -d -i ~/.ssh/id_ed25519`.

---

## 7. Check locally, then open the pull request

### Set up the local tools

Install Rust and build this checked-out repository with `cargo build`; run the
CLI as `./target/debug/gitforgeops` (or install it with `cargo install
--path .`). `validate` invokes a separate Ferrum Edge validator. Use the
repository-approved Ferrum Edge v0.9.5 binary (SHA-256
`31573f0afab23694ce0cfe432f1220dd38099e3ee643e8c5d5b6d2bb3488297c`),
installed on `PATH` as `ferrum-edge` or selected with
`FERRUM_EDGE_BINARY_PATH=/path/to/ferrum-edge`. The bundled workflows verify
this digest against `.github/ferrum-edge-checksums.txt` before use.

Install `age` for decrypting the delivered credential in step 8, and install
`python3` for the bootstrap commands in steps 3 and 5. If you prefer not to
set up local validation, skip the commands below and wait for
`gitforgeops-required-static-validation` and `rust-ci-check` on your pull
request; the latter runs formatting, clippy and unit tests for Rust changes.

```bash
./target/debug/gitforgeops validate                      # assembles and shells out to ferrum-edge validate
./target/debug/gitforgeops --env production plan         # validation + diff + breaking/security/policy + blockers
```

`plan` needs gateway credentials to compare against live state. Without them it
still reports every *offline* blocker — literal credentials, required
credential slots, schema, policy, security — and exits 1 if any exist.

Run `gitforgeops doctor` for local checks and GitHub metadata, then
`gitforgeops doctor --scope all --env production` when production gateway
credentials are available for the read-only gateway checks. See
[README: Setup doctor](../README.md#setup-doctor). Keep `validate` for the
gateway schema check and `plan` for the live diff and apply-blocker report;
doctor does not replace either command.

Open the pull request. You should see:

- **`gitforgeops-required-static-validation`** — secretless assembly and schema
  validation, no gateway contact.
- **`rust-ci-check`**, **`security-*`**, **`state-guard-reject-state-edits`** —
  the required checks.
- A **GitForgeOps review comment** listing the resources that would be added,
  the credential slots awaiting allocation, and the verdict.

Merge it. Zero approving reviews are required; the checks are.

---

## 8. Approve the apply, and watch what lands

The merge triggers `GitForgeOps Apply`. It binds the `production` environment,
so it stops at **waiting for approval** until your required reviewer — someone
other than whoever merged — releases it.

Once approved, the successful run prints, in this order:

```
Triggering commit: 4f2c…
Protected main HEAD: 4f2c…
...
CREATE Upstream orders-upstream
CREATE PluginConfig orders-key-auth
CREATE Proxy orders-proxy
CREATE Consumer orders-client
Allocated credential slot ferrum/orders-client/keyauth/key
convergence: mode=cp, 1 data plane connected, oldest last_sync_at ...
Pushed state on attempt 1.
```

Three things to verify afterwards:

1. **A new commit on `main`** authored by `gitforgeops[bot]`:
   `chore(gitforgeops): state update for production`, touching
   `.state/production.json` only.
2. **A comment on your merged pull request** carrying an age-encrypted blob.
   Decrypt it:
   ```bash
   age -d -i ~/.ssh/id_ed25519 < delivered.age
   ```
3. **Real traffic**, using that key:
   ```bash
   curl -i https://your-gateway/orders -H "X-API-Key: <decrypted value>"
   curl -i https://your-gateway/orders            # expect 401 without it
   ```

If the second call succeeds, the scoped auth plugin is not attached — check
that the plugin's `proxy_id` matches the proxy's `id`.

### Confirm the loop is closed

```bash
gitforgeops --env production diff --exit-on-drift   # exit 0: in sync
```

Re-running the apply must also be a no-op. If it is not, something in the
document normalizes differently than the gateway stores it; open an issue
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

Be clear about what that is and is not. Both jobs start from the same merge,
`fail-fast: false`, and **production does not wait for staging**. Staging
failing does not stop production, and production is not "promoted" from
anything — it reconciles the same source revision with its own overlay.

If you want a real promotion path — staging applies, representative traffic is
verified, and only then is production authorized for the same revision — opt
production into it with `promotion.requires: staging` and declare staging's
checks in `.gitforgeops/smoke.yaml`; see
[Staged promotion](../README.md#staged-promotion). Do not read parallel matrix
jobs as staged rollout.

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
