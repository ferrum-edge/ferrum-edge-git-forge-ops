# Ferrum Edge GitForgeOps

GitOps workflow for managing [Ferrum Edge](https://github.com/ferrum-edge/ferrum-edge) gateway configuration via pull requests. Fork, configure, and get a full multi-environment pipeline: PR-based submission, policy-enforced review, scoped apply, credential brokering, and drift monitoring — **without** leaving GitHub's free tier and **without** any third-party secret manager.

## Headline features

- **Multi-environment from one repo** — declare staging/production/sandbox/etc. in `.gitforgeops/config.yaml`, deploy each to its own gateway via GitHub Environments. No per-env branches, no per-env repos.
- **Ownership modes** — `shared` (default): repo only touches what it has previously applied; admin-added resources are left alone. `exclusive`: repo is authoritative for a namespace set.
- **Extensible policy framework** — opt-in rules (timeout bands, HTTPS-only backends, required auth, …) block PRs that violate organization standards. Override via labeled PR from a write-permission user.
- **In-GitHub credential broker** — consumer secrets never live in the repo. Placeholders (`${gh-env-secret:alloc=generate}`) are resolved from GitHub Environment Secrets at apply time. New values are generated, libsodium-sealed, written to env secrets via the REST API, and age-encrypted to the PR author's SSH key for one-time delivery.
- **Drift detection with awareness of ownership** — scheduled comparisons surface changes on both sides, filtering the noise based on the env's configured mode.
- **Free-tier only** — GitHub Secrets, GitHub Environments, GitHub Actions, GitHub API. No Vault, no AWS, no 1Password required.

## Quick start

1. Fork this repo.
2. **Create a GitHub Environment per deployment target** (Settings → Environments → New). Name it whatever you want to call the environment — e.g. `staging`, `production`. Add its scoped secrets: `FERRUM_GATEWAY_URL`, `FERRUM_ADMIN_JWT_SECRET`, and any TLS material. Optionally set protection rules (required reviewers, wait timers).
3. **Declare those environments in `.gitforgeops/config.yaml`** — see `.gitforgeops/config.example.yaml`. The file carries overlay names and ownership modes; it does *not* carry any secret or URL.
4. Add resources under `resources/<namespace>/{proxies,consumers,upstreams,plugins}/*.yaml`.
5. Open a PR. CI runs the matrix across every declared environment, posts a review comment per env, and blocks merge on policy/validation failures.
6. Merge. `apply-on-merge.yml` applies to each environment in parallel (per-env concurrency lock prevents clobbering).

## Repository layout

```
.gitforgeops/
  config.yaml                    # environments, overlays, ownership modes
  policies.yaml                  # optional policy rules + override config

resources/
  ferrum/                        # namespace: ferrum
    proxies/
      my-api.yaml                # kind: Proxy
    consumers/
      alice.yaml                 # kind: Consumer
    upstreams/
      api-cluster.yaml           # kind: Upstream
    plugins/
      rate-limit.yaml            # kind: PluginConfig
  team-alpha/                    # namespace: team-alpha
    proxies/
      alpha-service.yaml

overlays/                        # environment-specific deep-merge fragments
  staging/
    ferrum/proxies/my-api.yaml   # overrides backend_host, timeouts, etc.
  production/
    ferrum/proxies/my-api.yaml

.state/                          # auto-committed by CI, per environment
  staging.json
  production.json

.github/workflows/
  validate-pr.yml                # matrix validate + review per env
  apply-on-merge.yml             # matrix apply per env (with env binding)
  drift-check.yml                # scheduled diff per env
  rotate.yml                     # workflow_dispatch for credential rotation
  materialize-file.yml           # workflow_dispatch for encrypted flat-file delivery
  release.yml                    # builds multi-arch image on push to main / v* tag
```

### What a single PR can change

One PR can include any number of new, modified, or deleted resources across any number of namespaces, in any mix of kinds (proxies, consumers, upstreams, plugin configs). The loader walks every `resources/<namespace>/{proxies,consumers,upstreams,plugins}/` directory, the assembler flattens into a single `GatewayConfig`, and apply groups by namespace on the way out — each namespace gets its own `X-Ferrum-Namespace` header and its own incremental diff against the live gateway. Namespaces are isolated: a failure applying to `team-alpha` doesn't block `team-beta`.

## Repo configuration: `.gitforgeops/config.yaml`

This is the single file that declares environments. Each entry picks an
overlay, apply strategy, and ownership mode. **No URLs, no secret names, no
credentials ever live here.**

```yaml
version: 1

environments:
  staging:
    overlay: staging             # → overlays/staging/
    apply_strategy: incremental
    ownership:
      mode: shared               # safer; repo only manages what it declared
      drift_report: true

  production:
    overlay: production
    apply_strategy: full_replace
    ownership:
      mode: exclusive            # repo is authoritative for these namespaces
      namespaces: [ferrum]
      large_prune_threshold_percent: 25

default_environment: staging
```

The environment names here must match the GitHub Environments you've set up in repo settings. The apply workflow binds `environment: ${{ matrix.environment }}` and GitHub injects that environment's secrets automatically.

## Ownership modes

`gitforgeops` classifies every gateway resource as one of:

1. **Declared** — in the repo's desired config right now.
2. **Previously managed** — repo applied it before, not declared now (intentional removal).
3. **Unmanaged** — exists on the gateway, repo never put it there.

### `shared` (default, safer)

- Add/modify declared resources → applied normally.
- Previously managed but removed from repo → deleted.
- Unmanaged resources → **left alone, reported in PR review**.
- `full_replace` is rejected (would wipe unmanaged resources).

Choose this when ops teams or admins still make changes via the GUI alongside the repo, or for sandbox environments where experimentation is fine.

### `exclusive` (strict 1:1)

- Repo is authoritative for the listed `namespaces`.
- Unmanaged resources in those namespaces → **pruned**.
- Requires explicit `namespaces` list (safety rail against misconfiguration).
- `large_prune_threshold_percent` guards against runaway deletions. Default 25%: if an apply would delete more than 25% of the managed set, it refuses unless `--allow-large-prune` is passed.

Choose this for production or regulated environments where git is the single source of truth.

### First-apply behavior

In `shared` mode, the first apply (when `.state/<env>.json` doesn't yet exist) treats **all** gateway resources as unmanaged. A loud warning goes to the apply output; nothing is deleted. The state file is written at the end, so subsequent applies distinguish between bucket 2 and bucket 3 correctly.

## Policy framework: `.gitforgeops/policies.yaml`

Enforce organization standards across every PR. All rules default off (opt-in).

```yaml
version: 1

policies:
  proxy_timeout_bands:
    enabled: true
    severity: error              # error | warning | info
    connect_timeout_ms: { min: 500,  max: 15000 }
    read_timeout_ms:    { min: 1000, max: 60000 }
    write_timeout_ms:   { min: 1000, max: 60000 }

  backend_scheme:
    enabled: true
    severity: error
    allowed_protocols: [https, wss, grpcs]

  require_auth_plugin:
    enabled: false
    severity: error
    auth_plugin_names: [jwt, key_auth, basic_auth, oauth2, oidc]

  forbid_tls_verify_disabled:
    enabled: false
    severity: error

  allowed_proxy_plugins:
    enabled: false
    severity: error
    allowed_plugin_names: [jwt, key_auth, rate_limiting]

  allowed_backend_domains:
    enabled: false
    severity: error
    allowed_domains:
      - api.internal.example.com
      - "*.svc.cluster.local"
      - "*.corp.example.com"

overrides:
  require_label: gitforgeops/policy-override
  required_permission: write     # admin | maintain | write
```

### Rule semantics

- `severity: error` → **blocks `gitforgeops apply`** until the violation is fixed or overridden.
- `severity: warning` / `info` → surfaced in PR review, but apply proceeds.
- Each violation includes the rule id, the resource, the current value, and a remediation hint in the PR comment.
- `allowed_backend_domains` checks both direct proxy `backend_host` values and upstream `targets[*].host` values. `*.example.com` matches subdomains like `api.example.com` and `deep.api.example.com`; list `example.com` separately if the root domain is allowed too.
- `allowed_proxy_plugins` checks plugin configs explicitly referenced from a proxy's `plugins:` list, matching `plugin_name` case-insensitively.

### Override flow (B2: label + permission)

1. Someone with `write` repo permission (or higher — configurable) adds the `gitforgeops/policy-override` label to the PR.
2. On next workflow run, gitforgeops fetches the PR labels and checks the labeler's permission via the GitHub API.
3. If both checks pass, error-severity findings get annotated `OVERRIDDEN by @user` and no longer block apply.
4. The override event is recorded in `.state/<env>.json.overrides` for audit.

If you want two-person separation-of-duties instead of one-person override, change `required_permission: admin` and only grant admin to a small group — the check is strictly `>=` on the permission rank (`admin > maintain > write > triage > read`).

### Adding a new policy rule

1. Create `src/policy/rules/my_rule.rs` implementing `PolicyCheck`.
2. Add its typed config to `src/policy/config.rs::PolicyRules`.
3. Register it in `src/policy/registry.rs::build_registry`.
4. Write a test in `tests/unit/policy_tests.rs`.
5. Document the rule and its config in `.gitforgeops/policies.example.yaml`.

No changes to `plan` / `review` / `apply` required — those iterate the registry.

## Credential broker: `${gh-env-secret:...}` placeholders

Consumer credentials never live in the repo. Example:

```yaml
kind: Consumer
spec:
  id: app-mobile
  namespace: ferrum
  credentials:
    api_key:
      key: "${gh-env-secret:alloc=generate}"
    basic_auth:
      username: app-mobile
      password: "${gh-env-secret:alloc=generate|len=48}"
```

### Placeholder syntax

```
${gh-env-secret:alloc=<mode>|len=<bytes>}
```

- `alloc=require` (default) — the value must already exist in the bundle; apply fails if it doesn't.
- `alloc=generate` — if the value is missing, generate a new one on apply.
- `alloc=rotate` — marker for "this slot is eligible for rotation." Behaves identically to `generate` at apply time: first apply allocates, subsequent applies reuse the stored value. **Re-rotation is explicit** — trigger the `rotate.yml` workflow (see below) with a specific slot and recipient. The previous auto-rotate-on-every-apply behavior was removed because it redelivered persistent rotate slots to whichever user merged the latest PR, even when their PR didn't touch the consumer.
- `len=<16..=256>` — bytes of entropy for generated values. Default 32.

Slot names are derived automatically from `(namespace, consumer_id, cred_key)` — you don't write them anywhere. Renaming a consumer gets a new slot (and the ability to intentionally retire the old one).

### Storage: bundled environment secrets

Secrets are stored as JSON bundles inside **GitHub Environment Secrets** named `FERRUM_CREDS_BUNDLE`, `FERRUM_CREDS_BUNDLE_1`, `FERRUM_CREDS_BUNDLE_2`, …

- Each bundle is a JSON object: `{ "<slot>": "<value>", ... }`.
- Single bundle holds ~440 credentials at 48 KB GitHub secret cap.
- Auto-sharded by deterministic hash when any bundle approaches 40 KB.
- GitHub's 100-secrets-per-env limit × ~440 slots/bundle = **~44,000 credentials per environment** before you hit any ceiling.

The apply workflow reads all matching secrets via `${{ toJSON(secrets) }}`, filters `FERRUM_CREDS_BUNDLE*`, and merges into `FERRUM_CREDS_JSON` for the binary.

### Allocation, writing, and delivery

On apply, for each `alloc=generate` or first-apply `alloc=rotate` placeholder with no existing value:

1. Generate a 32-byte (or `len=`) random value with `OsRng`.
2. Fetch the env's libsodium public key from `GET /repos/.../environments/<env>/secrets/public-key`.
3. Encrypt the updated bundle with `crypto_box_seal` and `PUT` to `/repos/.../environments/<env>/secrets/FERRUM_CREDS_BUNDLE[_N]`.
4. Fetch the PR author's SSH public keys from `GET /users/{login}/keys`.
5. Encrypt the new value with age to an Ed25519 (preferred) or RSA SSH recipient.
6. Post an age-armored blob as a comment on the PR; the author decrypts locally.

Requires `FERRUM_GH_PROVISIONER_TOKEN` — a GitHub App installation token (preferred, short-lived) or a fine-grained PAT with `Secrets: write` + `Environments: write`. Everything stays inside GitHub.

### Rotation

Trigger the `rotate.yml` workflow manually:

```
Actions → GitForgeOps Rotate Credential → Run workflow
  environment: production
  consumer: app-mobile
  credential: api_key
```

The rotation re-generates the value, overwrites the env secret, pushes the new value to the gateway via the normal apply path, and delivers age-encrypted to `${{ github.actor }}` (whoever triggered the workflow).

### File mode (two-stage)

File-mode gateways consume a single assembled YAML at boot. We can't commit that with credentials inlined — it would defeat the whole point of the broker. So file mode is two stages:

**Stage 1 — placeholder assembly (automatic, on every merge)**

`apply-on-merge.yml` in file mode runs `gitforgeops export --output assembled/<env>.yaml` **without** resolving credentials. The committed file still contains the `${gh-env-secret:alloc=...}` strings for each consumer credential — safe for version control, useful as a diff artifact for PR review, useless to an attacker.

**Stage 2 — on-demand materialization (admin-initiated, delivered encrypted)**

When an admin needs the real file (to deploy it, test locally, inspect the full config), they trigger the `materialize-file.yml` workflow:

```
Actions → GitForgeOps Materialize File → Run workflow
  environment: production
```

The workflow:

1. Binds `environment: production` — pulls that env's `FERRUM_CREDS_BUNDLE*` secrets.
2. Runs `gitforgeops export --materialize --encrypt-to ${{ github.actor }}`:
   - Replaces placeholders with real values from the bundle.
   - Refuses if any slot needs allocation (tells the admin to run `apply` first).
   - Age-encrypts the entire YAML to the actor's GitHub-published SSH public key.
3. Uploads the `.age` blob as a workflow artifact with **1-day retention**.

The admin downloads the artifact and decrypts locally:

```bash
age -d -i ~/.ssh/id_ed25519 < assembled-production.age > assembled.yaml
```

The plaintext file never touches the repo, never lives in workflow logs, never leaves the admin's laptop.

Access to Stage 2 is controlled by GitHub Environment protection rules on the target environment: required reviewers, branch restrictions, wait timers. Everything is in `github.com` — no external secret manager, no new auth primitives.

If the admin has no compatible SSH key on their GitHub account, materialization fails with a pointer to `https://github.com/settings/keys`.

### Audit trail

`.state/<env>.json.credentials[slot]` records:
- `last_rotated` timestamp
- `sha256_prefix` (first 16 hex chars of the value's hash — enough to confirm "gateway matches store," not enough to brute-force)
- `delivered_to` login, `delivered_run_id` workflow run number

These are committed to git automatically by the apply workflow, so `git log .state/<env>.json` is the credential history.

## Logistics: scale characteristics

Practical limits you should know about:

| Dimension | Limit | Notes |
|---|---|---|
| Environments per repo | ~100 (soft) | Each needs its own GitHub Environment; workflow matrix spreads to parallel jobs. GitHub Actions caps concurrent jobs at 20 on free public, 60+ on paid tiers. |
| Namespaces per environment | Unbounded | Handled by the gateway; repo just groups them. |
| Resources per apply | Unbounded in file mode; gateway-limited in API mode. | Incremental mode fetches `/backup` once per namespace and diffs locally. |
| Consumer credential slots per env | ~44,000 | 100 env secrets × ~440 slots/bundle. Not a soft limit you will hit. |
| Policy rules | Unbounded | Each adds ~50 µs per apply at 1k resources. |
| Apply wall-clock time | Dominated by `/backup` fetch + per-resource API writes. | Roughly O(changed resources) in incremental mode. `full_replace` is constant time but bigger blast radius. |
| Credential bundle write concurrency | Serialized per env via `concurrency: ferrum-apply-${{ matrix.environment }}`. | Within an env, two apply/rotate runs never interleave. Across envs they parallelize. |
| PR review latency | ~30-90s typical per env matrix job. | Dominated by `cargo install` (cached after first run). |
| State file size | ~1-2 KB per 100 resources. | Committed to git; watch `git log` if it grows unexpectedly. |

### How this scales out in real setups

- **Solo maintainer, one gateway** — one environment (`default`), no `.gitforgeops/config.yaml` needed (tool falls back to env-var driven behavior). Credential broker still works if you set up one GitHub Environment.
- **Small team, staging + prod** — two environments, matrix runs two jobs in parallel, two `.state/*.json` files, two sets of env secrets. The most common setup.
- **Platform team, 5-10 environments** — matrix scales linearly. Protection rules on GitHub Environments (required reviewers for production, wait timers for canary, etc.) enforce deployment gates without code changes.
- **Multi-tenant platform, 50+ namespaces in one env** — per-namespace ownership is still via `FERRUM_NAMESPACE` filter + `ownership.namespaces` list; the single apply pass handles all of them. For bigger scale, split into multiple environments backed by the same gateway with `FERRUM_NAMESPACE` acting as a slice.

### What does *not* scale

- **Single-shot overrides for every commit.** If every PR needs an override label, tighten or disable the rule instead — overrides are break-glass, not routine.
- **Full-replace on a gateway with >10k resources.** The atomic POST to `/restore` gets heavy; consider incremental mode there.
- **Manual credential allocation.** The broker is designed for auto-generate; avoid `alloc=require` for new slots unless you pre-populate them.

## Failure recovery

There's no hard limit in `gitforgeops` on how many resources a single PR can add, modify, or delete. The loader streams one file at a time, the assembler flattens into a `GatewayConfig` in memory (tens of MB even at tens of thousands of resources), and apply runs per namespace.

- **Sequential per-resource HTTP calls in incremental mode.** One PUT / DELETE / POST per changed resource. At ~100 ms round-trip per call, 1,000 changes take roughly 2 minutes. 10,000 changes would take ~20 minutes but are not fundamentally problematic.
- **Full-replace mode is one HTTP call per namespace.** `FERRUM_APPLY_STRATEGY=full_replace` calls `POST /restore?confirm=true` once per namespace in scope. The `/restore` call is atomic for the single namespace it targets, but **atomicity does not extend across namespaces** — an exclusive-mode env with `ownership.namespaces: [alpha, beta]` issues two independent restores, and if `beta` fails after `alpha` succeeded, `alpha` is already replaced on the gateway side. The apply loop records every namespace that fails (instead of bailing on the first) so the error message enumerates partial state, but operators must reconcile it manually. For strict environment-wide atomicity, scope `full_replace` to a single namespace.
- **Namespaces apply independently.** `apply_api` iterates `split_config_by_namespace` and applies each namespace in turn. A failure applying to `team-alpha` doesn't abort `team-beta` — you get per-namespace error reporting via `ApplyResult`.

### Retry behavior

Every admin-API call goes through `AdminClient::send_with_retry`, which retries up to `FERRUM_GATEWAY_MAX_RETRIES` (default 3) on:

- **Connection errors** (`reqwest::Error::is_connect()`) — the server never saw the request, so retry is always safe.
- **HTTP 5xx** — server-side transient; ferrum-edge admin endpoints are idempotent for PUT/DELETE/POST-batch/POST-restore, and create-paths surface 409 on retry races (visible in `ApplyResult.errors`).
- **HTTP 429** — inherently transient.

Backoff is exponential (`500ms · 2^attempt`) capped at 8 seconds.

What we deliberately don't retry:

- **Request timeouts** — a timeout means state is ambiguous (gateway may or may not have applied). Retrying a large `/restore` after timeout could double-write. The next CI run re-diffs and converges.
- **4xx other than 429** — 400/401/403/404/409/422 are permanent.

**Partial-failure visibility** (incremental mode): errors are collected per resource rather than bailing on first failure. A run where 99 of 100 resources apply cleanly but 1 hits a 400 returns an `ApplyResult` with 99 successes and 1 error. CLI exits non-zero; you see exactly which resource failed and why.

### What if apply fails after merge?

The merge commit is already on `main`, but config isn't (fully) applied. Re-run the failed `GitForgeOps Apply` workflow from the Actions tab. Re-run is safe because:

1. Incremental mode re-fetches actual state via `GET /backup`, so already-applied resources are skipped.
2. Full-replace mode is idempotent — `POST /restore` converges regardless of prior partial state.
3. `.state/<env>.json` is a hash manifest of the *last successful* apply; it never causes re-runs to skip work.

If a resource is permanently broken (bad schema, illegal listen_path collision), fix it in a follow-up PR.

## Timeouts

Every call to the admin API is bounded by two timeouts so CI never hangs:

- **Connect timeout** (`FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS`, default `10s`) — TCP handshake + TLS negotiation. reqwest's pool may reuse connections within a run.
- **Request timeout** (`FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS`, default `60s`) — end-to-end cap per request, including body send and response read.

Commonly tuned when:

- `GET /backup` on very large configs takes >60s — raise request timeout.
- `POST /restore` on slow-commit gateways (large MongoDB transactions, high replication lag) — raise request timeout.
- Gateway behind a slow LB or cold NLB — raise connect timeout.

The same bounding applies to the GitHub API call used by `gitforgeops review --pr N` via `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` (default 10s) and `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` (default 30s).

## Configuration reference

Only three kinds of configuration source exist:

1. **`.gitforgeops/config.yaml` and `.gitforgeops/policies.yaml`** — logical shape of the deployment. Committed to the repo.
2. **GitHub Environment Secrets** — deployment targets and credentials. Scoped per environment. Set in repo settings, never in the codebase.
3. **Environment variables** — runtime overrides, mostly for local development.

### Per-environment GitHub Environment secrets

| Secret | Required | Description |
|---|---|---|
| `FERRUM_GATEWAY_URL` | yes (api mode) | Admin API base URL |
| `FERRUM_ADMIN_JWT_SECRET` | yes (api mode) | HS256 secret for minting admin JWTs; min 32 chars |
| `FERRUM_GATEWAY_CA_CERT` | no | Custom CA (base64 PEM) |
| `FERRUM_GATEWAY_CLIENT_CERT` | no | Client cert for mTLS (base64 PEM) |
| `FERRUM_GATEWAY_CLIENT_KEY` | no | Client key for mTLS (base64 PEM, required if cert is set) |
| `FERRUM_GH_PROVISIONER_TOKEN` | no (required for allocate/rotate) | GitHub App installation token or PAT with `Secrets: write` + `Environments: write` |
| `FERRUM_CREDS_BUNDLE[_N]` | managed by broker | Credential bundles — **you generally never touch these by hand** |

### Repo-wide variables (Settings → Variables)

| Variable | Default | Description |
|---|---|---|
| `FERRUM_GATEWAY_MODE` | `api` | `api` = push via Admin API, `file` = assemble flat YAML (two-stage) |
| `FERRUM_NAMESPACE` | — | Filter to one namespace. Omit to process all. |
| `FERRUM_APPLY_STRATEGY` | `incremental` | `incremental` (CRUD) or `full_replace` (POST /restore). Ignored when repo config sets it. |
| `FERRUM_OVERLAY` | — | Legacy overlay selector (superseded by `FERRUM_ENV` + repo config) |
| `FERRUM_EDGE_VERSION` | `latest` | Ferrum Edge release tag for validation binary (e.g. `v0.9.0`). Pin this to match your runtime. |
| `FERRUM_TLS_NO_VERIFY` | `false` | Skip TLS verification (dev only) |
| `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `10` | Timeout for TCP/TLS connection to the admin API. Raise if the gateway is behind a slow LB. |
| `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `60` | Total HTTP request timeout (connect + send + receive). Raise for very large `/backup` responses or slow `/restore` commits. |
| `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` | `10` | Timeout for TCP/TLS connection to `api.github.com` when posting PR review comments. |
| `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` | `30` | Total HTTP timeout for the GitHub API call used by `gitforgeops review --pr N`. |
| `FERRUM_GATEWAY_MAX_RETRIES` | `3` | Retries on transient admin-API failures (connection errors, 5xx, 429). `0` disables. |
| `GITFORGEOPS_RELEASE_ENABLED` | `false` (on forks) | Opt a fork into running the `release` workflow. Upstream always publishes regardless. |
| `DOCKERHUB_IMAGE` | `ferrumedge/ferrum-edge-git-forge-ops` | Where the `release` workflow pushes on Docker Hub. Only matters if `GITFORGEOPS_RELEASE_ENABLED=true`. GHCR path is auto-derived from the repo. |

### Docker Hub secrets (upstream maintainers / forks publishing their own image only)

**Forks don't need these.** The `release` workflow is gated; forks consume the already-published `ferrumedge/ferrum-edge-git-forge-ops` image and skip the build.

Required only if you're the upstream maintainer, or if your fork has opted in via `GITFORGEOPS_RELEASE_ENABLED=true`:

| Secret | Description |
|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub account that owns the target namespace |
| `DOCKERHUB_TOKEN` | Docker Hub access token with push access |

The `release` workflow also pushes to GHCR using the built-in `GITHUB_TOKEN` — no extra secret needed. Ensure Settings → Actions → General → Workflow permissions is set to **Read and write** so `GITHUB_TOKEN` can push to `ghcr.io/<owner>/…`.

### Local environment variables

See `.env.example`. Essentials for running `gitforgeops` on your laptop:

- `FERRUM_ENV=<name>` — pick an environment from `.gitforgeops/config.yaml`
- `FERRUM_GATEWAY_URL` + `FERRUM_ADMIN_JWT_SECRET` — connect to a live gateway
- `FERRUM_CREDS_JSON` — manually provide the bundle for local apply tests

## CLI reference

All commands accept `--env <name>` globally.

```
gitforgeops validate [--format text|json|github-annotations]
gitforgeops diff [--exit-on-drift]
gitforgeops plan
gitforgeops apply [--auto-approve] [--allow-large-prune]
gitforgeops export [--output PATH] [--materialize] [--encrypt-to GH_LOGIN]
gitforgeops import --from-api | --from-file PATH [--output-dir DIR]
gitforgeops review [--pr N]
gitforgeops envs [--format json|text]           # for CI matrix discovery
gitforgeops rotate --consumer ID --credential KEY \
  [--namespace NS] [--recipient GH_LOGIN]
```

## PR review output

```markdown
Environment: `staging` · Ownership: `Shared` · Strategy: `Incremental`

## Ferrum Edge Config Review

### Validation: PASSED

### Changes
| Action | Kind | ID | Details |
|--------|------|----|---------|
| Add | Proxy | new-service | - |
| Modify | Proxy | my-api | backend_read_timeout_ms |

### Unmanaged Resources (shared mode)
These resources exist on the gateway but were not applied by this repo. They will not be modified or deleted.
- **Proxy `admin-experiment`** (`ferrum`)

### Policy Violations
- [error] `backend_scheme` on **Proxy `my-api`** (`ferrum`): backend_protocol=http is not in the allowed list (https, wss, grpcs) · BLOCKING
  - _Change backend_protocol to one of: https, wss, grpcs_

> **Apply is blocked** until the listed violations are resolved. To override, add the `gitforgeops/policy-override` label (requires `write` permission on this repo).

### Credential Slots
| Slot | Status |
|------|--------|
| `ferrum/app-mobile/api_key` | needs allocation (generated on apply) |
| `ferrum/web-portal/api_key` | resolved |

### Breaking Changes
- **Proxy `my-api`**: backend_protocol change (http → https) will reject existing connections

### Security Findings
- [WARNING] **Proxy `new-service`**: No auth plugin attached

### Best Practice Recommendations
- **Proxy `new-service`**: Consider adding rate_limiting plugin
```

## Trust and security posture

- **Fork PRs cannot see production secrets.** The `validate-pr.yml` workflow runs with no `environment:` binding, so GitHub Environment Secrets are not available. Contributors can propose credential slots but cannot cause allocation.
- **Apply only runs post-merge on `main`.** `apply-on-merge.yml` binds the environment; GitHub enforces protection rules (required reviewers, branch restrictions).
- **Credential values are never written back to the repo.** Only hashes and metadata in `.state/`.
- **Policy overrides leave a permanent trail.** PR label event + approver permission + `.state/<env>.json.overrides` record.
- **The provisioner token is the bootstrap credential.** Rotate periodically; prefer GitHub App installation tokens over PATs (automatic 1-hour expiry, org-scoped).
- **TLS material stays as GitHub secrets.** The binary only ever sees the base64-decoded PEM in-process.

## Drift detection

`drift-check.yml` runs nightly (configurable via cron). Per environment:

- `shared` mode: reports on managed-modified and managed-deleted by default. Unmanaged additions are informational and don't alert (configurable via `drift_alert_on`).
- `exclusive` mode: any unmanaged resource is drift. Exit non-zero, workflow fails.

```bash
# Run once manually from the Actions tab, or via CLI:
gitforgeops --env production diff --exit-on-drift
```

## Docker

A Dockerfile is included that bundles both `gitforgeops` and `ferrum-edge` into a single image. The `ferrum-edge` binary is copied from the official `ferrumedge/ferrum-edge` Docker Hub image; `gitforgeops` is compiled from source in a builder stage.

### Published images

The `release` workflow publishes to two registries on every push to `main` and every `v*` tag:

- `docker.io/ferrumedge/ferrum-edge-git-forge-ops`
- `ghcr.io/ferrum-edge/ferrum-edge-git-forge-ops`

Tags:

| Trigger | Tags published |
|---|---|
| push to `main` | `:latest`, `:main-<sha>` |
| push of `v0.1.0` | `:0.1.0`, `:0.1`, `:v0.1.0` |

Platforms: `linux/amd64` + `linux/arm64`.

### Prerequisites for the release workflow

1. Docker Hub repo `ferrumedge/ferrum-edge-git-forge-ops` exists (public)
2. Repo secrets `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` are set
3. Settings → Actions → General → Workflow permissions = **Read and write** (for GHCR push)

### Building locally

```bash
docker build -t gitforgeops .
docker build --build-arg FERRUM_EDGE_VERSION=v0.9.0 -t gitforgeops .

docker run --rm -v $(pwd):/repo gitforgeops --env staging validate
```

## Build, test, lint

```
cargo build                                    # Debug
cargo build --release
cargo test --test unit_tests                   # 89+ tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI runs all four on every PR.

### Publishing your own fork's image

If you'd rather not depend on the upstream image (air-gapped env, vendored build, divergent customizations), your fork can publish its own:

1. Create a Docker Hub repo you can push to (e.g. `acme/ferrum-edge-git-forge-ops`).
2. Set repo secrets `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN`.
3. Set repo variables:
   - `GITFORGEOPS_RELEASE_ENABLED=true` — opts the fork into running `release.yml`.
   - `DOCKERHUB_IMAGE=acme/ferrum-edge-git-forge-ops` — where to push on Docker Hub. GHCR path auto-derives from the repo.
4. Push to `main` — `release.yml` builds + pushes to Docker Hub and GHCR.

### Version pinning

Set the `FERRUM_EDGE_VERSION` GitHub Actions variable to pin the `ferrum-edge` binary version used in CI workflows. Pin this to match the version of Ferrum Edge running in your environment so validation rules stay consistent. Example: if your gateways run `v0.9.0`, set `FERRUM_EDGE_VERSION=v0.9.0`. If unset, `latest` is used.

## License

PolyForm Noncommercial License 1.0.0
