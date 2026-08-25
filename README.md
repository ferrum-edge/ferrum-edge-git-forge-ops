# Ferrum Edge GitForgeOps

GitOps workflow for managing [Ferrum Edge](https://github.com/ferrum-edge/ferrum-edge) gateway configuration via pull requests. Fork, configure, and get a full multi-environment pipeline: PR-based submission, policy-aware review, scoped apply, credential brokering, and drift monitoring — **without** leaving GitHub's free tier and **without** any third-party secret manager.

## Headline features

- **Multi-environment from one repo** — declare staging/production/sandbox/etc. in `.gitforgeops/config.yaml`, deploy each to its own gateway via GitHub Environments. No per-env branches, no per-env repos.
- **Ownership modes** — `shared` (default): repo only touches what it has previously applied; admin-added resources are left alone. `exclusive`: repo is authoritative for a namespace set.
- **Extensible policy framework** — opt-in rules (timeout bands, TLS-only backends, required auth, WAF enforcement, AI guardrails, …) surface in PR review and block `apply` when severity is `error`. Override via labeled PR from a write-permission user.
- **In-GitHub credential broker** — consumer secrets never live in the repo. Placeholders (`${gh-env-secret:alloc=generate}`) are resolved from GitHub Environment Secrets at apply time. New values are generated, libsodium-sealed, written to env secrets via the REST API, and age-encrypted to the PR author's SSH key for one-time delivery.
- **Mesh configuration as fragments** — `kind: MeshConfig` files under `resources/<ns>/mesh/` merge into one standalone `{version, mesh}` document for file-protocol mesh nodes, validated with `ferrum-edge validate -m mesh`.
- **Drift detection with awareness of ownership** — scheduled comparisons surface changes on both sides, filtering the noise based on the env's configured mode.
- **Free-tier only** — GitHub Secrets, GitHub Environments, GitHub Actions, GitHub API. No Vault, no AWS, no 1Password required.

## Quick start

1. Fork this repo.
2. **Create a GitHub Environment per deployment target** (Settings → Environments → New). Name it whatever you want to call the environment — e.g. `staging`, `production`. Add its scoped secrets: `FERRUM_GATEWAY_URL`, `FERRUM_ADMIN_JWT_SECRET`, and any TLS material. Optionally set protection rules (required reviewers, wait timers).
3. **Declare those environments in `.gitforgeops/config.yaml`** — see `.gitforgeops/config.example.yaml`. The file carries overlay names and ownership modes; it does *not* carry any secret or URL.
4. Add resources under `resources/<namespace>/{proxies,consumers,upstreams,plugins}/*.yaml` (and, for a service mesh, `resources/<namespace>/mesh/*.yaml`).
5. **Create the two override labels** — they do not exist by default, and labels are not copied when you fork:

   ```bash
   gh label create gitforgeops/policy-override --color B60205 --description "Bypass blocking policy violations on this PR (requires write permission)"
   ```

   ```bash
   gh label create gitforgeops/state-override --color B60205 --description "Allow this PR to modify the CI-owned .state/ ledger"
   ```

   Or Settings → Labels → New label. `policy-override` is the escape hatch for blocking policy rules ([Override flow](#override-flow-b2-label--permission)); `state-override` is the one for `state-guard.yml` ([State file trust model](#state-file-trust-model)). Both are gated on `write` repo permission, since only users with write access can apply labels. Rename `policy-override` freely — it is configurable via `overrides.require_label` in `.gitforgeops/policies.yaml`.
6. Open a PR. CI runs the matrix across every declared environment, validates the assembled config, and posts a review comment per env with policy, drift, credential, security, and best-practice findings. Policy errors are enforced by `apply`.
7. Merge. `apply-on-merge.yml` applies to each environment in parallel (per-env concurrency lock prevents clobbering).

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
    mesh/
      core.yaml                  # kind: MeshConfig (fragment, not a gateway resource)
  team-alpha/                    # namespace: team-alpha
    proxies/
      alpha-service.yaml

overlays/                        # environment-specific deep-merge fragments
  staging/
    ferrum/proxies/my-api.yaml   # overrides backend_host, timeouts, etc.
    ferrum/mesh/core.yaml        # matches the mesh fragment by file name
  production/
    ferrum/proxies/my-api.yaml

assembled/                       # file-mode output (gateway doc + mesh doc)
  staging.yaml
  staging-mesh.yaml

.state/                          # auto-committed by CI, per environment; never hand-edit
  staging.json
  production.json

.github/workflows/
  validate-pr.yml                # matrix validate + review per env
  apply-on-merge.yml             # matrix apply per env (with env binding)
  drift-check.yml                # scheduled diff per env
  state-guard.yml                # rejects PR-authored .state/ edits
  rotate.yml                     # workflow_dispatch for credential rotation
  materialize-file.yml           # workflow_dispatch for encrypted flat-file delivery
  release.yml                    # builds multi-arch image on push to main / v* tag
```

Overlay object fields deep-merge. Arrays replace by default so environment
overlays can narrow lists such as `allowed_methods`, `hosts`,
`allowed_ws_origins`, and `acl_groups`; `spec.plugins` and `spec.targets` are
additive and merge by item identity, as are a mesh fragment's `spec.workloads`
(by `spiffe_id`) and `spec.services` (by `name` + `namespace`).

### Proxy backend scheme

A proxy declares its backend wire scheme with `backend_scheme`, one of six values: `http`, `https`, `tcp`, `tcps`, `udp`, `dtls`. WebSocket and gRPC are detected per request rather than declared, and HTTP/3 is negotiated per backend, so the older wider variant set is gone.

Existing trees keep loading. The legacy field name `backend_protocol` is accepted as an alias, and legacy values are folded onto the canonical set: `ws`/`grpc` → `http`, `wss`/`grpcs`/`h3` → `https`, `tcp_tls` → `tcps`. Serialization always emits a canonical value and the canonical field name, so a load/export cycle upgrades a legacy tree in place.

**Omitting the field is resolved at assembly time, not left as `null`.** The gateway canonicalizes a proxy's scheme on write — a non-stream proxy stored without one comes back from `GET /backup` as `backend_scheme: https` — so gitforgeops applies the same rule to the desired config: any proxy with no `backend_scheme` and no `listen_port` is assembled as `https`. Without that, a schemeless proxy would diff as modified against the live gateway on every run and be reported as a breaking `backend_scheme changed` on every PR, forever, with no edit that clears it.

Stream proxies (`listen_port` set) are deliberately **not** defaulted. The gateway does not default them either — it rejects a stream proxy with no scheme during validation — and guessing `tcp` for a proxy that meant `tcps` or `udp` would replace a clear validation error with a silently wrong one.

### What a single PR can change

One PR can include any number of new, modified, or deleted resources across any number of namespaces, in any mix of kinds (proxies, consumers, upstreams, plugin configs, mesh fragments). The loader walks every `resources/<namespace>/{proxies,consumers,upstreams,plugins,mesh}/` directory, the assembler flattens the four gateway kinds into a single `GatewayConfig` (mesh fragments merge into their own separate document), and apply groups by namespace on the way out. Each namespace gets its own `X-Ferrum-Namespace` header; incremental mode diffs that namespace against live `/backup`, and full-replace mode restores that namespace independently. Namespaces are isolated: a failure applying to `team-alpha` doesn't block `team-beta`.

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

The environment names here must match the GitHub Environments you've set up in repo settings. The review, apply, drift, rotate, and materialize workflows bind `environment: ${{ matrix.environment }}` or `environment: ${{ inputs.environment }}` so GitHub can inject that environment's scoped secrets automatically. Fork PRs still receive empty secrets under GitHub's `pull_request` secret rules, so review falls back to static-only output there.

## Ownership modes

`gitforgeops` classifies every gateway resource as one of:

1. **Declared** — in the repo's desired config right now.
2. **Previously managed** — repo applied it before, not declared now (intentional removal).
3. **Unmanaged** — exists on the gateway, repo never put it there.
4. **Spec-owned** — exists on the gateway carrying an `api_spec_id`, i.e. provisioned by the gateway's own OpenAPI spec ingestion (`/api-specs`).

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

### State file trust model

`.state/<env>.json` is the ownership ledger, and it is load-bearing twice over:

- `previously_managed` reads it to decide **what shared mode may delete**. A resource the ledger doesn't list is unmanaged; nothing outside the ledger is ever removed.
- `resolved_namespaces` unions the namespaces it names with the namespaces the repo currently declares, deciding **what gets reconciled at all**. Without that union, a PR removing the last resource from namespace `foo` would stop `foo` being diffed entirely — the orphaned resource would stay on the gateway forever while its key sat in the ledger, never re-reconciled.

Both of those make sense only because the ledger is **CI-authored**. `apply-on-merge.yml` and `rotate.yml` write it after a successful run and push it to `main` as `gitforgeops[bot]`; nobody edits it by hand.

That trust is enforced at the boundary, not inside the binary:

- **`state-guard.yml` fails any PR that touches `.state/**`.** A hand-edited ledger is a privilege escalation — forged entries name live resources as previously managed, and the next post-merge apply deletes them. Deliberate repairs (restoring a corrupted ledger, adopting an existing gateway) need the `gitforgeops/state-override` label, which only a user with `write` permission can add and which lands in the PR timeline.
- **`.state/*.json` is tracked in git; locks and temp files are not.** If you fork this repo, keep the `.gitignore` entries as shipped. Ignoring `.state/` makes the workflows' `git add` a no-op, the ledger never lands on `main`, and every apply starts from an empty ledger — shared mode then treats the whole gateway as unmanaged and silently stops deleting anything.
- **Apply runs post-merge only**, so a poisoned ledger has to survive review and land on `main` before it can act.

Narrowing what the binary reads out of the ledger is not a substitute for any of this: an attacker who can write `.state/<env>.json` can already forge entries inside a declared namespace, which no amount of namespace scoping catches.

### Spec-owned resources (both modes)

A live proxy, upstream, or plugin config with `api_spec_id` set was provisioned by the gateway's OpenAPI spec importer, which re-provisions it authoritatively on every spec re-import. gitforgeops stays off those rows in **both** ownership modes, regardless of what the state file says:

- Never modified. If the repo also declares the same `(namespace, kind, id)`, the run reports a **conflict** — two owners writing one row, and the spec importer wins on its next import.
- Never deleted, except in `exclusive` mode with `gitforgeops apply --confirm-api-spec-deletion`. Otherwise apply prints one line per skipped row and counts them.
- Rendered in `plan` / `diff` output and in the PR comment's "Spec-owned Resources" section. Unlike the unmanaged block this is not gated on `ownership.drift_report` — a repo fighting the spec importer is a correctness problem, not drift noise.

The same flag governs `full_replace`: by default a restore carries the namespace's live `api_specs` and `gateway_trust_bundles` sections through untouched (a bare restore would read as "delete every API spec here" and the gateway answers 409). `--confirm-api-spec-deletion` opts into dropping them.

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
    allowed_protocols: [https, tcps, dtls]

  require_auth_plugin:
    enabled: false
    severity: error
    auth_plugin_names: [jwt_auth, jwks_auth, key_auth, basic_auth, oauth2_introspection, oidc_relying_party]

  forbid_tls_verify_disabled:
    enabled: false
    severity: error

  allowed_proxy_plugins:
    enabled: false
    severity: error
    allowed_plugin_names: [jwt_auth, key_auth, rate_limiting]

  allowed_backend_domains:
    enabled: false
    severity: error
    allowed_domains:
      - api.internal.example.com
      - "*.svc.cluster.local"
      - "*.corp.example.com"

  waf_enforcement:
    enabled: false
    severity: error
    # min_paranoia_level: 2

  require_ai_guardrails:
    enabled: false
    severity: error
    guardrail_plugin_names: [ai_prompt_shield, ai_semantic_firewall]

  rate_limit_completeness:
    enabled: false
    severity: error

  plugin_name_is_known:
    enabled: false
    severity: warning
    allowed_extra_plugin_names: []

  priority_override_range:
    enabled: false
    severity: error

overrides:
  require_label: gitforgeops/policy-override
  required_permission: write     # admin | maintain | write
```

### Rule semantics

- `severity: error` → **blocks `gitforgeops apply`** until the violation is fixed or overridden.
- `severity: warning` / `info` → surfaced in PR review, but apply proceeds.
- Each violation includes the rule id, the resource, the current value, and a remediation hint in the PR comment.
- `allowed_backend_domains` checks direct proxy `backend_host` values when no `upstream_id` is set, and always checks upstream `targets[*].host` values. `*.example.com` matches subdomains like `api.example.com` and `deep.api.example.com`; list `example.com` separately if the root domain is allowed too. IP literals must be listed exactly; wildcard entries only apply to DNS names.
- `allowed_proxy_plugins` checks plugin configs explicitly referenced from a proxy's `plugins:` list, matching `plugin_name` case-insensitively.
- `backend_scheme` compares against the six canonical schemes (`http`, `https`, `tcp`, `tcps`, `udp`, `dtls`). A proxy that leaves `backend_scheme` unset is evaluated as `https`, matching the gateway's own default. Legacy entries in `allowed_protocols` (`wss`, `grpcs`, `tcp_tls`, …) are normalized before comparison, so an older policy file keeps meaning the same thing.
- `require_auth_plugin` evaluates each proxy's *effective* plugin list — scoped plugin configs merged over global ones of the same `plugin_name`, with disabled instances discarded. Omit `auth_plugin_names` to accept all eleven built-in authenticators: `spiffe_identity`, `mtls_auth`, `jwks_auth`, `oauth2_introspection`, `oidc_relying_party`, `jwt_auth`, `key_auth`, `ldap_auth`, `basic_auth`, `hmac_auth`, `soap_ws_security`.
- `waf_enforcement` catches a `waf` plugin that is attached but not blocking: `mode` other than `enforce`, a rule pack left entirely at `monitor`, or `on_body_too_large: skip`. Optional `min_paranoia_level` (gateway accepts 1–4, defaults to 1).
- `require_ai_guardrails` requires a proxy carrying AI traffic (any `ai_*` plugin, `mcp_gateway`, or `a2a_gateway`) to also carry an *enforcing* content guardrail — not a dry-run or warn-only one.
- `rate_limit_completeness` catches rate limiters with no usable budget: `rate_limiting` with missing/empty `limits`, no `scope: default` entry, or an entry with neither a window+`max_requests` nor `requests_per_*`; `ai_rate_limiter` with no `token_limit`; `redis_failure_policy: local_fallback` on either. It also flags the removed top-level budget fields, which the current gateway rejects outright.
- `plugin_name_is_known` checks `plugin_name` against the gateway's 82 built-ins plus `allowed_extra_plugin_names`. Retired names (`oauth2_auth`, `semantic_ai_firewall`) and the reserved `__mesh_bpf_metrics` always report at `error` regardless of configured severity — the gateway refuses to load a config that mentions them. Note that `jwt`, `oauth2`, and `oidc` are *not* plugin names; `jwt_auth`, `oauth2_introspection`, and `oidc_relying_party` are.
- `priority_override_range` checks `priority_override` against the gateway's accepted `0..=10000`.

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
    keyauth:
      - key: "${gh-env-secret:alloc=generate}"
    jwt:
      - secret: "${gh-env-secret:alloc=generate|len=32}"
```

### Credential shapes

ferrum-edge recognizes exactly five credential types, and each one is an **array** of entries:

| Type | Entry field | Notes |
|---|---|---|
| `keyauth` | `key` | non-empty, ≤4096 chars |
| `jwt` | `secret` | ≥32 characters |
| `hmac_auth` | `secret` | ≥32 characters, unique per namespace |
| `mtls_auth` | `identity` | cert CN / SAN / fingerprint — never broker-generated |
| `basicauth` | `password` **xor** `password_hash` | `hmac_sha256:<64 hex>` for the hash form |

Write the array form. `GET /backup` always returns arrays, so a bare object (`keyauth: {key: …}`) reads as permanent drift in `gitforgeops diff`. gitforgeops normalizes the object form during assembly so existing trees keep working, but the array form is what the gateway means.

Removal is asymmetric on the gateway side: omitting `keyauth`, `jwt`, `hmac_auth`, or `mtls_auth` **deletes** the stored entries on the next apply, while omitting `basicauth` (or an unrecognized type) **preserves** whatever the gateway already has. To actually clear one of the first four, write an explicit empty array (`keyauth: []`).

### What the broker will and won't generate

Generation constraints are checked at resolve time, so `plan` fails before `apply` writes a value the gateway would reject:

- `jwt` / `hmac_auth` need ≥32-character secrets, so `len=` must be at least 24 entropy bytes. The default `len=32` yields 43 base64url characters.
- `basicauth` in **file mode** is refused: a file-mode gateway requires `password_hash`, and that hash is an HMAC-SHA256 under the gateway's own `FERRUM_BASIC_AUTH_HMAC_SECRET`, which gitforgeops does not have. Set the hash by hand, or use api mode where the admin API hashes a plaintext password on write.
- `basicauth/…/password_hash` is refused in either mode, for the same reason.
- A bundle value of `[REDACTED]` is refused — that is what a plain `GET /consumers/…` returns for `keyauth`/`jwt`/`hmac_auth` secrets, so a bundle holding it was seeded from the wrong endpoint. Re-seed from `GET /backup` or rotate the slot.
- `mtls_auth.identity` has to match a real certificate field. Nothing stops you writing `alloc=generate` there, but the gateway will reject the result.

### Placeholder syntax

```
${gh-env-secret:alloc=<mode>|len=<bytes>}
```

- `alloc=require` (default) — the value must already exist in the bundle; apply fails if it doesn't.
- `alloc=generate` — if the value is missing, generate a new one on apply.
- `alloc=rotate` — marker for "this slot is eligible for rotation." Behaves identically to `generate` at apply time: first apply allocates, subsequent applies reuse the stored value. **Re-rotation is explicit** — trigger the `rotate.yml` workflow (see below) with a specific slot and recipient.
- `len=<16..=256>` — bytes of entropy for generated values. Default 32.

### Slot names

Slot names are derived automatically from `(namespace, consumer_id, cred_key)` — you don't write them anywhere. Renaming a consumer gets a new slot (and the ability to intentionally retire the old one).

`cred_key` is the `/`-joined path from the credential type down to the placeholder string. Because credentials are arrays and **index 0 is elided**, the first entry of each type is addressed without an index:

```text
keyauth: [{key: K}]              ->  ferrum/app-mobile/keyauth/key
keyauth: [{key: K}, {key: K2}]   ->  ferrum/app-mobile/keyauth/key
                                     ferrum/app-mobile/keyauth/[1]/key
jwt:     [{secret: S}]           ->  ferrum/app-mobile/jwt/secret
```

The elision is what keeps the object→array normalization from orphaning every value already allocated in `FERRUM_CREDS_BUNDLE*`. Lookups also fall back to older encodings (verbatim `[0]`, and the legacy dotted form) so a bundle written by an earlier gitforgeops still resolves after an upgrade; only the elided form is ever written.

The same path syntax is what `gitforgeops rotate --credential` takes: `keyauth/key`, `jwt/secret`, `hmac_auth/secret`, `mtls_auth/identity`, `basicauth/password`, or `keyauth/[1]/key` for a second entry.

#### Hazard: entry position is the slot identity

Nothing about an entry's *contents* goes into its slot name — only its index does. For a credential type with **more than one entry**, that makes list order load-bearing:

```text
before:  keyauth: [{key: A}, {key: B}]      A -> ferrum/app/keyauth/key
                                            B -> ferrum/app/keyauth/[1]/key

you delete the first entry:
after:   keyauth: [{key: B}]                B -> ferrum/app/keyauth/key   <-- now A's stored value
```

The credential you meant to retire is still live, now issued to the entry that shifted into index 0, and `[1]` is orphaned in the bundle where re-growing the list would resurrect it.

So: **rotate, don't delete or reorder.** `gitforgeops rotate --consumer app --credential keyauth/[1]/key` replaces a value in place and leaves every other slot alone. Deleting the *last* entry of a list is safe; deleting or reordering anything else is not.

`plan`, `diff` and `apply` detect both shapes and print a warning: one when a brokered credential array has more than one entry (order is identity), and one naming any bundle slot whose index is past the end of the current array (orphaned by a shrink). Neither blocks the run — the bundle is not corrupt — but an orphaned slot should be rotated rather than left to be re-inherited.

### Storage: bundled environment secrets

Secrets are stored as JSON bundles inside **GitHub Environment Secrets** named `FERRUM_CREDS_BUNDLE`, `FERRUM_CREDS_BUNDLE_1`, `FERRUM_CREDS_BUNDLE_2`, …

- Each bundle is a JSON object: `{ "<slot>": "<value>", ... }`.
- Single bundle holds ~440 credentials at 48 KB GitHub secret cap.
- Auto-sharded by deterministic hash when any bundle approaches 40 KB.
- GitHub's 100-secrets-per-env limit × ~440 slots/bundle = **~44,000 credentials per environment** before you hit any ceiling.

The bundled workflows read all matching secrets via `${{ toJSON(secrets) }}`, filter `FERRUM_CREDS_BUNDLE*`, write that JSON to a temporary file, and pass the path as `FERRUM_CREDS_JSON_FILE`. The binary still supports inline `FERRUM_CREDS_JSON` for local testing, but the file form is preferred because large multi-shard bundles can exceed OS environment-block limits.

### Allocation, writing, and delivery

On apply, for each `alloc=generate` or first-apply `alloc=rotate` placeholder with no existing value:

1. Generate a 32-byte (or `len=`) random value from the OS CSPRNG, encoded base64url-no-pad (so 32 bytes → 43 characters).
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
  credential: keyauth/key
```

The rotation re-generates the value, overwrites the env secret, delivers it age-encrypted to `${{ github.actor }}` (whoever triggered the workflow), and then pushes the updated consumer directly to the live Admin API. Rotation is refused in file mode because there is no live gateway push path; use materialization to produce a new resolved flat file for file-mode gateways.

### File mode (two-stage)

File-mode gateways consume a single assembled YAML at boot. We can't commit that with credentials inlined — it would defeat the whole point of the broker. So file mode is two stages:

**Stage 1 — placeholder assembly (automatic, on every merge)**

`apply-on-merge.yml` in file mode runs `gitforgeops apply --auto-approve` with `FERRUM_GATEWAY_MODE=file`, `FERRUM_FILE_OUTPUT_PATH=assembled/<env>.yaml`, and `FERRUM_MESH_FILE_OUTPUT_PATH=assembled/<env>-mesh.yaml`. The file write happens before credential allocation mutates the in-memory config, so the committed file still contains the `${gh-env-secret:alloc=...}` strings for each consumer credential. That placeholder file is safe for version control, useful as a diff artifact for PR review, and useless to an attacker. The same apply run can allocate GitHub Environment Secret slots, deliver encrypted credentials, update `.state/<env>.json`, and commit the assembled placeholder file.

Both documents are published atomically (write temp → `fsync` → `rename(2)` in the destination directory), because a file-mode gateway and a mesh node both re-read their file and require two reads 20 ms apart to be byte-identical before reloading. The gateway document also carries a `resource_counts` seal that ferrum-edge's loader checks against the actual array lengths, so a truncated file fails loudly instead of silently deploying a partial config.

**Stage 2 — on-demand materialization (admin-initiated, delivered encrypted)**

When an admin needs the real file (to deploy it, test locally, inspect the full config), they trigger the `materialize-file.yml` workflow:

```
Actions → GitForgeOps Materialize File → Run workflow
  environment: production
```

The workflow:

1. Binds `environment: production` — pulls that env's `FERRUM_CREDS_BUNDLE*` secrets.
2. Runs `gitforgeops export --materialize --encrypt-to ${{ github.actor }} --output out/assembled-<env>.age`:
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

## Mesh configuration

Ferrum Edge's service mesh is configured by a document that is **not** a gateway config: mesh nodes read a standalone `{version, mesh}` YAML, and the two documents are mutually exclusive in shape. The mesh loader is `deny_unknown_fields` and rejects a document carrying `proxies:` / `upstreams:`, while a gateway in file mode ignores a `mesh:` key entirely. So gitforgeops keeps them as two artifacts.

### Fragments

Mesh config is authored as fragments under `resources/<namespace>/mesh/*.yaml`:

```yaml
kind: MeshConfig
id: core            # optional; defaults to the file stem. Overlays match on it.
spec:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      selector:
        labels: { app: api }
      service_name: api
      addresses: ["10.0.0.5"]
      ports:
        - port: 8080
          protocol: http
      trust_domain: cluster.local
      namespace: ferrum
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
      workloads:
        - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
  peer_authentications:
    - name: mesh-strict
      namespace: ferrum
      mtls_mode: strict
```

Every fragment in the repo contributes to **one** merged document:

- List fields (`workloads`, `services`, `peer_authentications`, …) concatenate across fragments.
- Singleton fields (`istio_root_namespace`, `trust_bundles`, `multi_cluster`, `outbound_traffic_policy`) may be set by at most one fragment, or by several fragments agreeing on the same value. A conflict is an error, not a last-writer-wins merge.

A mesh fragment has no top-level namespace of its own — the identity that matters lives inside each workload / service / policy entry. The directory namespace is only a handle for `FERRUM_NAMESPACE` filtering and overlay matching. See `resources/ferrum/mesh/_example.yaml`.

### Overlays

`overlays/<env>/<ns>/mesh/<same-file-name>.yaml` deep-merges onto the matching fragment. `spec.workloads` merges additively by `spiffe_id` and `spec.services` by `(name, namespace)`; **every other mesh list is replaced** by the overlay's version, so an overlay's `peer_authentications` are exactly the peer authentications for that environment.

### Output and consumption

`gitforgeops export` and file-mode `gitforgeops apply` publish the merged document to `FERRUM_MESH_FILE_OUTPUT_PATH` (default `./assembled/mesh.yaml`; the bundled workflows use `assembled/<env>-mesh.yaml`):

```yaml
version: "1"
mesh:
  workloads: [...]
  services: [...]
```

Point a mesh node's `FERRUM_MESH_FILE_CONFIG_PATH` at that file with `FERRUM_MESH_CONFIG_PROTOCOL=file`. Every node loads the same document and derives its own slice from its `FERRUM_MESH_WORKLOAD_SPIFFE_ID`. Mesh config holds no credential placeholders, so there is no materialize stage for it — what apply writes is final.

### Validation, and the absence of a mesh admin API

`validate`, `plan`, and `apply` run a **second** validation pass, `ferrum-edge validate -m mesh`, against the rendered document (byte-for-byte what gets published, `version` stamp included). That pass runs the same parse → normalize → validate → slice-derivation pipeline a mesh node runs at startup. It only runs when the repo actually declares mesh fragments.

There is **no mesh admin API**. Mesh resources therefore never appear in `gitforgeops diff` and are never pushed anywhere: an api-mode `apply` validates the mesh document and prints a notice telling you to run `export` or a file-mode apply to publish it. Distribute the published file to mesh nodes however you distribute config (image build, config volume, artifact download).

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

- **Sequential per-resource HTTP calls in incremental mode.** One PUT / DELETE / POST per changed resource. At ~100 ms round-trip per call, 1,000 changes take roughly 2 minutes. 10,000 changes would take ~20 minutes but are not fundamentally problematic. A namespace whose diff is pure adds skips this entirely via the `POST /batch` fast path (see [Apply ordering and the batch fast path](#apply-ordering-and-the-batch-fast-path)).
- **Full-replace mode is one HTTP call per namespace.** `FERRUM_APPLY_STRATEGY=full_replace` calls `POST /restore?confirm=true` once per namespace in scope. The `/restore` call is atomic for the single namespace it targets, but **atomicity does not extend across namespaces** — an exclusive-mode env with `ownership.namespaces: [alpha, beta]` issues two independent restores, and if `beta` fails after `alpha` succeeded, `alpha` is already replaced on the gateway side. The apply loop records every namespace that fails (instead of bailing on the first) so the error message enumerates partial state, but operators must reconcile it manually. For strict environment-wide atomicity, scope `full_replace` to a single namespace.
- **Namespaces apply independently.** `apply_api` iterates `split_config_by_namespace` and applies each namespace in turn. A failure applying to `team-alpha` doesn't abort `team-beta` — you get per-namespace error reporting via `ApplyResult`.

### Retry behavior

Every admin-API call goes through `AdminClient::send_with_retry`, which retries up to `FERRUM_GATEWAY_MAX_RETRIES` (default 3). The response body is buffered before the decision is made, because the admin API's error envelope carries markers that override the status code.

Retried:

- **Connection errors** (`reqwest::Error::is_connect()`) — the server never saw the request, so retry is always safe.
- **HTTP 408, 429, 500, 502, 503, 504** — transient. ferrum-edge admin endpoints are idempotent for PUT/DELETE/POST-restore, and create paths surface 409 on retry races (visible in `ApplyResult.errors`).
- **`/restore` 503 with `failure_class: connectivity`** — nothing was written, safe to re-send.

Never retried:

- **HTTP 501** — a standalone-MongoDB gateway (no multi-document transactions) will answer it forever. For `POST /batch` this is not even an error: apply falls back to per-resource creates.
- **`applied: false` in the body** — the write is durably committed but not live on the running gateway. Re-sending re-applies an already-committed write; check gateway health instead. Surfaces as a `CommittedNotLive` error naming the gateway's `reason` (`config_rejected` / `reload_timeout` / `sequence_unavailable`).
- **`/restore` 500 with `rollback: incomplete` or `unknown_outcome`** — the namespace may hold a partially restored configuration and a retry would re-run a destructive replace. gitforgeops stops and tells you to inspect with `gitforgeops diff` and reconcile by hand rather than re-running apply.
- **Request timeouts** — a timeout means state is ambiguous (gateway may or may not have applied). Retrying a large `/restore` after timeout could double-write. The next CI run re-diffs and converges.
- **4xx other than 408/429** — 400/401/403/404/409/422 are permanent.

Backoff is exponential (`500ms · 2^attempt`) capped at 8 seconds, **unless** the response carries `Retry-After`, which is honored verbatim in delta-seconds form and capped at 30 seconds so a pathological value can't wedge CI.

Some failures get their own error rather than a generic HTTP one:

- **403 with `Admin API is in read-only mode`** → `GatewayReadOnly`. An authenticated `GET /health` preflight runs before the first mutation, so a gateway with `admin_writes_enabled: false` (or running in `file` / `dp` / `mesh` / `node_agent` mode) fails the run once, up front, instead of producing N per-resource 403s. A `/health` that cannot be reached is treated as "unknown" and does not block.
- **409 carrying `api_specs_at_risk`** → `ApiSpecsAtRisk`, with a pointer to `--confirm-api-spec-deletion` (see [Spec-owned resources](#spec-owned-resources-both-modes)).
- **413** → the restore payload exceeded the gateway's body limit; the message names `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` and suggests incremental mode.

**Stale gateway views.** If `GET /backup` comes back with `X-Data-Source: cached`, the gateway served its in-memory snapshot instead of the config database, so the live view may be stale. The flag is sticky for the run: any apply that would issue deletions is refused with `StaleGatewayView` unless `--allow-large-prune` is passed to acknowledge pruning from a possibly-stale view. Applies with no deletions proceed with a warning.

**404-tolerant deletes.** A DELETE that answers 404 already achieved its goal. The gateway cascades deletes server-side (deleting a proxy removes its scoped plugin configs), so a diff-driven follow-up delete legitimately finds nothing; treating that as an error used to wedge every later run on the same delete.

**Partial-failure visibility** (incremental mode): errors are collected per resource rather than bailing on first failure. A run where 99 of 100 resources apply cleanly but 1 hits a 400 returns an `ApplyResult` with 99 successes and 1 error. CLI exits non-zero; you see exactly which resource failed and why. Read-only refusals, stale views, and restore-rollback damage are the exceptions — they are fatal for the whole run, because continuing to the next namespace is pointless or unsafe.

### Apply ordering and the batch fast path

Incremental apply sorts the diff into dependency order rather than by kind, because the gateway enforces referential integrity:

| Rank | Operations |
|---|---|
| 0 | Add/Modify Upstream, Add/Modify Consumer |
| 1 | Add/Modify Proxy |
| 2 | Add/Modify PluginConfig |
| 3 | Delete PluginConfig |
| 4 | Delete Proxy |
| 5 | Delete Upstream, Delete Consumer |

Deletes come *after* adds and modifies: an upstream can only be removed once nothing references it (`DELETE /upstreams/{id}` answers 409 while a proxy still points at it), so the proxy modify that drops the reference has to land first.

Proxy deletes are issued with `cleanup_orphaned_upstream=false`. That server-side cascade defaults to on and would delete the last-referenced hand-owned upstream along with the proxy — an invisible deletion that makes the next diff-driven `DELETE /upstreams/{id}` answer 404. gitforgeops owns the upstream lifecycle through its own diff and issues that delete itself.

When a namespace's diff is **pure adds**, apply takes `POST /batch` instead — one transactional, all-or-nothing call, chunked below the gateway's 1 MiB body cap. Any Modify or Delete in the set disqualifies it (`/batch` is create-only), and a 501 falls back to per-resource creates.

### Post-apply convergence

After an api-mode apply, gitforgeops makes a best-effort `GET /cluster` call and prints a one-line convergence summary: the gateway's mode, connected data-plane and mesh-node counts, the oldest `last_sync_at` among them, and a warning if any node reports `config_diverged`. On a DP-mode gateway it reports that node's view of its control plane instead; on a database/file-mode gateway there is no cluster to converge and it says so. Advisory only — a gateway that can't answer (older build, network hiccup) reports "unknown" and never fails the apply.

### What if apply fails after merge?

The merge commit is already on `main`, but config isn't (fully) applied. Re-run the failed `GitForgeOps Apply` workflow from the Actions tab. Re-run is safe because:

1. Incremental mode re-fetches actual state via `GET /backup`, so already-applied resources are skipped.
2. Full-replace mode is idempotent — `POST /restore` converges regardless of prior partial state.
3. `.state/<env>.json` is a hash manifest of the *last successful* apply; it never causes re-runs to skip work.

Two failures are the exception — do **not** blindly re-run:

- **`RestoreNeedsManualRecovery`** (`/restore` answered 500 with `rollback: incomplete` or `unknown_outcome`). The namespace may hold a partially restored configuration and another restore is another destructive replace. Inspect with `gitforgeops diff`, restore from a known backup if needed, then reconcile.
- **`CommittedNotLive`** (`applied: false`). The write is persisted but the running gateway hasn't picked it up. Re-applying re-sends an already-committed write; check gateway health instead.

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
| `FERRUM_ADMIN_JWT_ISSUER` | no (default `ferrum-edge`) | `iss` claim; must equal the gateway's own issuer or every call is 401 |
| `FERRUM_ADMIN_JWT_ROLE` | no (default `admin`) | `role` claim; `/backup`, `/restore`, `/batch` and consumer CRUD are admin-only |
| `FERRUM_ADMIN_JWT_AUDIENCE` | no | `aud` claim, emitted **only** when set — a gateway with no configured audience rejects a token that carries one |
| `FERRUM_ADMIN_JWT_TTL_SECS` | no (default `3600`) | Token lifetime; must sit inside the gateway's `FERRUM_ADMIN_JWT_MAX_TTL` |
| `FERRUM_GATEWAY_CA_CERT` | no | Custom CA (base64 PEM) |
| `FERRUM_GATEWAY_CLIENT_CERT` | no | Client cert for mTLS (base64 PEM) |
| `FERRUM_GATEWAY_CLIENT_KEY` | no | Client key for mTLS (base64 PEM, required if cert is set) |
| `FERRUM_GH_PROVISIONER_TOKEN` | no (required for allocate/rotate) | GitHub App installation token or PAT with `Secrets: write` + `Environments: write` |
| `FERRUM_CREDS_BUNDLE[_N]` | managed by broker | Credential bundles — **you generally never touch these by hand** |

#### Migrating from older gitforgeops

The default `iss` claim changed from `gitforgeops` to `ferrum-edge`, matching the gateway's own default issuer. Nothing to do for most repos — a gateway left at its default accepts the new value and rejected the old one.

You must act only if your **gateway** is explicitly configured with `FERRUM_ADMIN_JWT_ISSUER=gitforgeops`. Then every call from a current gitforgeops is `401`, and either side can be brought back into agreement:

- set the gateway's `FERRUM_ADMIN_JWT_ISSUER` to `ferrum-edge` (or unset it, which is the same thing); or
- set `FERRUM_ADMIN_JWT_ISSUER=gitforgeops` for gitforgeops too, as an environment secret, so it keeps minting the old issuer.

The two values must match exactly; the issuer is compared as an opaque string.

Minted tokens also carry an `ns` claim listing the namespaces the run actually touches (from `FERRUM_NAMESPACE`, refined to an exclusive environment's namespace list where one applies). It is consulted only by gateways running with `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`; elsewhere it is inert, and it is omitted entirely when the scope is "all namespaces", which is what a non-tenancy gateway expects.

### GitHub Actions variables used by bundled workflows

| Variable | Default | Description |
|---|---|---|
| `FERRUM_GATEWAY_MODE` | `api` | `api` = push via Admin API, `file` = assemble flat YAML. The bundled workflows use this to choose apply/materialize behavior and to skip API-only drift checks in file-mode repos. |
| `FERRUM_EDGE_VERSION` | `latest` | Ferrum Edge release tag for validation binary (e.g. `v0.9.0`). Pin this to match your runtime. |
| `GITFORGEOPS_RELEASE_ENABLED` | `false` (on forks) | Opt a fork into running the `release` workflow. Upstream always publishes regardless. |
| `DOCKERHUB_IMAGE` | `ferrumedge/ferrum-edge-git-forge-ops` | Where the `release` workflow pushes on Docker Hub. Only matters if `GITFORGEOPS_RELEASE_ENABLED=true`. GHCR path is auto-derived from the repo. |

These are GitHub **Variables** because the workflow YAML reads them through `vars.*`. Runtime knobs such as `FERRUM_NAMESPACE`, `FERRUM_TLS_NO_VERIFY`, and timeout/retry settings are normal process environment variables; set them locally, or explicitly pass them through if you customize the bundled workflows.

### Docker Hub secrets (upstream maintainers / forks publishing their own image only)

**Forks don't need these.** The `release` workflow is gated; forks consume the already-published `ferrumedge/ferrum-edge-git-forge-ops` image and skip the build.

Required only if you're the upstream maintainer, or if your fork has opted in via `GITFORGEOPS_RELEASE_ENABLED=true`:

| Secret | Description |
|---|---|
| `DOCKERHUB_USERNAME` | Docker Hub account that owns the target namespace |
| `DOCKERHUB_TOKEN` | Docker Hub access token with push access |

The `release` workflow also pushes to GHCR using the built-in `GITHUB_TOKEN` — no extra secret needed. Keep repository default workflow permissions at **Read repository contents permission**; `release.yml` explicitly grants `packages: write` only to the release job for GHCR publishing.

### Local environment variables

See `.env.example`. Essentials for running `gitforgeops` on your laptop:

- `FERRUM_ENV=<name>` — pick an environment from `.gitforgeops/config.yaml`
- `FERRUM_GATEWAY_URL` + `FERRUM_ADMIN_JWT_SECRET` — connect to a live gateway
- `FERRUM_CREDS_JSON_FILE` — preferred path to a JSON file containing `FERRUM_CREDS_BUNDLE*` values
- `FERRUM_CREDS_JSON` — inline equivalent for small local apply tests

Runtime variables supported by the binary include:

| Variable | Default | Description |
|---|---|---|
| `FERRUM_ENV` | — | Environment selected from `.gitforgeops/config.yaml`; overridden by global `--env`. |
| `FERRUM_NAMESPACE` | — | Filter to one namespace. Omit to process all namespaces. |
| `FERRUM_APPLY_STRATEGY` | `incremental` | Legacy/env-driven strategy: `incremental` or `full_replace`. Repo config wins when an environment is selected. |
| `FERRUM_OVERLAY` | — | Legacy overlay selector used only without repo config/env selection. |
| `FERRUM_FILE_OUTPUT_PATH` | `./assembled/resources.yaml` | File-mode output path. Bundled file-mode apply sets this to `assembled/<env>.yaml`. |
| `FERRUM_MESH_FILE_OUTPUT_PATH` | `./assembled/mesh.yaml` | Where the standalone `{version, mesh}` document is published by `export` and file-mode `apply`. Separate document, separate path — see [Mesh configuration](#mesh-configuration). Bundled workflows set `assembled/<env>-mesh.yaml`. |
| `FERRUM_ADMIN_JWT_ISSUER` | `ferrum-edge` | `iss` claim minted into admin tokens. |
| `FERRUM_ADMIN_JWT_ROLE` | `admin` | `role` claim. `viewer` / `operator` are insufficient for what gitforgeops does. |
| `FERRUM_ADMIN_JWT_AUDIENCE` | — | `aud` claim; emitted only when set. |
| `FERRUM_ADMIN_JWT_TTL_SECS` | `3600` | Admin token lifetime. |
| `FERRUM_EDGE_BINARY_PATH` | `ferrum-edge` | Validation binary path. |
| `FERRUM_TLS_NO_VERIFY` | `false` | Skip TLS verification for gateway HTTP calls. Dev only. |
| `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `10` | TCP/TLS connect timeout for the Admin API. |
| `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `60` | End-to-end Admin API request timeout. Raise for large `/backup` or slow `/restore`. |
| `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` | `10` | TCP/TLS connect timeout for GitHub API calls. |
| `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` | `30` | End-to-end GitHub API request timeout. |
| `FERRUM_GATEWAY_MAX_RETRIES` | `3` | Retries on connection errors, HTTP 408/429/5xx (not 501). `0` disables retries. |

## CLI reference

All commands accept `--env <name>` globally.

```
gitforgeops validate [--format text|json|github|github-annotations]
gitforgeops diff [--exit-on-drift]
gitforgeops plan
gitforgeops apply [--auto-approve] [--allow-large-prune] [--confirm-api-spec-deletion]
gitforgeops export [--output PATH] [--materialize] [--encrypt-to GH_LOGIN]
gitforgeops import --from-api | --from-file PATH [--output-dir DIR]
gitforgeops review [--pr N]
gitforgeops envs [--format json|text]           # for CI matrix discovery
gitforgeops rotate --consumer ID --credential KEY \
  [--namespace NS] [--recipient GH_LOGIN]
```

Notes:

- `--from-api` is a flag, not a value: `gitforgeops import --from-api`. It conflicts with `--from-file`.
- `--format github` is an alias for `github-annotations`.
- `--confirm-api-spec-deletion` is the opt-in for touching resources the gateway's OpenAPI spec importer owns: under `full_replace` it drops the namespace's `api_specs` section instead of carrying it through, and under exclusive incremental apply it allows pruning live resources tagged with an `api_spec_id`. Without it, those rows are reported and skipped.
- `--allow-large-prune` doubles as the acknowledgement that pruning from a stale (`X-Data-Source: cached`) gateway view is acceptable.
- `import` writes per-resource YAML for the four gateway kinds only; API specs and gateway trust bundles present in the source backup are reported as skipped rather than silently dropped, because they are managed through `/api-specs` and `/gateway-trust-bundles`, not through this repo.

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

### Breaking Changes
- **Proxy `my-api`**: backend_scheme changed

### Security Findings
- [WARNING] **Proxy `new-service`** (`ferrum`): No auth plugin attached to proxy new-service in namespace ferrum — its effective plugin list contains no enabled authenticator; attach one of: jwt_auth, key_auth, ...

### Best Practice Recommendations
- [warning] **Proxy `new-service`** (`ferrum`): No rate-limit plugin attached to proxy new-service in namespace ferrum (scheme https) — a single client can saturate the backend; attach rate_limiting

### Unmanaged Resources (shared mode)
These resources exist on the gateway but were not applied by this repo. They will not be modified or deleted.
- **Proxy `admin-experiment`** (`ferrum`)

### Spec-owned Resources
These gateway resources carry an `api_spec_id`: they are provisioned by an OpenAPI spec import, not by this repo. gitforgeops does not modify or prune them.

- **Proxy `petstore-list-pets`** (`ferrum`) owned by spec `petstore-v3`

### Policy Violations
- [error] `backend_scheme` on **Proxy `my-api`** (`ferrum`): backend_scheme=http is not in the allowed list (https) · BLOCKING
  - _Change backend_scheme to one of: https_

> **Apply is blocked** until the listed violations are resolved. To override, add the `gitforgeops/policy-override` label (requires `write` permission on this repo).

### Credential Slots
| Slot | Declared as |
|------|-------------|
| `ferrum/app-mobile/keyauth/key` | needs allocation (generated on apply) |
| `ferrum/web-portal/keyauth/key` | resolved |
```

## Trust and security posture

- **Fork PRs cannot see production secrets.** `validate-pr.yml` binds each review job to the matching GitHub Environment so same-repo PRs can include live gateway comparison in review comments, but GitHub withholds environment secrets from forked `pull_request` runs. Fork PRs degrade to static-only review output, and contributors from forks can propose credential slots but cannot cause allocation.
- **Apply only runs post-merge on `main`.** `apply-on-merge.yml` binds the environment; GitHub enforces protection rules (required reviewers, branch restrictions).
- **Credential values are never written back to the repo.** Only hashes and metadata in `.state/`.
- **The state file is CI-owned.** `state-guard.yml` rejects PRs that modify `.state/**` unless a maintainer adds the `gitforgeops/state-override` label — the ledger decides what shared mode may delete, so a hand-edited one is a privilege escalation. See [State file trust model](#state-file-trust-model).
- **Policy overrides leave a permanent trail.** PR label event + approver permission + `.state/<env>.json.overrides` record.
- **The provisioner token is the bootstrap credential.** Rotate periodically; prefer GitHub App installation tokens over PATs (automatic 1-hour expiry, org-scoped).
- **TLS material stays as GitHub secrets.** The binary only ever sees the base64-decoded PEM in-process.
- **Validation is hermetic.** `ferrum-edge validate` is invoked with `-m file` (or `-m mesh`) pinned and `-s` pointed at an empty settings file, so an inherited `FERRUM_MODE` or a stray `ferrum.conf` in the checkout can't turn validation into a fail-open no-op that still exits 0. Every `FERRUM_*` variable is removed from the child's environment for the same reason. The temporary spec is written through `tempfile` at mode 0600 with an unpredictable name and removed on drop — callers resolve credential placeholders *before* validating, so that file can hold live consumer credentials. `ferrum-edge validate` itself has no machine-readable output mode; the text/JSON/GitHub-annotation formats of `--format` are produced gitforgeops-side.

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
3. Settings → Actions → General → Workflow permissions = **Read repository contents permission** (recommended default; `release.yml` grants `packages: write` at job scope)

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
cargo test --test unit_tests                   # aggregated unit/integration suite
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Rust CI runs `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --test unit_tests` on PRs/pushes that touch source, tests, Cargo metadata, the Dockerfile, or the Rust CI workflow. Resource-only PRs run `validate-pr.yml` instead.

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
