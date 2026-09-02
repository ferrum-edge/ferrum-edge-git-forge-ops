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
2. **Create a GitHub Environment per deployment target** (Settings → Environments → New). Name it whatever you want to call the environment — e.g. `staging`, `production`. Add its scoped secrets: `FERRUM_GATEWAY_URL`, `FERRUM_ADMIN_JWT_SECRET`, and any TLS material. Before launch, required reviewers, self-review prevention, and a protected-`main` deployment policy are mandatory; see step 6.
3. **Declare those environments in `.gitforgeops/config.yaml`** — see `.gitforgeops/config.example.yaml`. The file carries overlay names and ownership modes; it does *not* carry any secret or URL.
4. Add resources under `resources/<namespace>/{proxies,consumers,upstreams,plugins}/*.yaml` (and, for a service mesh, `resources/<namespace>/mesh/*.yaml`).
5. **Create the two override labels** — they do not exist by default, and labels are not copied when you fork:

   ```bash
   gh label create gitforgeops/policy-override --color B60205 --description "Bypass blocking policy violations on this PR (requires write permission)"
   ```

   ```bash
   gh label create gitforgeops/state-override --color B60205 --description "Allow this PR to modify the CI-owned .state/ ledger"
   ```

   Or Settings → Labels → New label. `policy-override` is the escape hatch for blocking policy rules ([Override flow](#override-flow-b2-label--permission)); `state-override` is the one for `state-guard.yml` ([State file trust model](#state-file-trust-model)). GitHub's triage role can apply labels, so neither flow trusts label presence: each resolves the effective label event and requires the actor's current permission to be `write`, `maintain`, or `admin`. Rename `policy-override` freely — it is configurable via `overrides.require_label` in `.gitforgeops/policies.yaml`; the state label is intentionally exact.
6. **Configure the mandatory GitHub launch controls.** Create the contents-only state-writer App, require the state guard and CI checks in an active `main` ruleset, protect release tags and every deployment environment, restrict Actions, and configure the scheduled settings audit. Follow [GitHub launch controls](docs/github-launch-controls.md) before adding production credentials. Forks do not inherit any of these settings.
7. **Pin the validator release identity.** Select an allowed `FERRUM_EDGE_VERSION`. Every allowed release and digest lives in reviewed `.github/ferrum-edge-checksums.txt`; the checked-in fallback is the content-pinned 2026-08-27 `latest` snapshot. A moved tag or an unreviewed version fails before execution.
8. Open a PR. The PR-built binary runs static validation without an environment or gateway secrets. A default-branch `workflow_run` then sanitizes only declarative YAML, builds and hashes the protected-branch binary once, waits for environment approval, and posts the live policy/drift/security review for same-repository PRs. Each live job is intersected with the environment's protected namespace scope and fails if comparison is unavailable. Fork PRs remain static-only.
9. Merge. `apply-on-merge.yml` applies to each environment in parallel (per-env concurrency lock prevents clobbering) and uses the short-lived state-writer App token for its protected ledger commit.

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
  sandbox/                       # every overlay a config.yaml environment
                                 # selects must exist, even if it is empty

assembled/                       # file-mode output (gateway doc + mesh doc)
  staging.yaml
  staging-mesh.yaml

.state/                          # auto-committed by CI, per environment; never hand-edit
  staging.json
  production.json

.github/workflows/
  validate-pr.yml                # secretless PR-built static validation
  trusted-pr-review.yml          # trusted binary + sanitized-data live review
  apply-on-merge.yml             # matrix apply per env (with env binding)
  drift-check.yml                # scheduled diff per env
  state-guard.yml                # rejects PR-authored .state/ edits
  settings-audit.yml             # detects GitHub protection drift
  rotate.yml                     # workflow_dispatch for credential rotation
  materialize-file.yml           # workflow_dispatch for encrypted flat-file delivery
  release.yml                    # builds multi-arch image on push to main / v* tag
```

Overlay object fields deep-merge. Arrays replace by default so environment
overlays can narrow lists such as `allowed_methods`, `hosts`,
`allowed_ws_origins`, and `acl_groups`; `spec.plugins` and `spec.targets` are
additive and merge by item identity, as are a mesh fragment's `spec.workloads`
(by `spiffe_id`) and `spec.services` (by `name` + `namespace`).

Input loading is fail-closed and deterministic. A selected overlay must exist —
the check runs before any resource file is read and names the environment, the
overlay, and the file that declared the selection;
every resource/overlay path is sorted before parsing; walker errors propagate;
symlinks anywhere in `resources/` or the selected overlay are rejected; and
duplicate overlay targets name both source files instead of depending on
filesystem order. Gateway overlay fragments require `kind` and `spec.id`;
mesh fragments use an explicit `id` or their non-empty filename stem. Enabled
configuration files must use lowercase `.yaml` or `.yml`. Files beginning with
`_` are intentionally disabled, and only `README`, `README.md`, `.gitkeep`,
and the generated `.gitforgeops-import.json` inventory are accepted as
non-configuration files inside declarative trees; spellings
such as `.YAML`, `.yam`, or `.yaml.bak` fail instead of disappearing from the
desired inventory. `.DS_Store`, `Thumbs.db` and `desktop.ini` are the one
exception: they are skipped in silence, because a file manager re-creates them
the moment someone opens the folder and no commit can remove them for good.
The trusted-review archive applies the same rules — the same two lists — before
it crosses the privileged data boundary.

### Supported fields, and what happens to unsupported ones

The typed companion schema rejects unknown wrapper, resource, and nested object
keys before assembly, reporting the source file and full YAML path. This
prevents a typo such as `spec.plguins` from disappearing before the
authoritative `ferrum-edge validate` pass. Deliberately opaque values remain
lossless and forward-compatible: arbitrary plugin `config`, consumer
credential maps, and per-item mesh resource objects are preserved verbatim.

Rejection is authoritative, which has a cost: a **gateway release that adds a
field** is unusable until gitforgeops ships a matching release. Set
`FERRUM_ALLOW_UNKNOWN_FIELDS=true` to unblock that. Unknown **top-level**
`spec` fields on `Proxy`, `Upstream`, `Consumer` and `PluginConfig` are then
kept verbatim and travel through overlay merge, `export`, `diff` and `apply`
untouched, so the gateway — which is the real schema — decides whether they are
valid. Each affected file gets a `Warning:` on stderr naming every field kept
(never on stdout, which carries the exported YAML document).

Three limits are deliberate:

* **Nested unknown fields stay fatal in both modes.** Carrying them would mean
  opening every nested struct to silent acceptance, which is the bug the strict
  loader exists to prevent.
* **Fail-closed is the default.** The flag is for unblocking a version skew,
  not for running on indefinitely; upgrade gitforgeops when a release catches
  up.
* **A field only the gateway carries is not drift.** If a newer gateway returns
  a field this client does not model and your repository does not declare,
  `diff` ignores it — reporting it would mean permanent drift that no `apply`
  could clear. Declaring a field in your YAML is how the repository takes
  ownership of it.

`gitforgeops import` is the one place an unmodelled field reaches your tree
without you typing it: a resource imported from a newer gateway is written out
complete, so a later `validate` names the field instead of losing it. Either
upgrade gitforgeops, set the flag, or delete the field from the imported YAML.

Two further input rules follow from the same "no silent rewrites" principle:

* **YAML merge keys (`<<:`) and anchors-as-merge are not supported.** Merging
  is opt-in in the YAML library and gitforgeops does not opt in, so `<<` stays
  an ordinary key and is reported as unknown field `.spec.<<` rather than
  silently doing nothing. Repeat the fields, or use an overlay.
* **Opaque islands are JSON-shaped, which means string keys only.** Plugin
  `config`, consumer credential entries and mesh items round-trip verbatim
  through a JSON representation, so a non-string YAML key (`404:`, `true:`) is
  rejected with the path of the mapping it appears in rather than being quietly
  stringified to `"404"`.

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

The environment names here must match the GitHub Environments you've set up in repo settings and use `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$` (one safe state/artifact path component). Trusted live review, apply, drift, rotate, and materialize bind `environment: ${{ matrix.environment }}` or `environment: ${{ inputs.environment }}` so GitHub can enforce reviewers/branch policies and inject scoped secrets. `validate-pr.yml` deliberately has no environment binding at all: PR-built code never receives gateway credentials. Fork PRs get static validation only; the privileged `workflow_run` resolves their metadata but skips every build, artifact, and Environment-bound step before any privileged input is prepared.

Repository and policy configuration are closed, versioned contracts. Both
`.gitforgeops/config.yaml` and `.gitforgeops/policies.yaml` currently accept
exactly `version: 1`; future versions and unknown keys at any typed level fail
with the source path and offending key. This is intentionally stricter than
the Ferrum Edge resource mirror, whose documented free-form plugin,
credential, and mesh-item values remain forward-compatible.

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

Choose this when ops teams or admins still make changes via the GUI alongside the repo, or for sandbox environments where experimentation is fine. Immediately before an API create, gitforgeops durably records the key in a separate pending-create journal. Pending keys are **not** part of the delete fence. On the next authoritative backup, an exact current desired/live match triggers an idempotent PUT that explicitly asserts repository ownership before the key becomes managed; an absent live row remains an ordinary Add, and a live row whose desired declaration disappeared blocks reconciliation because ownership cannot be proven. This closes the crash window without turning an uncertain POST—or equality with a racing admin-created row—into deletion authority.

### `exclusive` (strict 1:1)

- Repo is authoritative for the listed `namespaces`.
- Unmanaged resources in those namespaces → **pruned**.
- Requires explicit `namespaces` list (safety rail against misconfiguration).
- `large_prune_threshold_percent` guards against runaway deletions. Default 25%: if an apply would delete more than 25% of the managed set, it refuses unless `--allow-large-prune` is passed. The decision compares the exact ratio (an exact threshold match is allowed), so fractional percentages are never truncated below the limit.

Choose this for production or regulated environments where git is the single source of truth.

### First-apply behavior

In `shared` mode, the first apply (when `.state/<env>.json` doesn't yet exist) treats **all** gateway resources as unmanaged. A loud warning goes to the apply output; nothing is deleted. Adds enter the pending-create journal immediately before the first create POST and enter the ownership ledger only after a successful response or an exact authoritative readback followed by a successful idempotent ownership assertion. A process failure therefore leaves a recoverable journal entry, never unproven deletion authority.

### State file trust model

`.state/<env>.json` is the ownership ledger, and it is load-bearing twice over:

- `previously_managed` reads it to decide **what shared mode may delete**. A resource the ledger doesn't list is unmanaged; nothing outside the ledger is ever removed.
- `resolved_namespaces` unions the namespaces named by managed and pending-create entries with the namespaces the repo currently declares, deciding **what gets reconciled at all**. Without that union, a PR removing the last resource from namespace `foo` would stop `foo` being diffed entirely — an orphan or uncertain create could stay on the gateway forever, never re-reconciled.

Before computing the large-prune ratio, an authoritative backup also removes ledger keys absent from both desired and live state. Otherwise externally deleted rows would accumulate forever and dilute the denominator used by the deletion guard. Namespace-filtered runs touch only keys in namespaces they actually read.

Both of those make sense only because the ledger is **CI-authored**. `apply-on-merge.yml` and `rotate.yml` write it after a successful run and push it to `main` as `gitforgeops[bot]`; nobody edits it by hand.

That trust is enforced at the boundary, not inside the binary:

- **`state-guard.yml` fails any PR that touches or renames a path from `.state/**`.** A hand-edited ledger is a privilege escalation — forged entries name live resources as previously managed, and the next post-merge apply deletes them. Deliberate repairs need the exact `gitforgeops/state-override` label. The guard replays paginated label/unlabel events, attributes the latest effective label, queries that actor's current permission, rejects triage/read/deleted/unknown actors and API ambiguity, and records actor, permission, event ID, and timestamp in the job summary. Label and unlabel events rerun the check under per-PR concurrency so a removed authorization cannot leave an older successful run authoritative.
- **`.state/*.json` is tracked in git; locks and temp files are not.** If you fork this repo, keep the `.gitignore` entries as shipped. Ignoring `.state/` makes the workflows' `git add` a no-op, the ledger never lands on `main`, and every apply starts from an empty ledger — shared mode then treats the whole gateway as unmanaged and silently stops deleting anything.
- **Apply runs post-merge only**, so a poisoned ledger has to survive review and land on `main` before it can act.
- **The guard must be a required status check before launch.** The state-writer GitHub App is the sole ruleset bypass and receives only short-lived `Contents: write` installation tokens. See [GitHub launch controls](docs/github-launch-controls.md).

Narrowing what the binary reads out of the ledger is not a substitute for any of this: an attacker who can write `.state/<env>.json` can already forge entries inside a declared namespace, which no amount of namespace scoping catches.

### Spec-owned resources (both modes)

A live proxy, upstream, or plugin config with `api_spec_id` set was provisioned by the gateway's OpenAPI spec importer, which re-provisions it authoritatively on every spec re-import. gitforgeops stays off those rows in **both** ownership modes, regardless of what the state file says:

- Never modified. If the repo also declares the same `(namespace, kind, id)`, the run reports a **conflict** — two owners writing one row, and the spec importer wins on its next import.
- Never deleted, except in `exclusive` mode with `gitforgeops apply --confirm-api-spec-deletion`. Otherwise apply prints one line per skipped row and counts them.
- Rendered in `plan` / `diff` output and in the PR comment's "Spec-owned Resources" section. Unlike the unmanaged block this is not gated on `ownership.drift_report` — a repo fighting the spec importer is a correctness problem, not drift noise.

The same flag governs `full_replace`, but preserving API specs requires conditional restore semantics that the gateway does not currently expose. A namespace with a non-empty `api_specs` section therefore fails closed under `full_replace`; use incremental apply to retain the spec-owned graph, or pass `--confirm-api-spec-deletion` only when deleting that complete graph is intentional. An authoritative empty/absent section is omitted from the restore so a spec created after the backup triggers the gateway's 409 guard instead of being silently wiped. `gateway_trust_bundles` is always omitted: the gateway defines absence as a no-op, which preserves a concurrent trust rotation instead of replaying stale roots. A missing graph member, cached backup, repo/spec ID collision, or unfamiliar top-level backup section also fails before any namespace is mutated. Repository-authored `api_spec_id` fields are rejected under both apply strategies, even with the confirmation flag; only the gateway may assign the ownership marker.

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

The bundled workflows read all matching secrets via `${{ toJSON(secrets) }}` and pass them through a fail-closed loader: the outer inventory, exact `FERRUM_CREDS_BUNDLE[_N]` names, each inner JSON object, and every string slot/value are validated before a new mode-0600 runner file is published as `FERRUM_CREDS_JSON_FILE`. Malformed inventories never degrade to an empty bundle (which could otherwise trigger duplicate allocation/rotation). The binary still supports inline `FERRUM_CREDS_JSON` for local testing, but the file form is preferred because large multi-shard bundles can exceed OS environment-block limits.

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

Both documents are published atomically (write temp → `fsync` → `rename(2)` in the destination directory), because a file-mode gateway and a mesh node both re-read their file and require two reads 20 ms apart to be byte-identical before reloading. The gateway document also carries a `resource_counts` seal that ferrum-edge's loader checks against the actual array lengths, so a truncated file fails loudly instead of silently deploying a partial config. Imports accept the one historical seal shape in which `upstreams` is absent only when the decoded upstream list is actually empty; every present count and every non-zero section remains mandatory and exact.

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
- `delivered_to` login, `delivered_run_id` workflow run number

These are committed to git automatically by the apply workflow, so `git log .state/<env>.json` is the delivery history. State deliberately contains no credential-derived hashes: even a truncated unkeyed hash lets anyone with repository access verify low-entropy guesses offline. State version 3 also stores a constant marker beside each managed-resource key rather than hashing the resolved resource; version 2 files are sanitized in memory and rewritten in the safe form on the next apply or rotate save. Rotate any low-entropy credential whose older hash metadata has already entered repository history.

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
- **Full-replace mode is one HTTP call per namespace.** `FERRUM_APPLY_STRATEGY=full_replace` prebuilds and validates every namespace payload before the first mutation, then calls `POST /restore?confirm=true` once per namespace in scope. The `/restore` call is atomic for one namespace, but **atomicity does not extend across namespaces** — a runtime failure on `beta` after `alpha` succeeds leaves `alpha` replaced. Deterministic errors in any namespace, including unsupported backup sections and malformed/spec-owned graphs, now yield zero restore calls. Runtime failures still require manual reconciliation. For strict environment-wide atomicity, scope `full_replace` to a single namespace.
- **Namespaces apply independently.** `apply_api` iterates `split_config_by_namespace` and applies each namespace in turn. A failure applying to `team-alpha` doesn't abort `team-beta` — you get per-namespace error reporting via `ApplyResult`.

### Retry behavior

Every admin-API call goes through `AdminClient::send_with_retry`, which retries up to `FERRUM_GATEWAY_MAX_RETRIES` (default 3). The response body is buffered before the decision is made, because the admin API's error envelope carries markers that override the status code.

Retried:

- **Connection-establishment errors** (`reqwest::Error::is_connect()`) — no HTTP response was received and the connection could not be established.
- **HTTP 408, 429, and 5xx except 501 for reads and idempotent PUT/DELETE calls** — transient responses are safe to replay for those endpoint semantics.
- **`/restore` 503 with `failure_class: connectivity`** — nothing was written, safe to re-send.

Never retried:

- **HTTP 501** — a standalone-MongoDB gateway (no multi-document transactions) will answer it forever. For `POST /batch` this is not even an error: apply falls back to per-resource creates.
- **Every error response from non-idempotent create and batch POSTs** — a gateway or intermediary can return an error after commit. Gitforgeops sends the POST once, then fetches an authoritative backup after an ambiguous response. If the exact desired resource or complete batch is live, idempotent PUTs explicitly assert repository ownership before success is recorded; equality alone never grants deletion authority. A batch is decomposed into individual creates only for documented definitive rejections (400/409/413/422), never for transport/5xx ambiguity.
- **`applied: false` in the body** — the write is durably committed but not live on the running gateway. Re-sending re-applies an already-committed write; check gateway health instead. Surfaces as a `CommittedNotLive` error naming the gateway's `reason` (`config_rejected` / `reload_timeout` / `sequence_unavailable`).
- **`/restore` failures other than the explicit pre-commit connectivity case** — restore is destructive and not generally idempotent. A 500 with `rollback: incomplete` or `unknown_outcome` additionally surfaces as manual-recovery-required because the namespace may be partially restored.
- **Request timeouts** — a timeout means state is ambiguous (gateway may or may not have applied). Retrying a large `/restore` after timeout could double-write. The next CI run re-diffs and converges.
- **4xx other than 408/429** — 400/401/403/404/409/422 are permanent.

Backoff is exponential (`500ms · 2^attempt`) capped at 8 seconds, **unless** the response carries `Retry-After`, which is honored verbatim in delta-seconds form and capped at 30 seconds so a pathological value can't wedge CI.

Some failures get their own error rather than a generic HTTP one:

- **403 with `Admin API is in read-only mode`** → `GatewayReadOnly`. An authenticated `GET /health` preflight runs before the first mutation, so a gateway with `admin_writes_enabled: false` (or running in `file` / `dp` / `mesh` / `node_agent` mode) fails the run once, up front, instead of producing N per-resource 403s. A `/health` that cannot be reached is treated as "unknown" and does not block.
- **409 carrying `api_specs_at_risk`** → `ApiSpecsAtRisk`, with a pointer to `--confirm-api-spec-deletion` (see [Spec-owned resources](#spec-owned-resources-both-modes)).
- **413** → the restore payload exceeded the gateway's body limit; the message names `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` and suggests incremental mode.

**Stale gateway views.** If `GET /backup` comes back with `X-Data-Source: cached`, the gateway served its in-memory snapshot instead of the config database. That fallback also omits API-spec documents and clears ownership tags, so **every API-mode mutation** is refused with `StaleGatewayView` before credential allocation or the first write. `--allow-large-prune` does not bypass this ownership-safety gate; validation and read-only reporting remain available while the database recovers.

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
3. `.state/<env>.json` is an ownership manifest of the *last successful* apply; it never causes re-runs to skip work.

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
| `FERRUM_GATEWAY_MODE` | `api` | `api` = push via Admin API, `file` = assemble flat YAML. Values are trimmed/case-folded; every other present value fails the workflow preflight before credentials or binaries are loaded. |
| `FERRUM_EDGE_VERSION` | `latest` | Ferrum Edge release tag for the validator. It must have an exact reviewed digest in `.github/ferrum-edge-checksums.txt`. |
| `GITFORGEOPS_RELEASE_ENABLED` | `false` (on forks) | Opt a fork into running the `release` workflow. Upstream always publishes regardless. |
| `DOCKERHUB_IMAGE` | `ferrumedge/ferrum-edge-git-forge-ops` | Where the `release` workflow pushes on Docker Hub. Only matters if `GITFORGEOPS_RELEASE_ENABLED=true`. GHCR path is auto-derived from the repo. |

These are GitHub **Variables** because the workflow YAML reads them through `vars.*`. Runtime knobs such as `FERRUM_NAMESPACE`, `FERRUM_TLS_NO_VERIFY`, and timeout/retry settings are normal process environment variables; set them locally, or explicitly pass them through if you customize the bundled workflows.

Every deployment environment also needs `GITFORGEOPS_STATE_APP_ID` and
`GITFORGEOPS_STATE_APP_PRIVATE_KEY` for the contents-only App that commits the
ownership ledger through the protected branch ruleset. Set repository variable
`GITFORGEOPS_STATE_APP_ID` to that same numeric ID so the scheduled audit can
verify the exact bypass actor. The repository-level
`SETTINGS_AUDIT_TOKEN` needs Administration: read and is used only by the
scheduled default-branch settings audit. See
[GitHub launch controls](docs/github-launch-controls.md).

Absent or blank runtime values use the documented defaults. Present values are
validated before repository loading, credential access, client construction,
or file output: unknown modes/strategies/roles, invalid booleans, malformed or
overflowing integers, and zero/negative timeout or JWT TTL values are errors.
Mode and boolean names are trimmed and case-insensitive; accepted booleans are
`true`, `false`, `1`, and `0`.

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
| `FERRUM_ALLOW_UNKNOWN_FIELDS` | `false` | Keep unknown **top-level** `spec` fields verbatim instead of rejecting them, for a gateway newer than this release. Nested unknown fields stay fatal either way. See [Supported fields](#supported-fields-and-what-happens-to-unsupported-ones). |
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
| `FERRUM_GATEWAY_MAX_RETRIES` | `3` | Retries connection-establishment errors and transient responses for reads/idempotent writes; create/batch POST responses are never replayed. `0` disables retries. |

`plan` and `review` fail closed if the validator cannot be started or executed.
Plan prints `Validation: ERROR` and exits nonzero; review renders
`Validation: ERROR` with a bounded diagnostic before returning nonzero. A
schema rejection remains `FAILED`, and only a completed successful validation
is `PASSED`.

## CLI reference

All commands accept `--env <name>` globally.

```
gitforgeops validate [--format text|json|github|github-annotations]
gitforgeops diff [--exit-on-drift]
gitforgeops plan
gitforgeops apply [--auto-approve] [--allow-large-prune] [--confirm-api-spec-deletion]
gitforgeops export [--output PATH] [--materialize] [--encrypt-to GH_LOGIN]
gitforgeops import --from-api | --from-file PATH [--output-dir DIR] \
  [--credential-bundle-output PRIVATE_PATH]
gitforgeops review [--pr N] [--require-live]
gitforgeops envs [--format json|text] [--include-scopes] # for CI matrix discovery
gitforgeops rotate --consumer ID --credential KEY \
  [--namespace NS] [--recipient GH_LOGIN]
```

Notes:

- `--from-api` is a flag, not a value: `gitforgeops import --from-api`. It conflicts with `--from-file`.
- `--format github` is an alias for `github-annotations`.
- `--confirm-api-spec-deletion` is the opt-in for touching resources the gateway's OpenAPI spec importer owns: a namespace with live API specs otherwise rejects `full_replace`, and exclusive incremental apply otherwise skips tagged resources. Repository/spec identity conflicts always block the whole apply before unrelated writes; the confirmation flag is not a way to make two owners share one row.
- `--allow-large-prune` acknowledges only the configured deletion percentage. A cached (`X-Data-Source: cached`) backup blocks every mutation and has no override because API-spec ownership is unknown.
- API import requires `FERRUM_NAMESPACE` (or the selected environment's namespace filter), mints an exact namespace-scoped JWT, and imports one namespace at a time. This fails closed on gateways that require namespace claims: an unscoped `GET /namespaces` intentionally returns an empty list and therefore cannot safely drive an all-namespace import.
- `review --require-live` returns non-zero after rendering the fallback report if either the gateway comparison was unavailable or the required PR comment could not be posted. The trusted PR workflow uses it; secretless static review intentionally keeps comment delivery best-effort. Review comments are UTF-8-safe and capped below GitHub's API limit, with explicit omission counts. When a review has no credential bundle, only unresolved broker-controlled leaves in Consumer credentials and plugin config are excluded from live comparison; literal siblings, extra entries, shape changes, adds/deletes, and all nonsecret fields remain authoritative.
- `envs --format json --include-scopes` emits protected environment/namespace routing for trusted CI and is not a replacement for `envs --format json`'s string array.
- `import` requires an empty output directory and publishes the complete resource tree in one directory rename. API imports refuse cached or cross-namespace snapshots because they cannot prove an authoritative source boundary. The published root includes `.gitforgeops-import.json`, a deterministic, machine-readable inventory of source/version metadata, validated count seals, written/skipped totals, namespaces, and unsupported sections; it never contains resource bodies or credential-derived values.
- Backups contain unredacted consumer credentials and raw plugin configuration. Import replaces every string credential leaf—including custom credential types—and every schema- or heuristic-classified sensitive plugin-config string with `${gh-env-secret:alloc=require}` before staging any resource file. Unknown/custom plugin configs fail closed by brokering every string. When any live secret is present, `--credential-bundle-output PRIVATE_PATH` is mandatory. It atomically writes the exact live values under their canonical broker slots, shards them into `FERRUM_CREDS_BUNDLE*` objects under the same 40 KiB policy as allocation, forces mode 0600 on Unix, and refuses any path inside the resource tree or another Git worktree. The migration bundle is published before the redacted tree, so a later publication failure cannot discard the only captured copy.
- Treat both the source backup and migration bundle as plaintext secrets. To verify locally without copying values into an environment variable, set `FERRUM_CREDS_JSON_FILE=/secure/path/migration.json` and run `gitforgeops plan`. To seed GitHub, set each top-level `FERRUM_CREDS_BUNDLE*` object as the JSON value of the same-named GitHub Environment Secret (for example, `jq -c '.FERRUM_CREDS_BUNDLE' migration.json | gh secret set FERRUM_CREDS_BUNDLE --env production`). Confirm the redacted config resolves without drift, then securely remove the local artifacts according to your storage policy.
- `import` writes per-resource YAML for the four gateway kinds only; API specs and gateway trust bundles present in the source backup are reported as skipped rather than silently dropped, because they are managed through `/api-specs` and `/gateway-trust-bundles`, not through this repo. Unknown future top-level backup sections are also named explicitly. Present `counts` / `resource_counts` objects are validated against the decoded document before publication so a truncated-but-parseable backup cannot become an incomplete desired tree.

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

### Secret Broker Slots
| Slot | Declared as |
|------|-------------|
| `ferrum/app-mobile/keyauth/key` | needs allocation (generated on apply) |
| `ferrum/web-portal/keyauth/key` | resolved |
```

## Trust and security posture

- **PR-built code never receives production secrets.** `validate-pr.yml` has a read-only token, disables persisted checkout credentials, and binds no GitHub Environment. It runs on every PR and exposes a stable required gate while internally skipping irrelevant validation. The privileged `trusted-pr-review.yml` definition comes from the default branch, requires the static run to succeed, verifies the current same-repository PR head, and gives forks no privileged steps. Its artifact contains only bounded regular YAML beneath `resources/` and `overlays/`; environment/policy configuration and ownership state are copied from the recorded protected-branch SHA after manifest verification. Live review runs separately for each protected-branch resource namespace intersected with that environment's protected ownership/filter scope, with `FERRUM_NAMESPACE` set; that also scopes the JWT claim, so a PR-authored environment mapping or `spec.namespace` override cannot turn review into a cross-namespace read. `--require-live` makes a failed gateway comparison fail the privileged job. New namespaces receive static review until their directory is trusted on `main`. A `build.rs`, workflow, executable, symlink, traversal path, or unexpected artifact file cannot cross that data boundary.
- **Apply only runs post-merge on `main`.** `apply-on-merge.yml` binds the environment; GitHub enforces protection rules (required reviewers, branch restrictions). Before mutation, the workflow resolves exactly one merged PR for the pushed commit; ambiguous/unattributed commits cannot borrow another PR's policy override or credential-delivery recipient.
- **Credential values are never written back to the repo.** `.state/` contains ownership keys with constant markers plus non-secret delivery metadata—no credential-derived hashes.
- **The state file is CI-owned and permission-attributed.** `state-guard.yml` rejects `.state/**` changes unless the latest effective override label actor currently has write/maintain/admin. Triage label authority is explicitly insufficient. Protected state commits use a short-lived, contents-only App token rather than a human PAT or unbypassable `GITHUB_TOKEN`. See [State file trust model](#state-file-trust-model).
- **Policy overrides leave a permanent trail.** PR label event + approver permission + `.state/<env>.json.overrides` record.
- **The provisioner token is the bootstrap credential.** Rotate periodically; prefer GitHub App installation tokens over PATs (automatic 1-hour expiry, org-scoped).
- **TLS material stays as GitHub secrets.** The binary only ever sees the base64-decoded PEM in-process.
- **Executable dependencies are pinned and verified.** Every third-party Action uses a full commit SHA, Rust and `cargo-llvm-cov` use exact versions, validator bytes must match publisher and checked-in SHA-256 values, and Docker bases use manifest digests without mutable package-manager installs during the release build. Releases publish max-mode provenance, SBOM attestations, a GitHub-signed GHCR provenance statement, and a retained manifest of every action/toolchain/base/binary input. Dependabot proposes controlled updates and `check_supply_chain.py` rejects regressions.
- **GitHub settings are part of the security boundary.** CODEOWNERS alone is advisory; the active ruleset, environment reviewers/branch restrictions, Actions allowlist/SHA policy, state-App bypass, and scheduled settings audit described in [GitHub launch controls](docs/github-launch-controls.md) are launch requirements.
- **Validation is hermetic.** `ferrum-edge validate` is invoked with `-m file` (or `-m mesh`) pinned and `-s` pointed at an empty settings file, so an inherited `FERRUM_MODE` or a stray `ferrum.conf` in the checkout can't turn validation into a fail-open no-op that still exits 0. Every `FERRUM_*` variable is removed from the child's environment for the same reason. The temporary spec is written through `tempfile` at mode 0600 with an unpredictable name and removed on drop — callers resolve credential placeholders *before* validating, so that file can hold live consumer credentials. If literal or resolved Consumer credential material is present, child stdout/stderr is suppressed and a generic failure is reported so a malicious or overly verbose validator cannot echo secrets into CI. `ferrum-edge validate` itself has no machine-readable output mode; the text/JSON/GitHub-annotation formats of `--format` are produced gitforgeops-side.

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

The `release` workflow publishes to two registries on every push to `main` and every protected `v*` tag. Images include BuildKit max-mode provenance and SBOM attestations; GHCR also receives a GitHub-signed build-provenance attestation tied to the pushed digest:

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
4. A tag ruleset restricts creation/update/deletion of `v*` tags to the release administrators/App

### Building locally

```bash
docker build -t gitforgeops .

docker run --rm -v $(pwd):/repo gitforgeops --env staging validate
```

The Ferrum Edge, Rust, and Debian stages are pinned by multi-architecture
manifest digest. Update those references through reviewed Dependabot PRs; do
not reintroduce a floating build argument for an executable base.

## Build, test, lint

```
cargo build                                    # Debug
cargo build --release
cargo test --test unit_tests                   # aggregated unit/integration suite
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Rust CI runs `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --test unit_tests` on PRs/pushes that touch source, tests, Cargo metadata, the Dockerfile, or the Rust CI workflow. Resource-only PRs run `validate-pr.yml` instead.

The weekly security job also rejects new vulnerabilities, unsound advisories,
and yanked active dependencies. Any unavoidable exception is exact-version,
owner-assigned, and time-bounded; see
[Dependency security policy](docs/dependency-security.md).

### Publishing your own fork's image

If you'd rather not depend on the upstream image (air-gapped env, vendored build, divergent customizations), your fork can publish its own:

1. Create a Docker Hub repo you can push to (e.g. `acme/ferrum-edge-git-forge-ops`).
2. Set repo secrets `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN`.
3. Set repo variables:
   - `GITFORGEOPS_RELEASE_ENABLED=true` — opts the fork into running `release.yml`.
   - `DOCKERHUB_IMAGE=acme/ferrum-edge-git-forge-ops` — where to push on Docker Hub. GHCR path auto-derives from the repo.
4. Push to `main` — `release.yml` builds + pushes to Docker Hub and GHCR.

### Version pinning

Set `FERRUM_EDGE_VERSION` to the release tag matching the gateway. That tag
must appear beside the SHA-256 of `ferrum-edge-linux-x86_64` in
`.github/ferrum-edge-checksums.txt`; adding or changing a pin therefore goes
through normal CODEOWNER review. The installer downloads the binary and its
publisher `.sha256` asset, verifies they agree, then verifies the computed
bytes against the checked-in digest before making the file executable. If
unset, the fallback selects the content-pinned 2026-08-27 `latest` snapshot;
if that tag moves, CI stops until the lock file is deliberately updated.

## License

PolyForm Noncommercial License 1.0.0
