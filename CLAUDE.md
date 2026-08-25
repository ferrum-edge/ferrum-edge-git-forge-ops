# CLAUDE.md — gitforgeops

## Project Overview

`gitforgeops` — GitOps CLI that turns a directory of per-resource YAML files into a Ferrum Edge gateway configuration and reconciles it with a running gateway. Consumed by the CI workflows in `.github/workflows/` on the user's fork; forks add resources under `resources/<namespace>/`, open a PR, CI validates + previews, and post-merge workflows apply.

Rust 2021 edition. Single binary `gitforgeops`. License: PolyForm Noncommercial 1.0.0.

Companion to [ferrum-edge](https://github.com/ferrum-edge/ferrum-edge) — shells out to `ferrum-edge validate` for schema validation and talks to the admin REST API for live operations.

## Commands

All commands accept `--env <name>` to select an environment declared in
`.gitforgeops/config.yaml`. When unset, `FERRUM_ENV` is the fallback; when that
is also unset and the repo config has one entry or a `default_environment`,
that is used.

```bash
gitforgeops validate [--format text|json|github|github-annotations] # Assemble + shell to `ferrum-edge validate`
gitforgeops export [--output PATH]                        # Emit flat YAML (placeholders preserved) + mesh doc
gitforgeops export --materialize [--encrypt-to GH_LOGIN]  # Resolve creds; age-encrypt output (file mode stage 2)
gitforgeops diff [--exit-on-drift]                        # Compare desired vs live gateway (/backup)
gitforgeops plan                                          # Validate + diff + breaking + security + best-practice + policy
gitforgeops apply [--auto-approve] [--allow-large-prune] \
  [--confirm-api-spec-deletion]                           # Apply incrementally (CRUD) or full-replace (/restore)
gitforgeops import --from-api | --from-file PATH [--output-dir DIR]  # --from-api is a flag, not a value
gitforgeops review [--pr N]                               # Post structured PR comment via GitHub API
gitforgeops envs [--format json|text]                     # List environments (used by CI matrix)
gitforgeops rotate --consumer ID --credential KEY \       # Rotate a credential slot and re-deliver
  [--namespace NS] [--recipient GH_LOGIN]
```

## Build / Test / Lint

```bash
cargo build                                   # Debug
cargo build --release
cargo test --test unit_tests                  # Single aggregated test binary
cargo clippy --all-targets -- -D warnings
cargo fmt --all && cargo fmt --all -- --check
```

### Before Every Commit — MANDATORY

1. `cargo fmt --all`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --test unit_tests`

`.github/workflows/rust-ci.yml` runs those same three on every PR that touches
`src/**`, `tests/**`, `Cargo.{toml,lock}`, or the Dockerfile. Resource-only
PRs (touching `resources/**`, `overlays/**`, `.gitforgeops/**`) skip Rust CI
and run `validate-pr.yml` instead; the two paths are mutually exclusive.

## Architecture

### Pipeline

```
resources/<ns>/{proxies,consumers,upstreams,plugins,mesh}/*.yaml
  → loader::load_resources   (walkdir, kind-tagged Resource enum incl. MeshConfig)
  → overlays/<env>/...       (object deep-merge via apply_overlay; arrays replace
                              except additive spec.plugins/spec.targets and mesh
                              spec.workloads (by spiffe_id) / spec.services
                              (by name+namespace))
  → assembler::assemble      (AssembledOutput { gateway: GatewayConfig,
                              mesh: Option<MeshConfigSpec> }; directory namespace
                              inference; merge_mesh_fragments concatenates lists
                              and errors on conflicting singletons;
                              normalize_consumer_credentials folds bare-object
                              credentials into the canonical array form)
  → secrets::resolve_secrets (replace ${gh-env-secret:...} placeholders in-memory
                              from FERRUM_CREDS_JSON_FILE or FERRUM_CREDS_JSON,
                              never written back to disk)
  → policy::evaluate_policies
  → validate / export / diff / plan / apply / review / rotate
                             (gateway doc → FERRUM_FILE_OUTPUT_PATH,
                              mesh doc → FERRUM_MESH_FILE_OUTPUT_PATH)
```

### Gateway Modes

- **api** — push to admin REST (POST creates, PUT updates, DELETE removes, POST `/batch` for pure-add namespaces, or POST `/restore` for full-replace)
- **file** — assemble flat YAML for a file-mode Ferrum Edge gateway, published atomically (temp + fsync + rename) with a `resource_counts` seal

Set via `FERRUM_GATEWAY_MODE`. Mesh config is file-only in both modes — there is no mesh admin API, so an api-mode apply validates the mesh document and prints a notice instead of pushing it.

### Apply Strategies

- **incremental** (default) — compute diff against `/backup`, then CRUD per changed resource in dependency order (`operation_rank`: add/modify upstream+consumer → proxy → plugin config, then deletes in reverse). Deletes tolerate 404. A namespace whose diff is **pure adds** takes the transactional `POST /batch` fast path (create-only, all-or-nothing, chunked under the 1 MiB body cap), falling back to per-resource creates on 501.
- **full_replace** — POST to `/restore?confirm=true` atomically **per namespace** (not environment-wide; a multi-namespace exclusive env can partial-fail if namespace N's restore errors after namespace N-1's succeeded, and the aggregate error enumerates both). The live `api_specs` / `gateway_trust_bundles` sections are read from `/backup` and carried through the restore verbatim unless `--confirm-api-spec-deletion` is passed — a bare restore reads as "delete every API spec in this namespace" and the gateway answers 409.

Set via `FERRUM_APPLY_STRATEGY`. Incremental is safer (partial-failure visibility, no destructive no-op replace); full_replace is stronger (per-namespace atomic, removes drift). For strict environment-wide atomicity, scope `full_replace` to a single namespace.

A `GET /health` preflight runs before the first mutation so a read-only plane fails once instead of N times; a sticky `X-Data-Source: cached` on any `/backup` blocks prune computation unless `--allow-large-prune` acknowledges the stale view. After apply, a best-effort `GET /cluster` prints a convergence line.

### Mesh config

`kind: MeshConfig` fragments live under `resources/<ns>/mesh/`. They are not gateway resources: every fragment folds into one standalone `{version: "1", mesh: {...}}` document (`apply::render_mesh_yaml`, `MESH_DOCUMENT_VERSION`) published to `FERRUM_MESH_FILE_OUTPUT_PATH` by `export` and file-mode `apply`. `validate` / `plan` / `apply` run a second pass, `ferrum-edge validate -m mesh`, over the rendered bytes. Mesh resources never appear in `diff` — there is no live API to compare against.

### Namespace Handling

- Directory-inferred: `resources/<ns>/…` → resource `namespace: <ns>` unless the spec overrides with a non-default value.
- `FERRUM_NAMESPACE` filters everything (load, diff, apply, import). When unset, all namespaces round-trip.
- API calls send `X-Ferrum-Namespace: <ns>` per namespace; `split_config_by_namespace()` groups operations.

### Multi-Environment (repo config)

`.gitforgeops/config.yaml` declares logical environments. Each entry picks an
overlay, apply strategy, and ownership mode. **No gateway URL, no JWT, no
secret names** live in this file — those come from GitHub Environment Secrets
of the same name as the entry (e.g. `production` entry → GitHub Environment
`production`'s secrets are injected by the workflow). See
`.gitforgeops/config.example.yaml`.

Workflows run as a matrix over `gitforgeops envs --format json`, binding
`environment: ${{ matrix.environment }}` to pull the scoped secrets. Concurrency
groups serialize per-env applies so two concurrent writes to the same
environment never interleave.

### Ownership modes

Configured per environment in repo config.

- **`shared`** (default, safer): repo manages only what it has previously applied.
  State file is the fence — unknown resources on the gateway are reported as
  *unmanaged* and left alone. `full_replace` is rejected in this mode.
- **`exclusive`**: repo is authoritative for the listed `namespaces`. Unmanaged
  resources get pruned. Required for `full_replace`.

The state file is the trust boundary for both of those, and it is CI-authored:
`apply-on-merge.yml` / `rotate.yml` commit `.state/<env>.json` back to `main`
as `gitforgeops[bot]`, `.gitignore` tracks `.state/*.json` (ignoring only locks
and temp files), and `state-guard.yml` fails any PR touching `.state/**` unless
a maintainer adds the `gitforgeops/state-override` label. That workflow runs
on **every** PR with no `paths:` filter and decides internally whether
`.state/` was touched — a path-filtered workflow reports no status on
non-matching PRs, which stalls them forever once the check is required. Keep the fence there
rather than narrowing what the binary reads out of the ledger — shared mode
must keep reconciling namespaces the repo no longer declares, or a PR that
removes a namespace's last resource orphans it on the gateway forever.

`diff::compute_diff_with_ownership` takes an optional `previously_managed: &HashSet<String>`
of `namespace:Kind:id` keys from the state file. `Some(set)` = shared mode,
`None` = exclusive. Large-prune guard refuses applies that would delete more
than `ownership.large_prune_threshold_percent` of the managed set unless
`--allow-large-prune` is passed.

#### Spec-owned tier

There is a third owner besides this repo and a human admin: the gateway's
OpenAPI **spec ingestion** (`/api-specs`), which atomically provisions proxies,
upstreams and plugin configs and tags them `api_spec_id: Some(...)`. Its
re-imports are authoritative, so gitforgeops stays off those rows entirely —
in *both* ownership modes, and regardless of what the state file says.

Any **live** resource with `api_spec_id` set is classified `spec_owned`
(`DiffResult::spec_owned`, its own bucket — not `unmanaged`):

- Never emitted as a Modify. If the repo also declares the same
  `(namespace, kind, id)`, that is reported as a **conflict**
  (`DiffResult::spec_conflicts()`): two owners writing one row, and the spec
  importer wins on its next run.
- Never emitted as a Delete, except in **exclusive** mode with
  `apply --confirm-api-spec-deletion` (`DiffOptions::prune_spec_owned`).
  Otherwise apply skips them with a per-resource message and counts them in
  `ApplyResult::spec_owned_skipped`. Shared mode ignores the flag — the state
  file is its fence and a spec-owned row was never behind it.
- Rendered in `plan` / `diff` stdout and in the PR comment's "Spec-owned
  Resources" section. Unlike the unmanaged block, it is *not* gated on
  `ownership.drift_report`: a repo fighting the spec importer is a correctness
  problem, not drift noise.

The same flag also drives `full_replace`, where `/restore` would otherwise wipe
the namespace's `api_specs` section (see Apply Strategies).

### Policy framework

`.gitforgeops/policies.yaml` declares enforceable standards. Each rule lives
in `src/policy/rules/` and implements `PolicyCheck`. Register new rules in
`src/policy/registry.rs::build_registry` and add its typed config to
`src/policy/config.rs::PolicyRules`.

Rules: `proxy_timeout_bands`, `backend_scheme`, `require_auth_plugin`,
`forbid_tls_verify_disabled`, `allowed_proxy_plugins`, `allowed_backend_domains`,
`waf_enforcement`, `require_ai_guardrails`, `rate_limit_completeness`,
`plugin_name_is_known`, `priority_override_range`. All default to `enabled: false`.

Plugin-name knowledge lives in `src/plugin_catalog.rs` (82 builtins, retired and
reserved names, the 11 auth plugins, and `effective_plugins` merge semantics
where a scoped plugin config replaces a global one of the same `plugin_name`).
Rules that reason about plugins go through it rather than hard-coding names.

Severity `error` blocks `apply` unless overridden. Override = PR label
(configurable name) added by a user whose repo permission is ≥
`overrides.required_permission` (default `write`). Implementation:
`src/policy/github_override.rs::check_override`.

### Credential broker (in-GitHub, no third-party)

Consumer credentials use placeholders like
`keyauth: [{ key: "${gh-env-secret:alloc=generate}" }]`. Slot names are derived
from `(namespace, consumer_id, cred_key)` — never hand-written.

ferrum-edge recognizes exactly five credential types, each an **array** of
entries (`KNOWN_CREDENTIAL_TYPES`): `basicauth`, `keyauth`, `jwt`, `hmac_auth`,
`mtls_auth`. The array form is canonical — `/backup` always returns it, so a
bare object is permanent false drift; the assembler normalizes the object form
on load. Slot paths elide `ArrayIndex(0)` so the normalization doesn't rename
(and orphan) already-allocated slots; entries ≥1 get a `[N]` segment. Older
encodings stay in the read-only lookup candidate list.

Generation constraints, enforced at resolve time so `plan` fails before `apply`
writes an unusable value: `jwt`/`hmac_auth` secrets need ≥32 chars (`len=` ≥ 24
entropy bytes); `basicauth` generation is refused in file mode and
`basicauth/…/password_hash` in either mode (the hash is HMAC-SHA256 under the
gateway's own secret); a bundle value of `[REDACTED]` is refused.

Storage: one or more GitHub Environment Secrets named `FERRUM_CREDS_BUNDLE[_N]`,
each holding a JSON object of `slot → value`. Capacity ~440 slots per bundle,
auto-sharded by fnv-style hash when a bundle approaches 40 KB. The apply
workflow's "Load credential bundles" step collects all matching secrets via
`${{ toJSON(secrets) }}`, writes the filtered payload to a runner-local file,
and exports the path as `FERRUM_CREDS_JSON_FILE`. Inline `FERRUM_CREDS_JSON`
is still supported for small local tests.

Allocation (first apply, or rotation): generate random value → libsodium
`crypto_box_seal` to the env's public key → PUT to
`repos/.../environments/<env>/secrets/FERRUM_CREDS_BUNDLE[_N]`. Writes require
`FERRUM_GH_PROVISIONER_TOKEN` (GitHub App installation token preferred, PAT
with `Secrets: write` as fallback).

Delivery: after allocation or rotation, the value is age-encrypted to the PR
author's (or dispatcher's) SSH public key fetched from
`GET /users/{login}/keys`, then posted as a PR comment or workflow output.
Author decrypts with `age -d -i ~/.ssh/id_ed25519`.

### Source Layout

- `src/main.rs` — async Tokio entry, command dispatch
- `src/cli.rs` — clap parser (global `--env` flag, subcommands incl. `envs`, `rotate`)
- `src/config/` — `schema.rs` (permissive serde mirror of Ferrum Edge types, incl. `BackendScheme` with legacy-value folding and `MeshConfigSpec`), `loader.rs` (walks `proxies/consumers/upstreams/plugins/mesh`), `assembler.rs` (overlay deep-merge via `serde_json::Value`, `merge_mesh_fragments`, `normalize_consumer_credentials`), `env.rs` (process-env vars), `repo_config.rs` (`.gitforgeops/config.yaml`), `resolved.rs` (merges repo + env-var into a single `ResolvedEnv` per invocation)
- `src/diff/` — `resource_diff.rs` (add/modify/delete + field-level changes + unmanaged and spec-owned tracking), `breaking.rs`, `security.rs`, `best_practice.rs`
- `src/apply/` — `api_target.rs` (incremental + full_replace, dependency ordering, `/batch` fast path, ownership-aware delete filter, spec-owned skip messages), `file_target.rs` (atomic publish, `resource_counts` seal, `render_mesh_yaml` / `apply_mesh_file`)
- `src/plugin_catalog.rs` — 82 builtin plugin names, retired/reserved names, auth/rate-limit/observability/AI-guardrail groupings, `effective_plugins` merge, small `cfg_*` JSON accessors
- `src/policy/` — `config.rs` (yaml + override config), `registry.rs`, `rules/*` (one file per rule), `github_override.rs` (label + permission check via GitHub API)
- `src/secrets/` — `placeholder.rs` (`${gh-env-secret:...}` parser), `bundle.rs` (shard layout + hash), `resolver.rs` (walks consumers, replaces in-memory), `github_api.rs` (libsodium seal + PUT), `delivery.rs` (age encryption to SSH pubkey), `allocator.rs` (generate + write + deliver)
- `src/http_client.rs` — `AdminClient` wrapping reqwest; base64-encoded PEM for CA / mTLS from env; typed `ApiErrorBody` + `classify_retry` (408/429/5xx retry, 501 and `applied:false` never), `Retry-After` honoring, paginated list helpers, `BackupExtras` (api_specs / trust bundles), `ClusterStatus` + `convergence_summary`
- `src/validate/` — `runner.rs` shells to `ferrum-edge validate` with `-m file` / `-m mesh` pinned, an empty `-s` settings file, `FERRUM_*` scrubbed from the child env, and a 0600 temp spec; `reporter.rs` formats (text/JSON/GitHub annotations) for one or both passes
- `src/review/` — `pr_comment.rs` builds markdown (v2 includes unmanaged, spec-owned, policy, credential sections), `github.rs` posts via GitHub API
- `src/import/` — `from_api.rs` (walks namespaces, pulls `/backup`), `from_file.rs`, `mod.rs::split_config` (emits per-resource YAML; reports skipped `api_specs` / trust-bundle sections instead of dropping them silently)
- `src/state.rs` — `.state/<env>.json` tracks applied hashes, credential metadata, shard count, override history
- `src/reconcile.rs` — `resolved_namespaces` (which namespaces a run iterates; shared mode unions repo-declared with state-derived so orphans stay reconcilable) and `previously_managed` (the shared-mode delete fence)
- `src/jwt.rs` — mints HS256 tokens for admin API auth
- `src/error.rs` — unified `Error` enum via `thiserror`

### Key Design Principles

1. **Permissive schema** — Serde types mirror Ferrum Edge but accept unknown fields. The gateway (via `validate`) is the authoritative schema.
2. **Path-component sanitization** — resource `namespace` and `id` flow into filesystem paths during `import`. `import::safe_path_component` rejects `..`, `/`, `\`, null bytes, and empty strings before `Path::join` to prevent traversal.
3. **Deterministic state hashes** — resources hash through `serde_json::Value` first (BTreeMap-backed in default builds) so `HashMap` field ordering doesn't produce false-positive drift in `.state/<env>.json`.
4. **Namespace-scoped operations** — every API call, diff entry, and breaking-change lookup keys on `(namespace, id)`, never `id` alone.
5. **Partial-failure visibility** — incremental apply reports per-resource errors via `ApplyResult`; failures don't abort the whole run.

## Key Environment Variables

See `.env.example` for the full list. Essentials:

- `FERRUM_GATEWAY_URL` (required for api mode)
- `FERRUM_ADMIN_JWT_SECRET` (required for api mode; ≥32 chars to match ferrum-edge)
- `FERRUM_ADMIN_JWT_ISSUER` (default `ferrum-edge`) — must equal the gateway's own issuer or every call is 401
- `FERRUM_ADMIN_JWT_ROLE` (default `admin`) — `/backup`, `/restore`, `/batch` and consumer CRUD are admin-only
- `FERRUM_ADMIN_JWT_AUDIENCE` (default unset) — `aud` is emitted only when set; a gateway with no audience rejects tokens carrying it
- `FERRUM_ADMIN_JWT_TTL_SECS` (default `3600`) — must be within the gateway's `FERRUM_ADMIN_JWT_MAX_TTL`
- `FERRUM_NAMESPACE` (filter; default = all namespaces)
- `FERRUM_GATEWAY_MODE` = `api` | `file` (default `api`)
- `FERRUM_APPLY_STRATEGY` = `incremental` | `full_replace` (default `incremental`)
- `FERRUM_OVERLAY` (applies `overlays/<name>/` deep-merge)
- `FERRUM_EDGE_BINARY_PATH` (default `ferrum-edge` on `$PATH`)
- `FERRUM_FILE_OUTPUT_PATH` (file mode; default `./assembled/resources.yaml`)
- `FERRUM_MESH_FILE_OUTPUT_PATH` (default `./assembled/mesh.yaml`) — standalone `{version, mesh}` document; separate file from the gateway doc, written by `export` and file-mode `apply` whenever the repo declares any `MeshConfig`
- `FERRUM_TLS_NO_VERIFY` (dev only)
- `FERRUM_GATEWAY_CA_CERT` / `FERRUM_GATEWAY_CLIENT_CERT` / `FERRUM_GATEWAY_CLIENT_KEY` — base64-encoded PEM. mTLS requires BOTH cert and key; setting only one is rejected.
- `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` (default `10`) — TCP/TLS handshake cap
- `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` (default `60`) — end-to-end request cap; raise for large `/backup` or slow `/restore`
- `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` (default `10`) — same shape, for `gitforgeops review --pr N`
- `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` (default `30`) — GitHub API call is small; 30s is plenty
- `FERRUM_GATEWAY_MAX_RETRIES` (default `3`) — retries on connect errors, 408, 429, 500/502/503/504; exponential backoff 500ms·2^n capped at 8s, or `Retry-After` (capped 30s) when present. NOT retried: timeouts (ambiguous state), 501, `applied:false` bodies, `/restore` 500 with `rollback: incomplete|unknown_outcome`.

## Testing

- `tests/unit_tests.rs` is the single integration test binary; submodules live under `tests/unit/*.rs` and register in `tests/unit/mod.rs`.
- Fixtures under `tests/fixtures/` (`simple-config/`, `overlay-test/`).
- New test file: create `tests/unit/<name>.rs` AND add `mod <name>;` to `tests/unit/mod.rs`.
- `tempfile` crate for filesystem tests.
- No network in tests — `AdminClient::new` constructs the client without connecting, so credential-validation paths can be exercised without mocking.

## Development Guidelines

- **No `.unwrap()` in production code paths** — use `?`, `.unwrap_or()`, or explicit match.
- **No `.expect()` except where failure is a genuine bug** (e.g. `serde_json::to_string` on a static `Value`).
- Return `crate::error::Error` variants via `?`; prefer descriptive variants over `Config(String)` when the category is clear.
- New `FERRUM_*` env vars: add to `EnvConfig`, `load_env_config()`, `.env.example`, and doc block in `env.rs`.
- Schema additions: mirror the Ferrum Edge struct, keep `#[serde(default)]` + `#[serde(skip_serializing_if = "Option::is_none")]` for optional fields. Don't validate — ferrum-edge does.

## PR Checklist

1. `cargo fmt --all` clean
2. `cargo clippy --all-targets -- -D warnings` clean
3. `cargo test --test unit_tests` passes
4. No `.unwrap()` / `.expect()` in prod code
5. New env var → `.env.example` + `env.rs` doc block
6. Schema change → unit test in `tests/unit/schema_tests.rs`
7. Commit messages in imperative mood; branches `feature/…`, `fix/…`, `claude/…`
