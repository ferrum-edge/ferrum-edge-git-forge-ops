# CLAUDE.md — gitforgeops

## Project Overview

`gitforgeops` — GitOps CLI that turns a directory of per-resource YAML files into a Ferrum Edge gateway configuration and reconciles it with a running gateway. Consumed by the CI workflows in `.github/workflows/` on the user's fork; forks add resources under `resources/<namespace>/`, open a PR, and CI validates + previews + applies.

Rust 2021 edition. Single binary `gitforgeops`. License: PolyForm Noncommercial 1.0.0.

Companion to [ferrum-edge](https://github.com/ferrum-edge/ferrum-edge) — shells out to `ferrum-edge validate` for schema validation and talks to the admin REST API for live operations.

## Commands

All commands accept `--env <name>` to select an environment declared in
`.gitforgeops/config.yaml`. When unset, `FERRUM_ENV` is the fallback; when that
is also unset and the repo config has one entry or a `default_environment`,
that is used.

```bash
gitforgeops validate [--format text|json|github]         # Assemble + shell to `ferrum-edge validate`
gitforgeops export [--output PATH]                        # Emit flat YAML (placeholders preserved)
gitforgeops export --materialize [--encrypt-to GH_LOGIN]  # Resolve creds; age-encrypt output (file mode stage 2)
gitforgeops diff [--exit-on-drift]                        # Compare desired vs live gateway (/backup)
gitforgeops plan                                          # Validate + diff + breaking + security + best-practice + policy
gitforgeops apply [--auto-approve] [--allow-large-prune]  # Apply incrementally (CRUD) or full-replace (/restore)
gitforgeops import --from-api | --from-file PATH [--output-dir DIR]
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
resources/<ns>/{proxies,consumers,upstreams,plugins}/*.yaml
  → loader::load_resources   (walkdir, kind-tagged Resource enum)
  → overlays/<env>/...       (deep-merge via apply_overlay, overlay picked by env)
  → assembler::assemble      (flat GatewayConfig, directory namespace inference)
  → secrets::resolve_secrets (replace ${gh-env-secret:...} placeholders in-memory
                              from FERRUM_CREDS_JSON bundle, never written back to disk)
  → policy::evaluate_policies
  → validate / export / diff / plan / apply / review / rotate
```

### Gateway Modes

- **api** — push to admin REST (POST `/batch` or `/restore`, PUT/DELETE per resource)
- **file** — assemble flat YAML for a file-mode Ferrum Edge gateway

Set via `FERRUM_GATEWAY_MODE`.

### Apply Strategies

- **incremental** (default) — compute diff against `/backup`, then CRUD per changed resource
- **full_replace** — POST to `/restore?confirm=true` atomically

Set via `FERRUM_APPLY_STRATEGY`. Incremental is safer (partial-failure visibility, no destructive no-op replace); full_replace is stronger (atomic, removes drift).

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

`diff::compute_diff_with_ownership` takes an optional `previously_managed: &HashSet<String>`
of `namespace:Kind:id` keys from the state file. `Some(set)` = shared mode,
`None` = exclusive. Large-prune guard refuses applies that would delete more
than `ownership.large_prune_threshold_percent` of the managed set unless
`--allow-large-prune` is passed.

### Policy framework

`.gitforgeops/policies.yaml` declares enforceable standards. Each rule lives
in `src/policy/rules/` and implements `PolicyCheck`. Register new rules in
`src/policy/registry.rs::build_registry` and add its typed config to
`src/policy/config.rs::PolicyRules`.

Starter rules: `proxy_timeout_bands`, `backend_scheme`, `require_auth_plugin`,
`forbid_tls_verify_disabled`.

Severity `error` blocks `apply` unless overridden. Override = PR label
(configurable name) added by a user whose repo permission is ≥
`overrides.required_permission` (default `write`). Implementation:
`src/policy/github_override.rs::check_override`.

### Credential broker (in-GitHub, no third-party)

Consumer credentials use placeholders like
`key: "${gh-env-secret:alloc=generate}"`. Slot names are derived from
`(namespace, consumer_id, cred_key)` — never hand-written.

Storage: one or more GitHub Environment Secrets named `FERRUM_CREDS_BUNDLE[_N]`,
each holding a JSON object of `slot → value`. Capacity ~440 slots per bundle,
auto-sharded by fnv-style hash when a bundle approaches 40 KB. The apply
workflow's "Load credential bundles" step collects all matching secrets via
`${{ toJSON(secrets) }}` and exports them as `FERRUM_CREDS_JSON`.

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
- `src/config/` — `schema.rs` (permissive serde mirror of Ferrum Edge types), `loader.rs`, `assembler.rs` (overlay deep-merge via `serde_json::Value`), `env.rs` (process-env vars), `repo_config.rs` (`.gitforgeops/config.yaml`), `resolved.rs` (merges repo + env-var into a single `ResolvedEnv` per invocation)
- `src/diff/` — `resource_diff.rs` (add/modify/delete + field-level changes + unmanaged tracking), `breaking.rs`, `security.rs`, `best_practice.rs`
- `src/apply/` — `api_target.rs` (incremental + full_replace, ownership-aware delete filter), `file_target.rs`
- `src/policy/` — `config.rs` (yaml + override config), `registry.rs`, `rules/*` (one file per rule), `github_override.rs` (label + permission check via GitHub API)
- `src/secrets/` — `placeholder.rs` (`${gh-env-secret:...}` parser), `bundle.rs` (shard layout + hash), `resolver.rs` (walks consumers, replaces in-memory), `github_api.rs` (libsodium seal + PUT), `delivery.rs` (age encryption to SSH pubkey), `allocator.rs` (generate + write + deliver)
- `src/http_client.rs` — `AdminClient` wrapping reqwest; base64-encoded PEM for CA / mTLS from env
- `src/validate/` — `runner.rs` shells to `ferrum-edge validate`, `reporter.rs` formats (text/JSON/GitHub annotations)
- `src/review/` — `pr_comment.rs` builds markdown (v2 includes unmanaged, policy, credential sections), `github.rs` posts via GitHub API
- `src/import/` — `from_api.rs` (walks namespaces, pulls `/backup`), `from_file.rs`, `mod.rs::split_config` (emits per-resource YAML)
- `src/state.rs` — `.state/<env>.json` tracks applied hashes, credential metadata, shard count, override history
- `src/jwt.rs` — mints HS256 tokens for admin API auth
- `src/error.rs` — unified `Error` enum via `thiserror`

### Key Design Principles

1. **Permissive schema** — Serde types mirror Ferrum Edge but accept unknown fields. The gateway (via `validate`) is the authoritative schema.
2. **Path-component sanitization** — resource `namespace` and `id` flow into filesystem paths during `import`. `import::safe_path_component` rejects `..`, `/`, `\`, null bytes, and empty strings before `Path::join` to prevent traversal.
3. **Deterministic state hashes** — resources hash through `serde_json::Value` first (BTreeMap-backed in default builds) so `HashMap` field ordering doesn't produce false-positive drift in `.state/state.json`.
4. **Namespace-scoped operations** — every API call, diff entry, and breaking-change lookup keys on `(namespace, id)`, never `id` alone.
5. **Partial-failure visibility** — incremental apply reports per-resource errors via `ApplyResult`; failures don't abort the whole run.

## Key Environment Variables

See `.env.example` for the full list. Essentials:

- `FERRUM_GATEWAY_URL` (required for api mode)
- `FERRUM_ADMIN_JWT_SECRET` (required for api mode; ≥32 chars to match ferrum-edge)
- `FERRUM_NAMESPACE` (filter; default = all namespaces)
- `FERRUM_GATEWAY_MODE` = `api` | `file` (default `api`)
- `FERRUM_APPLY_STRATEGY` = `incremental` | `full_replace` (default `incremental`)
- `FERRUM_OVERLAY` (applies `overlays/<name>/` deep-merge)
- `FERRUM_EDGE_BINARY_PATH` (default `ferrum-edge` on `$PATH`)
- `FERRUM_FILE_OUTPUT_PATH` (file mode; default `./assembled/resources.yaml`)
- `FERRUM_TLS_NO_VERIFY` (dev only)
- `FERRUM_GATEWAY_CA_CERT` / `FERRUM_GATEWAY_CLIENT_CERT` / `FERRUM_GATEWAY_CLIENT_KEY` — base64-encoded PEM. mTLS requires BOTH cert and key; setting only one is rejected.
- `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` (default `10`) — TCP/TLS handshake cap
- `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` (default `60`) — end-to-end request cap; raise for large `/backup` or slow `/restore`
- `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` (default `10`) — same shape, for `gitforgeops review --pr N`
- `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` (default `30`) — GitHub API call is small; 30s is plenty
- `FERRUM_GATEWAY_MAX_RETRIES` (default `3`) — retries on connect errors, 5xx, 429; exponential backoff 500ms·2^n capped at 8s. Timeouts NOT retried (ambiguous state).

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
