# CLAUDE.md — gitforgeops

## Project Overview

`gitforgeops` — GitOps CLI that turns a directory of per-resource YAML files into a Ferrum Edge gateway configuration and reconciles it with a running gateway. Consumed by the CI workflows in `.github/workflows/` on the user's fork; forks add resources under `resources/<namespace>/`, open a PR, and CI validates + previews + applies.

Rust 2021 edition. Single binary `gitforgeops`. License: PolyForm Noncommercial 1.0.0.

Companion to [ferrum-edge](https://github.com/ferrum-edge/ferrum-edge) — shells out to `ferrum-edge validate` for schema validation and talks to the admin REST API for live operations.

## Commands

```bash
gitforgeops validate [--format text|json|github]         # Assemble + shell to `ferrum-edge validate`
gitforgeops export [--output PATH]                        # Emit flat YAML (file-mode gateways)
gitforgeops diff [--exit-on-drift]                        # Compare desired vs live gateway (/backup)
gitforgeops plan                                          # Validate + diff + breaking + security + best-practice
gitforgeops apply [--auto-approve]                        # Apply incrementally (CRUD) or full-replace (/restore)
gitforgeops import --from-api | --from-file PATH [--output-dir DIR]
gitforgeops review [--pr N]                               # Post structured PR comment via GitHub API
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

CI runs the same three on every PR.

## Architecture

### Pipeline

```
resources/<ns>/{proxies,consumers,upstreams,plugins}/*.yaml
  → loader::load_resources   (walkdir, kind-tagged Resource enum)
  → overlays/<env>/...       (optional deep-merge via apply_overlay)
  → assembler::assemble      (flat GatewayConfig, directory namespace inference)
  → validate / export / diff / plan / apply / review
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

### Source Layout

- `src/main.rs` — async Tokio entry, command dispatch
- `src/cli.rs` — clap parser
- `src/config/` — `schema.rs` (permissive serde mirror of Ferrum Edge types), `loader.rs`, `assembler.rs` (overlay deep-merge via `serde_json::Value`), `env.rs`
- `src/diff/` — `resource_diff.rs` (add/modify/delete + field-level changes), `breaking.rs`, `security.rs`, `best_practice.rs`
- `src/apply/` — `api_target.rs` (incremental + full_replace), `file_target.rs`
- `src/http_client.rs` — `AdminClient` wrapping reqwest; base64-encoded PEM for CA / mTLS from env
- `src/validate/` — `runner.rs` shells to `ferrum-edge validate`, `reporter.rs` formats (text/JSON/GitHub annotations)
- `src/review/` — `pr_comment.rs` builds markdown, `github.rs` posts via GitHub API
- `src/import/` — `from_api.rs` (walks namespaces, pulls `/backup`), `from_file.rs`, `mod.rs::split_config` (emits per-resource YAML)
- `src/state.rs` — `.state/state.json` tracks applied hashes + commit SHA
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
