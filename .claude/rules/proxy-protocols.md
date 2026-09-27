---
paths:
  - "src/config/schema.rs"
  - "src/diff/**"
  - "src/plugin_catalog.rs"
  - "tests/unit/{analysis,diff,schema}_tests.rs"
  - "resources/*/{proxies,upstreams}/**"
  - "overlays/**"
---

# Proxy and upstream configuration rules

GitForgeOps models gateway configuration; it does not implement proxy data-plane protocols.

- Keep proxy and upstream Serde types in step with the companion gateway. Unknown fields fail
  closed; only top-level `spec` fields pass through, under `FERRUM_ALLOW_UNKNOWN_FIELDS=true`. Do
  not add local schema validation that belongs to `ferrum-edge validate`.
- `BackendScheme` accepts the legacy values (and the `backend_protocol` field alias) and
  serializes the canonical spelling. `assembler::normalize_proxy_backend_schemes` sets an omitted
  `backend_scheme` to `https` on non-stream proxies, matching what the gateway stores, so the
  assembled and exported document carries it explicitly. Stream proxies (discriminated by
  `listen_port`) are left unset so validation rejects them instead of guessing `tcp`.
- When `upstream_id` supplies the dial address, `backend_host`/`backend_port` may be empty/0; a
  non-empty `backend_host` is a fallback that policy still checks. Do not conflate direct and
  upstream-backed routing in diff or policy checks.
- Breaking analysis (`src/diff/breaking.rs`) is namespace scoped. It covers Proxy/Consumer
  deletion, `listen_path`, `hosts`, `listen_port`, `backend_scheme`, `frontend_tls`,
  `passthrough` and `upstream_subset` changes, and auth-plugin removal or lost authenticator
  coverage. Avoid flagging equivalent normalized forms.
- Security and best-practice analysis must consider global plus scoped effective plugins, upstream
  targets, health checks, timeouts, TLS verification, and explicit fail-open controls.
- Preserve stable field-level diff output and mask only sensitive leaves. A masking change must not
  erase shape drift, array-entry additions, or non-secret sibling changes.
- New schema fields remain optional with `#[serde(default)]` and
  `#[serde(skip_serializing_if = "Option::is_none")]` when appropriate.

## Verification

Schema changes require `tests/unit/schema_tests.rs`; diff and analysis behavior belongs in the
matching flat unit modules. Run the mandatory repository gate before every commit.
