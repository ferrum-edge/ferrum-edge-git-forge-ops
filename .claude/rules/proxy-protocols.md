---
paths:
  - "src/config/schema.rs"
  - "src/diff/**"
  - "src/plugin_catalog.rs"
  - "tests/unit/{analysis,diff,schema}_tests.rs"
  - "resources/*/{proxies,upstreams}/**"
  - "overlays/*/{proxies,upstreams}/**"
---

# Proxy and upstream configuration rules

GitForgeOps models gateway configuration; it does not implement proxy data-plane protocols.

- Keep proxy and upstream Serde types compatible with the companion gateway while preserving
  unknown fields. Do not add local schema validation that belongs to `ferrum-edge validate`.
- `BackendScheme` accepts the documented legacy values and serializes the canonical spelling.
  Absence resolves to HTTPS for analysis/diff semantics without inventing an explicit field in
  exported YAML.
- A proxy referencing an upstream omits direct backend host/port/scheme fields. Direct and
  upstream-backed routing must not be conflated in diff or policy checks.
- Breaking analysis is namespace scoped and covers resource deletion plus listener, backend scheme,
  passthrough, TLS, and upstream-subset changes. Avoid flagging equivalent normalized forms.
- Security and best-practice analysis must consider global plus scoped effective plugins, upstream
  targets, health checks, timeouts, TLS verification, and explicit fail-open controls.
- Preserve stable field-level diff output and mask only sensitive leaves. A masking change must not
  erase shape drift, array-entry additions, or non-secret sibling changes.
- New schema fields remain optional with `#[serde(default)]` and
  `#[serde(skip_serializing_if = "Option::is_none")]` when appropriate.

## Verification

Schema changes require `tests/unit/schema_tests.rs`; diff and analysis behavior belongs in the
matching flat unit modules. Run the mandatory repository gate before every commit.
