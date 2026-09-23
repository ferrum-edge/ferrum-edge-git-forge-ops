---
paths:
  - "src/apply/**"
  - "src/diff/**"
  - "src/http_client.rs"
  - "src/import/**"
  - "src/review/**"
  - "tests/unit/{apply,diff,http_client,import,review}_tests.rs"
---

# Admin API and reconciliation rules

- All live operations are namespace scoped. Send `X-Ferrum-Namespace` and key resources by
  `(namespace, kind, id)`; an `id` alone is never globally unique.
- Treat `/backup` as the source for desired/live comparison. Preserve opaque `api_specs` and
  `gateway_trust_bundles` on full replace unless the explicit deletion confirmation applies.
- A live resource carrying `api_spec_id` is spec-owned. Never modify it. Delete it only in
  exclusive mode with `--confirm-api-spec-deletion`; shared mode ignores that flag.
- Shared ownership deletes only keys recorded in the CI-authored state fence. Exclusive ownership
  may prune unknown rows but requires declared namespaces and is the only mode that permits
  `full_replace`.
- Run the read-only `/health` preflight before the first mutation. Never retry an ambiguous
  mutation timeout, an `applied:false` response, or a restore whose rollback is incomplete or has
  unknown outcome.
- Incremental apply orders dependency writes before dependent writes and deletes in reverse.
  Continue collecting per-resource failures so partial application stays visible.
- A cached `/backup` (`X-Data-Source: cached`) blocks every mutation, including adds and modifies,
  because the cached view drops API-spec ownership metadata. No flag bypasses this gate, including
  `--allow-large-prune`.
- Keep preview and execution semantics aligned. `diff`, `plan`, PR review, confirmation prompts,
  large-prune accounting, and apply must classify the same operation set.
- Resource IDs interpolated into URL paths must pass the shared path-segment validation; do not
  rely on percent encoding to make traversal-like IDs safe.

## Verification

Add or update the flat unit-test modules registered in `tests/unit/mod.rs`, especially the apply,
ownership, diff, HTTP-client, import, and review suites. Run the mandatory repository gate from
`CLAUDE.md` before every commit.
