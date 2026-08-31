---
paths:
  - "src/config/{schema,loader,assembler}.rs"
  - "src/apply/file_target.rs"
  - "src/validate/**"
  - "resources/*/mesh/**"
  - "overlays/**"
  - "tests/unit/mesh_tests.rs"
---

# Mesh document rules

- `MeshConfig` fragments are not gateway resources. Merge them into one standalone
  `{version: "1", mesh: {...}}` document and never include them in the gateway document or live
  resource diff.
- Merge fragment collection fields deterministically. Workloads merge by `spiffe_id`; services
  merge by `(name, namespace)`. Deep-equal duplicates deduplicate, while conflicting identities or
  singleton fields are errors naming both fragments.
- Arrays not explicitly documented as additive replace during overlay application.
- Respect namespace filtering before merge. No selected fragments means no mesh output document.
- Mesh is file-only. File-mode export/apply publishes it atomically to
  `FERRUM_MESH_FILE_OUTPUT_PATH`; API-mode apply validates it and reports that no mesh admin API
  exists rather than attempting a push.
- Validate rendered mesh bytes through `ferrum-edge validate -m mesh` with the same scrubbed child
  environment and private temporary-file handling as gateway validation.
- Preserve unknown mesh fields in the permissive mirror while omitting runtime-derived fields that
  do not belong in GitOps input.

## Verification

Put mesh behavior coverage in `tests/unit/mesh_tests.rs` and run the mandatory repository gate from
`CLAUDE.md` before every commit.
