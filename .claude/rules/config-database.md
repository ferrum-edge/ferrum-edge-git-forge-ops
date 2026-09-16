---
paths:
  - "src/config/**"
  - "src/reconcile.rs"
  - "src/state.rs"
  - "src/main.rs"
  - "src/cli.rs"
  - ".gitforgeops/**"
  - "resources/**"
  - "overlays/**"
  - "tests/unit/{assembler,env,loader,reconcile,repo_config,schema,state}_tests.rs"
---

# Configuration, overlays, and state rules

This repository has no configuration database. It assembles repository YAML, applies overlays,
and reconciles the result with the companion `ferrum-edge` gateway.

- Follow the [buildout and schema policy](../../CLAUDE.md#buildout-and-schema-policy): there are
  no users or backward-compatibility requirements for earlier buildout revisions. Update the
  current schema and fixtures together. If a database is introduced, maintain one complete initial
  schema during buildout and fold subsequent changes into it.
- Keep the Serde mirror fail-closed for unknown typed fields. Free-form plugin config, credential
  maps, and mesh-item values round-trip unchanged. `FERRUM_ALLOW_UNKNOWN_FIELDS=true` permits
  unknown top-level `spec` fields with a warning; nested unknowns stay fatal. The companion
  `ferrum-edge validate` command is authoritative for gateway schema validation.
- Resource load order is `resources/<namespace>/<kind>/*.yaml`, followed by the selected
  `overlays/<environment>/` deep merge, then assembly. Arrays replace by default; only the
  documented plugin, target, workload, and service collections merge additively.
- Infer namespace from the directory only when the resource does not override it with a
  non-default value. Apply `FERRUM_NAMESPACE` consistently to load, diff, apply, and import.
- Validate duplicate `(namespace, kind, id)` keys after selection. Overlay targets must exist and
  must agree with their directory kind.
- Consumer credential object form normalizes to the canonical array form. Preserve slot identity,
  including the legacy index-zero elision.
- `.gitforgeops/config.yaml` contains logical environment behavior, never gateway URLs, JWTs, or
  GitHub secret names. Environment secrets supply runtime credentials.
- `.state/<env>.json` is a CI-authored delete fence. Never weaken the state guard or silently ignore
  malformed state. Shared mode unions state-derived namespaces with currently declared namespaces
  so removing a namespace's last resource can still delete the orphan.
- Store managed-resource keys with constant non-secret markers in state; never hash resolved
  resources or credentials into the public ledger. Keep exported configuration and API payloads
  deterministic so map iteration order cannot create spurious differences.
- New `FERRUM_*` variables require `EnvConfig`, `load_env_config()`, `.env.example`, and the env
  documentation block in `src/config/env.rs`.

## Verification

Schema additions need coverage in `tests/unit/schema_tests.rs`. New flat test files must be declared
in `tests/unit/mod.rs`. Run the mandatory repository gate from `CLAUDE.md` before every commit.
