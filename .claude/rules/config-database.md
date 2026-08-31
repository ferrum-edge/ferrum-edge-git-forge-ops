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

- Keep the Serde mirror permissive. The companion `ferrum-edge validate` command is authoritative
  for gateway schema validation; unknown fields must round-trip unless a typed field is needed by
  GitForgeOps logic.
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
- Hash resources through a deterministic JSON representation; map iteration order must not create
  state drift.
- New `FERRUM_*` variables require `EnvConfig`, `load_env_config()`, `.env.example`, and the env
  documentation block in `src/config/env.rs`.

## Verification

Schema additions need coverage in `tests/unit/schema_tests.rs`. New flat test files must be declared
in `tests/unit/mod.rs`. Run the mandatory repository gate from `CLAUDE.md` before every commit.
