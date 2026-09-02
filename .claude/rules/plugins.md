---
paths:
  - "src/plugin_catalog.rs"
  - "src/policy/**"
  - "src/secrets/**"
  - "src/config/schema.rs"
  - "tests/unit/{analysis,policy,secrets,schema}_tests.rs"
---

# Plugin catalog and policy rules

- `src/plugin_catalog.rs` is the shared source of truth for built-in, retired, reserved, auth,
  rate-limit, observability, and AI-guardrail plugin names. Policy rules must use the catalog rather
  than duplicating name lists.
- Effective plugin resolution is name based: a scoped config replaces a global config of the same
  `plugin_name`; disabled instances do not satisfy enforcement policies. Preserve deterministic
  priority ordering and all instances where the policy intentionally reasons about multiplicity.
- New policy rules implement `PolicyCheck`, add typed config in `src/policy/config.rs`, register in
  `src/policy/registry.rs`, default to disabled, and include unit coverage.
- Policy severity `error` blocks apply unless the configured label exists and the effective label
  actor currently has at least the required repository permission. Pagination and unknown
  permissions fail closed.
- The credential broker currently resolves consumer credentials only. `PluginConfig.config` values
  are neither brokered nor masked on this branch, so repository plugin configs must not contain
  secrets. Any future plugin-secret support must add explicit import, diff, review, and log-redaction
  behavior with tests before this rule can claim that protection.
- Never print resolved consumer credentials, credential bundles, or validator diagnostics that may
  echo them.
- Spec-owned plugin configs follow the same ownership rules as spec-owned proxies/upstreams and are
  never imported as repository-managed resources.

## Verification

Update the relevant flat unit modules and run the mandatory repository gate. Secret-handling
changes require focused coverage in `tests/unit/secrets_tests.rs` plus import, diff, and review tests
for every output surface they affect.
