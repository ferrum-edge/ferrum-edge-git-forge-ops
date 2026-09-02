---
paths:
  - "Cargo.toml"
  - "Cargo.lock"
  - "Dockerfile"
  - ".github/workflows/**"
  - ".github/scripts/**"
---

# Dependency and supply-chain rules

- Use `cargo add` or an intentional manifest edit, then commit the matching `Cargo.lock` change.
  Avoid adding a direct dependency when an existing crate or the standard library is sufficient.
- Prefer reviewed full commit SHAs for new or updated external GitHub Actions and immutable digests
  for container references. Do not assume an existing mutable reference is already compliant; keep
  a pinning change scoped and verify the selected upstream revision.
- Do not introduce pipe-to-shell installers, mutable download URLs, or unverified release assets in
  CI. Downloaded tools need an immutable version and checksum verification.
- `.github/workflows/security.yml` currently runs `cargo audit` with one documented
  `RUSTSEC-2023-0071` ignore. Do not add, broaden, or remove an audit exception casually: verify the
  live dependency path, document the reason, and add a machine-enforced reachability guard before
  treating an exception as an accepted control.
- Do not expose repository write credentials or environment secrets to untrusted PR builds. Keep
  PR jobs read-only and use `persist-credentials: false` when checkout credentials are unnecessary.
- Candidate-controlled workflow helpers are untrusted input. Security-sensitive classifiers should
  come from a trusted base revision, fail closed on API pagination or count uncertainty, and inspect
  both current and previous filenames when renames matter. If the current workflow lacks those
  controls, describe them as required work rather than existing behavior.
- Keep `Cargo.toml` comments that document security-sensitive feature choices aligned with the
  actual feature set and policy code.

## Verification

Run the mandatory Rust gate plus applicable workflow-script tests, `cargo audit`, `actionlint`, and
`git diff --check` when their governed files change.
