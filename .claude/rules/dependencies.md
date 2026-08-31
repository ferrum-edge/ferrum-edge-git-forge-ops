---
paths:
  - "Cargo.toml"
  - "Cargo.lock"
  - "Dockerfile"
  - ".github/actions/**"
  - ".github/workflows/**"
  - ".github/scripts/check_cargo_audit.py"
  - ".github/scripts/check_supply_chain.py"
  - ".github/cargo-audit-policy.json"
---

# Dependency and supply-chain rules

- Use `cargo add` or an intentional manifest edit, then commit the matching `Cargo.lock` change.
  Avoid adding a direct dependency when an existing crate or the standard library is sufficient.
- External GitHub Actions must be pinned to a reviewed full commit SHA. Docker base images and
  `docker://` action references must use immutable digests. Keep the supply-chain policy test green.
- Do not introduce pipe-to-shell installers, mutable download URLs, or unverified release assets in
  CI. Downloaded tools need an immutable version and checksum verification.
- `cargo audit` is enforced by `.github/scripts/check_cargo_audit.py`. Never suppress a finding in
  workflow flags. A reviewed exception must be exact, owned, expiring, justified, and backed by
  machine-enforced compensating controls.
- The current RSA exception exists only because `rsa` is reachable through age's public-key
  encryption path. Any age feature, API, source-location, or dependency-path change must fail the
  reachability guard and receive a fresh security review.
- Do not expose repository write credentials to untrusted PR builds. State-writer tokens are minted
  after untrusted build/validation work, used only for the exact state commit, then removed from git
  configuration.
- Pull-request path classification must inspect both current and previous filenames, consume every
  API page, compare the observed count with GitHub's declared count, and fail safe on uncertainty.
  Execute classifiers only from the PR base SHA, never the candidate branch.
- Keep `Cargo.toml` comments that document security-sensitive feature choices aligned with the
  actual feature set and policy code.

## Verification

Run the mandatory Rust gate plus the workflow-script tests, cargo-audit policy, supply-chain
policy, `actionlint`, and `git diff --check` when their governed files change.
