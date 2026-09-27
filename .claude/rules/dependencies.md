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
  Avoid a new direct dependency when an existing crate or the standard library is enough.
- External GitHub Actions must use full 40-hex commit SHAs and container `FROM` lines immutable
  digests. `.github/scripts/check_supply_chain.py` enforces both; pin to a reviewed upstream
  revision.
- No pipe-to-shell installers, mutable download URLs or unverified release assets in CI.
  Downloaded tools need an immutable version and checksum verification. The validator binary is
  pinned by content: `install-ferrum-edge.sh` makes it executable only after its SHA-256 matches
  `.github/ferrum-edge-checksums.txt`.
- `cargo audit` runs in `.github/workflows/security.yml` through `check_cargo_audit.py`. Exceptions
  live in `.github/cargo-audit-policy.json` (currently only `RUSTSEC-2023-0071`, `rsa` via `age`'s
  SSH recipients) and need owner, `review_by` (at most 120 days out), rationale, affected call
  paths, compensating controls and a reachability verifier; expired or stale entries fail. Do not
  add, broaden or remove an exception casually: verify the live dependency path and keep its
  reachability guard machine-enforced.
- Never expose repository write credentials or environment secrets to untrusted PR builds. Keep PR
  jobs read-only and use `persist-credentials: false` when checkout credentials are not needed.
- Candidate-controlled workflow helpers are untrusted input. Security-sensitive classifiers run
  from a trusted default-branch checkout, fail closed on API pagination or count uncertainty, and
  inspect both current and previous filenames when renames matter. If a workflow lacks one of
  these controls, describe it as required work, not existing behavior.
- Keep `Cargo.toml` comments that document security-sensitive feature choices aligned with the
  actual features and policy code.

## Verification

Run the mandatory Rust gate plus applicable workflow-script tests, `cargo audit`, `actionlint`, and
`git diff --check` when these files change.
