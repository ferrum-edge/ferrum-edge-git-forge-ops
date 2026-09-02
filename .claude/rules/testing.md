---
paths:
  - "src/**"
  - "tests/**"
  - ".github/**"
  - "Cargo.toml"
  - "Cargo.lock"
  - "Dockerfile"
---

# Testing rules

## Mandatory before every commit

Run these sequentially with `CARGO_TARGET_DIR` unset:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --test unit_tests
```

Do not delegate these checks to CI and do not replace them with narrower commands. Additional
focused tests are welcome, but they do not replace the mandatory three-command gate.

## Test layout

- `tests/unit_tests.rs` is the single integration-test binary.
- Unit modules are flat files under `tests/unit/*.rs` and must be registered with `mod <name>;` in
  `tests/unit/mod.rs`.
- Reuse fixtures in `tests/fixtures/` and `tempfile` for filesystem behavior.
- Tests must not require a live network. `AdminClient::new` is intentionally connection-free so
  validation paths can be exercised locally.
- Prefer behavior-level coverage through public or `pub(crate)` surfaces. Keep inline source tests
  limited to truly private helpers when widening the runtime API would be worse.
- Do not use sleeps for deterministic unit behavior. Validate ordering, failure classification,
  masking, and namespace ownership through explicit inputs and outputs.

## Additional changed-surface gates

- Workflow/script changes: run Python test discovery under `.github/scripts/tests`, the relevant
  policy scripts, `actionlint`, and `git diff --check`.
- Agent setup changes: run `.github/scripts/check_agent_setup.py`, `bash -n` and `shellcheck` over
  dispatchers and the shared resolver.
- Documentation-only changes: still run the mandatory repository gate, then `git diff --check`.

Report exact commands and counts. Treat every red CI check as real until logs prove an external
infrastructure failure; this repository has no standing known-flake allowlist.
