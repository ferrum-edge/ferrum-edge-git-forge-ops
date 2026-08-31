# Dependency security policy

The `Security` workflow runs `cargo audit` through
`.github/scripts/check_cargo_audit.py`. The gate treats vulnerability,
unsoundness, and yanked-package findings as failures unless an exact finding is
recorded in `.github/cargo-audit-policy.json`.

An exception must identify the advisory (except yanked packages), exact package
and version, owner, reachable call paths, compensating controls, upstream
tracking link, and review deadline. Deadlines may be at most 120 days away.
Expired exceptions fail before the audit is evaluated, and stale exceptions
fail once an upgrade removes or changes the finding. This prevents a blanket
ignore from silently covering a different version or surviving its reason.

## Current RSA exception

`rsa 0.9.10` is affected by RUSTSEC-2023-0071. As of the 2026-08-30 review,
RustCrypto has not published a stable patched release. The lockfile has one
remaining dependency path:

```text
gitforgeops -> age 0.12.1 (ssh feature) -> rsa 0.9.10
```

The `jsonwebtoken` dependency uses its `aws_lc_rs` provider with default
features disabled. Admin JWTs are HS256-only, so that path no longer brings in
the RustCrypto RSA implementation.

The remaining path is in `src/secrets/delivery.rs`. GitHub supplies an SSH
*public* key, `age::ssh::Recipient` parses it, and gitforgeops encrypts a
credential locally for that recipient. The CLI never accepts an SSH private
key and never calls RSA signing or decryption. The timing advisory concerns
private-key operations observable by an attacker; those operations are not
reachable from this path. Ed25519 and RSA public-recipient encryption are both
covered by the aggregated test suite.

The exception owner must re-review or remove the entry by 2026-11-30. The
preferred resolution is an `age` release whose stable RSA dependency contains
the upstream constant-time work. Dropping SSH-RSA recipient compatibility is a
fallback only if a safe upstream route remains unavailable at review time.

## Maintenance

Run the same checks locally with:

```bash
cargo update
python3 .github/scripts/tests/test_check_cargo_audit.py
python3 .github/scripts/check_cargo_audit.py
cargo tree --target all -i rsa@0.9.10
cargo test --test unit_tests
```

Do not invoke `cargo audit --ignore` in CI. Add a narrowly scoped policy entry
only after documenting reachability and controls, and keep its review window
within 120 days.
