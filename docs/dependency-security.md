# Dependency security policy

The `Security` workflow runs `cargo audit` through
`.github/scripts/check_cargo_audit.py` on every pull request, on pushes to
`main` that touch build inputs, and on the weekly schedule.

The gate fails on `vulnerability`, `unsound`, and `yanked` findings unless an
exact finding is recorded in `.github/cargo-audit-policy.json`. Every other
`cargo audit` bucket — `unmaintained`, `notice`, and any bucket a future
cargo-audit release adds — is reported as a non-fatal `::warning::` annotation
naming the advisory id and package. An advisory that only says "this crate is
no longer maintained" should not turn every open pull request red before a
human can triage it; a maintainer can still write a reviewed exception for one
if the finding needs to be tracked to a deadline.

The gate also refuses to pass when `cargo audit` itself exited 1 while this
gate parsed no findings, and when `vulnerabilities.count` disagrees with the
list it parsed. A cargo-audit report-shape change fails loudly instead of
reading as "clean".

An exception must identify the advisory (except yanked packages), exact package
and version, owner, reachable call paths, compensating controls, upstream
tracking link, and review deadline. Deadlines may be at most 120 days away.
Expired exceptions fail before the audit is evaluated, and stale exceptions
fail once an upgrade removes or changes the finding. This prevents a blanket
ignore from silently covering a different version or surviving its reason.

**An expired exception blocks everything, not just the weekly job.** The
deadline check runs on every pull request, every push to `main` that touches
build inputs, and the scheduled run. From the day after `review_by`, the
`Security / cargo-audit` job fails repo-wide until the entry is re-reviewed or
removed. To make that arrival visible in advance, the gate emits a
`::warning::` annotation (exit code unchanged) for any exception whose
`review_by` is 21 days out or nearer.

## Reachability verifiers

An exception may name a machine-checked reachability premise in its
`reachability` field; entries that predate the field are matched by
`(kind, advisory, package)`. Either way the selector deliberately ignores the
version, so bumping a patch release of the vulnerable crate cannot silently
switch the verifier off. Some packages must always resolve to a verifier
(currently `rsa`); an exception for one of those that resolves to no verifier,
or that names a verifier the gate does not implement, is a policy error rather
than a pass.

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
covered by the aggregated test suite. `age` rejects SSH-RSA recipient keys
smaller than 2048 bits.

The `age-encryption-only` verifier machine-checks that premise before accepting
the exception. It requires the manifest to declare an `age 0.12` requirement
with exactly the `ssh` and `armor` features (feature order is irrelevant and
`default-features = false` is accepted as stricter), requires the dependency
graph to contain only `gitforgeops -> age 0.12.x -> rsa 0.9.x`, and rejects
unreviewed `age::` references under `src/` outside the encryption-only delivery
module. A decrypt/private-key feature or a second RSA dependency path therefore
makes the required audit check fail even while the advisory tuple and exception
deadline are unchanged.

The API scan is syntactic: it strips `//` and `/* */` comments and string
literals, then matches literal `age::<path>` references in `src/**/*.rs`. It
does not resolve re-exports or aliases and does not walk `tests/` or
`build.rs`. Treat it as a tripwire on the reviewed module boundary, not as a
proof of unreachability — the reachability argument above is what the reviewer
signs off on.

Patch upgrades are expected to pass unchanged: `age 0.12.2` or `rsa 0.9.11`
satisfy the graph check, so a routine Dependabot bump does not need a Python
edit. When the advisory tuple itself changes, update the exception's `version`;
when `rsa` leaves the graph entirely, the gate reports a stale exception and
names the file to edit.

The exception owner must re-review or remove the entry by 2026-11-30. The
preferred resolution is an `age` release whose stable RSA dependency contains
the upstream constant-time work. Dropping SSH-RSA recipient compatibility is a
fallback only if a safe upstream route remains unavailable at review time.

## Maintenance

`cargo audit` is not part of the Rust toolchain; install it first (CI pins the
same version in `.github/workflows/security.yml`):

```bash
cargo install cargo-audit --version 0.22.1 --locked
```

Then run the same checks locally. None of these mutate `Cargo.lock`:

```bash
python3 -m unittest discover -s .github/scripts/tests -v
python3 .github/scripts/check_cargo_audit.py
cargo tree --locked --target all -i rsa@0.9.10
cargo test --test unit_tests
```

Run `cargo update` only when you intend to move the lockfile; it is an upgrade
step, not a check. `cargo audit` reads the committed `Cargo.lock` as-is.

Do not invoke `cargo audit --ignore` in CI. Add a narrowly scoped policy entry
only after documenting reachability and controls, and keep its review window
within 120 days.
