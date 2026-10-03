# Dependency security policy

The `Security` workflow runs `cargo audit` through
`.github/scripts/check_cargo_audit.py`:

- on every pull request to `main`;
- on pushes to `main` that touch build inputs or security policy inputs;
- weekly on a schedule.

The push filter explicitly includes `.github/cargo-audit-policy.json`,
`.github/ferrum-edge-checksums.txt` and `.github/CODEOWNERS`, and
`check_supply_chain.py` rejects removing or excluding them. That way policy
checks run again after a policy-only merge. Validator compatibility is checked
on pull requests and by the canary, not here.

CI installs cargo-audit **0.22.1** with
`taiki-e/install-action@9983c65e42da123ff25d1f78505eb6de315aa172`, using
`checksum: true` and `fallback: none`. The action pin fixes the installer code.
Separately, its [committed cargo-audit manifest](https://github.com/taiki-e/install-action/blob/9983c65e42da123ff25d1f78505eb6de315aa172/manifests/cargo-audit.json)
records the 0.22.1 Linux x86-64 archive SHA-256
`c32506f338bdcdaef5a17fb9f33abb6ecf9561324cfd34237fd335f9283a1eab`, and the
[installer](https://github.com/taiki-e/install-action/blob/9983c65e42da123ff25d1f78505eb6de315aa172/main.sh)
verifies that digest before extracting. (The action SHA alone says nothing
about the contents of an external release asset.) With fallback disabled, an
unsupported version or platform fails instead of installing from the registry.
The job installs the tool on every run and does not cache `~/.cargo/bin`.
Policy tests enforce the install method, version, checksum and fallback
inputs, and the absence of that cache.

## CI trust boundary

On pull requests, the workflow runs the checker, its tests and the exception
policy from a separate checkout of the protected default branch, and
`--source-root` points the audit and reachability checks at the candidate tree.
A pull request therefore cannot approve its own dependency finding by weakening
the checker or adding an exception. Because `security.yml` itself comes from
the pull request head, `check_supply_chain.py` checks that this arrangement is
still in place; otherwise one commit could add an exception and remove the
trusted checkout in the same change.

Push and schedule runs use the tree's own checker and policy. Those events have
no untrusted author, and pinning them to the default branch would stop a merged
policy change from ever taking effect.

### Candidate cargo configuration is ignored

A trusted checker is not enough if the commands it runs read configuration
from the tree under review. Cargo discovers `.cargo/config.toml` (and the
legacy `.cargo/config`) in the working directory and every ancestor, so a
candidate `[alias]` could redefine `audit`. Rustup selects a toolchain from
`rust-toolchain.toml` or `rust-toolchain` the same way, including a `path`
toolchain inside the checkout. cargo-audit reads `./.cargo/audit.toml`, whose
ignore list, advisory-database location and yanked settings decide what it
reports. None of these is looked up next to `--manifest-path` or `--file`.

So `check_cargo_audit.py` never runs cargo from the candidate checkout:

- `cargo tree --manifest-path <candidate>/Cargo.toml` and
  `cargo audit --file <candidate>/Cargo.lock` run from a fresh temporary
  directory with a fresh, empty `CARGO_HOME`;
- inherited `CARGO_*` variables (including `CARGO_ALIAS_<name>`), cargo's
  internal `__CARGO_*` overrides, `RUSTUP_TOOLCHAIN`, `RUSTC`,
  `RUSTC_BOOTSTRAP`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `RUSTFLAGS`
  and `RUSTDOCFLAGS` are removed from their environment, so the toolchain is
  the runner's default from the workflow's pinned toolchain step;
- `Cargo.toml` and `Cargo.lock` must be regular files, not symlinks, and a
  missing lockfile is refused rather than generated;
- the gate refuses to run when the temporary directory is inside the
  checkout, or when any of those configuration files exists at or above it
  (point `TMPDIR` elsewhere).

Candidate copies of these files are ignored, not rejected: the log lists the
ones present. A local `.cargo/audit.toml` ignore list therefore has no effect on
the gate; record a reviewed exception in `.github/cargo-audit-policy.json`
instead. The tests drive the checker with a stand-in `cargo` that answers
differently whenever it can see candidate configuration, and assert it never
does.

### The expand/contract cost

Because the policy comes from `main`, a pull request that *changes* the policy
is not judged by its own change:

- **Adding an exception.** The PR that adds the entry to
  `.github/cargo-audit-policy.json` is judged by `main`'s policy, which lacks
  it, so `Security` stays red on that PR. Merging it past that required check
  takes a deliberate admin decision, because the baseline ruleset has no human
  bypass. Every later PR is green.
- **Removing a dependency that has an exception.** A PR that drops the crate
  *and* its policy entry is judged by `main`'s policy, which still names the
  crate, so the gate reports `stale exception: <pkg>@<ver> is no longer in the
  dependency graph`. Land the policy removal first, or merge past the red check
  as above.

The supply-chain policy has the same cost for the same reason; it is the price
of a gate that cannot approve itself. Do not work around it by pointing
`--policy` at the candidate tree. That is the bypass the trusted checkout
exists to close, and `check_supply_chain.py` rejects it.

## What fails the gate

The gate fails on `vulnerability`, `unsound` and `yanked` findings unless the
exact finding is recorded in `.github/cargo-audit-policy.json`. Every other
bucket (`unmaintained`, `notice`, and any bucket a future cargo-audit adds) is
reported as a non-fatal `::warning::` naming the advisory and package, so an
"unmaintained" notice does not turn every open pull request red before someone
can triage it. A maintainer can still add a reviewed exception for one if it
needs to be tracked to a deadline.

The gate also fails when `cargo audit` exits 1 but no findings were parsed, or
when `vulnerabilities.count` disagrees with the parsed list. A change in the
report format fails loudly instead of reading as clean.

## Exceptions

An exception must name the advisory (except for yanked packages), the exact
package and version, an owner, the reachable call paths, compensating
controls, an upstream tracking link and a review deadline (`review_by`) at most
120 days away. Expired exceptions fail before the audit is evaluated. Stale
exceptions fail once an upgrade removes or changes the finding. So an exception
cannot silently cover a different version or outlive its reason.

**An expired exception blocks everything, not just the weekly job.** The
deadline check runs on every trigger above. From the day after `review_by`,
the `security-cargo-audit` job fails for every PR until the entry is
re-reviewed or removed. The gate emits a `::warning::` (without failing) for
any exception whose `review_by` is 21 days away or less.

## Reachability verifiers

An exception can name a machine-checked reachability premise in its
`reachability` field. Entries without the field are matched by
`(kind, advisory, package)`. Either way the version is ignored, so a patch bump
of the vulnerable crate cannot silently switch the verifier off. Some packages
must always resolve to a verifier (currently `rsa`). An exception for one of
them that resolves to no verifier, or names a verifier the gate does not
implement, is a policy error.

## Current RSA exception

`rsa 0.9.10` is affected by RUSTSEC-2023-0071. As of the 2026-08-30 review,
RustCrypto has not published a stable patched release. The lockfile has one
remaining dependency path:

```text
gitforgeops -> age 0.12.1 (ssh feature) -> rsa 0.9.10
```

The `jsonwebtoken` dependency uses its `aws_lc_rs` provider with default
features disabled. Admin JWTs are HS256-only, so it does not pull in the
RustCrypto RSA implementation.

The remaining path is in `src/secrets/delivery.rs`. GitHub supplies an SSH
*public* key, `age::ssh::Recipient` parses it, and gitforgeops encrypts a
credential locally for that recipient. The CLI never accepts an SSH private
key and never calls RSA signing or decryption. The advisory is about timing of
private-key operations, which this path cannot reach. The test suite covers
encryption to both Ed25519 and RSA recipients. `age` rejects SSH-RSA recipient
keys smaller than 2048 bits.

The `age-encryption-only` verifier checks that premise before accepting the
exception. It requires:

- an `age 0.12` requirement in `Cargo.toml` with exactly the `ssh` and `armor`
  features (in any order);
- a dependency graph containing only `gitforgeops -> age 0.12.x -> rsa 0.9.x`;
- no `age::` references under `src/` outside the reviewed delivery module, and
  only the reviewed `age` APIs inside it.

Adding a decrypt or private-key feature, or a second RSA dependency path,
therefore fails the required audit check even though the advisory and deadline
are unchanged.

The API scan is syntactic. It strips comments and string literals, then matches
literal `age::<path>` references in `src/**/*.rs`. It does not resolve
re-exports or aliases and does not look at `tests/` or `build.rs`. Treat it as a
tripwire on the reviewed module boundary, not a proof of unreachability; the
reviewer signs off on the reachability argument above.

Patch upgrades such as `age 0.12.2` or `rsa 0.9.11` pass the graph check
unchanged, so a routine Dependabot bump needs no script edit. When the flagged
`rsa` version changes, update the exception's `version`. When `rsa` leaves the
graph entirely, the gate reports a stale exception.

The exception owner must re-review or remove the entry by 2026-11-30. The
preferred resolution is an `age` release whose stable RSA dependency contains
the upstream constant-time work. Dropping SSH-RSA recipient compatibility is a
fallback only if a safe upstream route remains unavailable at review time.

## Maintenance

`cargo audit` is not part of the Rust toolchain. Install the version CI pins in
`.github/workflows/security.yml`:

```bash
cargo install cargo-audit --version 0.22.1 --locked
```

Then run the same checks locally. None of these change `Cargo.lock`:

```bash
python3 -m unittest discover -s .github/scripts/tests -v
python3 .github/scripts/check_cargo_audit.py
cargo tree --locked --target all -i rsa@0.9.10
cargo test --test unit_tests
```

Run locally, `check_cargo_audit.py` behaves exactly as it does in CI. Each
`cargo tree` and `cargo audit` call gets a fresh, empty `CARGO_HOME`, so every
run downloads the crates.io index, the needed crate manifests and the RustSec
advisory database again; your `~/.cargo` cache, registry configuration and
`~/.cargo/audit.toml` are not used. It also runs from a temporary directory, so
the repository's `rust-toolchain.toml` does not apply: cargo comes from your
rustup default toolchain (or `PATH`), and `RUSTUP_TOOLCHAIN` is ignored. To
match CI, make the channel pinned in `rust-toolchain.toml` your rustup default.

`cargo audit` reads the committed `Cargo.lock` as-is. Run `cargo update` only
when you mean to move the lockfile; it is an upgrade, not a check.

Never use `cargo audit --ignore` in CI. Add a narrowly scoped policy entry
instead, and only after documenting reachability and controls.
