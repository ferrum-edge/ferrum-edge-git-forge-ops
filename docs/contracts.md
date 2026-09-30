# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored
plugin catalog, `provisioned-by` vocabulary, and GitForgeOps resource-envelope fixtures are
byte-for-byte copies from `contracts-edge-0.9.8`. The contract test verifies every file's SHA-256,
compares plugin names and priorities plus retired and reserved names with the local catalog,
checks the assembler's `provisioned-by` label, and parses the valid and invalid resource fixtures
with the local `Resource` serde type.

The plugin catalog also describes config schemas and per-plugin scope constraints. This repository
does not duplicate those values in its local catalog, so the conformance test compares the catalog
fields GitForgeOps does carry: built-in names, priorities, retired names, and reserved names.

## Bumping the pin

1. Choose the new immutable `contracts-edge-*` tag. Read its commit SHA from
   `gh api repos/ferrum-edge/ferrum-contracts/git/ref/tags/<tag>` and dereference the object
   if the tag points to an annotated tag.
2. Download the adopted vocabulary and GitForgeOps resource fixture files from that tag into the
   matching paths under `contracts/ferrum-contracts/`.
3. Update `PIN` with the tag, commit SHA, and `shasum -a 256` for every vendored file.
4. Review any local drift exposed by the contract test and update the local copy when needed.
5. Open a PR and let the existing Rust CI run the contract test.
