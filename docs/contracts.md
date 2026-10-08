# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored plugin
catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures, and the
GitForgeOps-owned resource schema are byte-for-byte copies from `contracts-edge-0.9.15`. The
contract test verifies every file's SHA-256, checks that the pinned Edge version maps to the
contracts tag and appears in the validator checksum allowlist, compares plugin names and
priorities plus retired and reserved names with the local catalog, checks the assembler's
`provisioned-by` label, parses valid and invalid resource fixtures with the local `Resource` serde
type, and checks the schema's top-level envelope against that type.

The published [contracts-edge-0.9.15 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.15)
resolves to `6fb64c5dc2e014204c17609fc717d976f3b4589e`. It was published on
2026-10-08 at 20:42:07 UTC. Its Edge vocabulary provenance identifies published
Edge v0.9.15 at `25b37395ff61bfea0f3ffd189d9011c4984fa755`; the plugin catalog
pins that source's `openapi.yaml` SHA-256 to
`f6c7d8b1d247060c4d0ae66e5c149ad3d76721addb8176eff45b6fc3d1b4d6b2`.
The resource schema and all ten fixtures are unchanged from the previous pin.

The release does not change adopted schema wire rules. It updates vocabulary values,
descriptions and provenance and adds fixtures. The plugin catalog points to Edge's
updated plugin schemas, including the removed LDAP `consumer_mapping` option, the
external identity header change, and the `FERRUM_PLUGIN_SECRET_<NAME>` environment
reference namespace. Current GitForgeOps resources and examples contain none of
those affected plugin settings. Operators using them should follow the Edge
[0.9.15 upgrade guide](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.15/docs/upgrade_guide.md#upgrading-to-0915).
Other new contract surfaces remain outside this repository's adopted scope.

The previous published [contracts-edge-0.9.13 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.13)
resolves to `9626821eb089c71f5d4d71268c7b8276a8a5ab50`, with Edge v0.9.13 provenance
at `9b83115de7ec23ab51ec4feae6bed65e596db425`.

The plugin catalog and attribution vocabulary retain their values from the prior pin;
their Edge release and source metadata now identify v0.9.15. Attribution still grants no
ownership or authorization.

This repository vendors only the resource schema, its fixtures and the two
vocabularies listed above. The canonical release's shared Alloy v1 status is
EXISTING/implemented at its qualified owner, whose availability remains unreleased.
That metadata does not qualify production apply or publish Alloy. This pin update adds no
deployment profiles, Alloy manifest consumption or diagnostic-report consumption here.
GitForgeOps hosted conformance, exact-byte hosted gateway qualification and
[first-release acceptance](../release/README.md) remain separate gates; canonical
artifact availability does not establish their success.

The plugin catalog also describes config schemas and per-plugin scope constraints. This repository
does not duplicate those values in its local catalog, so the conformance test compares the catalog
fields GitForgeOps does carry: built-in names, priorities, retired names, and reserved names.

## Bumping the pin

1. Choose a new immutable `contracts-edge-*` tag with a published release that is neither draft
   nor prerelease. Read its commit SHA from
   `gh api repos/ferrum-edge/ferrum-contracts/git/ref/tags/<tag>` and dereference the object
   if the tag points to an annotated tag.
2. Download the adopted vocabularies, GitForgeOps resource schema and fixtures from that exact
   commit into the matching paths under `contracts/ferrum-contracts/`.
3. Update `PIN` with the tag, commit SHA, and `shasum -a 256` for every vendored file.
4. Update `edge_version` in `PIN` and the explicit compatible-version mapping in the contract
   test when the pinned Ferrum Edge version changes.
5. Resolve drift through the owning implementation or the upstream contract, then re-vendor; do
   not patch a shared vendored file locally.
6. Open a PR and let the existing Rust CI run the contract test.
