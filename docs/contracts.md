# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored plugin
catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures, and the
GitForgeOps-owned resource schema are byte-for-byte copies from `contracts-edge-0.9.14`. The
contract test verifies every file's SHA-256, checks that the pinned Edge version maps to the
contracts tag and appears in the validator checksum allowlist, compares plugin names and
priorities plus retired and reserved names with the local catalog, checks the assembler's
`provisioned-by` label, parses valid and invalid resource fixtures with the local `Resource` serde
type, and checks the schema's top-level envelope against that type.

The published [contracts-edge-0.9.14 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.14)
resolves to `ddbdd845733b7046c4393ac951011dafb774db33`. It was published on
2026-10-08 at 09:22:24 UTC. Its Edge vocabulary provenance identifies published
Edge v0.9.14 at `9bd4d5f9caa4ebe8f0ea13e76d8a6e2172eaca7d`; the plugin catalog
pins that source's `openapi.yaml` SHA-256 to
`6d286649ae744691e2eeb7d16607c538ca02e31bdeaafe98ab07fc861e7b9da4`.
The resource schema and all ten fixtures are unchanged from the previous pin.

The release also updates the `backend-egress-policy` v2 schema with optional
`data_plane_attestation`, adds durable descriptions to the deployment mutation
acknowledgement contract, and updates gateway error classification notes. GitForgeOps
vendors none of those surfaces and has no parser for a backend egress policy or its
control-plane answers. They do not flow through the repository's resource loader,
gateway config mirror, or admin response parsers, so this pin needs no implementation
adaptation for those changes.

The previous published [contracts-edge-0.9.13 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.13)
resolves to `9626821eb089c71f5d4d71268c7b8276a8a5ab50`, with Edge v0.9.13 provenance
at `9b83115de7ec23ab51ec4feae6bed65e596db425`.

The plugin catalog and attribution vocabulary retain their values from the prior pin;
their Edge release and source metadata now identify v0.9.14. Attribution still grants no
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
