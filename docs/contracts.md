# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored plugin
catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures, and the
GitForgeOps-owned resource schema are byte-for-byte copies from `contracts-edge-0.9.13`. The
contract test verifies every file's SHA-256, checks that the pinned Edge version maps to the
contracts tag and appears in the validator checksum allowlist, compares plugin names and
priorities plus retired and reserved names with the local catalog, checks the assembler's
`provisioned-by` label, parses valid and invalid resource fixtures with the local `Resource` serde
type, and checks the schema's top-level envelope against that type.

The published [contracts-edge-0.9.13 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.13)
resolves to `9626821eb089c71f5d4d71268c7b8276a8a5ab50`. It was published on
2026-10-06 at 17:58:52 UTC. Its Edge vocabulary provenance identifies published
Edge v0.9.13 at `9b83115de7ec23ab51ec4feae6bed65e596db425`; the plugin catalog
pins that source's `openapi.yaml` SHA-256 to
`5f3e50e217b22b97d068490bdad9563ea450097a2daf7df4f80ff61f98559a81`.
The resource schema and all ten fixtures are unchanged from the previous pin.

The release also publishes `backend-egress-policy` v2 and
`admin-deployment-snapshot` v2 schemas. GitForgeOps does not vendor or consume
either schema, so those major versions require no implementation adaptation here.

The previous published [contracts-edge-0.9.12 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.12)
remains at `31f0a21d707795be293d15837c2f77c3d84219d8`, with Edge v0.9.12 provenance
at `0d917701b63ef38210c49df830f48cf0457cbc7d`.

The plugin catalog and attribution vocabulary retain their values from the prior pin;
their Edge release and source metadata now identify v0.9.13. Attribution still grants no
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
