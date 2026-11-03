# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored plugin
catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures, and the
GitForgeOps-owned resource schema are byte-for-byte copies from `contracts-edge-0.9.20`. The
contract test verifies every file's SHA-256, checks that the pinned Edge version maps to the
contracts tag and appears in the validator checksum allowlist, compares plugin names and
priorities plus retired and reserved names with the local catalog, checks the assembler's
`provisioned-by` label, parses valid and invalid resource fixtures with the local `Resource` serde
type, and checks the schema's top-level envelope against that type.

The published [contracts-edge-0.9.20 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.20)
is an annotated tag (`82b277b495e73cfadfacb6f3123de02a984658e4`) that resolves to commit
`39da322083044c2e92617209e62983c92387f0ad`. It was published on
2026-11-03 at 09:34:12 UTC. Its Edge vocabulary provenance identifies published
Edge v0.9.20 at `e4a606a00352674daaef08636e3e359e6c48ba18`; the plugin catalog
pins that source's `openapi.yaml` SHA-256 to
`8fa7232d96e1094578dee03cfa1966a4fdd9df77b8e027a9625f56ce6bfd355e`.
The resource schema and all ten fixtures are unchanged from the previous pin.

The release does not change adopted schema wire rules. Only the two vocabularies change,
and only in their Edge release, provenance refs and commits, the `openapi.yaml` digest and
the catalog note. Every plugin entry, priority, phase, failure policy, retired and reserved
name is unchanged, so the local catalog does not move. The note records that v0.9.20 closes
nested plugin-config objects (`mesh_authz` scopes and attachments, `workload_metrics`
providers, metrics and `tag_overrides`) and that built-in plugins now declare their
lifecycle hooks; GitForgeOps carries none of those fields. Operators should review the Edge
[0.9.20 upgrade guide](https://github.com/ferrum-edge/ferrum-edge/blob/e4a606a00352674daaef08636e3e359e6c48ba18/docs/upgrade_guide.md#upgrading-to-0920)
before rollout; nested unknown keys that v0.9.19 ignored are now refused.
Other new contract surfaces remain outside this repository's adopted scope.

The previous pin was the published [contracts-edge-0.9.19 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.19),
which resolves to `d96b0292a0f87647f7552f25e0e5ce1b4ae30f8b`, with Edge v0.9.19 provenance
at `510ce7121c3d9754110d330a30a3bd9b7a7b278e`.

The attribution vocabulary keeps its values from the prior pin; its Edge release and
source metadata now identify v0.9.20. Attribution still grants no ownership or
authorization.

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
