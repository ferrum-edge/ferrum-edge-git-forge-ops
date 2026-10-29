# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored plugin
catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures, and the
GitForgeOps-owned resource schema are byte-for-byte copies from `contracts-edge-0.9.19`. The
contract test verifies every file's SHA-256, checks that the pinned Edge version maps to the
contracts tag and appears in the validator checksum allowlist, compares plugin names and
priorities plus retired and reserved names with the local catalog, checks the assembler's
`provisioned-by` label, parses valid and invalid resource fixtures with the local `Resource` serde
type, and checks the schema's top-level envelope against that type.

The published [contracts-edge-0.9.19 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.19)
resolves to `d96b0292a0f87647f7552f25e0e5ce1b4ae30f8b`. It was published on
2026-10-27 at 08:27:10 UTC. Its Edge vocabulary provenance identifies published
Edge v0.9.19 at `510ce7121c3d9754110d330a30a3bd9b7a7b278e`; the plugin catalog
pins that source's `openapi.yaml` SHA-256 to
`610e2645961e7a5deca73468439be9c4a5b7070045099506c212a0a36b045e90`.
Edge v0.9.18 was tagged but never published, so there is no `contracts-edge-0.9.18`.
The resource schema and all ten fixtures are unchanged from the previous pin.

The release does not change adopted schema wire rules. Only the two vocabularies change.
In the plugin catalog, `ai_token_metrics` moves from priority 4100 to 4070, and the
local catalog follows it. Other catalog changes are to fields GitForgeOps does not
carry: `stdout_logging`'s registration failure policy, active phases,
`request_transformer`'s WebSocket handshake protocol surface, and the
`openapi_validator` proxy scope constraint. Operators should review the Edge
[0.9.19 upgrade guide](https://github.com/ferrum-edge/ferrum-edge/blob/510ce7121c3d9754110d330a30a3bd9b7a7b278e/docs/upgrade_guide.md#upgrading-to-0919)
before rollout; several plugin configurations that v0.9.17 accepted are now refused.
Other new contract surfaces remain outside this repository's adopted scope.

The previous pin was the published [contracts-edge-0.9.15 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.15),
which resolves to `6fb64c5dc2e014204c17609fc717d976f3b4589e`, with Edge v0.9.15 provenance
at `25b37395ff61bfea0f3ffd189d9011c4984fa755`. `contracts-edge-0.9.17` was never adopted.

The attribution vocabulary keeps its values from the prior pin; its Edge release and
source metadata now identify v0.9.19. Attribution still grants no ownership or
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
