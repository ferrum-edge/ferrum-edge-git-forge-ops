# Shared Ferrum contracts

GitForgeOps pins the shared Ferrum contracts release in
[`contracts/ferrum-contracts/PIN`](../contracts/ferrum-contracts/PIN). The vendored plugin
catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures, and the
GitForgeOps-owned resource schema are byte-for-byte copies from `contracts-edge-0.9.21`. The
contract test verifies every file's SHA-256, checks that the pinned Edge version maps to the
contracts tag and appears in the validator checksum allowlist, compares plugin names and
priorities plus retired and reserved names with the local catalog, checks the assembler's
`provisioned-by` label, loads every valid resource fixture and refuses every invalid one with the
strict production loader (`load_resources`, the same path `import`, `validate` and `apply` use),
and checks the schema's top-level envelope against that loader. `check_release_baseline.py`
also requires the PIN's `edge_version` to equal `validator.version` in
[`release/baseline.json`](../release/baseline.json).

The loader accepts only `kind` and `spec` (plus `id` on a MeshConfig) and refuses any other
wrapper key. The `contracts-edge-0.9.21` envelope schema says the same: it is closed
(`additionalProperties: false`) and admits `id` only on a MeshConfig, which resolves
[ferrum-contracts#73](https://github.com/ferrum-edge/ferrum-contracts/issues/73) (the
`contracts-edge-0.9.20` envelope was open). Three new invalid fixtures pin the closure
(`proxy-unknown-wrapper-key`, `proxy-with-id`, `upstream-null-id`); the strict loader refuses
each of them. The contract test fails on a re-pin to any release whose envelope is open again.

The published [contracts-edge-0.9.21 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.21)
is an annotated tag (`3e7e10ef6d4aefa9874319326943ec2186b29981`) that resolves to commit
`92d8da5be93ea1ece9f47729b1f7aa10ae8a7c3f`. It was published on
2026-11-22 at 09:12:33 UTC. Its Edge vocabulary provenance identifies published
Edge v0.9.21 at `f9915358c8032214f4034a17c28cdf72d14006c3`; the plugin catalog
pins that source's `openapi.yaml` SHA-256 to
`13c21d12d3028c8044ad2f467cbca6425d9bd2f3fce787d6fe7ae78316c21bee`.
The ten fixtures carried over from the previous pin are unchanged.

Every plugin name, priority, retired and reserved name is unchanged, so the local catalog
does not move. The catalog re-transcribes metadata GitForgeOps does not carry: the
`http_logging`, `udp_logging`, `statsd_logging`, `loki_logging` and `ws_frame_logging`
registration failure policies move from `optional_fail_open` to `keep_last_known_good`,
five log sinks add the `on_ws_disconnect` phase, `request_transformer` and
`response_transformer` add a body phase each, and `compression` names `zstd`. Operators
should review the Edge
[0.9.21 upgrade guide](https://github.com/ferrum-edge/ferrum-edge/blob/f9915358c8032214f4034a17c28cdf72d14006c3/docs/upgrade_guide.md#upgrading-to-0921)
before rollout: v0.9.21 refuses many configurations v0.9.20 accepted, including removed
plugin options and the removed `Proxy.pool_max_requests_per_connection`.
Other new contract surfaces remain outside this repository's adopted scope.

The previous pin was the published [contracts-edge-0.9.20 release](https://github.com/ferrum-edge/ferrum-contracts/releases/tag/contracts-edge-0.9.20),
which resolves to `39da322083044c2e92617209e62983c92387f0ad`, with Edge v0.9.20 provenance
at `e4a606a00352674daaef08636e3e359e6c48ba18`.

The attribution vocabulary keeps its values from the prior pin; its Edge release and
source metadata now identify v0.9.21. Attribution still grants no ownership or
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
3. Rewrite `PIN` in the format ferrum-contracts defines for every consumer
   ([consumer-pins.md](https://github.com/ferrum-edge/ferrum-contracts/blob/main/docs/consumer-pins.md#format)):
   `tag <tag>`, `commit <sha>`, `edge_version <vX.Y.Z>`, then one `<sha256>  <path>` row per
   vendored file (`sha256sum` text-mode lines, two spaces), sorted by path byte order. The
   contract test parses it strictly and refuses any other line.
4. Update `edge_version` in `PIN` and the literal tag, commit and Edge version the contract test
   asserts. The Edge version must already be in `.github/ferrum-edge-checksums.txt` and must
   equal `validator.version` in `release/baseline.json` (move the Edge pin in the same change;
   see [the release baseline](../release/README.md)).
5. Resolve drift through the owning implementation or the upstream contract, then re-vendor; do
   not patch a shared vendored file locally.
6. Open a PR and let the existing Rust CI run the contract test.
