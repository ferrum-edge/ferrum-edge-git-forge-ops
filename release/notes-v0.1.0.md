# GitForgeOps v0.1.0 release notes

The [baseline record](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/baseline.json)
supplies publication status, exact
revision, image digest, and lifecycle evidence. Copy this note into the GitHub
release when that record is finalized; the committed copy remains available
after workflow artifacts expire.

## Supported pairing

GitForgeOps v0.1.0 pairs with Ferrum Edge v0.9.10, using the checked-in
v0.9.10 validator asset pin. See the [support table](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/README.md#support-and-compatibility)
for the precise profile and file/mesh and monitoring boundaries.

## Adoption and verification

Use the [immutable source adoption and provenance instructions](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/README.md#adopt-the-immutable-sourcetemplate-revision)
with the exact SHA and digest in the supported record. Start with the
[one-gateway quickstart](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/v0.1.0/docs/quickstart.md), then use
[the downstream update procedure](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/v0.1.0/docs/template-updates.md)
for later fixes.

## Changes and known limitations

- First supported source/template and container pairing, conditional on the
  record's `supported` status and passing exact-revision release gate.
- The paired gateway is Ferrum Edge v0.9.10. It includes v0.9.9's request-path
  hardening, which refuses non-final empty path segments and requires
  `allow_path_parameters: true` on a proxy to accept semicolon path parameters;
  review the
  [Edge upgrade guide](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.10/docs/upgrade_guide.md#upgrading-to-099)
  when upgrading a gateway. GitForgeOps does not currently expose the new
  `allow_path_parameters` proxy option, so semicolon path parameters remain
  refused on proxies declared through this repository. Run validation on a
  pull request before adopting this pairing.
- Edge v0.9.10 refuses non-UTF-8 charsets on MCP `ai_prompt_shield` and
  `mcp_gateway` requests, and fails closed on uninspectable or over-nested
  JSON-RPC batches (GHSA-4f9m-cfqg-fhx9, GHSA-f2jp-59r9-fp64).
- API-mode shared ownership is the first deployment profile. File/mesh output
  is assembled and validated, with external fleet delivery required.
- Scheduled monitoring needs approval unless `monitoring.unattended` binds its
  restricted monitor environment; its admin signing secret is still
  gateway-write-equivalent.
- The container image runs as the non-root user `gitforgeops` (UID/GID
  `65532`) instead of root. Anyone who ran an earlier pre-release `:latest` or
  `:main-<sha>` image against a bind-mounted checkout should pass
  `--user "$(id -u):$(id -g)"` so written files stay owned by the checkout
  owner, and may need to `chown` files earlier root runs left behind.
