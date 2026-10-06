# GitForgeOps v0.1.0 release notes

The [baseline record](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/baseline.json)
supplies publication status, exact
revision, image digest, and lifecycle evidence. Copy this note into the GitHub
release when that record is finalized; the committed copy remains available
after workflow artifacts expire.

## Candidate pairing

The intended GitForgeOps v0.1.0 pairing uses published Ferrum Edge v0.9.13
and its verified validator asset and multi-platform image pins. Edge published
the release on 2026-10-06 at tag commit
`9b83115de7ec23ab51ec4feae6bed65e596db425`; its release run completed all 20
jobs successfully. GitForgeOps hosted qualification against those bytes is
still required. The record remains `pending`; a supported GitForgeOps release
requires exact-revision lifecycle evidence and publication.
See the [support table](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/README.md#support-and-compatibility)
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
- The candidate gateway is Ferrum Edge v0.9.13. It includes v0.9.9's request-path
  hardening, which refuses non-final empty path segments and requires
  `allow_path_parameters: true` on a proxy to accept semicolon path parameters;
  review the
  [Edge upgrade guide](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.13/docs/upgrade_guide.md#upgrading-to-099)
  when upgrading a gateway. GitForgeOps exposes the per-proxy
  `allow_path_parameters` opt-in and preserves the mesh service opt-in; semicolon
  path parameters remain refused when the applicable option is absent or false.
  Run validation on a pull request before adopting this pairing.
- Edge v0.9.13 retains v0.9.10 hardening: it refuses non-UTF-8 charsets on MCP
  `ai_prompt_shield` and `mcp_gateway` requests, and fails closed on uninspectable
  or over-nested JSON-RPC batches (GHSA-4f9m-cfqg-fhx9, GHSA-f2jp-59r9-fp64).
- Adopt credential-complete consumer verification and snapshot-conditional full
  replacement, with original row/namespace `If-Match` tokens, opaque Basic HMACs,
  ownership and ledger fences, and no stale-token replay. Rotation checks live
  safety before broker publication and records completion only after its
  conditional gateway write succeeds. Hosted enforcement qualification remains
  required on the exact released bytes (#462).
- Pin the scoped resource schema, fixtures and vocabularies to published
  `contracts-edge-0.9.11` at `390edbd5b2485af0988e02f7827fde778d76ae0a`, retaining
  strict conformance and upstream descriptions. Canonical metadata alone grants
  no production apply or first-release acceptance. The v0.9.13 binary and image
  refresh leaves that pin and the conditional API implementation unchanged.
- API-mode shared ownership is the first deployment profile. File/mesh output
  is assembled and validated, with external fleet delivery required.
- Scheduled monitoring needs approval unless `monitoring.unattended` binds its
  restricted monitor environment. The drift workflow uses the distinct viewer
  key; provision it and remove the admin key from monitor environments before
  deployment. Unverified secrets do not certify an in-sync result.
- The container image runs as the non-root user `gitforgeops` (UID/GID
  `65532`) instead of root. Anyone who ran an earlier pre-release `:latest` or
  `:main-<sha>` image against a bind-mounted checkout should pass
  `--user "$(id -u):$(id -g)"` so written files stay owned by the checkout
  owner, and may need to `chown` files earlier root runs left behind.

The first supported release remains blocked by #266's second human reviewer,
state-writer GitHub App, disposable template repository and HTTPS gateway
acceptance run. The settings audit (#458) and viewer provisioning (#440) retain
their operational steps. This candidate does not fill publication fields,
publish a GitForgeOps tag or claim human acceptance.
