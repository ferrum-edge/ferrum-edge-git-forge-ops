# First supported baseline: GitForgeOps v0.1.0

The [upstream machine-readable record](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/baseline.json)
is the authority for this pairing. Its `status` is `pending` while the release
is being prepared. **There is no supported GitForgeOps release until it says
`supported` and its three release fields (`gitforgeops.source_sha`,
`gitforgeops.image_digest`, `lifecycle.run_url`) are filled.** A Cargo
version, a `main` image or a successful development run is not a published
baseline.

The tag's own source archive contains the earlier `pending` record, because the
image digest can only be committed after the image is published. Read the
finalized record on upstream `main` when adopting the tag. The
[release notes](notes-v0.1.0.md) are committed here so the pairing stays
discoverable after Actions artifacts expire.

The intended first pairing is GitForgeOps v0.1.0 with Ferrum Edge v0.9.19:

| Artifact | Digest |
| --- | --- |
| v0.9.19 Linux x86_64 binary: the approved validator and the lifecycle suite's gateway | `446e5aa4a85f03bc33a4cd2d618904a676ecf06f657954dca5b67a9563dec818` (SHA-256) |
| v0.9.19 Linux aarch64 standalone gateway asset | `6b82a48ea56a59a2ce86c48d423b0d77de42d1b4e4d8b1f67da99b5b80e20b08` (SHA-256) |
| Docker Hub v0.9.19 linux/amd64 image manifest | `sha256:a6383110354ad04905ed4be2036a36c26bee5c9439e40ae52502ef4d7604f03d` |
| Docker Hub v0.9.19 linux/arm64 image manifest | `sha256:0ab3341d8204fa5696f57c2ffc07e3d82914bac22c58b0ddc741077968262019` |
| Docker Hub v0.9.19 multi-platform index, used by the Dockerfile's gateway stage | `sha256:0e2ed6d720cbc474e29cfa6bcd3945db010674d69988e2bd795a26399c3cb80e` |

Standalone binaries and OCI manifests are separate artifacts; the container
copies its gateway from the pinned platform image, not the standalone asset. See the
[upstream release](https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.19)
and the [Docker Hub version tag](https://hub.docker.com/r/ferrumedge/ferrum-edge/tags?name=v0.9.19).
Because the Dockerfile pins the index digest, the GitForgeOps image bundles
this verified gateway candidate. Edge v0.9.19 was published on 2026-10-27 at
tag commit `510ce7121c3d9754110d330a30a3bd9b7a7b278e`. Its
[release run](https://github.com/ferrum-edge/ferrum-edge/actions/runs/40457120201)
completed successfully. These upstream release
facts do not replace GitForgeOps hosted validation or exact-revision lifecycle
acceptance against these bytes; both remain required.

The standard image's signed SLSA provenance binds the index and both platform
manifests above to that source commit, release workflow and `refs/tags/v0.9.19`.
Review the [v0.9.19 operator changes](https://github.com/ferrum-edge/ferrum-edge/blob/510ce7121c3d9754110d330a30a3bd9b7a7b278e/docs/upgrade_guide.md#upgrading-to-0919)
before rollout. v0.9.19 carries the changes prepared for the unpublished v0.9.18
tag, whose ARM64 build failed; many plugin configurations v0.9.17 accepted are now
refused, and PluginConfig updates and deletes require `expected_proxy_ids`, which
GitForgeOps already sends. The unpublished v0.9.16 and v0.9.18 tags are not
distribution candidates. The scoped vendored Contracts pin moves to
`contracts-edge-0.9.19`; that adoption does not claim conformance or acceptance
against the new gateway.

## Support and compatibility

| Combination or profile | Initial support boundary |
| --- | --- |
| GitForgeOps v0.1.0 source/template with Ferrum Edge v0.9.19 | Intended first pairing; supported only after the record is finalized against passing exact-revision lifecycle evidence. The validator is the checked-in v0.9.19 x86_64 asset. |
| GitForgeOps container | Linux AMD64 and ARM64 image at the recorded immutable GitForgeOps digest. The bundled gateway comes from the v0.9.19 OCI index above. The x86_64 standalone validator pin describes GitHub's Linux x86_64 runners, not an ARM64 binary checksum. |
| Earlier or later Ferrum Edge versions | Not a supported pair. v0.9.4 and earlier cannot accept the resource labels GitForgeOps emits. A newer validator added to the checksum allowlist is not automatically a new supported pairing. Upstream v0.9.6, v0.9.16 and v0.9.18 were tagged but never published. Older allowlist entries, including v0.9.5, v0.9.7, v0.9.8, v0.9.9, v0.9.10, v0.9.11, v0.9.12, v0.9.13, v0.9.14, v0.9.15 and v0.9.17, are kept only so in-flight pull requests keep validating; they are not part of this pairing. |
| API mode, one namespace, shared ownership, incremental apply | The first customer deployment profile. It includes PR validation/review, human-approved apply, credential delivery, traffic verification, and ownership ledger publication. See the [quickstart](../docs/quickstart.md). |
| File mode and mesh | Supported as assembly, validation, placeholder-preserving publication, and separate encrypted materialization. File output and mesh documents are **not** delivered to nodes by the bundled workflows; mesh has no admin API. Live fleet rollout and file-mode drift monitoring need an external delivery/observation system. Set `live_review: false` for file-only environments. |
| Multiple environments | Independent matrix jobs can run in parallel, each with its own GitHub Environment approval, concurrency group, and ledger. For ordering, set `promotion.requires: staging` and declare traffic checks in `.gitforgeops/smoke.yaml`; promotion waits for successful staging apply and verify for the same eligible revision. Parallel jobs alone provide no promotion gate. |
| Drift monitoring | By default, the scheduled API diff uses the approval-gated deployment environment. Until approved, it reports `Not completed`, never `In sync`. `monitoring.unattended: true` binds a separate `<env>-monitor` environment limited to the exact default branch and GitHub-side read inputs. The workflow binds the distinct viewer-capped `FERRUM_ADMIN_JWT_VIEWER_SECRET` for `GET /config/export`; provision that key and remove the admin key from monitor environments before deployment. Unverified secrets never certify an in-sync result. See [launch controls §3.1](../docs/github-launch-controls.md#31-unattended-drift-monitoring). |

The lifecycle suite's file/mesh scenario certifies the assembly boundary, not
production fleet delivery. Its GitHub acceptance scenarios cover environment
approvals, scheduling, attribution and the state-writer App. A skipped or stale
scenario cannot authorize publication: the
[release workflow](../.github/workflows/release.yml) requires a sealed result
for the **exact source SHA**. Record that run's URL in `lifecycle.run_url` when
publishing.

## Adopt the immutable source/template revision

Once the upstream record is `supported`, copy its `gitforgeops.source_sha` into
`GFO_SHA` and check that the protected tag resolves to that commit. GitHub's
**Use this template** button always copies the current default branch, so
start a clean repository from the verified source archive instead:

```bash
GFO_SHA='PASTE_40_HEX_SOURCE_SHA_FROM_RELEASE_RECORD'
git clone --no-checkout https://github.com/ferrum-edge/ferrum-edge-git-forge-ops.git gitforgeops-upstream
test "$(git -C gitforgeops-upstream rev-parse 'v0.1.0^{commit}')" = "$GFO_SHA"
mkdir gateway-config
git -C gitforgeops-upstream archive "$GFO_SHA" | tar -x -C gateway-config
cd gateway-config
git init -b main
git add -A
git commit -m 'Adopt GitForgeOps v0.1.0 baseline'
gh repo create OWNER/REPO --private --source . --push
python3 .github/scripts/template_update.py detect-baseline --write
git add .gitforgeops/baseline.json
git commit -m 'Record upstream template baseline'
git push
```

Choose repository visibility and GitHub plan with the
[quickstart prerequisites](../docs/quickstart.md#0-before-you-start), then
follow the rest of the quickstart.

Your copy builds the GitForgeOps engine from its own checkout. The validator
installer fetches Ferrum Edge's newest published release, checks the
publisher's checksum, and refuses the binary unless its digest is on this
source revision's allowlist. So neither step silently accepts new executable
bytes. If a newer gateway release makes this frozen source fail closed, move to
a later tested baseline; do not append a new validator digest to this pairing.

## Verify the distributed image and provenance

After publication, take `GFO_SHA` and `IMAGE_DIGEST` from the supported record,
and authenticate `gh` and the OCI registry. The release workflow attests the
same image digest under both registry names. For GHCR, verify the GitHub-signed
SLSA provenance, restricted to this repository, signer workflow, source commit
and release tag:

```bash
IMAGE_DIGEST='PASTE_SHA256_IMAGE_DIGEST_FROM_RELEASE_RECORD'
gh attestation verify \
  "oci://ghcr.io/ferrum-edge/ferrum-edge-git-forge-ops@${IMAGE_DIGEST}" \
  --repo ferrum-edge/ferrum-edge-git-forge-ops \
  --signer-workflow ferrum-edge/ferrum-edge-git-forge-ops/.github/workflows/release.yml \
  --source-digest "$GFO_SHA" --source-ref refs/tags/v0.1.0
```

For Docker Hub, run the same flags against
`oci://docker.io/ferrumedge/ferrum-edge-git-forge-ops@${IMAGE_DIGEST}`.

As a cross-check, the publishing run's `supply-chain-inputs-<source SHA>`
artifact should show `published_image_digest` equal to `IMAGE_DIGEST` and
`source_sha` equal to `GFO_SHA`. That artifact expires after 90 days, so it is **not** the release
record; the committed record and release notes are.

## Publishing and later changes

The protected `release.yml` is the only packaging path. Before building, it
checks the merged PR's required checks and a sealed lifecycle result for the
exact commit. It then publishes to both registries, attests provenance under
each name, and uploads the `supply-chain-inputs` artifact with the resulting
digest. Finalize `baseline.json` with that digest and the exact source SHA
**after** the image exists. `release.yml` ignores changes under `release/`, so
the record-only commit does not republish the image or move `latest`. Publish
the GitHub release with the committed notes and link to this record.

After the first supported baseline, announce each fix in a versioned release
note with the affected versions, replacement source SHA, image digest, gateway
pairing and any operator action. Patch releases carry compatible fixes.
During 0.x, breaking CLI, configuration, state or workflow changes need a new
minor version, explicit migration steps and a new tested pairing. Security
fixes use [security advisories](../SECURITY.md) as needed.

Existing template copies get none of these changes automatically; use
[the downstream update procedure](../docs/template-updates.md) to review and
adopt the exact released revision. No compatibility layer is promised for
formats from before the first release.

## Conditional API adoption qualification (#462)

The candidate pairing pins published Edge v0.9.19 to owner commit
`510ce7121c3d9754110d330a30a3bd9b7a7b278e`, with content-pinned (SHA-256)
release artifacts, the verified x86_64 asset and default multi-platform image
index listed above. The existing conditional API implementation is unchanged.
Vendored Contracts are pinned to published
`contracts-edge-0.9.19`, commit `d96b0292a0f87647f7552f25e0e5ce1b4ae30f8b`;
all scoped canonical copies and PIN hashes match that tag. The contract
adoption does not change the conditional API implementation or extend the
vendored scope. See the [contracts guide](../docs/contracts.md) for the
adoption scope and authority limits.

Hosted qualification must exercise complete consumer verification, hidden
credential conflicts, rotation conflicts before and after broker delivery, and
the required `conditional-full-replace` lifecycle scenario against these exact
released bytes. The old v0.9.10 fixture cannot qualify these endpoints and must
not be made green by skipping the new scenario. This pin update does not record
passing lifecycle evidence or first-release acceptance: `baseline.json` remains
`pending`, with GitForgeOps source SHA, image digest and lifecycle URL unset.

Qualification must cover original-token restore, spec-owned graph and verbatim
documents, trust preservation, ABA, empty namespaces and confirmed spec deletion;
exact-token/body precommit retry; and no replay after ambiguous commit, audit or
fence refusal, unsupported topology or `applied:false`. Seal the exact client SHA
and released server bytes. Source/parser evidence alone is not enforcement.
Existing eight advisory fixes and #458/#440 provisioning remain required; #266
still requires a second human reviewer, the state-writer GitHub App, a disposable
customer template repository and an HTTPS gateway acceptance run. No GitForgeOps
tag or supported release is established by this candidate.
