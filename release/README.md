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

The intended first pairing is GitForgeOps v0.1.0 with Ferrum Edge v0.9.7:

| Artifact | Digest |
| --- | --- |
| v0.9.7 Linux x86_64 binary: the approved validator and the lifecycle suite's gateway | `c26ba4c059be2d78f4044a3768ebfed5be4e7eb5640620fa93ea9199776b0902` (SHA-256) |
| Docker Hub v0.9.7 multi-platform index, used by the Dockerfile's gateway stage | `sha256:4c9530e09443649526dc4fbbec0720ba7b47ceb91b0dd5cb06db85430908874a` |

They differ because a binary and an OCI index are different artifacts. See the
[upstream release](https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.7)
and the [Docker Hub version tag](https://hub.docker.com/r/ferrumedge/ferrum-edge/tags?name=v0.9.7).
Because the Dockerfile pins the index digest, the GitForgeOps image bundles
this tested gateway.

## Support and compatibility

| Combination or profile | Initial support boundary |
| --- | --- |
| GitForgeOps v0.1.0 source/template with Ferrum Edge v0.9.7 | Intended first pairing; supported only after the record is finalized against passing exact-revision lifecycle evidence. The validator is the checked-in v0.9.7 x86_64 asset. |
| GitForgeOps container | Linux AMD64 and ARM64 image at the recorded immutable GitForgeOps digest. The bundled gateway comes from the v0.9.7 OCI index above. The x86_64 standalone validator pin describes GitHub's Linux x86_64 runners, not an ARM64 binary checksum. |
| Earlier or later Ferrum Edge versions | Not a supported pair. v0.9.4 and earlier cannot accept the resource labels GitForgeOps emits. A newer validator added to the checksum allowlist is not automatically a new supported pairing. Upstream v0.9.6 was tagged but never published. Older allowlist entries, including v0.9.5, are kept only so in-flight pull requests keep validating; they are not part of this pairing. |
| API mode, one namespace, shared ownership, incremental apply | The first customer deployment profile. It includes PR validation/review, human-approved apply, credential delivery, traffic verification, and ownership ledger publication. See the [quickstart](../docs/quickstart.md). |
| File mode and mesh | Supported as assembly, validation, placeholder-preserving publication, and separate encrypted materialization. File output and mesh documents are **not** delivered to nodes by the bundled workflows; mesh has no admin API. Live fleet rollout and file-mode drift monitoring need an external delivery/observation system. Set `live_review: false` for file-only environments. |
| Multiple environments | Independent matrix jobs can run in parallel, each with its own GitHub Environment approval, concurrency group, and ledger. For ordering, set `promotion.requires: staging` and declare traffic checks in `.gitforgeops/smoke.yaml`; promotion waits for successful staging apply and verify for the same eligible revision. Parallel jobs alone provide no promotion gate. |
| Drift monitoring | By default, the scheduled API diff uses the approval-gated deployment environment. Until approved, it reports `Not completed`, never `In sync`. `monitoring.unattended: true` binds a separate `<env>-monitor` environment limited to the exact default branch and GitHub-side read inputs. Its JWT signing secret remains gateway-write-equivalent because Ferrum Edge has no read-only admin credential. See [launch controls §3.1](../docs/github-launch-controls.md#31-unattended-drift-monitoring). |

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
