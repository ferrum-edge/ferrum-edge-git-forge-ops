# First supported baseline: GitForgeOps v0.1.0

The [upstream machine-readable record](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/blob/main/release/baseline.json)
is the authority for this pairing. The release tag's source archive contains
the earlier `pending` record because its image digest can only be committed
after that image is published; read the finalized upstream record when
adopting the tag.
Its `status` is `pending` during release preparation. **There is no supported
GitForgeOps release until it says `supported` and all three release-step fields
are filled.** Do not treat the Cargo version, a `main` image, or a successful
development run as a published baseline. The [release notes](notes-v0.1.0.md)
are committed here so the pairing remains discoverable after Actions artifacts
expire.

The intended first pairing is GitForgeOps v0.1.0 with Ferrum Edge v0.9.5.
The v0.9.5 Linux x86_64 asset's SHA-256 is
`31573f0afab23694ce0cfe432f1220dd38099e3ee643e8c5d5b6d2bb3488297c`;
it is the approved validator and the gateway binary used by the lifecycle
suite. The Docker Hub v0.9.5 multi-platform index is
`sha256:eca46c84bca92d6ef467979f8846537f7ab56c0cdc137befff465526a10fe10f`.
The [upstream release](https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.5)
and [Docker Hub version tag](https://hub.docker.com/r/ferrumedge/ferrum-edge/tags?name=v0.9.5)
identify those published artifacts. The Dockerfile uses the versioned index
digest, so the distributed GitForgeOps image bundles this tested gateway line.
These are separate digests: a binary asset and an OCI index cannot share one
SHA-256.

## Support and compatibility

| Combination or profile | Initial support boundary |
| --- | --- |
| GitForgeOps v0.1.0 source/template with Ferrum Edge v0.9.5 | Intended first pairing; supported only after the record is finalized against passing exact-revision lifecycle evidence. The validator is the checked-in v0.9.5 x86_64 asset. |
| GitForgeOps container | Linux AMD64 and ARM64 image at the recorded immutable GitForgeOps digest. The bundled gateway comes from the v0.9.5 OCI index above. The x86_64 standalone validator pin describes GitHub's Linux x86_64 runners, not an ARM64 binary checksum. |
| Earlier or later Ferrum Edge versions | Untested as a supported pair. v0.9.4 and earlier cannot accept the resource labels GitForgeOps emits. A newer validator allowed by the evolving checksum list is not automatically a new supported pairing. |
| API mode, one namespace, shared ownership, incremental apply | The first customer deployment profile. It includes PR validation/review, human-approved apply, credential delivery, traffic verification, and ownership ledger publication. See the [quickstart](../docs/quickstart.md). |
| File mode and mesh | Supported as assembly, validation, placeholder-preserving publication, and separate encrypted materialization. File output and mesh documents are **not** delivered to nodes by the bundled workflows; mesh has no admin API. Live fleet rollout and file-mode drift monitoring need an external delivery/observation system. Set `live_review: false` for file-only environments. |
| Multiple environments | Independent matrix jobs can run in parallel, each with its own GitHub Environment approval, concurrency group, and ledger. For ordering, set `promotion.requires: staging` and declare traffic checks in `.gitforgeops/smoke.yaml`; promotion waits for successful staging apply and verify for the same eligible revision. Parallel jobs alone provide no promotion gate. |
| Drift monitoring | By default, the scheduled API diff uses the approval-gated deployment environment. Until approved, it reports `Not completed`, never `In sync`. `monitoring.unattended: true` binds a separate `<env>-monitor` environment limited to the exact default branch and GitHub-side read inputs. Its JWT signing secret remains gateway-write-equivalent because Ferrum Edge has no read-only admin credential. See [launch controls §3.1](../docs/github-launch-controls.md#31-unattended-drift-monitoring). |

The lifecycle suite's file/mesh scenario certifies the assembly boundary, not
production fleet delivery. Its GitHub acceptance scenarios cover environment
approvals, scheduling, attribution, and the state-writer App. A skipped or
stale scenario cannot authorize publication; the [release workflow](../.github/workflows/release.yml)
requires a sealed result for the **exact source SHA**. Record that run's URL in
`lifecycle.run_url` when publishing.

## Adopt the immutable source/template revision

When the upstream record is `supported`, copy its `gitforgeops.source_sha` into
`GFO_SHA` and verify the protected tag resolves to that commit. GitHub's **Use
this template** button copies the current default branch and has no immutable
revision selector. A clean customer repository can instead start from the
verified source archive:

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

Choose repository visibility and GitHub plan using the
[quickstart prerequisites](../docs/quickstart.md#0-before-you-start). Then
follow its bootstrap, environment, resources, first PR, and apply steps. The
copy builds the GitForgeOps engine from its own checkout and installs the
validator only after checking the publisher checksum against the committed
allowlist. Neither operation silently accepts new executable bytes. The
installer fetches Ferrum Edge's newest published version and refuses it when
its digest is not on this source revision's allowlist. If a newer gateway
release makes this frozen source fail closed, use a subsequently tested
baseline; do not silently append a new validator digest to this pairing.

## Verify the distributed image and provenance

After publication, take `GFO_SHA` and `IMAGE_DIGEST` from the supported record.
Authenticate `gh` and the OCI registry before verification. The release
workflow attests the same Buildx output digest under both registry names. For
the primary GHCR route, verify the GitHub-signed SLSA provenance and restrict
it to this repository, signer workflow, source commit, and release tag:

```bash
IMAGE_DIGEST='PASTE_SHA256_IMAGE_DIGEST_FROM_RELEASE_RECORD'
gh attestation verify \
  "oci://ghcr.io/ferrum-edge/ferrum-edge-git-forge-ops@${IMAGE_DIGEST}" \
  --repo ferrum-edge/ferrum-edge-git-forge-ops \
  --signer-workflow ferrum-edge/ferrum-edge-git-forge-ops/.github/workflows/release.yml \
  --source-digest "$GFO_SHA" --source-ref refs/tags/v0.1.0
```

The equivalent Docker Hub subject is
`oci://docker.io/ferrumedge/ferrum-edge-git-forge-ops@${IMAGE_DIGEST}`;
run the same verification flags for that subject when using Docker Hub.
Verify the digest in `supply-chain-inputs-<source SHA>` from the publishing run
matches `IMAGE_DIGEST` and its `source_sha` matches `GFO_SHA`. That run artifact
is a useful cross-check, but its 90-day retention is **not** the release
record; the committed record and release notes retain the identifying facts.

## Publishing and later changes

The existing protected `release.yml` is the only packaging path. It checks
the merged PR's required checks and sealed lifecycle result before building,
publishes both registries, signs provenance for each name, and records the
resulting digest. Use the resulting digest and exact source SHA to finalize
`baseline.json` **after** the image exists. A record-only commit is excluded
from image publishing to avoid moving `latest` while recording a past build.
Publish the GitHub release with the committed notes and link to this record.

After the first supported baseline, announce fixes in a versioned release note
with the affected versions, replacement source SHA, artifact digest, gateway
pairing, and any operator action. Patch releases carry compatible fixes;
breaking CLI, configuration, state, or workflow changes require a new minor
version during the 0.x series, explicit migration steps, and a new tested
pairing. Security fixes use [security advisories](../SECURITY.md) as needed.
Existing template copies receive none of these changes automatically: use
[the downstream update procedure](../docs/template-updates.md) to review and
adopt the exact released revision. No compatibility layer is promised for
pre-user buildout formats.
