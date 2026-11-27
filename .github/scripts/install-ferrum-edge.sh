#!/usr/bin/env bash
set -euo pipefail

# Install the reviewed Ferrum Edge validator binary.
#
# The trust anchor is CONTENT, never a locator. Upstream publishes production
# artifacts only for version tags; assets on a given tag are immutable, and a
# new version tag is a new candidate. This script installs exactly the release
# the release baseline pins (`validator.version`, `validator.asset` and
# `validator.sha256` in release/baseline.json), never "whatever upstream
# published last":
#
#   1. the allowlist and the baseline are parsed before any network access,
#      and the baseline's digest must already be on the allowlist;
#   2. the pinned tag is resolved through `/releases/tags/<tag>` and must be a
#      published (non-draft, non-prerelease) release of exactly that tag;
#   3. the asset is downloaded by exact NAME from the upstream repository's
#      asset API, together with the publisher's own `.sha256` file;
#   4. the computed SHA-256 must match the publisher's checksum, the
#      baseline's `validator.sha256`, and a line of the reviewed allowlist at
#      .github/ferrum-edge-checksums.txt.
#
# The bytes become executable only after all three agree, so an unreviewed
# build is never executed. The allowlist keeps one line per approved build, so
# moving the pin does not orphan in-flight pull requests that still carry the
# previous baseline.
#
# The baseline defaults to `release/baseline.json` beside the allowlist's
# `.github/` directory, so the pinned version and the digest allowlist always
# come from the same tree (the protected default branch for privileged
# workflows, the candidate for pull-request validation).
#
# Separately, and only to inform, the newest published version release is
# looked up (GitHub's `/releases/latest`, which skips drafts and prereleases,
# with the version-release list as fallback) and reported when it differs from
# the pin. That lookup never selects which bytes are installed, and its failure
# does not fail the install.
#
# Usage: install-ferrum-edge.sh [destination] [allowlist] [baseline]

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [ -n "${RUNNER_TEMP:-}" ]; then
  default_destination="$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"
else
  default_destination=/usr/local/bin/ferrum-edge
fi
destination=${1:-$default_destination}
allowlist=${2:-$script_dir/../ferrum-edge-checksums.txt}
baseline=${3:-$(dirname -- "$allowlist")/../release/baseline.json}
asset=ferrum-edge-linux-x86_64
releases_api="https://api.github.com/repos/ferrum-edge/ferrum-edge/releases"
asset_url_pattern="^https://api\.github\.com/repos/ferrum-edge/ferrum-edge/releases/assets/[1-9][0-9]*$"
release_tag_pattern="^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"

if [ ! -f "$allowlist" ] || [ -L "$allowlist" ]; then
  echo "Pinned Ferrum Edge digest allowlist is missing or is a symlink: $allowlist" >&2
  exit 1
fi

# Parse the allowlist before touching the network: an unreadable or malformed
# policy file must fail closed rather than fall back to "whatever upstream
# serves today".
allowed_digests=()
line_number=0
while IFS= read -r allowlist_line || [ -n "$allowlist_line" ]; do
  line_number=$((line_number + 1))
  record=${allowlist_line%%#*}
  digest=
  digest_asset=
  trailing=
  read -r digest digest_asset trailing <<<"$record"
  [ -n "$digest" ] || continue
  if [ -n "$trailing" ] || [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]] || [ "$digest_asset" != "$asset" ]; then
    echo "Malformed digest allowlist entry at $allowlist:$line_number" >&2
    echo "Expected '<64 lowercase hex sha256>  $asset' with an optional trailing '# comment'." >&2
    exit 1
  fi
  allowed_digests+=("$digest")
done <"$allowlist"

if [ ${#allowed_digests[@]} -eq 0 ]; then
  echo "Digest allowlist $allowlist approves no $asset build." >&2
  exit 1
fi

# The release baseline names the one release to install. It is read just as
# strictly: a missing, symlinked or malformed record fails closed.
if [ ! -f "$baseline" ] || [ -L "$baseline" ]; then
  echo "Release baseline is missing or is a symlink: $baseline" >&2
  exit 1
fi
if ! pinned_tag=$(jq -er '.validator.version | strings' "$baseline" 2>/dev/null) ||
  ! pinned_asset=$(jq -er '.validator.asset | strings' "$baseline" 2>/dev/null) ||
  ! pinned_sha256=$(jq -er '.validator.sha256 | strings' "$baseline" 2>/dev/null); then
  echo "Release baseline $baseline must name validator.version, validator.asset and validator.sha256 as strings." >&2
  exit 1
fi
if [[ ! "$pinned_tag" =~ $release_tag_pattern ]]; then
  echo "Release baseline $baseline pins an invalid validator version '$pinned_tag'; expected vMAJOR.MINOR.PATCH." >&2
  exit 1
fi
if [ "$pinned_asset" != "$asset" ]; then
  echo "Release baseline $baseline pins asset '$pinned_asset'; this installer installs only $asset." >&2
  exit 1
fi
if [[ ! "$pinned_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Release baseline $baseline must pin validator.sha256 as 64 lowercase hex characters." >&2
  exit 1
fi
pin_allowlisted=false
for allowed_digest in "${allowed_digests[@]}"; do
  if [ "$allowed_digest" = "$pinned_sha256" ]; then
    pin_allowlisted=true
    break
  fi
done
if [ "$pin_allowlisted" != true ]; then
  {
    echo "The release baseline pins a $asset digest the reviewed allowlist does not approve."
    echo "  Baseline:  $baseline ($pinned_tag)"
    echo "  Allowlist: $allowlist"
    echo "  Digest:    $pinned_sha256"
    echo "Record the reviewed build with:"
    echo "  bash .github/scripts/refresh-ferrum-edge-pin.sh --append"
  } >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
binary="$tmp_dir/$asset"
checksum="$tmp_dir/$asset.sha256"
release_json="$tmp_dir/release.json"
newest_json="$tmp_dir/newest.json"

curl_common=(
  --proto '=https' --tlsv1.2 --fail --silent --show-error --location
  --retry 3 --retry-connrefused
  -H 'X-GitHub-Api-Version: 2022-11-28'
  -H 'User-Agent: gitforgeops-validator-installer'
)
curl_auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  curl_auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi

# Informational only: report a newer published version release. GitHub's
# `/releases/latest` skips drafts and prereleases; the release list, filtered
# the same way and ordered by published_at, is the fallback. Nothing below
# reads this result to choose bytes.
newest_tag=
if curl "${curl_common[@]}" "${curl_auth[@]}" \
  -H 'Accept: application/vnd.github+json' \
  "$releases_api/latest" --output "$newest_json" 2>/dev/null; then
  newest_tag=$(jq -r '.tag_name // ""' "$newest_json" 2>/dev/null || true)
else
  releases_json="$tmp_dir/releases.json"
  if curl "${curl_common[@]}" "${curl_auth[@]}" \
    -H 'Accept: application/vnd.github+json' \
    "$releases_api?per_page=5" --output "$releases_json" 2>/dev/null; then
    newest_tag=$(jq -r --arg name "$asset" '
      [ .[]
        | select(.draft | not)
        | select(.prerelease | not)
        | select([.assets[]?.name] | index($name) != null)
      ]
      | sort_by(.published_at)
      | reverse
      | .[0].tag_name // ""
    ' "$releases_json" 2>/dev/null || true)
  fi
fi
if [ -z "$newest_tag" ]; then
  echo "Note: the newest published Ferrum Edge release could not be determined; installing the pinned $pinned_tag." >&2
elif [ "$newest_tag" != "$pinned_tag" ]; then
  echo "Note: the newest published Ferrum Edge release is $newest_tag; release/baseline.json pins $pinned_tag, which is what is installed." >&2
fi

# Resolve exactly the pinned version release.
if ! curl "${curl_common[@]}" "${curl_auth[@]}" \
  -H 'Accept: application/vnd.github+json' \
  "$releases_api/tags/$pinned_tag" --output "$release_json"; then
  echo "Cannot resolve the pinned Ferrum Edge release $pinned_tag." >&2
  exit 1
fi
if ! jq -e --arg tag "$pinned_tag" '
  .tag_name == $tag and .draft == false and .prerelease == false
' "$release_json" >/dev/null 2>&1; then
  echo "Release '$pinned_tag' is not a published, non-draft, non-prerelease release of exactly that tag." >&2
  exit 1
fi

release_tag=$(jq -r '.tag_name // ""' "$release_json")
published_at=$(jq -r '.published_at // ""' "$release_json")
asset_url=$(jq -r --arg name "$asset" \
  '[.assets[]? | select(.name == $name) | .url] | if length == 1 then .[0] else "" end' \
  "$release_json")
checksum_url=$(jq -r --arg name "${asset}.sha256" \
  '[.assets[]? | select(.name == $name) | .url] | if length == 1 then .[0] else "" end' \
  "$release_json")

if [ -z "$asset_url" ] || [ -z "$checksum_url" ]; then
  echo "Release '${release_tag:-<unresolved>}' must publish exactly one $asset and one $asset.sha256 asset." >&2
  exit 1
fi
for candidate_url in "$asset_url" "$checksum_url"; do
  if [[ ! "$candidate_url" =~ $asset_url_pattern ]]; then
    echo "Refusing to download from an unexpected asset URL: $candidate_url" >&2
    exit 1
  fi
done

curl "${curl_common[@]}" "${curl_auth[@]}" \
  -H 'Accept: application/octet-stream' \
  "$asset_url" --output "$binary"
curl "${curl_common[@]}" "${curl_auth[@]}" \
  -H 'Accept: application/octet-stream' \
  "$checksum_url" --output "$checksum"

published_sha256=$(awk -v asset="$asset" '
  NF == 2 && ($2 == asset || $2 == "*" asset) && $1 ~ /^[0-9A-Fa-f]{64}$/ { print tolower($1) }
' "$checksum")
if [[ -z "$published_sha256" || "$published_sha256" == *$'\n'* ]]; then
  echo "Published checksum file must contain exactly one valid entry for $asset." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$binary" | awk '{print $1}')
else
  actual_sha256=$(shasum -a 256 "$binary" | awk '{print $1}')
fi

if [[ "$actual_sha256" != "$published_sha256" ]]; then
  echo "Downloaded $asset does not match its published checksum." >&2
  echo "Published: $published_sha256" >&2
  echo "Actual:    $actual_sha256" >&2
  exit 1
fi

if [[ "$actual_sha256" != "$pinned_sha256" ]]; then
  {
    echo "Refusing to execute a $asset build the release baseline does not pin."
    echo "  Baseline: $baseline ($pinned_tag)"
    echo "  Pinned:   $pinned_sha256"
    echo "  Actual:   $actual_sha256"
    echo "  Release:  ${release_tag:-<unknown>} published ${published_at:-<unknown>}"
  } >&2
  exit 1
fi

approved=false
for allowed_digest in "${allowed_digests[@]}"; do
  if [ "$allowed_digest" = "$actual_sha256" ]; then
    approved=true
    break
  fi
done
if [ "$approved" != true ]; then
  {
    echo "Refusing to execute an unreviewed $asset build."
    echo "  Allowlist: $allowlist"
    echo "  Digest:    $actual_sha256"
    echo "  Release:   ${release_tag:-<unknown>} published ${published_at:-<unknown>}"
    echo "Review the upstream build, then record it with:"
    echo "  bash .github/scripts/refresh-ferrum-edge-pin.sh --append"
  } >&2
  exit 1
fi

# The bytes become executable only after the publisher checksum, the release
# baseline and the reviewed allowlist all agree.
mkdir -p -- "$(dirname -- "$destination")"
install -m 0755 "$binary" "$destination"
if [ -n "${GITHUB_PATH:-}" ]; then
  dirname -- "$destination" >>"$GITHUB_PATH"
fi
echo "Installed $asset (sha256:$actual_sha256) from release ${release_tag:-<unknown>} published ${published_at:-<unknown>}."
