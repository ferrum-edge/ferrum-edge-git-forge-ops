#!/usr/bin/env bash
set -euo pipefail

# Install the reviewed Ferrum Edge validator binary.
#
# The trust anchor is CONTENT, never a locator. Upstream publishes a single
# rolling `latest` release whose assets are deleted and re-uploaded on every
# build, so release ids, asset ids and tags all move underneath us. This script
# therefore resolves the asset by its exact NAME, verifies the publisher's own
# checksum file, and then requires the computed SHA-256 to appear in the
# reviewed allowlist at .github/ferrum-edge-checksums.txt. The bytes become
# executable only after that allowlist match, so an unreviewed build is never
# executed. The allowlist holds one line per approved build, so refreshing it
# does not orphan in-flight pull requests.
#
# Usage: install-ferrum-edge.sh [destination] [allowlist]

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [ -n "${RUNNER_TEMP:-}" ]; then
  default_destination="$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"
else
  default_destination=/usr/local/bin/ferrum-edge
fi
destination=${1:-$default_destination}
allowlist=${2:-$script_dir/../ferrum-edge-checksums.txt}
asset=ferrum-edge-linux-x86_64
releases_api="https://api.github.com/repos/ferrum-edge/ferrum-edge/releases"
asset_url_pattern="^https://api\.github\.com/repos/ferrum-edge/ferrum-edge/releases/assets/[1-9][0-9]*$"

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

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
binary="$tmp_dir/$asset"
checksum="$tmp_dir/$asset.sha256"
release_json="$tmp_dir/release.json"

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

# Upstream ships one rolling `latest` tag. Resolve it directly, and fall back to
# the release list so a renamed or unpublished tag degrades into "newest release
# that still carries the asset" instead of a hard failure.
if ! curl "${curl_common[@]}" "${curl_auth[@]}" \
  -H 'Accept: application/vnd.github+json' \
  "$releases_api/tags/latest" --output "$release_json"; then
  echo "Rolling 'latest' release tag is unavailable; falling back to the release list." >&2
  releases_json="$tmp_dir/releases.json"
  curl "${curl_common[@]}" "${curl_auth[@]}" \
    -H 'Accept: application/vnd.github+json' \
    "$releases_api?per_page=5" --output "$releases_json"
  jq --arg name "$asset" '
    [ .[]
      | select(.draft | not)
      | select([.assets[]?.name] | index($name) != null)
    ]
    | sort_by(.published_at)
    | reverse
    | .[0] // empty
  ' "$releases_json" >"$release_json"
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

# The bytes become executable only after the publisher checksum and the
# reviewed allowlist both agree.
mkdir -p -- "$(dirname -- "$destination")"
install -m 0755 "$binary" "$destination"
if [ -n "${GITHUB_PATH:-}" ]; then
  dirname -- "$destination" >>"$GITHUB_PATH"
fi
echo "Installed $asset (sha256:$actual_sha256) from release ${release_tag:-<unknown>} published ${published_at:-<unknown>}."
