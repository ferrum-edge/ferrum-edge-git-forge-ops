#!/usr/bin/env bash
set -euo pipefail

# Print (and optionally append) the reviewed digest allowlist line for the
# Ferrum Edge validator build upstream is publishing right now.
#
# This is the only supported way to refresh .github/ferrum-edge-checksums.txt.
# It resolves the asset by exact NAME, downloads it together with the
# publisher's checksum file, and refuses to emit a line unless the two agree.
# Appending still goes through CODEOWNER review: the allowlist is an owned path.
#
# Usage: refresh-ferrum-edge-pin.sh [--append] [--allowlist PATH]

append=false
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
allowlist=$script_dir/../ferrum-edge-checksums.txt
asset=ferrum-edge-linux-x86_64
releases_api="https://api.github.com/repos/ferrum-edge/ferrum-edge/releases"
asset_url_pattern="^https://api\.github\.com/repos/ferrum-edge/ferrum-edge/releases/assets/[1-9][0-9]*$"

while [ $# -gt 0 ]; do
  case "$1" in
    --append)
      append=true
      shift
      ;;
    --allowlist)
      [ $# -ge 2 ] || {
        echo "--allowlist requires a path." >&2
        exit 1
      }
      allowlist=$2
      shift 2
      ;;
    -h | --help)
      sed -n '4,15p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
binary="$tmp_dir/$asset"
checksum="$tmp_dir/$asset.sha256"
release_json="$tmp_dir/release.json"

curl_common=(
  --proto '=https' --tlsv1.2 --fail --silent --show-error --location
  --retry 3 --retry-connrefused
  -H 'X-GitHub-Api-Version: 2022-11-28'
  -H 'User-Agent: gitforgeops-validator-pin-refresh'
)
curl_auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  curl_auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi

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
  echo "Downloaded $asset does not match its published checksum; refusing to emit a pin." >&2
  echo "Published: $published_sha256" >&2
  echo "Actual:    $actual_sha256" >&2
  exit 1
fi

record="$actual_sha256  $asset  # ${published_at:-unknown} release ${release_tag:-unknown}"
printf '%s\n' "$record"

if [ "$append" = true ]; then
  if [ ! -f "$allowlist" ] || [ -L "$allowlist" ]; then
    echo "Digest allowlist is missing or is a symlink: $allowlist" >&2
    exit 1
  fi
  if grep -qE "^${actual_sha256}[[:space:]]" "$allowlist"; then
    echo "Digest $actual_sha256 is already allowlisted in $allowlist." >&2
    exit 0
  fi
  printf '%s\n' "$record" >>"$allowlist"
  echo "Appended the digest to $allowlist; commit it through CODEOWNER review." >&2
fi
