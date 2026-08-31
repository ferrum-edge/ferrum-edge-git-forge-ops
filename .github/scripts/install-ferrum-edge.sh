#!/usr/bin/env bash
set -euo pipefail

release_identity=${1:-}
if [ -n "${RUNNER_TEMP:-}" ]; then
  default_destination="$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"
else
  default_destination=/usr/local/bin/ferrum-edge
fi
destination=${2:-$default_destination}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
checksum_policy=${3:-$script_dir/../ferrum-edge-checksums.txt}
asset=ferrum-edge-linux-x86_64

if [[ ! "$release_identity" =~ ^release-[1-9][0-9]*$ ]]; then
  echo "Invalid FERRUM_EDGE_VERSION: '$release_identity'" >&2
  echo "Expected an immutable release identity like 'release-379454492'." >&2
  exit 1
fi

if [ ! -f "$checksum_policy" ] || [ -L "$checksum_policy" ]; then
  echo "Pinned Ferrum Edge checksum policy is missing or is a symlink: $checksum_policy" >&2
  exit 1
fi
policy_record=$(awk -v release_identity="$release_identity" -v asset="$asset" '
  NF == 5 && $1 == release_identity && $2 == asset && $3 ~ /^[1-9][0-9]*$/ &&
    $4 ~ /^[1-9][0-9]*$/ && $5 ~ /^[0-9A-Fa-f]{64}$/ {
      print $3, $4, tolower($5)
    }
' "$checksum_policy")
if [[ -z "$policy_record" || "$policy_record" == *$'\n'* ]]; then
  echo "Checksum policy must contain exactly one pin for $release_identity $asset." >&2
  exit 1
fi
read -r asset_id checksum_asset_id expected_sha256 <<< "$policy_record"

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
binary="$tmp_dir/$asset"
checksum="$tmp_dir/$asset.sha256"
asset_api="https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/assets"
curl_auth=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  curl_auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi

# Fetch both publisher artifacts by immutable GitHub asset ID, rather than by
# a movable tag. The repository-pinned digest below remains the trust anchor:
# deleting and re-uploading an asset produces a new ID, while changed bytes
# also fail the checked-in SHA-256 comparison.
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --retry-connrefused \
  "${curl_auth[@]}" \
  -H 'Accept: application/octet-stream' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: gitforgeops-validator-installer' \
  "$asset_api/$asset_id" --output "$binary"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --retry-connrefused \
  "${curl_auth[@]}" \
  -H 'Accept: application/octet-stream' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -H 'User-Agent: gitforgeops-validator-installer' \
  "$asset_api/$checksum_asset_id" --output "$checksum"

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
  exit 1
fi
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "Downloaded $asset does not match the repository-pinned SHA-256." >&2
  echo "Expected: $expected_sha256" >&2
  echo "Actual:   $actual_sha256" >&2
  exit 1
fi

# The bytes become executable only after both checksum comparisons pass.
mkdir -p -- "$(dirname -- "$destination")"
install -m 0755 "$binary" "$destination"
if [ -n "${GITHUB_PATH:-}" ]; then
  dirname -- "$destination" >> "$GITHUB_PATH"
fi
echo "Installed $asset from $release_identity (sha256:$actual_sha256)."
