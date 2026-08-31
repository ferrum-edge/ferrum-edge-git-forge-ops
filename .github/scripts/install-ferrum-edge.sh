#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
if [ -n "${RUNNER_TEMP:-}" ]; then
  default_destination="$RUNNER_TEMP/gitforgeops-validator-bin/ferrum-edge"
else
  default_destination=/usr/local/bin/ferrum-edge
fi
destination=${2:-$default_destination}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
checksum_policy=${3:-$script_dir/../ferrum-edge-checksums.txt}
asset=ferrum-edge-linux-x86_64

if [[ ! "$version" =~ ^latest$|^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid FERRUM_EDGE_VERSION: '$version'" >&2
  echo "Expected 'latest' or a release tag like 'v1.2.3'." >&2
  exit 1
fi

if [ ! -f "$checksum_policy" ] || [ -L "$checksum_policy" ]; then
  echo "Pinned Ferrum Edge checksum policy is missing or is a symlink: $checksum_policy" >&2
  exit 1
fi
expected_sha256=$(awk -v version="$version" -v asset="$asset" '
  $1 == version && $2 == asset && $3 ~ /^[0-9A-Fa-f]{64}$/ { print tolower($3) }
' "$checksum_policy")
if [[ -z "$expected_sha256" || "$expected_sha256" == *$'\n'* ]]; then
  echo "Checksum policy must contain exactly one pin for $version $asset." >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
binary="$tmp_dir/$asset"
checksum="$tmp_dir/$asset.sha256"
base_url="https://github.com/ferrum-edge/ferrum-edge/releases/download/${version}"

# Fetch both publisher artifacts. The repository-pinned digest below remains
# the trust anchor: a compromised/moved release cannot replace both files and
# silently pass, because the computed bytes must also match the checked-in pin.
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --retry-connrefused "$base_url/$asset" --output "$binary"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --retry-connrefused "$base_url/$asset.sha256" --output "$checksum"

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
echo "Installed $asset from release $version (sha256:$actual_sha256)."
