#!/usr/bin/env bash
set -euo pipefail

# Print (and optionally append) the reviewed digest allowlist line for the
# Ferrum Edge release that release/baseline.json pins.
#
# This is the only supported way to refresh .github/ferrum-edge-checksums.txt.
# Upstream publishes production artifacts only for version tags; assets on a
# given tag are immutable, and a new version tag is a new candidate. Content,
# not the tag, remains the pin: this script resolves exactly one published
# (non-draft, non-prerelease) version release by tag, downloads the asset by
# exact NAME together with the publisher's checksum file, and refuses to emit
# a line unless the two agree. Without --release it resolves the baseline's
# `validator.version` and also refuses unless the bytes match the baseline's
# `validator.sha256`. The emitted record names the version tag (for example
# `# 2026-09-14T02:44:07Z release v0.9.5`). Appending still goes through
# exact-head root review and hosted CI.
#
# Moving the pin to a new Edge release: run with `--release vX.Y.Z --append`,
# then set `validator` and `tested_gateway` in release/baseline.json to that
# version and digest in the same reviewed change.
#
# `--newest` prints the highest published version release: the numerically
# greatest plain `vMAJOR.MINOR.PATCH` tag among all published releases (every
# page of the list) that are neither drafts nor prereleases and publish the
# asset. GitHub's
# "latest" designation is not used: a release can be published without it,
# and a backport can carry it. `--newer` prints that tag only when it is
# numerically greater than the baseline's `validator.version`, and nothing
# otherwise. Neither downloads an asset; both fail when the lookup fails. The
# validator pin canary uses `--newer` to report a newer upstream release.
#
# Usage: refresh-ferrum-edge-pin.sh [--append] [--allowlist PATH]
#                                   [--baseline PATH | --release vX.Y.Z]
#        refresh-ferrum-edge-pin.sh --newest
#        refresh-ferrum-edge-pin.sh --newer [--baseline PATH]

append=false
newest=false
newer=false
explicit_release=
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
allowlist=$script_dir/../ferrum-edge-checksums.txt
baseline=$script_dir/../../release/baseline.json
asset=ferrum-edge-linux-x86_64
releases_api="https://api.github.com/repos/ferrum-edge/ferrum-edge/releases"
asset_url_pattern="^https://api\.github\.com/repos/ferrum-edge/ferrum-edge/releases/assets/[1-9][0-9]*$"
release_tag_pattern="^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"

while [ $# -gt 0 ]; do
  case "$1" in
    --append)
      append=true
      shift
      ;;
    --newest)
      newest=true
      shift
      ;;
    --newer)
      newer=true
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
    --baseline)
      [ $# -ge 2 ] || {
        echo "--baseline requires a path." >&2
        exit 1
      }
      baseline=$2
      shift 2
      ;;
    --release)
      [ $# -ge 2 ] || {
        echo "--release requires a vMAJOR.MINOR.PATCH tag." >&2
        exit 1
      }
      explicit_release=$2
      shift 2
      ;;
    -h | --help)
      sed -n '4,36p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if { [ "$newest" = true ] || [ "$newer" = true ]; } &&
  { [ "$append" = true ] || [ -n "$explicit_release" ]; }; then
  echo "--newest and --newer print a tag only; they cannot be combined with --append or --release." >&2
  exit 1
fi
if [ "$newest" = true ] && [ "$newer" = true ]; then
  echo "Choose one of --newest and --newer." >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
binary="$tmp_dir/$asset"
checksum="$tmp_dir/$asset.sha256"
release_json="$tmp_dir/release.json"

curl_common=(
  --proto '=https' --tlsv1.2 --fail --silent --show-error --location
  --connect-timeout 20 --retry 3 --retry-connrefused
  -H 'X-GitHub-Api-Version: 2022-11-28'
  -H 'User-Agent: gitforgeops-validator-pin-refresh'
)
curl_auth=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  curl_auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi
# Release-list pages are small: bound each request so a stalled endpoint fails
# the lookup quickly instead of consuming the caller's time budget.
curl_list=(
  --proto '=https' --tlsv1.2 --fail --silent --show-error --location
  --connect-timeout 10 --max-time 30 --retry 2
  -H 'X-GitHub-Api-Version: 2022-11-28'
  -H 'User-Agent: gitforgeops-validator-pin-refresh'
)

# The highest published plain version release, compared numerically across
# every page of the release list. GitHub orders the list by creation, not by
# version, so a higher version may sit on any page: enumeration must reach a
# short page, and a page that fails or the page cap fails the whole lookup.
max_release_pages=20
highest_published_release() {
  local page=1 page_json count candidates="$tmp_dir/candidates.txt"
  : >"$candidates"
  while :; do
    if [ "$page" -gt "$max_release_pages" ]; then
      echo "The release list has more than $max_release_pages pages; refusing to guess." >&2
      return 1
    fi
    page_json="$tmp_dir/releases-$page.json"
    curl "${curl_list[@]}" "${curl_auth[@]}" \
      -H 'Accept: application/vnd.github+json' \
      "$releases_api?per_page=100&page=$page" --output "$page_json" || return 1
    count=$(jq -er 'if type == "array" then length else error("not a release list") end' \
      "$page_json") || return 1
    jq -r --arg name "$asset" '
      .[]
      | select(.draft | not)
      | select(.prerelease | not)
      | select([.assets[]?.name] | index($name) != null)
      | .tag_name
      | strings
      | select(test("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"))
    ' "$page_json" >>"$candidates" || return 1
    [ "$count" -lt 100 ] && break
    page=$((page + 1))
  done
  jq -Rr -s '
    split("\n")
    | map(select(length > 0))
    | max_by(ltrimstr("v") | split(".") | map(tonumber))
    // empty
  ' "$candidates"
}

if [ "$newest" = true ] || [ "$newer" = true ]; then
  if ! newest_tag=$(highest_published_release) || [[ ! "$newest_tag" =~ $release_tag_pattern ]]; then
    echo "Could not determine the highest published version release (got '${newest_tag:-<none>}')." >&2
    exit 1
  fi
  if [ "$newest" = true ]; then
    printf '%s\n' "$newest_tag"
    exit 0
  fi
  if [ ! -f "$baseline" ] || [ -L "$baseline" ]; then
    echo "Release baseline is missing or is a symlink: $baseline" >&2
    exit 1
  fi
  if ! pinned_tag=$(jq -er '.validator.version | strings' "$baseline" 2>/dev/null) ||
    [[ ! "$pinned_tag" =~ $release_tag_pattern ]]; then
    echo "Release baseline $baseline must pin validator.version as vMAJOR.MINOR.PATCH." >&2
    exit 1
  fi
  if jq -en --arg newest "$newest_tag" --arg pinned "$pinned_tag" '
    ($newest | ltrimstr("v") | split(".") | map(tonumber))
      > ($pinned | ltrimstr("v") | split(".") | map(tonumber))
  ' >/dev/null; then
    printf '%s\n' "$newest_tag"
  fi
  exit 0
fi

pinned_sha256=
if [ -n "$explicit_release" ]; then
  release_tag=$explicit_release
else
  if [ ! -f "$baseline" ] || [ -L "$baseline" ]; then
    echo "Release baseline is missing or is a symlink: $baseline" >&2
    exit 1
  fi
  if ! release_tag=$(jq -er '.validator.version | strings' "$baseline" 2>/dev/null) ||
    ! pinned_asset=$(jq -er '.validator.asset | strings' "$baseline" 2>/dev/null) ||
    ! pinned_sha256=$(jq -er '.validator.sha256 | strings' "$baseline" 2>/dev/null); then
    echo "Release baseline $baseline must name validator.version, validator.asset and validator.sha256 as strings." >&2
    exit 1
  fi
  if [ "$pinned_asset" != "$asset" ]; then
    echo "Release baseline $baseline pins asset '$pinned_asset'; this script handles only $asset." >&2
    exit 1
  fi
  if [[ ! "$pinned_sha256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Release baseline $baseline must pin validator.sha256 as 64 lowercase hex characters." >&2
    exit 1
  fi
fi
if [[ ! "$release_tag" =~ $release_tag_pattern ]]; then
  echo "Invalid Ferrum Edge release '$release_tag'; expected vMAJOR.MINOR.PATCH." >&2
  exit 1
fi

if ! curl "${curl_common[@]}" "${curl_auth[@]}" \
  -H 'Accept: application/vnd.github+json' \
  "$releases_api/tags/$release_tag" --output "$release_json"; then
  echo "Cannot resolve the Ferrum Edge release $release_tag." >&2
  exit 1
fi
if ! jq -e --arg tag "$release_tag" '
  .tag_name == $tag and .draft == false and .prerelease == false
' "$release_json" >/dev/null 2>&1; then
  echo "Release '$release_tag' is not a published, non-draft, non-prerelease release of exactly that tag." >&2
  exit 1
fi

published_at=$(jq -r '.published_at // ""' "$release_json")
asset_url=$(jq -r --arg name "$asset" \
  '[.assets[]? | select(.name == $name) | .url] | if length == 1 then .[0] else "" end' \
  "$release_json")
checksum_url=$(jq -r --arg name "${asset}.sha256" \
  '[.assets[]? | select(.name == $name) | .url] | if length == 1 then .[0] else "" end' \
  "$release_json")

if [ -z "$asset_url" ] || [ -z "$checksum_url" ]; then
  echo "Release '$release_tag' must publish exactly one $asset and one $asset.sha256 asset." >&2
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

if [ -n "$pinned_sha256" ] && [[ "$actual_sha256" != "$pinned_sha256" ]]; then
  echo "Release $release_tag's $asset does not match the digest release/baseline.json pins; refusing to emit a pin." >&2
  echo "Pinned: $pinned_sha256" >&2
  echo "Actual: $actual_sha256" >&2
  exit 1
fi

record="$actual_sha256  $asset  # ${published_at:-unknown} release $release_tag"
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
  echo "Appended the digest to $allowlist; commit it through exact-head root review." >&2
fi
