#!/usr/bin/env bash
set -euo pipefail

# Run only AFTER install-ferrum-edge.sh has verified both the publisher's
# checksum and the reviewed digest allowlist. Capability does not replace trust.
# Usage: check-validator-resource-labels.sh /absolute/path/to/ferrum-edge
if [ "$#" -ne 1 ] || [[ "$1" != /* ]] || [ ! -x "$1" ]; then
  echo 'Expected an absolute path to the installed, verified Ferrum Edge validator.' >&2
  exit 1
fi
binary=$1
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture="$script_dir/../fixtures/validator-resource-labels.yaml"
tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT
: >"$tmp_dir/empty.conf"

# The fixture uses the default ferrum namespace. Empty settings and a clean
# environment keep ambient gateway/mesh settings out of this offline check.
# The timeout also fails closed for a hung or broken upstream validator.
if ! env -i PATH="$PATH" timeout 60 "$binary" validate -m file \
  -s "$tmp_dir/empty.conf" -c "$fixture"; then
  echo '::error::Pinned Ferrum Edge validator must accept resource labels on Proxy, Consumer, Upstream and PluginConfig. Review and allowlist a build including ferrum-edge#5483.'
  exit 1
fi
echo 'Pinned Ferrum Edge validator accepts resource labels on all four gateway resource kinds.'
