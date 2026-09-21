#!/usr/bin/env bash
# Start a real gateway and a test upstream, run the lifecycle scenarios, and
# leave a sealed acceptance result behind.
#
# The gateway is the SAME binary the validator installer already fetches and
# verifies against `.github/ferrum-edge-checksums.txt`. Reusing it rather than
# pinning a second artifact means the suite certifies the build this repository
# already trusts, and adds no new supply-chain surface.
#
# Everything is disposable: a temporary working directory, a loopback gateway,
# a generated admin secret that exists only for this process, and a seeded
# credential bundle written 0600 under that directory. Nothing here may point
# at a real environment -- see README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
RESULT="${LIFECYCLE_RESULT:-$ROOT/lifecycle-result.json}"
GATEWAY_LOG="$WORKDIR/gateway.log"
# shellcheck disable=SC2329  # invoked through the EXIT trap below
cleanup() {
  local status=$?
  [ -n "${GATEWAY_PID:-}" ] && kill "$GATEWAY_PID" 2>/dev/null || true
  [ -n "${UPSTREAM_PID:-}" ] && kill "$UPSTREAM_PID" 2>/dev/null || true
  if [ "$status" -ne 0 ] && [ -f "$GATEWAY_LOG" ]; then
    echo "--- gateway log (last 50 lines, redacted) ---" >&2
    # The admin secret is the one value certain to be in this process's
    # environment; strip it before any of this reaches a CI log.
    sed -e "s/${FERRUM_ADMIN_JWT_SECRET:-__none__}/[REDACTED]/g" \
        -e "s/${GITFORGEOPS_LIFECYCLE_CONSUMER_KEY:-__none__}/[REDACTED]/g" \
        "$GATEWAY_LOG" | tail -50 >&2
  fi
  rm -rf "$WORKDIR"
  exit "$status"
}
trap cleanup EXIT

command -v "${FERRUM_EDGE_BINARY_PATH:-ferrum-edge}" >/dev/null || {
  echo "::error::The gateway binary is not on PATH. Install it with" \
       ".github/scripts/install-ferrum-edge.sh, which verifies it against the" \
       "allowlisted digests." >&2
  exit 1
}

# Disposable credentials. Generated per run, never persisted, never reused.
FERRUM_ADMIN_JWT_SECRET="$(head -c 48 /dev/urandom | base64 | tr -d '\n=/+' | head -c 48)"
GITFORGEOPS_LIFECYCLE_CONSUMER_KEY="$(head -c 32 /dev/urandom | base64 | tr -d '\n=/+' | head -c 32)"
export FERRUM_ADMIN_JWT_SECRET GITFORGEOPS_LIFECYCLE_CONSUMER_KEY

# The broker bundle the seeded `alloc=require` slot resolves from. 0600, inside
# the throwaway workdir, removed with it.
CREDS="$WORKDIR/creds.json"
umask 077
printf '{"FERRUM_CREDS_BUNDLE":{"ferrum/orders-client/keyauth/key":"%s"}}' \
  "$GITFORGEOPS_LIFECYCLE_CONSUMER_KEY" > "$CREDS"
export FERRUM_CREDS_JSON_FILE="$CREDS"

python3 "$ROOT/tests/lifecycle/upstream.py" --port-file "$WORKDIR/upstream.port" &
UPSTREAM_PID=$!
for _ in $(seq 1 50); do [ -s "$WORKDIR/upstream.port" ] && break; sleep 0.1; done
UPSTREAM_PORT="$(cat "$WORKDIR/upstream.port")"
UPSTREAM_URL="http://127.0.0.1:${UPSTREAM_PORT}"

GATEWAY_PORT="${LIFECYCLE_GATEWAY_PORT:-18080}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"

# The gateway launch is the one integration point that depends on the
# companion's own CLI surface. It is a single variable so a Ferrum Edge change
# is a one-line edit here rather than a rewrite of the suite, and so an
# operator can point the suite at a gateway they started themselves.
GATEWAY_CMD="${LIFECYCLE_GATEWAY_CMD:-${FERRUM_EDGE_BINARY_PATH:-ferrum-edge} serve -m database}"
if [ -z "${LIFECYCLE_GATEWAY_EXTERNAL:-}" ]; then
  # shellcheck disable=SC2086  # the command is a deliberate word-split hook
  env FERRUM_ADMIN_JWT_SECRET="$FERRUM_ADMIN_JWT_SECRET" \
      FERRUM_ADMIN_PORT="$GATEWAY_PORT" \
      FERRUM_PROXY_PORT="$GATEWAY_PORT" \
      $GATEWAY_CMD > "$GATEWAY_LOG" 2>&1 &
  GATEWAY_PID=$!
fi

ready=
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "${GATEWAY_URL}/health" 2>/dev/null; then ready=1; break; fi
  sleep 0.5
done
[ -n "$ready" ] || {
  echo "::error::The gateway did not answer GET /health at ${GATEWAY_URL} within 30s." \
       "Set LIFECYCLE_GATEWAY_CMD for this Ferrum Edge build, or start a gateway" \
       "yourself and re-run with LIFECYCLE_GATEWAY_EXTERNAL=1." >&2
  exit 1
}

# An admin token for the scenarios' own out-of-band gateway edits -- the ones
# that simulate a human admin, which gitforgeops must not perform itself.
GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN="$(
  python3 "$ROOT/tests/lifecycle/admin_token.py" --secret "$FERRUM_ADMIN_JWT_SECRET"
)"
export GITFORGEOPS_LIFECYCLE_ADMIN_TOKEN

python3 "$ROOT/.github/scripts/lifecycle_result.py" init --result "$RESULT"

ONLY=()
[ -n "${LIFECYCLE_ONLY:-}" ] && ONLY=(--only "$LIFECYCLE_ONLY")

set +e
python3 "$ROOT/tests/lifecycle/scenarios.py" \
  --workdir "$WORKDIR/repo" \
  --result "$RESULT" \
  --gateway-url "$GATEWAY_URL" \
  --upstream-url "$UPSTREAM_URL" \
  --binary "${GITFORGEOPS_BINARY:-gitforgeops}" \
  "${ONLY[@]+"${ONLY[@]}"}"
SCENARIO_STATUS=$?
set -e

# Seal even on failure: an unsealed result reads as "the suite was cancelled",
# and a suite that ran and found problems is a different, louder thing.
python3 "$ROOT/.github/scripts/lifecycle_result.py" seal \
  --result "$RESULT" \
  --revision "${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}" \
  --gateway "$(sha256sum "$(command -v "${FERRUM_EDGE_BINARY_PATH:-ferrum-edge}")" | cut -d' ' -f1)"

exit "$SCENARIO_STATUS"
