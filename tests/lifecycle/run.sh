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

# The admin API and the data plane are SEPARATE listeners on separate ports.
# Conflating them would make the traffic scenarios send their requests at the
# admin API, which answers 404 for `/orders` and would look exactly like a
# routing failure.
ADMIN_PORT="${LIFECYCLE_ADMIN_PORT:-18080}"
PROXY_PORT="${LIFECYCLE_PROXY_PORT:-18081}"
GATEWAY_URL="http://127.0.0.1:${ADMIN_PORT}"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

# A SQLite file inside the throwaway workdir: `database` mode needs a config
# store, and this is the only one that needs no service to be running. It goes
# with the workdir when the trap fires.
#
# `?mode=rwc` is load-bearing. sqlx opens a SQLite URL read-write but will not
# CREATE a missing file without it, and the failure — "unable to open database
# file" — reads like a permissions problem rather than a missing flag.
export FERRUM_DB_TYPE="${LIFECYCLE_DB_TYPE:-sqlite}"
export FERRUM_DB_URL="${LIFECYCLE_DB_URL:-sqlite://$WORKDIR/ferrum.db?mode=rwc}"

# The gateway launch is the one integration point that depends on the
# companion's own CLI surface, so it is DISCOVERED rather than guessed. A
# hard-coded subcommand is wrong exactly once — the moment Ferrum Edge renames
# or removes it — and the failure it produces ("unrecognized subcommand") tells
# the reader nothing about what to use instead.
#
# `LIFECYCLE_GATEWAY_CMD` still overrides everything, for an operator who knows
# better than this heuristic or is testing a build with a different surface.
BINARY="${FERRUM_EDGE_BINARY_PATH:-ferrum-edge}"
GATEWAY_CMD="${LIFECYCLE_GATEWAY_CMD:-}"
AVAILABLE=""
if [ -z "$GATEWAY_CMD" ]; then
  # clap prints `Commands:` followed by indented `<name>  <about>` lines, and
  # stops at the next unindented section. Anything unparseable leaves
  # AVAILABLE empty, and the bare invocation below is then tried on its own.
  AVAILABLE=$("$BINARY" --help 2>&1 | awk '
    /^Commands:/ {inside = 1; next}
    inside && /^[^ ]/ {inside = 0}
    inside && /^[[:space:]]+[a-z][a-z0-9-]*/ {print $1}
  ' | tr '\n' ' ')
  for candidate in serve server run start gateway; do
    case " $AVAILABLE " in
      *" $candidate "*) GATEWAY_CMD="$BINARY $candidate"; break ;;
    esac
  done
  # No serving subcommand: the gateway is configured entirely through FERRUM_*
  # and started by the bare binary. That is the shape `-m file` / `-m mesh`
  # validation implies, so it is the fallback rather than an error.
  [ -n "$GATEWAY_CMD" ] || GATEWAY_CMD="$BINARY"
fi

if [ -z "${LIFECYCLE_GATEWAY_EXTERNAL:-}" ]; then
  echo "Starting the gateway with: $GATEWAY_CMD"
  # shellcheck disable=SC2086  # the command is a deliberate word-split hook
  env FERRUM_ADMIN_JWT_SECRET="$FERRUM_ADMIN_JWT_SECRET" \
      FERRUM_MODE="${LIFECYCLE_GATEWAY_MODE:-database}" \
      FERRUM_DB_TYPE="$FERRUM_DB_TYPE" \
      FERRUM_DB_URL="$FERRUM_DB_URL" \
      FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
      FERRUM_ADMIN_HTTP_PORT="$ADMIN_PORT" \
      FERRUM_PROXY_BIND_ADDRESS=127.0.0.1 \
      FERRUM_PROXY_HTTP_PORT="$PROXY_PORT" \
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
       "Tried: ${GATEWAY_CMD}." \
       "${AVAILABLE:+Subcommands this build offers: ${AVAILABLE}.}" \
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
  --proxy-url "$PROXY_URL" \
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
