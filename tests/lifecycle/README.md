# Lifecycle acceptance suite

The unit suite proves the code does what the code says. This proves the
*product* does what the README says: a real Ferrum Edge gateway, a real
upstream, the real `gitforgeops` binary, real HTTP traffic through the routes
it created.

Its sealed result is what [`release.yml`](../../.github/workflows/release.yml)
refuses to publish without.

---

## What it certifies

One scenario per acceptance promise. Every one must be `passed` before a
revision may be published; the ids are the contract, declared once in
[`.github/scripts/lifecycle_result.py`](../../.github/scripts/lifecycle_result.py)
and asserted against this file by the test suite.

| Scenario | Question it answers |
| --- | --- |
| `create-and-route` | Do an upstream, proxy, scoped plugin and consumer actually serve authenticated traffic? |
| `reapply-is-a-no-op` | Does applying the same desired state again change nothing — no normalization-induced false drift? |
| `modify-and-delete-in-order` | Do modify and delete succeed in dependency-safe order — including the large-prune guard refusing first, and `--allow-large-prune` carrying it through — and does an unmanaged row survive shared mode? |
| `credentials-generate-and-rotate` | Does a rotated credential authenticate, does the old one stop, and does no plaintext reach a log, a commit, a comment or an artifact? |
| `partial-failure-recovery` | Do the recovery safeguards preserve successful work and ownership across an injected partial failure and an ambiguous response? |
| `ledger-publication-failure` | When state publication is rejected after a gateway mutation and retries are exhausted, does a fresh runner recover ownership by the documented procedure — rather than treating a runner-local ledger as durable? |
| `runner-interruption` | After an interruption mid-mutation, does the documented reconciliation path work, with state-override authorization only where it is genuinely required? |
| `scheduling-and-attribution` | Queued and superseded applies, unrelated later merges, re-runs of an older workflow, PR-author credential delivery, policy-override attribution — including [#261](https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/issues/261)'s regression. |
| `staged-promotion` | Does an opted-in production environment stay blocked until staging applied *and* served traffic for the same revision — and does breaking staging's routing block it even though the gateway accepted the write? |
| `drift-monitoring` | Is drift distinguishable from a failed check and from a skipped one? |
| `file-and-mesh-boundary` | For the advertised file/mesh profile: assembly, encrypted materialization, delivery boundary — and that assembly is *not* reported as live fleet deployment. |

### `skipped` is not `passed`

Several scenarios need a disposable GitHub repository, which the suite cannot
create for itself. Those record `skipped` with the reason, and **a skipped
scenario never certifies anything** — the release gate refuses a result that
contains one exactly as it refuses a failure. Run them through
[the GitHub acceptance path](#the-github-repository-half) and record their
outcomes into the same result file before publishing.

---

## Running it

### Prerequisites

- `python3` (standard library only — no packages to install)
- nothing else: the config store is a SQLite file the run creates and deletes
- the `gitforgeops` binary on `PATH` (`cargo install --path . --locked`)
- the `ferrum-edge` binary on `PATH`, installed through
  [`install-ferrum-edge.sh`](../../.github/scripts/install-ferrum-edge.sh),
  which verifies it against the allowlisted SHA-256 digests

The suite deliberately reuses that same binary as the gateway rather than
pinning a second artifact: it certifies the build this repository has already
approved, and adds no new supply-chain surface.

### Commands

```bash
# Everything, sealed into ./lifecycle-result.json
bash tests/lifecycle/run.sh

# One scenario, while you are working on it
LIFECYCLE_ONLY=create-and-route bash tests/lifecycle/run.sh

# Against a gateway you started yourself
LIFECYCLE_GATEWAY_EXTERNAL=1 LIFECYCLE_ADMIN_PORT=9000 LIFECYCLE_PROXY_PORT=9001 \
  bash tests/lifecycle/run.sh

# Read the result the way the release gate does
python3 .github/scripts/lifecycle_result.py verify \
  --result lifecycle-result.json --revision "$(git rev-parse HEAD)"
```

| Variable | Purpose |
| --- | --- |
| `LIFECYCLE_RESULT` | where to seal the result (default `./lifecycle-result.json`) |
| `LIFECYCLE_ONLY` | run one scenario id |
| `LIFECYCLE_ADMIN_PORT` | admin API port (default `18080`) |
| `LIFECYCLE_PROXY_PORT` | data-plane port (default `18081`) — a separate listener |
| `LIFECYCLE_DB_TYPE` / `LIFECYCLE_DB_URL` | config store (default a SQLite file in the throwaway workdir) |
| `LIFECYCLE_GATEWAY_CMD` | how to start the gateway. Left unset, the runner reads the build's own `--help`, picks the first of `serve`/`server`/`run`/`start`/`gateway` it offers, and falls back to the bare binary (a gateway configured entirely through `FERRUM_*`) |
| `LIFECYCLE_GATEWAY_MODE` | `FERRUM_MODE` for the gateway (default `database`) |
| `LIFECYCLE_GATEWAY_EXTERNAL` | do not start a gateway; one is already listening |
| `GITFORGEOPS_BINARY` | the binary under test (default `gitforgeops` on `PATH`) |

If the gateway does not answer `GET /health` within 30 seconds the run **fails
loudly** with the command it used *and the subcommands that build actually
offers*. It does not fall back to skipping every
scenario: a suite that silently certifies nothing is worse than one that is
red.

### Cleanup

`run.sh` owns a single temporary directory and removes it on exit, including
on failure and on `Ctrl-C`. It holds the repository tree, the gateway log, the
credential bundle, and the upstream's port file. Both background processes are
killed by the same trap.

Nothing survives a run except the sealed result file, which contains no secret
— only scenario ids, statuses, one-line details, the revision, and the gateway
build's digest.

### Disposability is a requirement, not a convenience

Every credential the suite uses is generated for the process and destroyed
with it: the admin JWT signing secret, the consumer key, the broker bundle.
The gateway is loopback-only. **Do not point this suite at a real gateway or
supply a real environment's secrets** — several scenarios deliberately mutate
resources out of band and delete managed ones.

---

## Redacted failure evidence

A failing lifecycle run is the single most likely place for a live credential
to reach a log: the values are real, and the instinct on failure is to dump
everything. So redaction happens at the point of capture, not at the point of
printing.

- Every `gitforgeops` stdout/stderr the harness captures goes through
  `Harness.redact()`, keyed on the secrets *this run* created.
- Scenario failure details are redacted before they are written into the
  result file.
- `run.sh` strips the admin secret and the consumer key from the gateway log
  before printing its tail on failure.
- The test upstream never echoes a request header and never logs a request
  line.

When you need more than the redacted tail, re-run with
`LIFECYCLE_GATEWAY_EXTERNAL=1` against a gateway whose log you control, and
keep that log off CI.

---

## Injecting failures

`partial-failure-recovery` needs the admin API to misbehave on demand — a 500
after a commit, a connection dropped mid-response, a `X-Data-Source: cached`
header on `/backup`. Put a fault-injecting reverse proxy between the harness
and the gateway and point `LIFECYCLE_ADMIN_PORT` at it:

```bash
LIFECYCLE_GATEWAY_EXTERNAL=1 LIFECYCLE_ADMIN_PORT=18090 \
  bash tests/lifecycle/run.sh
```

The scenario asserts the *safeguards*, not the fault: that successful work is
preserved, that ownership is recorded for what actually committed, and that an
ambiguous outcome stops the run rather than being retried blindly.

---

## The GitHub-repository half

Six scenarios are about GitHub's own controls — environment approvals,
state-writer App permissions, protected-branch ledger writes, scheduling and
attribution. They cannot run inside this repository's CI, which has no
authority to create repositories, environments or Apps. They run against a
**disposable repository** you create, and their outcomes are recorded into the
same result file.

See [`github_acceptance.md`](github_acceptance.md) for the procedure. In
short:

```bash
# 1. Create a disposable repository from the template, then:
export GH_TOKEN=$(gh auth token)
python3 .github/scripts/bootstrap_repo_settings.py \
  --repo <you>/gitforgeops-acceptance --state-writer-app-id <id> \
  --reviewer <second-maintainer> --apply

# 2. Work through github_acceptance.md, then record each outcome:
python3 .github/scripts/lifecycle_result.py record \
  --result lifecycle-result.json \
  --scenario scheduling-and-attribution --status passed \
  --detail "run 123456: docs-only merge did not strand the queued apply"

# 3. Re-seal, so the record certifies the revision you actually tested.
python3 .github/scripts/lifecycle_result.py seal \
  --result lifecycle-result.json \
  --revision "$(git rev-parse HEAD)" --gateway "<gateway digest>"
```

Delete the repository, its environments and its App installation when you are
done. Nothing in it is meant to outlive the run.

---

## Adding a scenario

Adding a fail-closed gate to `apply` without adding a scenario here narrows
what the suite certifies without narrowing what ships. So:

1. Add the id and its description to `REQUIRED_SCENARIOS` in
   `.github/scripts/lifecycle_result.py`.
2. Implement it in `scenarios.py` and register it in `SCENARIOS`.
3. Add a row to the table at the top of this file.

`test_lifecycle_result.py` asserts all three stay in step, so a half-added
scenario fails the build rather than silently certifying nothing.
