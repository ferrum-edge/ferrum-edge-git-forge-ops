# Lifecycle acceptance suite

The unit suite checks that the code does what the code says. This suite checks
that the *product* does what the README says, with a real Ferrum Edge gateway,
a real upstream, the real `gitforgeops` binary and real HTTP traffic through
the routes it creates.

[`release.yml`](../../.github/workflows/release.yml) refuses to publish without
its sealed result.

---

## What it certifies

One scenario per acceptance promise. Every one must be `passed` before a
revision can be published. The ids are declared once, in
[`.github/scripts/lifecycle_result.py`](../../.github/scripts/lifecycle_result.py),
and a test checks that this file lists each of them.

The harness (`run.sh`) runs six scenarios itself: `create-and-route`,
`reapply-is-a-no-op`, `modify-and-delete-in-order`, `conditional-overwrite`,
`drift-monitoring` and `file-and-mesh-boundary`. The other six always record
`skipped` and are exercised by hand (see below).

| Scenario | Question it answers |
| --- | --- |
| `create-and-route` | Do an upstream, proxy, scoped plugin and consumer actually serve authenticated traffic? |
| `reapply-is-a-no-op` | Does applying the same desired state again change nothing — no normalization-induced false drift? |
| `modify-and-delete-in-order` | Do modify and delete succeed in dependency-safe order — including the large-prune guard refusing first, and `--allow-large-prune` carrying it through — and does an unmanaged row survive shared mode? |
| `conditional-overwrite` | Does the gateway issue a strong `ETag` for every kind incremental apply overwrites and refuse a write carrying a superseded one with `412` — and does an apply over an out-of-band edit re-plan and converge through its `If-Match` writes, consumers (redacted read, credentials from `/backup`) included? |
| `credentials-generate-and-rotate` | Does a rotated credential authenticate, does the old one stop, and does no plaintext reach a log, a commit, a comment or an artifact? |
| `partial-failure-recovery` | Do the recovery safeguards preserve successful work and ownership across an injected partial failure and an ambiguous response? |
| `ledger-publication-failure` | When state publication is rejected after a gateway mutation and retries are exhausted, does a fresh runner recover ownership by the documented procedure — rather than treating a runner-local ledger as durable? |
| `runner-interruption` | After an interruption mid-mutation, does the documented reconciliation path work, with state-override authorization only where it is genuinely required? |
| `scheduling-and-attribution` | Queued and superseded applies, unrelated later merges (a queued apply must survive one), re-runs of an older workflow, PR-author credential delivery, policy-override attribution. |
| `staged-promotion` | Does an opted-in production environment stay blocked until staging applied *and* served traffic for the same revision — and does breaking staging's routing block it even though the gateway accepted the write? |
| `drift-monitoring` | Is drift distinguishable from a failed check and from a skipped one? |
| `file-and-mesh-boundary` | For the advertised file/mesh profile: assembly that preserves placeholders, a separate mesh document, and 0600 materialization that never touches the committed artifact — and that assembly is *not* reported as live fleet deployment. Encrypted delivery to a GitHub key is `credentials-generate-and-rotate`'s. |

### `skipped` is not `passed`

Five scenarios need a disposable GitHub repository, which the suite cannot
create, and `partial-failure-recovery` needs a fault-injecting proxy. The
harness records all six as `skipped` with the reason. **A skipped scenario
never certifies anything**: the release gate refuses it exactly as it refuses a
failure. Exercise them by hand ([GitHub half](#the-github-repository-half),
[injecting failures](#injecting-failures)) and submit the outcomes as an
attestation to a dispatched acceptance run for the release revision.

---

## Running it

### Prerequisites

- `python3` (standard library only)
- the `gitforgeops` binary on `PATH` (`cargo install --path . --locked`)
- the `ferrum-edge` binary on `PATH`, installed with
  [`install-ferrum-edge.sh`](../../.github/scripts/install-ferrum-edge.sh),
  which checks it against the allowlisted SHA-256 digests

No database is needed: the config store is a SQLite file the run creates and
deletes. The suite uses the approved validator binary as the gateway too, so it
certifies the build this repository already trusts and adds no second
artifact to pin.

The released Ferrum Edge v0.9.6 source contains strong `ETag` and `If-Match`
handling ([source](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.6/src/admin/preconditions.rs),
[PR 5661](https://github.com/ferrum-edge/ferrum-edge/pull/5661)). That source
does not establish an earliest or minimum version, or prove that a particular
released binary contains or enforces the capability. The
`conditional-overwrite` scenario must pass against the exact released build to
qualify it, including the CLI's namespace and credential checks. This
qualification also covers the gateway's backup and consumer representations;
pending representation fixes are not assumed released.

The Python harness checks its admin and data-plane URLs before use and sends
credentials only over HTTPS or HTTP to literal loopback IPs (`127.0.0.0/8`,
`::1`). It refuses every redirect and ignores environment proxies for plaintext
loopback requests. Both out-of-band admin helpers and traffic probes share
this boundary. HTTP hostnames, including `localhost`, are refused, matching
the CLI's admin transport policy. The external-gateway mode above still uses
`127.0.0.1` and disposable credentials.

### Commands

Scenarios run in sequence and change shared state (one deletes the proxy), so
each deploys what it needs first. That is why any scenario can run alone with
`LIFECYCLE_ONLY`.

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

If the gateway does not answer `GET /health` within 30 seconds, the run **fails**
and prints the command it used and the subcommands that build offers. It never
falls back to skipping every scenario; a suite that silently certifies nothing
is worse than a red one.

### Cleanup

`run.sh` owns one temporary directory and removes it on exit, including on
failure and `Ctrl-C`. It holds the repository tree, the gateway log, the
credential bundle and the upstream's port file. The same trap stops both
background processes (gateway and upstream).

Only the sealed result file survives a run. It holds no secret: scenario ids,
statuses, one-line details, the revision and the gateway build's digest.

### Disposability is a requirement, not a convenience

Every credential the suite uses (admin JWT signing secret, consumer key, broker
bundle) is generated for the run and destroyed with it. The gateway listens on
loopback only. **Do not point this suite at a real gateway or give it a real
environment's secrets**: several scenarios change resources out of band and
delete managed ones.

---

## Redacted failure evidence

A failing lifecycle run is the most likely place for a live credential to reach
a log: the values are real, and the instinct on failure is to dump everything.
So redaction happens when output is captured, not when it is printed.

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

`partial-failure-recovery` needs the admin API to misbehave on demand: a 500
after a commit, a connection dropped mid-response, an `X-Data-Source: cached`
header on `/backup`. No fault injector ships with this repository, and the
harness does not drive this scenario; it always records `skipped`.

To exercise it, put your own fault-injecting reverse proxy between
`gitforgeops` and a disposable gateway, and run `gitforgeops apply` through it
by hand. Check the *safeguards*, not the fault: successful work is preserved,
ownership is recorded for what actually committed, and an ambiguous outcome
stops the run instead of being retried blindly. Record the outcome with
`lifecycle_result.py record`, as for the GitHub scenarios below.

---

## The GitHub-repository half

Five scenarios test GitHub's own controls: environment approvals, state-writer
App permissions, protected-branch ledger writes, scheduling and attribution.
This repository's CI cannot run them, because it has no authority to create
repositories, environments or Apps. You run them against a **disposable
repository** and record the outcomes in the same result file.

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

# 3. Re-seal, so the record certifies the upstream revision you tested.
python3 .github/scripts/lifecycle_result.py seal \
  --result lifecycle-result.json \
  --revision <upstream commit> --gateway "<gateway digest>"

# 4. Hand it to the release gate: dispatch the acceptance workflow on the
#    release ref with the sealed file as its input, then re-run Release.
gh workflow run lifecycle.yml --ref <release tag or main> \
  -f github_acceptance="$(cat lifecycle-result.json)"
```

The dispatched run merges your outcomes into **only** the scenarios it recorded
as `skipped`, attributed to you. It refuses an attestation sealed for another
revision, for a different gateway build than the one it installs, or more than
72 hours before it runs, and it never overwrites a scenario it ran itself.

Delete the repository, its environments and its App installation when you are
done.

---

## Adding a scenario

A new fail-closed gate in `apply` without a matching scenario here is a
behavior that ships uncertified. When adding one:

1. Add the id and its description to `REQUIRED_SCENARIOS` in
   `.github/scripts/lifecycle_result.py`.
2. Implement it in `scenarios.py` and register it in `SCENARIOS`.
3. Add a row to the table at the top of this file.

`test_lifecycle_result.py` checks that all three agree, so a half-added
scenario fails the build.
