# Staged promotion and traffic checks

By default every declared environment deploys as an independent job in the
`apply` matrix: same merge, in parallel, each with its own approval.
**Parallel is not staged.** Production does not wait for staging.

## Declaring a promotion

```yaml
# .gitforgeops/config.yaml
environments:
  staging: {}
  production:
    promotion:
      requires: staging
```

`production` then leaves the parallel matrix and runs in the `promote` job,
which starts only after the whole independent phase succeeded. It proceeds only
if `staging` **applied** and **passed its traffic checks** for the same source
revision.

Promotion is one stage deep. Several environments may require the same
predecessor, but a predecessor may not itself require another environment;
that is refused when the config loads.

Staging's approval grants nothing in production, which still needs its own
reviewer.

## The promotion record

Job ordering proves that jobs ran in sequence, not what the gateway serves.
So each environment's apply writes a promotion record (environment, source
revision, apply result, traffic result, and the run, actor and PR), and the
promoting job refuses unless its predecessor's record:

- exists (a missing record means never started, cancelled or lost);
- shows a successful apply;
- shows successful traffic verification;
- names the revision about to be applied, or an ancestor of it that differs
  only outside the
  [deployment inputs](../README.md#deployment-inputs-one-list-for-scheduling-and-for-supersession).

The ancestor rule is needed because staging's own ledger commit moves `main`
before production runs. A ledger, documentation or test commit in between is
the same deployment; a resource, policy, engine or workflow change is not. If
`main` moves a deployment input while production waits, the
[freshness guard](apply.md#ordering-between-runs) refuses the run and the
newer merge runs its own staging-to-production cycle. The ledger is always read
fresh from the current head.

## Traffic checks

A successful apply proves the gateway accepted a write, not that a route
answers or that authentication is enforced. `gitforgeops verify` runs checks
declared in `.gitforgeops/smoke.yaml` (see
[`smoke.example.yaml`](../.gitforgeops/smoke.example.yaml)):

```yaml
version: 1

environments:
  staging:
    checks:
      - name: orders route serves authenticated traffic
        method: GET
        path: /orders/healthz
        headers:
          X-API-Key:
            slot: ferrum/orders-probe/keyauth/key
        expect_status: 200
        attempts: 5
        timeout_secs: 10

      - name: orders route rejects an unauthenticated request
        path: /orders/healthz
        expect_status: 401
```

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Label in results. |
| `method` | `GET` | HTTP method. |
| `path` | required | Must start with `/`. |
| `headers` | none | Each value is exactly one of `literal:` or `slot:` (a [probe credential](#probe-credentials) slot). `Host`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `Via` and hop-by-hop or framing headers are refused. |
| `expect_status` | required | Status the check must see. |
| `timeout_secs` | `10` | Per attempt, 1 to 60. |
| `attempts` | `3` | Including the first, 1 to 10. |
| `retry_backoff_ms` | `500` | Base delay, at most 30000. The pause before attempt `n + 1` is `n` times it. |
| `replay_safe` | `false` | Allow retrying a non-idempotent method after a possible delivery. |

There are no hooks or shell commands: the job holds deployment credentials,
and the closed schema is the whole execution surface. An unknown key such as
`run:` is a load error. `validate`, `plan` and `apply` load the file too, so a
malformed check refuses the apply up front; `review` reports it as the
`invalid-smoke-checks` blocker. No `smoke.yaml` at all is fine; a present one
must be a plain file (symlinks, non-regular files and files over 1 MiB are
refused before parsing).

### Budgets

Verification runs after the gateway changed and before the ownership ledger is
committed, while the environment's deployment concurrency group is held, so
every check is bounded and so is the set:

- `attempts` at most 10, `timeout_secs` at most 60, `retry_backoff_ms` at most
  30000;
- at most 50 checks per environment;
- at most 15 minutes for an environment's checks together, counting every
  attempt timing out plus every backoff pause
  (`attempts × timeout_secs + retry_backoff_ms × attempts × (attempts − 1) / 2`,
  summed over the checks).

A file over any bound is refused at load, so `validate`, `plan` and `apply`
refuse it before anything changes. `verify` also holds the run to an outer
deadline of that worst case plus 30 seconds; a check the deadline interrupts,
or never starts, is reported as `TIMEOUT` and fails verification. Both
`Verify traffic` steps in `apply-on-merge.yml` carry a step-level
`timeout-minutes: 20` as a backstop. It is a step timeout on purpose: the step
fails, `continue-on-error` records it, and the ledger commit still runs. A job
timeout would cancel the job and skip that commit.

### Probe credentials

The verify step holds the environment's whole credential bundle, so a check
may send only a credential that was set aside for verification. A `slot:`
header is honoured only when all of these hold; otherwise `verify` exits 1
before any request is sent:

- The slot is a Consumer credential secret slot,
  `<namespace>/<consumer-id>/<credential-type>/<field>`, with a built-in
  credential type. Plugin-config (`@plugin-config`) and service-discovery
  (`@service-discovery`) slots, identity fields (`basicauth` `username`,
  `mtls_auth` `identity`) and unknown types are refused at load.
- The check's method is `GET` or `HEAD`, so a probe credential is never spent
  on a side effect. Also refused at load.
- The Consumer is in the environment's desired configuration (after overlays
  and namespace scope) and carries the label `gitforgeops/verify-probe: "true"`.
- The slot is one of that Consumer's brokered (`${gh-env-secret:...}`) secret
  leaves, in canonical spelling.

`verify` hands the runner only those values, never the bundle. Give the label
to a dedicated, low-privilege Consumer that exists to be probed, never to a
customer:

```yaml
kind: Consumer
spec:
  id: "orders-probe"
  username: "orders-probe"
  labels:
    gitforgeops/verify-probe: "true"
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=generate}"
```

### How checks run

- **Target.** Requests go to `FERRUM_VERIFY_BASE_URL`, the gateway's data
  plane (not the Admin API), under the same
  [transport rules](reference.md#transport-security). TLS is always verified;
  `FERRUM_TLS_NO_VERIFY` does not apply. A private CA in
  `FERRUM_GATEWAY_CA_CERT` is honored.
- **No redirects.** A `3xx` is compared with `expect_status`, never followed.
- **Slots.** Only [probe credentials](#probe-credentials) resolve. An
  authorized `slot:` missing from the bundle fails the check instead of
  sending an empty header. Slots resolve against the bundle the apply finished
  with: the apply writes it to `FERRUM_CREDS_JSON_OUTPUT_FILE` (mode 0600,
  under `$RUNNER_TEMP`), so a credential generated by the same run can be
  checked. If that file is missing, verification fails.
- **Retries.** `attempts` are spent freely on `GET`, `HEAD`, `OPTIONS`,
  `TRACE`, `PUT` and `DELETE`. For other methods only a connection that was
  never established is retried, unless `replay_safe: true`. Prefer `GET` or
  `HEAD` probes.
- **Output.** Results show name, method, path, expected and actual status.
  Header values are never printed and response bodies are never read.

## Results

| `verify` exit | Result | Recorded as | Deployment job |
|---|---|---|---|
| `0` | every check passed | `success` | green |
| `4` | a check ran and failed | `failure` | **failed** |
| `5` | no checks declared for the environment | `skipped` | green |
| `1` | could not run (bad `smoke.yaml`, no `FERRUM_VERIFY_BASE_URL`, unreadable bundle, a slot that is not a probe credential) | `failure` | **failed** |

`--format json` reports `"status": "passed" | "failed" | "skipped"`.

A failed verification fails the deployment job after the promotion record and
the ledger are committed. Because `promote` needs the whole independent phase
to succeed, a failed check in any independent environment also stops every
promotion. Nothing is rolled back; the environment stays as applied so you can
inspect it. A file-mode environment, or a repository without `smoke.yaml`,
skips verification and stays green, recorded as `skipped` (or `not_run` with
no `smoke.yaml`), which never authorizes a promotion.

What blocks a promotion:

| Predecessor state | Result |
|---|---|
| apply failed | blocked |
| a declared check failed, timed out or could not connect | blocked |
| job cancelled, or no record | blocked |
| no checks declared, or file mode | blocked (`skipped` authorizes nothing) |
| `main` changed a deployment input meanwhile | blocked; the newer merge promotes its own revision |

Every outcome is written to the run's job summary.
