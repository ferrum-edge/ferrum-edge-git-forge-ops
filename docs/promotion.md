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
version: 2

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
| `headers` | none | Each value is exactly one of `literal:` or `slot:` (a [probe credential](#probe-credentials) slot). `Host`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `Via`, the method overrides (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`) and hop-by-hop or framing headers are refused, case-insensitively. |
| `expect_status` | required | Status the check must see. |
| `timeout_secs` | `10` | Per attempt, 1 to 60. |
| `attempts` | `3` | Including the first, 1 to 10. |
| `retry_backoff_ms` | `500` | Base delay, at most 30000. The pause before attempt `n + 1` is `n` times it. |
| `replay_safe` | `false` | Allow retrying a non-idempotent method after a possible delivery. |

`version: 2` is the current contract. A `version: 1` file, or one with no
`version`, still loads when no check sends a `slot:`; one that names a slot is
refused, because under version 1 a slot could name any credential in the
bundle. Review every slot against [Probe credentials](#probe-credentials),
then declare `version: 2`.

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
may send only a credential that the operator set aside for verification. A
`slot:` header is honoured only when all of these hold; otherwise `verify`
exits 1 before the bundle is read or any request is sent:

- The slot is a Consumer credential secret slot,
  `<namespace>/<consumer-id>/<credential-type>/<field>`, with a built-in
  credential type. Plugin-config (`@plugin/<plugin_name>`) and service-discovery
  (`@service-discovery`) slots, identity fields (`basicauth` `username`,
  `mtls_auth` `identity`) and unknown types are refused at load.
- The check's method is `GET` or `HEAD`, so a probe credential is never spent
  on a side effect. Also refused at load.
- **The operator lists the Consumer** in the `FERRUM_VERIFY_PROBE_CONSUMERS`
  variable of the environment's GitHub Environment, as
  `<namespace>/<consumer-id>`. This is the authorization. A GitHub Environment
  variable can be changed only by a repository administrator, never by a
  merge. Unset or empty, every check that sends a slot is refused; a
  malformed entry is an error.
- The Consumer is in the environment's desired configuration (after overlays
  and namespace scope) and carries the label `gitforgeops/verify-probe: "true"`.
  The label is required too, but it lives in `resources/`, which the pull
  request that names the slot could also change, so it authorizes nothing by
  itself.
- The slot is one of that Consumer's brokered (`${gh-env-secret:...}`) secret
  leaves, in canonical spelling.

`verify` hands the runner only those values, never the bundle.

The same binding is checked before anything changes. `validate`, `plan` and
`apply` refuse a slot whose Consumer is missing, unlabelled or (when the run
can see `FERRUM_VERIFY_PROBE_CONSUMERS`) not listed. `review` reports it as the
`invalid-smoke-checks` blocker and lists, by name only, each check's header,
slot and the Consumer it would spend, plus every Consumer carrying the label,
so a pull request that adds a label or a slot is visible. A run narrowed by
`FERRUM_NAMESPACE` does not judge slots in other namespaces. The bundled
workflows bind the variable into both `Validate` steps (before Apply) and both
`Verify traffic` steps of `apply-on-merge.yml`, and into the trusted live
review.

#### Operator setup

1. Create a dedicated, low-privilege Consumer that exists to be probed, never
   a customer, with a brokered credential and the label:

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

2. A repository administrator adds the variable to each GitHub Environment
   whose checks send a slot (**Settings → Environments → _env_ → Environment
   variables**, or
   `gh variable set FERRUM_VERIFY_PROBE_CONSUMERS --env <env> --body ferrum/orders-probe`).
   List several probes comma-separated. Use an Environment variable, not a
   repository variable or a secret: it is per environment and is the value
   the workflows bind.
3. Name the probe's slot in `.gitforgeops/smoke.yaml` (`version: 2`) on a
   `GET` or `HEAD` check.

Removing a Consumer from the variable revokes it at the next `verify`; no
merge is needed. Never list a customer Consumer.

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
| `1` | could not run (bad `smoke.yaml`, no `FERRUM_VERIFY_BASE_URL`, unreadable bundle, `FERRUM_VERIFY_PROBE_CONSUMERS` unset or malformed while a check sends a slot, a slot that is not a probe credential) | `failure` | **failed** |

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
