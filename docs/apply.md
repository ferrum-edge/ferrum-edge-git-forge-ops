# Apply behavior

How `gitforgeops apply` talks to a gateway's Admin API: strategies, retries,
write ordering, run ordering, timeouts and scale. For recovering a failed or
superseded run, see the
[README](../README.md#what-if-apply-fails-after-merge).

## Strategies and namespaces

Apply works one namespace at a time (`apply_api` over
`split_config_by_namespace`). A failure in `team-alpha` does not stop
`team-beta`; results are reported per namespace in `ApplyResult`.

- **`incremental`** (default) reads `/backup` once per namespace, diffs
  locally, and sends one `POST`/`PUT`/`DELETE` per changed resource. At about
  100 ms per call, 1,000 changes take about two minutes. A namespace whose diff
  is only adds uses `POST /batch` instead. A namespace that overwrites existing
  rows reads `/backup` once more before its first overwrite; see
  [Changes made during an apply](#changes-made-during-an-apply).
- **`full_replace`** (exclusive mode only) builds and validates every
  namespace payload first, then calls `POST /restore?confirm=true` once per
  namespace. Deterministic errors in any namespace mean no restore is sent.
  Each restore is atomic for its namespace, but **not across namespaces**: a
  runtime failure on `beta` after `alpha` succeeded leaves `alpha` replaced.
  Scope `full_replace` to one namespace if you need environment-wide
  atomicity. Namespaces that completed keep their ledger results.

Set the strategy per environment with `apply_strategy` in
`.gitforgeops/config.yaml`, or with `FERRUM_APPLY_STRATEGY` when no
environment is selected.

## Retries

Every Admin API call retries up to `FERRUM_GATEWAY_MAX_RETRIES` times
(default 3; `0` disables). The response body is read first, because the
gateway's error body can override the status code.

Retried:

- connection-establishment errors (no response was received);
- HTTP 408, 429 and 5xx (except 501) on reads and idempotent `PUT`/`DELETE`;
- `/restore` 503 with `failure_class: connectivity` (nothing was written).

Never retried:

- **501** — for example a standalone-MongoDB gateway without transactions.
  `POST /batch` then falls back to per-resource creates.
- **Any error from a create or batch `POST`.** The write may have committed.
  GitForgeOps re-reads an authoritative backup instead:
  - the exact resource (or complete batch) is live → an idempotent `PUT`
    records repository ownership, then the create counts;
  - nothing under that id → the create did not commit; it is an ordinary
    failure and the run continues;
  - a different row, or no usable backup → the run stops for reconciliation.
- **`applied: false`** in the body → `CommittedNotLive` (reason
  `config_rejected`, `reload_timeout` or `sequence_unavailable`). The write is
  stored but not live; check gateway health instead of re-sending.
- **`/restore` failures** other than the connectivity case. A 500 with
  `rollback: incomplete` or `unknown_outcome` is `RestoreNeedsManualRecovery`.
- **Request timeouts.** The outcome is unknown; the next run re-diffs.
- **Other 4xx** (400, 401, 403, 404, 409, 422).
- **3xx.** Redirects are never followed. The error names the `Location`; point
  `FERRUM_GATEWAY_URL` at the final origin.

Backoff is full-jitter, up to `500ms · 2^(attempt-1)` and capped at 8 s. A
`Retry-After` (delta-seconds) is honored, capped at 30 s.

## Errors with their own meaning

- **`GatewayReadOnly`.** An authenticated `GET /health` preflight runs before
  the first write. A gateway with `admin_writes_enabled: false`, or in `file`,
  `dp`, `mesh` or `node_agent` mode, fails the run once instead of producing a
  403 per resource. An unreachable `/health` only prints a warning.
- **`ApiSpecsAtRisk`** (409 with `api_specs_at_risk`) points at
  `--confirm-api-spec-deletion`. See
  [Spec-owned resources](ownership.md#spec-owned-resources).
- **413** on `/restore` names the gateway's
  `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` and suggests incremental mode.
- **`StaleGatewayView`.** A `/backup` answered with `X-Data-Source: cached`
  is the gateway's in-memory fallback, which lacks API-spec documents and
  ownership tags. Every api-mode mutation is refused before allocation or any
  write, and `--allow-large-prune` does not bypass it.
- **Namespace-scoped backups** must carry an explicit, matching `namespace` on
  every row, and must not contain duplicate `(namespace, id)` rows within a
  kind. Otherwise the snapshot is rejected before diffing: `diff`, `plan` and
  `apply` fail, `review` withholds its comparison, and `import` refuses.
- **Count seals.** A backup whose `counts` / `resource_counts` disagree with
  its contents is a warning for read-only commands and refuses the namespace
  for `apply` and `import`.
- **404 on DELETE** counts as success; the gateway cascades some deletes
  itself.
- **Namespace discovery** stops with an error after 100,000 rows without a
  complete listing, rather than returning a truncated list.

Incremental errors are collected per resource: 99 successes and 1 failure
report exactly that, and the CLI exits non-zero. Read-only refusals, stale
views, unsupported backup sections and restore rollback damage stop the whole
run.

## Apply ordering and the batch fast path

Incremental apply orders the diff by dependency, because the gateway enforces
referential integrity:

| Rank | Operations |
|---|---|
| 0 | Add/Modify Upstream, Add/Modify Consumer |
| 1 | Add/Modify PluginConfig |
| 2 | Add/Modify Proxy (including new proxy + scoped-plugin create batches) |
| 3 | Delete Proxy |
| 4 | Delete PluginConfig |
| 5 | Delete Upstream, Delete Consumer |

Deletes come last: an upstream cannot be deleted while a proxy references it,
so the proxy change must land first.

- **Failed writes defer deletes.** If any add or modify in a namespace fails,
  every planned delete in that namespace is deferred for this run and reported
  separately. Deferred deletes keep their ledger entries. `plan` and `diff`
  describe deletes as conditional for this reason.
- **Renames are not atomic.** Moving a routing key (for example a
  `listen_path`) to a new proxy id conflicts with the incumbent on every retry.
  Modify the existing id, or stage the replacement on a different routing key
  first.
- **Proxy deletes send `cleanup_orphaned_upstream=false`**, so the gateway
  never deletes an upstream behind the repository's back.
- **Plugin retention.** Proxies are deleted before plugins, and plugins
  referenced by a proxy whose delete failed are kept.

When a namespace's diff is **only adds**, apply uses `POST /batch`: one
transaction per chunk, chunked under the gateway's 1 MiB body limit. A new
proxy and its new scoped plugins always go in the same chunk. A batch counts as
applied only for HTTP 200/201 with a complete `created` object whose
`proxies`, `consumers`, `plugin_configs` and `upstreams` counts match the
chunk. Anything else (including 207) is ambiguous and is resolved by the
readback described under [Retries](#retries), never by replaying the batch.

A 501 or a definitive rejection (400/409/413/422) allows falling back to
independent creates, except for a new proxy with new scoped plugins: that pair
must be created together, so an unsupported or oversized cycle is reported
rather than publishing an unprotected proxy. On gateways that answer 501 or
413, `apply --allow-nontransactional-plugin-attach` (or
`GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH=true`) permits creating the
proxy first and its plugins second. The proxy is then **briefly published
without its scoped plugin**, including any authentication it provides. If
attachment fails, the proxy stays unprotected, apply exits non-zero and defers
pruning; repair it immediately.

Retargeting an existing plugin to a brand-new proxy cannot use a create-only
batch; the gateway rejects that plugin update, so apply withholds the proxy
create and defers pruning. Create the proxy in an earlier apply, or use
exclusive `full_replace`.

## Changes made during an apply

`apply` plans each namespace from the `/backup` it reads before allocating and
delivering credentials, so another writer can change the gateway before the
writes go out. Before a namespace's first write that overwrites an existing row
(a modify, a delete, or a pending-create ownership assertion), incremental
apply reads `/backup` again and compares every row it is about to overwrite
with the row it planned against:

- **Ownership moved.** A row that gained, lost or changed its `api_spec_id` is
  not written: an `/api-specs` import claimed it after the plan. See
  [Spec-owned resources](ownership.md#spec-owned-resources).
- **Content changed.** A row that differs in anything but server timestamps is
  not written, so someone else's edit is not reverted.
- **Row gone.** The write goes out and the gateway answers for itself: a
  `DELETE` gets a tolerated 404, a `PUT` fails.

Each refusal is a per-resource error naming the row, so the run exits non-zero,
and a refused modify defers the namespace's deletes like any failed write.
Re-run apply to plan against the current gateway. A cached confirmation stops
the run; a failed confirmation read refuses every overwrite in the namespace.

Creates need no confirmation, because `POST` and `POST /batch` are create-only.
A proxy update that follows this run's scoped-plugin writes is checked against
the post-plugin backup instead, ignoring the associations the gateway rewrote
itself. After an ambiguous create, a readback row that carries an
`api_spec_id` is never claimed, even when its content matches.

The confirmation narrows the race to one read-to-write interval per namespace.
It cannot close it: `/backup` carries no per-row revision that a `PUT` or
`DELETE` could be made conditional on.

## Ordering between runs

Applies to one environment are serialized by the `ferrum-apply-<env>`
concurrency group, which `rotate.yml` shares. A queued run still checked out
its triggering commit, so after taking the lock `apply-on-merge.yml` and
`rotate.yml` fetch the protected branch, move onto its **current** head, and
print both:

```
Triggering commit: 4f2c...
Protected main HEAD: 9ab1...
```

The binary, the desired resources and `.state/<env>.json` all come from that
head. So a merge queued behind another reads the ledger the earlier apply
published. Before building anything, the run is refused if:

- the triggering commit is no longer an ancestor of the head
  (`Stale deployment`), or
- the head changed a [deployment input](../README.md#deployment-inputs-one-list-for-scheduling-and-for-supersession)
  since the triggering commit (`Superseded deployment`).

Policy-override lookup and credential delivery stay tied to the triggering
merge's PR; the supersession check guarantees no later PR's input is applied
under that attribution. The classifier is taken from the triggering commit and
piped into an isolated interpreter
(`git show "${TRIGGER_SHA}:..." | python3 -I - classify ...`), so a newer head
cannot approve its own helper changes. `check_supply_chain.py` accepts only
that form. See also
[GitHub launch controls](github-launch-controls.md#scheduling-and-supersession-are-one-list).

## Post-apply convergence

After an api-mode apply, GitForgeOps calls `GET /cluster` and prints a
one-line summary: gateway mode, connected data-plane and mesh-node counts, the
oldest `last_sync_at`, and a warning if any node reports `config_diverged`. It
is advisory: an unanswered call prints "unknown" and never fails the apply.

## Timeouts

| Variable | Default | Bounds |
|---|---|---|
| `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `10` | TCP + TLS connect to the Admin API |
| `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `60` | one whole Admin API request |
| `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` | `10` | TCP + TLS connect to the GitHub API |
| `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` | `30` | one whole GitHub API request |

Raise the request timeout for a very large `/backup` or a slow `/restore`, and
the connect timeout for a slow load balancer.

## Scale

| Dimension | Limit | Notes |
|---|---|---|
| Environments per repository | no fixed limit | Each needs a GitHub Environment; the matrix runs them as parallel jobs, within your plan's concurrent-job limit. |
| Namespaces per environment | no fixed limit | |
| Resources per apply | gateway-limited in api mode | Incremental apply is roughly O(changed resources). `full_replace` sends one large request per namespace; prefer incremental on very large gateways. |
| Credential slots per environment | about 7,000 | 16 bundle shards; see [Storage](credential-broker.md#storage). |
| Bundle write concurrency | one run per environment | The `ferrum-apply-<env>` group covers apply and rotate. |

Every declared environment needs a committed `.gitforgeops/config.yaml`
entry: without the file, `apply-on-merge.yml` deploys nothing and
`drift-check.yml` fails its preflight. The implicit `default` environment is a
local CLI fallback driven by `FERRUM_*` variables, never a workflow target.
