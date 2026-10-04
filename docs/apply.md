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
  locally, and sends one `POST`/`PUT`/`DELETE` per changed resource. Every
  `PUT` or `DELETE` of an existing row is first read with `GET /<kind>/{id}`
  and sent with `If-Match`. Consumer writes instead use credential-complete
  `GET /consumers/{id}/verification`; see
  [Changes made during an apply](#changes-made-during-an-apply). At about
  100 ms per call, 1,000 creates take about two minutes, and 1,000 modifies or
  deletes about four. A namespace whose diff is only adds uses `POST /batch`
  instead.
- **`full_replace`** (exclusive mode only) builds and validates every
  namespace payload from `GET /backup?conditional=true` first, then calls
  `POST /restore?confirm=true` once per namespace with that original snapshot's
  namespace `If-Match`. Deterministic errors in any namespace mean no restore is sent.
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
- `/restore` 503 with the established precommit `failure_class: connectivity`
  (nothing was written), using the identical prepared body and namespace token.
  Contradictory incomplete/unknown rollback or `applied:false` prevents replay.

Never retried:

- **501** — for example a standalone-MongoDB gateway without transactions.
  `POST /batch` then falls back to per-resource creates.
- **Any error from a create or batch `POST`.** The write may have committed.
  GitForgeOps re-reads an authoritative backup instead:
  - the exact resource (or complete batch) is live → an idempotent `PUT`
    records repository ownership, then the create counts. Consumer recovery uses
    a coherent conditional backup and a complete tagged verification read; an
    opaque Basic HMAC cannot prove equality to submitted plaintext;
  - nothing under that id → the create did not commit; it is an ordinary
    failure and the run continues;
  - a different row, or no usable backup → the run stops for reconciliation.
- **`applied: false`** in the body → `CommittedNotLive` (reason
  `config_rejected`, `reload_timeout` or `sequence_unavailable`). The write is
  stored but not live; check gateway health instead of re-sending.
- **Malformed mutation envelopes.** Duplicate keys, incorrectly typed fields,
  null markers and non-object responses cannot establish success or permit a
  retry. Diagnostics withhold response bytes and parser details. Ordinary writes
  accept empty HTTP 204 acknowledgements; batch creates still require matching
  per-kind counts, and conditional restore still requires its complete count seal.
  An invalid acknowledgement leaves the write's outcome uncertain: no blind
  replay, pruning or ledger completion is authorized. Create and batch recovery
  may establish success through authoritative readback and conditional ownership
  assertions; rotation records completion only after confirmed live publication.
- **`/restore` failures** other than the connectivity case. A 500 with
  `rollback: incomplete` or `unknown_outcome` is `RestoreNeedsManualRecovery`.
- **Request timeouts.** The outcome is unknown; the next run re-diffs.
- **Other 4xx** (400, 401, 403, 404, 409, 412, 422). A `412` answers a
  conditional write; see
  [Changes made during an apply](#changes-made-during-an-apply).
- **3xx.** Redirects are never followed. Because `FERRUM_GATEWAY_URL` is a
  GitHub Environment secret, the error describes the `Location` only by how it
  relates to the configured base (same origin and a different path, a changed
  scheme, or another origin) instead of echoing it; point `FERRUM_GATEWAY_URL`
  at the final origin.

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
  write, and `--allow-large-prune` does not bypass it. A cached single-row
  read before a conditional write stops the run the same way.
- **`StalePlan`.** A row changed after this run planned its write: its
  conditional read disagreed with the plan, or the gateway answered `412` to
  the `If-Match` write. The row is not written and the namespace's remaining
  writes are withheld. See
  [Changes made during an apply](#changes-made-during-an-apply).
- **`ConditionalWriteUnavailable`.** A required strong row tag, complete consumer
  verification or coherent conditional snapshot is unavailable or invalid. The
  operation refuses before allocation. Cached reads, audit-admission refusal and
  unsupported transaction topology cannot downgrade to unconditional writes.
  Capability reads do not establish server enforcement of `If-Match`.
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
views, missing entity-tags, unsupported backup sections and restore rollback
damage stop the whole run.

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
writes go out. Incremental apply therefore never overwrites or deletes an
existing row unconditionally. For every modify, delete, pending-create
ownership assertion, adoption claim and ambiguous-create ownership assertion it:

1. reads the row with `GET /<kind>/{id}` and requires a strong `ETag` for the
   stored row;
2. compares that row with the row it planned against; and
3. sends the `PUT` or `DELETE` with `If-Match: <etag>`.

Released Ferrum Edge v0.9.6 source includes this conditional-write capability,
with no minimum-version claim
([release source](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.6/src/admin/preconditions.rs),
[Edge PR 5661](https://github.com/ferrum-edge/ferrum-edge/pull/5661)). Apply
probes only for a strong `ETag` and always sends `If-Match`. The operator must
qualify the exact released gateway build to establish that it honors
`If-Match`; a server that returns tags but ignores the condition is not
detected or automatically refused. This capability does not certify the rest
of the gateway's backup or consumer representation for this client. Apply
still requires explicit matching namespaces, authoritative ownership metadata
and comparable consumer credentials; the lifecycle suite must pass against
the exact gateway build. Pending gateway fixes to those representations are
not implied by the v0.9.6 source.

Edge compares the tag and commits the write under one namespace admission lease
that every admin writer (CRUD, `/batch`, `/restore`, `/api-specs`, credential
endpoints) takes, so a change that lands after the read is refused with
`412 Precondition Failed` instead of being overwritten. The read refuses what
changed before it:

- **Ownership moved.** A row that gained, lost or changed its `api_spec_id` is
  not written: an `/api-specs` import claimed it after the plan. See
  [Spec-owned resources](ownership.md#spec-owned-resources).
- **Content changed.** A row that differs in anything but server timestamps is
  not written, so someone else's edit is not reverted. An update is also
  refused when the row now carries a nested field this build cannot represent,
  because the write would reset it.
- **Row gone.** A delete is not sent and counts as already gone; sending it
  could only remove a row someone created since. An update is refused.

The plan's `/backup` is normalized by the gateway as it loads, while the
single-row read returns the row as stored, so a row stored before a
normalization rule existed can read differently without having changed. When
the read disagrees with the plan, apply reads `/backup` once more, after the
read, and goes ahead only if that backup still shows the planned row: a change
made before the read shows there in the plan's own form, and a change made
after it fails the `If-Match`. Such a row is never refused forever.

A refused write (by the read or by a `412`) is a per-resource error naming the
row, and it proves the namespace's plan stale: **nothing more is sent to that
namespace** in this run. Its remaining creates and updates are reported as
withheld, its deletes are deferred, and adoption is skipped. Other namespaces
continue, and the run exits non-zero. Re-run apply to plan against the current
gateway.

A `412` that answers a retried `PUT` (an earlier attempt reached the gateway,
got a retryable answer and was sent again) may be refusing a replay of this
run's own committed write. Apply reads the row once more and counts the write
as applied when the row now carries what it sent and no API spec owns it.
Consumers are never counted that way: credential transformations, particularly
opaque Basic HMACs, cannot prove that the earlier plaintext write committed.
Their refusal says the earlier attempt may have committed, and the re-run
reconciles it.

A read served from cache (`X-Data-Source: cached`) or one without a strong
`ETag` stops the run: no write can be made conditional on it. The apply
preflight, before any credential is allocated or any row written, reads one
row the run will overwrite to check for a strong tag, so a missing tag is
refused up front rather than after earlier creates landed; `doctor --scope
gateway` checks for the tag too. Neither check verifies that the server honors
`If-Match`; operator qualification of the exact released build must establish
that safety requirement. A read that fails refuses that write like any failed
write.

**Consumers** require exact stored evidence. Before allocation, apply captures
`GET /consumers/{id}/verification` for the consumer targets. Its comparison-only
canonical projection must still match the original archival backup. The raw row
and row token stay separate from that projection. Immediately before modify,
delete, pending assertion or shared ownership claim, complete verification must
match the planned evidence, including hidden/custom fields and legacy entries;
the write uses its row `If-Match`. Unknown fields are not discarded to make a
match. A desired update or replacement that would lose retained credential fields
refuses. Omitted hidden Basic/custom types survive incremental PUT under the
server's omission semantics; they cannot be omitted from a replacement that
keeps that consumer. Basic HMACs use a gateway key and remain opaque; the admin
signing key is never used to infer plaintext equality.

**Full replacement** captures all four resource arrays and row-token maps,
verbatim spec documents and the namespace token in one primary transaction.
The token covers the entire namespace, including trust, ownership and namespace
metadata, and detects delete/recreate or change/revert cycles. Every prepared
restore carries that original token, including empty namespaces and confirmed
spec deletion. `412` abandons the prepared body and requires a new plan; there
is no fresh-token replay. Trust and authoritative empty spec sections remain
omitted under the existing server semantics. The former spec-document reread
is not a concurrency guarantee and is no longer used.

`doctor --scope gateway` probes complete verification and coherent snapshots
using GET only. No consumer to probe means unknown, never pass. Ordinary diff,
plan, review and viewer drift reads retain their current endpoints and explain
these runtime requirements. The immutable Edge owner contract is
`c764084b3b51c3f7ffde268c039688d35e49c553`; a final released artifact containing
and enforcing it must be qualified before release acceptance. This change does
not invent a new release pin or certify an older binary.

**Proxies and their plugins.** Ferrum Edge rewrites a proxy's association list
itself when a scoped plugin is created, retargeted or removed. A proxy this
run reads after its own plugin writes is compared without the associations to
the plugin configs this run wrote, and with every other association: one
someone attached or detached concurrently is a change, so the repository's
list never silently reverts it. The same exclusion lets one apply move a
scoped plugin to another proxy and delete the proxy it left.

A delete compares the row as this build decodes it, so a concurrent change
confined to a nested field this build does not model does not refuse a delete.

Creates need no precondition, because `POST` and `POST /batch` are create-only.
After an ambiguous create, the row is read before the verification backup, and
a row that carries an `api_spec_id` is never claimed, even when its content
matches.

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

Both workflows run both checks. For a rotation the triggering commit is the
one it was dispatched from, so its environment approval never carries a newer
binary, helper or resource change; see
[A superseded rotation](../README.md#a-superseded-rotation).

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
