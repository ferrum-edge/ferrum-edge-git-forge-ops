# CLAUDE.md — gitforgeops

## Project Overview

`gitforgeops` — GitOps CLI that turns a directory of per-resource YAML files into a Ferrum Edge gateway configuration and reconciles it with a running gateway. Consumed by the CI workflows in `.github/workflows/` on the user's fork; forks add resources under `resources/<namespace>/`, open a PR, CI validates + previews, and post-merge workflows apply.

Rust 2021 edition. Single binary `gitforgeops`. License: PolyForm Noncommercial 1.0.0.

Companion to [ferrum-edge](https://github.com/ferrum-edge/ferrum-edge) — shells out to `ferrum-edge validate` for schema validation and talks to the admin REST API for live operations.

## Commands

All commands accept `--env <name>` to select an environment declared in
`.gitforgeops/config.yaml`. When unset, `FERRUM_ENV` is the fallback; when that
is also unset and the repo config has one entry or a `default_environment`,
that is used.

They also accept `--allow-credential-slot-remap`, which downgrades the
credential-array slot-remap refusal to a report (see Credential broker). It is
CLI-only on purpose — no env var — because accepting a credential reassignment
is a per-run decision, not a repository setting. The safe alternative is
slot-addressed rotation: `gitforgeops rotate --credential <type>/[N]/<key>`
first, remove the entry second.

```bash
gitforgeops validate [--format text|json|github|github-annotations] # Assemble + shell to `ferrum-edge validate`
gitforgeops export [--output PATH]                        # Emit flat YAML (placeholders preserved) + mesh doc
gitforgeops export --materialize [--encrypt-to GH_LOGIN]  # Resolve creds; age-encrypt output (file mode stage 2)
gitforgeops diff [--exit-on-drift]                        # Compare desired vs live gateway (/backup)
gitforgeops plan                                          # Validate + diff + breaking + security + best-practice + policy
                                                          # Exits 1 on validation failure, an error-severity security
                                                          # finding, or an unacknowledged credential-slot remap
gitforgeops apply [--auto-approve] [--allow-large-prune] \
  [--confirm-api-spec-deletion]                           # Apply incrementally (CRUD) or full-replace (/restore)
gitforgeops import --from-api | --from-file PATH --output-dir DIR \
  [--credential-bundle-output PRIVATE_PATH]               # --output-dir required + must be empty; API import requires an explicit namespace filter
gitforgeops review [--pr N] [--require-live]              # Post PR comment; optionally require live comparison
gitforgeops envs [--format json|text] [--include-scopes]  # List envs / trusted CI namespace scopes
gitforgeops rotate --consumer ID --credential KEY \       # Rotate a credential slot and re-deliver
  [--namespace NS] [--recipient GH_LOGIN]
```

## Build / Test / Lint

```bash
cargo build                                   # Debug
cargo build --release
cargo test --test unit_tests                  # Single aggregated test binary
cargo clippy --all-targets -- -D warnings
cargo fmt --all && cargo fmt --all -- --check
```

### Before Every Commit — MANDATORY

1. `cargo fmt --all`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --test unit_tests`

`.github/workflows/rust-ci.yml` reports its required status on every PR and
runs those same three commands when the PR touches current **or previous**
Rust/build/workspace input paths (`src`, `tests`, benches/examples, `build.rs`,
`.cargo`, Cargo manifests/lockfiles, toolchain/lint config, or Dockerfile).
Resource-only PRs skip the Rust steps
and run secretless `validate-pr.yml` instead. `trusted-pr-review.yml` is a
default-branch `workflow_run` that accepts only manifest-verified resource and
overlay YAML, copies environment/policy routing from the protected branch, and
runs a trusted binary with `FERRUM_NAMESPACE` set to one protected-branch
resource namespace per job, intersected with the environment's protected
namespace scope. `review --require-live` fails that job when comparison is
unavailable or its required PR comment cannot be delivered. Review markdown is
bounded below GitHub's API limit, and unresolved credential values are excluded
from live comparison when no bundle is available without hiding other Consumer
fields. Environments with `live_review: false` are removed before the
Environment-bound matrix, which is required for file mode. Fork PRs and
new/remapped namespaces never enter the privileged
live-read boundary. Rust is pinned to 1.98.0 in
`rust-toolchain.toml`; external Actions use full commit SHAs.

## Architecture

### Pipeline

```
resources/<ns>/{proxies,consumers,upstreams,plugins,mesh}/*.yaml
  → loader::load_resources   (walkdir, kind-tagged Resource enum incl. MeshConfig)
  → overlays/<env>/...       (object deep-merge via apply_overlay; arrays replace
                              except additive spec.plugins/spec.targets and mesh
                              spec.workloads (by spiffe_id) / spec.services
                              (by name+namespace))
  → assembler::assemble      (AssembledOutput { gateway: GatewayConfig,
                              mesh: Option<MeshConfigSpec> }; directory namespace
                              inference; merge_mesh_fragments concatenates lists
                              and errors on conflicting singletons;
                              normalize_consumer_credentials folds bare-object
                              credentials into the canonical array form)
  → secrets::resolve_secrets (replace ${gh-env-secret:...} placeholders in-memory
                              from FERRUM_CREDS_JSON_FILE or FERRUM_CREDS_JSON,
                              never written back to disk)
  → policy::evaluate_policies
  → validate / export / diff / plan / apply / review / rotate
                             (gateway doc → FERRUM_FILE_OUTPUT_PATH,
                              mesh doc → FERRUM_MESH_FILE_OUTPUT_PATH)
```

Two things happen at the `validate` hand-off that exist nowhere else in the
pipeline, both because resolution has already run by then:

- `validate::with_validation_standins` replaces credential leaves that are
  *still* `${gh-env-secret:…}` placeholders with a deterministic fake
  (`gitforgeops-validation-standin-<64 hex>`, or `hmac_sha256:<64 hex>` for a
  `basicauth` `password_hash`) derived from the slot path. `${gh-env-secret:alloc=generate}`
  is 30 characters and ferrum-edge's floor for `jwt`/`hmac_auth` is 32, so a
  bundle-less fork PR would otherwise fail on the placeholder rather than on
  the repo. Substitution happens on a **copy**, into the 0600 temp spec only;
  no other output path ever sees a stand-in.
- `secrets::SecretScrubber` collects every non-placeholder Consumer credential
  leaf (minus the identity fields `basicauth[].username` /
  `mtls_auth[].identity`) and every `sensitive_string_paths` plugin-config
  leaf, and removes those exact byte sequences — plus their base64 and
  percent-encoded forms — from the validator child's stdout/stderr, replacing
  each with `[REDACTED]`. Non-credential diagnostics stay intact. Blanket
  suppression survives only as a fallback for a secret shorter than
  `MIN_SCRUB_LENGTH` (8 bytes), which cannot be substring-replaced without
  mangling the report.

### Gateway Modes

- **api** — push to admin REST (POST creates, PUT updates, DELETE removes, POST `/batch` for pure-add namespaces, or POST `/restore` for full-replace)
- **file** — assemble flat YAML for a file-mode Ferrum Edge gateway, published atomically (temp + fsync + rename) with a `resource_counts` seal

Set via `FERRUM_GATEWAY_MODE`. Mesh config is file-only in both modes — there is no mesh admin API, so an api-mode apply validates the mesh document and prints a notice instead of pushing it.

### Apply Strategies

- **incremental** (default) — compute diff against `/backup`, then CRUD per changed resource in dependency order (`operation_rank`: add/modify upstream+consumer → proxy → plugin config, then deletes in reverse). Deletes tolerate 404. A namespace whose diff is **pure adds** takes the transactional `POST /batch` fast path (create-only, all-or-nothing, chunked under the 1 MiB body cap), falling back to per-resource creates on 501.
- **full_replace** — POST to `/restore?confirm=true` atomically **per namespace** (not environment-wide; a runtime failure after an earlier namespace succeeds can still partial-fail). Every namespace payload is prebuilt before the first mutation. The body carries the repo's desired rows **plus the complete live spec-owned graph**: `/restore` validates `api_specs.items` against the tagged proxies/upstreams/plugin configs in the same payload and rejects either half on its own, and it re-creates the documents verbatim rather than re-extracting resources from them, so carrying both cannot duplicate rows. An **empty** spec section and all `gateway_trust_bundles` are omitted instead — the gateway reads `items: []` as an intentional wipe but an absent section as "count the live specs and answer 409", and an absent trust section as "leave trust exactly as it is", so omission is what preserves a concurrent update. `--confirm-api-spec-deletion` is the only path that drops the graph (trust bundles still survive). A graph that cannot be proven complete, a repo/spec ID conflict, cached data, or an unfamiliar top-level backup section fails before mutation.

Set via `FERRUM_APPLY_STRATEGY`. Incremental is safer (partial-failure visibility, no destructive no-op replace); full_replace is stronger (per-namespace atomic, removes drift). For strict environment-wide atomicity, scope `full_replace` to a single namespace.

A `GET /health` preflight runs before the first mutation so a read-only plane fails once instead of N times; a sticky `X-Data-Source: cached` on any `/backup` blocks **all** mutations because cached fallback omits API-spec ownership metadata. `--allow-large-prune` does not bypass that gate.

Create and batch POST error responses are never retried blindly. An ambiguous outcome is reconciled through an authoritative (non-cached) backup, and the readback has three severities (`LiveMatch`): the **exact** row live → an idempotent PUT declares repository ownership and the create is recorded; the row **absent** → the write provably did not commit, so it is an ordinary per-resource error and the rest of the run continues; the row **present but different**, or no usable verification at all → a run-stopping `AmbiguousMutation`. `resource_values_match` is a subset test (desired ⊆ live, minus server timestamps) so a gateway-populated optional does not read as a foreign row.

A separate write-ahead `pending_creates` journal closes the process-crash window without granting deletion authority: exact evidence triggers that PUT, an absent row stays retryable. A live row whose declaration disappeared is **forgotten with a warning** and handed to the ordinary rules for the mode — shared reports it as unmanaged and never deletes it, exclusive prunes it under the large-prune guard, full_replace does not journal at all. Nothing here may fail closed: CI is the only writer of `.state/<env>.json` and `state-guard.yml` blocks the hand edit a wedged journal would demand. The journal survives a process crash, because `apply-on-merge.yml` commits state with `if: !cancelled()`; it does **not** survive workflow cancellation or runner loss, which leaves the row live and unjournaled for the next run's ordinary diff to pick up.

After apply, a best-effort `GET /cluster` prints a convergence line.

### Mesh config

`kind: MeshConfig` fragments live under `resources/<ns>/mesh/`. They are not gateway resources: every fragment folds into one standalone `{version: "1", mesh: {...}}` document (`apply::render_mesh_yaml`, `MESH_DOCUMENT_VERSION`) published to `FERRUM_MESH_FILE_OUTPUT_PATH` by `export` and file-mode `apply`. `validate` / `plan` / `apply` run a second pass, `ferrum-edge validate -m mesh`, over the rendered bytes. Mesh resources never appear in `diff` — there is no live API to compare against.

### Namespace Handling

- Directory-inferred: `resources/<ns>/…` → resource `namespace: <ns>` unless the spec overrides with a non-default value.
- `FERRUM_NAMESPACE` filters load, diff, apply, and import. API import requires this (or an environment namespace filter) and processes one namespace at a time; other commands process all namespaces when it is unset.
- API calls send `X-Ferrum-Namespace: <ns>` per namespace; `split_config_by_namespace()` groups operations.

### Multi-Environment (repo config)

`.gitforgeops/config.yaml` declares logical environments. Each entry picks an
overlay, apply strategy, ownership mode, and whether live PR review is enabled.
Set `live_review: false` for file-mode environments. **No gateway URL, no JWT, no
secret names** live in this file — those come from GitHub Environment Secrets
of the same name as the entry (e.g. `production` entry → GitHub Environment
`production`'s secrets are injected by the workflow). See
`.gitforgeops/config.example.yaml`.

Workflows run as a matrix over `gitforgeops envs --format json`, binding
`environment: ${{ matrix.environment }}` to pull the scoped secrets. Concurrency
groups serialize per-env applies so two concurrent writes to the same
environment never interleave.

#### Freshness guard (the lock does not move the checkout)

`ferrum-apply-<env>` serializes `apply-on-merge.yml` and `rotate.yml`, but
`actions/checkout` still selects the *triggering* commit, so a queued run would
reconcile against a `.state/<env>.json` that predates the ledger the run ahead
of it publishes — and shared mode reads rows it never saw as "never managed".
Both workflows therefore check out `ref: <default_branch>` with `fetch-depth: 0`
and then, in a **`Refresh protected branch and reject stale deployments`** step
that runs before any build or gateway call: re-fetch the branch, `git checkout
--force -B <branch> refs/remotes/origin/<branch>` (stay on the branch — the
ledger commit later pushes it), print the triggering SHA and the branch head,
and fail closed unless `git merge-base --is-ancestor` puts the trigger inside
that head. Binary, desired state and ledger then all come from one commit;
`GITHUB_SHA` for the apply is that refreshed head, matching
`state.last_applied_commit`. PR attribution (override label, credential
recipient) stays on the triggering merge. `check_supply_chain.py::
stale_deployment_guard_violations` enforces the shape and the step ordering.

### Ownership modes

Configured per environment in repo config.

- **`shared`** (default, safer): repo manages only what it has previously applied.
  State file is the fence — unknown resources on the gateway are reported as
  *unmanaged* and left alone. `full_replace` is rejected in this mode.
- **`exclusive`**: repo is authoritative for the listed `namespaces`. Unmanaged
  resources get pruned. Required for `full_replace`.

#### Adoption of already-matching rows

A declared resource identical to its live row yields no diff entry, so no
operation would ever record ownership of it — the ledger stayed empty, the row
sat outside the shared-mode delete fence, and removing it from the repo pruned
nothing. `apply::api_target::adoption_candidates` / `adopt_matching_rows` close
that: at the end of an incremental apply, every declared `(namespace, kind, id)`
that is live, exactly as declared, untouched by an operation this run, absent
from `ApplyOptions::managed_ledger`, and not `api_spec_id`-tagged is claimed and
recorded (`ApplyResult::adopted`, replayed through `StateFile::record_op`).

- **shared** issues the same idempotent PUT the pending-create recovery uses —
  equality is not provenance. The PUT runs only against a *fresh* `GET /backup`,
  so a row edited between diff and assertion is skipped with a per-resource
  message (`ApplyResult::adoption_skipped`) instead of being overwritten.
- **exclusive** records without any PUT (already authoritative; the entry keeps
  the fence correct if the env is later switched to `shared`).
- **file mode** is unchanged — `StateFile::record` stamps the whole desired set.
- **full_replace** needs none: `record_full_replace` rebuilds the namespace.

Never adopt from a cached (`X-Data-Source: cached`) backup — it clears
`api_spec_id` tags — and never adopt a spec-owned row. A failed adoption PUT
records nothing and lands in `ApplyResult::errors`. `apply` prints
`adoption_summary_line` plus per-resource lines; the interactive preview lists
`ADOPT <Kind> <id>` and no longer reports "No changes to apply."

The state file is the trust boundary for both of those, and it is CI-authored:
`apply-on-merge.yml` / `rotate.yml` commit `.state/<env>.json` back to `main`
as `gitforgeops[bot]` with a short-lived, contents-only GitHub App token;
`.gitignore` tracks `.state/*.json` (ignoring only locks and temp files), and
`state-guard.yml` fails any PR touching `.state/**` (including rename source
paths) unless the exact `gitforgeops/state-override` `labeled` webhook targets
the current head and its actor currently has `write`, `maintain`, or `admin`
permission. It rejects every push or other PR transition until a qualified
maintainer removes and reapplies the label, and records the actor, permission,
head, run ID, and attempt. Label changes rerun under per-PR concurrency so
removed authorization cannot leave a stale success. It triggers on
`pull_request_target`, never `pull_request`: the latter loads the guard from
the PR's own head, so one commit could forge a ledger entry and delete the
check that rejects it. That is safe only because the job never checks out the
PR — files, labels, and permission all come from `gh api`, and
`changed_files.py` from an explicit default-branch checkout. It runs
on **every** PR with no `paths:` filter and decides internally whether
`.state/` was touched — a path-filtered workflow reports no status on
non-matching PRs, which stalls them forever once the check is required.
The launch baseline requires the check and gives only the dedicated App an
always-on `main` ruleset bypass. Repository variable
`GITFORGEOPS_STATE_APP_ID` (public metadata, read identically by the workflows
and by the settings audit) and environment secret
`GITFORGEOPS_STATE_APP_PRIVATE_KEY` feed the commit workflows, and both are
verified in a preflight before the gateway is mutated; see
`docs/github-launch-controls.md`. Keep the fence there
rather than narrowing what the binary reads out of the ledger — shared mode
must keep reconciling namespaces the repo no longer declares, or a PR that
removes a namespace's last resource orphans it on the gateway forever.

`diff::compute_diff_with_ownership` takes an optional `previously_managed: &HashSet<String>`
of `namespace:Kind:id` keys from the state file. `Some(set)` = shared mode,
`None` = exclusive. Large-prune guard refuses applies that would delete more
than `ownership.large_prune_threshold_percent` of the managed set unless
`--allow-large-prune` is passed. Pending-create keys widen recovery namespace
scope but are excluded from this set until a successful idempotent update
asserts repository ownership. Before that ratio is computed, authoritative
backup evidence removes managed keys absent from both desired and live state so
externally deleted rows cannot dilute the denominator forever.

#### Spec-owned tier

There is a third owner besides this repo and a human admin: the gateway's
OpenAPI **spec ingestion** (`/api-specs`), which atomically provisions proxies,
upstreams and plugin configs and tags them `api_spec_id: Some(...)`. Its
re-imports are authoritative, so gitforgeops stays off those rows entirely —
in *both* ownership modes, and regardless of what the state file says.

Any **live** resource with `api_spec_id` set is classified `spec_owned`
(`DiffResult::spec_owned`, its own bucket — not `unmanaged`):

- Never emitted as a Modify. If the repo also declares the same
  `(namespace, kind, id)`, that is reported as a **conflict**
  (`DiffResult::spec_conflicts()`): two owners writing one row, and the spec
  importer wins on its next run. A conflict takes the whole **namespace** out
  of the run (`apply::spec_owned_conflict_block`) — skipping just the row and
  exiting green would falsely report convergence — but only that namespace:
  every other one still reconciles, and the reason lands in
  `ApplyResult::errors` so the run exits non-zero with the conflict named.
- Never emitted as a Delete, except in **exclusive** mode with
  `apply --confirm-api-spec-deletion` (`DiffOptions::prune_spec_owned`).
  Otherwise apply skips them with a per-resource message and counts them in
  `ApplyResult::spec_owned_skipped`. Shared mode ignores the flag — the state
  file is its fence and a spec-owned row was never behind it.
- Rendered in `plan` / `diff` stdout and in the PR comment's "Spec-owned
  Resources" section. Unlike the unmanaged block, it is *not* gated on
  `ownership.drift_report`: a repo fighting the spec importer is a correctness
  problem, not drift noise.
- Counted as drift by `diff --exit-on-drift` (exit 2), independently of every
  `ownership.drift_alert_on` flag — `apply` blocks the namespace, so a nightly
  monitor reporting success would be reporting on a gateway nobody can
  reconcile. Non-conflicting spec-owned rows stay non-blocking, and other
  namespaces are still compared. See `verdict::DriftVerdict`.

`full_replace` does not delete the graph either: the restore body carries the
live spec-owned rows and the live `api_specs` section through unchanged, which
is what the gateway's restore validator requires. `--confirm-api-spec-deletion`
is the only path that drops them (see Apply Strategies).

### Policy framework

`.gitforgeops/policies.yaml` declares enforceable standards. Each rule lives
in `src/policy/rules/` and implements `PolicyCheck`. Register new rules in
`src/policy/registry.rs::build_registry` and add its typed config to
`src/policy/config.rs::PolicyRules`.

Rules: `proxy_timeout_bands`, `backend_scheme`, `require_auth_plugin`,
`forbid_tls_verify_disabled`, `allowed_proxy_plugins`, `allowed_backend_domains`,
`waf_enforcement`, `require_ai_guardrails`, `rate_limit_completeness`,
`plugin_name_is_known`, `priority_override_range`. All default to `enabled: false`.

Import's plugin-config classification (`src/secrets/plugin_config.rs::classify_plugin_config`)
is schema-first for the 82 builtins and heuristics-only for anything else: a
non-builtin plugin brokers only the leaves the key/URL sensitivity heuristics
flag, and the leaves they did not flag come back as
`ImportResult::unbrokered_plugin_config` for a loud per-plugin review notice.
`basicauth[].username` and `mtls_auth[].identity` are never brokered in either
path (`resolver::is_identity_credential_leaf`).

Plugin-name knowledge lives in `src/plugin_catalog.rs` (82 builtins, retired and
reserved names, the 11 auth plugins, and `effective_plugins` merge semantics
where a scoped plugin config replaces a global one of the same `plugin_name`).
Rules that reason about plugins go through it rather than hard-coding names.

Severity `error` blocks `apply` unless overridden. Override = PR label
(configurable name) added by a user whose repo permission is ≥
`overrides.required_permission` (default `write`). Implementation:
`src/policy/github_override.rs::check_override`.

### Preview verdicts (`src/verdict.rs`)

Two pure computations, shared so a preview and the run it previews cannot
disagree.

**`apply_blockers`** — every fail-closed gate `apply` refuses on that is
decidable *without* a gateway, as `Vec<ApplyBlocker>` over five
`BlockerKind`s: `Validation`, `Security`, `Policy`, `RequiredCredentials`,
`SlotRemap`. `plan` evaluates the whole set, prints an `=== Apply Blockers ===`
section (class, count, remedy) plus a summary line, and exits 1 when it is
non-empty. `cmd_apply` calls the *same per-class predicates*
(`security_blocker`, `policy_blocker`, `required_credentials_blocker`,
`validation_blocker`) at its own gate points rather than the aggregate, because
its ordering is load-bearing — the security audit has to refuse before the
credential bundle is read, the required-slot check before the first gateway
call. Sharing the predicates and not the control flow is the whole design.

Rules that must not drift: warning severity never blocks; `alloc=generate`
awaiting first-apply allocation is *not* a blocker (`missing_required()` is,
`needs_allocation()` is not); `policy_findings` are fed **post-override**
(`PolicyFinding::is_blocking` reads `overridden_by`). `plan` resolves the
override through the same `resolve_pr_number` + `check_override` path `apply`
uses, and fails closed — no PR, an inactive decision, or a GitHub error leaves
every blocking finding standing. Gateway-dependent gates (large-prune,
stale-view, per-resource write failures) are deliberately excluded: a preview
cannot decide them.

Adding a new fail-closed gate to `apply` means adding a `BlockerKind` here, or
`plan` silently goes back to promising applies that refuse.

**`DriftVerdict`** — what makes `diff --exit-on-drift` exit `DRIFT_EXIT_CODE`
(2). Managed add/modify, managed delete and unmanaged-added each honor their
`ownership.drift_alert_on` flag; **spec conflicts do not** and cannot be muted
(see the spec-owned tier). Informational spec-owned rows the repo does not
declare are never drift.

### Credential broker (in-GitHub, no third-party)

Consumer credentials use placeholders like
`keyauth: [{ key: "${gh-env-secret:alloc=generate}" }]`. Slot names are derived
from `(namespace, consumer_id, cred_key)` — never hand-written.

ferrum-edge recognizes exactly five credential types, each an **array** of
entries (`KNOWN_CREDENTIAL_TYPES`): `basicauth`, `keyauth`, `jwt`, `hmac_auth`,
`mtls_auth`. The array form is canonical — `/backup` always returns it, so a
bare object is permanent false drift; the assembler normalizes the object form
on load. Slot paths elide `ArrayIndex(0)` so the normalization doesn't rename
(and orphan) already-allocated slots; entries ≥1 get a `[N]` segment. Older
encodings stay in the read-only lookup candidate list.

`basicauth[].username` and `mtls_auth[].identity` are **identities, not
secrets** — the public halves of their credentials, which the broker cannot
generate and a resource file cannot omit and still say which credential it
describes. `secrets::resolver::is_identity_credential_leaf(credential_type,
leaf)` is the single classifier, keyed on the credential type *and* the leaf
key together (a `username` under a custom credential type is still a secret).
Four callers must agree or a config becomes acceptable to one command and
refused by another: the resolver (never broker one), `import`'s capture walk
(never redact one out of the file), `secrets::scrubber` (never black one out of
a validator diagnostic), and `diff::security::check_literal_credentials` (never
block `apply` on one). That last one carries the credential type and leaf key
down the walk separately from the human-readable diagnostic path.

Generation constraints, enforced at resolve time so `plan` fails before `apply`
writes an unusable value: `jwt`/`hmac_auth` secrets need ≥32 chars (`len=` ≥ 24
entropy bytes); `basicauth` generation is refused in file mode and
`basicauth/…/password_hash` in either mode (the hash is HMAC-SHA256 under the
gateway's own secret); a bundle value of `[REDACTED]` is refused.

Slot identity is positional, and `resolver::check_array_slot_identity` splits
the two consequences by whether evidence exists:

- Multi-entry brokered array → `ResolveReport::warnings`, advisory. A reorder
  or prepend re-owns stored values but leaves the document, the bundle keys and
  every slot status identical to steady state, so refusing here would refuse
  every multi-entry credential forever.
- Bundle holds a slot at an entry index the array no longer has (a shrink) →
  `ResolveReport::slot_remaps`, and resolution returns
  `Error::CredentialSlotRemap`. This cannot fire in steady state. `apply`,
  `export --materialize` and `rotate` refuse; `plan` and `review` resolve with
  `SlotRemapPolicy::Allow` so they can render it (plan then exits 1 itself).
  `--allow-credential-slot-remap` downgrades the refusal for the documented
  shrink-then-rotate sequence. Messages name slots only, never values.

Literal (non-placeholder) consumer credentials are an apply blocker too:
`cmd_apply` runs `diff::audit_security_with_policy` on the **unresolved**
document before the state lock, the bundle read, and any gateway call, health
preflight, allocation or file publish, and refuses every finding
`diff::security_blockers` returns. The escape hatch is the policy override (PR
label + repo permission), resolved once and shared by both gates.

Storage: one or more GitHub Environment Secrets named `FERRUM_CREDS_BUNDLE[_N]`,
each holding a JSON object of `slot → value`. Capacity ~440 slots per bundle,
auto-sharded by fnv-style hash when a bundle approaches 40 KB.

The shard layout is capped at `MAX_BUNDLE_SHARDS = 16` (shards 0..15,
~7,000 slots). The cap exists because the privileged workflows'
"Load credential bundles" step binds every bundle secret **by name**
(`FERRUM_CREDS_BUNDLE: ${{ secrets.FERRUM_CREDS_BUNDLE }}`, …
`FERRUM_CREDS_BUNDLE_15`) rather than dumping the whole `secrets` context: a
`toJSON(secrets)` spill hands the step the admin JWT signing key, the
state-writer App private key and the registry token to read a handful of bundle
values, and since GitHub's 2026-07-28 change it also makes public-repository
runs wait for manual approval. `bundle::reserve_shard` refuses to create shard
16 with an actionable error instead of PUTting a secret nothing reads back.
Adding capacity means raising `MAX_BUNDLE_SHARDS` in **both**
`src/secrets/bundle.rs` and `.github/scripts/credential_bundles.py` and adding
the matching `FERRUM_CREDS_BUNDLE_<N>` bindings to `apply-on-merge.yml`,
`drift-check.yml`, `materialize-file.yml` and `rotate.yml`;
`.github/scripts/check_supply_chain.py` cross-checks all three and fails the
build on drift. Reads stay uncapped so a repo sharded under an older ceiling
still resolves its existing slots.

`credential_bundles.py` reads those enumerated env vars (blank = unset),
validates every populated value as a JSON object of string slots to string
values, rejects a bundle name outside the bound range instead of dropping it,
writes a new 0600 file without following/overwriting a destination, and the
step exports the path as `FERRUM_CREDS_JSON_FILE`. Malformed input fails closed
rather than becoming an empty bundle. Inline `FERRUM_CREDS_JSON` is still
supported for small local tests.

Allocation (first apply, or rotation): generate random value → libsodium
`crypto_box_seal` to the env's public key → PUT to
`repos/.../environments/<env>/secrets/FERRUM_CREDS_BUNDLE[_N]`. Writes require
`FERRUM_GH_PROVISIONER_TOKEN` (GitHub App installation token preferred, PAT
with `Secrets: write` as fallback).

Delivery: after allocation or rotation, the value is age-encrypted to the PR
author's (or dispatcher's) SSH public key fetched from
`GET /users/{login}/keys`, then posted as a PR comment or workflow output.
Author decrypts with `age -d -i ~/.ssh/id_ed25519`.

### Source Layout

- `src/main.rs` — async Tokio entry, command dispatch
- `src/cli.rs` — clap parser (global `--env` flag, subcommands incl. `envs`, `rotate`)
- `src/config/` — `schema.rs` (typed companion mirror of Ferrum Edge types, incl. `BackendScheme` with legacy-value folding and opaque per-item `MeshConfigSpec` values), `strict.rs` (`LoadOptions` unknown-field policy, unknown-field detection with full YAML paths, non-string mapping-key rejection, lowercase-extension enforcement, the silent `OS_ARTIFACT_FILES` skip list — kept in step with `.github/scripts/pr_input.py` by a Python test — and deliberate free-form/disabled-value handling), `loader.rs` (sorted, error-propagating, symlink-rejecting walk of `proxies/consumers/upstreams/plugins/mesh`), `assembler.rs` (deterministic overlay deep-merge, duplicate-target rejection, `merge_mesh_fragments`, credential normalization), `env.rs` (strict process-env parsing, incl. `validate_gateway_transport` — the https-only gateway URL rule and the CI/loopback gate on the insecure opt-ins), `repo_config.rs` (closed version-1 `.gitforgeops/config.yaml` contract), `resolved.rs` (merges repo + env-var into a single `ResolvedEnv` per invocation)
- `src/diff/` — `resource_diff.rs` (add/modify/delete + field-level changes + unmanaged and spec-owned tracking), `breaking.rs`, `security.rs`, `best_practice.rs`
- `src/apply/` — `api_target.rs` (incremental + full_replace, all-namespace restore preflight, spec-conflict and concurrent-spec restore gates, dependency ordering, non-idempotent create reconciliation, `/batch` fast path, authoritative-backup mutation gate, exact large-prune ratio, ownership-aware delete filter, `adoption_candidates` / `adopt_matching_rows` claiming already-matching declared rows into the ledger), `file_target.rs` (atomic publish, `resource_counts` seal, `render_mesh_yaml` / `apply_mesh_file`)
- `src/plugin_catalog.rs` — 82 builtin plugin names, retired/reserved names, auth/rate-limit/observability/AI-guardrail groupings, `effective_plugins` merge, small `cfg_*` JSON accessors
- `src/policy/` — `config.rs` (closed version-1 YAML + override config), `registry.rs`, `rules/*` (one file per rule), `github_override.rs` (label + permission check via GitHub API)
- `src/secrets/` — `scrubber.rs` (`SecretScrubber`: the secret byte sequences to redact from child-process output), `placeholder.rs` (`${gh-env-secret:...}` parser), `bundle.rs` (shard layout + hash placement, `MAX_BUNDLE_SHARDS` ceiling + `reserve_shard`), `resolver.rs` (walks consumers, replaces in-memory), `github_api.rs` (libsodium seal + PUT), `delivery.rs` (age encryption to SSH pubkey), `allocator.rs` (generate + write + deliver)
- `src/http_client.rs` — `AdminClient` wrapping reqwest; namespace-scoped JWT construction; base64-encoded PEM for CA / mTLS from env; typed `ApiErrorBody` + endpoint-semantic retry classification (create/batch responses never replayed, restore only on explicit pre-commit connectivity failure), `Retry-After` honoring, paginated list helpers, `BackupExtras` (api_specs / trust bundles), `ClusterStatus` + `convergence_summary`
- `src/validate/` — `runner.rs` shells to `ferrum-edge validate` with `-m file` / `-m mesh` pinned, an empty `-s` settings file, `FERRUM_*` scrubbed from the child env, and a 0600 temp spec, then passes the child's output through a `SecretScrubber`; `standin.rs` fabricates the validator-only credential stand-ins; `reporter.rs` formats (text/JSON/GitHub annotations) for one or both passes
- `src/review/` — `pr_comment.rs` builds markdown (v2 includes unmanaged, spec-owned, policy, credential sections), `github.rs` posts via GitHub API
- `src/import/` — `from_api.rs` (fetches all namespaces before publishing and refuses cached/cross-namespace backups), `from_file.rs` (parses the full backup envelope), `mod.rs::split_config` (captures every credential string under the resolver's canonical slot, requires an outside-tree mode-0600 migration bundle for source imports, emits deterministic `alloc=require` YAML plus a non-secret `.gitforgeops-import.json` inventory, percent-encodes a leading `_`/`%` in an id so a live resource can never dead-end the import (identity comes from `spec.id`, not the filename), and atomically publishes an empty output tree; reports skipped/unsupported sections)
- `src/state.rs` — `.state/<env>.json` tracks managed resource keys with non-secret markers, credential delivery metadata, shard count, override history, and a non-authoritative write-ahead pending-create journal
- `src/reconcile.rs` — `resolved_namespaces` (which namespaces a run iterates; shared mode unions repo-declared with state-derived so orphans stay reconcilable) and `previously_managed` (the shared-mode delete fence)
- `src/jwt.rs` — mints HS256 tokens for admin API auth
- `src/verdict.rs` — `apply_blockers` (the offline fail-closed gates `plan` and `apply` share) and `DriftVerdict` / `DRIFT_EXIT_CODE` (what makes `diff --exit-on-drift` exit 2)
- `src/error.rs` — unified `Error` enum via `thiserror`

### Key Design Principles

1. **Fail-closed typed schema, explicit opaque islands** — wrapper/resource/nested keys unknown to this companion version are rejected with source file + YAML path before lossy re-serialization. Intentionally free-form plugin `config`, credential maps, and per-item mesh values round-trip unchanged to the authoritative gateway validator.
   The one escape hatch is `FERRUM_ALLOW_UNKNOWN_FIELDS=true` (`config::LoadOptions`, threaded from `main` — never read from the process env inside the parse path): unknown **top-level** `spec` fields land in a `#[serde(flatten)]` `extra: BTreeMap` (`schema::PassthroughFields`) and flow through overlay merge → export → diff → apply verbatim, with one `Warning:` per file on **stderr** (stdout carries the exported YAML). Nested unknowns stay fatal in both modes — `serde_ignored` still sees them, because `flatten` only intercepts keys the struct did not claim. A pass-through key present only on the *live* side is not drift (`compare_fields` skips it); declaring a key in the repo is how the repo takes ownership of it.
   Two corollaries of the same no-silent-rewrites rule: YAML merge keys (`<<:`) are unsupported and surface as unknown field `.spec.<<`, and opaque islands are **JSON-shaped**, so a non-string YAML mapping key is rejected (`strict::reject_non_string_keys`) rather than stringified.
   Deterministic output depends on this too: every map serialized into the exported document or an API body is a `BTreeMap`. `HashMap` re-seeds `RandomState` per instance, so the same input would export different bytes every run.
2. **Path-component sanitization** — resource `namespace` and `id` flow into filesystem paths during `import`. `import::safe_path_component` rejects `..`, `/`, `\`, null bytes, and empty strings before `Path::join` to prevent traversal.
3. **No public credential oracles** — the state ledger stores only managed-resource keys plus a constant marker and non-secret credential delivery metadata. It never hashes resolved Consumers or credential values.
4. **Namespace-scoped operations** — every API call, diff entry, and breaking-change lookup keys on `(namespace, id)`, never `id` alone.
5. **Partial-failure visibility** — incremental apply reports per-resource errors via `ApplyResult`; failures don't abort the whole run.

## Key Environment Variables

See `.env.example` for the full list. Essentials:

- `FERRUM_GATEWAY_URL` (required for api mode) — must be `https://`; `http://` needs `FERRUM_ALLOW_INSECURE_HTTP=true`, every other scheme and any embedded `user:password@` are refused. Checked in `load_env_config` so the command fails before a client exists.
- `FERRUM_ADMIN_JWT_SECRET` (required for api mode; ≥32 chars to match ferrum-edge)
- `FERRUM_ADMIN_JWT_ISSUER` (default `ferrum-edge`) — must equal the gateway's own issuer or every call is 401
- `FERRUM_ADMIN_JWT_ROLE` (default `admin`) — `/backup`, `/restore`, `/batch` and consumer CRUD are admin-only
- `FERRUM_ADMIN_JWT_AUDIENCE` (default unset) — `aud` is emitted only when set; a gateway with no audience rejects tokens carrying it
- `FERRUM_ADMIN_JWT_TTL_SECS` (default `3600`) — must be within the gateway's `FERRUM_ADMIN_JWT_MAX_TTL`
- `FERRUM_NAMESPACE` (filter; default = all namespaces except API import, which requires one explicit namespace)
- `FERRUM_ALLOW_UNKNOWN_FIELDS` (default `false`) — keep unknown top-level `spec` fields verbatim instead of rejecting them; nested unknowns stay fatal. For a gateway newer than this release.
- `FERRUM_GATEWAY_MODE` = `api` | `file` (default `api`)
- `FERRUM_APPLY_STRATEGY` = `incremental` | `full_replace` (default `incremental`)
- `FERRUM_OVERLAY` (applies `overlays/<name>/` deep-merge; a configured missing directory is fatal — `resolved::validate_overlay_selection` reports it up front naming the environment, the overlay and the declaring file)
- `FERRUM_EDGE_BINARY_PATH` (default `ferrum-edge` on `$PATH`)
- `FERRUM_FILE_OUTPUT_PATH` (file mode; default `./assembled/resources.yaml`)
- `FERRUM_MESH_FILE_OUTPUT_PATH` (default `./assembled/mesh.yaml`) — standalone `{version, mesh}` document; separate file from the gateway doc, written by `export` and file-mode `apply` whenever the repo declares any `MeshConfig`
- `FERRUM_TLS_NO_VERIFY` (dev only; accepted values `true|false|1|0`) — TLS stays on but any certificate is accepted
- `FERRUM_ALLOW_INSECURE_HTTP` (default `false`; dev only) — permits a cleartext `http://` gateway URL. Independent of `FERRUM_TLS_NO_VERIFY`; both print a loud stderr banner once per process and both are refused when `GITHUB_ACTIONS=true` unless the gateway host is loopback (`localhost`, `127.0.0.0/8`, `::1`). `config::env::validate_gateway_transport` owns the whole rule.
- `FERRUM_GATEWAY_CA_CERT` / `FERRUM_GATEWAY_CLIENT_CERT` / `FERRUM_GATEWAY_CLIENT_KEY` — base64-encoded PEM. mTLS requires BOTH cert and key; setting only one is rejected.
- `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` (default `10`) — TCP/TLS handshake cap
- `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` (default `60`) — end-to-end request cap; raise for large `/backup` or slow `/restore`
- `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` (default `10`) — same shape, for `gitforgeops review --pr N`
- `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` (default `30`) — GitHub API call is small; 30s is plenty
- `FERRUM_GATEWAY_MAX_RETRIES` (default `3`) — retries connection-establishment failures and transient responses for reads/idempotent PUT/DELETE calls; exponential backoff 500ms·2^n capped at 8s, or `Retry-After` (capped 30s). Create/batch POST responses are never retried; restore retries only an explicit `503 failure_class=connectivity` pre-commit failure.

Absent/blank env values use defaults; every present invalid enum, boolean, or integer fails before loading resources or credentials. `plan` / `review` treat validator execution failure as `ERROR` and return nonzero, never as a passed/skipped validation.

## Testing

- `tests/unit_tests.rs` is the single integration test binary; submodules live under `tests/unit/*.rs` and register in `tests/unit/mod.rs`.
- Fixtures under `tests/fixtures/` (`simple-config/`, `overlay-test/`, `companion-schema/`).
- `companion-schema/` holds one file per kind populating **every** field mirrored in `src/config/schema.rs`. `tests/unit/companion_schema_tests.rs` loads it strictly, assembles it, round-trips it through export, and — by reading the struct definitions out of `schema.rs` — fails when a newly mirrored field is not exercised there. Add new mirrored fields to that fixture in the same PR.
- New test file: create `tests/unit/<name>.rs` AND add `mod <name>;` to `tests/unit/mod.rs`.
- `tempfile` crate for filesystem tests.
- No network in tests — `AdminClient::new` constructs the client without connecting, so credential-validation paths can be exercised without mocking.

## Development Guidelines

Repository-local agent skills, Claude rules, and their dispatchers are guarded by
`agent-setup-policy.yml`. The workflow runs trusted default-branch validation over candidate
content on every PR, has only read access, and cancels stale runs per PR. Requiring
`Agent Setup Policy / validate-trusted-policy` and code-owner review is what prevents a candidate
from weakening its own validator; forks do not inherit those repository settings automatically.

- **No `.unwrap()` in production code paths** — use `?`, `.unwrap_or()`, or explicit match.
- **No `.expect()` except where failure is a genuine bug** (e.g. `serde_json::to_string` on a static `Value`).
- Return `crate::error::Error` variants via `?`; prefer descriptive variants over `Config(String)` when the category is clear.
- New `FERRUM_*` env vars: add to `EnvConfig`, `load_env_config()`, `.env.example`, and doc block in `env.rs`.
- Schema additions: mirror the Ferrum Edge struct, keep `#[serde(default)]` + `#[serde(skip_serializing_if = "Option::is_none")]` for optional fields. Don't validate — ferrum-edge does.

## PR Checklist

1. `cargo fmt --all` clean
2. `cargo clippy --all-targets -- -D warnings` clean
3. `cargo test --test unit_tests` passes
4. Agent/rule changes → `python3 .github/scripts/check_agent_setup.py` and
   `python3 -m unittest discover -s .github/scripts/tests -p 'test_agent_setup.py'`
5. No `.unwrap()` / `.expect()` in prod code
6. New env var → `.env.example` + `env.rs` doc block
7. Schema change → unit test in `tests/unit/schema_tests.rs`
8. Commit messages in imperative mood; branches `feature/…`, `fix/…`, `claude/…`
