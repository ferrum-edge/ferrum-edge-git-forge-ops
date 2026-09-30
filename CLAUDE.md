# CLAUDE.md — gitforgeops

## Project Overview

`gitforgeops` is a GitOps CLI. It assembles a directory of per-resource YAML
files into a Ferrum Edge gateway configuration and reconciles it with a running
gateway. Forks add resources under `resources/<namespace>/` and open a PR; CI
validates and previews; post-merge workflows apply.

Rust 2021, single binary `gitforgeops`, PolyForm Noncommercial 1.0.0. Companion
to [ferrum-edge](https://github.com/ferrum-edge/ferrum-edge): it shells out to
`ferrum-edge validate` for schema validation and uses the admin REST API for
live operations.

## Buildout and schema policy

GitForgeOps is in pre-launch buildout with no users. Breaking changes are
acceptable. Update implementation, examples, fixtures, tests and docs together;
do not add compatibility layers or upgrade guides for earlier buildout
revisions.

There is no database, SQL schema or migration runner. Edit these definitions
directly:

- `src/config/schema.rs` — gateway configuration mirror
- `src/config/repo_config.rs`, `src/policy/config.rs` — repository configuration
- `src/state.rs` — JSON ownership ledger

If database persistence is ever introduced during buildout, keep one complete
initial schema and fold later changes into it; no incremental migration files.

Credential import bundles move secrets from an existing gateway into the broker.
They are runtime artifacts and stay outside Git worktrees. The companion
gateway's API contract, secret handling and ownership rules still apply.

## Commands

```bash
gitforgeops validate [--format text|json|github|github-annotations]  # assemble + `ferrum-edge validate`
gitforgeops export [--output PATH]                   # flat YAML (placeholders kept) + mesh doc
gitforgeops export --materialize [--encrypt-to LOGIN] # resolve creds, age-encrypt (materialize-file.yml)
gitforgeops diff [--exit-on-drift] [--format text|json]  # desired vs live (/backup)
gitforgeops plan [--format text|json]                # validate + diff + breaking + security + best-practice
                                                     # + policy + adoption + apply blockers
gitforgeops apply [--auto-approve] [--allow-large-prune] [--confirm-api-spec-deletion] \
  [--allow-nontransactional-plugin-attach]
gitforgeops import (--from-api | --from-file PATH) --output-dir DIR \
  [--credential-bundle-output PRIVATE_PATH] \
  [--accept-unknown-field NAME]... [--allow-plaintext-plugin-config PLUGIN_NAME]...
gitforgeops review [--pr N] [--require-live] [--fail-on-blockers]  # PR comment
gitforgeops verify [--format text|json]              # declared traffic checks vs the data plane
gitforgeops doctor [--format text|json] [--scope local|github|gateway|all]... \
  [--repo OWNER/REPO] [--state-writer-app-id N]      # read-only readiness diagnosis
gitforgeops envs [--format json|text] [--include-scopes]  # envs / trusted CI namespace scopes
gitforgeops version [--format text|json]             # package version + build-time git metadata
gitforgeops rotate --consumer ID --credential KEY [--namespace NS] [--recipient LOGIN]  # api mode
```

`github` and `github-annotations` are the same validate format.

Global flags:

- `--env <name>` selects an environment from `.gitforgeops/config.yaml`.
  Fallbacks: `FERRUM_ENV`, then the only entry or `default_environment`.
- `--allow-credential-slot-remap` downgrades the credential slot-remap refusal
  (array shrink, dropped credential type, deleted Consumer, revived slot) to a
  report. See [Credential slot remaps](#credential-slot-remaps).
- `--allow-empty-namespace` demotes the empty-selection refusal (a
  `FERRUM_NAMESPACE` that selects zero desired resources while the tree is
  non-empty) from an error to a warning in `validate`, `plan`, `diff` and
  `apply`.

Both `--allow-*` flags are CLI-only on purpose, with no env var: accepting them
is a per-run decision, not a repository setting. The bundled apply workflow
never passes `--allow-credential-slot-remap`.

`import` requires `--output-dir`, which must be empty. API import requires an
explicit namespace filter. Both acknowledgement flags are repeatable and import
fails closed without them.

`--version` / `-V` print the Cargo package version. `version` adds build-time
git commit and `git describe` (`unknown` when built without `.git`).

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success. `review` stays 0 on offline apply blockers unless `--fail-on-blockers` / `GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS=true`. |
| 1 | Error. `plan` also exits 1 on offline apply blockers, invalid backup namespaces or live ownership conflicts. Empty-namespace refusals are 1, not 2. |
| 2 | `diff --exit-on-drift` found drift (`DRIFT_EXIT_CODE`). |
| 3 | `doctor` found a blocker (`DOCTOR_FAILED_EXIT_CODE`). |
| 4 | `verify` check failed (`VERIFY_FAILED_EXIT_CODE`). |
| 5 | `verify` had no declared check for the environment (`VERIFY_SKIPPED_EXIT_CODE`). Skipped is never a pass. |

## Build / Test / Lint

```bash
cargo build                                   # Debug
cargo build --release
cargo test --test unit_tests                  # single aggregated test binary
cargo test --lib                              # inline #[cfg(test)] modules in src/
cargo clippy --all-targets -- -D warnings
cargo fmt --all && cargo fmt --all -- --check
```

### Before Every Commit — MANDATORY

1. `cargo fmt --all`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --test unit_tests`
4. `cargo test --lib`

### CI routing

- `rust-ci.yml` reports its required status on every PR. It runs the four
  commands above (coverage measures both test targets) when the PR touches
  current **or previous** Rust/build input paths (`src`, `tests`,
  benches/examples, `build.rs`, `.cargo`, Cargo manifests/lockfiles,
  toolchain/lint config, `Dockerfile`) or a non-Rust file the unit suite reads
  or the binary embeds (`docs/quickstart.md`, `.gitforgeops/*.example.yaml`,
  `.github/scripts/audit_settings.py`).
- Unit tests never read the customer-owned `resources/` tree. Shipped-example
  checks use `tests/fixtures/shipped-examples/`.
- Resource-only PRs skip the Rust steps and run secretless `validate-pr.yml`.
- `trusted-pr-review.yml` is a default-branch `workflow_run`. It accepts only
  manifest-verified resource and overlay YAML, copies environment/policy routing
  from the protected branch, and runs a trusted binary with `FERRUM_NAMESPACE`
  set to one protected-branch namespace per job, intersected with the
  environment's protected namespace scope. `review --require-live` fails that
  job when live comparison is unavailable or the PR comment cannot be posted.
- Environments with `live_review: false` are removed before the
  Environment-bound matrix; file mode requires it. Fork PRs and new or remapped
  namespaces never enter the privileged live-read boundary.
- Rust is pinned to 1.98.0 in `rust-toolchain.toml`. External Actions use full
  commit SHAs.

## Architecture

### Pipeline

```
resources/<ns>/{proxies,consumers,upstreams,plugins,mesh}/*.yaml
  → loader::load_resources    kind-tagged Resource enum, incl. MeshConfig
  → overlays/<env>/...        apply_overlay object deep-merge (see Overlays)
  → assembler::assemble       AssembledOutput { gateway, mesh }; namespace
                              inference; merge_mesh_fragments;
                              normalize_proxy_backend_schemes (omitted scheme
                              → https on non-stream proxies, as Edge stores it);
                              normalize_consumer_credentials (object → array);
                              normalize_proxy_plugin_associations (scoped
                              attachments after namespace inference)
  → secrets::resolve_secrets  ${gh-env-secret:...} → values, in memory only, from
                              FERRUM_CREDS_JSON_FILE or FERRUM_CREDS_JSON; covers
                              consumer credentials, plugin config and modeled
                              Upstream.service_discovery secrets; never written
                              back to disk
  → policy::evaluate_policies
  → validate::standin         validator input only (see below)
  → validate / export / diff / plan / apply / review / rotate
                              gateway doc → FERRUM_FILE_OUTPUT_PATH
                              mesh doc    → FERRUM_MESH_FILE_OUTPUT_PATH
```

**Overlays.** Objects deep-merge. Arrays replace, except these, which merge by
identity: Proxy `spec.plugins` (`plugin_config_id`), Upstream `spec.targets`
(`host:port:path`), MeshConfig `spec.workloads` (`spiffe_id`) and
`spec.services` (`(name, namespace)`). Every other array, including all other
mesh policy lists, replaces.

### Validator hand-off

The shared runner used by `validate`, `plan`, `review` and `apply` passes the
full assembled gateway document to `ferrum-edge validate -m file` once per
distinct effective resource namespace, in lexical order.

- Each child gets an empty settings file, has inherited `FERRUM_*` variables
  scrubbed, and gets its own `FERRUM_NAMESPACE` from the document. The parent's
  filter is never forwarded.
- Edge filters by namespace before cross-resource checks, so every selected
  namespace needs its own pass. A truly empty document still gets one explicit
  `ferrum` pass; the parent `NamespaceScope` refusal for typoed filters still
  applies. The runner never passes Edge's `--allow-empty-namespace`.
- Schema failures from all passes are combined. Multi-pass diagnostics get
  namespace labels before secret scrubbing. Text/JSON/GitHub annotation formats
  are preserved.
- Mesh has its own `-m mesh` pass with a validation-only identity context
  (`FERRUM_MESH_ALLOW_NO_CA=true`, because `-m mesh` refuses a missing workload
  identity before reading the document and a CI runner is not a mesh node).
- `plan` / `review` treat validator execution failure as `ERROR` and exit
  nonzero, never as passed or skipped.

**Stand-ins** (`validate::with_validation_standins`). Credential leaves that are
*still* `${gh-env-secret:…}` placeholders after resolution get a deterministic
fake derived from the slot path: `gitforgeops-validation-standin-<64 hex>`,
`hmac_sha256:<64 hex>` for a `basicauth` `password_hash`, or
`<scheme>://…standin.invalid/<hash>` for endpoint-typed plugin fields. Reason:
`${gh-env-secret:alloc=generate}` is 30 characters and Edge's floor for
`jwt`/`hmac_auth` is 32, so a bundle-less fork PR would fail on the placeholder.

- Substitution happens on a **copy**, written only to the 0600 temp spec. No
  stand-in is ever exported, applied, delivered or written to state.
- On resolved snapshots, only slots the `ResolveReport` marks unresolved (canonical
  consumer and plugin slots) get stand-ins. Resolved or unreported values stay
  byte-for-byte, even with placeholder syntax. Consumer paths share the
  resolver's escaping and index-zero elision.
- The report-free API and file apply keep syntax-based stand-ins for unresolved
  publication documents. Modeled service-discovery fields are never replaced.

**Scrubbing** (`secrets::SecretScrubber`). It collects every non-placeholder
Consumer credential leaf (minus literal identities), every
`sensitive_string_paths` plugin-config leaf, modeled service-discovery secrets,
and — when paired with a `ResolveReport` — the value at every resolved slot,
even if it looks like a placeholder or has a nonsensitive field name. Those
bytes and their single-line re-encodings (base64, percent, JSON-escape,
single-quoted YAML) become `[REDACTED]` in the child's stdout/stderr;
`scrub_streams` is the one decision point. Non-credential diagnostics stay
intact. The whole stream is withheld (fail-closed) when:

- a secret is shorter than `MIN_SCRUB_LENGTH` (8 bytes);
- a secret is an `is_reencoding_hazard` (newline, CR, quote, backslash, `#`,
  `: `, edge whitespace, any control or non-ASCII character);
- a `FRAGMENT_SCAN_LENGTH`-byte run of a secret survives scrubbing and is not
  also in the scrubbed document.

`FRAGMENT_SCAN_LENGTH == MIN_SCRUB_LENGTH` is a compile-time assertion, so every
scrubbable length keeps fragment coverage. Reports never retain secret values.
File-mode apply validates its unresolved publication document without a report.

### Resource attribution and validator compatibility

The assembler always emits `labels: {provisioned-by: ferrum-edge-git-forge-ops}`
on Proxy, Consumer, Upstream and PluginConfig, keeping existing labels and an
existing origin. No opt-out. This needs a gateway and validator that include
ferrum-edge#5483; Edge 0.9.4 and earlier reject the labels.

`validate::compatibility` recognizes only a failed validator's unknown-`labels`
diagnostic (prefix `Validation error: Spec validation failed:`, with one of the
four kinds' expected-field signature). It prepends `gitforgeops error
[validator-resource-labels]` with the validator path (from the existing `which`
lookup), the upgrade remedy, and the alternative of pinning an older Git Forge
Ops. No version probe or version gate. Original output still goes through
scrubbing. All formats carry the message; `plan` and `review` keep their
validation-blocker verdicts; file apply refuses before publication. Mesh and
other schema errors are unchanged.

`check-validator-resource-labels.sh` runs after the installer verifies the
publisher and allowlisted SHA-256 digests. It validates
`tests/fixtures/validator-resource-labels.yaml` (all four kinds) with empty
settings and a clean environment.

- The daily validator-pin canary fails, and keeps its tracking issue open, on a
  stale digest or failed label acceptance.
- `validate-pr.yml` runs the same probe, including the unconditional
  `validator-pairing` job required by `gitforgeops-required-static-validation`
  (even on pin-only or code-only PRs and empty repositories).
- Both use the installer, probe and fixture from the protected default-branch
  `trusted-validator` checkout, with the candidate allowlist. The trusted
  supply-chain checker enforces their commands and ordering, so candidate
  probe/checker changes cannot approve themselves. The installer keeps its
  read-only token; the probe gets no GitHub token.
- An approved digest does not by itself prove schema compatibility.

### Gateway modes

Set via `FERRUM_GATEWAY_MODE`.

- **api** — admin REST: POST creates, PUT updates, DELETE removes, POST `/batch`
  for pure-add namespaces, POST `/restore` for full replace.
- **file** — flat YAML for a file-mode gateway, published atomically (temp +
  fsync + rename) with a `resource_counts` seal.

Mesh is file-only in both modes. There is no mesh admin API, so api-mode apply
validates the mesh document and prints a notice instead of pushing it.

### Apply strategies

Set via `FERRUM_APPLY_STRATEGY`. Incremental is safer (partial-failure
visibility, no destructive no-op replace). `full_replace` is stronger
(per-namespace atomic, removes drift). For environment-wide atomicity, scope
`full_replace` to a single namespace.

#### incremental (default)

Diff against `/backup`, then CRUD each changed resource in dependency order
(`operation_rank`: add/modify upstream + consumer → plugin config → proxy, then
deletes in reverse).

- Association comparison sorts IDs without deduplicating live data. Payloads
  and printed changes keep original order.
- After scoped plugin writes, one fresh backup per namespace suppresses proxy
  updates that already converged, while keeping required ownership assertions
  (including ledger adoption of unchanged exclusive rows).
- Deletes tolerate 404.
- **Pure-add namespace** → transactional `POST /batch` (create-only,
  all-or-nothing, chunked under the 1 MiB `BATCH_MAX_BODY_BYTES` cap), falling
  back to per-resource creates on 501.
- New proxies and their new scoped plugins need one create transaction by
  default, even in mixed namespaces. In a mixed namespace, a create group whose
  proxy references a PluginConfig whose write already failed is withheld and
  reported by name (proxy, failed plugin, withheld scoped plugins); every other
  group still goes through `POST /batch`. Dependency groups never split across
  chunks and are deterministic across input order.
- `order_incremental_diffs` shares cycle ordering with the plan/review/apply
  previews, which explain the batch requirement and the opt-in below.
- A failed proxy delete defers deletion of the plugins it references. Edge
  detaches references when deleting a plugin instead of rejecting the delete,
  so this order keeps a surviving proxy protected.

**`--allow-nontransactional-plugin-attach`** (or strictly parsed
`GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH=true`, default false) permits
proxy-then-plugin creates, only after batch 501/413. It warns that the proxy is
briefly published without its scoped plugin.

- Only the new cyclic associations are left out of the initial proxy POST. All
  other dependencies and intended associations stay intact.
- A failed attachment exits nonzero, keeps successful ownership records and
  defers pruning; the proxy can stay exposed until repaired.
- Other batch rejection statuses and ambiguous responses cannot use this path.
- Retargeting an existing plugin to a brand-new proxy still fails, even with the
  flag: Edge rejects the plugin update, the dependent proxy create is withheld,
  pruning is deferred. Stage the target separately or use exclusive full
  replace.

**Delete deferral.** Any incremental Add/Modify failure defers every planned
Delete in that namespace, including failed pending-create ownership assertions.
Other writes and namespaces continue under the usual fatal-error rules. No flag
bypasses this.

- `ApplyResult::deletes_deferred` and CLI counts separate deferrals from
  deletes; per-resource messages say what was kept and why.
- Deferred and failed deletes never enter `applied_incremental`, so the managed
  ledger survives and the run exits nonzero.
- Plan/diff/apply previews say pruning is conditional.
- A same-routing-key ID rename still conflicts on an unchanged retry: keeping
  the incumbent does not free its key. Keep its ID and modify it, stage a
  replacement on a distinct key, or plan a migration window. Incremental CRUD
  has no atomic route swap.

#### full_replace

POST `/restore?confirm=true` atomically **per namespace**, not environment-wide:
a failure after an earlier namespace succeeded is a partial failure. Every
namespace payload is built before the first mutation.

- The body carries the repo's desired rows **plus the complete live spec-owned
  graph**. `/restore` validates `api_specs.items` against the tagged
  proxies/upstreams/plugin configs in the same payload and rejects either half
  alone. It re-creates spec documents verbatim rather than re-extracting
  resources, so carrying both cannot duplicate rows.
- An **empty** spec section and all `gateway_trust_bundles` are omitted. The
  gateway reads `items: []` as a wipe, an absent spec section as "409 if live
  specs exist", and an absent trust section as "leave trust alone". Omission
  preserves concurrent updates.
- `--confirm-api-spec-deletion` is the only way to drop the spec graph. Trust
  bundles always survive.
- Refused before mutation: a spec graph that cannot be proven complete, a
  repo/spec ID conflict, cached data, or an unfamiliar top-level backup section.
- A non-empty `api_specs` section is wipe-and-reinsert, and the admin API has no
  `ETag`/`If-Match`/revision precondition. So the section is re-read (`GET
  /backup`) right before the POST, and that namespace's restore is abandoned if
  any spec document changed. This narrows the lost-update window to one round
  trip; it cannot close it.

#### Mutation safety (both strategies)

- A `GET /health` preflight runs before the first mutation, so a read-only
  plane fails once instead of N times.
- A sticky `X-Data-Source: cached` on any `/backup` blocks **all** mutations:
  cached fallback drops API-spec ownership metadata. `--allow-large-prune` does
  not bypass this.
- Create and batch POST errors are never retried blindly. An ambiguous outcome
  is checked against an authoritative (non-cached) backup (`LiveMatch`):
  - **exact** row live → an idempotent PUT declares repository ownership and the
    create is recorded;
  - row **absent** → the write did not commit; ordinary per-resource error, run
    continues;
  - row **present but different**, or no usable verification → run-stopping
    `AmbiguousMutation`.
- `resource_values_match` is a subset test (desired ⊆ live, minus server
  timestamps), so a gateway-populated optional does not look like a foreign row.
- **`pending_creates` journal.** A write-ahead journal closes the process-crash
  window without granting delete authority. Exact evidence triggers the PUT;
  an absent row stays retryable.
  - Because the match is a subset test, a row can also be an ordinary Modify.
    `dedupe_pending_assertions` drops the assertion whenever the diff already
    names the row (apply and every preview), so it is PUT exactly once.
  - A live row whose declaration disappeared is **forgotten with a warning** and
    handled by the mode's ordinary rules: shared reports it unmanaged and never
    deletes it; exclusive prunes it under the large-prune guard; full_replace
    never journals.
  - Nothing here may fail closed: CI is the only writer of `.state/<env>.json`
    and `state-guard.yml` blocks the hand edit a wedged journal would need.
  - The journal survives a process crash (`apply-on-merge.yml` commits state
    with `if: !cancelled()`). It does **not** survive workflow cancellation or
    runner loss; the next run's ordinary diff picks up the live row.
- After apply, a best-effort `GET /cluster` prints a convergence line.

### Mesh config

`kind: MeshConfig` fragments live under `resources/<ns>/mesh/`. They are not
gateway resources.

- All fragments fold into one standalone `{version: "1", mesh: {...}}` document
  (`apply::render_mesh_yaml`, `MESH_DOCUMENT_VERSION`), published to
  `FERRUM_MESH_FILE_OUTPUT_PATH` by `export` and file-mode `apply`.
- `merge_mesh_fragments`: collections concatenate in load order; `workloads`
  (`spiffe_id`) and `services` (`(name, namespace)`) also check identity —
  identical duplicates dedupe, conflicting ones are errors naming both
  fragments. Singletons must agree or error. The loader rejects duplicate
  fragment ids per directory namespace, and `assemble` repeats that check.
- `validate` / `plan` / `apply` run a second pass, `ferrum-edge validate -m
  mesh`, over the rendered bytes.
- Mesh never appears in `diff`; there is no live API to compare.

**Publication reconciles.** `apply::reconcile_mesh_file` is total over
`Option<&MeshConfigSpec>`. Removing the last fragment **retracts** the
destination by rewriting it as `{version: '1', mesh: {}}` — never by deleting
it. Edge's mesh file source fails with `mesh configuration file not found`, so
deletion would turn a policy retraction into a node outage; `MeshFileDocument`
accepts the empty mapping.

A retraction may touch the path only if both `MeshRetractionScope` gates pass:

1. The state ledger attributes the destination to this repo
   (`StateFile::mesh_document_path`). Canonical formatting alone is not
   provenance; unattributed files are reported and left alone.
2. The run covers the environment's publication scope
   (`ResolvedEnv::covers_environment`: unfiltered, or filtered only by the
   environment's own `namespace_filter`).

An ad-hoc `FERRUM_NAMESPACE` neither retracts (an empty selection is not
evidence of deletion) nor publishes (a subset would drop other namespaces'
fragments); it reports `NarrowedScope`. `apply::plan_mesh_publication` makes the
same decision without writing, so `plan` and `review` preview exactly what
`apply` does, and all print a `RETRACT mesh` line. Retraction failures are
errors. api-mode apply neither publishes nor retracts.

### Namespace handling

- `resources/<ns>/…` → `namespace: <ns>` unless the spec sets a non-default
  value.
- `FERRUM_NAMESPACE` filters load, diff, apply and import. API import requires
  it (or an environment `namespace_filter`) and handles one namespace at a
  time. Other commands process all namespaces when it is unset.
- `validate`, `plan`, `diff` and `apply` fail closed (exit 1) when the filter
  selects zero desired resources while the on-disk tree has at least one;
  `--allow-empty-namespace` demotes this to a warning. When filtered live
  inventory is empty only because the filter matched no live namespace, `plan`
  and `diff` say so in text and JSON.
- File-mode documents are document-wide. An ad-hoc `FERRUM_NAMESPACE` that
  drops any loaded resource from a file-mode environment is the
  `NarrowedFilePublication` apply blocker. An environment's own
  `namespace_filter` is its publication scope, not narrowing.
- API calls send `X-Ferrum-Namespace: <ns>`; `split_config_by_namespace()`
  groups operations.
- `BackupSnapshot::from_scoped_body` checks every resource's explicit wire
  namespace before deserialization can default it. A missing or foreign
  namespace refuses the snapshot for every API consumer, including confirmation
  reads (`diff`, `plan`, `apply` fail; `review` withholds comparison, and
  `--require-live` fails). The incremental loop refuses a diff entry whose
  namespace differs from the enclosing one. Repository YAML defaults are
  unchanged.

### Diff and review masking

Unresolved credential values are excluded from authoritative live comparison
**per leaf**, after resolution, including with empty or partial bundles.
Resolved-secret and sibling drift stay visible. Masking uses canonical slots
from the resolution report, not value syntax, so seeded secrets that look like
placeholders remain comparable. Modeled service-discovery diff values are
redacted even when they look like placeholders. The same rule covers plugin
config and service-discovery secrets in `diff`, `plan` and `review`. Missing
required values still block apply. Review markdown is bounded below GitHub's
API limit.

### Multi-environment (repo config)

`.gitforgeops/config.yaml` (closed version-1 contract) declares logical
environments. Each picks an overlay, `namespace_filter`, apply strategy,
ownership, `live_review`, monitoring and promotion. Set `live_review: false` for
file-mode environments. **No gateway URL, JWT or secret names** go in this file;
they come from the GitHub Environment of the same name. See
`.gitforgeops/config.example.yaml`.

Workflows run a matrix over `gitforgeops envs --format json` with `environment:
${{ matrix.environment }}`. Per-environment concurrency groups keep applies to
one environment from interleaving.

#### Unattended drift monitoring

`monitoring.unattended: true` makes `EnvironmentScope` report
`monitoring_environment = "<env>-monitor"` (`MONITORING_ENVIRONMENT_SUFFIX`), and
`drift-check.yml` binds that instead of the deployment environment. Default
`false` keeps the check on the deployment environment, where GitHub withholds
secrets until a reviewer approves; that is reported as `not_completed`, never
in sync. A deployment environment may not use the suffix (the settings audit
waives its required-reviewer rule for that shape).

Fences on the reviewer-free environment:

- Its deployment policy admits only the repo's exact default branch.
- `audit_settings.py` rejects a `<env>-monitor` holding
  `GITFORGEOPS_STATE_APP_PRIVATE_KEY`, `FERRUM_GH_PROVISIONER_TOKEN`,
  `SETTINGS_AUDIT_TOKEN` or `FERRUM_CREDS_BUNDLE[_N]` (names only, never values),
  and requires its base environment to exist.
- `check_supply_chain.py::monitoring_workflow_violations` rejects a
  `drift-check.yml` that binds any of those, holds a write permission, omits the
  outcome classifier, or runs any subcommand other than `diff`.
- `drift-check.yml` binds no credential bundle; `diff` excludes unresolved broker
  leaves per leaf. That is why `CREDENTIAL_BUNDLE_WORKFLOWS` is a subset of
  `PRIVILEGED_WORKFLOWS`.

Outcomes come from `.github/scripts/drift_report.py`: `in_sync`, `drift`,
`failed`, `skipped` (file mode), `not_completed`. Only `in_sync` is a successful
comparison; `drift`/`failed`/`not_completed` block; `skipped` does not. A matrix
entry with no record becomes `not_completed`. The settings audit also fails when
the newest successful `drift-check.yml` run is older than
`--monitoring-max-age-hours` (48), so a `cron:` entry alone proves nothing.
Ferrum Edge has no read-only admin role, so the monitoring JWT secret is
gateway-write-equivalent.

#### Freshness guard

`ferrum-apply-<env>` serializes `apply-on-merge.yml` and `rotate.yml`, but
`actions/checkout` still picks the *triggering* commit. A queued run would then
reconcile against a `.state/<env>.json` older than the ledger the previous run
published, and shared mode would read rows it never saw as "never managed".

So both workflows check out `ref: <default_branch>` with `fetch-depth: 0`, then,
in a **`Refresh protected branch and reject stale deployments`** step before any
build or gateway call:

1. re-fetch the branch and `git checkout --force -B <branch>
   refs/remotes/origin/<branch>` (stay on the branch; the ledger commit pushes
   it);
2. print the triggering SHA and branch head;
3. fail closed unless `git merge-base --is-ancestor` puts the trigger inside the
   head.

Binary, desired state and ledger all come from the refreshed checkout;
`GITHUB_SHA` for the apply is the refreshed head, matching
`state.last_applied_commit`. PR attribution (override label, credential
recipient) stays on the triggering merge.
`check_supply_chain.py::stale_deployment_guard_violations` enforces the shape
and step order.

Apply also runs `.github/scripts/deployment_scope.py classify`, which refuses
the queued run when the refreshed head changed a **deployment input**. This
binds the triggering PR's authorization and credential recipient to unchanged
executable and desired inputs.

- `DEPLOYMENT_INPUT_PATHS` is one list used twice: it is also
  `apply-on-merge.yml`'s `on.push.paths`, and
  `check_supply_chain.py::deployment_scope_violations` fails when they differ.
  Equality is the invariant: a change that supersedes a queued apply always
  schedules a replacement run, and a change that schedules nothing (docs,
  `tests/**`, an unrelated workflow) can never supersede one.
- The classifier is piped from the triggering commit into `python3 -I -` under
  `set -euo pipefail` (never via a temp file), so the refreshed head cannot
  approve its own helper or executable changes.
- `GENERATED_PATHS` (`.state/**`, `assembled/**`) is in neither half: apply
  writes them, so they must not reject a queued run or re-trigger the job.
- Operator recovery: `README.md#recovering-a-superseded-apply`.

### Staged promotion

`promotion.requires: <env>` moves an environment out of the parallel matrix into
a second phase. `apply-on-merge.yml` splits on
`EnvironmentScope.promotion_requires`: `null` = independent (same merge,
parallel jobs, own approval, own concurrency group); non-null = the `promote`
job. `RepoConfig::validate` refuses a missing predecessor, a self-reference, a
cycle, and any chain deeper than one stage (the predecessor must be
independent) — each would leave a job waiting on a record nothing writes.

Ordering is not authorization. `needs: [list-envs, apply]` is the coarse half;
`.github/scripts/promotion_record.py` is the precise half.

- Each apply writes `{environment, source_revision, apply_result, verify_result,
  authorized, run_id, actor, pull_request}` as an artifact.
- `require` refuses unless the predecessor's record exists, applied `success`,
  verified `success`, **and** recorded the revision this job will apply — or an
  ancestor that `deployment_scope.classify` finds differs only outside
  `DEPLOYMENT_INPUT_PATHS`. That clause matters: the predecessor's own ledger
  commit always moves the branch before the promote job refreshes.
- Only `success` authorizes. `skipped` (file mode, or `smoke.yaml` declares no
  check for the env), `not_run` (no `smoke.yaml`) and `cancelled` all block.
- The bound value is the source commit, never the assembled document (staging
  and production use different overlays).
- The promote job runs the same freshness guard and `deployment_scope.py
  classify`, so a deployment-affecting merge during staging verification refuses
  the promotion; that merge runs its own staging→production cycle. The ledger is
  still read from the refreshed head, so revision pinning cannot resurrect an
  obsolete `.state/<env>.json`.
- `check_supply_chain.py::state_writer_token_violations` checks
  `install < mint < commit` per privileged job, because both jobs carry it.

#### Traffic verification (`src/verify/`)

Checks are **data, never code**: a job holding deployment credentials must not
run arbitrary commands from a repository file, so the closed schema in
`.gitforgeops/smoke.yaml` is the whole execution surface.

- TLS is always verified. `FERRUM_TLS_NO_VERIFY` is deliberately not passed to
  `verify::runner`; a private CA goes in `FERRUM_GATEWAY_CA_CERT`. The
  data-plane base URL is `FERRUM_VERIFY_BASE_URL`.
- Header values are exactly one of `literal:` or `slot:`. An unresolvable slot
  fails the check instead of sending an empty header (which could make a
  `401`-expecting check pass for the wrong reason).
- Results carry name, method, path and status only. The body is never read.
- `validate`, `plan` and `apply` load `smoke.yaml` through `SmokeConfig::load`
  before any mutation, so a malformed or unknown-field check fails the preview.
  An absent file is fine.
- `runner::run_check` retries an ambiguous attempt (timeout, or any failure
  except a connect error) only when `SmokeCheck::replays_ambiguous_attempts`: an
  RFC 9110 idempotent method (`GET HEAD OPTIONS TRACE PUT DELETE`,
  case-sensitive) or explicit `replay_safe: true`. A wrong status is never
  retried.

Both deployment jobs end with `Fail on traffic verification failure`, after the
record is published and the ledger committed. A failed `verify` (exit 4 or 1)
fails the job even with no successor. A skipped verify (no `smoke.yaml`, file
mode, or exit 5 because `SmokeConfig::declared_checks` finds nothing for the
env) does not. The verify step maps exit 5 to a green step with
`result=skipped`; a green step without `result=passed` records `failure`.

`apply` with `FERRUM_CREDS_JSON_OUTPUT_FILE` clears that path first and writes
`per_shard` there only on completion (`secrets::write_bundle_handoff`: wrapper
shape, 0600, temp + fsync + rename, regular files only, never the input path).
The verify step points `FERRUM_CREDS_JSON_FILE` at it and fails if it is
missing, so a slot allocated by the same apply resolves.

### Ownership modes

Configured per environment.

- **`shared`** (default): the repo manages only what it previously applied. The
  state file is the fence; unknown gateway resources are reported *unmanaged*
  and left alone. `full_replace` is rejected.
- **`exclusive`**: the repo is authoritative for the listed `namespaces`.
  Unmanaged resources are pruned. Required for `full_replace`.

`load_and_assemble_all` enforces exclusive scope after overlays and namespace
filtering, before returning to any command. Gateway resources use their
effective namespace; mesh fragments use their directory namespace
(`AssembledOutput.mesh_sources` keeps each fragment's namespace and label
through merging, so `validate_mesh_scope` rejects unowned fragments even when
they only set a mesh-wide singleton). Diagnostics name `namespace/mesh/id`
(file stem fallback) and explain how to add ownership or move the fragment.
Inner workload/service namespaces do not grant ownership. An unowned exclusive
filter is rejected even when it selects nothing. This keeps the offline
ownership gate for `validate` and `export`, including materialization. Shared
mode is unrestricted.

#### Delete fence and large-prune guard

`diff::compute_diff_with_ownership` takes `previously_managed:
Option<&HashSet<String>>` of `namespace:Kind:id` keys from the state file:
`Some` = shared, `None` = exclusive.

- The large-prune guard refuses an apply that would delete more than
  `ownership.large_prune_threshold_percent` (default 25) **of the managed set**
  unless `--allow-large-prune`.
- Pending-create keys widen recovery namespace scope but are excluded from the
  managed set until an idempotent update asserts ownership.
- Before computing the ratio, authoritative backup evidence removes managed keys
  absent from both desired and live state, so externally deleted rows cannot
  dilute the denominator forever.
- Shared mode must keep reconciling namespaces the repo no longer declares
  (`reconcile::resolved_namespaces` unions declared and state-derived
  namespaces), or removing a namespace's last resource orphans it. Keep the
  fence in the state guard; never narrow what the binary reads from the ledger.

#### Adoption of already-matching rows

A declared resource identical to its live row yields no diff entry, so no
operation records ownership: it would stay outside the shared delete fence
forever. `apply::api_target::adoption_candidates` / `adopt_matching_rows` fix
this. At the end of an incremental apply, every declared `(namespace, kind, id)`
that is live exactly as declared, untouched this run, absent from
`ApplyOptions::managed_ledger`, and not `api_spec_id`-tagged is claimed and
recorded (`ApplyResult::adopted`, replayed through `StateFile::record_op`).

- **shared**: the same idempotent PUT as pending-create recovery (equality is
  not provenance), only against a *fresh* `GET /backup`. A row edited in between
  is skipped with a message (`ApplyResult::adoption_skipped`).
- **exclusive**: recorded without a PUT (keeps the fence correct if the env later
  switches to shared).
- **file mode**: `StateFile::record` stamps the whole desired set.
- **full_replace**: `record_full_replace` rebuilds the namespace.

Never adopt from a cached backup (it clears `api_spec_id`) or a spec-owned row.
A failed adoption PUT records nothing and lands in `ApplyResult::errors`. `apply`
prints `adoption_summary_line` plus per-resource lines. The interactive preview,
`plan` and `review` list `ADOPT <Kind> <id>` and explain the widened fence. The
shared `ownership_preview` also includes pending-create assertions, runs before
secret masking, and excludes full-replace and cached comparisons.

#### State file trust boundary

The state file is CI-authored. `apply-on-merge.yml` / `rotate.yml` commit
`.state/<env>.json` to `main` as `gitforgeops[bot]` with a short-lived,
contents-only GitHub App token. `.gitignore` tracks `.state/*.json` and ignores
only locks and temp files.

`state-guard.yml` fails any PR touching `.state/**` (including rename sources)
unless:

- the exact `gitforgeops/state-override` `labeled` webhook targets the current
  head, and
- its actor currently has `write`, `maintain` or `admin`.

It rejects every later push or PR transition until a qualified maintainer
removes and reapplies the label, and records actor, permission, head, run ID
and attempt. Label changes rerun the check so removed authorization cannot
leave a stale success.

- It uses `pull_request_target`, never `pull_request` (which would load the guard
  from the PR head, letting one commit forge a ledger entry and delete the
  check). That is safe only because the job never checks out the PR: files,
  labels and permission come from `gh api`, and `changed_files.py` from an
  explicit default-branch checkout.
- It runs on **every** PR with no `paths:` filter and decides internally. A
  path-filtered required check never reports on non-matching PRs and stalls
  them.

The guard runs on every PR through `pull_request_target`, without checking out
PR content; the changed-file list, labels and permission come from `gh api`,
and the only checkout is the default branch. It requires a fresh
`gitforgeops/state-override` `labeled` event for the current head by an actor
with current `write`, `maintain` or `admin` permission, and re-reads the PR's
head, base and label immediately before reporting success. The workflow has no
concurrency group: every delivery runs to completion, though a manual cancel or
runner failure can still interrupt one. On #407, branch protection read the
newest check suite; the guard is safe under that selection and under a model
that requires every suite's latest run to pass. `check_supply_chain.py` enforces
the trigger, checkout, no-concurrency and final-recheck requirements.
The launch baseline requires the check and gives only the dedicated App an
always-on `main` ruleset bypass. Repository variable `GITFORGEOPS_STATE_APP_ID`
(public; read the same way by workflows and the settings audit) and environment
secret `GITFORGEOPS_STATE_APP_PRIVATE_KEY` feed the commit workflows; both are
checked in a preflight before the gateway is mutated. See
`docs/github-launch-controls.md`.

#### Spec-owned tier

A third owner exists besides this repo and a human admin: the gateway's OpenAPI
**spec ingestion** (`/api-specs`), which provisions proxies, upstreams and
plugin configs tagged `api_spec_id: Some(...)`. Its re-imports are
authoritative, so gitforgeops stays off those rows in *both* ownership modes,
whatever the state file says.

Any **live** row with `api_spec_id` is `spec_owned` (`DiffResult::spec_owned`,
its own bucket, not `unmanaged`):

- **Never a Modify.** If the repo declares the same `(namespace, kind, id)`,
  that is a **conflict** (`DiffResult::spec_conflicts()`). A conflict blocks the
  whole **namespace** (`apply::spec_owned_conflict_block`); skipping only the row
  and exiting green would falsely claim convergence. Other namespaces still
  reconcile, and the reason goes to `ApplyResult::errors` (nonzero exit).
- **Never a Delete**, except exclusive mode with `--confirm-api-spec-deletion`
  (`DiffOptions::prune_spec_owned`). Otherwise skipped with a message and
  counted in `ApplyResult::spec_owned_skipped`. Shared mode ignores the flag.
- Rendered in `plan` / `diff` and the PR comment's "Spec-owned Resources"
  section, regardless of `ownership.drift_report`.
- Conflicts count as drift for `diff --exit-on-drift` (exit 2) regardless of
  `ownership.drift_alert_on`. Non-conflicting spec-owned rows never do. See
  `verdict::DriftVerdict`.
- `full_replace` carries live spec-owned rows and `api_specs` through unchanged
  (see [full_replace](#full_replace)).

### Unknown fields and opaque islands

The typed schema is fail-closed. Wrapper, resource and nested keys unknown to
this companion version are rejected with source file and YAML path before lossy
re-serialization. Intentionally free-form plugin `config`, credential *entry
values* and per-item mesh values round-trip unchanged to the gateway validator.
Consumer credential *map keys* are the closed built-in set
(`KNOWN_CREDENTIAL_TYPES`); unknown keys fail before apply and before import
publication.

**`FERRUM_ALLOW_UNKNOWN_FIELDS=true`** (`config::LoadOptions`, threaded from
`main`, never read inside the parse path) is the one escape hatch:

- Unknown **top-level** `spec` fields go into a `#[serde(flatten)] extra:
  BTreeMap` (`schema::PassthroughFields`) and flow verbatim through overlay →
  export → diff → apply, with one `Warning:` per file on **stderr** (stdout
  carries exported YAML).
- Nested unknowns stay fatal either way (`serde_ignored` still sees them).
- A pass-through key present only on the live side is not drift
  (`compare_fields` skips it). Declaring the key is how the repo takes ownership.

**Import inverts this**, because the value comes from the gateway and the broker
only redacts leaves it models:

- A non-empty `extra` on an importable resource is refused
  (`import::reject_import_passthrough_fields`). `--accept-unknown-field NAME`
  (repeatable) acknowledges one field and also requires
  `FERRUM_ALLOW_UNKNOWN_FIELDS=true`, or the strict loader would reject the files
  import just wrote. `ImportPassthroughPolicy` carries both; `split_config` is
  `strict()`. Acknowledged fields are named on stderr
  (`ImportResult::acknowledged_passthrough_notice`).
- Unknown credential map keys are refused
  (`import::reject_import_unknown_credential_types`,
  `unknown_credential_type_message`), no acknowledgement flag.
- Nested unknowns: `BackupSnapshot::from_value_with_strictness` records each
  skipped nested field (resource identity + `.spec…` path) in
  `unmodeled_nested_fields`, and `import::reject_import_unmodeled_nested_fields`
  fails file and API import before anything is written. No acknowledgement flag
  (the loader cannot represent a nested unknown). Read-only live comparisons
  ignore the list.
- Error text passes ids and field names through `diagnostic_metadata` (untrusted
  backup data).

**Apply refuses rewrites that would drop live-only fields.** The nested list is
copied onto `BackupExtras::unmodeled_nested_fields`. The live decode also always
keeps live-only unknown **top-level** fields in `extra` (whatever
`FERRUM_ALLOW_UNKNOWN_FIELDS` says), and `undeclared_live_top_level_fields` lists
every declared row's live `extra` key its declaration lacks (as `.spec.<field>`).
`apply::api_target::prepare_apply` blocks the **namespace**
(`unmodeled_field_block`, per namespace like the spec conflict block — never per
row, which would break dependency ordering) when an affected row will actually
be written:

- incremental: `incremental_rewrite_keys` = Modify diffs +
  `pending_create_assertions` + (shared only) exactly the rows
  `adoption_candidates` returns;
- full replace: every row of the `/restore` body. Preserved spec-owned rows are
  copied from live with `extra` intact, so only their nested fields can block.

An unchanged declared row needing no claim (always, in exclusive mode) must not
block, or a newly serialized defaulted field would wedge every apply. We refuse
rather than merge live values into a write, which would make the gateway, not
the repo, the source of those fields. A key the declaration names (possible
only under `FERRUM_ALLOW_UNKNOWN_FIELDS=true`) is sent and diffed normally, so
declaring it — or upgrading — is the remedy. **Never suggest "stop declaring the
row"**: in exclusive mode that deletes the live row.

- `prepare_apply` and `preflight_api_apply` take the `OwnershipScope`. A live
  view supplied without its `BackupExtras` is refused rather than skipping the
  check.
- `preflight_api_apply` returns per-namespace refusals (`BlockedNamespaces`,
  spec conflicts included). `cmd_apply` allocates credentials from
  `ResolveReport::without_namespaces` and journals creates only outside that
  set. The interactive preview prints it via `apply_blocked_namespaces` (same
  preparation, no `/health` probe).
- Later re-reads (post-plugin proxy snapshot, shared adoption confirmation,
  ambiguous-create verification) intentionally do not re-check.
- Offenders render through `http_client::describe_unmodeled_nested_fields`,
  capped at `MAX_LISTED_UNMODELED_NESTED_FIELDS` with `…and N more`.
- Keep `config::schema` nested structs in step with each ferrum-edge pin bump so
  live rows do not trip either refusal.

Corollaries of the no-silent-rewrites rule:

- YAML merge keys (`<<:`) are unsupported and surface as unknown field
  `.spec.<<`.
- Opaque islands are **JSON-shaped**: a non-string YAML mapping key is rejected
  (`strict::reject_non_string_keys`), not stringified.
- Every map serialized into an exported document or API body is a `BTreeMap`.
  `HashMap` re-seeds `RandomState` per instance, so output would change every
  run.

### Policy framework

`.gitforgeops/policies.yaml` declares standards. Each rule lives in
`src/policy/rules/` and implements `PolicyCheck`. Register new rules in
`src/policy/registry.rs::build_registry` and add typed config to
`src/policy/config.rs::PolicyRules`.

Rules (all default `enabled: false`): `proxy_timeout_bands`, `backend_scheme`,
`require_auth_plugin`, `forbid_tls_verify_disabled`, `allowed_proxy_plugins`,
`allowed_backend_domains`, `waf_enforcement`, `require_ai_guardrails`,
`rate_limit_completeness`, `plugin_name_is_known`, `priority_override_range`.
Enabled scheme, proxy-plugin and AI-guardrail rules reject empty or blank-only
governing lists with a blocking `PolicyConfig` error, whatever the configured
severity. Omitted AI guardrail names use built-in defaults.

#### Plugin catalog and auth coverage

`src/plugin_catalog.rs` holds plugin-name knowledge: 82 builtins, retired and
reserved names, the 10 auth plugins, rate-limit/observability/AI-guardrail
groups, and `effective_plugins` (a scoped config replaces a global one with the
same `plugin_name`). Rules that reason about plugins use it instead of
hard-coding names.

`auth_coverage` is the shared auth classification for `require_auth_plugin`,
the security audit and breaking-change detection, driven by one `AuthAllowlist`
(`effective_auth_allowlist`). Edge filters each request's plugin chain by
protocol, so a proxy is authenticated only when an authenticator runs on
**every** request protocol its listener serves
(`ProxyTransport::request_protocols`: HTTP, gRPC and WebSocket for HTTP-family;
TCP or UDP for stream listeners).

- `builtin_auth_protocols` mirrors Edge's `supported_protocols()`: `mtls_auth`
  covers everything, `soap_ws_security` plain HTTP only, the rest the HTTP
  family. Update it when the pinned Edge version changes.
- `spiffe_identity` is not an authenticator (extraction-only).
- Custom authenticators default to plain HTTP (Edge's trait default) unless
  `require_auth_plugin.custom_auth_plugin_protocols` declares them.
- A stream proxy is authenticated only if its listener terminates TLS/DTLS
  (`frontend_tls` without `passthrough`). An HTTP proxy with `passthrough:
  true` (which Edge rejects) fails closed: its authenticators are inert and
  cover no protocol.
- An authenticator carrying a `trigger` (`PluginConfig::is_conditional`) is
  `AuthCoverage::conditional` and covers no protocol, whatever its predicate:
  repository data cannot prove a trigger matches every request. An intentionally
  public route can use the exact code-owned
  `require_auth_plugin.conditional_auth_exemptions` identity; its finding stays
  visible at info, and missing or unnecessary entries are informational.
  Breaking-change detection still counts it as running (`AuthCoverage::running`), because
  consumer credentials apply on the requests it matches.

#### Security audit of plugin associations

The pre-resolve audit (`audit_security_with_scope`) uses the environment's
ownership mode:

- Errors in both modes: a reference to a declared global config, a reference to
  a proxy-scoped config that targets another/no proxy, and every `proxy_group`
  config with `proxy_id` (associated or not).
- A reference absent from this repo namespace: warning under
  `OwnershipScope::Shared`, error under `Exclusive`. Remedy: declare the config
  or confirm external ownership. Never detach a working association just to
  silence the warning.
- Assembly keeps invalid references visible. Edge stores disabled proxy-scoped
  associations (they do not satisfy auth checks), removes global associations
  on plugin writes and rejects explicit global references, so import preserves
  valid Edge graphs without rewrites.
- The report-free wrappers assume a complete document (exclusive). CLI
  plan/apply/review pass the actual scope.

#### Plugin-config secrets on import

`src/secrets/plugin_config.rs::classify_plugin_config` brokers builtin leaves
covered by `rules_for`. Secret-looking key/URL heuristic matches outside those
rules come back as `ImportResult::unbrokered_plugin_config`.

- The rule table is deliberately incomplete. Builtin fallback also flags
  compound `*_key` names and extra/outbound/additional header maps. Other
  builtin strings stay literal without a notice.
- Custom plugins: heuristic matches are brokered; unflagged strings need review.
- Both kinds of unbrokered string **fail the import**
  (`import::enforce_plaintext_plugin_config_allowance`) unless
  `--allow-plaintext-plugin-config <plugin_name>` (repeatable, exact match) is
  passed; then they are written literally and listed in a per-plugin notice. The
  refusal names the plugin id, `plugin_name` and every path, echoes no value,
  and writes nothing (no tree, no bundle).
- `sensitive_string_paths` still includes builtin heuristic matches for
  redaction and security checks. This gate is import-only; `apply`/`plan` are
  unaffected.
- Schema rules cover OAuth/OIDC client secrets and private keys, OIDC session
  encryption secrets, LDAP service-account passwords, and SOAP WS-Security Redis
  and UsernameToken credentials. Check additions against the gateway's OpenAPI
  schemas.
- `basicauth[].username` and `mtls_auth[].identity` are never brokered
  (`resolver::is_identity_credential_leaf`).

#### Policy overrides

Severity `error` blocks `apply` unless overridden. An override needs all of:

- the current configured PR label;
- its latest labeler's current permission ≥ `overrides.required_permission`
  (default `write`);
- that account's latest submitted review with exact body
  `gitforgeops-override <configured-label>`, APPROVED or COMMENTED, whose
  `commit_id` is the current PR head. A label event's `commit_id` is not a
  labeled-at head.

Actual desired/configuration bytes and executable source must match that head's
complete Git tree. Merged PRs also need merge ancestry; `.state/**` and
`assembled/**` are the only allowed post-review differences. Trusted review
splits candidate data from protected source via review-only
`GITFORGEOPS_OVERRIDE_SOURCE`; apply/plan always inspect their own checkout. All
paths use the authorization predicate in `src/policy/github_override.rs` and raw
input verification in `src/policy/override_input.rs`. Pagination and unknown
permissions fail closed. Audit entries record PR, review id, authorized head and
applied revision.

### Setup doctor (`src/doctor/`)

`gitforgeops doctor` answers "is this repo ready to deploy, and what is
misconfigured?" without provisioning anything.

1. **Never mutates.** No settings write, gateway write, credential allocation
   or state lock. `doctor::gateway` calls only `GET /health` (unauthenticated on
   Edge) and `GET /cluster` (proves the admin JWT).
2. **Never guesses.** `Status::Unknown` (check could not run: no
   administration-read token, no environment credentials) is never a pass, and
   the text report says so. `Skipped` means the check does not apply (file mode
   has no Admin API; a template has no deployment target), so a fresh template
   reads as unconfigured, not broken.
3. **Owns no baseline.** Repository settings are judged by running
   `audit_settings.py` — the same script `bootstrap_repo_settings.py` writes for
   and `settings-audit.yml` schedules — and republishing each violation as a
   `settings-control` check. Doctor runs the copy compiled into its binary
   (`python3 -I -c`), never the checkout's, with only `GH_TOKEN` and what
   `python3`/`gh` need.

Scopes are trust boundaries: `local` (no credential), `github`
(administration-read token), `gateway` (that environment's deployment
credentials, reads only). Default `local,github`; gateway is opt-in. Credentials
are reported by presence only (`Check::secret_presence` says presence is not
correctness). A 401 remediation prints the four JWT claim settings to compare.

### Preview verdicts (`src/verdict.rs`)

Two pure computations, shared so a preview cannot disagree with the run.

**`apply_blockers`** returns every fail-closed `apply` gate decidable without a
gateway, as `Vec<ApplyBlocker>` over ten `BlockerKind`s:

| BlockerKind | Gate |
|---|---|
| `Validation` | `ferrum-edge validate` rejected the document or could not run |
| `Security` | un-overridden error-severity security findings |
| `Policy` | un-overridden `error` policy findings |
| `RequiredCredentials` | `alloc=require` slot missing from the bundle |
| `SlotRemap` | slot remap without `--allow-credential-slot-remap` |
| `ProvisionerToken` | pending allocation, `FERRUM_GH_PROVISIONER_TOKEN` unset |
| `ProvisioningRepository` | pending allocation, `GITHUB_REPOSITORY` unset |
| `NarrowedFilePublication` | file-mode apply narrowed by ad-hoc `FERRUM_NAMESPACE` |
| `PublicationPathCollision` | gateway and mesh destinations resolve to one file |
| `InvalidSmokeChecks` | `.gitforgeops/smoke.yaml` exists but does not load |

- `plan` evaluates the whole set, prints `=== Apply Blockers ===` (class, count,
  remedy) plus a summary, and exits 1 when non-empty.
- `plan` and `apply` refuse `PublicationPathCollision` / `InvalidSmokeChecks`
  before assembly (`preflight_deployment_inputs`); only `review` surfaces them
  as blockers.
- `review --fail-on-blockers` uses the same computation for its exit code;
  default `review` renders the verdict and exits 0.
- `cmd_apply` calls the *same per-class predicates* (`security_blocker`,
  `policy_blocker`, `required_credentials_blocker`, `validation_blocker`,
  `credential_provisioning_blockers`) at its own gate points, because order
  matters: the security audit and the policy gate must refuse before the state
  lock and bundle read (the policy gate evaluates the unresolved document, as
  the security audit sees it); API mode evaluates policy again after credential
  resolution and before validation, using the resolved-slot report to scrub
  diagnostics. Both policy refusals include the same override guidance. The
  required-slot check runs before the first gateway call. Share predicates,
  not control flow.

Rules that must not drift:

- Warning severity never blocks.
- `alloc=generate` awaiting first-apply allocation is *not* a blocker
  (`missing_required()` is; `needs_allocation()` alone is not).
- `policy_findings` are fed **post-override** (`PolicyFinding::is_blocking`
  reads `overridden_by`). `plan` resolves the override through the same
  `resolve_pr_number` + `check_override` path as `apply` and fails closed: no
  PR, an inactive decision, or a GitHub error leaves every blocking finding.
- Gateway-dependent gates (large-prune, stale view, per-resource write failures)
  are excluded; a preview cannot decide them.
- Pending allocations need both provisioning variables (presence only; validity
  is a remote question). With nothing pending, neither is required. The
  secretless PR check has no bundle, so every `alloc=generate` slot reads as
  pending there. Apply checks at its allocation gate (after safety checks,
  before external writes, same refusal text); file apply also checks before
  publishing either document, while allocating only after placeholder
  publication.
- **Adding a fail-closed gate to `apply` means adding a `BlockerKind`**, or
  `plan` goes back to promising applies that refuse.

**`DriftVerdict`** decides when `diff --exit-on-drift` exits `DRIFT_EXIT_CODE`
(2). Managed add/modify, managed delete and unmanaged-added each honor their
`ownership.drift_alert_on` flag (defaults: modified and deleted on,
unmanaged-added off). **Spec conflicts** always count and cannot be muted.
Undeclared spec-owned rows are never drift.

### Credential broker (in-GitHub, no third party)

Consumer credentials use placeholders such as
`keyauth: [{ key: "${gh-env-secret:alloc=generate}" }]`. Slot names derive from
`(namespace, consumer_id, cred_key)` and are never hand-written.

#### Credential types and identities

Edge recognizes exactly five credential types, each an **array**
(`KNOWN_CREDENTIAL_TYPES`): `basicauth`, `keyauth`, `jwt`, `hmac_auth`,
`mtls_auth`.

- Unknown `credentials` keys (e.g. `api_key`, `basic_auth`) fail closed in
  `validate`, `plan`, `import` and the broker, with an error naming the key, the
  Consumer and the recognized set (`api_key` → `keyauth`, `basic_auth` →
  `basicauth`). `import` refuses before writing any tree file or bundle.
- The array form is canonical (`/backup` returns it; a bare object is permanent
  false drift). The assembler normalizes object form on load.
- Slot paths elide `ArrayIndex(0)` so normalization does not rename (orphan)
  existing slots; entries ≥1 get `[N]`. Older encodings stay in the read-only
  lookup candidate list.

`basicauth[].username` and `mtls_auth[].identity` are **identities, not
secrets**. `secrets::resolver::is_identity_credential_leaf(credential_type,
leaf)` is the single classifier, keyed on credential type plus leaf key
(carried through arrays; rendered diagnostic paths never decide it). It governs
generation/rotation, import capture (keep literal), `secrets::scrubber` (keep
readable) and `diff::security::check_literal_credentials` (never flag).

- `validate_identity_placeholders` rejects broker syntax in identity leaves
  before any read-only (including lenient) or mutating walk. The CLI also calls
  it in `load_and_assemble_all`, covering plain export and inspect-only apply
  before bundle reads, locks, validation or allocation; `rotate` loads through
  the same boundary. No allocation-mode, seeded-bundle or slot-remap exception.
  Diagnostics name only the slot and the literal-identity remedy.
- Mutating resolution works on a copy and commits only on success; any failure
  leaves the whole input unchanged.

See `docs/credential-identities.md` for the command-boundary audit.

#### Generation and rotation constraints

Shared by `resolver::check_generation_allowed` and the allocator, so `plan` and
generation agree:

- `jwt`/`hmac_auth` secrets need ≥32 chars (`len=` ≥ 24 entropy bytes).
- `basicauth` generation is refused in file mode; `basicauth/…/password_hash`
  in every mode (it is HMAC-SHA256 under the gateway's own secret).
- A plugin-config endpoint leaf (`secrets::plugin_config::endpoint_paths`, e.g.
  `ldap_auth.ldap_url`) is refused (random bytes have no scheme or host). Plugin
  walks record these in `ResolveReport::endpoint_slots`; the allocator checks its
  batch with `ResolveReport::check_generation_allowed_for`.
- A bundle value of `[REDACTED]` is refused.
- A Consumer secret whose bundle value equals the placeholder committed at
  that slot, or matches the `${gh-env-secret:…}` grammar at all, is refused
  (`resolver::check_consumer_secret_not_placeholder_text`, same shape as the
  `[REDACTED]` refusal: slot and reason, never the value). It is the one
  exception to "supplied means resolved": placeholder text is
  repository-known, low-entropy, and kept readable by the scrubber. Every
  Consumer lookup goes through it: validate, plan, diff, review, apply,
  `export --materialize`, and rotate's sibling resolve and publisher.
  Plugin-config and service-discovery slots keep provenance semantics.
- The allocator validates the whole candidate batch before GitHub key discovery,
  including direct callers and lenient reports. Structural types must match the
  slot. Non-generatable discovery secrets (`SD_SECRET_FIELDS`) and public
  identity fields are refused. Seeded secret slots resolve regardless of
  allocation mode; identity leaves reject broker syntax even when seeded.

`allocator::check_rotation_allowed` limits rotation to Consumer `keyauth/key`,
`jwt/secret`, `hmac_auth/secret` and api-mode `basicauth/password`, including
indexed entries. Both the CLI and `rotate_and_deliver` enforce it.

- `rotate` publishes Consumers only; PluginConfig/Upstream slots cannot be
  rotated even if they share a Consumer id. Plugin allocation via apply still
  works.
- Rotation PUTs the whole desired Consumer, so
  `diff::consumer_security_blockers` audits that unresolved row with apply's
  literal-credential gate before the bundle read, lock, secret write or gateway
  call; the publisher re-audits. A literal secret sibling is refused with no
  override (identities exempt): rotation has no reviewed revision to bind one
  to.
- Target placeholder, generation, namespace/ownership, sibling resolution and
  client construction all happen before secret writes. Publication reuses the
  preflight's Consumer snapshot.
- Sibling resolution, the publisher and `export --materialize` decide what is
  unresolved from `ResolveReport::unresolved` of the resolve that consumed the
  bundle, never by re-scanning bytes, so a seeded plugin-config or discovery
  value that looks like a placeholder is published byte-for-byte (a Consumer
  secret that is placeholder text is refused, see above).
- Externally issued secrets must be reissued, reseeded and applied. A value
  destroyed by an older rotation cannot be recovered from GitHub's write-only
  secret API.

#### Credential slot remaps

Slot identity is positional. `resolver::check_array_slot_identity` splits the
consequences by evidence:

- **Multi-entry brokered array** → `ResolveReport::warnings` (advisory). A
  reorder or prepend re-owns values but looks identical to steady state, so
  refusing would refuse every multi-entry credential forever.
- **Shrink** (bundle holds a slot at an index the array no longer has) →
  `ResolveReport::slot_remaps` and `Error::CredentialSlotRemap`. Cannot fire in
  steady state. `apply`, `export --materialize` and `rotate` refuse; `plan` and
  `review` resolve with `SlotRemapPolicy::Allow` to render it (`plan` then exits
  1). `--allow-credential-slot-remap` downgrades the refusal for the
  shrink-then-rotate sequence. Messages name slots, never values.
- **Omitted type**: a Consumer that drops a known type while the bundle still
  holds `ns/id/<type>` is the same as `<type>: []`
  (`check_omitted_credential_types`); re-adding it would resurrect the value.
- **Retired Consumers** need the ledger: `check_consumer_ledger` runs only when
  `ResolveOptions::consumer_ledger` has a `ConsumerLedger` (from
  `main.rs::consumer_ledger`). `plan`, `review`, the first resolve of `apply`
  and `export --materialize` pass one; `validate`, `diff`, `rotate` and the
  post-allocation re-resolve do not.
  - *Deleted Consumer*: the ledger records `ns/id` (resources or pending
    creates), the document does not declare it, and the bundle still holds
    `ns/id/<known-type>/…`. `ConsumerCoverage` mirrors mesh retraction scope:
    `Complete` (unfiltered), `Namespace(ns)` (the env's own filter), `Partial`
    (ad-hoc `FERRUM_NAMESPACE`; never deletion). A slot the ledger never
    attributed is a pre-seeded value, not a retirement.
  - *Revived slot*: a declared Consumer the ledger does not record resolves an
    `alloc=generate`/`alloc=rotate` slot from the bundle, so a reused id would
    silently inherit a retired credential. Exempt: `alloc=require` (operator
    seed) and an allocation `state.credentials` recorded after
    `last_applied_at` by this same apply (matching `AllocationBinding`; covers
    retrying an apply that allocated — even partially — and failed before
    recording the Consumer).
- **Plugin-config arrays** get the same split via
  `check_plugin_array_slot_identity` in both plugin walks. Their slots carry
  `[N]` for every entry (no index-0 elision), so only a stored index at or past
  the array length is a remap. Remedy: reseed the bundle (`rotate` is
  Consumer-only).

The bundle-update procedure for an intentional shrink: rotation replaces a value
at its current slot but does not remove that bundle key. Before shrinking or
shifting an array, move each surviving rotated value to its new canonical slot
in the private bundle and remove vacated keys, keeping unrelated entries.

#### Literal credentials

Literal (non-placeholder) consumer credentials block apply. `cmd_apply` runs
`diff::audit_security_with_policy` on the **unresolved** document before the
state lock, bundle read, and any gateway call, health preflight, allocation or
file publish, and refuses every `diff::security_blockers` finding. The escape
hatch is the policy override, resolved once and shared by both gates. `rotate`
audits the Consumer it publishes and `export --materialize` audits the whole
document before the bundle read; neither has an override, and an `apply`
override does not carry over. A number or boolean at a secret leaf counts as
literal.

#### Secrets outside `Consumer.credentials`

Two more places hold brokered secrets, each with a reserved slot kind (the `@`
prefix keeps them out of the credential-type keyspace):

- `PluginConfig.config` → `<ns>/<plugin-id>/@plugin-config/config/<path>`,
  classified by `src/secrets/plugin_config.rs`.
- `Upstream.service_discovery` → `<ns>/<upstream-id>/@service-discovery/<path>`
  (e.g. `ferrum/orders/@service-discovery/consul/token`). Modeled secret leaves
  live in one table, `src/secrets/service_discovery.rs::SD_SECRET_FIELDS`, read
  by import capture, resolution, diff redaction, validator scrubbing and the
  literal-credential audit. Today it holds only `consul.token` (marked
  `generatable: false`: only Consul mints one, so `alloc=generate` is refused).
  `consul.address`/`service_name`/`datacenter`/`tag` are identity; `dns_sd`,
  `kubernetes` and `mesh` have no secret field. `diff` redacts these leaves
  individually; `is_sensitive_diff_field` deliberately omits
  `service_discovery` so address and service-name drift stay reviewable.

#### Bundle storage and sharding

Values live in GitHub Environment Secrets `FERRUM_CREDS_BUNDLE[_N]`, each a JSON
object of `slot → value`. A bundle holds ~440 slots; a new shard starts when one
nears 40 KB (`BUNDLE_SOFT_LIMIT_BYTES`; GitHub's limit is 48 KB). Placement is
`sha256(slot) mod shard_count`, falling back to any shard with room.

- The layout is capped at `MAX_BUNDLE_SHARDS = 16` (~7,000 slots) because the
  "Load credential bundles" step binds every shard **by name**
  (`FERRUM_CREDS_BUNDLE` … `FERRUM_CREDS_BUNDLE_15`). A `toJSON(secrets)` spill
  would hand the step the admin JWT key, state-writer App key and registry
  token, and makes public-repo runs wait for manual approval.
  `bundle::reserve_shard` refuses to create shard 16.
- Raising capacity: change `MAX_BUNDLE_SHARDS` in **both**
  `src/secrets/bundle.rs` and `.github/scripts/credential_bundles.py`, and add
  `FERRUM_CREDS_BUNDLE_<N>` bindings to every `CREDENTIAL_BUNDLE_WORKFLOWS`
  entry (`apply-on-merge.yml`, `materialize-file.yml`, `rotate.yml`).
  `check_supply_chain.py` cross-checks them.
- Reads stay uncapped (`load_bundles_from_env`), so shards allocated under an
  older, higher ceiling still resolve; only new placements stop.
- `credential_bundles.py` reads the enumerated env vars (blank = unset),
  validates each as a JSON object of string → string, rejects a bundle name
  outside the bound range, and writes a new 0600 file without following or
  overwriting the destination; the step exports it as `FERRUM_CREDS_JSON_FILE`.
  Malformed input fails closed, never becomes an empty bundle. Inline
  `FERRUM_CREDS_JSON` is for small local tests.
- `bundle::parse_bundles_from_json` reserves the prefix: a `FERRUM_CREDS_BUNDLE*`
  key must round-trip through `shard_secret_name`, so `_0`, `_01` or `_+1` fail
  closed instead of overwriting a shard and losing slots on the next PUT.

#### Allocation

First apply or rotation: generate a random value → libsodium sealed box
(`crypto_box` seal) to the environment's public key → PUT
`repos/.../environments/<env>/secrets/FERRUM_CREDS_BUNDLE[_N]`. Needs
`FERRUM_GH_PROVISIONER_TOKEN` (GitHub App installation token preferred, PAT with
`Secrets: write` as fallback). Each shard PUT is its own external commit.

- `allocate_if_needed` journals every committed slot through
  `StateFile::record_allocation` and saves the ledger before returning, in API
  and file mode, on success and when a later shard fails
  (`AllocationFailure.partial` = exactly the committed slots). The journal is
  non-secret (slot, shard, recipient, run id) and never records an unwritten
  shard, so a retry resolves committed slots as pending and allocates only the
  rest.
- Each entry carries a `state::AllocationBinding` (`allocation_commit`,
  `allocation_recipient`). `ConsumerLedger::from_state` counts an entry as
  pending only when both equal the current run's; a missing value never matches
  (not even another missing one). `record_credential` (rotation) clears both. An
  unmatched entry is refused as a revived slot, with a hint.
- The revision is `GITFORGEOPS_ALLOCATION_REVISION`, bound to `github.sha` in
  every `apply-on-merge.yml` apply step
  (`check_supply_chain.py::allocation_revision_binding_violations`): the
  triggering merge survives a re-run, while the refreshed head moves with the
  failed attempt's state commit. Locally, the checked-out commit is used.
  `main.rs` resolves the binding once per command (`AllocationBinding::from_env`)
  for both ledger and journal.
- Only an **unset** `GITFORGEOPS_ACTOR` means no recipient;
  `AllocationBinding::resolve` refuses a set-but-blank or non-login value.
  `cmd_apply` resolves the binding before any state, bundle or network access.
  `rotate --recipient` and `export --encrypt-to` call
  `secrets::check_recipient_login` first.

#### Delivery

After allocation or rotation, the value is age-encrypted to the PR author's (or
dispatcher's) SSH public key from `GET /users/{login}/keys` and posted as a PR
comment or workflow output. The allocator discovers the key once per batch
(`discover_recipient_at`) and encrypts each slot locally with
`DeliveryRecipient::encrypt`. Discovery is unauthenticated and rate-limited;
never call it per slot. The author decrypts with `age -d -i ~/.ssh/id_ed25519`.

### Downstream template updates

A repo created from the template shares no history with upstream and builds
from its own checkout, so upstream images update nothing.
`.github/scripts/template_update.py` does a three-way comparison against
`.gitforgeops/baseline.json`. Operator runbook: `docs/template-updates.md`.
Invariants:

- Conflicts (`L ≠ B` and `L ≠ U`) are reported, never overwritten, and the
  baseline does not advance while one remains. `--keep PATH` is refused for a
  path not in conflict.
- `detect-baseline [--write]` finds the exact upstream commit whose managed
  files match (inexact needs `--accept-closest`), because a template copy
  inherits upstream's `baseline.json`. It lists local files with `git ls-files
  --cached --others --exclude-standard`, so ignored runtime files are not local
  edits.
- `CUSTOMER_OWNED` (`resources/`, `overlays/`, `.gitforgeops/config.yaml`,
  `.gitforgeops/policies.yaml`, `.state/`, `assembled/`, `.github/CODEOWNERS`)
  also applies to upstream's tree, so an upstream `.state/` file cannot
  overwrite a live ledger. `UPSTREAM_MANAGED` is the other fence.
- Every local read/write (`read_local`/`write_local`/`remove_local`) walks one
  component at a time with `O_NOFOLLOW` relative to the parent directory
  descriptor. A symlink or special file at or above a managed path (or at
  `baseline.json`) fails the run before any write. Non-normalized paths and
  non-regular upstream entries (mode `120000`, gitlinks) are refused. Writes are
  temp-file + rename, so a hard-linked destination is replaced, not written
  through.
- The upstream copy is a bare repo fetched with `+refs/heads/*:refs/heads/*` plus
  tags, with `gc.auto=0`, `maintenance.auto=false`, `core.fsmonitor=false`.
- `POST_ADOPTION_CHECKS` is printed by `apply` and asserted against
  `docs/template-updates.md`.
- Recovery is `git revert` of the adoption commit, never restoring an obsolete
  ledger (that is a separate state-override repair).

### Source layout

Only what the sections above do not already say.

- `src/main.rs` — async Tokio entry, command dispatch. `src/cli.rs` — clap
  parser. `src/version.rs` — version identity (`build.rs` git metadata).
- `src/doctor/` — `local.rs`, `github.rs` (delegates to `audit_settings.py`),
  `gateway.rs`.
- `src/config/` — `schema.rs` (typed Edge mirror, incl. `BackendScheme` legacy
  value folding and opaque `MeshConfigSpec` items); `strict.rs` (`LoadOptions`,
  unknown-field detection with YAML paths, non-string key rejection,
  lowercase-extension enforcement, the silent `OS_ARTIFACT_FILES` skip list kept
  in step with `.github/scripts/pr_input.py` by a Python test); `loader.rs`
  (sorted, error-propagating, symlink-rejecting walk); `assembler.rs`;
  `env.rs`; `repo_config.rs`; `resolved.rs` (repo config + env → one
  `ResolvedEnv`); `namespace_guard.rs` (empty-selection finding).
- `src/diff/` — `resource_diff.rs` (field-level changes in wire order;
  order-insensitive association comparison that detects live duplicates),
  `breaking.rs` (also flags a surviving proxy that loses an effective
  authenticator, projecting post-apply plugin configs so unmanaged/spec-owned
  rows survive), `security.rs`, `best_practice.rs`.
- `src/apply/` — `api_target.rs`, `file_target.rs`. One `(namespace, id)`
  `ResourceIndex` per kind serves desired and live sides, so pairing, adoption,
  pending-create recovery and batch readback never scan a document per row;
  `PreparedApply` borrows caller-supplied live views instead of cloning.
- `src/http_client.rs` — `AdminClient`: namespace-scoped JWTs, base64-PEM
  CA/mTLS, typed `ApiErrorBody`, endpoint-aware retry classification, 413 advice
  per request kind (restore body limit vs the 1 MiB batch cap), `Retry-After`,
  paginated lists, `BackupExtras`, `convergence_summary`.
- `src/import/` — `from_api.rs` (fetches all namespaces before publishing;
  refuses cached/cross-namespace backups), `from_file.rs`, `mod.rs::split_config`
  (captures every credential under its canonical slot; requires an outside-tree
  0600 credential import bundle when the source has credentials; emits
  deterministic `alloc=require` YAML plus a non-secret
  `.gitforgeops-import.json` inventory; percent-encodes a leading `_`/`%` in an
  id, since identity comes from `spec.id`, not the filename; publishes
  atomically into an empty output tree).
- `src/state.rs` — `.state/<env>.json`: managed keys, credential delivery
  metadata, shard count, override history, `mesh_document_path`, pending-create
  journal. `ResourceKeys` is the prebuilt `namespace:Kind:id` set.
- `src/reconcile.rs` — `resolved_namespaces`, `previously_managed`.
- `src/jwt.rs` — HS256 admin tokens. `src/verdict.rs` — `apply_blockers`,
  `DriftVerdict`.
- `src/diagnostics.rs` — shared log sanitizer (`sanitize*` and `safe*`
  adapters). Every diagnostic routes untrusted ids, namespaces, plugin names,
  YAML paths and gateway text through it: control characters and line
  separators become `U+FFFD`, output is bounded, and no line may start with
  `::`, so repository YAML cannot forge a workflow command.
  `import::diagnostic_metadata` delegates here. `validate`'s GitHub-annotation
  format and the PR comment do their own escaping.
- `src/error.rs` — `Error` enum (`thiserror`); every variant renders untrusted
  payloads through `diagnostics`, so `Display` is safe anywhere.

### Key design principles

1. **Fail-closed typed schema, explicit opaque islands.** See
   [Unknown fields and opaque islands](#unknown-fields-and-opaque-islands).
2. **Path-component sanitization.** `namespace` and `id` become filesystem paths
   during `import`; `import::safe_path_component` rejects `..`, `/`, `\`, NUL
   and empty strings before `Path::join`.
3. **No public credential oracles.** The ledger stores only managed-resource
   keys, a constant marker and non-secret delivery metadata. It never hashes
   resolved Consumers or credential values.
4. **Namespace-scoped operations.** Every API call, diff entry and
   breaking-change lookup keys on `(namespace, id)`, never `id` alone.
5. **Partial-failure visibility.** Incremental apply reports per-resource errors
   via `ApplyResult`; one failure does not abort the run.

## Key Environment Variables

See `.env.example` for the full list. Absent or blank values use defaults; any
present invalid enum, boolean or integer fails before loading resources or
credentials. Booleans accept `true|false|1|0`.

| Variable | Default | Notes |
|---|---|---|
| `FERRUM_GATEWAY_URL` | — (api mode: required) | `https://` only; `http://` needs `FERRUM_ALLOW_INSECURE_HTTP=true`; other schemes and embedded `user:password@` are refused, in `load_env_config` before any client exists. |
| `FERRUM_ADMIN_JWT_SECRET` | — (api mode: required) | ≥32 chars, matching Edge. |
| `FERRUM_ADMIN_JWT_ISSUER` | `ferrum-edge` | Must equal the gateway's issuer or every call is 401. |
| `FERRUM_ADMIN_JWT_ROLE` | `admin` | `viewer`/`operator`/`admin`. `/backup`, `/restore`, `/batch` and consumer CRUD are admin-only. |
| `FERRUM_ADMIN_JWT_AUDIENCE` | unset | `aud` emitted only when set; a gateway with no audience rejects tokens carrying it. |
| `FERRUM_ADMIN_JWT_TTL_SECS` | `3600` | Must be within the gateway's `FERRUM_ADMIN_JWT_MAX_TTL`. |
| `FERRUM_ENV` | unset | Environment fallback when `--env` is absent. |
| `FERRUM_NAMESPACE` | all namespaces | API import requires one. See [Namespace handling](#namespace-handling). |
| `FERRUM_ALLOW_UNKNOWN_FIELDS` | `false` | Keep unknown top-level `spec` fields; nested stay fatal. Does not lift apply's refusal to rewrite rows with undeclared live top-level fields — declaring the field under the flag does. |
| `FERRUM_GATEWAY_MODE` | `api` | `api` \| `file`. |
| `FERRUM_APPLY_STRATEGY` | `incremental` | `incremental` \| `full_replace`. |
| `GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH` | `false` | Same as `apply --allow-nontransactional-plugin-attach`. |
| `GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS` | `false` | Same as `review --fail-on-blockers`; the PR comment is identical either way. |
| `FERRUM_OVERLAY` | unset | `overlays/<name>/`. A configured missing directory is fatal; `resolved::validate_overlay_selection` names the environment, overlay and declaring file. |
| `FERRUM_EDGE_BINARY_PATH` | `ferrum-edge` on `$PATH` | Validator binary. |
| `FERRUM_FILE_OUTPUT_PATH` | `./assembled/resources.yaml` | File-mode gateway document. |
| `FERRUM_MESH_FILE_OUTPUT_PATH` | `./assembled/mesh.yaml` | Standalone `{version, mesh}` document. File-mode `validate`/`plan`/`apply` and `export --output` refuse, before any publication, state or broker write, when it resolves to the same file as the gateway document (`apply::ensure_distinct_publication_paths`: `./`/`..` spellings, symlinked parents and existing file identity all count). |
| `FERRUM_VERIFY_BASE_URL` | unset | Data-plane base URL for `verify`. |
| `FERRUM_TLS_NO_VERIFY` | `false` | Dev only. TLS stays on but any certificate is accepted. |
| `FERRUM_ALLOW_INSECURE_HTTP` | `false` | Dev only. Permits cleartext `http://`. |
| `FERRUM_GATEWAY_CA_CERT` / `_CLIENT_CERT` / `_CLIENT_KEY` | unset | Base64-encoded PEM. mTLS needs both cert and key. |
| `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `10` | TCP/TLS handshake cap. |
| `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `60` | End-to-end cap; raise for large `/backup` or slow `/restore`. |
| `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` | `10` | GitHub API. |
| `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` | `30` | GitHub API. |
| `FERRUM_GATEWAY_MAX_RETRIES` | `3` | Retries connection failures and transient responses for reads and idempotent PUT/DELETE. Backoff 500 ms·2^n (jittered) capped at 8 s, or `Retry-After` capped at 30 s. Create/batch POST responses are never retried; restore retries only an explicit `503 failure_class=connectivity` pre-commit failure. |

`FERRUM_TLS_NO_VERIFY` and `FERRUM_ALLOW_INSECURE_HTTP` are independent. Each
prints a loud stderr banner once per process, and both are refused when
`GITHUB_ACTIONS=true` unless the gateway host is loopback (`localhost`,
`127.0.0.0/8`, `::1`). `config::env::validate_gateway_transport` owns the rule.

## Testing

- `tests/unit_tests.rs` is the single integration test binary. Modules are flat
  files `tests/unit/<name>.rs`; a new one also needs `mod <name>;` in
  `tests/unit/mod.rs`.
- Use `tempfile` for filesystem tests.
- **No network.** `AdminClient::new` builds the client without connecting, so
  credential-validation paths need no mocking. GitHub Environment Secret
  adapters are driven against an in-process loopback stub in
  `tests/unit/github_api_tests.rs` through test-only origin injection
  (`fetch_public_key_at` / `put_environment_secret_at` /
  `allocate_and_deliver_at` / `rotate_and_deliver_at`). Production keeps the
  compiled-in `https://api.github.com`; there is no env-var override.

Fixtures (`tests/fixtures/`):

- Fixtures never carry literal consumer secrets. `simple-config/` uses
  `${gh-env-secret:alloc=require}`; `literal-credential/` is the negative case
  for the security gate. Others: `overlay-test/`, `backup/`,
  `shipped-examples/`, `validator-resource-labels.yaml`.
- `companion-schema/` has one file per kind populating **every** field mirrored
  in `src/config/schema.rs`. `companion_schema_tests.rs` loads it strictly,
  assembles, round-trips through export, and — by reading struct definitions
  from `schema.rs` — fails when a new mirrored field is not exercised. Add new
  fields to the fixture in the same PR. Values are illustrative only.
- `quickstart/` is the copyable half of `docs/quickstart.md` (the files the
  guide tells operators to write, plus its `.gitforgeops/config.yaml`).
  `quickstart_tests.rs` loads it strictly, applies the production overlay,
  audits it with the same `security_blockers` gate `cmd_apply` runs, and asserts
  **byte equality** between each fenced block in the guide and its fixture file.
  Edit guide and fixture together.
- `mesh-minimal/` is a MeshConfig with a required workload `selector` and the
  smallest workload/service set `ferrum-edge validate -m mesh` accepts.
  `mesh_minimal_tests.rs` asserts the rendered document keeps the selector. Do
  not change `companion-schema/` when editing it.

`validator_namespace_tests.rs` exercises the shared command paths with a
namespace-checking stub, and with the real validator when
`GITFORGEOPS_TEST_EDGE_BINARY` names one (otherwise those tests skip).
`rust-ci.yml` does not set it yet. Wiring it in must use the trusted installer,
the candidate checksum allowlist and the same pin as `validate-pr.yml`, and
requires a pinned validator that accepts resource labels. The installer
candidate is GitHub's newest published release (`GET /releases/latest`); the
trust anchor is the content allowlist, not the tag.

## Lifecycle acceptance (`tests/lifecycle/`)

Runs the product end to end: a real gateway (the same allowlisted binary the
validator installer fetches), a stdlib test upstream, the real binary and real
traffic. Details: `tests/lifecycle/README.md`. Invariants:

- `REQUIRED_SCENARIOS` in `.github/scripts/lifecycle_result.py` is the contract.
  `test_lifecycle_result.py` keeps it, `scenarios.py`'s `SCENARIOS` map and the
  README in step. Adding a fail-closed gate to `apply` needs a scenario, or the
  suite certifies less than ships.
- `release.yml`'s `authorize-release` accepts the newest successful run for the
  exact revision whose sealed result passes `lifecycle_result.py verify`. Only
  `passed` certifies; an unrun suite, another revision or gateway build, an
  unsealed (cancelled) record, a `skipped` scenario or a stale record is a
  refusal. `--gateway-allowlist` binds the gateway build to the revision's own
  checksum allowlist.
- Not a per-PR required check: it needs a gateway build, and an often-red check
  trains people to override it.
- Six scenarios (`credentials-generate-and-rotate`, `partial-failure-recovery`,
  `ledger-publication-failure`, `runner-interruption`,
  `scheduling-and-attribution`, `staged-promotion`) need a disposable GitHub
  repository or the fault-injecting proxy, so CI records them `skipped`. They
  count only through an attestation: `lifecycle.yml` dispatched on the release
  ref with the operator's sealed result as `github_acceptance`, merged by
  `lifecycle_result.py attest` only into scenarios the run recorded `skipped`,
  attributed to the dispatcher, and refused for another revision or gateway
  build or when older than the `verify` freshness window.
- Redaction happens at capture: `Harness.redact` over captured streams, `run.sh`
  over the gateway log tail; the test upstream never echoes a header or logs a
  request line.

## Development Guidelines

Repository-local agent skills, Claude rules and their dispatchers are guarded
by `agent-setup-policy.yml`, which validates candidate content with trusted
default-branch policy on every PR (read-only, stale runs cancelled per PR). The
required check is `Agent Setup Policy / validate-trusted-policy`. The root
orchestrator reviews the exact PR head and merges only after hosted CI passes
and actionable review threads are resolved; no separate Code Owner or
maintainer approval is required. Forks do not inherit repository settings.

- **No `.unwrap()` in production code paths** — use `?`, `.unwrap_or()` or an
  explicit match.
- **No `.expect()` unless failure is a genuine bug** (e.g.
  `serde_json::to_string` on a static `Value`).
- Return `crate::error::Error` variants via `?`; prefer a descriptive variant
  over `Config(String)` when the category is clear.
- New `FERRUM_*` env vars: add to `EnvConfig`, `load_env_config()`,
  `.env.example` and the doc block in `env.rs`.
- Schema additions: mirror the Ferrum Edge struct; optional fields get
  `#[serde(default)]` + `#[serde(skip_serializing_if = "Option::is_none")]`.
  Don't validate — ferrum-edge does.
- Config structs with a hand-written `Default` (`config/repo_config.rs`,
  `OverrideConfig` / `PolicyConfig` in `policy/config.rs`) use container-level
  `#[serde(default)]`, so the `Default` impl is the only definition of a
  field's default. Never add a per-field `#[serde(default = "…")]` beside one.
  `tests/unit/serde_default_tests.rs` asserts `{}` deserializes to
  `T::default()`. `StateFile` keeps required keys, so its `Default` routes each
  optional field through the same `default_*` fn its attribute names.

## PR Checklist

1. `cargo fmt --all` clean
2. `cargo clippy --all-targets -- -D warnings` clean
3. `cargo test --test unit_tests` and `cargo test --lib` pass
4. Agent/rule changes → `python3 .github/scripts/check_agent_setup.py` and
   `python3 -m unittest discover -s .github/scripts/tests -p 'test_agent_setup.py'`
5. No `.unwrap()` / `.expect()` in prod code
6. New env var → `.env.example` + `env.rs` doc block
7. Schema change → unit test in `tests/unit/schema_tests.rs`
8. Commit messages in imperative mood; branches `feature/…`, `fix/…`, `claude/…`
