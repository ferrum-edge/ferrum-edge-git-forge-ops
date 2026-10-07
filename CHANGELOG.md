# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Credential-complete consumer verification and coherent conditional namespace
  snapshots for API mutations (#462). Sensitive response parsers validate identities,
  duplicate records, row-map coverage, strong opaque tokens, source/cache state and
  count seals without exposing credentials, tokens or response bodies. Doctor uses
  GET-only capability probes and reports unavailable evidence as unknown.
- Lifecycle coverage for hidden consumer edits and namespace restore conditions,
  including ABA, empty replacement and confirmed spec deletion. Qualification
  on the published Edge v0.9.13 release, content-pinned (SHA-256), remains
  required; an older fixture or passing parser tests do not establish first-release
  acceptance.
- A hosted consumer qualification check for Alloy's generated GitForgeOps
  resource trees ([Alloy #27](https://github.com/ferrum-edge/ferrum-alloy/issues/27)).
  The non-required `alloy-consumer.yml` workflow (consumer-surface pull
  requests, weekly and on demand) builds the immutable producer, generates
  both original manifest fixtures, and tests strict loading, assembly and real
  Edge validation through the shared runner and CLI. The producer is pinned by
  full commit SHA; mutated generated files cover transport and cross-namespace
  graph refusals, while generic loader refusals, nullable controls and the
  CLI's `api_spec_id` refusal run in the offline unit suite. The required validator-pairing job stays a fast install and
  probe with a 10-minute limit. Validator pins, protected install/probe
  bindings, credential protections and release qualification gates are
  unchanged.
- Support the per-proxy `allow_path_parameters` option for HTTP-family routes
  and preserve the mesh service opt-in through mesh configuration output.
- Scheduled drift monitoring binds only `FERRUM_ADMIN_JWT_VIEWER_SECRET`,
  with the issuer, audience and TTL settings. The protected policy requires
  those exact step-local bindings and refuses the admin key in the drift
  workflow and the viewer key in every other workflow or composite action.
  The settings audit requires the viewer secret name and forbids the admin
  secret name in `<env>-monitor`, even when both exist; it never reads secret
  values. Bootstrap guidance lists the viewer key for each bound API
  environment (the monitor environment for unattended checks, otherwise the
  deployment environment), while retaining deployment admin credentials.
  Operators must provision the distinct gateway viewer key before switching
  the workflow and remove the admin key from monitor environments. Namespace
  restrictions and approval gates remain in place. The bundled drift command
  never certifies unverified secrets as in sync; it adds no
  fingerprint-baseline storage (#440).
- `diff` reads Ferrum Edge's `GET /config/export` with a viewer-capped
  credential when `FERRUM_ADMIN_JWT_VIEWER_SECRET` is set, and never uses the
  admin secret on that path; without it, `diff` keeps reading `GET /backup`
  with the admin credential. Secrets arrive as gateway-keyed fingerprints a
  viewer cannot reproduce. Declared secret-bearing fields (and every declared
  consumer's hidden-credentials fingerprint) are reported as unverified, never
  as in sync: JSON `in_sync` is `false`, and `--exit-on-drift` exits 6 instead
  of 0 unless `--accept-unverified-secrets` is passed (drift found on a fresh
  read still exits 2; a cached read always exits 1). Fingerprinted credentials the
  repository does not declare, and fingerprint-shaped values in non-secret
  fields, are still drift. New `--write-fingerprint-baseline` /
  `--fingerprint-baseline` record an export's fingerprints and report declared
  secrets that changed between two exports as managed drift; a rotated gateway
  key makes the baseline "not comparable", which is not authoritative either.
  Whole values Edge fingerprints around a secret keep a run non-authoritative
  even with that flag or a baseline, and a declared consumer whose export lacks
  its hidden-credentials fingerprint is never verified. Brokered locations stay
  secret-bearing when a credential bundle resolves them. The export-only flags
  are refused when no viewer secret is configured. The viewer token is sent
  only over `https://`, or `http://` to a literal loopback IP address.
  Recording a baseline is refused when the run found drift unless
  `--force-baseline` is passed, and `diff` warns when a baseline path is inside
  a git worktree. A cached export (`X-Data-Source: cached`) never yields an
  in-sync or drift verdict and is never recorded as a baseline. `plan`,
  `review` and `apply` still read `GET /backup` (#432).
- Add exact, code-owned `require_auth_plugin.conditional_auth_exemptions` entries
  for intentionally public proxies. Exempted auth findings stay visible at
  `info`; stale entries are informational, while malformed, wildcard and
  duplicate entries are rejected.

### Changed

- Refresh the Ferrum Edge validator and bundled gateway pins to published
  v0.9.13: validator SHA-256
  `bdb8756c30bd2c04c3483ebff26bf0163ebeb0d5dfdc887897a7eb473305ed6c` and
  Docker Hub multi-platform index
  `sha256:6caa0987adb4c0a3a368fcd800bb0459cff3d3e219522e2e9c56280205862e50`.
  Retain all earlier approved validator digests for in-flight pull requests and
  preserve publisher-checksum verification. Edge release 404961860 was published
  at `9b83115de7ec23ab51ec4feae6bed65e596db425`; upstream release jobs passed.
  GitForgeOps hosted validation and exact-revision lifecycle acceptance remain
  required, the release baseline stays pending, and the conditional API
  implementation and `contracts-edge-0.9.11` pin are unchanged.
- Simplify the trusted checker's probe-binding rules (#476). The hand-written
  Bash lexer, expression renderer and rendered matrix/step-output source
  proofs are gone. In their place: the Verify traffic script and the credential-file
  hand-off in each `Load credential bundles` step are pinned line for line
  (comment lines are ignored unless they hold an expression), and every
  workflow is banned from spelling `GITHUB_ENV`, `GITHUB_PATH` or `BASH_ENV`,
  the runner's file-command file names (`set_env_`, `add_path_`,
  `save_state_`, `_runner_file_commands`), indirect expansion, the
  `github.env`/`github.path` contexts, or a redirect or `tee` into any GitHub
  file channel other than `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY`, outside
  that hand-off; those two may appear only as a plain `>>` or `tee -a` target
  (and the summary as `--summary`). Quotes, backslashes and line continuations
  are removed before matching, shell comments count, a `run:` interpolation
  may not adjoin a name character (with quotes removed), and an `env:` mapping
  may not be computed or bind `ENV` or a GitHub file destination. The
  Environment-bound workflows may interpolate into `run:` only a per-job
  allowlist, and each allowlisted value is pinned to its producer by exact
  job-output, matrix and producer-step pins (the enumerator step whole; the
  metadata step's hex-checked event SHA and its two SHA writes). Apply's
  hand-off keeps `id: load-bundles`, and Apply and Verify traffic must read the
  finalized bundle path from it. Outside the guarded Apply steps
  `apply-on-merge.yml` may invoke the binary only on the pinned `envs`,
  `validate` and `verify` lines; `$(command -v gitforgeops) apply` counts as an
  invocation. Protected bindings and the Validate/Apply/Verify flow pins are
  unchanged; the GitHub context-access rules now cover every workflow. The
  rules read workflow text only: a program a step runs (the binary, a helper,
  or Bash evaluating computed text) can still write `$GITHUB_ENV`, which is
  left to review of every workflow change. Some legitimate text now fails the check and must be reworded: a
  shell comment that names an env-file channel or a protected variable
  outside its pinned step, a redirect or `tee` into `$GITHUB_WORKSPACE/...`,
  any name containing `GITHUB_ENV`, `GITHUB_PATH` or a file-command prefix
  (such as `GITHUB_ENVIRONMENT`), an interpolation glued to a name
  (`v${{ matrix.version }}`), and indexed or whole `github` context access
  (`toJSON(github)`, `github.event.commits[0]`) in any workflow.
- `diff --exit-on-drift` exits with the new code `6` ("in sync, secrets
  unverified") instead of `1` when a fresh viewer-credential read found no
  drift in an alerted category and no fingerprint baseline was supplied, so the
  only gap is fingerprinted secrets the viewer cannot verify. `drift_report.py`
  records it as the non-blocking `in_sync_secrets_unverified` outcome, shown as
  a warning in the job summary and as a `::warning::` annotation, so scheduled
  viewer-only monitoring of an in-sync environment that declares secrets no
  longer fails every run and keeps the settings audit's monitoring evidence
  current. Drift still exits `2` and fails the workflow; a cached read, a whole
  value fingerprinted around a secret, a refused baseline write, and a supplied
  `--fingerprint-baseline` that cannot verify secrets (missing file, changed
  gateway fingerprint key, incomplete recorded namespace) still exit `1`.
  `--accept-unverified-secrets` still returns `0`; runs without
  `--exit-on-drift` and apply-time verification are unchanged (#471).
- Align `rust-toolchain.toml`, workflow Rust pins, and the Docker builder rule on
  Rust 1.99.0. The trusted supply-chain checker enforces a 1.99.0 minimum,
  rejects legacy `rust-toolchain` files and unsupported toolchain keys, and
  requires every Rust `FROM` stage to match the parsed channel used in release
  provenance, with exactly one stage named `builder` (#474).

- Refresh the existing 13-file ferrum-contracts adoption to published
  `contracts-edge-0.9.13` at `9626821eb089c71f5d4d71268c7b8276a8a5ab50`, with an
  explicit Edge v0.9.13 mapping and updated vocabulary byte hashes. The resource
  schema and ten fixtures are unchanged; plugin and attribution values remain
  unchanged. The new `backend-egress-policy` v2 and
  `admin-deployment-snapshot` v2 schemas are not consumed here. This pin update
  adds no deployment profiles or Alloy manifest/report consumption and does not
  qualify production apply or first-release acceptance.
- Mutation acknowledgements refuse duplicate keys, malformed field types and
  ambiguous envelopes without exposing response bytes (#462). Invalid responses
  cannot authorize retries, pruning, ownership ledger updates or rotation
  completion. DELETE 404 responses also validate any nonempty acknowledgement
  and cannot count `applied:false` as deletion; empty 404 and valid not-found
  responses remain accepted. Ordinary empty 204 acknowledgements remain valid;
  batch counts and conditional restore count seals still require complete matching
  evidence.
- Consumer modify/delete, ownership claims, pending-create and ambiguous-create/batch
  recovery require complete stored evidence. Rotation establishes health, ownership
  and representability before broker publication, then changes only the authorized
  credential with the original row `If-Match`; refusal after delivery reports
  recoverable divergence without recording completion. Basic HMACs remain opaque.
- Every full replacement uses the original coherent snapshot's namespace `If-Match`,
  including empty namespaces and confirmed API-spec deletion. The spec-only reread
  is removed. Proven precommit connectivity retries reuse the identical body and
  token; stale, unsupported and uncertain outcomes never retag or downgrade.
- API import uses exact conditional exports and refuses unsupported hidden/custom
  or legacy credentials before tree or bundle publication. Canonical file imports
  retain explicit provenance; conditional files require authenticated response
  headers. Ordinary diff, plan, review and viewer drift reads keep their endpoints.
- Incremental `apply` needs a gateway that issues strong `ETag` values for
  existing rows and honors conditional writes with `If-Match`. The released
  Ferrum Edge v0.9.6 source contains this capability
  ([source](https://github.com/ferrum-edge/ferrum-edge/blob/v0.9.6/src/admin/preconditions.rs),
  [PR 5661](https://github.com/ferrum-edge/ferrum-edge/pull/5661)); this does
  not establish an earliest or minimum version, or prove that a particular
  released binary contains or enforces it. Apply's preflight checks only for a
  strong `ETag` and refuses before credential allocation or writes when none
  is present; creates alone still work, and `doctor --scope gateway` reports
  `gateway-conditional-writes`. A server that ignores `If-Match` is not
  detected. Each modify or delete costs one extra `GET`. This capability does
  not qualify the gateway's backup or consumer representations: the lifecycle
  suite must pass against the exact released build, and pending representation
  fixes are not assumed released.
- Incremental `apply` takes one confirmation `/backup` per namespace instead of
  one per row whose single-row read differs from the plan (#475). A later
  mismatching read reuses the most recent backup only while that backup shows
  the row at the read's server `updated_at`; a row the gateway has rewritten
  since, including a proxy whose association this run's own plugin write
  changed, takes a fresh backup after the read. The plugin-reference guard adds
  a `/backup` read of its own before a plugin delete or retarget.
- `diff --format json` gains two fields on every path: `live_source`
  (`backup` or `config_export`) and `secret_fingerprints` (`null` on the
  `/backup` path). The cached-read warning now names the source it came from,
  says the snapshot may predate the database, and the `--exit-on-drift`
  refusal reads "requires an authoritative backup (GET /backup)" or
  "requires an authoritative configuration export (GET /config/export)".
- `EnvConfig`'s `Debug` output redacts the admin and viewer JWT secrets, the
  GitHub tokens, the inline credential bundle and the mTLS client key.
- Refresh the Ferrum Edge validator and bundled gateway pins to the verified
  published v0.9.12 binary and multi-platform image, resolving the installer
  refusal after the new upstream release. Keep every earlier approved validator
  digest for in-flight pull requests and preserve publisher-checksum verification.
  Upstream Edge artifact qualification is complete; GitForgeOps hosted validation,
  exact-revision lifecycle qualification and external acceptance remain required,
  so the release baseline stays pending. That gateway refresh left the conditional
  API implementation and then-current `contracts-edge-0.9.11` pin unchanged.
  The gateway retains v0.9.10 MCP charset and uninspectable or over-nested
  JSON-RPC batch hardening (GHSA-4f9m-cfqg-fhx9, GHSA-f2jp-59r9-fp64).
- Report an authenticator-loss breaking change when an HTTP proxy is changed to
  passthrough, which Ferrum Edge rejects on non-stream proxies.
- Report `mtls_auth` loss when a stream proxy stops terminating TLS and becomes
  passthrough. Auth-loss reasons distinguish enabled authenticators that no
  longer run from proxies with no enabled authenticator.
- Include `CHANGELOG.md` and `.env.example` in downstream template updates so adopters receive
  release notes and current environment-variable examples.
- Pin the plugin catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures,
  and the GitForgeOps-owned resource schema to published ferrum-contracts
  `contracts-edge-0.9.11` at `390edbd5b2485af0988e02f7827fde778d76ae0a`; unit tests check
  vendored hashes, fixture deserialization, schema envelope fields, and compatibility with
  the qualified Ferrum Edge version.

### Security

- Allowlist `run:` interpolations in every workflow (#495). GitHub renders a
  `run:` interpolation into the script before the shell parses it, and an env,
  matrix, input, job- or step-output or event value can carry text computed or
  chosen elsewhere (`env.A` set by `fromJSON(...)`, a pull request title), so
  refusing only computed expressions inside `run:` would be bypassed by
  indirection. A `run:` interpolation is now accepted only when it
  is exactly `github.event_name`, `github.sha`, `github.run_id`,
  `github.run_attempt`, `runner.os` or `runner.arch`, or in an
  Environment-bound job one of its existing per-job pins. Every key named `run`
  is read, so composite actions' `runs.steps` count, and each local action a
  workflow reaches is judged by the same allowlist (Environment-bound
  workflows' local actions still interpolate nothing). Pass any other value
  through step `env:` and read it as `"$NAME"`. The shipped workflows already
  comply.
- Close the remaining supply-chain checker residuals (#493). `env:` mappings may
  no longer bind any `LD_*` loader variable (`LD_AUDIT` included), and job and
  service containers may no longer set `options:` (whose `-e`/`--env`/
  `--env-file` would bind them for every step) or be computed, and their images
  must be pinned by `@sha256:` digest. Bash ANSI-C quoting (`$'...'`) is refused
  in every workflow scalar and reached local action, because it spells names by
  character code (`$'\x67'itforgeops`, `$'GITHUB_\x45NV'`) that no text rule
  decodes; escapes elsewhere are still stripped, so `GITH\UB_ENV` reads as
  `GITHUB_ENV`. `GITHUB_STATE` is refused anywhere, like `GITHUB_ENV`. The
  `apply-on-merge.yml` display-name exemption now covers only the `name:` of the
  workflow, a job or a step, not an action input or env value called `name`.
  Every action file under `.github/actions/` must be in the strict YAML subset,
  and its remote `uses:` are pinned from the parsed file in any key case. No job
  may run a local action after an `actions/checkout` of another ref or
  repository over the workspace root, and a local action may not make such a
  checkout. `.github/actions/**` is now a deployment input, a `security.yml`
  push path and code-owned, each required by the checker.
- Close supply-chain checker residuals (#487). A local action (`uses: ./...`)
  is no longer exempt and unread: every local reference must name, by a plain
  path, a composite action under `.github/actions/` with exactly one
  `action.yml` or `action.yaml`, reached through no symbolic link and inside the
  strict YAML subset, and each one a workflow reaches (also through another
  local action) is judged by that workflow's channel bans, protected names,
  `run:` interpolation rule and, in `apply-on-merge.yml`, binary pin. Any other
  local reference, including a local reusable workflow, fails closed. `env:`
  mappings at every level may no longer bind `BASH_FUNC_*`, `SHELLOPTS`,
  `BASHOPTS`, `PS4`, `LD_PRELOAD` or `LD_LIBRARY_PATH` (in any case), beside
  `ENV` and `BASH_ENV`. `apply-on-merge.yml` now reads every scalar outside the
  guarded Apply steps for the binary, including step and default `shell:`
  values and action inputs; only the pinned read-only `run:` lines and pinned
  display names may name it. The step with `id: load-bundles` in each apply job
  must be the one named `Load credential bundles`, and producer step ids compare
  without regard to case. The docs now name file-command paths discovered from
  the filesystem (`"$RUNNER_TEMP"/*/…`, `/proc/$$/fd`) as program-level, out of
  scope for text rules.
- Refuse a plugin config delete, or an update that moves its scope or target,
  when a proxy outside the plan references the plugin (#475). Ferrum Edge
  removes every association to a deleted plugin config, and every association
  but the target of a `proxy` or `global` one, and the plugin's `ETag` does not
  cover association rows, so a proxy that attached the plugin after the plan
  was silently detached. Apply now re-reads the namespace's `/backup`
  immediately before such a write and refuses it as `UnplannedPluginReference`
  when any referencing proxy is neither in the plan's live view, declared by
  the repository, nor the kept target; the namespace's remaining writes are
  withheld. A proxy that attaches the plugin between that read and the write
  is still detached: the gateway offers no association precondition, and only
  an Edge-side referenced-plugin guard inside the write transaction closes
  that window.
- Harden the trusted supply-chain checker. The strict workflow reader refuses
  folded block scalars (`>`, `>-`, `>+`) for every key except `if`: it joined
  folded lines with spaces where YAML keeps line breaks, so a folded `run:`
  could hide an env-file write behind a `#`. Every file in
  `.github/workflows/` must end in exactly `.yml` or `.yaml`. The required
  `security-cargo-audit` job is pinned by its parsed shape (job keys, every
  step, the exact trusted `run:` scripts; action commits and the Rust
  toolchain stay with their own rules), and `security.yml` may not set a
  workflow-level `env:` or `defaults:`, so a commented-out, skipped or
  swallowed audit command no longer passes. No job may be keyed or named like
  any required context (`state-guard-reject-state-edits` included) except that
  context's own job. Shipped workflows that folded a `run:` or `description:`
  now spell the same value on one line. Template repositories must rewrite
  their own folded scalars outside `if:` as literal (`|`) or one-line scalars;
  a copy with a customized `security-cargo-audit` job, a workflow-level `env:`
  or `defaults:` in `security.yml`, or an extra `security.yml` trigger (such as
  `workflow_dispatch`) now fails the checker too.
- Fail closed on ambiguous consumer verification 404s and remove unconditional update/delete methods.
- Complete the cargo-audit installer rotation to reviewed v2.87.22 commit
  `83ac0ad63c0167e6f06796fab0fce28db1bf3db0` after #465, retiring v2.87.20 while
  retaining cargo-audit 0.22.1, checksum verification and `fallback: none`.
- Pin the operator-held `FERRUM_VERIFY_PROBE_CONSUMERS` binding in both
  apply/promote Validate and Verify traffic steps and trusted live review,
  with `FERRUM_VERIFY_PROBE_CONSUMERS_BOUND: "true"` in Validate and review.
  The protected checker reads parsed workflow structure, including decoded
  YAML scalars, and refuses inherited/dynamic env sources, alternate bindings
  and shell rebinding. All protected operational workflows refuse whole or
  indexed GitHub context access, including computed env/path/output references
  that could inject `BASH_ENV`. In apply, the pinned credential-file hand-off
  is the only allowed `GITHUB_ENV` access. Validate must execute the pinned command
  unconditionally and propagate failure before either Apply mode. Changed
  job dependencies, nonblocking validation, reordered/extra inline mutations,
  alternate execution defaults and mutation conditions that bypass success
  are refused. Adversarial fixtures exercise both bypasses with the checker
  outside the candidate tree, and positive coverage retains the real pinned
  operations and safe step outputs (#453, #440).

- Release waits up to 900 seconds for pending or missing checks on the exact
  merged PR head, preserving source-bound required checks and lifecycle
  qualification. Every poll requires complete check-run history with consistent
  page counts and distinct, consistent run identities; passing CLI output cannot
  hide a missing newer retry (#459).
- Lifecycle admin and data-plane requests share a transport boundary that
  refuses all redirects, permits credentials only over HTTPS or HTTP to a
  literal loopback IP, and bypasses environment proxies for plaintext
  loopback. This covers both out-of-band admin helpers and consumer traffic
  probes without changing the gateway's conditional-write assertions.
- Incremental `apply` no longer overwrites or deletes a row from a stale plan.
  The plan comes from the `/backup` read before credential allocation and
  delivery, so every `PUT` or `DELETE` of an existing row (a modify, a delete,
  a pending-create, ambiguous-create or adoption ownership assertion, and a
  proxy update after scoped-plugin writes) is now conditional: apply reads the
  row with `GET /<kind>/{id}`, refuses it when it gained, lost or changed its
  `api_spec_id` or changed content since the plan, and sends the write with
  `If-Match` on the strong `ETag` Ferrum Edge v0.9.6+ returned. Edge refuses a
  row changed after that read with `412`, atomically with the write. A refusal
  is a per-resource error and withholds every later write in that namespace
  (its deletes are deferred and adoption is skipped); the run exits non-zero.
  A delete whose row is already gone is not sent. When the read differs from
  the plan only because `/backup` normalizes rows the read returns as stored,
  a `/backup` taken after the read settles it, so such a row is not refused
  forever. Consumers use `GET /consumers/{id}/verification` to compare complete
  credential evidence and row tags against the original plan, including hidden
  credential changes that `/backup` cannot show. A proxy read after
  this run's plugin writes ignores only the associations to plugin configs
  this run wrote, so a plugin someone else attached is never detached, and a
  scoped plugin can move off a proxy deleted in the same apply. A `412` that
  answers a retried `PUT` whose earlier attempt committed, shown by a re-read
  of the desired row, counts as applied. A cached read stops the run, and so
  does a read without a strong `ETag` (`ConditionalWriteUnavailable`), since
  an older gateway would ignore `If-Match`. An ambiguous create whose readback
  finds the declared content under an `api_spec_id` no longer claims that
  row. A new `conditional-overwrite` lifecycle scenario certifies the
  gateway's tags and `412` and an apply through them for every overwritten
  kind (GHSA-fh5w-5x4f-86gh).
- The admin client sends its bearer token, and the resolved credentials in
  request bodies, over cleartext `http://` only to a literal loopback IP
  (`127.0.0.0/8`, `::1`), never a hostname such as `localhost`. Every admin
  request retains the parsed, checked target through request construction,
  and the client refuses to build for a remote `http://` gateway or embedded
  URL credentials. HTTPS clients also enforce HTTPS at send time. Plaintext
  loopback clients bypass environment proxies, which could otherwise forward
  credentials to a remote host. `FERRUM_ALLOW_INSECURE_HTTP=true` no longer
  makes a remote cleartext gateway usable (CodeQL alert #298, PR #450).
- Capture one bounded, regular-file data snapshot for the cargo-audit gate's
  manifest, source reachability, Cargo graph, audit and independent yanked
  checks (#454). Original-file replacements can no longer redirect Cargo or
  split the checks across different lockfiles. Refuse symlinked source
  directories/files, special files, oversized source trees and local path
  dependencies. Check RSA reachability with all features and all targets,
  including optional direct RSA paths; hosted regressions cover a real offline
  Cargo graph, deterministic replacements and dangerous source inputs.
- Fail the cargo-audit gate closed when yanked-package verification cannot
  complete (#455). Independently verify every locked crates.io version's
  checksum and explicit yanked status against fresh sparse-index records;
  cargo-audit 0.22.1's JSON and exit status can otherwise omit an index or
  package-lookup failure. Reject workspace redirection for this single-package
  repository so Cargo's effective graph uses the audited root lockfile, and
  validate both bounded, regular-file Cargo inputs before any content read or
  Cargo invocation (#454). Isolate `HOME` alongside `CARGO_HOME` while keeping
  the runner's trusted rustup toolchain store. Complete-gate regression tests
  cover unsafe inputs, workspace redirects and incomplete index evidence.
- The cargo-audit policy gate no longer runs `cargo` from the candidate
  checkout (#448). `cargo tree` and `cargo audit` run from a fresh temporary
  directory with a fresh `CARGO_HOME`, take captured copies of the candidate's
  `Cargo.toml` and `Cargo.lock` through `--manifest-path` and `--file`, and drop
  inherited `CARGO_*`, `__CARGO_*`, `RUSTUP_TOOLCHAIN`, `RUSTC_BOOTSTRAP` and rustc
  wrapper variables. A pull request's
  `.cargo/config[.toml]` aliases or `[env]`, `.cargo/audit.toml` ignore list or
  advisory-database settings, and `rust-toolchain[.toml]` therefore cannot
  change the audit verdict or the RSA dependency-path check; the gate lists
  the candidate files it ignored. A missing or symlinked `Cargo.lock` or
  `Cargo.toml` is refused, and so is a temporary directory inside the
  checkout or below cargo or rustup configuration. Local runs of the checker
  therefore re-download the index, crates and advisory database each time
  and use the rustup default toolchain, not `rust-toolchain.toml`.
- New `supply-chain-policy.yml` reports a `trusted-supply-chain-policy` check
  whose definition the pull request under review cannot edit. It runs on
  `pull_request_target`, checks out the pull request's head as data, and runs
  only the protected branch's checker under `python3 -I` with `--root`, with
  `contents: read`, no secrets and a 10-minute timeout.
  `check_supply_chain.py`:
  - before reading anything, refuses a symlink in the judged tree that is
    absolute, whose target passes through another symlink or climbs above the
    tree root (followed component by component), that resolves outside the
    tree or does not resolve, any special file, and a `--root` that is itself
    a link;
  - requires every workflow to be in a small YAML subset, read by a strict
    stdlib reader before any rule runs. Anchors, aliases, tags, explicit and
    merge keys, quoted keys, flow mappings, an indented root, tabs, markers,
    directives and Unicode line breaks are refused. Block scalars and flow
    sequences are accepted only for listed keys;
  - pins every non-comment line of the new workflow except the
    `actions/checkout` commit;
  - refuses, on the parsed structure, any other job keyed or named
    `trusted-supply-chain-policy`, a computed job display name, and
    `checks`/`statuses` write (or `write-all`) in any workflow.

  The bootstrap now writes the new context alongside
  `security-supply-chain-policy` and binds every required context to the
  GitHub Actions app (`integration_id` 15368). The settings audit warns until
  the `main` ruleset requires the new context. It fails when
  `trusted-supply-chain-policy` or `state-guard-reject-state-edits` is
  unbound, so it is red after this merges until the operator re-runs the
  bootstrap, and it warns for the other unbound contexts. The release gate
  requires a reported result to pass. Add the context to the ruleset after
  this change merges (`docs/github-launch-controls.md`, "Switching the
  supply-chain policy check"). The `security-supply-chain-policy` job stays,
  unchanged, until a later change retires it (GHSA-x5m2-4555-q4cr).
- Upgrade note for repositories made from this template: every workflow in
  `.github/workflows/`, including your own, must now fit the YAML subset
  above, or the supply-chain policy check fails. Common forms to rewrite
  include `permissions: {}`, bracketed lists other than
  `branches`/`tags`/`paths`/`types`/`needs`/`workflows` (for example a
  matrix `environment: [staging, prod]` or `runs-on: [self-hosted, x]`),
  anchors and aliases, a multi-line plain `if:`, and `|2` block scalars. Use
  block style instead. The violation names the file and line.
- A queued rotation whose protected branch moved first prints a
  rotation-specific notice: the freshness guard's refusal text is written for
  apply, but no apply reschedules a rotation, so dispatch it again from the
  current head.
- Traffic checks can no longer spend arbitrary credentials from the
  environment's bundle (GHSA-8mhw-ghx8-9m63). A `slot:` header in
  `.gitforgeops/smoke.yaml` must name a Consumer credential secret slot
  (`<namespace>/<consumer-id>/<credential-type>/<field>` with a built-in type;
  plugin-config, service-discovery and identity slots are refused at load) on a
  `GET` or `HEAD` check. `verify` honours the slot only when it is a brokered
  `${gh-env-secret:...}` secret of a Consumer that a repository administrator
  lists in the new `FERRUM_VERIFY_PROBE_CONSUMERS` GitHub Environment variable
  (comma-separated `<namespace>/<consumer-id>`) **and** that the environment's
  desired configuration labels `gitforgeops/verify-probe: "true"`. The variable
  is the authorization, because no change to `resources/` or `.gitforgeops/`
  can change it (the protected supply-chain checker pins the workflow
  bindings, #453); the label lives in `resources/` and authorizes nothing
  alone. With the variable unset or empty, every check that sends a slot is
  refused; a malformed entry (anything
  but exactly one `/`) is an error. Anything else exits 1 before the bundle is
  read or any request is sent, and the runner (including `runner::run_check`)
  receives only the authorized values, never the bundle. `validate`, `plan` and
  `apply` refuse a slot whose Consumer is missing, unlabelled, outside the
  environment's own declared `namespace_filter` or, when the variable is
  visible to the run, unlisted, before anything changes; `review` reports it
  as `invalid-smoke-checks` and lists each check's header, slot and Consumer
  and every labelled Consumer, by name only. Steps bound to the environment
  also set `FERRUM_VERIFY_PROBE_CONSUMERS_BOUND: "true"`; there an unset, blank
  or malformed variable refuses a slot-sending check exactly as `verify` does,
  and `review` reports it as the separate `probe-consumer-allowlist` blocker
  for a repository administrator, not the pull request author. Without the
  marker an unset list is only "not visible". `apply-on-merge.yml` binds
  `vars.FERRUM_VERIFY_PROBE_CONSUMERS` into both `Validate` steps (with the
  marker) and both `Verify traffic` steps, and `trusted-pr-review.yml` into the
  live review (with the marker).
  `Host`, forwarding (`Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `Via`),
  method-override (`X-HTTP-Method-Override`, `X-HTTP-Method`,
  `X-Method-Override`), hop-by-hop and framing headers are refused in every
  check. Breaking: `smoke.yaml` is now `version: 2`; a `version: 1` file (or
  one with no `version`) that names a slot is refused so every slot is
  reviewed again. Create a dedicated, low-privilege probe Consumer, label it,
  list it in `FERRUM_VERIFY_PROBE_CONSUMERS` for each environment, and point
  slot checks at it.
- Traffic-check budgets are bounded (GHSA-p95x-q89j-hrhv). `attempts` is at
  most 10, `timeout_secs` at most 60 and `retry_backoff_ms` at most 30000; an
  environment declares at most 50 checks, and their worst case together (every
  attempt timing out, plus backoff) is at most 15 minutes. `validate`, `plan`
  and `apply` refuse a file over any bound before anything changes, and
  `review` reports it as `invalid-smoke-checks`. `verify` holds the run to that
  worst case plus 30 seconds and reports an interrupted or unstarted check as
  `TIMEOUT`, never a pass. Both `Verify traffic` steps in `apply-on-merge.yml`
  carry a step-level `timeout-minutes: 20` backstop; a step timeout fails only
  the step, so the ledger commit still runs.
- `FERRUM_GATEWAY_URL` and `FERRUM_VERIFY_BASE_URL` are GitHub Environment
  secrets, so no diagnostic echoes them any more (GHSA-pp23-79rj-gp54).
  Transport-validation errors report only the variable name — never the
  scheme, host, port or path — and the `GITHUB_ACTIONS` refusals no longer
  name the remote host. The admin HTTP client strips the request URL from
  `reqwest` failures (`without_url`) before formatting them, so a connection
  or timeout error no longer carries `for url (…)`, and a refused 3xx
  redirect is described only by how its `Location` relates to the configured
  base (same origin and a different path, a changed scheme, or another
  origin) rather than echoed — a normalized Location would evade GitHub's
  exact-value masking. `EnvConfig`'s and `ExportEndpoint`'s `Debug` output
  redact both URLs.
- Plugin-config credential slots now include the plugin type:
  `<ns>/<plugin-id>/@plugin/<plugin_name>/config/<path>` replaces
  `<ns>/<plugin-id>/@plugin-config/config/<path>`. A plugin that keeps its id
  and config path but changes `plugin_name` no longer resolves the previous
  type's stored secret. While the bundle still holds a slot of another type
  under that id, the change is a credential slot remap: `apply` and
  `export --materialize` refuse, and `plan` and `review` report it as
  blocking. `rotate` publishes Consumers only and never resolves a plugin
  config, so it is unaffected. Bundle keys in the old type-less form are never
  looked up.
  A declared plugin with the same id refuses on them until each value is
  reseeded under its typed slot (only if it was issued for that type) and the
  old key is removed. Import, diff and review masking, validator stand-ins and
  output scrubbing use the typed slot (GHSA-j6xj-prxm-wp2q).
- `rotate.yml` binds a queued rotation to the revision it was dispatched from.
  After taking the shared `ferrum-apply-<env>` lock and refreshing onto the
  current head of `main`, its freshness guard now also runs the
  trigger-pinned `deployment_scope.py classify`, as apply does. A rotation is
  refused before it builds anything, loads a credential bundle or writes a
  secret when a later merge changed a deployment input; apply's own ledger
  commits and other inert changes do not refuse it. Re-dispatch a refused
  rotation from the current head. `check_supply_chain.py` now requires the
  binding in every reconciling job of every freshness-guarded workflow, not
  only apply (GHSA-xwxm-vjgq-mxhj).
- The `security-supply-chain-policy` job runs the protected-branch checker
  under `python3 -I`, so no module in the pull request's checkout can load
  before the trusted policy. `check_supply_chain.py` requires the isolated
  invocation, exactly once, and rejects `PYTHONPATH`, `PYTHONSTARTUP` and
  `PYTHONHOME` in `security.yml`. `docs/github-launch-controls.md` now states
  that, until the required check moves to a workflow whose definition comes
  from the protected branch, a green result also depends on reviewing workflow
  changes (GHSA-x5m2-4555-q4cr).
- Repin the Debian Trixie runtime image to the current multi-architecture index.
  Keep the reviewed libpcre2-8-0 10.46-1~deb13u3 update because the published
  Trixie package index still lists the pre-fix u2 version; remove it after the
  base's installed package metadata confirms the fix is already present.
- Fail closed on HTTP passthrough proxies: Ferrum Edge rejects passthrough on
  non-stream proxies and rejects it with `frontend_tls: true`, so GitForgeOps
  does not count their HTTP authenticators. Set `passthrough: false` and
  terminate TLS at the gateway. Conditional-auth exemptions also refuse
  passthrough proxies.
- `require_auth_plugin`, the security audit and the shared auth-coverage
  classification no longer count an authenticator that carries a `trigger` as
  authentication for any protocol. A trigger limits the requests the gateway
  runs the authenticator on, and repository data cannot prove it matches every
  request. A proxy now needs an authenticator without a trigger on every
  protocol its listener serves, including when a scoped instance with a trigger
  replaces an unconditional global one. An intentionally public route needs
  the code-owned conditional-auth exemption. Breaking-change detection still
  treats a conditional authenticator as running. `require_ai_guardrails` also
  refuses conditional guardrails unless an unconditional enforcing guardrail
  is effective.
  `apply` evaluates policy before the state lock on the unresolved document,
  as the security audit sees it, and checks again after API credential
  resolution (GHSA-92v7-rq7m-pxfq).
- Neutralize both GitHub Actions workflow-command syntaxes in terminal output.
  Fenced validator diagnostics and resource IDs could reach stdout with `::`
  at the start of a line or the legacy `##[command]` form anywhere in a line,
  letting resource data forge annotations, add masks, fold logs, or suppress
  later output with `stop-commands`. Shared diagnostic sanitization now breaks
  both forms for validate, plan, apply and review terminal output, while the
  Markdown sent to the GitHub comment and step summary keeps readable text
  (GHSA-955f-64c5-hvfx).
