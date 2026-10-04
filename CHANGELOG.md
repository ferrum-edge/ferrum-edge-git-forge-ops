# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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
  still fails on unverified secrets and never certifies them as in sync; it
  adds no fingerprint-baseline storage (#440).
- `diff` reads Ferrum Edge's `GET /config/export` with a viewer-capped
  credential when `FERRUM_ADMIN_JWT_VIEWER_SECRET` is set, and never uses the
  admin secret on that path; without it, `diff` keeps reading `GET /backup`
  with the admin credential. Secrets arrive as gateway-keyed fingerprints a
  viewer cannot reproduce. Declared secret-bearing fields (and every declared
  consumer's hidden-credentials fingerprint) are reported as unverified, never
  as in sync: JSON `in_sync` is `false`, and `--exit-on-drift` exits 1 instead
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

- `diff --format json` gains two fields on every path: `live_source`
  (`backup` or `config_export`) and `secret_fingerprints` (`null` on the
  `/backup` path). The cached-read warning now names the source it came from,
  says the snapshot may predate the database, and the `--exit-on-drift`
  refusal reads "requires an authoritative backup (GET /backup)" or
  "requires an authoritative configuration export (GET /config/export)".
- `EnvConfig`'s `Debug` output redacts the admin and viewer JWT secrets, the
  GitHub tokens, the inline credential bundle and the mTLS client key.
- Pin the Ferrum Edge validator and bundled gateway to v0.9.10, keeping earlier
  approved validator digests in the allowlist for in-flight pull requests.
  The gateway refuses MCP requests with non-UTF-8 charsets and fails closed on
  uninspectable or over-nested JSON-RPC batches (GHSA-4f9m-cfqg-fhx9,
  GHSA-f2jp-59r9-fp64).
- Report an authenticator-loss breaking change when an HTTP proxy is changed to
  passthrough, which Ferrum Edge rejects on non-stream proxies.
- Report `mtls_auth` loss when a stream proxy stops terminating TLS and becomes
  passthrough. Auth-loss reasons distinguish enabled authenticators that no
  longer run from proxies with no enabled authenticator.
- Include `CHANGELOG.md` and `.env.example` in downstream template updates so adopters receive
  release notes and current environment-variable examples.
- Pin the plugin catalog, `provisioned-by` vocabulary, GitForgeOps resource-envelope fixtures,
  and the GitForgeOps-owned resource schema to ferrum-contracts `contracts-edge-0.9.9`; unit tests
  check vendored hashes, fixture deserialization, schema envelope fields, and compatibility with
  the qualified Ferrum Edge version.

### Security

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
- Pin libpcre2-8-0 10.46-1~deb13u3 into the runtime image to fix the HIGH
  CVE-2026-103111 finding while the pinned Debian base remains behind.
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
