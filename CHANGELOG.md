# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Support the per-proxy `allow_path_parameters` option for HTTP-family routes
  and preserve the mesh service opt-in through mesh configuration output.
- The supply-chain policy accepts `FERRUM_ADMIN_JWT_VIEWER_SECRET` as the
  signing key of the scheduled drift check (`drift-check.yml`) and refuses it
  in every other workflow or composite action. A step that binds it must also
  bind the issuer, audience and TTL settings. During the move,
  `drift-check.yml` may still bind `FERRUM_ADMIN_JWT_SECRET`, and binding both
  keys is reported as a warning. The settings audit accepts either key in a
  `<env>-monitor` environment and warns when it holds both, and `doctor`
  reports the auditor's warnings as `WARN` findings. Secret names are matched
  case-insensitively, as GitHub resolves them, and a `secrets.<name>`
  reference not spelled in upper case is a violation. The next change binds
  the viewer key in `drift-check.yml` and removes the admin key from
  monitoring (#440).
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
  `review` and `apply` still read `GET /backup`, and the bundled drift-check
  workflow does not bind the viewer secret yet (#432).
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

- `FERRUM_GATEWAY_URL` and `FERRUM_VERIFY_BASE_URL` are GitHub Environment
  secrets, so no diagnostic echoes them any more (GHSA-pp23-79rj-gp54).
  Transport-validation errors report only the variable name and a
  `<value withheld: … is an environment secret>` placeholder — never the
  scheme, host, port or path — and the `GITHUB_ACTIONS` refusals no longer
  name the remote host. The admin HTTP client strips the request URL from
  `reqwest` failures (`without_url`) before formatting them, so a connection
  or timeout error no longer carries `for url (…)`.
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
