# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `diff` reads Ferrum Edge's `GET /config/export` with a viewer-capped
  credential when `FERRUM_ADMIN_JWT_VIEWER_SECRET` is set, and never uses the
  admin secret on that path; without it, `diff` keeps reading `GET /backup`
  with the admin credential. Secrets arrive as gateway-keyed fingerprints a
  viewer cannot reproduce. Declared secret-bearing fields (and every declared
  consumer's hidden-credentials fingerprint) are reported as unverified, never
  as in sync: JSON `in_sync` is `false` and `--exit-on-drift` exits 1 unless
  `--accept-unverified-secrets` is passed. Fingerprinted credentials the
  repository does not declare, and fingerprint-shaped values in non-secret
  fields, are still drift. New `--write-fingerprint-baseline` /
  `--fingerprint-baseline` record an export's fingerprints and report declared
  secrets that changed between two exports as managed drift; a rotated gateway
  key makes the baseline "not comparable", which is not authoritative either.
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
- Pin the Ferrum Edge validator and bundled gateway to v0.9.9, keeping earlier
  approved validator digests in the allowlist for in-flight pull requests.
- Report an authenticator-loss breaking change when an HTTP proxy is changed to
  passthrough, which Ferrum Edge rejects on non-stream proxies.
- Report `mtls_auth` loss when a stream proxy stops terminating TLS and becomes
  passthrough. Auth-loss reasons distinguish enabled authenticators that no
  longer run from proxies with no enabled authenticator.
- Include `CHANGELOG.md` and `.env.example` in downstream template updates so adopters receive
  release notes and current environment-variable examples.
- Pin the plugin catalog, `provisioned-by` vocabulary, and GitForgeOps resource-envelope fixtures
  to ferrum-contracts `contracts-edge-0.9.8`; unit tests now check vendored hashes and local
  conformance. No catalog or label drift was found against the pinned release.

### Security

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
