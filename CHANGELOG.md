# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Pin the plugin catalog, `provisioned-by` vocabulary, and GitForgeOps resource-envelope fixtures
  to ferrum-contracts `contracts-edge-0.9.8`; unit tests now check vendored hashes and local
  conformance. No catalog or label drift was found against the pinned release.

### Security

- `require_auth_plugin`, the security audit and the shared auth-coverage
  classification no longer count an authenticator that carries a `trigger` as
  authentication for any protocol. A trigger limits the requests the gateway
  runs the authenticator on, and repository data cannot prove it matches every
  request. A proxy now needs an authenticator without a trigger on every
  protocol its listener serves, including when a scoped instance with a trigger
  replaces an unconditional global one. An intentionally public route needs
  the policy override. Breaking-change detection still treats a conditional
  authenticator as running. `require_ai_guardrails` also refuses conditional
  guardrails unless an unconditional enforcing guardrail is effective.
  `apply` evaluates policy before the state lock on the unresolved document,
  as the security audit sees it, and checks again after API credential
  resolution (GHSA-92v7-rq7m-pxfq).
