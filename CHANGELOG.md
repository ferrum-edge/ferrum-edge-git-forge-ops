# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- `require_auth_plugin`, the security audit and the shared auth-coverage
  classification no longer count an authenticator that carries a `trigger` as
  authentication for any protocol. A trigger limits the requests the gateway
  runs the authenticator on, and repository data cannot prove it matches every
  request. A proxy now needs an authenticator without a trigger on every
  protocol its listener serves, including when a scoped instance with a trigger
  replaces an unconditional global one. An intentionally public route needs
  the policy override. Breaking-change detection still treats a conditional
  authenticator as running. `apply` now evaluates policy before the state lock,
  credential bundle read, secret resolution and validation, on the same
  unresolved document `plan` previews (GHSA-92v7-rq7m-pxfq).
