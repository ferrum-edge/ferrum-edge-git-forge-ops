# Security policy

`gitforgeops` reconciles gateway configuration and brokers consumer
credentials from CI, so bugs in this repository can expose live secrets or
mutate a production gateway. Please report security problems privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
**Security → Report a vulnerability** (or
<https://github.com/ferrum-edge/ferrum-edge-git-forge-ops/security/advisories/new>).
Do not open a public issue or pull request for a security problem, and do not
include live credential values, JWT secrets, or gateway URLs in the report.

Include the version or commit you tested, the deployment mode (`api` or
`file`), the ownership mode, and the smallest resource/overlay layout that
reproduces the problem.

We acknowledge reports within five business days and keep the reporter
informed until a fix or a documented decision is published.

## Supported versions

Only the `main` branch and the most recent published release/container image
receive security fixes.

## Scope

In scope:

- the `gitforgeops` binary (`src/**`), including credential resolution,
  state handling, diff/apply reconciliation, import/export, and PR review
  rendering;
- the bundled GitHub Actions workflows and helper scripts under `.github/`;
- the published container image and its Dockerfile.

Out of scope: the Ferrum Edge gateway itself (report those to
<https://github.com/ferrum-edge/ferrum-edge>), and repository configuration
that this project documents but cannot enforce from source (branch rulesets,
environment reviewers, Actions permissions). The README section
"Trust and security posture" describes the intended boundaries.

## Hardening expectations for operators

Placeholders (`${gh-env-secret:...}`) are the only supported on-disk form for
consumer credentials; never commit literal secrets or unencrypted
materialized exports. Keep gateway and credential-broker secrets in GitHub
Environment secrets scoped to the environment that uses them.
