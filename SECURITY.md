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

Out of scope:

- the Ferrum Edge gateway itself (report those to
  <https://github.com/ferrum-edge/ferrum-edge>);
- repository settings this project documents but cannot enforce from source
  (branch rulesets, environment reviewers, Actions permissions).

See [Trust and security posture](README.md#trust-and-security-posture) for the
intended boundaries.

## Hardening expectations for operators

Placeholders (`${gh-env-secret:...}`) are the only supported on-disk form for
consumer credentials. Never commit literal secrets or unencrypted materialized
exports. Keep gateway and credential-broker secrets in GitHub Environment
secrets, scoped to the environment that uses them. For the full settings
baseline, see [GitHub launch controls](docs/github-launch-controls.md).

A process that only compares configuration needs no write authority. Give it
the gateway's `FERRUM_ADMIN_JWT_VIEWER_SECRET` (Ferrum Edge v0.9.9+) instead of
`FERRUM_ADMIN_JWT_SECRET`: `gitforgeops diff` then reads `GET /config/export`,
which the gateway caps at `viewer` and which carries keyed fingerprints instead
of secret values. Handle the viewer secret like the admin one: an environment
secret, never logged, never committed. Unless the gateway sets
`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`, it reads every namespace. A fingerprint
baseline file holds only keyed fingerprints, but keep it outside the
repository.

The trusted supply-chain checker allows the viewer secret only in the
scheduled drift-check workflow (`drift-check.yml`) and refuses it in every
other workflow. For now, that workflow may still bind the admin secret, and
binding both is a warning. The follow-up change (#440, step 2) binds the
viewer secret there, removes the admin secret from monitoring, and makes
binding it a policy violation. Before it merges, add
`FERRUM_ADMIN_JWT_VIEWER_SECRET` to every environment the drift check binds:
`<env>-monitor` when `monitoring.unattended` is true, otherwise the deployment
environment itself. Deployment environments keep `FERRUM_ADMIN_JWT_SECRET`,
because apply, review and rotate need it. See
[GitHub launch controls §3.1](docs/github-launch-controls.md#31-unattended-drift-monitoring).

Repository fixtures follow the same rule. `tests/fixtures/simple-config/` is
the copy-paste sample and uses `${gh-env-secret:alloc=require}` (switch to
`alloc=generate` for first-apply allocation, as in
`resources/ferrum/consumers/_example.yaml`). The only committed literal
credential is in `tests/fixtures/literal-credential/`, a negative case that
`plan` and `apply` must refuse; it is not a sample.
