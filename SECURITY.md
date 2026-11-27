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

There is no supported GitForgeOps release until the
[release record](release/baseline.json) says `supported`; until then only the
`main` branch receives security fixes.

From 1.0.0 onward:

| Version | Security fixes |
| --- | --- |
| Latest minor release of the current major line (1.x) | Yes, as a new patch release and container image |
| Earlier minor releases of the same major line | No; upgrade to the latest minor, which is compatible within the major line by the [release policy](release/README.md#publishing-and-later-changes) |
| `main` | Yes; fixes land here first, but `main` is not a release |
| Revisions from before the first supported release | No |

A security fix that cannot be made without an incompatible change is called
out in its advisory and release note, with the operator action it needs.

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
of secret values (keyed on Ferrum Edge after v0.9.20 from the gateway's own
`FERRUM_ADMIN_CONFIG_EXPORT_FINGERPRINT_SECRET`, which no GitForgeOps process
holds). Handle the viewer secret like the admin one: an environment
secret, never logged, never committed. Unless the gateway sets
`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`, it reads every namespace. A fingerprint
baseline file holds only keyed fingerprints, but keep it outside the
repository.

The trusted supply-chain checker allows the viewer secret only in the
scheduled drift-check workflow (`drift-check.yml`) and refuses it in every
other workflow. The drift check requires the viewer binding and refuses the
admin secret, including when both are bound. Provision the viewer key in every
environment the drift check binds, with no admin secret in `<env>-monitor`; see
[Scheduled monitoring](docs/reference.md#scheduled-monitoring).

Repository fixtures follow the same rule. `tests/fixtures/simple-config/` is
the copy-paste sample and uses `${gh-env-secret:alloc=require}` (switch to
`alloc=generate` for first-apply allocation, as in
`resources/ferrum/consumers/_example.yaml`). The only committed literal
credential is in `tests/fixtures/literal-credential/`, a negative case that
`plan` and `apply` must refuse; it is not a sample.
