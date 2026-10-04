# CLI and configuration reference

Commands, exit codes, environment variables, secrets and review output for
`gitforgeops`. Setup lives in the [README](../README.md) and the
[Quickstart](quickstart.md).

Configuration comes from three places:

1. **`.gitforgeops/config.yaml`, `policies.yaml`, `smoke.yaml`** — committed.
2. **GitHub Environment Secrets** — gateway targets and credentials, per
   environment.
3. **Process environment variables** — runtime settings, mostly for local use.

## Commands

Global flags: `--env <name>`, `--allow-credential-slot-remap`,
`--allow-empty-namespace`. `--version` / `-V` prints the package version.

```
gitforgeops validate [--format text|json|github|github-annotations]
gitforgeops diff     [--exit-on-drift] [--format text|json]
                     [--fingerprint-baseline PATH] [--write-fingerprint-baseline PATH]
                     [--force-baseline] [--accept-unverified-secrets]
gitforgeops plan     [--format text|json]
gitforgeops apply    [--auto-approve] [--allow-large-prune] [--confirm-api-spec-deletion]
                     [--allow-nontransactional-plugin-attach]
gitforgeops export   [--output PATH] [--materialize] [--encrypt-to GH_LOGIN]
gitforgeops import   (--from-api | --from-file PATH) --output-dir DIR
                     [--credential-bundle-output PRIVATE_PATH]
                     [--accept-unknown-field NAME]...
                     [--allow-plaintext-plugin-config PLUGIN_NAME]...
gitforgeops review   [--pr N] [--require-live] [--fail-on-blockers]
gitforgeops verify   [--format text|json]
gitforgeops doctor   [--format text|json] [--scope local|github|gateway|all]...
                     [--repo OWNER/REPO] [--state-writer-app-id N]
gitforgeops envs     [--format json|text] [--include-scopes]
gitforgeops version  [--format text|json]
gitforgeops rotate   --consumer ID --credential PATH [--namespace NS] [--recipient GH_LOGIN]
```

| Command | Does |
|---|---|
| `validate` | Loads and assembles the tree, runs the security audit and `ferrum-edge validate`. `--format github` is an alias for `github-annotations`. |
| `diff` | Compares desired state with the live gateway: `GET /config/export` with `FERRUM_ADMIN_JWT_VIEWER_SECRET` when it is set, otherwise `GET /backup` with the admin credential. See [Viewer-credential drift reads](#viewer-credential-drift-reads). |
| `plan` | Shows what `apply` would do, and exits non-zero for every offline reason `apply` would refuse. |
| `apply` | Reconciles the gateway (api mode) or writes the assembled files (file mode). |
| `export` | Writes the assembled document; `--materialize` resolves placeholders, `--encrypt-to` age-encrypts the result. |
| `import` | Turns a live gateway or backup file into a resource tree. See [Adopting an existing gateway](../README.md#adopting-an-existing-gateway). |
| `review` | Renders (and with `--pr`, posts) the PR review comment. |
| `verify` | Runs the environment's declared traffic checks. See [Staged promotion](promotion.md). |
| `doctor` | Read-only readiness diagnosis. See [Setup doctor](../README.md#setup-doctor). |
| `envs` | Lists declared environments as JSON for CI matrices; `--include-scopes` adds each environment's namespace and monitoring scope. |
| `version` | Package version and build-time Git metadata. |
| `rotate` | Rotates one Consumer credential slot. See [Rotation](credential-broker.md#rotation). |

### Exit codes

| Command | Codes |
|---|---|
| all | `0` success, `1` error or blocking finding |
| `diff --exit-on-drift` | `0` in sync, `2` drift, `1` the check could not complete |
| `verify` | `0` all checks passed, `4` a check failed, `5` no checks declared (skipped), `1` could not run |
| `doctor` | `0` nothing blocking, `3` something blocking, `1` the diagnosis itself failed |

`diff --exit-on-drift` counts as drift: managed resources added, modified or
deleted, and unmanaged resources, each as enabled by
`ownership.drift_alert_on`, plus any API-spec ownership conflict, which cannot
be muted. With `--fingerprint-baseline`, a declared resource's secret that
changed since the baseline counts as a managed modification.

`--exit-on-drift` exits `1` when the read cannot support the result:

- **Cached read** (`X-Data-Source: cached`): always `1`, whether or not drift
  was seen, because the snapshot may be stale. Nothing overrides this.
- **Unverified secrets on a fresh read** (viewer-credential path): no
  `--fingerprint-baseline`, a baseline missing a namespace or a declared
  resource, or a gateway fingerprint key that changed since the baseline.
  Every declared Consumer counts here, because its hidden-credentials
  fingerprint can only be checked against a baseline.
  - Drift found: `2`, as usual. The drift is real; unverified secrets only
    undermine a "no drift" claim.
  - No drift found: `1`, because "in sync" cannot be claimed.
    `--accept-unverified-secrets` returns `0` instead.
- **Whole values fingerprinted around a secret** (viewer-credential path):
  Edge fingerprinted a value that only *contains* a secret (for example a
  plugin `headers` map holding an API key), and its non-secret contents were
  not compared. Drift found elsewhere: `2`. No drift found: `1`, and neither
  a baseline nor `--accept-unverified-secrets` changes that. JSON reports them
  as `secret_fingerprints.masked_ancestor_fields` with `authoritative: false`.

In JSON output, `in_sync` is `true` only when nothing differs, every declared
secret is verified, no whole value was fingerprinted around a secret, and the
read was not cached. The `/backup` path has none of these.
`--fingerprint-baseline`, `--write-fingerprint-baseline`, `--force-baseline`
and `--accept-unverified-secrets` are refused there (exit `1`), since they only
apply to the export.

### `plan` blockers

`plan` and `apply` share one blocker computation (`src/verdict.rs`), so a clean
`plan` never promises an apply that deterministically fails. `plan` exits `1`
and prints an `=== Apply Blockers ===` section for:

- gateway or mesh validation failing or not running;
- an error-severity security finding;
- an error-severity policy violation with no verified override;
- an `alloc=require` slot with no bundle value;
- an unacknowledged credential slot remap;
- pending allocation without `FERRUM_GH_PROVISIONER_TOKEN`
  (`provisioner-token`) or `GITHUB_REPOSITORY` (`provisioning-repository`);
- gateway and mesh file outputs resolving to one file
  (`publication-path-collision`);
- a `.gitforgeops/smoke.yaml` that does not load, or names a slot `verify`
  would refuse (`invalid-smoke-checks`);
- a check that sends a slot while `FERRUM_VERIFY_PROBE_CONSUMERS` is malformed
  in any run, or unset/blank in an environment-bound run
  (`probe-consumer-allowlist`, a repository administrator's fix);
- a live comparison finding declarations that collide with API-spec-owned
  rows.

Warnings never block. Gates that need a live gateway (the large-prune
threshold, a cached backup, per-resource write failures) cannot be decided by
a preview and are not included. Overrides are evaluated exactly as in `apply`;
without a PR every blocker stands.

`review` computes the same verdict and always shows it, but exits `0` by
default. `review --fail-on-blockers` (or
`GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS=true`) makes it exit `1` on blockers;
`--require-live` makes it exit non-zero when the live comparison or the PR
comment fails. The bundled workflows use `--require-live` for trusted live
review and leave static review as comment output.

### Namespace filters

`FERRUM_NAMESPACE` (or an environment's `namespace_filter`) limits a run to one
namespace. `validate`, `plan`, `diff` and `apply` refuse a filter that selects
no desired resources while the tree is not empty (exit `1`, naming the
namespaces on disk). `--allow-empty-namespace` turns that into a warning for
one run; there is no environment variable for it. In file mode, `plan` and
`apply` refuse an ad-hoc filter that would drop resources from the
document-wide file (`narrowed-file-publication`); set `namespace_filter` on the
environment instead.

API import needs a namespace filter and imports one namespace at a time, with
a JWT scoped to it.

### Credential recipients

`rotate --recipient`, `export --encrypt-to` and `GITFORGEOPS_ACTOR` (during
`apply`) must be a GitHub login: an alphanumeric character followed by up to
38 alphanumerics or hyphens, or a `[bot]` login. They are checked before any
state, bundle or network access. An unset `GITFORGEOPS_ACTOR` means no
recipient; a set but blank one is an error.

## GitHub Environment secrets

Set these per deployment environment (Settings → Environments, or
`gh secret set NAME --env <env>`):

| Secret | Required | Notes |
|---|---|---|
| `FERRUM_GATEWAY_URL` | api mode | Admin API base URL; must be `https://`. |
| `FERRUM_ADMIN_JWT_SECRET` | api mode | HS256 signing secret, at least 32 characters. |
| `FERRUM_ADMIN_JWT_VIEWER_SECRET` | api drift monitoring | The gateway's `FERRUM_ADMIN_JWT_VIEWER_SECRET` (Ferrum Edge v0.9.9+), at least 32 characters and different from the admin secret. `diff` then reads with it and never uses the admin secret. Required by the bundled drift workflow; see [Scheduled monitoring](#scheduled-monitoring). |
| `GITFORGEOPS_STATE_APP_PRIVATE_KEY` | yes | State-writer App private key. |
| `FERRUM_GH_PROVISIONER_TOKEN` | to allocate or rotate | App installation token (preferred) or fine-grained PAT with `Secrets: write` + `Environments: write`. |
| `FERRUM_ADMIN_JWT_ISSUER` | optional | `iss` claim; default `ferrum-edge`. |
| `FERRUM_ADMIN_JWT_ROLE` | optional | `role` claim; default `admin` (`viewer` and `operator` cannot do what GitForgeOps needs). |
| `FERRUM_ADMIN_JWT_AUDIENCE` | optional | `aud` claim; sent only when set. |
| `FERRUM_ADMIN_JWT_TTL_SECS` | optional | Token lifetime; default `3600`. Must fit the gateway's `FERRUM_ADMIN_JWT_MAX_TTL`. |
| `FERRUM_GATEWAY_CA_CERT` | optional | Private CA, base64 PEM. |
| `FERRUM_GATEWAY_CLIENT_CERT` / `FERRUM_GATEWAY_CLIENT_KEY` | optional | mTLS client pair, base64 PEM; both or neither. |
| `FERRUM_VERIFY_BASE_URL` | for traffic checks | Data-plane base URL for `verify`. |
| `FERRUM_VERIFY_PROBE_CONSUMERS` | when a check sends a `slot:` | An Environment **variable**, not a secret: comma-separated `<namespace>/<consumer-id>` of the probe Consumers a traffic check may spend. See [Probe credentials](promotion.md#probe-credentials). |
| `FERRUM_CREDS_BUNDLE[_N]` | written by the broker | Credential bundles, shards 0–15. See [Storage](credential-broker.md#storage). |

The JWT claim settings are optional to set, but when set they must match the
gateway exactly, or every admin call returns `401`. A blank secret means
"default", not "empty". The secret, issuer and audience are used byte for byte
(no trimming). `apply-on-merge.yml`, `rotate.yml`, `drift-check.yml` and
`trusted-pr-review.yml` bind all four claim settings; `materialize-file.yml`
binds none, because it never calls the Admin API.

Minted tokens also carry an `ns` claim listing the namespaces the run touches.
Only gateways running with `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true` read it,
and it is omitted when the run covers all namespaces.

`SETTINGS_AUDIT_TOKEN` (Administration: read) belongs to the separate
`settings-audit` environment, never to a deployment environment or the
repository. See [GitHub launch controls](github-launch-controls.md).

## GitHub Actions variables

| Variable | Default | Meaning |
|---|---|---|
| `GITFORGEOPS_STATE_APP_ID` | — | Numeric id of the state-writer App. Required for apply and rotate. |
| `FERRUM_GATEWAY_MODE` | `api` | `api` pushes through the Admin API; `file` writes assembled YAML. Other values fail the workflow preflight. |
| `GITFORGEOPS_RELEASE_ENABLED` | unset | Set to `true` to let `release.yml` publish from a repository other than upstream. |
| `DOCKERHUB_IMAGE` | `ferrumedge/ferrum-edge-git-forge-ops` | Docker Hub target for `release.yml`. |

## Environment variables

Blank values count as unset. Present values are validated before anything else
runs: unknown modes, bad booleans (accepted: `true`, `false`, `1`, `0`,
case-insensitive), malformed or zero numbers, and bad URLs are errors. See
[`.env.example`](../.env.example) for a local starting point.

| Variable | Default | Meaning |
|---|---|---|
| `FERRUM_ENV` | — | Environment from `.gitforgeops/config.yaml`; `--env` wins. |
| `FERRUM_NAMESPACE` | — | Limit the run to one namespace. |
| `FERRUM_OVERLAY` | — | Overlay to use when no environment is selected. |
| `FERRUM_GATEWAY_MODE` | `api` | `api` or `file`. |
| `FERRUM_APPLY_STRATEGY` | `incremental` | `incremental` or `full_replace`; repository config wins when an environment is selected. |
| `FERRUM_GATEWAY_URL` | — | Admin API URL. See [Transport security](#transport-security). |
| `FERRUM_ADMIN_JWT_SECRET`, `_ISSUER`, `_ROLE`, `_AUDIENCE`, `_TTL_SECS` | see [secrets](#github-environment-secrets) | Admin JWT settings. |
| `FERRUM_ADMIN_JWT_VIEWER_SECRET` | — | Viewer-capped signing key for `diff`. Issuer, audience and TTL settings apply to its tokens too; the role claim is always `viewer`. |
| `FERRUM_GATEWAY_CA_CERT`, `FERRUM_GATEWAY_CLIENT_CERT`, `FERRUM_GATEWAY_CLIENT_KEY` | — | Base64 PEM TLS material. |
| `FERRUM_TLS_NO_VERIFY` | `false` | Accept any gateway certificate. Local use only. |
| `FERRUM_ALLOW_INSECURE_HTTP` | `false` | Allow an `http://` gateway or data-plane URL. Local use only. |
| `FERRUM_CREDS_JSON_FILE` | — | Path to a credential bundle file: `{"FERRUM_CREDS_BUNDLE": {"<slot>": "<value>"}, ...}`. |
| `FERRUM_CREDS_JSON` | — | The same JSON inline, for small tests. A flat slot map is rejected. |
| `FERRUM_CREDS_JSON_OUTPUT_FILE` | — | Where a completed `apply` writes its final bundle (input plus new slots), mode 0600. Must differ from the input file. |
| `FERRUM_GH_PROVISIONER_TOKEN` | — | Token for writing environment secrets. |
| `FERRUM_FILE_OUTPUT_PATH` | `./assembled/resources.yaml` | File-mode gateway document. |
| `FERRUM_MESH_FILE_OUTPUT_PATH` | `./assembled/mesh.yaml` | Mesh document. Must not resolve to the same file as the gateway document. |
| `FERRUM_EDGE_BINARY_PATH` | `ferrum-edge` | Validator binary. |
| `FERRUM_VERIFY_BASE_URL` | — | Data-plane URL for `verify`. |
| `FERRUM_VERIFY_PROBE_CONSUMERS` | — | Operator allowlist of probe Consumers (`<namespace>/<consumer-id>`, comma-separated). `verify` refuses every check that sends a slot while it is unset; `validate`, `plan`, `apply` and `review` check it when set. |
| `FERRUM_VERIFY_PROBE_CONSUMERS_BOUND` | `false` | Set (`true`) only by workflow steps bound to the environment. Then an unset or blank allowlist refuses a slot-sending check in `validate`, `plan`, `apply` and `review`, as `verify` refuses it, instead of reading as "not visible". A malformed allowlist refuses any run that sends a slot, with or without this marker. |
| `FERRUM_ALLOW_UNKNOWN_FIELDS` | `false` | Keep unknown top-level `spec` fields. See [Writing resources](resources.md#supported-fields-and-unknown-fields). |
| `GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH` | `false` | Same as `apply --allow-nontransactional-plugin-attach`. |
| `GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS` | `false` | Same as `review --fail-on-blockers`. |
| `FERRUM_GATEWAY_CONNECT_TIMEOUT_SECS` | `10` | Admin API connect timeout. |
| `FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS` | `60` | Admin API request timeout. |
| `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` | `10` | GitHub API connect timeout. |
| `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS` | `30` | GitHub API request timeout. |
| `FERRUM_GATEWAY_MAX_RETRIES` | `3` | Admin API retries; `0` disables. See [Retries](apply.md#retries). |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY` | — | GitHub API access for reviews, overrides and allocation. |
| `GITFORGEOPS_PR_NUMBER` | — | PR to associate with the run (set by review workflows). |
| `GITFORGEOPS_ACTOR` | — | Credential recipient during `apply`. |
| `GITFORGEOPS_ALLOCATION_REVISION` | checked-out commit | Revision allocation records are bound to. |

GitHub API calls always go to `https://api.github.com`; there is no override.

## Transport security

The admin JWT travels in every request and `apply` sends resolved
credentials, so the transport is checked at startup, before any HTTP client
exists:

- `FERRUM_GATEWAY_URL` and `FERRUM_VERIFY_BASE_URL` must be `https://`.
  `http://` needs `FERRUM_ALLOW_INSECURE_HTTP=true`. Other schemes, and URLs
  with embedded `user:password@`, are always refused.
- `FERRUM_ALLOW_INSECURE_HTTP` and `FERRUM_TLS_NO_VERIFY` print a banner, and
  under `GITHUB_ACTIONS=true` are refused unless the host is literally
  loopback (`localhost`, `127.0.0.0/8`, `::1`). Put a private CA in
  `FERRUM_GATEWAY_CA_CERT` instead.

See also [GitHub launch controls](github-launch-controls.md#the-gateway-url-must-be-https).

## Validation and diagnostics

`ferrum-edge validate` runs with `-m file` (or `-m mesh`), `-s` pointing at an
empty settings file, and every inherited `FERRUM_*` variable removed, so a
stray setting cannot turn validation into a no-op. The temporary document is
mode 0600 with an unpredictable name. `plan` and `review` fail closed if the
validator cannot run: the result is `ERROR`, a schema rejection is `FAILED`,
and only a completed pass is `PASSED`.

**Secrets are scrubbed from validator output, not hidden wholesale.**
Credentials are resolved before validation, and the validator may echo them.
Every resolved or literal credential, sensitive plugin-config value and modeled
service-discovery secret, plus its base64 and percent-encoded forms, is
replaced with `[REDACTED]`. Identities (`basicauth` usernames, `mtls_auth`
identities) stay readable. The whole stream is withheld instead when:

- a secret is shorter than 8 bytes;
- a secret contains something an emitter would re-encode: a newline, quote,
  backslash, `#`, `: `, leading or trailing whitespace, or any control or
  non-ASCII character (rotate it to a single-line printable-ASCII value to get
  diagnostics back);
- an 8-byte run of a secret survives the scrub.

**Unresolved placeholders are validated through stand-ins.** Without a bundle
(for example on a fork PR), a placeholder is too short for a `jwt` secret and
is not a URL. Only inside the temporary validation file, each unresolved slot
gets a fake value of the right shape:

| Brokered leaf | Stand-in |
|---|---|
| `basicauth` `password_hash` | `hmac_sha256:<64 hex>` |
| other credentials, and token/header/secret plugin config | `gitforgeops-validation-standin-<64 hex>` |
| endpoint plugin config (`ldap_url`, `redis_url`, `jwks_uri`, ...) | `<scheme>://gitforgeops-validation-standin.invalid/<64 hex>` |

The scheme follows the field (`ldaps://`, `redis://`, `kafka://`, otherwise
`https://`). Resolved values are always validated unchanged. Stand-ins are
never exported, applied, delivered or stored.

**Workflow-command injection is blocked.** Resource ids, namespaces and
gateway responses can be attacker-controlled. All diagnostics pass through one
sanitizer (`src/diagnostics.rs`) that replaces control characters and line
separators and prevents any line from starting a `::command::`. The
`github-annotations` format is the one deliberate exception, and it
percent-encodes its data.

## PR review output

`review` renders one comment. It starts with an **Apply verdict**: whether
apply is blocked, and counts for validation, security findings, policy
violations, spec-owned conflicts, slot remaps and broker slots. Then, as
applicable:

| Section | Contents |
|---|---|
| `## Ferrum Edge Config Review` / `### Validation: PASSED` | Gateway and mesh validation (`PASSED`, `FAILED` or `ERROR`). |
| `### Changes` | Add / Modify / Delete per resource, or `None (in sync)`. |
| `### Breaking Changes` | Changes that can break live traffic (below). |
| `### Security Findings` | Audit findings; blocking ones marked. |
| `### Best Practice Recommendations` | Advisory notes. |
| `### Ownership Adoption` | `ADOPT <Kind> <id>` entries. |
| `### Unmanaged Resources (shared mode)` | Live rows the repository does not manage. |
| `### Spec-owned Resources` | Rows owned by an OpenAPI spec import, and conflicts. |
| `### Policy Violations` | Per-rule findings, with `BLOCKING` or `OVERRIDDEN by @user`. |
| `### Credential Slot Remaps` | Blocking slot reassignments. |
| `### Secret Broker Slots` | Each slot's status (resolved, needs allocation, missing). |

The comment is capped at 60,000 bytes. Detailed lists may be shortened, but
the verdict counts are kept and the footer names what was cut.

In live comparisons, `review`, `diff` and `plan` leave out only broker leaves
that are still unresolved after loading the bundle, so unseeded slots do not
show as permanent drift. Everything else, including resolved secret
differences, is compared. A viewer-credential `diff` also cannot compare
secrets the gateway fingerprints; see below.

### Viewer-credential drift reads

With `FERRUM_ADMIN_JWT_VIEWER_SECRET` set, `diff` reads each namespace from
`GET /config/export` (Ferrum Edge v0.9.9+) with a token signed by that key. The
gateway caps such a token at `viewer`, so it cannot write, read `GET /backup`
or see a raw secret. `plan`, `review` and `apply` keep reading `GET /backup`
with the admin credential.

- **Fingerprinted fields.** Values the gateway's viewer projection withholds
  (keyauth keys, `jwt`/`hmac_auth` secrets, plugin-config secrets and
  credential-bearing URLs, URL userinfo in a Proxy or Upstream, the Consul
  token) arrive as `hmac-sha256:<64 hex>`. The MAC key derives from the
  gateway's *admin* secret, and Edge deliberately does not let a viewer
  compute it, so `diff` cannot fingerprint the repository's value. Where the
  repository declares a secret-bearing value at a fingerprinted location (a
  `${gh-env-secret:…}` placeholder, a URL with userinfo, a Consumer key or
  secret, a plugin-config path the secret classifier flags, the Consul token,
  or an ancestor of one), the field is left out of the comparison and counted
  as unverified. Placeholder locations are read from the repository before a
  credential bundle resolves them, so loading a bundle does not change which
  fields are secret-bearing. Replacing an ancestor also hides that value's
  non-secret contents, so those are counted separately and keep the run
  non-authoritative (see exit codes above). Edge v0.9.9 does not publish which
  pointers it redacted, so a
  fingerprint-shaped string anywhere else is compared like any value and shows
  as drift; a field Edge fingerprints but GitForgeOps does not classify, with
  a literal repository value, also shows as drift (noisy, never silent). Where
  the repository declares nothing, the difference is reported. While any
  declared secret is unverified, `diff` prints `No differences found in the
  compared fields` instead of `in sync`.
- **Fingerprint baseline.** `--write-fingerprint-baseline PATH` records the
  fingerprints of every exported resource (other namespaces already in the
  file are kept; refused for cached data). `--fingerprint-baseline PATH`
  compares each declared resource with it and reports secrets `CHANGED`,
  `ADDED` or `REMOVED` since, as managed drift. A missing file means no
  baseline yet. Both flags need the viewer secret. Recording is refused (exit
  `1`) when the same run found differences or secret changes, since the
  baseline would carry the drift forward; `--force-baseline` overrides that.
  `diff` warns when either baseline path lies inside a git worktree. A baseline
  shows change
  between two exports, never agreement with the repository. Fingerprints are
  comparable only under one `redaction.fingerprint_key_id`; after the
  gateway's `FERRUM_ADMIN_JWT_SECRET` rotates (or a gateway without one
  restarts), `diff` says the baseline is not comparable and reports no secret
  drift. Record the baseline from a trusted state, such as right after a
  successful apply; a baseline rewritten by every drift check alerts on a
  change once. It holds keyed fingerprints only; keep it out of the repository.
- **Hidden credentials.** `basicauth` and custom credential types are omitted
  from the export. Each consumer carries one `hidden_credentials_fingerprint`
  over them, which only a baseline can compare, so it is unverified on every
  declared Consumer, including one that declares no credentials. A declared
  Consumer whose export lacks the field (a non-conforming gateway) stays
  unverified even with a baseline. `mtls_auth` falls under the hidden
  fingerprint only when none of its identities is valid to Edge; when at least
  one is valid, the export lists the valid identities and the invalid entries
  are neither shown nor fingerprinted, so no baseline can see them change.
- **Consumer projection.** The export keeps only `keyauth[].key`,
  `jwt[].secret`, `hmac_auth[].secret` and `mtls_auth[].identity`; the
  repository's Consumers are projected the same way before comparison. Any
  other non-secret field inside a credential entry (a legacy or extra key) is
  therefore not compared on this path. `diff` drops only blank `mtls_auth`
  identities and does not reproduce the rest of Edge's identity filter, so a
  repository identity Edge rejects shows as drift: a false positive, never a
  hidden change.
- **No spec ownership.** `api_spec_id` is stripped, so spec-owned rows are
  compared like other live rows and spec ownership conflicts are not detected.
- **Cached data.** `X-Data-Source: cached` (or `source: cached`) marks the
  export as possibly stale. The gateway also serves its cached snapshot when
  another export holds the database load, so a retry may get a database read.
  `diff` warns, reports no authoritative result and refuses `--exit-on-drift`.
- **Transport.** The viewer token is sent only to an `https://` gateway URL,
  or over `http://` to a literal loopback IP address (`127.0.0.0/8`, `[::1]`;
  not `localhost`). This is stricter than the admin client, whose opted-in
  `http://` (`FERRUM_ALLOW_INSECURE_HTTP=true`) may name any host outside
  GitHub Actions. Any other URL is refused before a request is made.
- **Refusals.** `404` means the gateway predates the export, `401` a viewer key
  or claim mismatch, `403` a namespace outside
  `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES` or the token's `ns` claim. Each message
  says what to check.

### Scheduled monitoring

`drift-check.yml` binds only `FERRUM_ADMIN_JWT_VIEWER_SECRET`, with the optional
issuer, audience and TTL settings. The protected checker requires those exact
step-local secret bindings and forbids the admin key, inherited/dynamic env
sources, rebinding and environment-file injection. Namespace filters from the
repository configuration and the gateway's `FERRUM_ADMIN_JWT_VIEWER_NAMESPACES`
continue to limit the comparison; neither scope is widened by the key change.

A repository administrator must configure the gateway's distinct viewer key
(Ferrum Edge v0.9.9+) and, before deploying this workflow, provision the matching
`FERRUM_ADMIN_JWT_VIEWER_SECRET` through GitHub's **Settings → Environments →
selected environment → Environment secrets**. Do this for every API environment
the drift matrix binds: `<env>-monitor` when `monitoring.unattended: true`,
otherwise `<env>` itself. After the workflow switch, delete
`FERRUM_ADMIN_JWT_SECRET` from each `<env>-monitor`; keep the admin key in
deployment environments for apply, trusted review and rotate. The settings audit
checks only secret names, requires the viewer name in `<env>-monitor`, and
rejects an admin name there even alongside the viewer. No secret values are
read, printed or copied by the migration tooling. An operator provisions the
value through the protected secret-entry UI.

The workflow keeps `diff --exit-on-drift` without
`--accept-unverified-secrets` or automatic fingerprint-baseline storage. A fresh
viewer export with no drift but unverified secrets exits `1` and reports a failed
comparison; it never certifies "in sync". The CLI's explicit acceptance flag
still permits exit `0` for unverified secret leaves, while JSON remains
`in_sync: false`; it cannot accept a cached read or masked ancestors. The
settings-audit environment and secretless template mode are unchanged. File-mode
drift jobs still skip before receiving gateway credentials.

**Breaking changes** (also in `plan`):

- a deleted Proxy or Consumer;
- a Proxy whose `listen_path`, `hosts`, effective `backend_scheme`,
  `upstream_subset`, `listen_port`, `frontend_tls` or `passthrough` changes;
- an authentication plugin config that is deleted, disabled, or given a
  different `plugin_name`;
- a surviving proxy (declared or not) that stops running an authenticator it
  runs live (`proxy <ns>/<id> loses authenticator <plugin_name>`), counting
  only authenticators its listener runs. An authenticator with a `trigger`
  still counts as running here, although it never satisfies
  `require_auth_plugin`.

"Authentication plugin" means the `require_auth_plugin` definition: the
policy file's `auth_plugin_names` when present, otherwise the built-ins. Other
plugin edits are not breaking.

Intentionally public proxies that rely on conditional authenticators can be
listed under `policies.require_auth_plugin.conditional_auth_exemptions` in the
code-owned `.gitforgeops/policies.yaml`, using exact `<namespace>/<proxy_id>`
identities. Their auth findings remain visible at `info`; missing or
unnecessary entries are reported as informational stale findings. Wildcards,
malformed identities and duplicates fail policy loading.

## Import details

- `--output-dir` is required and must be empty. The tree is staged and
  published with one directory rename, including `.gitforgeops-import.json`: a
  machine-readable inventory of source metadata, validated counts, totals,
  namespaces and skipped sections. It holds no resource bodies or secrets.
- API import refuses cached, cross-namespace or duplicate-row backups.
- Every recognized secret becomes `${gh-env-secret:alloc=require}`: Consumer
  credential secrets, built-in plugin-config secrets covered by the broker
  rules, custom-plugin values the heuristics flag, and Consul tokens.
  Identities stay literal.
- A secret-looking value outside those rules, or any custom-plugin string the
  heuristics do not flag, **fails the import** before anything is written.
  After confirming the named paths hold no credentials, re-run with
  `--allow-plaintext-plugin-config <plugin_name>`; accepted values stay literal
  and are listed in a review notice.
- When anything was captured, `--credential-bundle-output PRIVATE_PATH` is
  required. It is written atomically at mode 0600, sharded like allocation
  (40 KiB, 16 shards), must be outside the tree and any Git worktree, and is
  published before the tree.
- API specs, gateway trust bundles and unknown top-level backup sections are
  reported as skipped. Spec-owned resources are not imported.
- Count seals are checked before publication; a mismatch refuses the import.

Treat the source backup and the credential import bundle as plaintext secrets.
