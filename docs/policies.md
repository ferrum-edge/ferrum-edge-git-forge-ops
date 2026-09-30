# Policy rules

`.gitforgeops/policies.yaml` enforces organization standards on every PR. It
is optional, and every rule defaults to `enabled: false`. Start from
[`.gitforgeops/policies.example.yaml`](../.gitforgeops/policies.example.yaml),
which documents every key. The file accepts only `version: 1`, and unknown keys
at any level fail with the file path and key. A present file must be a plain
file: symlinks, non-regular files and files over 1 MiB are refused before
parsing.

The override flow is in the
[README](../README.md#overrides-are-evaluated-only-on-a-github-pull-request).

```yaml
version: 1

policies:
  backend_scheme:
    enabled: true
    severity: error              # error | warning | info
    allowed_protocols: [https, tcps, dtls]

  require_auth_plugin:
    enabled: true
    severity: error
    conditional_auth_exemptions:
      - public/status

overrides:
  require_label: gitforgeops/policy-override
  required_permission: write
```

## Severity

- `error` **blocks `apply`** (and makes `plan` exit non-zero) until the
  violation is fixed or overridden.
- `warning` and `info` appear in PR review; apply proceeds.
- Each violation names the rule, the resource, the current value and a fix.
- An enabled `backend_scheme`, `allowed_proxy_plugins` or
  `require_ai_guardrails` rule with an empty or blank list is a blocking
  configuration error at any severity. Populate the list or disable the rule.
  Omitted scheme and plugin lists are empty; omitted guardrail names use the
  built-in defaults.

## Rules

| Rule | Checks |
|---|---|
| `proxy_timeout_bands` | Proxy connect/read/write timeouts stay inside `min`/`max` bands. |
| `backend_scheme` | Effective `backend_scheme` is in `allowed_protocols`. |
| `require_auth_plugin` | Every proxy runs an enabled authenticator on every protocol it serves. |
| `forbid_tls_verify_disabled` | No proxy or upstream sets `backend_tls_verify_server_cert: false`. |
| `allowed_proxy_plugins` | Proxies use only allowlisted plugins. |
| `allowed_backend_domains` | Statically authored destinations match an allowlist. |
| `waf_enforcement` | Attached `waf` plugins actually block. |
| `require_ai_guardrails` | AI proxies carry an enforcing content guardrail. |
| `rate_limit_completeness` | Rate limiters have a usable budget. |
| `plugin_name_is_known` | `plugin_name` is a built-in or an allowlisted custom name. |
| `priority_override_range` | `priority_override` is within `0..=10000`. |

### `backend_scheme`

Compares against the six canonical schemes (`http`, `https`, `tcp`, `tcps`,
`udp`, `dtls`). A proxy with no `backend_scheme` is evaluated as `https`, as
the gateway does. Aliases in `allowed_protocols` (`wss`, `grpcs`, `tcp_tls`,
...) are normalized first.

### `require_auth_plugin`

Evaluates each proxy's **effective** plugin list: scoped configs merged over
global ones with the same `plugin_name`, disabled instances dropped.

- **Which plugins authenticate.** Omit `auth_plugin_names` to accept the ten
  built-in authenticators: `mtls_auth`, `jwks_auth`, `oauth2_introspection`,
  `oidc_relying_party`, `jwt_auth`, `key_auth`, `ldap_auth`, `basic_auth`,
  `hmac_auth`, `soap_ws_security`. Listing any other built-in (such as `opa`,
  `access_control`, `mesh_authz` or `spiffe_identity`) fails the policy load.
  `spiffe_identity` never counts: it extracts an identity but lets callers
  without one through. List custom authenticators by their `plugin_name`.
- **Per protocol.** The gateway filters each request's plugin chain by
  protocol. `http`/`https` proxies serve HTTP, gRPC and WebSocket; `tcp`/`tcps`
  get a TCP listener and `udp`/`dtls` a UDP listener. A proxy passes only when
  an authenticator runs on every protocol its listener serves.
  - On HTTP-family proxies every built-in authenticator covers all three
    protocols except `soap_ws_security`, which covers plain HTTP only.
  - A passthrough proxy forwards TLS without terminating it, so the gateway
    cannot inspect HTTP requests and attached HTTP authenticators do not run.
    It cannot satisfy `require_auth_plugin` or qualify for a conditional-auth
    exemption, even when configured with `frontend_tls: true`.
  - On stream listeners only `mtls_auth` counts, and the listener must
    terminate TLS/DTLS (`frontend_tls: true` without `passthrough`) so the
    client certificate reaches it.
- **Conditional authenticators never count by default.** An authenticator with a
  `trigger` runs only on the requests its predicate matches (protocol, path,
  method, header, or any other match), and every other request reaches the
  backend unauthenticated. It covers no protocol, whatever the predicate, so a
  proxy needs an authenticator without a trigger on every protocol its listener
  serves. A scoped instance with a trigger replaces a global instance of the
  same `plugin_name` without one, so it can remove coverage. For an intentionally
  public route, list the exact `<namespace>/<proxy_id>` in
  `conditional_auth_exemptions`. The finding remains visible at `info`, naming
  the exemption, and the security audit reports the same exception at `info`.
  The exemption predicate checks which protocols a conditional authenticator
  can run on, not which requests its trigger matches, so exempted requests
  outside that trigger remain unauthenticated.
  The exemption is bound to proxy identity only, so later changes to that
  proxy's configuration retain the `info` rating. Code owners approving an
  entry also approve future edits to that proxy; delete the entry and add a new
  one when the service changes. The trusted review workflow reads
  `policies.yaml` from the base branch, so land the exemption first (it produces
  a harmless stale-exemption note), then submit the route. Non-listed proxies
  still block according to the configured severity. Missing, no-longer-needed,
  or insufficiently scoped entries produce an informational stale-exemption
  finding. Entries cannot contain wildcards and must be unique. Components use
  only ASCII letters, digits, `.`, `_` and `-`; `.` and `..` are not valid
  components.
- **Custom authenticators** are assumed to cover plain HTTP only. Declare what
  they implement under `custom_auth_plugin_protocols`, for example
  `company_sso: [http, grpc, websocket]` (values: `http`, `grpc`, `websocket`,
  `tcp`, `udp`). Each key must also be in `auth_plugin_names` and must not be a
  built-in or a non-plugin spelling such as `jwt` or `oauth2`.

The security audit's "No auth plugin" warning and breaking-change detection
use the same definition and allowlist, even when the rule is disabled.

### `allowed_backend_domains`

Checks the destinations this repository authors statically: proxy
`backend_host`, proxy `dns_override` pins, upstream `targets[*].host`, and
service-discovery control-plane addresses such as `consul.address`. It is not a
general egress control; plugin endpoints and names a discovery provider
resolves later are not checked.

- **Matching.** `*.example.com` matches any subdomain depth but not
  `example.com` itself. Internationalized names are compared in punycode.
  Wildcards never match IP literals. IP entries compare canonically, so IPv6
  spellings and brackets match. A bare `*` allows everything. An empty enabled
  list is a blocking configuration error.
- **Upstream-backed proxies.** A proxy's `backend_host` is skipped only when it
  is blank and `upstream_id` resolves to a same-namespace upstream with a
  static target or service discovery, or to an upstream acknowledged under
  `allowed_external_upstreams` (`{namespace, id}`). Any non-blank
  `backend_host` is still checked, because it remains a real dial target if the
  upstream reference stops resolving. Delete `backend_host`/`backend_port` from
  proxies that delegate to an upstream, or allow the host deliberately.
  Duplicate upstream identities are blocking configuration errors.
- **`dns_override` pins** must be exact IP literals; a name pin is reported
  because it is resolved at runtime. Pins are checked against
  `allowed_dns_override_addresses`, or, when that is empty, against the IP
  entries of `allowed_domains` (or a bare `*`).
- **Service discovery.** A discovery-backed upstream is reported as
  unverifiable unless its `{namespace, id}` is listed under
  `allowed_service_discovery_upstreams`. That acknowledgement covers only the
  dynamic targets: a Consul `consul.address` must still match
  `allowed_service_discovery_control_plane_addresses` (or `allowed_domains`
  when that list is empty). Keep the control-plane list separate so it does not
  widen data-plane egress.
- Findings show the parsed host, never the raw address, so credentials in a
  URL stay out of logs. Malformed entries are blocking configuration errors;
  stale acknowledgements are informational.

### `allowed_proxy_plugins`

Checks each proxy's effective enabled plugins (including namespace globals and
attached scoped configs), matching `plugin_name` case-insensitively. Messages
name the plugin, never its configuration.

### `waf_enforcement`

Flags a `waf` plugin that is attached but not blocking: `mode` other than
`enforce`, a rule pack left entirely at `monitor`, or
`on_body_too_large: skip`. A custom rule's effective action follows the
gateway: an omitted action defaults to the plugin `mode`, then
`rule_overrides.<id>.action` and `rule_modes.<id>` replace it; a rule that ends
up `disabled`, or above `paranoia_level` without `rule_modes.<id>: enforce`,
does not count. Optional `min_paranoia_level` (the gateway accepts 1–4,
default 1). The security audit runs the same check.

### `require_ai_guardrails`

A proxy carrying AI traffic (any `ai_*` plugin, `mcp_gateway` or
`a2a_gateway`) must also carry an enforcing content guardrail from
`guardrail_plugin_names`. A guardrail with a `trigger` only runs for matching
requests, so it does not satisfy the requirement unless an unconditional
enforcing guardrail is also effective on that proxy. Dry-run and warn-only
guardrails likewise do not satisfy the requirement.

### `rate_limit_completeness`

Flags `rate_limiting` with missing or empty `limits`, no `scope: default`
entry, or an entry with neither a window plus `max_requests` nor
`requests_per_*`; `ai_rate_limiter` with no `token_limit`;
`redis_failure_policy: local_fallback` on either; and top-level budget fields
the gateway no longer accepts.

### `plugin_name_is_known`

Checks `plugin_name` against the gateway's 82 built-ins plus
`allowed_extra_plugin_names`. Custom names match exactly and case-sensitively,
as the gateway loads them. `jwt`, `oauth2` and `oidc` are not plugin names;
`jwt_auth`, `oauth2_introspection` and `oidc_relying_party` are.

Retired names (`oauth2_auth`, `semantic_ai_firewall`) and reserved names
(`__mesh_bpf_metrics`) are always rejected at `error` by the security audit,
even when this rule or the plugin is disabled, and no allowlist admits them.

## Override details

The override flow itself is in the
[README](../README.md#overrides-are-evaluated-only-on-a-github-pull-request).
Further details:

- Overrides clear error-severity policy violations and error-severity security
  findings. Validation, credential requirements, slot remaps, ownership and
  gateway admission gates stay enforced.
- `required_permission` (default `write`) is compared by rank:
  `read < triage < write < maintain < admin`. For two-person separation of
  duties, set `admin` and grant admin to a small group.
- The resource, overlay, policy and environment files, and the executable
  source, must exactly match the reviewed tree. Run local commands from a
  clean Git repository root. Comparisons use Git blob hashes and run no
  repository filters or scripts.
- Post-merge apply also checks that the PR's merge is an ancestor of the
  checkout; only `.state/` and `assembled/` may differ. If merging brings in
  other base-branch changes, update the PR and submit a new override review
  before merging.
- Trusted live review checks its sanitized YAML against the reviewed tree, and
  its protected checkout (named by `GITFORGEOPS_OVERRIDE_SOURCE`, which only
  selects what to inspect) against the same tree. `plan` and `apply` ignore
  that variable. Static review without a GitHub token cannot verify an override
  and keeps blockers.
- Overridden findings are annotated `OVERRIDDEN by @user`. The ledger's
  `overrides` record stores `pr_number`, `review_id`, `authorized_head` and the
  applied `commit`.

If every PR needs an override, tighten or disable the rule instead; overrides
are for emergencies.

## Adding a rule

1. Create `src/policy/rules/my_rule.rs` implementing `PolicyCheck`.
2. Add its typed config to `PolicyRules` in `src/policy/config.rs`.
3. Register it in `build_registry` in `src/policy/registry.rs`.
4. Add tests in `tests/unit/policy_tests.rs`.
5. Document it in `.gitforgeops/policies.example.yaml`.

`plan`, `review` and `apply` iterate the registry, so they need no changes.
