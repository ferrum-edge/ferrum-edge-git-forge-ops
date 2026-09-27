# Writing resources

How the repository tree becomes a gateway configuration: layout, overlays,
schema strictness, plugin associations, mesh fragments and resource labels.
For the environment file (`.gitforgeops/config.yaml`) see the
[README](../README.md#repo-configuration-gitforgeopsconfigyaml).

## Layout

```
resources/
  ferrum/                        # namespace: ferrum
    proxies/my-api.yaml          # kind: Proxy
    consumers/alice.yaml         # kind: Consumer
    upstreams/api-cluster.yaml   # kind: Upstream
    plugins/rate-limit.yaml      # kind: PluginConfig
    mesh/core.yaml               # kind: MeshConfig (a mesh fragment, not a gateway resource)
  team-alpha/
    proxies/alpha-service.yaml

overlays/                        # per-environment deep-merge fragments
  staging/
    ferrum/proxies/my-api.yaml   # overrides backend_host, timeouts, ...
    ferrum/mesh/core.yaml        # matches the mesh fragment by file name
  production/
    ferrum/proxies/my-api.yaml
  sandbox/                       # a selected overlay must exist, even if empty

assembled/                       # file-mode output, written by CI
  staging.yaml
  staging-mesh.yaml

.state/                          # ownership ledger, written by CI; never hand-edit
  staging.json
```

The directory under `resources/` is the resource's namespace. One pull request
may add, change or delete any number of resources across any number of
namespaces and kinds. Apply groups the work by namespace: each namespace gets
its own `X-Ferrum-Namespace` header, and a failure in `team-alpha` does not
block `team-beta`.

## Loading rules

Loading is fail-closed and deterministic:

- Overlay names (in `.gitforgeops/config.yaml` or `FERRUM_OVERLAY`) and
  environment names are 1–64 ASCII letters, digits, `-` or `_`. An overlay
  name selects one directory under `overlays/`; paths and traversal segments
  are rejected.
- A selected overlay directory must exist. The error names the environment,
  the overlay and the file that selected it.
- Files are sorted before parsing, walker errors propagate, and symlinks
  anywhere in `resources/` or the selected overlay are rejected.
- Two overlay files targeting the same resource are an error that names both.
- Gateway overlay fragments need `kind` and `spec.id`. Mesh fragments use an
  explicit `id` or their file stem.
- Enabled files must end in lowercase `.yaml` or `.yml`. Files starting with
  `_` are disabled. The only other files allowed are `README`, `README.md`,
  `.gitkeep` and the generated `.gitforgeops-import.json`. Anything else,
  including `.YAML` or `.yaml.bak`, fails instead of silently dropping out.
- `.DS_Store`, `Thumbs.db` and `desktop.ini` are skipped silently, because a
  file manager re-creates them.

The trusted PR review applies the same rules to its artifact before it crosses
the privileged boundary.

## Overlays

Overlay object fields deep-merge onto the resource with the same `kind` and
`spec.id`. Arrays replace by default, so an environment can narrow lists such
as `allowed_methods`, `hosts`, `allowed_ws_origins` or `acl_groups`. The
exceptions merge by item identity:

| List | Merged by |
|---|---|
| `spec.plugins`, `spec.targets` | item identity (additive) |
| mesh `spec.workloads` | `spiffe_id` |
| mesh `spec.services` | `name` + `namespace` |

## Plugin configs and proxy associations

A `PluginConfig` with `scope: proxy` and a `proxy_id` automatically adds
`{plugin_config_id: <its id>}` to that proxy's `plugins` list during assembly.
The plugin and proxy must be in the same namespace:

```yaml
# resources/team-alpha/proxies/orders.yaml
kind: Proxy
spec:
  id: orders
  listen_path: /orders
  backend_host: orders.internal
  backend_port: 443
---
# resources/team-alpha/plugins/orders-keyauth.yaml
kind: PluginConfig
spec:
  id: orders-keyauth
  plugin_name: key_auth
  scope: proxy
  proxy_id: orders
  config: {}
```

The proxy may also list `plugins: [{plugin_config_id: orders-keyauth}]`
explicitly. Assembly keeps explicit entries in order, drops duplicate ids, and
appends missing derived ids in lexical order. Export, apply, diff, plan and the
security and policy checks all use this assembled list, matching the gateway's
own auto-attachment. Disabled configs are still associated but do not count as
authentication.

Rules for other scopes and references:

- `scope: global` needs no association. `scope: proxy_group` needs explicit
  `Proxy.plugins` entries and no `proxy_id`; a `proxy_group` config with a
  `proxy_id` is an error.
- Explicitly referencing a global config, or a config whose `scope` or
  `proxy_id` conflicts with the association, is an error in both ownership
  modes.
- Referencing a config this repository does not declare is a **warning in
  shared mode** (it may be owned by other tooling) and an **error in exclusive
  mode**.
- To detach a proxy-scoped plugin, remove or retarget its `PluginConfig` and
  remove any explicit reference. Clearing `Proxy.plugins` alone does not
  detach a config that still points at the proxy.

Association comparison ignores order but keeps duplicate counts, so live
duplicates are correctable drift. Write ordering and the create-transaction
rules are in [Apply behavior](apply.md#apply-ordering-and-the-batch-fast-path).

## Supported fields and unknown fields

The typed schema rejects unknown keys at every level before assembly, naming
the file and full YAML path. A typo such as `spec.plguins` therefore fails
instead of disappearing. Deliberately opaque values are kept verbatim: plugin
`config`, consumer credential maps, and per-item mesh objects.

A gateway release that adds a field is unusable until GitForgeOps models it.
`FERRUM_ALLOW_UNKNOWN_FIELDS=true` unblocks that for **top-level** `spec`
fields on `Proxy`, `Upstream`, `Consumer` and `PluginConfig`: they are kept
verbatim through overlays, `export`, `diff` and `apply`, and each affected file
gets a `Warning:` on stderr. Limits:

- **Nested unknown fields stay fatal** with or without the flag.
- **The flag is for version skew.** Upgrade GitForgeOps when a release catches
  up.
- **A field only the gateway carries is not drift.** `diff` ignores a live
  field this build does not model and the repository does not declare.
  Declaring it is how the repository takes ownership of it.

### Import refuses unmodelled fields

On `import` the value came from the gateway and nobody has read it, and the
credential broker only redacts leaves it models. So import refuses an
unmodelled field instead of writing a possible secret into the tree:

- An unknown top-level field is refused, naming the resource and field (never
  the value). After confirming it is not a credential, re-run with
  `--accept-unknown-field <NAME>` for each field **and**
  `FERRUM_ALLOW_UNKNOWN_FIELDS=true` (without it the strict loader would reject
  the tree import just wrote). Every resource that relied on an
  acknowledgement is listed again at the end.
- An unknown **nested** field (for example `.spec.targets[1].future_option`)
  is refused with no acknowledgement flag. Upgrade GitForgeOps or remove the
  field on the gateway. The refusal lists the first 20 offenders.
- An unknown Consumer credential map key is refused. See
  [Credential shapes](credential-broker.md#credential-shapes).

Nothing is written, neither tree nor credential import bundle, when import
refuses.

### Apply refuses to drop live-only fields

Every write to an existing resource is a full-resource `PUT` (and
`full_replace` re-creates every row), built from the repository's declaration.
A live field the declaration cannot carry would be reset by the gateway. So
`apply` refuses a namespace, before writing anything in it, when a row it will
actually write has:

- a nested field this build cannot represent, or
- an unknown top-level field that the declaration does not name.

Rows that count are incremental updates, pending-create ownership assertions,
shared-mode adoption claims, and every row of a `full_replace` body. A row that
already matches and needs no claim is not written, so it does not block.
Refused namespaces get no credential allocation; other namespaces still
reconcile and the run exits non-zero. The interactive preview lists each
refused namespace with its reason.

Fix it by upgrading GitForgeOps, removing the field on the gateway, or, for a
top-level field, declaring it under `FERRUM_ALLOW_UNKNOWN_FIELDS=true`. Do not
delete the declaration instead: in `exclusive` mode an undeclared live row is
**deleted** by the next apply.

### YAML rules

- **Merge keys (`<<:`) are not supported.** `<<` stays an ordinary key and is
  reported as unknown field `.spec.<<`. Repeat the fields or use an overlay.
- **Opaque values take string keys only.** Plugin `config`, credential entries
  and mesh items round-trip through JSON, so a non-string key (`404:`,
  `true:`) is rejected rather than quietly stringified.

## Proxy backend scheme

`backend_scheme` is one of `http`, `https`, `tcp`, `tcps`, `udp` or `dtls`.
WebSocket and gRPC are detected per request, and HTTP/3 is negotiated per
backend.

`backend_protocol` is accepted as an alias, and these values are normalized:
`ws`/`grpc` → `http`, `wss`/`grpcs`/`h3` → `https`, `tcp_tls` → `tcps`. Output
always uses `backend_scheme` and the canonical value.

A proxy with no `backend_scheme` and no `listen_port` is assembled as `https`,
matching how the gateway stores it; otherwise it would show as modified on
every diff. Stream proxies (`listen_port` set) are not defaulted: the gateway
rejects a stream proxy with no scheme, and guessing would hide that error.

## Mesh configuration

Mesh nodes read a standalone `{version, mesh}` document that is separate from
the gateway configuration: the mesh loader rejects `proxies:` and a file-mode
gateway ignores `mesh:`. GitForgeOps therefore produces two documents.

### Fragments

Author mesh config as fragments under `resources/<namespace>/mesh/*.yaml`.
This is the smallest fragment the validator accepts
(`tests/fixtures/mesh-minimal/`); `resources/ferrum/mesh/_example.yaml` shows
more fields.

```yaml
kind: MeshConfig
id: minimal         # optional; defaults to the file stem. Overlays match on it.
spec:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      selector:     # required
        labels:
          app: api
      service_name: api
      addresses: ["10.0.0.5"]
      ports:
        - port: 8080
          protocol: http
      trust_domain: cluster.local   # must match the SPIFFE ID
      namespace: ferrum
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
      workloads:
        - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
```

All fragments merge into **one** document:

- List fields (`workloads`, `services`, `peer_authentications`, ...)
  concatenate.
- Singleton fields (`istio_root_namespace`, `trust_bundles`, `multi_cluster`,
  `outbound_traffic_policy`) may be set by one fragment, or by several that
  agree. A conflict is an error.

The directory namespace is only a handle for `FERRUM_NAMESPACE` filtering,
overlay matching and exclusive ownership. Fragment ids must be unique within a
directory namespace.

`overlays/<env>/<ns>/mesh/<same-file-name>.yaml` deep-merges onto the matching
fragment. `spec.workloads` merges by `spiffe_id` and `spec.services` by
`(name, namespace)`; every other mesh list is **replaced** by the overlay.

### Output

`export` and file-mode `apply` write the merged document to
`FERRUM_MESH_FILE_OUTPUT_PATH` (default `./assembled/mesh.yaml`; the bundled
workflows use `assembled/<env>-mesh.yaml`). Point a mesh node's
`FERRUM_MESH_FILE_CONFIG_PATH` at it with `FERRUM_MESH_CONFIG_PROTOCOL=file`.
Mesh config holds no credential placeholders, so there is no materialize step.

There is **no mesh admin API**. Mesh resources never appear in `diff`, and an
api-mode `apply` only validates the document and prints a notice to publish it
with `export` or a file-mode apply. Distribute the file to mesh nodes the way
you distribute other config.

The gateway and mesh output paths must differ. File-mode `validate`, `plan`
and `apply` (and `export --output`) refuse before writing when they resolve to
the same file, whether or not the repository declares mesh fragments.

### Retraction

When a change removes the **last** `MeshConfig` fragment, `export` and
file-mode `apply` rewrite the destination as the empty document instead of
leaving the old policy in place:

```yaml
version: '1'
mesh: {}
```

The file is not deleted, because a mesh node treats a missing file as a fatal
startup error. `plan`, `apply`, `export` and the PR comment print a
`RETRACT mesh` line. Retraction only touches a destination this repository
published: `.state/<env>.json` must record it as `mesh_document_path`, and a
`FERRUM_NAMESPACE`-filtered run never retracts.

### Validation

`validate`, `plan`, `review` and `apply` run `ferrum-edge validate -m file` on
the assembled gateway document once per effective namespace, in lexical order.
Each run gets an empty settings file, an explicit `FERRUM_NAMESPACE`, and no
inherited `FERRUM_*` variables. Any failing slice fails the result, and
diagnostics carry namespace labels. An empty document still gets one pass.

When the repository declares mesh fragments, `validate`, `plan` and `apply`
also run `ferrum-edge validate -m mesh` on the rendered mesh document. That
pass alone sets `FERRUM_MESH_ALLOW_NO_CA=true`, the gateway's validation-only
opt-out from its workload-identity check, because a CI runner is not a mesh
node. It is not passed through from the caller and never reaches a running mesh
node or the published document.

The real-binary namespace tests in `tests/unit/validator_namespace_tests.rs`
run only when `GITFORGEOPS_TEST_EDGE_BINARY` points at a `ferrum-edge` binary;
otherwise they skip.

Test fixtures: `tests/fixtures/companion-schema/` is an every-field schema
mirror, not a working mesh document. `tests/fixtures/mesh-minimal/` is the
smallest mesh document the validator must accept. `tests/fixtures/simple-config/`
uses broker placeholders, and `tests/fixtures/literal-credential/` exists only
so the security gate has a committed literal to refuse.

## Resource labels

Assembled proxies, consumers, upstreams and plugin configs carry
`labels: {provisioned-by: ferrum-edge-git-forge-ops}`. An existing
`provisioned-by` value and other declared labels are kept. Add your own under
`spec.labels`; overlays merge them normally. Mesh fragments are not labeled.

Labels need a gateway and `ferrum-edge validate` binary with resource-label
support (Ferrum Edge v0.9.5 or later). If the validator rejects `labels`,
GitForgeOps reports `gitforgeops error [validator-resource-labels]`, names the
validator binary, and explains the upgrade. `plan` then reports a validation
blocker, `review` marks validation `FAILED`, and file-mode `apply` refuses to
publish. The validator pin checks enforce label support before merge and in the
daily canary.

Labels are informational. The ownership ledger and API-spec rules decide
adoption, reconciliation and deletion.
