# Credential broker

Credentials never live in the repository. Resource files hold
`${gh-env-secret:...}` placeholders, and the values live in GitHub Environment
Secrets. The [README](../README.md#credential-broker-gh-env-secret-placeholders)
has the overview; this page is the reference. Public identity fields have their
own page: [Credential identities](credential-identities.md).

## Placeholders

```yaml
kind: Consumer
spec:
  id: app-mobile
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=generate}"
    jwt:
      - secret: "${gh-env-secret:alloc=generate|len=32}"
```

Syntax: `${gh-env-secret:alloc=<mode>|len=<bytes>}`.

| Option | Meaning |
|---|---|
| `alloc=require` (default) | The value must already be in the bundle; apply fails otherwise. |
| `alloc=generate` | Generate a value on apply if the bundle has none. |
| `alloc=rotate` | Same as `generate` at apply time. Marks the slot as meant for rotation; re-rotation is always an explicit `rotate` run. |
| `len=<16..=256>` | Bytes of entropy for generated values. Default `32`, which encodes to 43 base64url characters. |

Placeholders are the only accepted on-disk form for secrets. Before it reads
the bundle, contacts a gateway or allocates anything, `apply` audits the
unresolved document and refuses every error-severity security finding, which
includes any credential secret that is not a valid placeholder (even an
unquoted number such as `key: 12345`). `plan` exits non-zero on the same set,
and the PR comment marks them blocking. The same gate covers plugin-config
leaves classified as secrets or endpoints (even on disabled plugins) and
modeled service-discovery secrets. Only a valid broker placeholder is exempt;
other interpolation syntax or a malformed placeholder is rejected. The escape
hatch is the policy override label, for emergencies only.

## Credential shapes

Ferrum Edge authenticates exactly five credential types. Each is an **array**
of entries:

| Type | Entry field | Notes |
|---|---|---|
| `keyauth` | `key` | non-empty, at most 4096 characters |
| `jwt` | `secret` | at least 32 characters |
| `hmac_auth` | `secret` | at least 32 characters, unique per namespace |
| `mtls_auth` | `identity` | certificate CN / SAN / fingerprint; a public identity, written literally |
| `basicauth` | `username` plus `password` **or** `password_hash` | `username` is a public identity; the hash form is `hmac_sha256:<64 hex>` |

- **Write the array form.** `GET /backup` returns arrays, so an object form
  (`keyauth: {key: ...}`) would read as drift. Assembly normalizes the object
  form, but the array form is canonical.
- **Unknown types are refused.** Any other `credentials` key (for example
  `api_key` or `basic_auth`) validates on the gateway but is never used for
  authentication, so `validate`, `plan`, `apply` and `import` refuse it,
  naming the consumer, the key and the valid set. Common misspellings get a
  suggestion (`api_key` → `keyauth`, `basic_auth` → `basicauth`).
- **Removal is asymmetric.** Omitting `keyauth`, `jwt`, `hmac_auth` or
  `mtls_auth` deletes the stored entries on the next apply; omitting
  `basicauth` keeps what the gateway has. Write an explicit empty array
  (`keyauth: []`) to clear one of the first four. Either way, retire the
  type's slots from the bundle too, or the change is refused as a
  [slot remap](#entry-position-is-the-slot-identity).

## What the broker will not generate

Plan and apply check these before any GitHub call or secret write:

- `jwt` / `hmac_auth` with `len` under 24 bytes (the gateway needs 32
  characters).
- `basicauth` passwords in **file mode**. A file-mode gateway needs
  `password_hash`, an HMAC under the gateway's own
  `FERRUM_BASIC_AUTH_HMAC_SECRET`, which GitForgeOps does not have. Set the hash
  by hand, or use api mode, where the admin API hashes a plaintext password.
- `basicauth` `password_hash`, in either mode.
- Plugin-config **endpoints** (`ldap_auth.ldap_url`, a `redis_url`, an OIDC
  `discovery_url`, ...). Use `alloc=require` and seed the real endpoint.
- Consul ACL tokens. They are minted by the Consul cluster; use
  `alloc=require` and seed the slot.
- `mtls_auth.identity` and `basicauth.username`. These are refused as
  placeholders in every mode, even seeded; see
  [Credential identities](credential-identities.md).

A bundle value of `[REDACTED]` is refused: that is what `GET /consumers/...`
returns, so the bundle was seeded from the wrong endpoint. Re-seed from
`GET /backup` or rotate the slot.

A Consumer credential secret whose bundle value is placeholder text is refused
too: a value equal to the placeholder committed at that slot, or any value in
the `${gh-env-secret:…}` grammar. The check trims surrounding whitespace before
matching, recognizes the prefix without regard to ASCII letter case, and also
refuses a trimmed value that starts with the prefix but has no closing `}`.
Such text is known from the repository and has almost no entropy, so it can
never be a live credential. Every command that reads Consumer slots from the
bundle refuses it (`validate`, `plan`, `diff`, `review`, `apply`,
`export --materialize` and `rotate`, which also checks the Consumer's other
slots). The error names the slot and the reason, never the value. Re-seed the
slot with the real secret or rotate it. This is the one exception to the rule
that a supplied value counts as resolved whatever its bytes spell;
plugin-config and service-discovery slots keep that rule.

## Slot names

Slot names are derived from `(namespace, id, path)`; you never write them.
The path runs from the credential type to the placeholder. Index 0 of a
credential array is omitted:

```text
keyauth: [{key: K}]              ->  ferrum/app-mobile/keyauth/key
keyauth: [{key: K}, {key: K2}]   ->  ferrum/app-mobile/keyauth/key
                                     ferrum/app-mobile/keyauth/[1]/key
jwt:     [{secret: S}]           ->  ferrum/app-mobile/jwt/secret
```

Older spellings (an explicit `[0]`, and a dotted form) are still read, but only
the form above is written. `gitforgeops rotate --credential` takes the same
path: `keyauth/key`, `jwt/secret`, `hmac_auth/secret`, `basicauth/password`, or
`keyauth/[1]/key`. Renaming a consumer gives it new slots.

Secrets outside `Consumer.credentials` get a reserved `@` segment:

```text
PluginConfig.config leaf     ->  <ns>/<plugin-id>/@plugin/<plugin_name>/config/<path>
                                 ferrum/ldap/@plugin/ldap_auth/config/ldap_url
Upstream.service_discovery   ->  <ns>/<upstream-id>/@service-discovery/<path>
                                 ferrum/orders/@service-discovery/consul/token
```

Plugin-config array paths keep every index, including `[0]`.

A plugin-config slot names the plugin type as well as its id, because what a
config path means, and where the plugin sends it, depends on the type (the
same `headers.*` path is a secret for more than one plugin, and some of them
send it to an endpoint their own config names). Changing a plugin's
`plugin_name` while keeping its id therefore gives it new slots: the previous
type's stored values are never resolved into it. See
[Entry position is the slot identity](#entry-position-is-the-slot-identity)
for what happens to the old values.

Bundle keys in the earlier type-less form (`<ns>/<plugin-id>/@plugin-config/config/<path>`)
are never read. A declared plugin with the same id refuses on them. If a value
was issued for the plugin's current type, copy it to the typed slot. In every
case, remove the old key.

Service discovery is brokered leaf by leaf. The only modeled secret is the
Consul ACL token. `consul.address`, `service_name`, `datacenter` and `tag`
stay readable for review and are checked by the `allowed_backend_domains`
policy. `dns_sd`, `kubernetes` and `mesh` discovery hold no secrets. The Consul
token is otherwise treated like a consumer credential: `import` captures it,
`diff` prints `[REDACTED]`, validator output is scrubbed, and a committed
literal is a blocking finding.

## Entry position is the slot identity

Only an entry's **index** goes into its slot name. For a credential type with
more than one entry, list order therefore decides who gets which stored value:

```text
before:  keyauth: [{key: A}, {key: B}]      A -> ferrum/app/keyauth/key
                                            B -> ferrum/app/keyauth/[1]/key

delete the first entry:
after:   keyauth: [{key: B}]                B -> ferrum/app/keyauth/key   <-- A's stored value
```

The credential you meant to retire stays live under B, and `[1]` is orphaned
in the bundle, ready to be handed to the next entry added there.

What GitForgeOps does about it:

| Situation | Result |
|---|---|
| A brokered array has more than one entry | Warning (a reorder cannot be detected from the document). |
| The bundle holds a slot at an index the array no longer has (a shrink, including deleting the last entry) | **Refused.** |
| A credential type was dropped from a Consumer while its slot is still in the bundle | **Refused.** |
| The bundle holds a slot of a different plugin type (or the type-less form) under a declared plugin's id | **Refused.** The value is never resolved into the plugin, even when the refusal is accepted. |
| The ledger records a Consumer as applied, it is no longer declared, and its slots are still in the bundle | **Refused** (only in runs that load that whole namespace). |
| A Consumer the ledger does not record resolves an `alloc=generate`/`alloc=rotate` value already in the bundle | **Refused** (the value may belong to a retired Consumer with a reused id). |

Refusals stop `apply`, `export --materialize` and `rotate`; `plan` prints a
`Credential Slot Remaps` section and exits non-zero; the PR comment shows them
as blocking. Messages name slots, never values. The ledger-backed checks (the
last two rows) run in `plan`, `review`, `apply` and `export --materialize`;
`rotate` requires a managed Consumer in shared mode; exclusive scope is checked too.

The revived-slot check exempts `alloc=require`, and exempts a slot recorded by
a failed apply only when its retry has the same triggering revision
(`GITFORGEOPS_ALLOCATION_REVISION` in the bundled workflow, otherwise the
checked-out commit) and the same recipient. `apply` records each allocated slot
as soon as its bundle shard reaches GitHub, so a retry reuses delivered values.
Until that retry completes, `plan` and `review` runs without
`GITFORGEOPS_ACTOR` report those slots as refusals.

Plugin-config arrays get the same shrink refusal and multi-entry warning
(`ferrum/oidc/@plugin/oidc_relying_party/config/providers/[1]/client_auth/client_secret`).
`rotate` does not publish plugin configs, so the remedy there is to reseed and
retire slots in the bundle. The same applies to a plugin type change: seed the
values the new type needs under its own slots and remove the old type's keys,
keeping every other slot. Changing the type back later would otherwise
resurrect a value nobody reviewed for that plugin.

### Retiring or shifting entries safely

To delete the **last** entry:

1. Rotate its slot while it is still declared.
2. Revoke the old credential wherever it was issued.
3. Remove the entry from the YAML and its slot key from the bundle, keeping
   every other slot. Merge.

To delete an entry that shifts later entries (A from `[A, B]`):

1. Rotate each surviving entry at its current index (rotate B at `[1]`).
2. In the private bundle, move B's rotated value from
   `ferrum/app/keyauth/[1]/key` to `ferrum/app/keyauth/key`, and remove the
   vacated keys. For a sharded bundle, edit only the affected shard and update
   only its secret.
3. Remove A from the YAML and merge.

Rotation replaces a value and sends it to the gateway, but it does not remove
bundle keys or revoke anything at an external issuer.

`--allow-credential-slot-remap` downgrades these refusals to warnings for one
CLI run (`plan`, `apply`, `export --materialize`, `rotate`), for a deliberate
reassignment. There is no environment variable for it, and the bundled apply
workflow never passes it. After accepting a deletion with the flag, retire the
slot before re-adding the type. Accepting a plugin type change never resolves
the old type's value into the plugin; it only lets the run proceed. An environment whose ledger is missing, or does
not record Consumers the bundle already serves through `alloc=generate`, is
refused until the slots are retired or accepted once with the flag.

## Storage

Values live in JSON bundles, one GitHub Environment Secret each:
`FERRUM_CREDS_BUNDLE`, `FERRUM_CREDS_BUNDLE_1`, ... `FERRUM_CREDS_BUNDLE_15`.

- Each bundle is `{ "<slot>": "<value>", ... }`.
- A bundle is sharded by a deterministic hash once it nears 40 KiB (GitHub's
  secret limit is 48 KB). That is roughly 440 slots per bundle and about 7,000
  per environment.
- `MAX_BUNDLE_SHARDS` is 16. `import`, `apply` and `rotate` refuse to create a
  17th shard.
- The prefix is reserved. When a bundle file is loaded, only the exact names
  above are accepted; a name such as `FERRUM_CREDS_BUNDLE_01` would alias a
  shard and fails.

### Loading bundles in workflows

`apply-on-merge.yml`, `materialize-file.yml` and `rotate.yml` bind every
bundle secret **by name** in their "Load credential bundles" step, rather than
reading the whole secrets context:

```yaml
env:
  FERRUM_CREDS_BUNDLE: ${{ secrets.FERRUM_CREDS_BUNDLE }}
  FERRUM_CREDS_BUNDLE_1: ${{ secrets.FERRUM_CREDS_BUNDLE_1 }}
  # ... through FERRUM_CREDS_BUNDLE_15
```

`.github/scripts/credential_bundles.py` validates them (blank means unset;
every value must be a JSON object of string slots to string values; an
out-of-range name is an error) and writes them to a fresh mode-0600 file under
`$RUNNER_TEMP`, exported as `FERRUM_CREDS_JSON_FILE`. Nothing reaches the log.
The binary also accepts inline `FERRUM_CREDS_JSON` for small local tests.

To add capacity, raise `MAX_BUNDLE_SHARDS` in both `src/secrets/bundle.rs`
and `.github/scripts/credential_bundles.py`, and add the matching
`FERRUM_CREDS_BUNDLE_<N>` bindings to those workflows.
`check_supply_chain.py` fails the build if they disagree.

## Allocation and delivery

On apply, each `alloc=generate` (or first-time `alloc=rotate`) slot with no
value is allocated:

1. Generate `len` random bytes (default 32) from the OS CSPRNG, encoded as
   base64url without padding.
2. Fetch the environment's public key
   (`GET /repos/{repo}/environments/{env}/secrets/public-key`).
3. Seal the updated bundle with libsodium `crypto_box_seal` and `PUT` it to
   `FERRUM_CREDS_BUNDLE[_N]`.
4. Find the recipient's first age-compatible SSH key (Ed25519 or RSA) from
   `GET /users/{login}/keys`, 100 keys per page, at most 20 pages. An
   incomplete search fails. This lookup runs once per apply.
5. Encrypt each new value with age to that key and post it as a PR comment.
   The recipient decrypts locally.

The recipient is the merged PR's author (`GITFORGEOPS_ACTOR` in the bundled
workflow). A recipient must be a valid GitHub login; a set but blank
`GITFORGEOPS_ACTOR` is a configuration error, not "no recipient".

Allocation needs `FERRUM_GH_PROVISIONER_TOKEN` (a GitHub App installation
token, preferred, or a fine-grained PAT with `Secrets: write` and
`Environments: write`) and `GITHUB_REPOSITORY`. `plan` reports each missing one
as a blocker when allocation is pending.

## Rotation

Run **Actions → GitForgeOps Rotate Credential** (`rotate.yml`) with an
environment, consumer, credential path and optional namespace (default
`ferrum`). It generates a new value, writes the environment secret, delivers
the value age-encrypted to whoever started the workflow, and pushes the updated
stored Consumer to the Admin API with its row `If-Match`. It shares the
environment's apply concurrency group.

The CLI equivalent is
`gitforgeops rotate --consumer ID --credential PATH [--namespace NS] [--recipient LOGIN]`.
Without `--namespace`, the environment's `namespace_filter`, then
`FERRUM_NAMESPACE`, then `ferrum` is used.

Rules:

- Only Consumer `keyauth/key`, `jwt/secret`, `hmac_auth/secret` and api-mode
  `basicauth/password` (including indexed entries) can be rotated. Hashes,
  identities, unknown fields and `@plugin` / `@service-discovery` slots
  are refused before anything is written.
- Rotation is refused in file mode; use materialization instead.
- The target must be a placeholder on a declared Consumer in the namespace,
  and its sibling slots must already resolve.
- A literal secret anywhere on the declared Consumer refuses rotation. An `apply`
  override does not carry over. Broker the literal with `alloc=require`, seed it
  and apply first.

Before any broker write, rotation establishes writable health, repository ownership,
complete authoritative verification and representability of the stored row. The
current target must match an available old bundle value when directly comparable;
Basic's gateway-keyed HMAC remains opaque. Without an old target value, the
complete stored row establishes the baseline; no plaintext equality is inferred.
Unsupported legacy or hidden fields that the server would canonicalize away refuse
before delivery. Publication changes only the authorized
credential leaf in the complete stored row, preserving unrelated entries and custom
credentials, and uses the original row token. A conditional refusal after delivery
is recoverable broker/gateway divergence: completion is not recorded, and a fresh
apply can reconcile. No unconditional rotation or dedicated credential-deletion
shortcut is used.

For externally issued secrets (a Consul token, a precomputed password hash),
mint the replacement at the source, reseed the existing slot keeping every
other bundle entry, then run `apply`.

## File mode

A file-mode gateway reads one assembled YAML at boot. Committing it with
credentials inlined would defeat the broker, so file mode has two stages.

**1. Placeholder assembly (every merge).** `apply-on-merge.yml` runs
`gitforgeops apply --auto-approve` with `FERRUM_GATEWAY_MODE=file`,
`FERRUM_FILE_OUTPUT_PATH=assembled/<env>.yaml` and
`FERRUM_MESH_FILE_OUTPUT_PATH=assembled/<env>-mesh.yaml`. The file is written
before allocation, so it keeps the placeholders and is safe to commit. The same
run can still allocate and deliver credentials and update the ledger.

Both files are written atomically (temp file, `fsync`, `rename`). The gateway
document carries a `resource_counts` seal that the gateway checks, so a
truncated file fails loudly.

**2. Materialization (on demand).** Run **Actions → GitForgeOps Materialize
File** (`materialize-file.yml`) with an environment. Bound to that GitHub
Environment, it runs:

```bash
gitforgeops export --materialize --encrypt-to "$ACTOR" --output out/assembled-<env>.age
```

which:

- refuses anything `apply`'s security gate refuses, such as a committed
  literal credential (an `apply` override does not carry over);
- replaces placeholders with bundle values, byte for byte;
- refuses if any slot has no value (run `apply` first);
- age-encrypts the whole document to the actor's GitHub SSH key.

The `.age` file (and the placeholder-free mesh document, if any) is uploaded
as an artifact with **1-day retention**. Decrypt it locally:

```bash
age -d -i ~/.ssh/id_ed25519 < assembled-production.age > assembled.yaml
```

Access is controlled by the environment's protection rules. If the actor has
no compatible SSH key on GitHub, materialization fails and points to
<https://github.com/settings/keys>.

## Audit trail

`.state/<env>.json` records, per slot: `last_rotated`, `delivered_to`,
`delivered_run_id`, and for slots `apply` allocated, `allocation_commit` and
`allocation_recipient` (cleared by `rotate`). CI commits the ledger, so
`git log .state/<env>.json` is the delivery history. The ledger holds no
credential-derived hashes. Version 2 ledgers that carried hashes are rewritten
without them on the next save; rotate any low-entropy credential whose old hash
is already in Git history.
