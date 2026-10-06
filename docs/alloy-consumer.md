# Consuming Alloy resource exports

Alloy's `ferrum-alloy edge export --format gitforgeops --output DIR` writes a
`resources/<namespace>/...` tree of per-resource `kind` and `spec` YAML documents.
GitForgeOps consumes that tree through its existing strict resource loader and
schema mirror, assembler, and `gitforgeops validate` command. Generate into an
empty directory, review the files, then copy the resource tree into the desired
repository. Normal ownership, credential, policy and apply checks still govern
publication.

The producer revision under test is
[`690aed7a9fa8458aeea4ac8416170c8daeb0470b`](https://github.com/ferrum-edge/ferrum-alloy/tree/690aed7a9fa8458aeea4ac8416170c8daeb0470b).
The [provenance file](../tests/fixtures/alloy-producer/PROVENANCE.json) records
the full SHA, original fixture paths, generation command and tracking
[Alloy issue #27](https://github.com/ferrum-edge/ferrum-alloy/issues/27).
The full commit SHA fixes the producer's inputs and implementation, so no
manifest copies or checksum lists are vendored. Generated YAML is produced
afresh by the pinned CLI in GitHub-hosted CI.

The qualification runs in its own workflow,
[`alloy-consumer.yml`](../.github/workflows/alloy-consumer.yml). It is **not a
required check**: it builds an external repository with crates.io
dependencies, so the required `validator-pairing` job and
`gitforgeops-required-static-validation` status stay fast and independent of
Alloy. It runs on pull requests that change the consumer surface, weekly, and
on manual dispatch. The surface is everything the test exercises: the CLI load
boundary (`src/main.rs`, `src/cli.rs`, `src/lib.rs`, `src/error.rs`,
`src/diagnostics.rs`), `src/config/**`, `src/validate/**`, the load-boundary
checks in `src/apply/**` and `src/secrets/**`, the build and dependency inputs
(`build.rs`, `.cargo/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`),
the test and its registration, the Alloy provenance, the validator allowlist
and the workflow itself. A red run should block merging a change to that surface by review,
not by branch protection.

The workflow installs the validator with the protected default-branch installer
and the candidate's allowlist, as `validate-pr.yml` does. It then checks out the
immutable Alloy producer, builds the CLI with locked dependencies, generates
both fixtures, and explicitly runs the consumer qualification test in
`tests/unit/companion_schema_tests.rs`; `cargo test` builds the `gitforgeops`
binary the test invokes. The test must list exactly once before execution.
Missing inputs, empty output, extra files, a missing validator or a failed
generation/validation fail the run.

The job holds only `contents: read`, binds no Environment or secrets, persists
no checkout credentials, and restores or publishes no build cache. The
installer's read-only token is scoped to its download step; producer builds and
generation receive no token binding.

The original orders manifest references `/etc/ferrum/edge-client.pem`,
`/etc/ferrum/edge-client.key` and `/etc/ferrum/alloy-ca.pem`. The allowlisted
validator reads and validates these files during schema validation. The hosted
qualification step creates a disposable CA and matching client certificate/key
with explicit OpenSSL commands at those paths. It refuses an existing
`/etc/ferrum` directory, gives the runner ownership of the new directory with
mode 0700, and keeps all files, including both private keys, at mode 0600.
OpenSSL output is suppressed; key material is never committed, cached or
uploaded. An exit trap removes only the job-created files and directory on
success or failure; the job's 30-minute limit and disposable hosted runner bound
their lifetime if the process is killed. The producer inputs and generated YAML
remain byte-for-byte unchanged. This exercises TLS material validation without
making a connection or proving a TLS handshake.

The fixtures exercise two output graphs:

| Producer input | Consumer coverage |
|---|---|
| `orders-api.toml` | `ferrum` namespace, HTTPS proxy, upstream with active HTTP health checks and TLS paths, correlation and tracing plugins |
| `plain-http.toml` | `retail` namespace, direct HTTP backend, base path, disabled read timeout, correlation and sampled tracing plugins |

The test loads each generated tree with default strictness, checks exact
non-empty inventories and namespace-scoped associations, preserves Alloy's
`generated-by` label alongside GitForgeOps attribution, invokes the shared Edge
validation runner, and invokes the actual `gitforgeops validate --format json`
CLI. It prints SHA-256 hashes of the generated files and verifies validation
does not rewrite them. Mutated copies cover only refusals that depend on the
generated shape: an unsupported `h2c` transport and an upstream moved outside
its proxy's namespace, which Edge rejects as a broken cross-namespace graph.
Generic refusals and controls run in the ordinary offline unit suite on every
Rust change instead:

- `loader_tests.rs`: unknown and null kinds; unknown wrapper, top-level and
  nested fields, including null-valued unknown keys; null required wrapper and
  spec fields (proxy `id` and `backend_port`, plugin `plugin_name` and `scope`,
  upstream target `host`); nullable optional proxy and upstream fields; and
  symlinks escaping the resource tree.
- `passthrough_tests.rs`: null-valued nested unknowns stay fatal under both
  strictness modes, and the unknown-field opt-in keeps a top-level null
  verbatim through export while refusing a null unknown wrapper.
- `validator_namespace_tests.rs`: `gitforgeops validate`, `plan`, `export` and
  file-mode `apply` refuse a repository-authored `api_spec_id` with
  "admin-generated" before any validator pass or publication. A
  path-traversing id such as `../escaped` reaches the validator verbatim and
  its refusal fails validation and blocks publication; GitForgeOps never uses a
  desired id as a path outside `import`, which refuses such ids itself
  (`import_tests.rs`).
- `namespace_filter_guard_tests.rs`: a typoed namespace filter refuses a
  non-empty tree.

This check qualifies resource consumption only. Alloy's pinned exporter emits
no Consumers, mesh fragments or credential slots. It does not qualify gateway
mutation APIs, traffic, TLS handshakes or release compatibility beyond the
reviewed producer and validator bytes actually exercised by a successful hosted
run. It adds no claim that manual acceptance in issue #266 passed. The validator
allowlist and release gates are unchanged; qualification uses the same
allowlisted validator as the pairing job. A digest absent from the allowlist
still fails closed. Update the producer SHA in the workflow and provenance
record, and the expected graph assertions, together when reviewing a producer
refresh.
