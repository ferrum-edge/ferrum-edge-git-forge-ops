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
The accompanying [hash manifest](../tests/fixtures/alloy-producer/SHA256SUMS)
covers the two input manifests, producer implementation, CLI tests and lockfile.
Only original input manifests are vendored; generated YAML is produced afresh
by the pinned CLI in GitHub-hosted CI.

The existing required `validator-pairing` job in `validate-pr.yml` first runs
the protected default-branch validator installer and resource-label probe with
their existing bindings. It then checks out and verifies the immutable Alloy
producer, builds both CLIs with locked dependencies, generates both fixtures,
and explicitly runs the consumer qualification test in
`tests/unit/companion_schema_tests.rs`. The test must list exactly once before
execution. Missing inputs, empty output, extra files, a missing validator or a
failed generation/validation fail the job. The existing
`gitforgeops-required-static-validation` status requires that pairing job on
every PR, including repositories without customer resources or environments.

The job holds only `contents: read`, binds no Environment or secrets, persists
no checkout credentials, and restores or publishes no build cache. The
installer's read-only token is scoped to its existing download step; producer
builds and generation receive no token binding. No protected checker admission
or guarded workflow binding is changed by this consumer check.

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
does not rewrite them. Mutated copies exercise unknown kinds, unknown top-level
and nested fields, unsupported `h2c` transport, an upstream moved outside its
proxy's namespace, a typoed namespace filter, forged `api_spec_id` ownership,
path-traversing resource IDs and symlinks escaping the resource tree. Explicit
namespace overrides retain their existing semantics; Edge rejects the broken
cross-namespace graph.

This check qualifies resource consumption only. Alloy's pinned exporter emits
no Consumers, mesh fragments or credential slots. It does not qualify gateway
mutation APIs, traffic, TLS handshakes or release compatibility beyond the
reviewed producer and validator bytes actually exercised by a successful hosted
run. It adds no claim that manual acceptance in issue #266 passed. The validator
allowlist and release gates are unchanged; qualification uses the validator
installed by the existing pairing job. A digest absent from the allowlist still
fails closed. Update the producer SHA, provenance hashes and expected graph
assertions together when reviewing a producer refresh.
