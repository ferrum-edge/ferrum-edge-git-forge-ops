# Alloy producer inputs

`orders-api.toml` and `plain-http.toml` are byte-for-byte input manifests fetched
from the immutable Alloy revision in [PROVENANCE.json](PROVENANCE.json).
[SHA256SUMS](SHA256SUMS) records their original producer paths and hashes, along
with the exporter, manifest parser, CLI implementation, CLI tests and lockfile.
These are inputs, not hand-written or captured GitForgeOps output.

The existing `validator-pairing` hosted CI job checks out that full producer SHA,
verifies these hashes, builds both CLIs with locked dependencies, and runs
`ferrum-alloy edge export --format gitforgeops` on both original manifests. The
consumer test in `tests/unit/companion_schema_tests.rs` loads those generated
trees through the strict loader, assembles them, and uses both the shared
validation runner and the `gitforgeops validate` command with the installed,
allowlisted Edge validator. It checks exact non-empty inventories and prints
the generated files' SHA-256 hashes into the job log.

The original orders TLS paths are populated only during hosted qualification
with disposable OpenSSL-generated CA/client material. The job uses private
permissions and an exit trap for cleanup; it never rewrites a manifest or
generated resource to avoid TLS validation, and no private key is vendored.
Generated-tree mutations cover required and unknown null values, with positive
controls for supported nullable fields and the explicit top-level opt-in.

The hosted test is explicitly selected with `--ignored --exact`; the CI step
first requires it to list exactly one test. It fails when fixture or validator
paths are missing. Ordinary unit tests verify the input provenance without
requiring network access, generation or an installed validator.

See [the consumer guide](../../../docs/alloy-consumer.md) for scope and limits.
