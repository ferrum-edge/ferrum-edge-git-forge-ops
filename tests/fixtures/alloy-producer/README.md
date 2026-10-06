# Alloy producer provenance

[PROVENANCE.json](PROVENANCE.json) pins the Alloy producer by full commit SHA
and lists the original input manifests the qualification generates from. The
commit SHA fixes their bytes, so no manifest copy, checksum list or generated
GitForgeOps output is vendored here.

The non-required [Alloy consumer qualification](../../../.github/workflows/alloy-consumer.yml)
workflow checks out that producer SHA, builds the Alloy CLI with locked
dependencies, and runs `ferrum-alloy edge export --format gitforgeops` on both
original manifests. The consumer test in `tests/unit/companion_schema_tests.rs`
loads those generated trees through the strict loader, assembles them, and uses
both the shared validation runner and the `gitforgeops validate` command with
the installed, allowlisted Edge validator. It checks exact non-empty
inventories and prints the generated files' SHA-256 hashes into the job log.

The original orders TLS paths are populated only during hosted qualification
with disposable OpenSSL-generated CA/client material. The job uses private
permissions and an exit trap for cleanup; it never rewrites a manifest or
generated resource to avoid TLS validation, and no private key is vendored.

The hosted test is explicitly selected with `--ignored --exact`; the workflow
first requires it to list exactly one test. It fails when fixture or validator
paths are missing. Ordinary unit tests check the provenance record without
requiring network access, generation or an installed validator.

See [the consumer guide](../../../docs/alloy-consumer.md) for scope and limits.
