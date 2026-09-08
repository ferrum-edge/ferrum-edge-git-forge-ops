# Credential identities and broker boundaries

`basicauth[].username` and `mtls_auth[].identity` are public identity fields.
Author their values literally. The broker rejects its `${gh-env-secret:` marker
in either leaf, including incomplete or embedded placeholders. The refusal is
independent of allocation mode, gateway mode, bundle contents and
`--allow-credential-slot-remap`. It names the canonical slot and explains the
literal-identity remedy without printing the supplied value or placeholder.

Literal identities remain readable in resource files and validator diagnostics.
Import keeps them literal; the security audit does not flag them as committed
secrets. A `username` under a custom credential type still follows the secret
rules. Classification uses the structural credential type and enclosing object
key, with array indexes carrying the key unchanged.

## Migration for the next release

Previously seeded identity placeholders are deliberately no longer accepted.
Generation was already forbidden; this change also refuses loading an existing
bundle value and refuses inspect-only previews of an invalid identity.

1. Replace each identity placeholder in resources and overlays with the intended
   public login or certificate identity. Keep the credential array order stable.
2. Retire the corresponding identity slot from the credential bundle. Preserve
   sibling password/key slots and their indexes; removing an array entry can
   reassign another credential's slot.
3. If an earlier run resolved the identity from the bundle, treat that value as
   potentially disclosed in validator logs or PR output. If it was also used as
   authentication material, replace that material through its owning system and
   reseed the appropriate secret slot. Do not use `rotate` on the identity slot.
4. Validate and plan the literal-identity configuration before applying it.

## Static command-boundary audit

All desired-resource CLI paths use `load_and_assemble_all`, directly or through
`load_and_assemble_for`. Its identity check runs after overlays and namespace
selection and before callers can read bundles or create state locks. The
resolver also checks independently, so direct library callers get the same
refusal. Its mutating entry point only commits a candidate document after the
whole resolution succeeds; any error preserves the caller's complete input.

| Path | Identity refusal and output boundary |
| --- | --- |
| `validate` | Shared load check, then resolution; the validator scrubber receives the resolved snapshot and its report. |
| `plan` / `diff` | Shared load check and resolution precede live comparison. Plan validation receives resolution provenance. |
| `review` | Shared load check precedes resolution, validation, gateway reads and comment delivery. Review validation receives resolution provenance. |
| API `apply`, including interactive preview | Shared load check precedes security/override evaluation, bundle/state work, validator execution and allocation. Validation receives resolution provenance. |
| File `apply`, including allocation preview | Shared load check precedes the read-only report and all publication/allocation. Validation sees the unresolved publication document. |
| `rotate` | Desired resources load before bundle/state work. The lenient report also refuses identity placeholders, including in sibling consumers, before provisioning or delivery. |
| Plain `export` | Shared load check runs even though export preserves placeholders and does not resolve secrets. |
| Materialized/encrypted `export` | Shared load check and resolution precede output publication and recipient discovery. |

The scrubber combines literal-secret classification with values at the report's
successfully resolved slots. It uses the resolver's canonical path constructors,
including index-zero elision, indexed entries and escaped object keys. It does
not collect unused bundle entries or redact an unrelated literal identity just
because of its field name. A value that itself resembles a placeholder is still
protected when its slot resolved. The report stores metadata, not secret values.

Regression coverage includes whole-input preservation in strict and lenient
resolution, literal identity audit/import controls, canonical provenance slots,
and CLI runs with synthetic bundles and a validator that quotes its input.
CLI refusal tests trap gateway/GitHub traffic on loopback and check that input,
bundle and existing output files survive and no validator, state lock or export
is created. These tests run in GitHub-hosted Rust CI.
