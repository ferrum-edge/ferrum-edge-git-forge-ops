# Credential identities and broker boundaries

`basicauth[].username` and `mtls_auth[].identity` are public identity fields.
Write their values literally. The broker refuses its `${gh-env-secret:` marker
in either field, including incomplete or embedded placeholders. The refusal
does not depend on allocation mode, gateway mode, bundle contents or
`--allow-credential-slot-remap`. The error names the canonical slot and tells
you to author the identity literally, without printing the supplied value.

Literal identities stay readable in resource files and validator diagnostics.
`import` keeps them literal, and the security audit does not flag them as
committed secrets. Unknown Consumer credential types are refused before any
field is classified. Classification uses the credential type and the enclosing
object key; array indexes do not change which field a value belongs to.

## Correcting identity placeholders

Identity fields always need literal values. A seeded bundle value does not
make a placeholder valid: generation, resolution and inspect-only previews all
reject an identity placeholder. To fix one:

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

Every CLI path that loads desired resources goes through
`load_and_assemble_all` (directly or via `load_and_assemble_for`). Its identity
check runs after overlays and namespace selection, and before a caller can read
a bundle or take a state lock. The resolver checks again on its own, so direct
library callers get the same refusal. Resolution works on a copy and only
replaces the caller's document once the whole resolution succeeds; on any
error the input is left unchanged.

| Path | Identity refusal and output boundary |
| --- | --- |
| `validate` | Shared load check, then resolution; the validator scrubber receives the resolved snapshot and its report. |
| `plan` / `diff` | Shared load check and resolution precede live comparison. Plan validation receives resolution provenance. |
| `review` | Shared load check precedes resolution, validation, gateway reads and comment delivery. Review validation receives resolution provenance. |
| API `apply`, including interactive preview | Shared load check precedes security/override evaluation, bundle/state work, validator execution and allocation. Validation receives resolution provenance. |
| File `apply`, including allocation preview | Shared load check precedes the read-only report and all publication/allocation. Validation sees the unresolved publication document. |
| `rotate` | Desired resources load before bundle/state work. The published Consumer row then passes apply's literal-credential check, which exempts literal identities and refuses literal secrets, before the bundle is read. The lenient report also refuses identity placeholders, including in sibling consumers, before provisioning or delivery. |
| Plain `export` | Shared load check runs even though export preserves placeholders and does not resolve secrets. |
| Materialized/encrypted `export` | Shared load check, then apply's security audit on the unresolved document (no override), precede the bundle read, resolution, output publication and recipient discovery. |

The validator-output scrubber combines literal-secret classification with the
values at the report's successfully resolved slots. It builds slot paths with
the resolver's own canonical path functions (index-zero elision, indexed
entries, escaped object keys). It does not collect unused bundle entries, and
it does not redact an unrelated literal identity just because of its field
name. A resolved value that itself looks like a placeholder is still redacted.
The report stores metadata, not secret values.

The same report controls validator stand-ins: only slots it marks as
unresolved consumer or plugin slots may be replaced with a stand-in. A resolved
value that looks like a placeholder reaches the validator byte-for-byte, so an
invalid short JWT secret or endpoint still fails validation without leaking
through diagnostics. Slots the report does not mention are left unchanged.
Without a report (the public `with_validation_standins` function, and
file-mode `apply`), the input is an unresolved publication document and
placeholder syntax alone selects a stand-in; a read-only allocation report is
not used as substitution provenance there. Modeled service-discovery values are
passed to the validator unchanged.

Regression tests (run in GitHub-hosted Rust CI) cover whole-input preservation
in strict and lenient resolution, identity handling in the audit and import,
canonical slot provenance, and CLI runs with synthetic bundles and a validator
that echoes its input. The CLI refusal tests trap gateway and GitHub traffic on
loopback and check that input, bundle and existing output files survive and
that no validator run, state lock or export happens.
