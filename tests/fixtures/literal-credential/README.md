# literal-credential fixture

The negative case for the literal-credential security gate.

`tests/fixtures/simple-config/` is the copy-paste sample and ships only
`${gh-env-secret:...}` placeholders. This tree is the opposite: one Consumer
whose `keyauth` key is a committed literal so `audit_security` still produces
the error-severity finding that blocks `plan` / `apply` / `review`.

Do not copy this tree into `resources/`. The value is a fixture needle, not a
secret, and findings must name the slot without echoing it.

`tests/unit/literal_credential_tests.rs` loads it under the fail-closed
strict loader and asserts that finding. CLI refusal of the same shape is
covered with an inline document in `tests/unit/apply_gate_tests.rs`.
