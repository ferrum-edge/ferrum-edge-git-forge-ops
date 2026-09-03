# companion-schema fixture

One resource file per kind, populating **every field** currently mirrored in
`src/config/schema.rs` — including the nested health-check, TLS,
service-discovery, plugin-trigger and stream-match structures, all five
credential types, and every top-level mesh collection.

`tests/unit/companion_schema_tests.rs` loads it under the fail-closed strict
loader, assembles it, and exports it. Two properties are pinned:

* the mirror can *read* everything it claims to model (a field added to
  ferrum-edge and mirrored here but spelled wrong in the mirror would fail the
  load), and
* the field set the fixture covers is checked against the struct definitions in
  `src/config/schema.rs`, so a newly mirrored field that nobody exercised here
  fails the test rather than shipping untested.

Two deliberate omissions, both asserted by that test:

* **`api_spec_id`** — admin-only, set by the gateway's OpenAPI spec importer.
  `apply::validate_no_desired_spec_tags` rejects a repository-authored one at
  the load boundary, so a fixture that declared it would not be a legal repo
  tree. Its round-trip is covered by the import and ownership tests.
* **`extra`** — the unknown-field pass-through, which by definition holds
  nothing the mirror models. Covered by `tests/unit/passthrough_tests.rs`.

Values are illustrative, not a working gateway configuration: a single
`service_discovery` block names all four providers so every mirrored sub-struct
is exercised in one file. `ferrum-edge validate` is the authority on which
combinations are legal; this fixture is about the companion's own serde mirror.

Credential values are `${gh-env-secret:alloc=require}` broker placeholders.
Never put a literal secret here.
