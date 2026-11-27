# edge-openapi fixture

`resource-fields.json` lists the top-level properties of the `Proxy` and
`Upstream` schemas in the Ferrum Edge `openapi.yaml` of the release this
repository pins, split into writable `properties` and `read_only` ones.
`source` records the release tag, commit and the SHA-256 of the
`openapi.yaml` the lists were read from.

`tests/unit/companion_schema_tests.rs` checks two things:

* every writable property is a field of the matching struct in
  `src/config/schema.rs`, so a gateway field the mirror does not model
  (and that import, apply and the strict loader would therefore refuse) fails
  CI instead of an operator's run; and
* every mirrored field (except the `extra` pass-through) is a property of the
  schema, so a misspelled or removed mirror field fails too.

It also requires `source.tag` to be the pinned release
(`validator.version` in `release/baseline.json`), so moving the validator pin
fails until this file is regenerated from the new release.

## Regenerating

From a ferrum-edge checkout, read `components.schemas.Proxy.properties` and
`components.schemas.Upstream.properties` of `openapi.yaml` at the new release
tag. A property is `read_only` when it carries `readOnly: true`. Keep both lists
sorted, update `source` (tag, the commit the tag resolves to, and
`shasum -a 256 openapi.yaml`), then mirror any new writable field in
`src/config/schema.rs` and the companion-schema fixture.
