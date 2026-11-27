# Paired `pool_max_requests_per_connection` fixtures

Two minimal, valid proxy trees that differ only in whether
`Proxy.spec.pool_max_requests_per_connection` is set (`#739`):

* **`with-field/`** — sets `pool_max_requests_per_connection: 1000`.
* **`without-field/`** — omits `pool_max_requests_per_connection`.

Ferrum Edge v0.9.20 accepts and persists `pool_max_requests_per_connection` (a
no-op field whose omission on write clears the stored value). Ferrum Edge
v0.9.21 removed the field while keeping `Proxy` `deny_unknown_fields`
(`ferrum-edge#7218`; detected ahead of release by the weekly Edge `main` check
in `#737`).

`tests/unit/edge_version_tests.rs` and `tests/unit/validator_namespace_tests.rs`
exercise both fixtures across an explicit v0.9.20 pairing and the v0.9.21
pairing (the default, the release the repository pins).
