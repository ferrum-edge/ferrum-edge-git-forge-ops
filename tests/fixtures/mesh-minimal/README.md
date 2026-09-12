# mesh-minimal fixture

A legal GitOps mesh tree that `ferrum-edge validate -m mesh` must accept.

`tests/fixtures/companion-schema/` is the serde every-field mirror: it
populates every collection the companion models, including combinations
ferrum-edge rejects (missing workload `selector`, mutually exclusive TLS
fields, and so on). That fixture must not be treated as a working mesh
document. This fixture is the opposite: the smallest `MeshConfig` that the
gateway's mesh validator grades green.

Shape, taken from Ferrum Edge's mesh data model (`docs/mesh.md`) and the
required `Workload` / `MeshService` fields:

* one workload with a `selector` (required on `Workload`, not optional)
* matching `spiffe_id` / `trust_domain`
* non-empty `service_name` and `namespace`
* one service referencing that workload by SPIFFE ID
* a non-zero service/workload port

`tests/unit/mesh_minimal_tests.rs` loads it under the fail-closed strict
loader, assembles it, and asserts the rendered `{version, mesh}` document
still carries that selector. Keep `companion-schema/` unchanged.

gitforgeops' mesh pass sets `FERRUM_MESH_ALLOW_NO_CA=true` on the validator
child so a CI runner without a mesh node's SVID can grade the document;
that opt-out is not part of this fixture.
