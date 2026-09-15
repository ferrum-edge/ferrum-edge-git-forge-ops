//! Coverage for `tests/fixtures/mesh-minimal/`: the smallest MeshConfig that
//! `ferrum-edge validate -m mesh` must accept.
//!
//! `companion-schema/` is the serde every-field mirror and is intentionally not
//! a working mesh document. This fixture is the opposite expectation: it
//! must load, assemble, and render a `{version, mesh}` document whose
//! workloads carry a `selector` and that includes the smallest
//! workload + service set Ferrum Edge's mesh data model requires.

use std::path::PathBuf;

use gitforgeops::apply::render_mesh_yaml;
use gitforgeops::config::{assemble, load_resources};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mesh-minimal")
}

fn load_fixture() -> gitforgeops::config::AssembledOutput {
    let resources =
        load_resources(&fixture_dir()).expect("mesh-minimal fixture must load under strict mode");
    assemble(resources).expect("assemble")
}

#[test]
fn mesh_minimal_fixture_loads_and_assembles_under_strict_mode() {
    let assembled = load_fixture();
    assert!(
        assembled.gateway.proxies.is_empty()
            && assembled.gateway.consumers.is_empty()
            && assembled.gateway.upstreams.is_empty()
            && assembled.gateway.plugin_configs.is_empty(),
        "mesh-minimal is mesh-only: {assembled:#?}"
    );

    let mesh = assembled.mesh.expect("mesh fragment merged");
    assert_eq!(mesh.workloads.len(), 1, "{mesh:?}");
    assert_eq!(mesh.services.len(), 1, "{mesh:?}");
    assert!(
        mesh.workloads[0].get("selector").is_some(),
        "every workload must carry a selector: {}",
        mesh.workloads[0]
    );
}

#[test]
fn mesh_minimal_fixture_renders_the_document_ferrum_edge_validates() {
    let mesh = load_fixture().mesh.expect("mesh fragment");
    let document = render_mesh_yaml(&mesh).expect("render mesh document");
    let value: serde_yaml::Value = serde_yaml::from_str(&document).expect("parse rendered YAML");

    assert_eq!(value["version"].as_str(), Some("1"));
    let rendered = &value["mesh"];
    assert_eq!(
        rendered["workloads"][0]["selector"]["labels"]["app"].as_str(),
        Some("api"),
        "{document}"
    );
    assert_eq!(
        rendered["workloads"][0]["spiffe_id"].as_str(),
        Some("spiffe://cluster.local/ns/ferrum/sa/api")
    );
    assert_eq!(
        rendered["workloads"][0]["trust_domain"].as_str(),
        Some("cluster.local")
    );
    assert_eq!(rendered["services"][0]["name"].as_str(), Some("api"));
    assert_eq!(
        rendered["services"][0]["workloads"][0]["spiffe_id"].as_str(),
        Some("spiffe://cluster.local/ns/ferrum/sa/api")
    );

    let reparsed: gitforgeops::config::MeshConfigSpec =
        serde_yaml::from_value(rendered.clone()).expect("reparse mesh");
    assert_eq!(reparsed, mesh);
}

#[test]
fn mesh_minimal_is_not_the_companion_schema_mirror() {
    // A regression that pointed this test at companion-schema would load
    // five kinds and a mesh without selectors — the exact invalid document
    // this fixture exists to replace as the green mesh contract.
    let assembled = load_fixture();
    assert_eq!(
        assembled.gateway.proxies.len()
            + assembled.gateway.consumers.len()
            + assembled.gateway.upstreams.len()
            + assembled.gateway.plugin_configs.len(),
        0
    );
    let mesh = assembled.mesh.expect("mesh");
    assert!(mesh.peer_authentications.is_empty());
    assert!(mesh.destination_rules.is_empty());
    assert!(mesh.trust_bundles.is_none());
}
