//! Coverage for `tests/fixtures/companion-schema/`: one resource per kind
//! populating every field the serde mirror in `src/config/schema.rs` models.
//!
//! Two things are being pinned. First, that the mirror can actually *read*
//! everything it claims to model — a mirrored field spelled differently from
//! the gateway's wire name fails the strict load here rather than in a user's
//! CI. Second, that the fixture stays complete: the covered field set is
//! checked against the struct definitions in `schema.rs`, so a newly mirrored
//! field that nobody exercised fails this test instead of shipping untested.

use std::collections::BTreeSet;
use std::path::PathBuf;

use gitforgeops::config::schema::Resource;
use gitforgeops::config::{assemble, load_resources};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/companion-schema")
}

fn schema_source() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/config/schema.rs"))
        .expect("read schema.rs")
}

/// Field names declared on one `pub struct` in `schema.rs`.
///
/// Reading the source is deliberate: Rust has no runtime reflection, and the
/// alternative — a hand-maintained list in this test — is the very thing that
/// goes stale. The file is written in a single consistent style (`pub name:`,
/// one field per line), so a line-oriented scan is exact.
fn declared_fields(source: &str, struct_name: &str) -> BTreeSet<String> {
    let header = format!("pub struct {struct_name} {{");
    let start = source
        .find(&header)
        .unwrap_or_else(|| panic!("`{header}` not found in schema.rs"))
        + header.len();
    let body = &source[start..];
    let end = body
        .find("\n}")
        .unwrap_or_else(|| panic!("unterminated `{struct_name}` in schema.rs"));

    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("pub ")?;
            let (name, _) = rest.split_once(':')?;
            Some(name.trim().to_string())
        })
        .collect()
}

/// Fields the fixture is *allowed* not to set, each for a stated reason.
fn intentionally_uncovered(struct_name: &str) -> BTreeSet<String> {
    let mut skip: BTreeSet<String> = BTreeSet::new();
    // The unknown-field pass-through holds, by construction, nothing the
    // mirror models. Exercised by `passthrough_tests.rs`.
    skip.insert("extra".to_string());
    // Admin-only, written by the gateway's OpenAPI spec importer.
    // `apply::validate_no_desired_spec_tags` rejects a repo-authored one, so a
    // fixture declaring it would not be a legal repository tree. Its
    // round-trip is covered by the import and ownership tests.
    if matches!(struct_name, "Proxy" | "Upstream" | "PluginConfig") {
        skip.insert("api_spec_id".to_string());
    }
    skip
}

fn spec_keys(resource: &Resource) -> BTreeSet<String> {
    let value = serde_json::to_value(resource).expect("serialize resource");
    value["spec"]
        .as_object()
        .expect("spec is an object")
        .keys()
        .cloned()
        .collect()
}

fn load_fixture() -> Vec<(String, Resource)> {
    // Fail-closed strict loader, no opt-outs: the fixture must be legal input
    // for the default configuration every operator runs.
    load_resources(&fixture_dir()).expect("companion-schema fixture must load under strict mode")
}

#[test]
fn companion_schema_fixture_loads_and_assembles_under_strict_mode() {
    let resources = load_fixture();
    assert_eq!(resources.len(), 5, "one resource per kind: {resources:#?}");

    let assembled = assemble(resources).expect("assemble");
    assert_eq!(assembled.gateway.proxies.len(), 1);
    assert_eq!(assembled.gateway.consumers.len(), 1);
    assert_eq!(assembled.gateway.upstreams.len(), 1);
    assert_eq!(assembled.gateway.plugin_configs.len(), 1);

    let mesh = assembled.mesh.expect("mesh fragment merged");
    assert!(!mesh.is_empty());
    assert_eq!(mesh.workloads.len(), 2);
    assert_eq!(mesh.services.len(), 2);
    assert_eq!(mesh.istio_root_namespace.as_deref(), Some("istio-system"));

    // All five credential types survive load and normalization, still as
    // unresolved broker placeholders.
    let consumer = &assembled.gateway.consumers[0];
    let credential_types: BTreeSet<&str> =
        consumer.credentials.keys().map(String::as_str).collect();
    assert_eq!(
        credential_types,
        BTreeSet::from(["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"])
    );
    // Every secret-bearing leaf is an unresolved broker placeholder: a fixture
    // is still a repository tree, and a literal credential must never be one.
    let mut secret_leaves = 0;
    for (credential_type, entries) in &consumer.credentials {
        for entry in entries.as_array().expect("canonical array form") {
            for (field, value) in entry.as_object().expect("credential entry object") {
                // `jwt.key` is the issuer/kid identifier, not secret material.
                let is_secret = match field.as_str() {
                    "secret" | "password_hash" => true,
                    "key" => credential_type == "keyauth",
                    _ => false,
                };
                if !is_secret {
                    continue;
                }
                secret_leaves += 1;
                assert_eq!(
                    value.as_str(),
                    Some("${gh-env-secret:alloc=require}"),
                    "credential leaf `{field}` must be a broker placeholder"
                );
            }
        }
    }
    assert_eq!(
        secret_leaves, 4,
        "basicauth password_hash, keyauth key, jwt secret, hmac_auth secret"
    );
}

#[test]
fn companion_schema_fixture_covers_every_mirrored_field() {
    let source = schema_source();
    let resources = load_fixture();

    for (struct_name, matcher) in [
        ("Proxy", "Proxy"),
        ("Consumer", "Consumer"),
        ("Upstream", "Upstream"),
        ("PluginConfig", "PluginConfig"),
        ("MeshConfigSpec", "MeshConfig"),
    ] {
        let resource = resources
            .iter()
            .map(|(_, resource)| resource)
            .find(|resource| {
                matches!(
                    (matcher, resource),
                    ("Proxy", Resource::Proxy { .. })
                        | ("Consumer", Resource::Consumer { .. })
                        | ("Upstream", Resource::Upstream { .. })
                        | ("PluginConfig", Resource::PluginConfig { .. })
                        | ("MeshConfig", Resource::MeshConfig { .. })
                )
            })
            .unwrap_or_else(|| panic!("fixture is missing a {matcher}"));

        let expected: BTreeSet<String> = declared_fields(&source, struct_name)
            .difference(&intentionally_uncovered(struct_name))
            .cloned()
            .collect();
        let covered = spec_keys(resource);
        let missing: Vec<&String> = expected.difference(&covered).collect();
        assert!(
            missing.is_empty(),
            "tests/fixtures/companion-schema/ does not exercise {struct_name} field(s) {missing:?} — \
             add them to the fixture (or to `intentionally_uncovered` with a reason)"
        );
    }
}

#[test]
fn companion_schema_fixture_survives_an_export_round_trip() {
    let assembled = assemble(load_fixture()).unwrap();
    let exported = gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap();

    // Every mirrored field is still there after serialization, and the
    // document re-parses into the same configuration.
    let document: serde_yaml::Value = serde_yaml::from_str(&exported).unwrap();
    let reparsed: gitforgeops::config::GatewayConfig = serde_yaml::from_value(document).unwrap();
    assert_eq!(
        serde_json::to_value(&reparsed).unwrap(),
        serde_json::to_value(&assembled.gateway).unwrap(),
        "export must round-trip every mirrored field"
    );

    let mesh = assembled.mesh.expect("mesh fragment");
    let mesh_document = gitforgeops::apply::render_mesh_yaml(&mesh).unwrap();
    let mesh_value: serde_yaml::Value = serde_yaml::from_str(&mesh_document).unwrap();
    let mesh_reparsed: gitforgeops::config::MeshConfigSpec =
        serde_yaml::from_value(mesh_value["mesh"].clone()).unwrap();
    assert_eq!(mesh_reparsed, mesh);
}

/// Directory walk order must not reach the output. `load_resources` sorts both
/// namespace entries and per-directory paths precisely so that two checkouts
/// of the same tree — whose `readdir` order differs by filesystem and by
/// creation order — export byte-identical documents; otherwise `diff` would
/// report drift that no edit could clear.
#[test]
fn export_bytes_are_independent_of_file_creation_order() {
    let files: Vec<(PathBuf, String)> = walk_fixture_files();
    assert!(files.len() >= 5, "expected the whole fixture: {files:#?}");

    let render = |order: &[usize]| {
        let tmp = tempfile::tempdir().unwrap();
        for &index in order {
            let (relative, contents) = &files[index];
            let destination = tmp.path().join(relative);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::write(&destination, contents).unwrap();
        }
        let assembled = assemble(load_resources(tmp.path()).unwrap()).unwrap();
        gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap()
    };

    let forward: Vec<usize> = (0..files.len()).collect();
    let reverse: Vec<usize> = (0..files.len()).rev().collect();
    // A deterministic "shuffle" — every ordering must agree, and a fixed
    // permutation keeps the test reproducible when it fails.
    let interleaved: Vec<usize> = (0..files.len())
        .step_by(2)
        .chain((1..files.len()).step_by(2))
        .collect();

    let baseline = render(&forward);
    assert_eq!(baseline, render(&reverse));
    assert_eq!(baseline, render(&interleaved));
    // And the fixture tree itself, read in place, agrees with all of them.
    let in_place =
        gitforgeops::apply::render_file_yaml(&assemble(load_fixture()).unwrap().gateway).unwrap();
    assert_eq!(baseline, in_place);
}

fn walk_fixture_files() -> Vec<(PathBuf, String)> {
    let root = fixture_dir();
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(&root).sort_by_file_name() {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(&root).unwrap().to_path_buf();
        files.push((relative, std::fs::read_to_string(entry.path()).unwrap()));
    }
    files
}
