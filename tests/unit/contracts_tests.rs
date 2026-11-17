//! Conformance checks for the pinned ferrum-contracts release.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use gitforgeops::config::load_resources;
use gitforgeops::config::schema::Resource;
use gitforgeops::plugin_catalog::{BUILTIN_PLUGINS, RESERVED_PLUGIN_NAMES, RETIRED_PLUGIN_NAMES};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts/ferrum-contracts")
}

fn parse_pin() -> (String, String, String, BTreeMap<String, String>) {
    let pin = fs::read_to_string(contract_dir().join("PIN")).expect("read contracts PIN");
    let mut tag = None;
    let mut commit = None;
    let mut edge_version = None;
    let mut hashes = BTreeMap::new();

    for line in pin.lines().filter(|line| !line.is_empty()) {
        if let Some(value) = line.strip_prefix("tag=") {
            tag = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("commit=") {
            commit = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("edge_version=") {
            edge_version = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("sha256 ") {
            let (path, hash) = value
                .split_once(' ')
                .unwrap_or_else(|| panic!("invalid sha256 PIN row: {line}"));
            assert!(hashes.insert(path.to_string(), hash.to_string()).is_none());
        } else {
            panic!("unrecognized contracts PIN row: {line}");
        }
    }

    (
        tag.expect("PIN has a tag"),
        commit.expect("PIN has a commit"),
        edge_version.expect("PIN has an Edge version"),
        hashes,
    )
}

fn contract_files(root: &Path, directory: &Path, found: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read contract directory") {
        let path = entry.expect("read contract directory entry").path();
        if path.is_dir() {
            contract_files(root, &path, found);
        } else if path.file_name().and_then(|name| name.to_str()) != Some("PIN") {
            found.insert(
                path.strip_prefix(root)
                    .expect("contract path is under contract root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn json(path: &str) -> Value {
    let bytes =
        fs::read(contract_dir().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn string_set<'a>(values: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    values.map(str::to_string).collect()
}

#[test]
fn vendored_contract_files_match_the_pin_hashes() {
    let (tag, commit, edge_version, hashes) = parse_pin();
    assert_eq!(tag, "contracts-edge-0.9.20");
    assert_eq!(commit, "39da322083044c2e92617209e62983c92387f0ad");
    assert_eq!(edge_version, "v0.9.20");

    let mut vendored = BTreeSet::new();
    contract_files(&contract_dir(), &contract_dir(), &mut vendored);
    let pinned: BTreeSet<String> = hashes.keys().cloned().collect();
    assert_eq!(
        vendored.difference(&pinned).cloned().collect::<Vec<_>>(),
        Vec::<String>::new(),
        "vendored files missing from PIN"
    );
    assert_eq!(
        pinned.difference(&vendored).cloned().collect::<Vec<_>>(),
        Vec::<String>::new(),
        "PIN entries without vendored files"
    );

    for (path, expected) in hashes {
        let bytes = fs::read(contract_dir().join(&path))
            .unwrap_or_else(|error| panic!("read pinned {path}: {error}"));
        let actual: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, expected, "pinned contract file changed: {path}");
    }
}

/// The pin's tag and Edge version are asserted literally above; this checks
/// that the Edge version it names is one the validator allowlist accepts.
#[test]
fn pinned_edge_version_is_in_the_checksum_allowlist() {
    let (_, _, edge_version, _) = parse_pin();
    let checksums = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/ferrum-edge-checksums.txt"),
    )
    .expect("read Edge checksum allowlist");
    let allowlisted_edge_versions: BTreeSet<&str> = checksums
        .lines()
        .filter_map(|line| line.split_once('#').map(|(_, note)| note))
        .flat_map(str::split_whitespace)
        .filter(|value| {
            value.starts_with('v')
                && value[1..]
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.')
        })
        .collect();
    assert!(
        allowlisted_edge_versions.contains(edge_version.as_str()),
        "PIN Edge version {edge_version} is absent from the checksum allowlist"
    );
}

#[test]
fn local_plugin_catalog_matches_the_pinned_contract() {
    let contract = json("vocabularies/plugin-catalog.json");
    let plugins = contract["plugins"]
        .as_array()
        .expect("contract plugins array");
    let mut contract_plugins = BTreeMap::new();
    let mut contract_reserved = BTreeSet::new();
    for plugin in plugins {
        let name = plugin["name"].as_str().expect("plugin name").to_string();
        let priority = plugin["priority"].as_u64().expect("plugin priority") as u16;
        assert!(contract_plugins.insert(name.clone(), priority).is_none());
        if plugin["classification"] == "reserved" {
            contract_reserved.insert(name);
        }
    }

    let local_plugins: BTreeMap<String, u16> = BUILTIN_PLUGINS
        .iter()
        .map(|plugin| (plugin.name.to_string(), plugin.priority))
        .collect();
    assert_eq!(
        contract_plugins.keys().collect::<Vec<_>>(),
        local_plugins.keys().collect::<Vec<_>>(),
        "plugin names differ; local missing names: {:?}; local extra names: {:?}",
        contract_plugins
            .keys()
            .filter(|name| !local_plugins.contains_key(*name))
            .collect::<Vec<_>>(),
        local_plugins
            .keys()
            .filter(|name| !contract_plugins.contains_key(*name))
            .collect::<Vec<_>>()
    );
    for (name, expected_priority) in &contract_plugins {
        assert_eq!(
            local_plugins.get(name),
            Some(expected_priority),
            "priority drift for plugin {name}"
        );
    }

    let contract_retired: BTreeSet<String> = contract["removed_plugins"]
        .as_array()
        .expect("removed_plugins array")
        .iter()
        .map(|plugin| {
            plugin["name"]
                .as_str()
                .expect("removed plugin name")
                .to_string()
        })
        .collect();
    assert_eq!(
        contract_retired,
        string_set(RETIRED_PLUGIN_NAMES.iter().copied()),
        "retired plugin names differ"
    );
    assert_eq!(
        contract_reserved,
        string_set(RESERVED_PLUGIN_NAMES.iter().copied()),
        "reserved plugin names differ"
    );
}

#[test]
fn local_provisioned_by_label_matches_the_pinned_contract() {
    let contract = json("vocabularies/provisioned-by.json");
    let label_key = contract["label"]["key"].as_str().expect("label key");
    let resources: BTreeSet<String> = contract["label"]["resources"]
        .as_array()
        .expect("label resources")
        .iter()
        .map(|resource| resource.as_str().expect("resource name").to_string())
        .collect();
    assert_eq!(label_key, "provisioned-by");
    assert_eq!(
        resources,
        ["Consumer", "PluginConfig", "Proxy", "Upstream"]
            .into_iter()
            .map(String::from)
            .collect(),
        "GitForgeOps provisioned-by resource set differs"
    );

    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/config/assembler.rs"),
    )
    .expect("read assembler.rs");
    let local_value = contract["values"]
        .as_array()
        .expect("provisioned-by values")
        .iter()
        .find(|entry| entry["product"] == "GitForgeOps")
        .and_then(|entry| entry["value"].as_str())
        .expect("GitForgeOps provisioned-by value");
    assert_eq!(local_value, "ferrum-edge-git-forge-ops");
    assert_eq!(source.matches("\"provisioned-by\"").count(), 4);
    assert_eq!(source.matches("\"ferrum-edge-git-forge-ops\"").count(), 4);
}

/// The resource-tree directory the production loader expects a kind under.
/// An unknown or missing kind goes under `proxies/`: the loader refuses it
/// while parsing, before any directory check.
fn kind_directory(document: &Value) -> &'static str {
    match document.get("kind").and_then(Value::as_str) {
        Some("Consumer") => "consumers",
        Some("Upstream") => "upstreams",
        Some("PluginConfig") => "plugins",
        Some("MeshConfig") => "mesh",
        _ => "proxies",
    }
}

/// Load one resource document the way `import`, `validate` and `apply` do:
/// written as YAML into a throwaway `resources/<namespace>/<kind>/` tree and
/// read back with the fail-closed production loader (`load_resources`), not
/// with serde, which ignores the envelope keys the loader refuses.
fn load_with_the_production_loader(
    document: &Value,
) -> gitforgeops::error::Result<Vec<(String, Resource)>> {
    let tree = tempfile::tempdir().expect("temporary resource tree");
    let directory = tree.path().join("ferrum").join(kind_directory(document));
    fs::create_dir_all(&directory).expect("create kind directory");
    let yaml = gitforgeops::yaml::to_string(document).expect("render fixture as YAML");
    fs::write(directory.join("fixture.yaml"), yaml).expect("write fixture");
    load_resources(tree.path())
}

fn resource_fixtures(class: &str) -> Vec<(String, Value)> {
    let directory = contract_dir()
        .join("fixtures/gitforgeops-resource")
        .join(class);
    let mut fixtures: Vec<(String, Value)> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read {class} fixtures: {error}"))
        .map(|entry| {
            let path = entry.expect("fixture entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).expect("read fixture");
            let document = serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("parse {class} fixture {name}: {error}"));
            (name, document)
        })
        .collect();
    fixtures.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(!fixtures.is_empty(), "no {class} contract fixtures");
    fixtures
}

#[test]
fn gitforgeops_resource_contract_fixtures_match_the_strict_production_loader() {
    for (name, document) in resource_fixtures("valid") {
        let resources = load_with_the_production_loader(&document).unwrap_or_else(|error| {
            panic!("valid contract fixture {name} rejected by the strict loader: {error}")
        });
        assert_eq!(resources.len(), 1, "{name}");
        let loaded = serde_json::to_value(&resources[0].1).expect("serialize loaded resource");
        assert_eq!(loaded["kind"], document["kind"], "{name}");
    }
    for (name, document) in resource_fixtures("invalid") {
        let error = load_with_the_production_loader(&document)
            .expect_err("an invalid contract fixture must be refused by the strict loader");
        // Refused for what the fixture says, never for the throwaway tree.
        assert!(
            !error.to_string().contains("but is under"),
            "invalid contract fixture {name} was refused only for its directory: {error}"
        );
    }
}

/// The loader accepts only `kind` and `spec`, plus `id` on a MeshConfig. Every
/// valid fixture with an extra wrapper key, or a non-mesh one with `id`, is
/// refused: the envelope a producer validates against must be just as closed.
#[test]
fn the_strict_loader_refuses_envelope_keys_outside_the_contract() {
    for (name, document) in resource_fixtures("valid") {
        let mut extra_key = document.clone();
        extra_key["metadata"] = serde_json::json!({"owner": "team-a"});
        let error = load_with_the_production_loader(&extra_key)
            .expect_err("an extra wrapper key must be refused");
        assert!(error.to_string().contains(".metadata"), "{name}: {error}");

        if document["kind"] != "MeshConfig" {
            let mut with_id = document.clone();
            with_id["id"] = serde_json::json!("fixture");
            let error = load_with_the_production_loader(&with_id)
                .expect_err("`id` on a gateway kind must be refused");
            assert!(error.to_string().contains(".id"), "{name}: {error}");
        }
    }
}

/// `contracts-edge-0.9.20` publishes an open envelope (no top-level
/// `additionalProperties: false`), which admits the keys the loader refuses
/// above (ferrum-contracts#73). Any later pin must close it: re-pinning to a
/// release whose envelope is still open fails here, so the schema and the
/// loader can only diverge on the release already vendored.
#[test]
fn a_repinned_contract_must_close_the_resource_envelope() {
    let (tag, _, _, _) = parse_pin();
    let schema = json("schemas/gitforgeops-resource/v1.schema.json");
    if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
        assert_eq!(
            tag, "contracts-edge-0.9.20",
            "the pinned gitforgeops-resource envelope admits wrapper keys the strict loader \
             refuses; pin a contracts release that closes it"
        );
    }
}

#[test]
fn gitforgeops_resource_schema_matches_the_local_resource_envelope() {
    let schema = json("schemas/gitforgeops-resource/v1.schema.json");
    let required: BTreeSet<String> = schema["required"]
        .as_array()
        .expect("schema required array")
        .iter()
        .map(|property| property.as_str().expect("required property").to_string())
        .collect();
    assert_eq!(
        required,
        ["kind", "spec"].into_iter().map(String::from).collect()
    );

    let properties: BTreeSet<String> = schema["properties"]
        .as_object()
        .expect("schema properties object")
        .keys()
        .cloned()
        .collect();
    // Resource is tagged with `kind`, every variant carries `spec`, and only
    // MeshConfig has the optional GitForgeOps-side `id` field.
    assert_eq!(
        properties,
        ["id", "kind", "spec"]
            .into_iter()
            .map(String::from)
            .collect()
    );
}
