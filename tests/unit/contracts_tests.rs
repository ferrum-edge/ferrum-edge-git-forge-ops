//! Conformance checks for the pinned ferrum-contracts release.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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
    assert_eq!(tag, "contracts-edge-0.9.9");
    assert_eq!(commit, "25c4e9e00033d7941a1dd0ab733fa74e735546ae");
    assert_eq!(edge_version, "v0.9.10");

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

#[test]
fn pinned_contract_tag_matches_the_qualified_edge_version() {
    let (tag, _, edge_version, _) = parse_pin();
    let edge_contract_tags = [
        ("v0.9.9", "contracts-edge-0.9.9"),
        ("v0.9.10", "contracts-edge-0.9.9"),
    ];
    let expected_tag = edge_contract_tags
        .iter()
        .find_map(|(edge, contracts)| (*edge == edge_version).then_some(*contracts))
        .unwrap_or_else(|| panic!("no contracts tag mapping for Edge {edge_version}"));
    assert_eq!(tag, expected_tag);

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

#[test]
fn gitforgeops_resource_contract_fixtures_match_the_local_serde_envelope() {
    let root = contract_dir().join("fixtures/gitforgeops-resource");
    for entry in fs::read_dir(root.join("valid")).expect("read valid fixtures") {
        let path = entry.expect("valid fixture entry").path();
        let bytes = fs::read(&path).expect("read valid fixture");
        let name = path.file_name().unwrap().to_string_lossy();
        serde_json::from_slice::<Resource>(&bytes).unwrap_or_else(|error| {
            panic!("valid contract fixture {name} rejected by Resource: {error}")
        });
    }
    for entry in fs::read_dir(root.join("invalid")).expect("read invalid fixtures") {
        let path = entry.expect("invalid fixture entry").path();
        let bytes = fs::read(&path).expect("read invalid fixture");
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            serde_json::from_slice::<Resource>(&bytes).is_err(),
            "invalid contract fixture {name} unexpectedly parsed as Resource"
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
