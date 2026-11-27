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

/// A parsed `contracts/ferrum-contracts/PIN`, in the format ferrum-contracts
/// defines for every consumer (`docs/consumer-pins.md`): `tag <tag>`,
/// `commit <sha>`, an optional `edge_version <version>`, then one
/// `<sha256>  <path>` row per vendored file, sorted by path.
#[derive(Debug)]
struct Pin {
    tag: String,
    commit: String,
    edge_version: Option<String>,
    rows: BTreeMap<String, String>,
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// `MAJOR.MINOR.PATCH`, digits only.
fn is_plain_version(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| is_number(part))
}

/// `contracts-edge-X.Y.Z`, optionally `-rN` with N starting at 2.
fn is_contracts_tag(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("contracts-edge-") else {
        return false;
    };
    let (version, revision) = match rest.split_once("-r") {
        Some((version, revision)) => (version, Some(revision)),
        None => (rest, None),
    };
    let revision_ok = revision.is_none_or(|revision| {
        is_number(revision)
            && !revision.starts_with('0')
            && revision.parse::<u64>().is_ok_and(|n| n >= 2)
    });
    is_plain_version(version) && revision_ok
}

fn is_pin_path(path: &str) -> bool {
    path != "PIN"
        && !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        })
}

/// The strict parse every consumer's drift test makes: any line that does not
/// match its position in the format is an error, never skipped.
fn parse_pin_text(text: &str) -> Result<Pin, String> {
    if !text.is_ascii() {
        return Err("PIN must be ASCII".into());
    }
    if text.contains('\r') {
        return Err("PIN must use LF line endings".into());
    }
    let Some(body) = text.strip_suffix('\n') else {
        return Err("PIN must end with a newline".into());
    };
    let lines: Vec<&str> = body.split('\n').collect();
    for (number, line) in lines.iter().enumerate() {
        if line.is_empty() || line.trim() != *line {
            return Err(format!("line {}: blank or padded line", number + 1));
        }
    }
    let mut lines = lines.into_iter().peekable();
    let tag = lines
        .next()
        .and_then(|line| line.strip_prefix("tag "))
        .filter(|tag| is_contracts_tag(tag))
        .ok_or("line 1 must be `tag contracts-edge-X.Y.Z[-rN]`")?
        .to_string();
    let commit = lines
        .next()
        .and_then(|line| line.strip_prefix("commit "))
        .filter(|commit| is_lower_hex(commit, 40))
        .ok_or("line 2 must be `commit <40 lowercase hex>`")?
        .to_string();
    let mut edge_version = None;
    if let Some(line) = lines.peek() {
        if let Some(value) = line.strip_prefix("edge_version ") {
            let Some(version) = value.strip_prefix('v').filter(|v| is_plain_version(v)) else {
                return Err("line 3 must be `edge_version vX.Y.Z`".into());
            };
            edge_version = Some(format!("v{version}"));
            lines.next();
        }
    }
    let mut rows = BTreeMap::new();
    let mut previous: Option<String> = None;
    for line in lines {
        let (hash, path) = line
            .split_once("  ")
            .filter(|(hash, path)| is_lower_hex(hash, 64) && is_pin_path(path))
            .ok_or_else(|| format!("not a `<sha256>  <path>` row: {line}"))?;
        if previous
            .as_deref()
            .is_some_and(|previous| previous.as_bytes() >= path.as_bytes())
        {
            return Err(format!("rows must be strictly ascending by path: {path}"));
        }
        previous = Some(path.to_string());
        rows.insert(path.to_string(), hash.to_string());
    }
    if rows.is_empty() {
        return Err("PIN must list at least one file".into());
    }
    Ok(Pin {
        tag,
        commit,
        edge_version,
        rows,
    })
}

fn parse_pin() -> Pin {
    let text = fs::read_to_string(contract_dir().join("PIN")).expect("read contracts PIN");
    parse_pin_text(&text).unwrap_or_else(|error| panic!("contracts PIN: {error}"))
}

/// Every vendored file, root-relative with `/` separators. Only the `PIN` at
/// the top of the vendored directory is excluded; a nested file named `PIN`
/// is an ordinary vendored file that needs its own row.
fn contract_files(root: &Path, directory: &Path, found: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read contract directory") {
        let path = entry.expect("read contract directory entry").path();
        if path.is_dir() {
            contract_files(root, &path, found);
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("contract path is under contract root")
            .to_string_lossy()
            .replace('\\', "/");
        if relative != "PIN" {
            found.insert(relative);
        }
    }
}

#[test]
fn only_the_top_level_pin_is_left_out_of_the_tree() {
    let tree = tempfile::tempdir().expect("temporary contract tree");
    fs::create_dir_all(tree.path().join("fixtures")).unwrap();
    fs::write(tree.path().join("PIN"), "tag contracts-edge-7.8.9\n").unwrap();
    fs::write(tree.path().join("fixtures/PIN"), "{}\n").unwrap();
    fs::write(tree.path().join("fixtures/a.json"), "{}\n").unwrap();
    let mut found = BTreeSet::new();
    contract_files(tree.path(), tree.path(), &mut found);
    assert_eq!(
        found,
        BTreeSet::from(["fixtures/PIN".to_string(), "fixtures/a.json".to_string()])
    );
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
    let Pin {
        tag,
        commit,
        edge_version,
        rows: hashes,
    } = parse_pin();
    // The adopted pin. A pin bump changes exactly these three literals (docs/contracts.md,
    // "Bumping the pin", step 4); every other test reads the live PIN or a fixed sample.
    assert_eq!(tag, "contracts-edge-0.9.21");
    assert_eq!(commit, "92d8da5be93ea1ece9f47729b1f7aa10ae8a7c3f");
    assert_eq!(edge_version.as_deref(), Some("v0.9.21"));

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

/// The strict parse refuses every line that does not match its position
/// (ferrum-contracts `docs/consumer-pins.md`, "Required checks" 1-3).
#[test]
fn the_pin_parse_is_strict() {
    // A fixed sample, independent of the adopted release, so re-pinning the
    // vendored copy never changes what this test mutates.
    let good = concat!(
        "tag contracts-edge-7.8.9\n",
        "commit 0123456789abcdef0123456789abcdef01234567\n",
        "edge_version v7.8.9\n",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  fixtures/a-b/x.json\n",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  fixtures/a/x.json\n",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  vocabularies/v.json\n",
    )
    .to_string();
    let pin = parse_pin_text(&good).expect("the sample parses");
    assert_eq!(pin.tag, "contracts-edge-7.8.9");
    assert_eq!(pin.edge_version.as_deref(), Some("v7.8.9"));
    assert_eq!(pin.rows.len(), 3);
    // The live PIN parses too (its literal values are asserted above).
    parse_pin();
    let row = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  fixtures/a/x.json";
    let (hash, path) = row.split_once("  ").unwrap();
    let cases: Vec<(&str, String)> = vec![
        ("CRLF", good.replace('\n', "\r\n")),
        ("no final newline", good.trim_end_matches('\n').to_string()),
        ("blank line", good.replacen('\n', "\n\n", 1)),
        ("comment", format!("# pinned\n{good}")),
        ("old key=value header", good.replacen("tag ", "tag=", 1)),
        (
            "uppercase hash",
            good.replace(row, &format!("{}  {path}", hash.to_uppercase())),
        ),
        ("one space", good.replace(row, &format!("{hash} {path}"))),
        ("three spaces", good.replace(row, &format!("{hash}   {path}"))),
        ("leading slash", good.replace(row, &format!("{hash}  /{path}"))),
        ("dot-dot segment", good.replace(row, &format!("{hash}  ../{path}"))),
        ("duplicate row", good.replace(row, &format!("{row}\n{row}"))),
        ("PIN lists itself", format!("{good}{hash}  PIN\n")),
        ("unknown key", good.replacen("commit ", "revision ", 1)),
        (
            "edge_version without v",
            good.replacen("edge_version v", "edge_version ", 1),
        ),
        ("trailing space", good.replacen('\n', " \n", 1)),
        (
            "revision -r1",
            good.replacen("tag contracts-edge-7.8.9", "tag contracts-edge-7.8.9-r1", 1),
        ),
        (
            "prerelease tag",
            good.replacen("tag contracts-edge-7.8.9", "tag contracts-edge-7.8.9-rc.1", 1),
        ),
        (
            "rows out of byte order",
            good.replacen(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  fixtures/a-b/x.json\n\
                 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  fixtures/a/x.json\n",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  fixtures/a/x.json\n\
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  fixtures/a-b/x.json\n",
                1,
            ),
        ),
    ];
    for (name, text) in cases {
        assert_ne!(text, good, "{name}: the mutation did not apply");
        assert!(parse_pin_text(&text).is_err(), "{name} must be refused");
    }
    // A later revision tag is a valid form.
    let revision = good.replacen("tag contracts-edge-7.8.9", "tag contracts-edge-7.8.9-r2", 1);
    assert_ne!(revision, good);
    assert_eq!(
        parse_pin_text(&revision).expect("a -r2 tag parses").tag,
        "contracts-edge-7.8.9-r2"
    );
    // A nested file named PIN is an ordinary row; only the top-level PIN may
    // not list itself.
    let nested = good.replace(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  vocabularies/v.json",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  vocabularies/PIN",
    );
    assert!(parse_pin_text(&nested).is_ok());
}

/// Check 4: nothing in the vendored directory may be anything but a regular
/// file or a directory.
#[test]
fn the_vendored_directory_holds_only_regular_files() {
    fn walk(directory: &Path) {
        for entry in fs::read_dir(directory).expect("read contract directory") {
            let entry = entry.expect("read contract directory entry");
            let kind = entry.file_type().expect("file type");
            assert!(
                !kind.is_symlink() && (kind.is_file() || kind.is_dir()),
                "{} is neither a regular file nor a directory",
                entry.path().display()
            );
            if kind.is_dir() {
                walk(&entry.path());
            }
        }
    }
    walk(&contract_dir());
}

/// The pin's tag and Edge version are asserted literally above; this checks
/// that the Edge version it names is one the validator allowlist accepts.
#[test]
fn pinned_edge_version_is_in_the_checksum_allowlist() {
    let edge_version = parse_pin()
        .edge_version
        .expect("GitForgeOps pins name the Edge release they target");
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
    // Sorted by file name, so failures are reported in a stable order.
    let fixtures: BTreeMap<String, Value> = fs::read_dir(&directory)
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
    assert!(!fixtures.is_empty(), "no {class} contract fixtures");
    fixtures.into_iter().collect()
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

/// `contracts-edge-0.9.20` published an open envelope (no top-level
/// `additionalProperties: false`) that admitted the keys the loader refuses
/// above (ferrum-contracts#73). `contracts-edge-0.9.21` closes it: no wrapper
/// key beyond `kind`, `spec` and `id`, and `id` only on a MeshConfig. Re-pinning
/// to a release whose envelope is open again fails here, so the schema a
/// producer validates against can never admit what the loader refuses.
#[test]
fn the_pinned_contract_closes_the_resource_envelope() {
    let schema = json("schemas/gitforgeops-resource/v1.schema.json");
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "the pinned gitforgeops-resource envelope admits wrapper keys the strict loader refuses"
    );
    let id_only_on_mesh = schema["allOf"]
        .as_array()
        .expect("schema allOf array")
        .iter()
        .any(|rule| {
            rule["if"]["required"] == serde_json::json!(["id"])
                && rule["then"]["properties"]["kind"]["const"] == "MeshConfig"
        });
    assert!(
        id_only_on_mesh,
        "the pinned envelope must admit `id` only on a MeshConfig"
    );
    // The fixtures that pin the closure ship with the release and are
    // vendored: the strict loader refuses each of them above.
    let invalid: BTreeSet<String> = resource_fixtures("invalid")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    for name in [
        "proxy-unknown-wrapper-key.json",
        "proxy-with-id.json",
        "upstream-null-id.json",
    ] {
        assert!(invalid.contains(name), "missing envelope fixture {name}");
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
