use gitforgeops::apply::{apply_file, publish_private_export, render_file_yaml};
use gitforgeops::config::GatewayConfig;

/// Fixture is built through serde rather than struct literals so it stays
/// insulated from field-level churn in `src/config/schema.rs`.
const FIXTURE: &str = r#"
version: "1"
proxies:
  - id: api-proxy
    namespace: ferrum
    listen_path: /api
    backend_scheme: http
    backend_host: api.internal
    backend_port: 8080
consumers:
  - id: alice
    username: alice
    namespace: ferrum
  - id: bob
    username: bob
    namespace: ferrum
plugin_configs:
  - id: global-rate-limit
    plugin_name: rate_limiting
    namespace: ferrum
    scope: global
upstreams:
  - id: api-upstream
    namespace: ferrum
    targets:
      - host: 10.0.0.1
        port: 8080
      - host: 10.0.0.2
        port: 8080
  - id: other-upstream
    namespace: ferrum
    targets:
      - host: 10.0.0.3
        port: 9090
  - id: third-upstream
    namespace: ferrum
    targets:
      - host: 10.0.0.4
        port: 9090
"#;

fn fixture() -> GatewayConfig {
    serde_yaml::from_str(FIXTURE).expect("fixture parses")
}

fn counts_of(yaml: &str) -> serde_yaml::Mapping {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).expect("written yaml parses");
    doc.get("resource_counts")
        .and_then(|v| v.as_mapping())
        .cloned()
        .expect("resource_counts present")
}

fn count_of(counts: &serde_yaml::Mapping, key: &str) -> u64 {
    counts
        .get(serde_yaml::Value::from(key))
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("resource_counts.{key} is an integer"))
}

#[test]
fn resource_counts_match_collection_lengths() {
    let config = fixture();
    let yaml = render_file_yaml(&config).expect("render");
    let counts = counts_of(&yaml);

    assert_eq!(count_of(&counts, "proxies"), config.proxies.len() as u64);
    assert_eq!(
        count_of(&counts, "consumers"),
        config.consumers.len() as u64
    );
    assert_eq!(
        count_of(&counts, "plugin_configs"),
        config.plugin_configs.len() as u64
    );
    assert_eq!(
        count_of(&counts, "upstreams"),
        config.upstreams.len() as u64
    );

    // Guard against a fixture that silently loses resources: the seal is only
    // meaningful if the collections are actually populated.
    assert_eq!(count_of(&counts, "proxies"), 1);
    assert_eq!(count_of(&counts, "consumers"), 2);
    assert_eq!(count_of(&counts, "plugin_configs"), 1);
    assert_eq!(count_of(&counts, "upstreams"), 3);

    // ferrum-edge's seal mapping is `deny_unknown_fields`.
    assert_eq!(counts.len(), 4);
}

#[test]
fn empty_config_seals_zero_counts() {
    let yaml = render_file_yaml(&GatewayConfig::default()).expect("render");
    let counts = counts_of(&yaml);

    for key in ["proxies", "consumers", "plugin_configs", "upstreams"] {
        assert_eq!(count_of(&counts, key), 0, "{key}");
    }
}

#[test]
fn resource_counts_appears_exactly_once_at_top_level() {
    let yaml = render_file_yaml(&fixture()).expect("render");

    let occurrences = yaml
        .lines()
        .filter(|line| line.starts_with("resource_counts:"))
        .count();
    assert_eq!(occurrences, 1, "yaml was:\n{yaml}");
    assert_eq!(yaml.matches("resource_counts").count(), 1);
}

#[test]
fn version_precedes_resource_counts() {
    let yaml = render_file_yaml(&fixture()).expect("render");

    let version_at = yaml.find("version:").expect("version emitted");
    let counts_at = yaml.find("resource_counts:").expect("seal emitted");
    assert!(version_at < counts_at, "yaml was:\n{yaml}");
}

#[test]
fn written_file_parses_back_into_gateway_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nested").join("resources.yaml");
    let config = fixture();

    apply_file(&config, path.to_str().expect("utf-8 path")).expect("apply_file");

    let written = std::fs::read_to_string(&path).expect("read back");
    let parsed: GatewayConfig = serde_yaml::from_str(&written).expect("parses as GatewayConfig");

    assert_eq!(parsed.proxies.len(), config.proxies.len());
    assert_eq!(parsed.consumers.len(), config.consumers.len());
    assert_eq!(parsed.plugin_configs.len(), config.plugin_configs.len());
    assert_eq!(parsed.upstreams.len(), config.upstreams.len());
    assert_eq!(parsed.version, config.version);
}

#[test]
fn atomic_write_leaves_no_temp_file_behind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("resources.yaml");

    apply_file(&fixture(), path.to_str().expect("utf-8 path")).expect("first write");
    // Republish over an existing destination — the rename path.
    apply_file(&fixture(), path.to_str().expect("utf-8 path")).expect("second write");

    let entries: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    assert_eq!(entries, vec!["resources.yaml".to_string()], "{entries:?}");

    // Still exactly one seal after republishing.
    let written = std::fs::read_to_string(&path).expect("read back");
    assert_eq!(written.matches("resource_counts").count(), 1);
}

#[cfg(unix)]
#[test]
fn republish_preserves_destination_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("resources.yaml");

    apply_file(&fixture(), path.to_str().expect("utf-8 path")).expect("first write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .expect("chmod destination");

    apply_file(&fixture(), path.to_str().expect("utf-8 path")).expect("second write");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640, "mode was {mode:o}");
}

#[cfg(unix)]
#[test]
fn private_export_forces_owner_only_permissions_on_create_and_replace() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("materialized.yaml");
    let path_str = path.to_str().expect("utf-8 path");

    publish_private_export(path_str, b"secret-one").expect("first publish");
    let first_mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(first_mode, 0o600, "mode was {first_mode:o}");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("make old destination broad");
    publish_private_export(path_str, b"secret-two").expect("secure replacement");

    let second_mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(second_mode, 0o600, "mode was {second_mode:o}");
    assert_eq!(std::fs::read(&path).unwrap(), b"secret-two");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

/// The two documents are published side by side and must not contaminate each
/// other: the gateway file keeps its `resource_counts` seal and gains no
/// `mesh:` key, and the mesh file carries neither the seal nor any gateway
/// array.
#[test]
fn gateway_and_mesh_documents_are_published_independently() {
    use gitforgeops::apply::apply_mesh_file;
    use gitforgeops::config::MeshConfigSpec;

    let dir = tempfile::tempdir().expect("tempdir");
    let gateway_path = dir.path().join("resources.yaml");
    let mesh_path = dir.path().join("mesh.yaml");

    let mut mesh = MeshConfigSpec::default();
    mesh.services
        .push(serde_json::json!({"name": "api", "namespace": "ferrum"}));

    apply_file(&fixture(), gateway_path.to_str().expect("utf-8 path")).expect("gateway write");
    apply_mesh_file(&mesh, mesh_path.to_str().expect("utf-8 path")).expect("mesh write");

    let gateway = std::fs::read_to_string(&gateway_path).expect("read gateway");
    let mesh_doc = std::fs::read_to_string(&mesh_path).expect("read mesh");

    assert!(gateway.contains("resource_counts"));
    assert!(!gateway.contains("mesh:"), "{gateway}");

    assert!(!mesh_doc.contains("resource_counts"), "{mesh_doc}");
    assert!(!mesh_doc.contains("proxies:"), "{mesh_doc}");
    assert!(mesh_doc.starts_with("version:"), "{mesh_doc}");
}

#[cfg(unix)]
#[test]
fn mesh_republish_preserves_destination_permissions() {
    use gitforgeops::apply::apply_mesh_file;
    use gitforgeops::config::MeshConfigSpec;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mesh.yaml");
    let mesh = MeshConfigSpec::default();

    apply_mesh_file(&mesh, path.to_str().expect("utf-8 path")).expect("first write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .expect("chmod destination");
    apply_mesh_file(&mesh, path.to_str().expect("utf-8 path")).expect("second write");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640, "mode was {mode:o}");
}
