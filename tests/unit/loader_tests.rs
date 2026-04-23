use std::path::PathBuf;

use gitforgeops::config::{load_resources, schema::Resource};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple-config")
}

#[test]
fn load_simple_config_finds_all_resources() {
    let resources = load_resources(&fixtures_dir()).unwrap();
    assert_eq!(
        resources.len(),
        4,
        "expected 4 resources (proxy, consumer, upstream, plugin)"
    );
}

#[test]
fn load_simple_config_infers_namespace() {
    let resources = load_resources(&fixtures_dir()).unwrap();
    for (ns, _) in &resources {
        assert_eq!(ns, "ferrum");
    }
}

#[test]
fn load_simple_config_parses_all_kinds() {
    let resources = load_resources(&fixtures_dir()).unwrap();

    let proxy_count = resources
        .iter()
        .filter(|(_, r)| matches!(r, Resource::Proxy { .. }))
        .count();
    let consumer_count = resources
        .iter()
        .filter(|(_, r)| matches!(r, Resource::Consumer { .. }))
        .count();
    let upstream_count = resources
        .iter()
        .filter(|(_, r)| matches!(r, Resource::Upstream { .. }))
        .count();
    let plugin_count = resources
        .iter()
        .filter(|(_, r)| matches!(r, Resource::PluginConfig { .. }))
        .count();

    assert_eq!(proxy_count, 1);
    assert_eq!(consumer_count, 1);
    assert_eq!(upstream_count, 1);
    assert_eq!(plugin_count, 1);
}

#[test]
fn load_nonexistent_dir_returns_error() {
    let result = load_resources(&PathBuf::from("/nonexistent/path"));
    assert!(result.is_err());
}

#[test]
fn load_skips_underscore_prefixed_files() {
    let example_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources");
    let resources = load_resources(&example_dir).unwrap();
    assert!(
        resources.is_empty(),
        "files starting with _ should be skipped"
    );
}
