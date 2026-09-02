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
fn loader_rejects_a_known_resource_directory_that_is_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    let namespace = tmp.path().join("team-alpha");
    std::fs::create_dir_all(&namespace).unwrap();
    let bad_path = namespace.join("proxies");
    std::fs::write(&bad_path, "not a directory").unwrap();

    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(error.contains("not a directory"), "{error}");
    assert!(error.contains(&bad_path.display().to_string()), "{error}");
}

#[test]
fn loader_rejects_unknown_resource_directories_and_misplaced_yaml() {
    for (relative, reported_relative) in [
        ("team-alpha/proxys/api.yaml", "team-alpha/proxys"),
        ("team-alpha/api.yaml", "team-alpha/api.yaml"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, minimal_proxy("")).unwrap();

        let error = load_resources(tmp.path()).unwrap_err().to_string();
        assert!(
            error.contains(&tmp.path().join(reported_relative).display().to_string()),
            "{error}"
        );
    }
}

#[test]
fn loader_rejects_yaml_outside_a_namespace_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("api.yaml");
    std::fs::write(&path, minimal_proxy("")).unwrap();

    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(error.contains("namespace directory"), "{error}");
}

#[test]
fn loader_rejects_a_resource_kind_in_the_wrong_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_resource(
        tmp.path(),
        "proxies",
        "alice.yaml",
        "kind: Consumer\nspec:\n  id: alice\n  username: alice\n",
    );

    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(error.contains("Consumer"), "{error}");
    assert!(error.contains("proxies"), "{error}");
}

#[cfg(unix)]
#[test]
fn loader_rejects_a_symlinked_resource_root() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = tmp.path().join("resources");
    symlink(&real, &link).unwrap();

    let error = load_resources(&link).unwrap_err().to_string();
    assert!(error.contains("symbolic links"), "{error}");
    assert!(error.contains(&link.display().to_string()), "{error}");
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

#[test]
fn loader_rejects_unsupported_files_in_resource_trees() {
    for name in ["api.YAML", "api.yam", "api.yaml.bak", "notes.txt"] {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_resource(tmp.path(), "proxies", name, &minimal_proxy(""));
        let error = load_resources(tmp.path()).unwrap_err().to_string();
        assert!(error.contains("unsupported file"), "{name}: {error}");
        assert!(
            error.contains(&path.display().to_string()),
            "{name}: {error}"
        );
        assert!(error.contains("lowercase .yaml or .yml"), "{name}: {error}");
    }
}

#[test]
fn loader_allows_explicit_documentation_and_disabled_files() {
    let tmp = tempfile::tempdir().unwrap();
    let directory = tmp.path().join("team-alpha/proxies");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("README.md"), "resource documentation").unwrap();
    std::fs::write(directory.join(".gitkeep"), "").unwrap();
    std::fs::write(directory.join("_api.yaml.bak"), "intentionally disabled").unwrap();
    std::fs::write(directory.join("api.yaml"), minimal_proxy("")).unwrap();

    let resources = load_resources(tmp.path()).unwrap();
    assert_eq!(resources.len(), 1);
}

/// `mesh/` is walked alongside the four gateway directories. It is listed last
/// so mesh support cannot reorder — or drop — any existing kind.
#[test]
fn load_walks_the_mesh_subdirectory_alongside_gateway_kinds() {
    let tmp = tempfile::tempdir().unwrap();
    let ns = tmp.path().join("ferrum");
    for (subdir, file, body) in [
        (
            "proxies",
            "api.yaml",
            "kind: Proxy\nspec:\n  id: api\n  listen_path: /api\n  backend_scheme: http\n  backend_host: h\n  backend_port: 80\n",
        ),
        (
            "consumers",
            "alice.yaml",
            "kind: Consumer\nspec:\n  id: alice\n  username: alice\n",
        ),
        (
            "upstreams",
            "pool.yaml",
            "kind: Upstream\nspec:\n  id: pool\n  targets:\n    - host: h\n      port: 80\n",
        ),
        (
            "plugins",
            "rl.yaml",
            "kind: PluginConfig\nspec:\n  id: rl\n  plugin_name: rate_limiting\n  scope: global\n",
        ),
        ("mesh", "core.yaml", "kind: MeshConfig\nspec: {}\n"),
    ] {
        std::fs::create_dir_all(ns.join(subdir)).unwrap();
        std::fs::write(ns.join(subdir).join(file), body).unwrap();
    }

    let resources = load_resources(tmp.path()).unwrap();

    assert_eq!(resources.len(), 5);
    assert_eq!(
        resources
            .iter()
            .filter(|(_, r)| matches!(r, Resource::MeshConfig { .. }))
            .count(),
        1
    );
    for (namespace, _) in &resources {
        assert_eq!(namespace, "ferrum");
    }
}

fn write_resource(root: &std::path::Path, subdir: &str, name: &str, body: &str) -> PathBuf {
    let directory = root.join("team-alpha").join(subdir);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

fn minimal_proxy(extra: &str) -> String {
    format!(
        "kind: Proxy\nspec:\n  id: api\n  listen_path: /api\n  backend_scheme: http\n  backend_host: h\n  backend_port: 80\n{extra}"
    )
}

#[test]
fn loader_rejects_unknown_wrapper_and_resource_fields_with_file_and_path() {
    for (extra, expected) in [
        ("metadata: {}\n", ".metadata"),
        ("spec:\n  plguins: []\n", ".spec.plguins"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let body = if extra.starts_with("metadata") {
            format!("{}{}", minimal_proxy(""), extra)
        } else {
            // Inject the typo into the existing spec rather than creating a
            // second YAML `spec` key.
            minimal_proxy("  plguins: []\n")
        };
        let path = write_resource(tmp.path(), "proxies", "api.yaml", &body);
        let error = load_resources(tmp.path()).unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert!(error.contains(expected), "expected {expected}: {error}");
    }
}

#[test]
fn loader_rejects_unknown_nested_fields_in_health_checks_and_plugin_associations() {
    let cases = [
        (
            "upstreams",
            "pool.yaml",
            "kind: Upstream\nspec:\n  id: pool\n  targets:\n    - host: h\n      port: 80\n  health_checks:\n    active:\n      timeot_ms: 50\n",
            "health_checks.active.timeot_ms",
        ),
        (
            "proxies",
            "api.yaml",
            "kind: Proxy\nspec:\n  id: api\n  backend_host: h\n  backend_port: 80\n  plugins:\n    - plugin_config_id: auth\n      priorty: 10\n",
            "plugins[0].priorty",
        ),
    ];

    for (subdir, name, body, expected) in cases {
        let tmp = tempfile::tempdir().unwrap();
        write_resource(tmp.path(), subdir, name, body);
        let error = load_resources(tmp.path()).unwrap_err().to_string();
        assert!(error.contains(expected), "expected {expected}: {error}");
    }
}

#[test]
fn loader_rejects_unknown_mesh_collection_but_preserves_free_form_mesh_items() {
    let tmp = tempfile::tempdir().unwrap();
    write_resource(
        tmp.path(),
        "mesh",
        "core.yaml",
        "kind: MeshConfig\nspec:\n  worklaods: []\n",
    );
    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(error.contains(".spec.worklaods"), "{error}");

    let tmp = tempfile::tempdir().unwrap();
    write_resource(
        tmp.path(),
        "mesh",
        "core.yaml",
        "kind: MeshConfig\nspec:\n  workloads:\n    - totally_future_field: preserved\n",
    );
    let resources = load_resources(tmp.path()).expect("mesh item shapes are intentionally opaque");
    let Resource::MeshConfig { spec, .. } = &resources[0].1 else {
        panic!("expected mesh")
    };
    assert_eq!(spec.workloads[0]["totally_future_field"], "preserved");
}

#[test]
fn arbitrary_plugin_config_keys_remain_supported() {
    let tmp = tempfile::tempdir().unwrap();
    write_resource(
        tmp.path(),
        "plugins",
        "custom.yaml",
        "kind: PluginConfig\nspec:\n  id: custom\n  plugin_name: custom-plugin\n  scope: global\n  config:\n    vendor_future_key:\n      nested: true\n",
    );
    let resources = load_resources(tmp.path()).expect("plugin config is intentionally free-form");
    let Resource::PluginConfig { spec } = &resources[0].1 else {
        panic!("expected plugin config")
    };
    assert_eq!(spec.config["vendor_future_key"]["nested"], true);
}

#[test]
fn loader_orders_resource_paths_lexically() {
    let tmp = tempfile::tempdir().unwrap();
    for id in ["z-last", "a-first", "m-middle"] {
        write_resource(
            tmp.path(),
            "proxies",
            &format!("{id}.yaml"),
            &format!("kind: Proxy\nspec:\n  id: {id}\n  backend_host: h\n  backend_port: 80\n"),
        );
    }
    let resources = load_resources(tmp.path()).unwrap();
    let ids = resources
        .iter()
        .map(|(_, resource)| match resource {
            Resource::Proxy { spec } => spec.id.as_str(),
            _ => "unexpected",
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["a-first", "m-middle", "z-last"]);
}

#[cfg(unix)]
#[test]
fn loader_rejects_symlinked_files_without_reading_the_target() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside.yaml");
    std::fs::write(&outside, minimal_proxy("")).unwrap();
    let directory = tmp.path().join("resources/team-alpha/proxies");
    std::fs::create_dir_all(&directory).unwrap();
    let link = directory.join("escape.yaml");
    symlink(&outside, &link).unwrap();

    let error = load_resources(&tmp.path().join("resources"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic links"), "{error}");
    assert!(error.contains(&link.display().to_string()), "{error}");
}

/// OS and file-browser droppings are skipped silently. Finder re-creates
/// `.DS_Store` the moment a folder is opened, so failing on it would let a
/// desktop file manager break a validate-and-apply pipeline, with nothing the
/// author could commit to fix it.
#[test]
fn loader_silently_skips_os_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let directory = tmp.path().join("team-alpha/proxies");
    std::fs::create_dir_all(&directory).unwrap();
    for artifact in [".DS_Store", "Thumbs.db", "desktop.ini"] {
        std::fs::write(directory.join(artifact), "binary junk").unwrap();
    }
    // ...including at the namespace and tree levels, where a file manager is
    // just as likely to leave one.
    std::fs::write(tmp.path().join("team-alpha/.DS_Store"), "junk").unwrap();
    std::fs::write(tmp.path().join(".DS_Store"), "junk").unwrap();
    std::fs::write(directory.join("api.yaml"), minimal_proxy("")).unwrap();

    let resources = load_resources(tmp.path()).unwrap();
    assert_eq!(resources.len(), 1, "{resources:#?}");
}

/// The skip list is exhaustive by name, not by shape: anything that could be a
/// resource document stays fatal, because a file that looks like configuration
/// and is silently not loaded is how a typo becomes a prune.
#[test]
fn loader_still_rejects_config_shaped_files_next_to_os_artifacts() {
    for name in [
        "ds_store.yaml.bak",
        "thumbs.db",
        "Desktop.ini",
        "settings.json",
        "settings.toml",
        "Makefile",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_resource(tmp.path(), "proxies", name, "not configuration");
        let error = load_resources(tmp.path()).unwrap_err().to_string();
        assert!(error.contains("unsupported file"), "{name}: {error}");
    }

    // Matching is by exact file name: `.DS_Store.yaml` is a lowercase `.yaml`
    // document and is loaded like any other, not skipped by association.
    let tmp = tempfile::tempdir().unwrap();
    write_resource(tmp.path(), "proxies", ".DS_Store.yaml", "not configuration");
    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(error.contains("must contain a YAML object"), "{error}");
}

/// Non-string YAML keys would be silently stringified by the
/// `serde_yaml::Value` → `serde_json::Value` hop every document takes, quietly
/// rewriting exactly the sections gitforgeops promises to carry verbatim.
#[test]
fn loader_rejects_non_string_mapping_keys_and_names_the_mapping() {
    let cases = [
        (
            "plugins",
            "kind: PluginConfig\nspec:\n  id: p\n  plugin_name: key_auth\n  scope: global\n  config:\n    status_codes:\n      404: not found\n",
            "`.spec.config.status_codes`",
            "number `404`",
        ),
        (
            "mesh",
            "kind: MeshConfig\nspec:\n  workloads:\n    - labels:\n        true: yes-please\n",
            "`.spec.workloads[0].labels`",
            "boolean `true`",
        ),
        (
            "proxies",
            "kind: Proxy\nspec:\n  id: api\n  backend_host: h\n  backend_port: 80\n  ? [a, b]\n  : value\n",
            "`.spec`",
            "a sequence",
        ),
    ];

    for (subdir, body, location, description) in cases {
        let tmp = tempfile::tempdir().unwrap();
        write_resource(tmp.path(), subdir, "doc.yaml", body);
        let error = load_resources(tmp.path()).unwrap_err().to_string();
        assert!(error.contains("non-string mapping key"), "{error}");
        assert!(error.contains(location), "expected {location}: {error}");
        assert!(
            error.contains(description),
            "expected {description}: {error}"
        );
    }
}

/// YAML merge keys are not supported: `serde_yaml` leaves `<<` as an ordinary
/// string key (merging is opt-in and gitforgeops does not opt in), so it
/// surfaces as an unknown field rather than silently doing nothing.
#[test]
fn loader_rejects_yaml_merge_keys_as_an_unknown_field() {
    let tmp = tempfile::tempdir().unwrap();
    write_resource(
        tmp.path(),
        "proxies",
        "api.yaml",
        "kind: Proxy\nspec:\n  id: api\n  backend_host: h\n  circuit_breaker: &defaults\n    failure_threshold: 5\n  <<: *defaults\n",
    );
    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(error.contains("unknown configuration field"), "{error}");
    assert!(error.contains(".spec.<<"), "{error}");
}
