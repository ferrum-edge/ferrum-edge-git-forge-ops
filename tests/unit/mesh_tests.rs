//! Mesh-configuration support: loading `kind: MeshConfig` fragments, merging
//! them into the single document a mesh node reads, overlaying them, and
//! publishing that document as a standalone `{version, mesh}` file.

use std::path::{Path, PathBuf};

use gitforgeops::apply::{apply_mesh_file, render_mesh_yaml};
use gitforgeops::config::{
    apply_overlay, assemble, assemble_with_namespace_filter, load_resources, schema::Resource,
    MeshConfigSpec,
};

/// Build a `resources/`-shaped tree from `(relative path, contents)` pairs.
fn write_tree(root: &Path, files: &[(&str, &str)]) {
    for (relative, contents) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture dir");
        }
        std::fs::write(&path, contents).expect("write fixture file");
    }
}

const CORE_FRAGMENT: &str = r#"
kind: MeshConfig
spec:
  istio_root_namespace: istio-system
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      service_name: api
      namespace: ferrum
      trust_domain: cluster.local
      addresses: ["10.0.0.5"]
  services:
    - name: api
      namespace: ferrum
      ports:
        - port: 80
          protocol: http
  peer_authentications:
    - name: mesh-strict
      namespace: ferrum
      mtls_mode: strict
"#;

const EXTRA_FRAGMENT: &str = r#"
kind: MeshConfig
spec:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/web
      service_name: web
      namespace: ferrum
      trust_domain: cluster.local
  service_entries:
    - name: external-billing
      namespace: ferrum
"#;

fn mesh_from(root: &Path) -> Option<MeshConfigSpec> {
    let resources = load_resources(root).expect("load resources");
    assemble(resources).expect("assemble").mesh
}

#[test]
fn loader_reads_mesh_fragments_from_mesh_subdirectory() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(tmp.path(), &[("ferrum/mesh/core.yaml", CORE_FRAGMENT)]);

    let resources = load_resources(tmp.path()).unwrap();

    assert_eq!(resources.len(), 1);
    let (namespace, resource) = &resources[0];
    assert_eq!(namespace, "ferrum");
    match resource {
        Resource::MeshConfig { id, spec } => {
            // The fragment declares no `id`, so the loader stamps the file
            // stem — the handle overlays match on.
            assert_eq!(id.as_deref(), Some("core"));
            assert_eq!(spec.workloads.len(), 1);
            assert_eq!(spec.services.len(), 1);
            assert_eq!(spec.peer_authentications.len(), 1);
        }
        other => panic!("expected MeshConfig, got {other:?}"),
    }
}

#[test]
fn loader_skips_underscore_prefixed_mesh_examples() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(tmp.path(), &[("ferrum/mesh/_example.yaml", CORE_FRAGMENT)]);

    assert!(load_resources(tmp.path()).unwrap().is_empty());
}

#[test]
fn loader_keeps_explicit_fragment_id_over_file_stem() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[(
            "ferrum/mesh/whatever.yaml",
            "kind: MeshConfig\nid: core\nspec: {}\n",
        )],
    );

    let resources = load_resources(tmp.path()).unwrap();
    match &resources[0].1 {
        Resource::MeshConfig { id, .. } => assert_eq!(id.as_deref(), Some("core")),
        other => panic!("expected MeshConfig, got {other:?}"),
    }
}

#[test]
fn repo_example_mesh_fragment_is_fully_commented_out() {
    // `resources/ferrum/mesh/_example.yaml` ships in the repo. It is skipped
    // by the `_` convention, but it must also parse as nothing if someone
    // renames it without editing — an example that silently declares a mesh
    // would be worse than one that errors.
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/ferrum/mesh");
    assert!(example.join("_example.yaml").is_file());
    let resources =
        load_resources(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources")).unwrap();
    assert!(
        !resources
            .iter()
            .any(|(_, r)| matches!(r, Resource::MeshConfig { .. })),
        "shipped mesh example must not be loaded as a live fragment"
    );
}

// --- Fragment merging -------------------------------------------------------

#[test]
fn fragments_concatenate_collection_fields() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("ferrum/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );

    let mesh = mesh_from(tmp.path()).expect("mesh document");

    assert_eq!(mesh.workloads.len(), 2, "workloads from both fragments");
    assert_eq!(mesh.services.len(), 1);
    assert_eq!(mesh.peer_authentications.len(), 1);
    assert_eq!(mesh.service_entries.len(), 1);
    assert_eq!(mesh.istio_root_namespace.as_deref(), Some("istio-system"));
}

#[test]
fn fragments_merge_across_namespaces_into_one_document() {
    // Every mesh node loads the SAME document; namespace directories are an
    // authoring convenience, not a partition of the mesh.
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("platform/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );

    let mesh = mesh_from(tmp.path()).expect("mesh document");
    assert_eq!(mesh.workloads.len(), 2);
    assert_eq!(mesh.service_entries.len(), 1);
}

/// A workload's SPIFFE ID is the mesh's primary key for it: policies, waypoint
/// bindings and authorization rules all refer to a workload by that string. Two
/// fragments defining it differently is an authoring conflict with no
/// defensible winner — merging would pick whichever the directory walk reached
/// last.
#[test]
fn conflicting_duplicate_workload_identity_is_an_error_naming_both_fragments() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/a.yaml", CORE_FRAGMENT),
            (
                "ferrum/mesh/b.yaml",
                r#"
kind: MeshConfig
spec:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      service_name: api
      namespace: ferrum
      trust_domain: cluster.local
      addresses: ["10.0.0.99"]
"#,
            ),
        ],
    );

    let resources = load_resources(tmp.path()).unwrap();
    let err = assemble(resources).expect_err("conflicting workload identity must fail");
    let message = err.to_string();

    assert!(message.contains("workloads"), "{message}");
    assert!(
        message.contains("spiffe://cluster.local/ns/ferrum/sa/api"),
        "{message}"
    );
    assert!(message.contains("ferrum/mesh/a"), "{message}");
    assert!(message.contains("ferrum/mesh/b"), "{message}");
}

/// Services are keyed by `(name, namespace)` — the same identity overlays merge
/// on. Name alone is not enough, so the conflict must be reported per
/// namespace.
#[test]
fn conflicting_duplicate_service_identity_is_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/a.yaml", CORE_FRAGMENT),
            (
                "ferrum/mesh/b.yaml",
                "kind: MeshConfig\nspec:\n  services:\n    - name: api\n      namespace: ferrum\n      ports:\n        - port: 8443\n          protocol: https\n",
            ),
        ],
    );

    let resources = load_resources(tmp.path()).unwrap();
    let err = assemble(resources).expect_err("conflicting service identity must fail");
    let message = err.to_string();

    assert!(message.contains("services"), "{message}");
    assert!(message.contains("ferrum/api"), "{message}");
    assert!(message.contains("(name, namespace)"), "{message}");
}

/// Two fragments repeating the *same* entry agree with each other. Shared
/// boilerplate copied into two files is harmless; emitting the entry twice
/// would hand the mesh node a document it then has to reconcile.
#[test]
fn deep_equal_duplicate_entries_are_deduplicated_silently() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/a.yaml", CORE_FRAGMENT),
            ("ferrum/mesh/b.yaml", CORE_FRAGMENT),
        ],
    );

    let mesh = mesh_from(tmp.path()).expect("mesh document");

    assert_eq!(mesh.workloads.len(), 1, "identical workload deduplicated");
    assert_eq!(mesh.services.len(), 1, "identical service deduplicated");
    // Collections without a mesh-wide identity still concatenate: two
    // similar-looking policy entries are two policies and both apply.
    assert_eq!(mesh.peer_authentications.len(), 2);
}

/// The identity check must not collapse a service that legitimately exists in
/// two mesh namespaces, nor two distinct workloads.
#[test]
fn distinct_identities_across_fragments_all_survive() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("ferrum/mesh/extra.yaml", EXTRA_FRAGMENT),
            (
                "ferrum/mesh/other-ns.yaml",
                "kind: MeshConfig\nspec:\n  services:\n    - name: api\n      namespace: platform\n      ports:\n        - port: 80\n          protocol: http\n",
            ),
        ],
    );

    let mesh = mesh_from(tmp.path()).expect("mesh document");

    assert_eq!(mesh.workloads.len(), 2, "two distinct spiffe ids");
    assert_eq!(
        mesh.services.len(),
        2,
        "same service name in two namespaces is two services"
    );
}

/// An entry the identity rules cannot read (no `spiffe_id`) is passed through
/// unchecked — `ferrum-edge validate -m mesh` owns required-field reporting and
/// says it far better than a merge-time guess could.
#[test]
fn entries_without_a_readable_identity_are_passed_through() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            (
                "ferrum/mesh/a.yaml",
                "kind: MeshConfig\nspec:\n  workloads:\n    - service_name: api\n",
            ),
            (
                "ferrum/mesh/b.yaml",
                "kind: MeshConfig\nspec:\n  workloads:\n    - service_name: web\n",
            ),
        ],
    );

    let mesh = mesh_from(tmp.path()).expect("mesh document");
    assert_eq!(mesh.workloads.len(), 2);
}

#[test]
fn conflicting_singleton_fields_are_an_error_naming_both_fragments() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            (
                "ferrum/mesh/a.yaml",
                "kind: MeshConfig\nspec:\n  istio_root_namespace: istio-system\n",
            ),
            (
                "ferrum/mesh/b.yaml",
                "kind: MeshConfig\nspec:\n  istio_root_namespace: mesh-system\n",
            ),
        ],
    );

    let resources = load_resources(tmp.path()).unwrap();
    let err = assemble(resources).expect_err("conflicting singletons must fail");
    let message = err.to_string();

    assert!(message.contains("istio_root_namespace"), "{message}");
    assert!(message.contains("istio-system"), "{message}");
    assert!(message.contains("mesh-system"), "{message}");
    assert!(message.contains("ferrum/mesh/a"), "{message}");
    assert!(message.contains("ferrum/mesh/b"), "{message}");
}

#[test]
fn identical_singleton_values_in_two_fragments_agree() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            (
                "ferrum/mesh/a.yaml",
                "kind: MeshConfig\nspec:\n  istio_root_namespace: mesh-system\n",
            ),
            (
                "ferrum/mesh/b.yaml",
                "kind: MeshConfig\nspec:\n  istio_root_namespace: mesh-system\n",
            ),
        ],
    );

    let mesh = mesh_from(tmp.path()).expect("mesh document");
    assert_eq!(mesh.istio_root_namespace.as_deref(), Some("mesh-system"));
}

#[test]
fn conflicting_object_singletons_are_detected_too() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            (
                "ferrum/mesh/a.yaml",
                "kind: MeshConfig\nspec:\n  multi_cluster:\n    local_cluster: east\n",
            ),
            (
                "ferrum/mesh/b.yaml",
                "kind: MeshConfig\nspec:\n  multi_cluster:\n    local_cluster: west\n",
            ),
        ],
    );

    let resources = load_resources(tmp.path()).unwrap();
    let err = assemble(resources).expect_err("conflicting multi_cluster must fail");
    assert!(err.to_string().contains("multi_cluster"), "{err}");
}

#[test]
fn no_mesh_fragments_produces_no_mesh_document() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[(
            "ferrum/proxies/api.yaml",
            "kind: Proxy\nspec:\n  id: api\n  listen_path: /api\n  backend_scheme: http\n  backend_host: api.internal\n  backend_port: 80\n",
        )],
    );

    let assembled = assemble(load_resources(tmp.path()).unwrap()).unwrap();
    assert_eq!(assembled.gateway.proxies.len(), 1);
    assert!(
        assembled.mesh.is_none(),
        "no mesh fragments must mean no mesh document at all, not an empty one"
    );
}

#[test]
fn namespace_filter_excludes_mesh_fragments_from_other_namespaces() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("platform/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );
    let resources = load_resources(tmp.path()).unwrap();

    let mesh = assemble_with_namespace_filter(resources, Some("ferrum"))
        .unwrap()
        .mesh
        .expect("ferrum fragment survives the filter");

    assert_eq!(mesh.workloads.len(), 1);
    assert!(
        mesh.service_entries.is_empty(),
        "platform/ fragment must be filtered out by directory namespace"
    );
}

#[test]
fn namespace_filter_matching_nothing_produces_no_mesh_document() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(tmp.path(), &[("ferrum/mesh/core.yaml", CORE_FRAGMENT)]);
    let resources = load_resources(tmp.path()).unwrap();

    let assembled = assemble_with_namespace_filter(resources, Some("platform")).unwrap();
    assert!(assembled.mesh.is_none());
}

// --- Overlays ---------------------------------------------------------------

fn overlaid_mesh(base: &[(&str, &str)], overlay: &[(&str, &str)]) -> MeshConfigSpec {
    let resources_root = tempfile::tempdir().unwrap();
    let overlay_root = tempfile::tempdir().unwrap();
    write_tree(resources_root.path(), base);
    write_tree(overlay_root.path(), overlay);

    let mut resources = load_resources(resources_root.path()).unwrap();
    apply_overlay(&mut resources, overlay_root.path()).expect("overlay applies");
    assemble(resources)
        .expect("assemble")
        .mesh
        .expect("mesh document")
}

#[test]
fn overlay_merges_workloads_additively_by_spiffe_id() {
    let mesh = overlaid_mesh(
        &[("ferrum/mesh/core.yaml", CORE_FRAGMENT)],
        &[(
            "ferrum/mesh/core.yaml",
            r#"
kind: MeshConfig
spec:
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      addresses: ["10.9.9.9"]
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/worker
      service_name: worker
      namespace: ferrum
"#,
        )],
    );

    assert_eq!(
        mesh.workloads.len(),
        2,
        "matching spiffe_id merges in place; a new one appends"
    );

    let api = mesh
        .workloads
        .iter()
        .find(|w| w["spiffe_id"] == "spiffe://cluster.local/ns/ferrum/sa/api")
        .expect("api workload survives");
    assert_eq!(api["addresses"][0], "10.9.9.9", "overlay overrides address");
    assert_eq!(
        api["service_name"], "api",
        "unmentioned base fields survive the deep merge"
    );

    assert!(mesh
        .workloads
        .iter()
        .any(|w| w["spiffe_id"] == "spiffe://cluster.local/ns/ferrum/sa/worker"));
}

#[test]
fn overlay_merges_services_by_name_and_namespace_not_name_alone() {
    let mesh = overlaid_mesh(
        &[(
            "ferrum/mesh/core.yaml",
            r#"
kind: MeshConfig
spec:
  services:
    - name: api
      namespace: ferrum
      cluster_ips: ["10.0.1.1"]
    - name: api
      namespace: platform
      cluster_ips: ["10.0.2.1"]
"#,
        )],
        &[(
            "ferrum/mesh/core.yaml",
            r#"
kind: MeshConfig
spec:
  services:
    - name: api
      namespace: platform
      cluster_ips: ["10.9.9.9"]
"#,
        )],
    );

    assert_eq!(mesh.services.len(), 2, "no new service was introduced");
    let ferrum_api = mesh
        .services
        .iter()
        .find(|s| s["namespace"] == "ferrum")
        .unwrap();
    let platform_api = mesh
        .services
        .iter()
        .find(|s| s["namespace"] == "platform")
        .unwrap();

    assert_eq!(
        ferrum_api["cluster_ips"][0], "10.0.1.1",
        "same-named service in another namespace is untouched"
    );
    assert_eq!(platform_api["cluster_ips"][0], "10.9.9.9");
}

#[test]
fn overlay_replaces_non_additive_mesh_arrays() {
    let mesh = overlaid_mesh(
        &[("ferrum/mesh/core.yaml", CORE_FRAGMENT)],
        &[(
            "ferrum/mesh/core.yaml",
            r#"
kind: MeshConfig
spec:
  peer_authentications:
    - name: staging-permissive
      namespace: ferrum
      mtls_mode: permissive
"#,
        )],
    );

    assert_eq!(
        mesh.peer_authentications.len(),
        1,
        "policy lists replace wholesale so an overlay can relax a posture"
    );
    assert_eq!(mesh.peer_authentications[0]["name"], "staging-permissive");
}

#[test]
fn overlay_matches_fragment_by_file_stem() {
    let resources_root = tempfile::tempdir().unwrap();
    let overlay_root = tempfile::tempdir().unwrap();
    write_tree(
        resources_root.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("ferrum/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );
    write_tree(
        overlay_root.path(),
        &[(
            "ferrum/mesh/extra.yaml",
            "kind: MeshConfig\nspec:\n  service_entries: []\n",
        )],
    );

    let mut resources = load_resources(resources_root.path()).unwrap();
    apply_overlay(&mut resources, overlay_root.path()).unwrap();
    let mesh = assemble(resources).unwrap().mesh.unwrap();

    assert!(
        mesh.service_entries.is_empty(),
        "overlay targeted extra.yaml's list"
    );
    assert_eq!(
        mesh.peer_authentications.len(),
        1,
        "core.yaml was not touched"
    );
}

#[test]
fn overlay_targeting_a_missing_mesh_fragment_is_rejected() {
    let resources_root = tempfile::tempdir().unwrap();
    let overlay_root = tempfile::tempdir().unwrap();
    write_tree(
        resources_root.path(),
        &[("ferrum/mesh/core.yaml", CORE_FRAGMENT)],
    );
    write_tree(
        overlay_root.path(),
        &[("ferrum/mesh/typo.yaml", "kind: MeshConfig\nspec: {}\n")],
    );

    let mut resources = load_resources(resources_root.path()).unwrap();
    let err = apply_overlay(&mut resources, overlay_root.path())
        .expect_err("an overlay with no base fragment is a typo, not a new resource");
    assert!(err.to_string().contains("MeshConfig"), "{err}");
}

// --- Document rendering + publishing ---------------------------------------

#[test]
fn mesh_document_carries_only_version_and_mesh() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(tmp.path(), &[("ferrum/mesh/core.yaml", CORE_FRAGMENT)]);
    let mesh = mesh_from(tmp.path()).unwrap();

    let yaml = render_mesh_yaml(&mesh).unwrap();
    let parsed: serde_yaml::Mapping = serde_yaml::from_str(&yaml).unwrap();

    let keys: Vec<String> = parsed
        .keys()
        .map(|k| k.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(keys, vec!["version".to_string(), "mesh".to_string()]);

    // ferrum-edge's mesh file loader is deny_unknown_fields: any gateway key
    // here would fail the node's load outright.
    for forbidden in ["proxies", "consumers", "upstreams", "plugin_configs"] {
        assert!(
            !parsed.contains_key(serde_yaml::Value::from(forbidden)),
            "mesh document must not carry `{forbidden}`"
        );
    }
    assert_eq!(parsed["version"], serde_yaml::Value::from("1"));
}

#[test]
fn mesh_document_round_trips_back_into_the_mirror() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("ferrum/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );
    let mesh = mesh_from(tmp.path()).unwrap();

    let yaml = render_mesh_yaml(&mesh).unwrap();

    #[derive(serde::Deserialize)]
    struct Document {
        version: String,
        mesh: MeshConfigSpec,
    }
    let parsed: Document = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(parsed.version, "1");
    assert_eq!(parsed.mesh, mesh);
}

#[test]
fn empty_collections_are_omitted_from_the_document() {
    let yaml = render_mesh_yaml(&MeshConfigSpec::default()).unwrap();
    let parsed: serde_yaml::Mapping = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(parsed.len(), 2);
    assert!(parsed["mesh"].as_mapping().is_some_and(|m| m.is_empty()));
}

#[test]
fn apply_mesh_file_creates_parent_directories_and_publishes() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("nested/out/mesh.yaml");

    let mut mesh = MeshConfigSpec::default();
    mesh.workloads
        .push(serde_json::json!({"spiffe_id": "spiffe://cluster.local/ns/ferrum/sa/api"}));

    apply_mesh_file(&mesh, target.to_str().unwrap()).unwrap();

    let written = std::fs::read_to_string(&target).unwrap();
    assert_eq!(written, render_mesh_yaml(&mesh).unwrap());
}

#[test]
fn apply_mesh_file_replaces_an_existing_document_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    std::fs::write(&target, "version: \"1\"\nmesh: {}\n").unwrap();

    let mut mesh = MeshConfigSpec::default();
    mesh.services
        .push(serde_json::json!({"name": "api", "namespace": "ferrum"}));
    apply_mesh_file(&mesh, target.to_str().unwrap()).unwrap();

    assert!(std::fs::read_to_string(&target).unwrap().contains("api"));

    // write-temp -> rename leaves no debris behind in the directory.
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name != "mesh.yaml")
        .collect();
    assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
}

#[test]
fn gateway_document_never_gains_a_mesh_key() {
    // The gateway's own `mesh:` field is inert in ferrum-edge file mode, so
    // mesh config must not leak into the gateway artifact.
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            (
                "ferrum/proxies/api.yaml",
                "kind: Proxy\nspec:\n  id: api\n  listen_path: /api\n  backend_scheme: http\n  backend_host: api.internal\n  backend_port: 80\n",
            ),
        ],
    );

    let assembled = assemble(load_resources(tmp.path()).unwrap()).unwrap();
    let gateway_yaml = gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap();

    assert!(!gateway_yaml.contains("mesh:"), "{gateway_yaml}");
    assert!(gateway_yaml.contains("proxies:"));
}

// --- Summary ----------------------------------------------------------------

#[test]
fn summary_reports_only_non_empty_collections() {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(
        tmp.path(),
        &[
            ("ferrum/mesh/core.yaml", CORE_FRAGMENT),
            ("ferrum/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );
    let mesh = mesh_from(tmp.path()).unwrap();

    let summary = mesh.summary();
    assert!(summary.contains("2 workloads"), "{summary}");
    assert!(summary.contains("1 service,"), "{summary}");
    assert!(summary.contains("1 peer authentication"), "{summary}");
    assert!(!summary.contains("sidecar"), "{summary}");
}

#[test]
fn summary_of_an_empty_document_is_empty() {
    assert_eq!(MeshConfigSpec::default().summary(), "");
    assert!(MeshConfigSpec::default().is_empty());
}
