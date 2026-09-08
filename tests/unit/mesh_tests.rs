//! Mesh-configuration support: loading `kind: MeshConfig` fragments, merging
//! them into the single document a mesh node reads, overlaying them, and
//! publishing that document as a standalone `{version, mesh}` file.

use std::path::{Path, PathBuf};

use gitforgeops::apply::{
    apply_mesh_file, plan_mesh_publication, reconcile_mesh_file, render_mesh_yaml, MeshPublication,
    MeshRetractionScope,
};
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

#[test]
fn assembled_mesh_retains_directory_scope_after_overlays_and_filtering() {
    let tmp = tempfile::tempdir().unwrap();
    let resources_dir = tmp.path().join("resources");
    let overlay_dir = tmp.path().join("overlays/staging");
    write_tree(
        &resources_dir,
        &[
            ("alpha/mesh/core.yaml", CORE_FRAGMENT),
            ("gamma/mesh/extra.yaml", EXTRA_FRAGMENT),
        ],
    );
    write_tree(
        &overlay_dir,
        &[(
            "gamma/mesh/extra.yaml",
            "kind: MeshConfig\nspec:\n  outbound_traffic_policy:\n    mode: ALLOW_ANY\n",
        )],
    );
    let mut resources = load_resources(&resources_dir).unwrap();
    apply_overlay(&mut resources, &overlay_dir).unwrap();
    let assembled = assemble(resources.clone()).unwrap();
    let error = assembled
        .validate_mesh_scope("production", &["alpha".into()])
        .unwrap_err()
        .to_string();
    assert!(error.contains("namespace 'gamma'"), "{error}");
    assert!(error.contains("gamma/mesh/extra"), "{error}");
    assembled
        .validate_mesh_scope("production", &["alpha".into(), "gamma".into()])
        .unwrap();
    let filtered = assemble_with_namespace_filter(resources, Some("alpha")).unwrap();
    filtered
        .validate_mesh_scope("production", &["alpha".into()])
        .unwrap();
    assert_eq!(filtered.mesh_sources.len(), 1);
    // Inner workload/service namespaces deliberately differ from directory scope.
    assert_eq!(filtered.mesh_sources[0].0, "alpha");
    assert!(filtered.mesh.unwrap().outbound_traffic_policy.is_none());
}

// ── Retraction ────────────────────────────────────────────────────────────
//
// Publication is a reconciliation: removing the last `MeshConfig` fragment has
// to converge the published document too. Otherwise every mesh node reading
// `FERRUM_MESH_FILE_OUTPUT_PATH` keeps enforcing policy the repository deleted,
// and (under `apply-on-merge.yml`) the stale document stays committed on the
// default branch forever.

/// A run that sees the whole repository, with `ledger_attributed` under test.
fn whole_repository(ledger_attributed: bool) -> MeshRetractionScope {
    MeshRetractionScope {
        ledger_attributed,
        covers_repository: true,
    }
}

fn one_workload() -> MeshConfigSpec {
    let mut mesh = MeshConfigSpec::default();
    mesh.workloads
        .push(serde_json::json!({"spiffe_id": "spiffe://cluster.local/ns/ferrum/sa/api"}));
    mesh
}

/// The document a retraction publishes.
fn empty_mesh_document() -> String {
    render_mesh_yaml(&MeshConfigSpec::default()).unwrap()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read published document")
}

#[test]
fn removing_the_last_fragment_retracts_the_published_document() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("assembled/sandbox-mesh.yaml");
    let path = target.to_str().unwrap();

    let published = reconcile_mesh_file(Some(&one_workload()), path, whole_repository(true));
    assert_eq!(published.unwrap(), MeshPublication::Published);
    assert!(read(&target).contains("spiffe"));

    let retracted = reconcile_mesh_file(None, path, whole_repository(true));
    assert_eq!(retracted.unwrap(), MeshPublication::Retracted);

    // The retraction is the document ferrum-edge's `MeshFileDocument` reads as
    // "no mesh policy": exactly `version` plus an empty `mesh` mapping.
    let written = read(&target);
    assert_eq!(written, empty_mesh_document());
    let parsed: serde_yaml::Mapping = serde_yaml::from_str(&written).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed["version"].as_str(), Some("1"));
    assert!(parsed["mesh"].as_mapping().is_some_and(|m| m.is_empty()));
}

#[test]
fn a_repository_that_never_published_a_mesh_document_retracts_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("assembled/sandbox-mesh.yaml");
    let path = target.to_str().unwrap();

    let publication = reconcile_mesh_file(None, path, whole_repository(false));

    assert_eq!(publication.unwrap(), MeshPublication::NeverPublished);
    assert!(!target.exists(), "retraction must not fabricate a document");
}

#[test]
fn a_document_this_renderer_produced_is_attributed_without_a_ledger_entry() {
    // The ledger only exists from the first apply that ran a build carrying
    // it. A repository that published under an older build, then deleted its
    // last fragment, still has to converge.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    let path = target.to_str().unwrap();
    apply_mesh_file(&one_workload(), path).unwrap();

    let publication = reconcile_mesh_file(None, path, whole_repository(false));

    assert_eq!(publication.unwrap(), MeshPublication::Retracted);
    assert_eq!(read(&target), empty_mesh_document());
}

#[test]
fn an_unattributed_destination_is_reported_and_left_untouched() {
    for foreign in [
        // Hand-written: same meaning, different formatting.
        "version: \"1\"\nmesh:\n  workloads: []\n",
        // Somebody else's file entirely.
        "# operator-managed\nproxies: []\n",
        // A gitforgeops-shaped document carrying an extra key.
        "version: '1'\nmesh: {}\nnote: keep\n",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("mesh.yaml");
        let path = target.to_str().unwrap();
        std::fs::write(&target, foreign).unwrap();

        let publication = reconcile_mesh_file(None, path, whole_repository(false));

        assert_eq!(publication.unwrap(), MeshPublication::Unattributed, "{foreign:?}");
        assert_eq!(read(&target), foreign);
    }
}

#[test]
fn a_hand_edited_destination_the_ledger_claims_is_still_retracted() {
    // Provenance is the gate and the ledger is the primary record, so an
    // operator who hand-edited a document this repository publishes still gets
    // convergence.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    let path = target.to_str().unwrap();
    std::fs::write(&target, "version: \"1\"\nmesh:\n  workloads: []\n").unwrap();

    let publication = reconcile_mesh_file(None, path, whole_repository(true));

    assert_eq!(publication.unwrap(), MeshPublication::Retracted);
    assert_eq!(read(&target), empty_mesh_document());
}

#[test]
fn retraction_is_idempotent_and_does_not_republish() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    let path = target.to_str().unwrap();
    apply_mesh_file(&one_workload(), path).unwrap();
    reconcile_mesh_file(None, path, whole_repository(true)).unwrap();
    let first = std::fs::metadata(&target).unwrap();

    let publication = reconcile_mesh_file(None, path, whole_repository(true));

    assert_eq!(publication.unwrap(), MeshPublication::AlreadyRetracted);
    // A mesh node reloads on any content change, so a no-op republish is not
    // worth one: the destination is not reopened for writing at all.
    let second = std::fs::metadata(&target).unwrap();
    assert_eq!(first.modified().unwrap(), second.modified().unwrap());
    assert_eq!(read(&target), empty_mesh_document());
}

#[test]
fn a_namespace_filtered_run_never_retracts() {
    // `FERRUM_NAMESPACE` narrows which fragments the assembler loads at all,
    // and the published document is mesh-wide. "No fragments selected" is not
    // evidence that the repository declares none.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    let path = target.to_str().unwrap();
    apply_mesh_file(&one_workload(), path).unwrap();
    let before = read(&target);

    let narrowed = MeshRetractionScope {
        ledger_attributed: true,
        covers_repository: false,
    };
    let publication = reconcile_mesh_file(None, path, narrowed);

    assert_eq!(publication.unwrap(), MeshPublication::NarrowedScope);
    assert_eq!(read(&target), before);
}

#[test]
fn planning_a_publication_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    let path = target.to_str().unwrap();

    let absent = plan_mesh_publication(None, path, whole_repository(true));
    assert_eq!(absent.unwrap(), MeshPublication::NeverPublished);
    assert!(!target.exists());

    apply_mesh_file(&one_workload(), path).unwrap();
    let before = read(&target);

    // The preview and the run it previews agree, and the preview is inert.
    let pending = plan_mesh_publication(None, path, whole_repository(true));
    assert_eq!(pending.unwrap(), MeshPublication::Retracted);
    let declared = plan_mesh_publication(Some(&one_workload()), path, whole_repository(true));
    assert_eq!(declared.unwrap(), MeshPublication::Published);
    assert_eq!(read(&target), before);
}

#[test]
fn a_retraction_that_cannot_be_written_is_an_error_not_a_silent_success() {
    // Fail-loud: the destination is a directory, so the publish cannot land.
    // Nothing may report a retraction that did not happen.
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("mesh.yaml");
    std::fs::create_dir(&target).unwrap();
    let path = target.to_str().unwrap();

    let result = reconcile_mesh_file(None, path, whole_repository(true));

    assert!(result.is_err(), "a failed retraction must not report success");
    assert!(target.is_dir(), "the destination is left as it was");
}

// ── Retraction, end to end ────────────────────────────────────────────────
//
// The publish/retract decision is only worth anything if the *commands* make
// it. These run the real binary in a throwaway checkout, in file mode, with a
// stub standing in for `ferrum-edge` (absent in Rust CI).

const RETRACTION_PROXY: &str = r#"kind: Proxy
spec:
  id: "api"
  listen_path: "/api"
  backend_scheme: https
  backend_host: "api.internal"
  backend_port: 443
"#;

const RETRACTION_FRAGMENT: &str = r#"kind: MeshConfig
spec:
  istio_root_namespace: istio-system
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      service_name: api
      namespace: ferrum
      trust_domain: cluster.local
      selector:
        static: api
"#;

/// A throwaway checkout plus a stub validator, run in file mode.
struct MeshRepo {
    dir: tempfile::TempDir,
    validator: PathBuf,
}

impl MeshRepo {
    fn new(with_fragment: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut files = vec![("resources/ferrum/proxies/api.yaml", RETRACTION_PROXY)];
        if with_fragment {
            files.push(("resources/ferrum/mesh/core.yaml", RETRACTION_FRAGMENT));
        }
        write_tree(dir.path(), &files);

        let validator = dir.path().join("ferrum-edge-stub");
        std::fs::write(&validator, "#!/bin/sh\nexit 0\n").expect("stub");
        set_executable(&validator);

        Self { dir, validator }
    }

    fn mesh_document(&self) -> PathBuf {
        self.dir.path().join("assembled/mesh.yaml")
    }

    fn published_mesh(&self) -> String {
        read(&self.mesh_document())
    }

    fn remove_fragment(&self) {
        let fragment = self.dir.path().join("resources/ferrum/mesh/core.yaml");
        std::fs::remove_file(fragment).expect("remove the last mesh fragment");
    }

    /// Run the binary hermetically: the child inherits only PATH/HOME/TMPDIR
    /// plus the `FERRUM_*` variables named here, so an ambient
    /// `FERRUM_GATEWAY_URL` in a developer shell cannot make a file-mode test
    /// talk to a gateway. Returns stdout and stderr combined.
    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> String {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        command
            .env("FERRUM_GATEWAY_MODE", "file")
            .env("FERRUM_FILE_OUTPUT_PATH", "assembled/resources.yaml")
            .env("FERRUM_MESH_FILE_OUTPUT_PATH", "assembled/mesh.yaml")
            .env("FERRUM_EDGE_BINARY_PATH", &self.validator);
        for (name, value) in extra_env {
            command.env(name, value);
        }
        let output = command.output().expect("run gitforgeops");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");
        assert!(output.status.success(), "{args:?} failed: {combined}");
        combined
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(path, mode).expect("chmod");
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

#[cfg(unix)]
#[test]
fn cli_apply_retracts_the_mesh_document_when_the_last_fragment_is_removed() {
    let repo = MeshRepo::new(true);
    repo.run(&["apply", "--auto-approve"], &[]);
    assert!(repo.published_mesh().contains("sa/api"));

    repo.remove_fragment();

    // The preview and the run it previews describe the same event, and the
    // preview publishes nothing.
    let planned = repo.run(&["plan"], &[]);
    assert!(planned.contains("=== Mesh ==="), "{planned}");
    assert!(planned.contains("RETRACT mesh"), "{planned}");
    assert!(repo.published_mesh().contains("sa/api"), "plan published");

    let applied = repo.run(&["apply", "--auto-approve"], &[]);
    assert!(applied.contains("RETRACT mesh"), "{applied}");
    assert_eq!(repo.published_mesh(), empty_mesh_document());

    // The ledger now attributes the destination, so the next run converges it
    // without re-deriving provenance from the bytes.
    let state_dir = repo.dir.path().join(".state");
    let mut state = String::new();
    for entry in std::fs::read_dir(state_dir).expect("state directory") {
        let path = entry.expect("state entry").path();
        state.push_str(&std::fs::read_to_string(path).unwrap_or_default());
    }
    assert!(state.contains("mesh_document_path"), "{state}");
    assert!(state.contains("assembled/mesh.yaml"), "{state}");

    let again = repo.run(&["apply", "--auto-approve"], &[]);
    assert!(again.contains("already holds the empty"), "{again}");
    assert_eq!(repo.published_mesh(), empty_mesh_document());
}

#[cfg(unix)]
#[test]
fn cli_never_publishes_a_mesh_document_for_a_repository_that_declares_none() {
    let repo = MeshRepo::new(false);

    let applied = repo.run(&["apply", "--auto-approve"], &[]);
    let planned = repo.run(&["plan"], &[]);
    let exported = repo.run(&["export", "--output", "export.yaml"], &[]);

    assert!(!repo.mesh_document().exists(), "fabricated a mesh document");
    for output in [&applied, &planned, &exported] {
        assert!(!output.contains("RETRACT mesh"), "{output}");
        assert!(!output.contains("mesh document"), "{output}");
    }
}

#[cfg(unix)]
#[test]
fn cli_export_retracts_with_and_without_materialize() {
    for materialize in [false, true] {
        let repo = MeshRepo::new(true);
        let mut args = vec!["export", "--output", "export.yaml"];
        if materialize {
            args.push("--materialize");
        }

        repo.run(&args, &[]);
        assert!(repo.published_mesh().contains("sa/api"), "{args:?}");

        repo.remove_fragment();
        let retracted = repo.run(&args, &[]);

        assert!(retracted.contains("RETRACT mesh"), "{args:?}: {retracted}");
        assert_eq!(repo.published_mesh(), empty_mesh_document(), "{args:?}");
    }
}

#[cfg(unix)]
#[test]
fn cli_leaves_an_unattributed_mesh_document_alone() {
    let repo = MeshRepo::new(false);
    let foreign = "version: \"1\"\nmesh:\n  workloads: []\n";
    std::fs::create_dir_all(repo.dir.path().join("assembled")).unwrap();
    std::fs::write(repo.mesh_document(), foreign).unwrap();

    let applied = repo.run(&["apply", "--auto-approve"], &[]);

    assert!(applied.contains("not a document gitforgeops"), "{applied}");
    assert_eq!(repo.published_mesh(), foreign);
}

#[cfg(unix)]
#[test]
fn cli_namespace_filtered_runs_never_retract() {
    let repo = MeshRepo::new(true);
    repo.run(&["apply", "--auto-approve"], &[]);
    let published = repo.published_mesh();

    // `edge` declares nothing at all, so the filtered run selects no fragment
    // — which is not evidence that the repository declares none.
    let only_edge = [("FERRUM_NAMESPACE", "edge")];
    let filtered = repo.run(&["apply", "--auto-approve"], &only_edge);

    assert!(filtered.contains("namespace-filtered run"), "{filtered}");
    assert_eq!(repo.published_mesh(), published);
}
