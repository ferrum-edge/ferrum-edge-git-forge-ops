//! Unknown-field policy: fail-closed by default, opt-in pass-through for
//! unknown **top-level** `spec` fields (`FERRUM_ALLOW_UNKNOWN_FIELDS`).

use std::path::Path;

use gitforgeops::config::schema::{PassthroughFields, Resource};
use gitforgeops::config::{
    apply_overlay, apply_overlay_with_options, assemble, load_resources,
    load_resources_with_options, LoadOptions,
};

const PROXY_WITH_UNKNOWN_TOP_LEVEL: &str = r#"
kind: Proxy
spec:
  id: edge
  listen_path: /edge
  backend_scheme: https
  backend_host: example.test
  backend_port: 443
  turbo_mode: true
  hypothetical_future_field:
    nested: value
"#;

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    for (relative, contents) in files {
        write(tmp.path(), relative, contents);
    }
    tmp
}

fn only_proxy(resources: &[(String, Resource)]) -> &gitforgeops::config::schema::Proxy {
    resources
        .iter()
        .find_map(|(_, resource)| match resource {
            Resource::Proxy { spec } => Some(spec),
            _ => None,
        })
        .expect("expected exactly one proxy")
}

#[test]
fn unknown_top_level_spec_field_is_rejected_by_default() {
    let tmp = tree(&[("ferrum/proxies/edge.yaml", PROXY_WITH_UNKNOWN_TOP_LEVEL)]);

    let error = load_resources(tmp.path()).unwrap_err().to_string();
    assert!(
        error.contains("unknown configuration field"),
        "expected the unknown-field error; got: {error}"
    );
    assert!(
        error.contains(".spec.turbo_mode") && error.contains(".spec.hypothetical_future_field"),
        "error must name every unknown field by its YAML path; got: {error}"
    );
}

#[test]
fn unknown_top_level_spec_fields_pass_through_on_explicit_opt_in() {
    let tmp = tree(&[("ferrum/proxies/edge.yaml", PROXY_WITH_UNKNOWN_TOP_LEVEL)]);

    let resources =
        load_resources_with_options(tmp.path(), LoadOptions::ALLOW_UNKNOWN_FIELDS).unwrap();
    let proxy = only_proxy(&resources);
    assert_eq!(
        proxy.passthrough().get("turbo_mode"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        proxy.passthrough().get("hypothetical_future_field"),
        Some(&serde_json::json!({"nested": "value"})),
        "nested structure inside an unknown field is carried verbatim"
    );

    // ...and survives assembly and export unchanged, so the gateway — the
    // authoritative schema — is the one that judges the field.
    let assembled = assemble(resources).unwrap();
    let exported = gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap();
    assert!(exported.contains("turbo_mode: true"), "{exported}");
    assert!(exported.contains("nested: value"), "{exported}");

    // Known fields still round-trip alongside the unknown ones.
    let reparsed: serde_yaml::Value = serde_yaml::from_str(&exported).unwrap();
    assert_eq!(
        reparsed["proxies"][0]["backend_host"],
        serde_yaml::Value::from("example.test")
    );
}

#[test]
fn nested_unknown_fields_stay_fatal_even_with_the_opt_in() {
    // Pass-through is deliberately top-level only: carrying nested unknowns
    // would mean flattening every nested struct, turning each into a
    // silent-accept surface.
    let tmp = tree(&[(
        "ferrum/proxies/edge.yaml",
        r#"
kind: Proxy
spec:
  id: edge
  listen_path: /edge
  backend_scheme: https
  backend_host: example.test
  backend_port: 443
  circuit_breaker:
    failure_threshold: 5
    turbo_trip: true
"#,
    )]);

    for options in [LoadOptions::STRICT, LoadOptions::ALLOW_UNKNOWN_FIELDS] {
        let error = load_resources_with_options(tmp.path(), options)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(".spec.circuit_breaker.turbo_trip"),
            "nested unknown must be rejected with its full path under {options:?}; got: {error}"
        );
    }
}

#[test]
fn deliberately_opaque_sections_are_untouched_by_the_policy() {
    // Plugin `config`, consumer `credentials` and mesh collection items are
    // free-form `serde_json::Value` islands; they were never unknown-field
    // surfaces and the pass-through must not change that.
    let tmp = tree(&[
        (
            "ferrum/plugins/rate.yaml",
            r#"
kind: PluginConfig
spec:
  id: rate
  plugin_name: rate_limiting
  scope: global
  config:
    invented_by_a_future_plugin:
      deeply:
        nested: [1, 2, 3]
"#,
        ),
        (
            "ferrum/consumers/app.yaml",
            r#"
kind: Consumer
spec:
  id: app
  username: app
  credentials:
    some_future_credential_type:
      - key: "${gh-env-secret:alloc=require}"
        extra_attribute: 7
"#,
        ),
        (
            "ferrum/mesh/core.yaml",
            r#"
kind: MeshConfig
spec:
  workloads:
    - spiffe_id: spiffe://mesh/ns/ferrum/sa/app
      invented_workload_attribute: true
"#,
        ),
    ]);

    let resources = load_resources(tmp.path()).expect("opaque islands stay free-form under STRICT");
    assert_eq!(resources.len(), 3);
}

#[test]
fn overlays_can_set_and_override_a_passthrough_field() {
    let base = tree(&[(
        "ferrum/proxies/edge.yaml",
        r#"
kind: Proxy
spec:
  id: edge
  listen_path: /edge
  backend_scheme: https
  backend_host: example.test
  backend_port: 443
  turbo_mode: false
"#,
    )]);
    let overlay = tree(&[(
        "ferrum/proxies/edge.yaml",
        r#"
kind: Proxy
spec:
  id: edge
  turbo_mode: true
  another_future_field: staging
"#,
    )]);

    let mut resources =
        load_resources_with_options(base.path(), LoadOptions::ALLOW_UNKNOWN_FIELDS).unwrap();
    apply_overlay_with_options(
        &mut resources,
        overlay.path(),
        LoadOptions::ALLOW_UNKNOWN_FIELDS,
    )
    .unwrap();

    let proxy = only_proxy(&resources);
    assert_eq!(
        proxy.passthrough().get("turbo_mode"),
        Some(&serde_json::json!(true)),
        "an overlay overrides a pass-through field like any other"
    );
    assert_eq!(
        proxy.passthrough().get("another_future_field"),
        Some(&serde_json::json!("staging")),
        "an overlay can introduce a pass-through field the base never declared"
    );
}

#[test]
fn overlays_cannot_introduce_unknown_fields_by_default() {
    let base = tree(&[(
        "ferrum/proxies/edge.yaml",
        r#"
kind: Proxy
spec:
  id: edge
  listen_path: /edge
  backend_scheme: https
  backend_host: example.test
  backend_port: 443
"#,
    )]);
    let overlay = tree(&[(
        "ferrum/proxies/edge.yaml",
        "kind: Proxy\nspec:\n  id: edge\n  turbo_mode: true\n",
    )]);

    let mut resources = load_resources(base.path()).unwrap();
    let error = apply_overlay(&mut resources, overlay.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains(".spec.turbo_mode"), "{error}");
}

#[test]
fn declared_passthrough_fields_are_diffed_but_live_only_ones_are_not() {
    use gitforgeops::config::GatewayConfig;
    use gitforgeops::diff::compute_diff;

    let load = |yaml: &str| {
        let tmp = tree(&[("ferrum/proxies/edge.yaml", yaml)]);
        let resources =
            load_resources_with_options(tmp.path(), LoadOptions::ALLOW_UNKNOWN_FIELDS).unwrap();
        assemble(resources).unwrap().gateway
    };

    let plain = load(
        r#"
kind: Proxy
spec:
  id: edge
  listen_path: /edge
  backend_scheme: https
  backend_host: example.test
  backend_port: 443
"#,
    );
    let with_field = load(
        r#"
kind: Proxy
spec:
  id: edge
  listen_path: /edge
  backend_scheme: https
  backend_host: example.test
  backend_port: 443
  turbo_mode: true
"#,
    );

    // The repo declares the field, the gateway does not have it: real drift
    // the repo owns and apply can push.
    let diffs = compute_diff(&with_field, &plain);
    assert_eq!(diffs.len(), 1, "{diffs:#?}");
    assert!(
        diffs[0]
            .details
            .iter()
            .any(|change| change.field == "turbo_mode"),
        "{:#?}",
        diffs[0].details
    );

    // The gateway carries a field this client does not model and the repo
    // never declared: not drift. Reporting it would make every gateway
    // upgrade permanent, unclearable drift on every resource.
    assert!(
        compute_diff(&plain, &with_field).is_empty(),
        "live-only unknown fields must not be reported as drift"
    );

    // Sanity: an empty pass-through map serializes to nothing, so a resource
    // that never saw an unknown field is byte-identical to one from a build
    // without the feature.
    let empty = GatewayConfig::default();
    assert!(compute_diff(&empty, &empty).is_empty());
}

/// The warning has to reach stderr: `gitforgeops export` writes the assembled
/// YAML document to stdout, and a warning interleaved into it would corrupt
/// the artifact a file-mode gateway consumes.
#[test]
fn the_passthrough_warning_goes_to_stderr_and_never_into_exported_yaml() {
    let repo = tempfile::tempdir().unwrap();
    write(
        repo.path(),
        "resources/ferrum/proxies/edge.yaml",
        PROXY_WITH_UNKNOWN_TOP_LEVEL,
    );

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gitforgeops"))
        .arg("export")
        .current_dir(repo.path())
        .env("FERRUM_ALLOW_UNKNOWN_FIELDS", "true")
        .env("FERRUM_GATEWAY_MODE", "file")
        .env_remove("FERRUM_OVERLAY")
        .env_remove("FERRUM_ENV")
        .env_remove("FERRUM_NAMESPACE")
        .output()
        .expect("run gitforgeops export");
    assert!(
        output.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stdout.contains("Warning"),
        "stdout must carry only the YAML document; got:\n{stdout}"
    );
    serde_yaml::from_str::<serde_yaml::Value>(&stdout).expect("stdout must parse as YAML");
    assert!(stdout.contains("turbo_mode: true"), "{stdout}");
    assert!(
        stderr.contains("Warning:")
            && stderr.contains("FERRUM_ALLOW_UNKNOWN_FIELDS")
            && stderr.contains(".spec.turbo_mode"),
        "stderr must name the file and every field kept; got:\n{stderr}"
    );
}
