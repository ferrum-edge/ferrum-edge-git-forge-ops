//! Coverage for `tests/fixtures/companion-schema/`: one resource per kind
//! populating every field the serde mirror in `src/config/schema.rs` models.
//!
//! Two things are being pinned. First, that the mirror can actually *read*
//! everything it claims to model — a mirrored field spelled differently from
//! the gateway's wire name fails the strict load here rather than in a user's
//! CI. Second, that the fixture stays complete: the covered field set is
//! checked against the struct definitions in `schema.rs`, so a newly mirrored
//! field that nobody exercised fails this test instead of shipping untested.
//!
//! The Alloy consumer test below also loads actual CLI-generated trees in
//! hosted CI. Its input manifests and producer provenance are pinned under
//! `tests/fixtures/alloy-producer/`; resource YAML is generated at runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gitforgeops::config::schema::{BackendScheme, Resource};
use gitforgeops::config::{assemble, load_resources, load_resources_with_options, LoadOptions};
use gitforgeops::validate::run_validation;
use serde_json::Value;
use sha2::{Digest, Sha256};

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

#[test]
fn export_without_declared_timestamps_is_byte_deterministic() {
    let simple = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple-config");
    let render = || {
        let assembled = assemble(load_resources(&simple).unwrap()).unwrap();
        gitforgeops::apply::render_file_yaml(&assembled.gateway).unwrap()
    };
    let first = render();
    let second = render();
    assert_eq!(
        first, second,
        "loading a tree that omits timestamps must not fabricate wall-clock values"
    );
    // Neither serialized document invents server-owned timestamps.
    assert!(!first.contains("created_at"), "{first}");
    assert!(!first.contains("updated_at"), "{first}");
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

fn alloy_producer_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alloy-producer")
}

#[test]
fn alloy_producer_inputs_have_pinned_provenance() {
    let root = alloy_producer_dir();
    let provenance: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("PROVENANCE.json")).unwrap()).unwrap();
    assert_eq!(provenance["repository"], "ferrum-edge/ferrum-alloy");
    assert_eq!(
        provenance["commit"],
        "690aed7a9fa8458aeea4ac8416170c8daeb0470b"
    );
    let checksums = std::fs::read_to_string(root.join("SHA256SUMS")).unwrap();
    let inputs = provenance["fixture_inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 2);
    for input in inputs {
        let producer_path = input.as_str().unwrap();
        let file_name = Path::new(producer_path).file_name().unwrap();
        let bytes = std::fs::read(root.join(file_name)).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        let record = format!("{digest}  {producer_path}");
        assert!(
            checksums.lines().any(|line| line == record),
            "vendored input must match the pinned producer: {producer_path}"
        );
    }
}

fn alloy_tree_hashes(root: &Path) -> BTreeMap<PathBuf, String> {
    walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .map(|entry| entry.unwrap())
        .filter(|entry| !entry.file_type().is_dir())
        .map(|entry| {
            assert!(
                entry.file_type().is_file(),
                "generated output must be regular"
            );
            let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
            let bytes = std::fs::read(entry.path()).unwrap();
            (relative, hex::encode(Sha256::digest(&bytes)))
        })
        .collect()
}

fn alloy_validate_cli(root: &Path, validator: &Path, namespace: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
    // The generated project has no repository configuration or credential
    // bundle. Do not inherit either from the CI checkout or the developer.
    command
        .args(["validate", "--format", "json"])
        .current_dir(root)
        .env_clear()
        .env("FERRUM_GATEWAY_MODE", "file")
        .env("FERRUM_EDGE_BINARY_PATH", validator);
    if let Some(namespace) = namespace {
        command.env("FERRUM_NAMESPACE", namespace);
    }
    command.output().expect("run GitForgeOps consumer CLI")
}

fn alloy_mutated_tree(
    root: &Path,
    relative: &str,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> tempfile::TempDir {
    let copy = tempfile::tempdir().unwrap();
    for path in alloy_tree_hashes(root).keys() {
        let destination = copy.path().join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(root.join(path), &destination).unwrap();
    }
    let path = copy.path().join(relative);
    let mut document: serde_json::Value =
        serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    mutate(&mut document);
    std::fs::write(path, serde_yaml::to_string(&document).unwrap()).unwrap();
    copy
}

/// This test consumes runtime output from the real, immutable Alloy CLI, never
/// a hand-written resource mirror. `validator-pairing` must select it explicitly
/// and verify that exactly one test is listed before running it. Missing inputs
/// are failures, not skips. Ordinary unit tests remain offline.
#[test]
#[ignore = "requires hosted Alloy generation and the verified Edge validator"]
fn alloy_generated_resources_load_assemble_and_validate() {
    let root = PathBuf::from(
        std::env::var_os("GITFORGEOPS_ALLOY_FIXTURE_ROOT")
            .expect("generated fixture root is required"),
    );
    let validator = PathBuf::from(
        std::env::var_os("GITFORGEOPS_ALLOY_VALIDATOR")
            .expect("verified Edge validator is required"),
    );
    assert!(validator.is_file(), "verified validator must exist");

    for (fixture, namespace, proxy_id, upstream_count) in [
        ("orders-api", "ferrum", "orders-api", 1),
        ("plain-http", "retail", "catalog", 0),
    ] {
        let project = root.join(fixture);
        let original = alloy_tree_hashes(&project);
        let mut expected = BTreeSet::from([
            PathBuf::from(format!("resources/{namespace}/proxies/{proxy_id}.yaml")),
            PathBuf::from(format!(
                "resources/{namespace}/plugins/{proxy_id}-correlation-id.yaml"
            )),
            PathBuf::from(format!(
                "resources/{namespace}/plugins/{proxy_id}-otel-tracing.yaml"
            )),
        ]);
        if upstream_count == 1 {
            expected.insert(PathBuf::from(format!(
                "resources/{namespace}/upstreams/{proxy_id}-upstream.yaml"
            )));
        }
        assert_eq!(original.keys().cloned().collect::<BTreeSet<_>>(), expected);
        for (path, digest) in &original {
            println!("{fixture}: {digest}  {}", path.display());
        }

        let resources = load_resources(&project.join("resources")).expect("strict producer load");
        assert_eq!(resources.len(), 3 + upstream_count);
        assert!(resources
            .iter()
            .all(|(directory, _)| directory == namespace));
        let assembled = assemble(resources).expect("assemble actual producer output");
        assert!(assembled.mesh.is_none());
        let gateway = &assembled.gateway;
        assert_eq!(gateway.proxies.len(), 1);
        assert_eq!(gateway.upstreams.len(), upstream_count);
        assert_eq!(gateway.plugin_configs.len(), 2);
        // Alloy does not export Consumers or broker credential slots.
        assert!(gateway.consumers.is_empty());
        gitforgeops::config::validate_unique_resource_keys(gateway).unwrap();
        gitforgeops::apply::validate_no_desired_spec_tags(gateway).unwrap();
        let proxy = &gateway.proxies[0];
        assert_eq!(proxy.id, proxy_id);
        assert_eq!(proxy.namespace, namespace);
        assert_eq!(proxy.labels["generated-by"], "ferrum-alloy");
        assert_eq!(proxy.labels["provisioned-by"], "ferrum-edge-git-forge-ops");
        let associations: BTreeSet<_> = proxy
            .plugins
            .iter()
            .map(|plugin| plugin.plugin_config_id.as_str())
            .collect();
        assert_eq!(associations.len(), 2);
        for plugin in &gateway.plugin_configs {
            assert_eq!(plugin.namespace, namespace);
            assert_eq!(plugin.proxy_id.as_deref(), Some(proxy_id));
            assert!(associations.contains(plugin.id.as_str()));
        }
        let tracing = gateway
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "otel_tracing")
            .unwrap();
        assert_eq!(tracing.config["trace_context_trust"], "untrusted");
        if upstream_count == 1 {
            assert_eq!(proxy.backend_scheme, Some(BackendScheme::Https));
            let upstream = &gateway.upstreams[0];
            assert_eq!(proxy.upstream_id.as_deref(), Some(upstream.id.as_str()));
            assert_eq!(upstream.namespace, namespace);
            assert_eq!(upstream.targets[0].host, "orders.internal");
            assert_eq!(upstream.targets[0].port, 8443);
            assert_eq!(upstream.labels["generated-by"], "ferrum-alloy");
            let active = upstream
                .health_checks
                .as_ref()
                .unwrap()
                .active
                .as_ref()
                .unwrap();
            assert_eq!(active.http_path, "/readyz");
            assert_eq!(active.interval_seconds, 10);
            assert!(active.use_tls);
            assert_eq!(
                upstream.backend_tls_client_cert_path.as_deref(),
                Some("/etc/ferrum/edge-client.pem")
            );
            assert_eq!(
                upstream.backend_tls_client_key_path.as_deref(),
                Some("/etc/ferrum/edge-client.key")
            );
            assert_eq!(
                upstream.backend_tls_server_ca_cert_path.as_deref(),
                Some("/etc/ferrum/alloy-ca.pem")
            );
        } else {
            assert_eq!(proxy.backend_scheme, Some(BackendScheme::Http));
            assert!(proxy.upstream_id.is_none());
            assert_eq!(proxy.backend_host, "127.0.0.1");
            assert_eq!(proxy.backend_port, 8080);
            assert_eq!(proxy.backend_path.as_deref(), Some("/v1"));
            assert_eq!(proxy.backend_read_timeout_ms, 0);
            assert_eq!(tracing.config["root_sampling"], "ratio");
            assert_eq!(tracing.config["root_sampling_ratio"], 0.25);
        }

        let result = run_validation(gateway, validator.to_str().unwrap())
            .expect("execute verified Edge validator through the shared runner");
        assert!(result.success, "{}\n{}", result.stdout, result.stderr);
        let output = alloy_validate_cli(&project, &validator, None);
        assert!(output.status.success(), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], true);
        assert_eq!(report["desired_count"], 3 + upstream_count);

        // A typoed parent namespace must refuse the non-empty generated tree.
        let output = alloy_validate_cli(&project, &validator, Some("missing-alloy-namespace"));
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["success"], false);
        assert_eq!(report["empty_namespace_filter"], "error");
        assert_eq!(report["desired_count"], 0);
        assert_eq!(
            alloy_tree_hashes(&project),
            original,
            "validation must not rewrite output"
        );
    }

    let orders = root.join("orders-api");
    let original = alloy_tree_hashes(&orders);
    alloy_generated_negative_cases(&orders, &validator);
    alloy_generated_nullable_cases(&orders, &validator);
    assert_eq!(
        alloy_tree_hashes(&orders),
        original,
        "mutations must leave the producer output unchanged"
    );
}

fn alloy_generated_negative_cases(project: &Path, validator: &Path) {
    let proxy_path = "resources/ferrum/proxies/orders-api.yaml";
    for (field, value, diagnostic) in [
        ("kind", "AlloyService", "unknown resource kind"),
        ("alloy_unknown_wrapper", "invalid", ".alloy_unknown_wrapper"),
        ("spec.backend_scheme", "h2c", "backend scheme"),
        (
            "spec.alloy_unknown_field",
            "invalid",
            ".spec.alloy_unknown_field",
        ),
    ] {
        let copy = alloy_mutated_tree(project, proxy_path, |document| {
            if let Some(spec_field) = field.strip_prefix("spec.") {
                document["spec"][spec_field] = value.into();
            } else {
                document[field] = value.into();
            }
        });
        let error = load_resources(&copy.path().join("resources")).unwrap_err();
        assert!(error.to_string().contains(diagnostic), "{error}");
    }

    for (field, diagnostic) in [
        ("kind", "missing 'kind'"),
        ("spec", "invalid resource spec"),
        ("spec.id", "invalid resource spec"),
        ("spec.backend_port", "invalid resource spec"),
        ("alloy_unknown_wrapper", ".alloy_unknown_wrapper"),
        ("spec.alloy_unknown_field", ".spec.alloy_unknown_field"),
    ] {
        let copy = alloy_mutated_tree(project, proxy_path, |document| {
            if let Some(spec_field) = field.strip_prefix("spec.") {
                document["spec"][spec_field] = Value::Null;
            } else {
                document[field] = Value::Null;
            }
        });
        let error = load_resources(&copy.path().join("resources")).unwrap_err();
        if diagnostic.starts_with('.') {
            match error {
                gitforgeops::error::Error::UnknownFields { fields, .. } => {
                    assert_eq!(fields, diagnostic);
                }
                other => panic!("expected an unknown-field refusal: {other}"),
            }
        } else {
            assert!(error.to_string().contains(diagnostic), "{error}");
        }
    }

    let plugin_path = "resources/ferrum/plugins/orders-api-correlation-id.yaml";
    for field in ["plugin_name", "scope"] {
        let copy = alloy_mutated_tree(project, plugin_path, |document| {
            document["spec"][field] = Value::Null;
        });
        let error = load_resources(&copy.path().join("resources")).unwrap_err();
        assert!(
            error.to_string().contains("invalid resource spec"),
            "{error}"
        );
    }

    let upstream_path = "resources/ferrum/upstreams/orders-api-upstream.yaml";
    for value in [Value::Bool(true), Value::Null] {
        let copy = alloy_mutated_tree(project, upstream_path, |document| {
            document["spec"]["targets"][0]["alloy_unknown_field"] = value;
        });
        let resource_root = copy.path().join("resources");
        for options in [LoadOptions::STRICT, LoadOptions::ALLOW_UNKNOWN_FIELDS] {
            let error = load_resources_with_options(&resource_root, options).unwrap_err();
            match error {
                gitforgeops::error::Error::UnknownFields { fields, .. } => {
                    assert_eq!(fields, ".spec.targets[0].alloy_unknown_field");
                }
                other => panic!("expected a nested unknown-field refusal: {other}"),
            }
        }
    }

    let copy = alloy_mutated_tree(project, upstream_path, |document| {
        document["spec"]["targets"][0]["host"] = Value::Null;
    });
    let error = load_resources(&copy.path().join("resources")).unwrap_err();
    assert!(
        error.to_string().contains("invalid resource spec"),
        "{error}"
    );

    // Explicit namespace overrides remain supported. Moving only an upstream
    // breaks the same-namespace graph and must fail authoritative validation.
    let copy = alloy_mutated_tree(project, upstream_path, |document| {
        document["spec"]["namespace"] = "retail".into();
    });
    let output = alloy_validate_cli(copy.path(), validator, None);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);

    let copy = alloy_mutated_tree(project, proxy_path, |document| {
        document["spec"]["api_spec_id"] = "forged-spec-owner".into();
    });
    let output = alloy_validate_cli(copy.path(), validator, None);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("admin-generated"));

    let copy = alloy_mutated_tree(project, proxy_path, |document| {
        document["spec"]["id"] = "../escaped".into();
    });
    let output = alloy_validate_cli(copy.path(), validator, None);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], false);

    #[cfg(unix)]
    {
        let copy = alloy_mutated_tree(project, proxy_path, |_| {});
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("outside.yaml");
        std::fs::copy(project.join(proxy_path), &target).unwrap();
        let before = std::fs::read(&target).unwrap();
        std::os::unix::fs::symlink(
            &target,
            copy.path().join("resources/ferrum/proxies/escape.yaml"),
        )
        .unwrap();
        assert!(matches!(
            load_resources(&copy.path().join("resources")),
            Err(gitforgeops::error::Error::ConfigSymlink(_))
        ));
        assert_eq!(std::fs::read(&target).unwrap(), before);
    }
}

fn alloy_generated_nullable_cases(project: &Path, validator: &Path) {
    let proxy_path = "resources/ferrum/proxies/orders-api.yaml";
    let copy = alloy_mutated_tree(project, proxy_path, |document| {
        document["spec"]["name"] = Value::Null;
        document["spec"]["backend_scheme"] = Value::Null;
        document["spec"]["backend_path"] = Value::Null;
        document["spec"]["circuit_breaker"] = Value::Null;
    });
    let resources = load_resources(&copy.path().join("resources")).unwrap();
    let assembled = assemble(resources).unwrap();
    let proxy = &assembled.gateway.proxies[0];
    assert!(proxy.name.is_none());
    assert_eq!(proxy.backend_scheme, Some(BackendScheme::Https));
    assert!(proxy.backend_path.is_none());
    assert!(proxy.circuit_breaker.is_none());
    let output = alloy_validate_cli(copy.path(), validator, None);
    assert!(output.status.success(), "{output:?}");

    let upstream_path = "resources/ferrum/upstreams/orders-api-upstream.yaml";
    let copy = alloy_mutated_tree(project, upstream_path, |document| {
        document["spec"]["targets"][0]["path"] = Value::Null;
        document["spec"]["health_checks"]["passive"] = Value::Null;
    });
    let resources = load_resources(&copy.path().join("resources")).unwrap();
    let assembled = assemble(resources).unwrap();
    let upstream = &assembled.gateway.upstreams[0];
    assert!(upstream.targets[0].path.is_none());
    let health_checks = upstream.health_checks.as_ref().unwrap();
    assert!(health_checks.passive.is_none());
    let output = alloy_validate_cli(copy.path(), validator, None);
    assert!(output.status.success(), "{output:?}");

    // The documented opt-in still carries unknown top-level values verbatim,
    // including null. It never permits an unknown wrapper or nested field.
    let copy = alloy_mutated_tree(project, proxy_path, |document| {
        document["spec"]["alloy_unknown_field"] = Value::Null;
    });
    let resources = load_resources_with_options(
        &copy.path().join("resources"),
        LoadOptions::ALLOW_UNKNOWN_FIELDS,
    )
    .unwrap();
    let assembled = assemble(resources).unwrap();
    let proxy = &assembled.gateway.proxies[0];
    assert_eq!(proxy.extra.get("alloy_unknown_field"), Some(&Value::Null));
    let exported = serde_json::to_value(proxy).unwrap();
    let object = exported.as_object().unwrap();
    assert!(object.contains_key("alloy_unknown_field"));
    assert_eq!(exported["alloy_unknown_field"], Value::Null);

    let copy = alloy_mutated_tree(project, proxy_path, |document| {
        document["alloy_unknown_wrapper"] = Value::Null;
    });
    let error = load_resources_with_options(
        &copy.path().join("resources"),
        LoadOptions::ALLOW_UNKNOWN_FIELDS,
    )
    .unwrap_err();
    match error {
        gitforgeops::error::Error::UnknownFields { fields, .. } => {
            assert_eq!(fields, ".alloy_unknown_wrapper");
        }
        other => panic!("expected a wrapper unknown-field refusal: {other}"),
    }
}
