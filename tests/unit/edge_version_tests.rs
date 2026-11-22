//! Version-aware handling for paired Ferrum Edge releases, covering
//! `Proxy.pool_max_requests_per_connection` across the v0.9.20 and v0.9.21
//! pairings (#739).

use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use gitforgeops::apply::render_file_yaml;
use gitforgeops::config::{
    adapt_gateway_for_edge_version, assemble, format_omitted_proxy_fields_notice, load_resources,
    resolve_env, EdgeVersion, EnvConfig, GatewayConfig, OmittedProxyField, RepoConfig,
    DEFAULT_EDGE_VERSION, POOL_MAX_REQUESTS_FIELD, POOL_MAX_REQUESTS_REMOVED_IN,
};
use gitforgeops::diff::{compute_diff, DiffAction};
use gitforgeops::pipeline::load_and_assemble;
use gitforgeops::validate::scrubbed_env_names;
use tempfile::NamedTempFile;

fn fixture_root(variant: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pool-max-requests")
        .join(variant)
}

fn load_fixture_gateway(variant: &str) -> GatewayConfig {
    let resources = load_resources(&fixture_root(variant))
        .expect("paired pool_max_requests_per_connection fixture must load under strict mode");
    assemble(resources).expect("assemble fixture").gateway
}

#[test]
fn edge_version_parsing_ordering_and_pool_max_capability() {
    assert_eq!(DEFAULT_EDGE_VERSION, EdgeVersion::new(0, 9, 20));
    assert_eq!(POOL_MAX_REQUESTS_REMOVED_IN, EdgeVersion::new(0, 9, 21));

    for (raw, expected) in [
        ("0.9.19", EdgeVersion::new(0, 9, 19)),
        ("v0.9.19", EdgeVersion::new(0, 9, 19)),
        ("0.9.20", EdgeVersion::new(0, 9, 20)),
        ("v0.9.20", EdgeVersion::new(0, 9, 20)),
        ("0.9.21", EdgeVersion::new(0, 9, 21)),
        ("v0.9.21", EdgeVersion::new(0, 9, 21)),
        ("0.10.0", EdgeVersion::new(0, 10, 0)),
        ("v1.0.0", EdgeVersion::new(1, 0, 0)),
    ] {
        let parsed = EdgeVersion::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
        assert_eq!(parsed, expected);
        assert_eq!(EdgeVersion::from_str(raw).unwrap(), expected);
        assert_eq!(
            parsed.to_string(),
            format!("v{}.{}.{}", expected.major, expected.minor, expected.patch)
        );
    }

    for invalid in [
        "",
        "v",
        "V0.9.20",
        "0.9",
        "0.9.20.1",
        "v0.9.21-rc.1",
        "0.9.21+build",
        "0.9.x",
        "+0.9.20",
        " 0.9.20",
        "0.9.20 ",
        "vv0.9.20",
    ] {
        let Err(err) = EdgeVersion::parse(invalid) else {
            panic!("must reject {invalid:?}");
        };
        assert!(
            err.to_string().contains("invalid Edge version"),
            "{invalid:?}: {err}"
        );
    }

    assert!(EdgeVersion::new(0, 9, 19).supports_pool_max_requests_per_connection());
    assert!(EdgeVersion::new(0, 9, 20).supports_pool_max_requests_per_connection());
    assert!(DEFAULT_EDGE_VERSION.supports_pool_max_requests_per_connection());
    assert!(!EdgeVersion::new(0, 9, 21).supports_pool_max_requests_per_connection());
    assert!(!EdgeVersion::new(0, 9, 22).supports_pool_max_requests_per_connection());
    assert!(!EdgeVersion::new(0, 10, 0).supports_pool_max_requests_per_connection());
    assert!(!EdgeVersion::new(1, 0, 0).supports_pool_max_requests_per_connection());
}

#[test]
fn repo_config_edge_version_precedence_and_validation() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        br#"
version: 1
environments:
  v20:
    edge_version: v0.9.20
  v21:
    edge_version: "0.9.21"
  inherited: {}
"#,
    )
    .unwrap();
    let repo = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    assert_eq!(
        repo.environment("v20").unwrap().edge_version,
        Some(EdgeVersion::new(0, 9, 20))
    );
    assert_eq!(
        repo.environment("v21").unwrap().edge_version,
        Some(EdgeVersion::new(0, 9, 21))
    );
    assert_eq!(repo.environment("inherited").unwrap().edge_version, None);

    // Repo config wins over FERRUM_EDGE_VERSION; unset falls back to env var,
    // then to DEFAULT_EDGE_VERSION (v0.9.20).
    let env_v21 = EnvConfig {
        edge_version: Some(EdgeVersion::new(0, 9, 21)),
        ..EnvConfig::default()
    };
    let resolved_v20 = resolve_env(Some(&repo), &env_v21, Some("v20")).unwrap();
    assert_eq!(
        resolved_v20.effective_edge_version(),
        EdgeVersion::new(0, 9, 20)
    );

    let resolved_inherited = resolve_env(Some(&repo), &env_v21, Some("inherited")).unwrap();
    assert_eq!(
        resolved_inherited.effective_edge_version(),
        EdgeVersion::new(0, 9, 21)
    );

    let resolved_default =
        resolve_env(Some(&repo), &EnvConfig::default(), Some("inherited")).unwrap();
    assert_eq!(
        resolved_default.effective_edge_version(),
        DEFAULT_EDGE_VERSION
    );

    // Synthetic default environment (no .gitforgeops/config.yaml) honors EnvConfig.
    let synthetic = resolve_env(None, &env_v21, None).unwrap();
    assert_eq!(
        synthetic.effective_edge_version(),
        EdgeVersion::new(0, 9, 21)
    );

    // Invalid edge_version in repo config is rejected fail-closed at load time.
    let mut bad = NamedTempFile::new().unwrap();
    bad.write_all(
        br#"
version: 1
environments:
  broken:
    edge_version: v0.9.21-beta
"#,
    )
    .unwrap();
    let err = RepoConfig::load_from_path(bad.path()).unwrap_err();
    assert!(
        err.to_string().contains("invalid Edge version"),
        "unexpected error: {err}"
    );
}

#[test]
fn ferrum_edge_version_is_scrubbed_from_validator_children() {
    let scrubbed = scrubbed_env_names(["FERRUM_EDGE_VERSION", "PATH"]);
    assert_eq!(scrubbed, vec!["FERRUM_EDGE_VERSION"]);
}

#[test]
fn paired_fixtures_keep_exact_v0920_emit_and_diff_semantics() {
    let with_field = load_fixture_gateway("with-field");
    let without_field = load_fixture_gateway("without-field");
    assert_eq!(
        with_field.proxies[0].pool_max_requests_per_connection,
        Some(1000)
    );
    assert_eq!(
        without_field.proxies[0].pool_max_requests_per_connection,
        None
    );

    // v0.9.20 pairing leaves both documents untouched.
    let mut v20_with = with_field.clone();
    let omitted = adapt_gateway_for_edge_version(&mut v20_with, EdgeVersion::new(0, 9, 20));
    assert!(omitted.is_empty());
    assert!(format_omitted_proxy_fields_notice(EdgeVersion::new(0, 9, 20), &omitted).is_none());
    assert_eq!(
        v20_with.proxies[0].pool_max_requests_per_connection,
        Some(1000)
    );

    let exported_with = render_file_yaml(&v20_with).unwrap();
    assert!(
        exported_with.contains("pool_max_requests_per_connection: 1000"),
        "{exported_with}"
    );
    let exported_without = render_file_yaml(&without_field).unwrap();
    assert!(
        !exported_without.contains("pool_max_requests_per_connection"),
        "{exported_without}"
    );

    // Exact v0.9.20 diff semantics:
    // 1. Matching 1000 vs 1000 -> in sync.
    assert!(compute_diff(&v20_with, &with_field).unwrap().is_empty());

    // 2. Desired sets 1000, live omits -> Modify (null -> 1000).
    let add_field = compute_diff(&v20_with, &without_field).unwrap();
    assert_eq!(add_field.len(), 1);
    assert_eq!(add_field[0].action, DiffAction::Modify);
    assert_eq!(add_field[0].details.len(), 1);
    assert_eq!(add_field[0].details[0].field, POOL_MAX_REQUESTS_FIELD);
    assert_eq!(add_field[0].details[0].old_value, "null");
    assert_eq!(add_field[0].details[0].new_value, "1000");

    // 3. Desired omits the field while live v0.9.20 has 1000 -> Modify (1000 -> null),
    // because a save that omits the field clears it on v0.9.20 (#739).
    let clear_field = compute_diff(&without_field, &with_field).unwrap();
    assert_eq!(clear_field.len(), 1);
    assert_eq!(clear_field[0].action, DiffAction::Modify);
    assert_eq!(clear_field[0].details.len(), 1);
    assert_eq!(clear_field[0].details[0].field, POOL_MAX_REQUESTS_FIELD);
    assert_eq!(clear_field[0].details[0].old_value, "1000");
    assert_eq!(clear_field[0].details[0].new_value, "null");

    // 4. Value change 500 -> 1000 -> Modify.
    let mut live_500 = with_field.clone();
    live_500.proxies[0].pool_max_requests_per_connection = Some(500);
    let changed = compute_diff(&v20_with, &live_500).unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].details[0].field, POOL_MAX_REQUESTS_FIELD);
    assert_eq!(changed[0].details[0].old_value, "500");
    assert_eq!(changed[0].details[0].new_value, "1000");
}

#[test]
fn paired_fixtures_omit_field_on_v0921_and_keep_live_mismatch_visible() {
    let with_field = load_fixture_gateway("with-field");
    let without_field = load_fixture_gateway("without-field");

    // v0.9.21 pairing adapts the desired document carrying the removed no-op field.
    let mut v21_desired = with_field.clone();
    let omitted = adapt_gateway_for_edge_version(&mut v21_desired, EdgeVersion::new(0, 9, 21));
    assert_eq!(
        omitted,
        vec![OmittedProxyField {
            namespace: "ferrum".to_string(),
            id: "pool-max-proxy".to_string(),
            field: POOL_MAX_REQUESTS_FIELD,
        }]
    );
    assert_eq!(
        v21_desired.proxies[0].pool_max_requests_per_connection,
        None
    );

    let notice = format_omitted_proxy_fields_notice(EdgeVersion::new(0, 9, 21), &omitted)
        .expect("omission notice");
    assert!(notice.contains("v0.9.21"), "{notice}");
    assert!(
        notice.contains("pool_max_requests_per_connection"),
        "{notice}"
    );
    assert!(notice.contains("ferrum/pool-max-proxy"), "{notice}");
    assert!(notice.contains("ferrum-edge#7218"), "{notice}");

    let exported = render_file_yaml(&v21_desired).unwrap();
    assert!(
        !exported.contains("pool_max_requests_per_connection"),
        "{exported}"
    );

    // Against a real v0.9.21 gateway (which never emits the field), the adapted
    // desired proxy diffs cleanly as in sync (no permanent drift).
    assert!(compute_diff(&v21_desired, &without_field)
        .unwrap()
        .is_empty());

    // Against a live v0.9.20 gateway that still stores 1000, live state is NOT
    // silently masked: diff honestly surfaces 1000 -> null.
    let mispaired = compute_diff(&v21_desired, &with_field).unwrap();
    assert_eq!(mispaired.len(), 1);
    assert_eq!(mispaired[0].action, DiffAction::Modify);
    assert_eq!(mispaired[0].details[0].field, POOL_MAX_REQUESTS_FIELD);
    assert_eq!(mispaired[0].details[0].old_value, "1000");
    assert_eq!(mispaired[0].details[0].new_value, "null");

    // Without the field, v0.9.21 adaptation records no omitted fields and emits no notice.
    let mut v21_clean = without_field.clone();
    let none_omitted = adapt_gateway_for_edge_version(&mut v21_clean, EdgeVersion::new(0, 9, 21));
    assert!(none_omitted.is_empty());
    assert!(
        format_omitted_proxy_fields_notice(EdgeVersion::new(0, 9, 21), &none_omitted).is_none()
    );
}

#[test]
fn pipeline_load_and_assemble_applies_edge_version_per_environment() {
    let env_v20 = EnvConfig {
        edge_version: Some(EdgeVersion::new(0, 9, 20)),
        ..EnvConfig::default()
    };
    let env_v21 = EnvConfig {
        edge_version: Some(EdgeVersion::new(0, 9, 21)),
        ..EnvConfig::default()
    };
    let resolved_v20 = resolve_env(None, &env_v20, None).unwrap();
    let resolved_v21 = resolve_env(None, &env_v21, None).unwrap();
    let overlays = tempfile::tempdir().unwrap();

    let assembled_v20 = load_and_assemble(
        &fixture_root("with-field"),
        overlays.path(),
        &resolved_v20,
        &env_v20,
    )
    .unwrap();
    assert_eq!(
        assembled_v20.gateway.proxies[0].pool_max_requests_per_connection,
        Some(1000)
    );
    assert!(assembled_v20.omitted_proxy_fields.is_empty());

    let assembled_v21 = load_and_assemble(
        &fixture_root("with-field"),
        overlays.path(),
        &resolved_v21,
        &env_v21,
    )
    .unwrap();
    assert_eq!(
        assembled_v21.gateway.proxies[0].pool_max_requests_per_connection,
        None
    );
    assert_eq!(assembled_v21.omitted_proxy_fields.len(), 1);
    assert_eq!(assembled_v21.omitted_proxy_fields[0].id, "pool-max-proxy");
}

#[cfg(unix)]
mod validator_pairing_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Output};

    use gitforgeops::config::{GatewayConfig, MeshConfigSpec};
    use gitforgeops::validate::{run_mesh_validation, run_validation, VALIDATION_STANDIN_PREFIX};
    use tempfile::TempDir;

    use super::fixture_root;

    const MARKER: &str = "gitforgeops error [validator-pool-max-requests-per-connection]";
    const PREFIX: &str = "Validation error: Spec validation failed: unknown field \
                          `pool_max_requests_per_connection`, expected one of ";
    const PROXY_FIELDS_V21: &str = "`labels`, `id`, `name`, `namespace`, `hosts`, `listen_path`, \
                                    `backend_scheme`, `backend_host`, `backend_port`, \
                                    `pool_http3_connections_per_backend`, `created_at`, \
                                    `updated_at`";

    fn edge_v21_rejection() -> String {
        format!("{PREFIX}{PROXY_FIELDS_V21} at line 12 column 5")
    }

    struct PairingRepo {
        dir: TempDir,
        validator: PathBuf,
    }

    impl PairingRepo {
        fn new(variant: &str, validator_script: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let src = fixture_root(variant).join("ferrum/proxies/api.yaml");
            let dst = dir.path().join("resources/ferrum/proxies/api.yaml");
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(&src, &dst).unwrap();

            let validator = dir.path().join("ferrum-edge-stub");
            std::fs::write(&validator, validator_script).unwrap();
            std::fs::set_permissions(&validator, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir, validator }
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.dir.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }

        fn published(&self) -> PathBuf {
            self.dir.path().join("published.yaml")
        }

        fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
            let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
            command.args(args).current_dir(self.dir.path()).env_clear();
            for name in ["PATH", "HOME", "TMPDIR"] {
                if let Ok(value) = std::env::var(name) {
                    command.env(name, value);
                }
            }
            command
                .env("FERRUM_GATEWAY_MODE", "file")
                .env("FERRUM_EDGE_BINARY_PATH", &self.validator)
                .env("FERRUM_FILE_OUTPUT_PATH", self.published());
            for (name, value) in extra_env {
                command.env(name, value);
            }
            command.output().unwrap()
        }

        fn assert_remedy(&self, output: &str) {
            for expected in [
                MARKER,
                "pool_max_requests_per_connection",
                "ferrum-edge#7218",
                self.validator.to_str().unwrap(),
                "edge_version: v0.9.21",
                "FERRUM_EDGE_VERSION=v0.9.21",
                "clears the stored field on v0.9.20",
            ] {
                assert!(output.contains(expected), "missing {expected:?}: {output}");
            }
        }
    }

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    /// Stub validator modelling Edge v0.9.21 (`deny_unknown_fields` without
    /// `pool_max_requests_per_connection`).
    fn v21_stub_script(use_stdout: bool) -> String {
        let redirect = if use_stdout { "" } else { " >&2" };
        let rejection = edge_v21_rejection();
        format!(
            "#!/bin/sh\n\
             set -eu\n\
             cp \"$7\" \"$(dirname \"$0\")/captured.yaml\"\n\
             if grep -q 'pool_max_requests_per_connection' \"$7\"; then\n\
               cat <<'EDGE_DIAGNOSTIC'{redirect}\n\
             {rejection}\n\
             EDGE_DIAGNOSTIC\n\
               exit 1\n\
             fi\n\
             echo 'Validation passed'\n\
             exit 0\n"
        )
    }

    /// Stub validator modelling Edge v0.9.20 (accepts `pool_max_requests_per_connection`
    /// and verifies stand-ins still reach it intact).
    const V20_STUB_SCRIPT: &str = "#!/bin/sh\n\
set -eu\n\
cp \"$7\" \"$(dirname \"$0\")/captured.yaml\"\n\
echo 'Validation passed'\n\
exit 0\n";

    #[test]
    fn v0920_pairing_emits_field_and_preserves_validation_standins() {
        let repo = PairingRepo::new("with-field", V20_STUB_SCRIPT);
        // Add a brokered consumer so we prove v0.9.20 stand-ins stay intact alongside
        // `pool_max_requests_per_connection`.
        repo.write(
            "resources/ferrum/consumers/app.yaml",
            "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials:\n    jwt:\n      - key: app-issuer\n        secret: '${gh-env-secret:alloc=generate}'\n",
        );

        for env in [&[][..], &[("FERRUM_EDGE_VERSION", "v0.9.20")][..]] {
            let output = repo.run(&["validate", "--format", "json"], env);
            assert!(output.status.success(), "{env:?}: {}", stderr(&output));
            let captured = std::fs::read_to_string(repo.dir.path().join("captured.yaml")).unwrap();
            assert!(
                captured.contains("pool_max_requests_per_connection: 1000"),
                "{captured}"
            );
            assert!(
                captured.contains(VALIDATION_STANDIN_PREFIX),
                "v0.9.20 validation stand-in must remain intact: {captured}"
            );

            let exported = repo.run(&["export"], env);
            assert!(exported.status.success(), "{}", stderr(&exported));
            assert!(
                stdout(&exported).contains("pool_max_requests_per_connection: 1000"),
                "{}",
                stdout(&exported)
            );
            assert!(
                !stderr(&exported).contains("omitted removed no-op Proxy field"),
                "v0.9.20 must emit no omission notice: {}",
                stderr(&exported)
            );
        }
    }

    #[test]
    fn v0921_pairing_qualifies_both_fixtures_across_validate_export_plan_review_and_apply() {
        for variant in ["with-field", "without-field"] {
            let repo = PairingRepo::new(variant, &v21_stub_script(false));
            let env = &[("FERRUM_EDGE_VERSION", "v0.9.21")];

            let val = repo.run(&["validate", "--format", "json"], env);
            assert!(val.status.success(), "{variant}: {}", stderr(&val));
            let report: serde_json::Value = serde_json::from_slice(&val.stdout).unwrap();
            assert_eq!(report["success"], true);
            let captured = std::fs::read_to_string(repo.dir.path().join("captured.yaml")).unwrap();
            assert!(
                !captured.contains("pool_max_requests_per_connection"),
                "{variant}: {captured}"
            );

            let exp = repo.run(&["export"], env);
            assert!(exp.status.success(), "{variant}: {}", stderr(&exp));
            let exported_yaml = stdout(&exp);
            assert!(
                !exported_yaml.contains("pool_max_requests_per_connection"),
                "{variant}: {exported_yaml}"
            );
            let exp_err = stderr(&exp);
            if variant == "with-field" {
                assert!(
                    exp_err.contains("omitted removed no-op Proxy field"),
                    "{exp_err}"
                );
            } else {
                assert!(
                    !exp_err.contains("omitted removed no-op Proxy field"),
                    "{exp_err}"
                );
            }
            // stdout remains valid YAML with no notice interleaved.
            let _: GatewayConfig = gitforgeops::yaml::from_str(&exported_yaml).unwrap();

            let plan = repo.run(&["plan", "--format", "json"], env);
            assert!(plan.status.success(), "{variant}: {}", stderr(&plan));
            let plan_json: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
            assert_eq!(plan_json["apply_blocked"], false);

            let review = repo.run(&["review", "--fail-on-blockers"], env);
            assert!(review.status.success(), "{variant}: {}", stderr(&review));
            assert!(stdout(&review).contains("Validation: PASSED"));

            let apply = repo.run(&["apply", "--auto-approve"], env);
            assert!(apply.status.success(), "{variant}: {}", stderr(&apply));
            let published = std::fs::read_to_string(repo.published()).unwrap();
            assert!(
                !published.contains("pool_max_requests_per_connection"),
                "{variant}: {published}"
            );
        }
    }

    #[test]
    fn v0921_pairing_preserves_validation_standins() {
        let repo = PairingRepo::new("with-field", &v21_stub_script(false));
        repo.write(
            "resources/ferrum/consumers/app.yaml",
            "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials:\n    jwt:\n      - key: app-issuer\n        secret: '${gh-env-secret:alloc=generate}'\n",
        );

        let val = repo.run(
            &["validate", "--format", "json"],
            &[("FERRUM_EDGE_VERSION", "v0.9.21")],
        );
        assert!(val.status.success(), "{}", stderr(&val));
        let captured = std::fs::read_to_string(repo.dir.path().join("captured.yaml")).unwrap();
        assert!(
            !captured.contains("pool_max_requests_per_connection"),
            "{captured}"
        );
        assert!(
            captured.contains(VALIDATION_STANDIN_PREFIX),
            "v0.9.21 validation stand-in must remain intact: {captured}"
        );
    }

    #[test]
    fn shared_repo_with_multi_env_config_serves_v0920_and_v0921_simultaneously() {
        let repo = PairingRepo::new("with-field", &v21_stub_script(false));
        repo.write(
            ".gitforgeops/config.yaml",
            "version: 1\ndefault_environment: prod\nenvironments:\n  prod:\n    edge_version: v0.9.20\n  staging:\n    edge_version: v0.9.21\n",
        );

        let prod_export = repo.run(&["--env", "prod", "export"], &[]);
        assert!(prod_export.status.success(), "{}", stderr(&prod_export));
        assert!(stdout(&prod_export).contains("pool_max_requests_per_connection: 1000"));

        let staging_export = repo.run(&["--env", "staging", "export"], &[]);
        assert!(
            staging_export.status.success(),
            "{}",
            stderr(&staging_export)
        );
        assert!(!stdout(&staging_export).contains("pool_max_requests_per_connection"));
        assert!(stderr(&staging_export).contains("ferrum/pool-max-proxy"));

        let staging_validate = repo.run(&["--env", "staging", "validate"], &[]);
        assert!(
            staging_validate.status.success(),
            "{}",
            stderr(&staging_validate)
        );
    }

    #[test]
    fn incompatible_document_on_v0921_validator_reports_actionable_remedy_before_apply() {
        for use_stdout in [false, true] {
            let repo = PairingRepo::new("with-field", &v21_stub_script(use_stdout));
            let diagnostic = edge_v21_rejection();

            for format in ["text", "json", "github", "github-annotations"] {
                let output = repo.run(&["validate", "--format", format], &[]);
                assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
                let rendered = stdout(&output);
                repo.assert_remedy(&rendered);
                assert!(rendered.contains(&diagnostic), "{format}: {rendered}");
                match format {
                    "json" => {
                        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
                        assert_eq!(value["success"], false);
                        assert_eq!(value["exit_code"], 1);
                        repo.assert_remedy(value["stderr"].as_str().unwrap());
                    }
                    "text" => assert!(rendered.contains("Validation failed.")),
                    _ => assert!(rendered.contains(&format!("::error ::{MARKER}"))),
                }
            }

            for format in ["text", "json"] {
                let output = repo.run(&["plan", "--format", format], &[]);
                assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
                let detail = if format == "json" {
                    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(value["apply_blocked"], true);
                    stderr(&output)
                } else {
                    stdout(&output)
                };
                repo.assert_remedy(&detail);
                assert!(detail.contains(&diagnostic), "{detail}");
                assert!(detail.contains("gateway: FAILED"), "{detail}");
            }

            for (args, code) in [
                (&["review"][..], 0),
                (&["review", "--fail-on-blockers"][..], 1),
            ] {
                let output = repo.run(args, &[]);
                assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
                let rendered = stdout(&output);
                repo.assert_remedy(&rendered);
                assert!(rendered.contains("Validation: FAILED"), "{rendered}");
                assert!(rendered.contains("Apply is blocked"), "{rendered}");
            }

            std::fs::write(repo.published(), "existing gateway document\n").unwrap();
            let output = repo.run(&["apply", "--auto-approve"], &[]);
            assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
            repo.assert_remedy(&stderr(&output));
            assert!(stderr(&output).contains(&diagnostic));
            assert_eq!(
                std::fs::read_to_string(repo.published()).unwrap(),
                "existing gateway document\n"
            );
            assert!(!repo.dir.path().join(".state/default.json").exists());
        }
    }

    #[test]
    fn pool_max_rejection_recognized_in_json_log_and_multi_namespace_and_preserves_scrubbing() {
        let json_log = format!(
            "{{\"timestamp\":\"2026-11-22T01:00:00Z\",\"level\":\"ERROR\",\
             \"fields\":{{\"message\":\"{PREFIX}{PROXY_FIELDS_V21}\"}},\"target\":\"ferrum_edge\"}}"
        );
        let script = format!("#!/bin/sh\necho '{json_log}' >&2\nexit 1\n");
        let repo = PairingRepo::new("with-field", &script);
        let result =
            run_validation(&GatewayConfig::default(), repo.validator.to_str().unwrap()).unwrap();
        assert!(!result.success);
        repo.assert_remedy(&result.stderr);
        assert!(result.stderr.contains(&json_log));

        // Multi-namespace bare form behind `[namespace "..."] ` annotation.
        let bare = edge_v21_rejection();
        let multi_script = format!("#!/bin/sh\necho '{bare}' >&2\nexit 1\n");
        let multi_repo = PairingRepo::new("with-field", &multi_script);
        let multi_config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "proxies": [
                { "id": "a", "namespace": "ferrum" },
                { "id": "b", "namespace": "other" },
            ],
        }))
        .unwrap();
        let multi_result =
            run_validation(&multi_config, multi_repo.validator.to_str().unwrap()).unwrap();
        assert!(!multi_result.success);
        multi_repo.assert_remedy(&multi_result.stderr);

        // Secret scrubbing and withholding are preserved.
        for secret in ["synthetic-secret-for-pool-max-scrub", "tiny"] {
            let scrub_script =
                format!("#!/bin/sh\nprintf '%s\\ncredential: {secret}\\n' '{bare}' >&2\nexit 1\n");
            let scrub_repo = PairingRepo::new("with-field", &scrub_script);
            let config: GatewayConfig = serde_json::from_value(serde_json::json!({
                "consumers": [{
                    "id": "c1",
                    "username": "c1",
                    "namespace": "ferrum",
                    "credentials": {"keyauth": [{"key": secret}]}
                }]
            }))
            .unwrap();
            let result = run_validation(&config, scrub_repo.validator.to_str().unwrap()).unwrap();
            assert!(!result.success);
            assert!(!result.stderr.contains(secret));
            assert!(!result.stdout.contains(secret));
            if secret == "tiny" {
                assert!(result.stderr.contains("withheld"), "{}", result.stderr);
            } else {
                scrub_repo.assert_remedy(&result.stderr);
                assert!(result.stderr.contains("[REDACTED]"));
            }
        }
    }

    #[test]
    fn unrelated_failures_and_mesh_never_get_pool_max_remedy() {
        let valid_rejection = edge_v21_rejection();
        for diagnostic in [
            valid_rejection.replace("pool_max_requests_per_connection", "pool_max_typo"),
            format!("{PREFIX}{PROXY_FIELDS_V21}, `pool_max_requests_per_connection`"),
            // Non-Proxy resource signature (Consumer) must not match.
            format!("{PREFIX}`id`, `username`, `namespace`, `credentials`, `acl_groups`"),
            format!("echoed config: {valid_rejection}"),
        ] {
            let script = format!("#!/bin/sh\ncat <<'EOF' >&2\n{diagnostic}\nEOF\nexit 1\n");
            let repo = PairingRepo::new("with-field", &script);
            let result =
                run_validation(&GatewayConfig::default(), repo.validator.to_str().unwrap())
                    .unwrap();
            assert!(!result.success);
            assert_eq!(result.stderr, format!("{diagnostic}\n"));
            assert!(!result.stderr.contains(MARKER));
        }

        // Mesh validation never rewrites diagnostics.
        let mesh_script = format!("#!/bin/sh\necho '{valid_rejection}' >&2\nexit 1\n");
        let repo = PairingRepo::new("with-field", &mesh_script);
        let mesh_result =
            run_mesh_validation(&MeshConfigSpec::default(), repo.validator.to_str().unwrap())
                .unwrap();
        assert!(!mesh_result.success);
        assert!(!mesh_result.stderr.contains(MARKER));
    }
}
