//! Compatibility classification and command verdicts against a stub Edge
//! validator. These tests require no gateway, GitHub credentials or network.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use gitforgeops::config::{GatewayConfig, MeshConfigSpec};
use gitforgeops::validate::{run_mesh_validation, run_validation};
use tempfile::TempDir;

const FIXTURE: &str = include_str!("../../.github/fixtures/validator-resource-labels.yaml");
const MARKER: &str = "gitforgeops error [validator-resource-labels]";
const PREFIX: &str = "Validation error: Spec validation failed: unknown field `labels`, \
                      expected one of ";
// The Consumer diagnostic is the complete pre-label Edge serde field list.
// The other lists exercise each resource signature; optional fields vary by
// Edge build and must not make recognition depend on an exact version number.
const RESOURCE_FIELDS: [&str; 4] = [
    "`id`, `name`, `namespace`, `hosts`, `listen_path`, `backend_scheme`, \
     `backend_host`, `backend_port`, `created_at`, `updated_at`",
    "`id`, `username`, `namespace`, `custom_id`, `credentials`, `acl_groups`, \
     `created_at`, `updated_at`",
    "`id`, `name`, `namespace`, `targets`, `algorithm`, `hash_on`, `health_checks`, \
     `service_discovery`, `created_at`, `updated_at`",
    "`id`, `plugin_name`, `namespace`, `config`, `scope`, `proxy_id`, `enabled`, \
     `priority_override`, `trigger`, `api_spec_id`, `created_at`, `updated_at`",
];

fn edge_error(fields: &str) -> String {
    format!("{PREFIX}{fields} at line 4 column 5")
}

struct Repo {
    dir: TempDir,
    validator: PathBuf,
}

impl Repo {
    fn new(diagnostic: &str, exit_code: i32, use_stdout: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let document: serde_json::Value = serde_yaml::from_str(FIXTURE).unwrap();
        for (section, folder, kind) in [
            ("proxies", "proxies", "Proxy"),
            ("consumers", "consumers", "Consumer"),
            ("upstreams", "upstreams", "Upstream"),
            ("plugin_configs", "plugins", "PluginConfig"),
        ] {
            let folder = dir.path().join("resources/ferrum").join(folder);
            std::fs::create_dir_all(&folder).unwrap();
            let mut spec = document[section][0].clone();
            // The CLI must inject attribution even without explicit labels.
            spec.as_object_mut().unwrap().remove("labels");
            let resource = serde_json::json!({"kind": kind, "spec": spec});
            std::fs::write(
                folder.join("labeled.yaml"),
                serde_yaml::to_string(&resource).unwrap(),
            )
            .unwrap();
        }
        let validator = dir.path().join("ferrum-edge-stub");
        let redirect = if use_stdout { "" } else { " >&2" };
        std::fs::write(
            &validator,
            format!(
                "#!/bin/sh\ncp \"$7\" \"$(dirname \"$0\")/captured.yaml\"\n\
                 cat <<'EDGE_DIAGNOSTIC'{redirect}\n{diagnostic}\nEDGE_DIAGNOSTIC\n\
                 exit {exit_code}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&validator, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir, validator }
    }

    fn run(&self, args: &[&str]) -> Output {
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
            .env("FERRUM_FILE_OUTPUT_PATH", self.published())
            .output()
            .unwrap()
    }

    fn published(&self) -> PathBuf {
        self.dir.path().join("published.yaml")
    }

    fn assert_remedy(&self, output: &str) {
        for expected in [
            MARKER,
            "Ferrum Edge resource-labels support",
            self.validator.to_str().unwrap(),
            "Upgrade the gateway and the `ferrum-edge validate` binary",
            "ferrum-edge#5483",
            "pin Git Forge Ops before #218",
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

#[test]
fn validate_reports_each_resource_rejection_in_every_format() {
    for fields in RESOURCE_FIELDS {
        let diagnostic = edge_error(fields);
        let repo = Repo::new(&diagnostic, 1, false);
        for format in ["text", "json", "github", "github-annotations"] {
            let output = repo.run(&["validate", "--format", format]);
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
    }
}

#[test]
fn exact_edge_diagnostic_without_location_is_recognized_on_either_stream() {
    let diagnostic = format!("{PREFIX}{}", RESOURCE_FIELDS[1]);
    for use_stdout in [false, true] {
        let repo = Repo::new(&diagnostic, 1, use_stdout);
        let binary = repo.validator.to_str().unwrap();
        let result = run_validation(&GatewayConfig::default(), binary).unwrap();
        assert!(!result.success);
        repo.assert_remedy(&result.stderr);
        assert!(result.stderr.contains(&diagnostic));
        if use_stdout {
            assert_eq!(result.stdout, format!("{diagnostic}\n"));
        }
    }
}

#[test]
fn labels_rejection_blocks_plan_and_review_and_preserves_file_apply_output() {
    let diagnostic = edge_error(RESOURCE_FIELDS[1]);
    // Edge builds may emit their error on either stream. Both must reach
    // plan's stderr-only failure detail and retain the original diagnostic.
    for use_stdout in [false, true] {
        let repo = Repo::new(&diagnostic, 1, use_stdout);
        for format in ["text", "json"] {
            let output = repo.run(&["plan", "--format", format]);
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
            assert!(detail.contains("validation (1)"), "{detail}");
        }
        for (args, code) in [
            (vec!["review"], 0),
            (vec!["review", "--fail-on-blockers"], 1),
        ] {
            let output = repo.run(&args);
            assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
            let rendered = stdout(&output);
            repo.assert_remedy(&rendered);
            assert!(rendered.contains("Validation: FAILED"), "{rendered}");
            assert!(rendered.contains("Apply is blocked"), "{rendered}");
            assert!(!rendered.contains("Validation: PASSED"));
        }
        std::fs::write(repo.published(), "existing gateway document\n").unwrap();
        let output = repo.run(&["apply", "--auto-approve"]);
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
fn unrelated_or_non_schema_failures_never_get_the_labels_remedy() {
    let labeled = edge_error(RESOURCE_FIELDS[0]);
    for diagnostic in [
        labeled.replace("unknown field `labels`", "unknown field `label`"),
        labeled.replace("unknown field `labels`", "unknown field `listen_path_typo`"),
        labeled.replace("Validation error: Spec validation failed: ", ""),
        format!("echoed configuration: {labeled}"),
        edge_error("`version`, `proxies`, `consumers`, `upstreams`, `plugin_configs`"),
        edge_error("`id`, `namespace`, `selector`, `services`, `workloads`"),
        edge_error("`id`, `namespace`, `config`, `headers`"),
        format!("{labeled}\nlabels: {{provisioned-by: example}}")
            .replace("`namespace`", "`nested_namespace`"),
        format!("{PREFIX}{}, `labels`", RESOURCE_FIELDS[0]),
        format!("{PREFIX}{}, malformed tail", RESOURCE_FIELDS[0]),
        "Validation error: labels keys must be nonblank".to_string(),
    ] {
        let repo = Repo::new(&diagnostic, 1, false);
        let binary = repo.validator.to_str().unwrap();
        let result = run_validation(&GatewayConfig::default(), binary).unwrap();
        assert!(!result.success);
        assert_eq!(result.stderr, format!("{diagnostic}\n"));
        assert!(!result.stderr.contains(MARKER));
    }
    for exit_code in [0, 2] {
        let repo = Repo::new(&labeled, exit_code, false);
        let result = run_validation(&GatewayConfig::default(), repo.validator.to_str().unwrap());
        if exit_code == 0 {
            let result = result.unwrap();
            assert!(result.success);
            assert_eq!(result.stderr, format!("{labeled}\n"));
        } else {
            let error = result.unwrap_err();
            assert!(matches!(
                error,
                gitforgeops::error::Error::ValidateProcess { .. }
            ));
            assert!(!error.to_string().contains(MARKER));
        }
    }
    let repo = Repo::new(&labeled, 1, false);
    let binary = repo.validator.to_str().unwrap();
    let result = run_mesh_validation(&MeshConfigSpec::default(), binary).unwrap();
    assert!(!result.success);
    assert_eq!(result.stderr, format!("{labeled}\n"));
}

#[test]
fn compatibility_mapping_preserves_secret_scrubbing_and_withholding() {
    let diagnostic = edge_error(RESOURCE_FIELDS[1]);
    for secret in ["synthetic-secret-for-scrubbing", "tiny"] {
        let repo = Repo::new(&format!("{diagnostic}\ncredential: {secret}"), 1, false);
        let mut config: GatewayConfig = serde_yaml::from_str(FIXTURE).unwrap();
        config.consumers[0]
            .credentials
            .insert("keyauth".to_string(), serde_json::json!([{"key": secret}]));
        let result = run_validation(&config, repo.validator.to_str().unwrap()).unwrap();
        assert!(!result.success);
        assert!(!result.stderr.contains(secret));
        assert!(!result.stdout.contains(secret));
        if secret == "tiny" {
            assert!(result.stderr.contains("withheld"), "{}", result.stderr);
        } else {
            repo.assert_remedy(&result.stderr);
            assert!(result.stderr.contains(&diagnostic));
            assert!(result.stderr.contains("[REDACTED]"));
        }
    }
}

#[test]
fn accepting_validator_receives_labels_for_all_four_resource_kinds() {
    let repo = Repo::new("Validation passed", 0, true);
    let output = repo.run(&["validate", "--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["success"], true);
    assert!(!stdout(&output).contains(MARKER));
    let captured = std::fs::read_to_string(repo.dir.path().join("captured.yaml")).unwrap();
    for document in [FIXTURE, captured.as_str()] {
        let value: serde_json::Value = serde_yaml::from_str(document).unwrap();
        for section in ["proxies", "consumers", "upstreams", "plugin_configs"] {
            assert_eq!(value[section].as_array().unwrap().len(), 1);
            assert_eq!(value[section][0]["namespace"], "ferrum");
            assert_eq!(
                value[section][0]["labels"]["provisioned-by"],
                "ferrum-edge-git-forge-ops"
            );
        }
    }
}
