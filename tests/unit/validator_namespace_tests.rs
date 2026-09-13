//! Validator child namespace contracts (#222). The real-binary cases run in
//! hosted Rust CI and skip when GITFORGEOPS_TEST_EDGE_BINARY is absent.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gitforgeops::config::GatewayConfig;
use gitforgeops::validate::{
    format_result, run_validation, run_validation_with_report, OutputFormat,
};
use tempfile::TempDir;

const STUB: &str = r#"#!/bin/sh
set -eu
fail() { echo 'error: validator child contract violated' >&2; exit 1; }
[ "$#" = 7 ] && [ "$1" = validate ] && [ "$2" = -m ] || fail
[ "$4" = -s ] && [ "$6" = -c ] && [ ! -s "$5" ] && [ -f "$7" ] || fail
root=$(dirname "$0")
printf '%s:%s\n' "$3" "${FERRUM_NAMESPACE-unset}" >> "$root/calls"
if [ "$3" = mesh ]; then
    [ "${FERRUM_NAMESPACE-unset}" = unset ] || fail
    [ "${FERRUM_MESH_ALLOW_NO_CA-unset}" = true ] || fail
    echo 'mesh checked'
    exit 0
fi
[ "$3" = file ] && [ -n "${FERRUM_NAMESPACE-}" ] || fail
if env | grep '^FERRUM_' | grep -qv '^FERRUM_NAMESPACE='; then fail; fi
# Every pass must receive the full document, not a reassembled partial graph.
while IFS= read -r namespace || [ -n "$namespace" ]; do
    grep -Fq "namespace: $namespace" "$7" || fail
done < "$root/expected-namespaces"
printf 'checked %s\n' "$FERRUM_NAMESPACE"
if [ -f "$root/invalid-namespace" ] &&
   [ "$FERRUM_NAMESPACE" = "$(cat "$root/invalid-namespace")" ]; then
    grep -q 'id: broken' "$7" || fail
    echo 'error: duplicate listen_path /contract' >&2
    exit 1
fi
"#;

struct Repo {
    dir: TempDir,
    validator: PathBuf,
}

impl Repo {
    fn new(namespaces: &[&str], invalid: Option<&str>, binary: Option<&Path>) -> Self {
        let dir = tempfile::tempdir().expect("test repository");
        std::fs::create_dir_all(dir.path().join("resources")).unwrap();
        let stub = dir.path().join("validator");
        std::fs::write(&stub, STUB).unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700)).unwrap();
        let repo = Self {
            dir,
            validator: binary.unwrap_or(&stub).to_path_buf(),
        };
        for namespace in namespaces {
            repo.proxy(namespace, "app");
        }
        if let Some(namespace) = invalid {
            // Cross-resource uniqueness runs AFTER Edge's namespace filter.
            // An invalid sibling must not disappear behind a valid first slice.
            repo.proxy(namespace, "broken");
            repo.write("invalid-namespace", namespace);
        }
        repo.write("expected-namespaces", &namespaces.join("\n"));
        // Auto-discovery must never load this unrelated settings file.
        repo.write(
            "ferrum.conf",
            "FERRUM_MODE=database\nFERRUM_DB_PORT=invalid\n",
        );
        repo
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.dir.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn proxy(&self, namespace: &str, id: &str) {
        self.write(
            &format!("resources/{namespace}/proxies/{id}.yaml"),
            &format!(
                r#"kind: Proxy
spec:
  id: {id}
  listen_path: /contract
  backend_scheme: http
  backend_host: 127.0.0.1
  backend_port: 9101
"#
            ),
        );
    }

    fn published(&self) -> PathBuf {
        self.dir.path().join("published/resources.yaml")
    }

    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        // Reset only this test's invocation log, never process-wide env vars.
        self.write("calls", "");
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("FERRUM_GATEWAY_MODE", "file")
            .env("FERRUM_EDGE_BINARY_PATH", &self.validator)
            .env("FERRUM_FILE_OUTPUT_PATH", self.published())
            .env(
                "FERRUM_MESH_FILE_OUTPUT_PATH",
                self.dir.path().join("mesh.yaml"),
            )
            .env("FERRUM_MODE", "database")
            .env("FERRUM_CONF_PATH", "must-not-load.conf")
            .env("FERRUM_NAMESPACE_FILE", "must-not-load.namespace")
            .env("FERRUM_MESH_ALLOW_NO_CA", "false");
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command.output().expect("gitforgeops invocation")
    }

    fn assert_calls(&self, namespaces: &[&str], mesh: bool) {
        let mut sorted = namespaces.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.is_empty() {
            sorted.push("ferrum");
        }
        let mut expected = sorted
            .iter()
            .map(|namespace| format!("file:{namespace}\n"))
            .collect::<String>();
        if mesh {
            expected.push_str("mesh:unset\n");
        }
        assert_eq!(
            std::fs::read_to_string(self.dir.path().join("calls")).unwrap(),
            expected
        );
    }
}

fn output_text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_command_contract(namespaces: &[&str], invalid: Option<&str>, binary: Option<&Path>) {
    for args in [
        vec!["validate", "--format", "json"],
        vec!["plan", "--format", "json"],
        vec!["review", "--fail-on-blockers"],
        vec!["apply", "--auto-approve"],
    ] {
        let repo = Repo::new(namespaces, invalid, binary);
        let output = repo.run(&args, &[]);
        let text = output_text(&output);
        assert_eq!(
            output.status.code(),
            Some(i32::from(invalid.is_some())),
            "{args:?}: {text}"
        );
        if invalid.is_some() {
            assert!(text.contains("duplicate listen_path"), "{args:?}: {text}");
        }
        match args[0] {
            "validate" | "plan" => {
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                let (field, expected) = if args[0] == "validate" {
                    ("success", invalid.is_none())
                } else {
                    ("apply_blocked", invalid.is_some())
                };
                assert_eq!(report[field], expected, "{text}");
                if args[0] == "validate" && invalid.is_none() && binary.is_some() {
                    let stdout = report["stdout"].as_str().unwrap();
                    for namespace in namespaces {
                        assert!(
                            stdout.contains(&format!("Namespace: {namespace}")),
                            "{text}"
                        );
                    }
                    assert_eq!(
                        stdout.matches("Proxies: 1").count(),
                        namespaces.len(),
                        "{text}"
                    );
                }
            }
            "review" => {
                let status = if invalid.is_some() {
                    "FAILED"
                } else {
                    "PASSED"
                };
                assert!(text.contains(&format!("Validation: {status}")), "{text}");
            }
            "apply" => {
                assert_eq!(repo.published().exists(), invalid.is_none(), "{text}");
                if invalid.is_none() {
                    let yaml = std::fs::read_to_string(repo.published()).unwrap();
                    let published: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();
                    assert_eq!(published.proxies.len(), namespaces.len());
                }
            }
            _ => unreachable!(),
        }
        if binary.is_none() {
            repo.assert_calls(namespaces, false);
        }
    }
}

#[test]
fn shared_commands_validate_every_document_namespace() {
    for namespaces in [
        vec!["ferrum-audit-main"],
        vec!["zeta", "ferrum"],
        vec!["zeta", "alpha"],
    ] {
        assert_command_contract(&namespaces, None, None);
        for namespace in &namespaces {
            assert_command_contract(&namespaces, Some(namespace), None);
        }
    }
}

#[test]
fn all_validate_formats_keep_ordered_namespace_diagnostics() {
    for format in ["text", "json", "github", "github-annotations"] {
        for invalid in [None, Some("alpha"), Some("zeta")] {
            let repo = Repo::new(&["zeta", "alpha"], invalid, None);
            let output = repo.run(&["validate", "--format", format], &[]);
            assert_eq!(output.status.success(), invalid.is_none(), "{output:?}");
            repo.assert_calls(&["alpha", "zeta"], false);
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            if format == "json" {
                let report: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(report["success"], invalid.is_none());
                assert_eq!(report["exit_code"], i32::from(invalid.is_some()));
                text = format!("{}{}", report["stdout"].as_str().unwrap(), report["stderr"]);
            }
            if matches!(format, "text" | "json") {
                assert!(text.find("checked alpha").unwrap() < text.find("checked zeta").unwrap());
            } else if let Some(namespace) = invalid {
                assert!(
                    text.contains(&format!(
                        "::error ::[namespace \"{namespace}\"] error: duplicate listen_path"
                    )),
                    "{text}"
                );
            } else {
                assert!(!text.contains("::error"), "{text}");
            }
        }
    }
}

#[test]
fn selected_namespace_overrides_ambient_child_context_and_keeps_parent_typo_gate() {
    let repo = Repo::new(&["alpha", "zeta"], None, None);
    repo.write("expected-namespaces", "alpha\n");
    let output = repo.run(&["validate"], &[("FERRUM_NAMESPACE", "alpha")]);
    assert!(output.status.success(), "{}", output_text(&output));
    repo.assert_calls(&["alpha"], false);

    repo.write("expected-namespaces", "");
    for args in [
        vec!["validate", "--format", "json"],
        vec!["plan", "--format", "json"],
    ] {
        let output = repo.run(&args, &[("FERRUM_NAMESPACE", "typo")]);
        assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["empty_namespace_filter"], "error");
        repo.assert_calls(&[], false);
    }

    repo.write(
        ".gitforgeops/config.yaml",
        r#"version: 1
default_environment: test
environments:
  test:
    namespace_filter: zeta
"#,
    );
    repo.write("expected-namespaces", "zeta\n");
    let output = repo.run(&["validate"], &[("FERRUM_NAMESPACE", "alpha")]);
    assert!(output.status.success(), "{}", output_text(&output));
    repo.assert_calls(&["zeta"], false);
}

#[test]
fn multiple_gateway_namespaces_leave_mesh_second_pass_intact() {
    let repo = Repo::new(&["zeta", "alpha"], None, None);
    repo.write(
        "resources/alpha/mesh/policy.yaml",
        "kind: MeshConfig\nspec:\n  istio_root_namespace: istio-system\n",
    );
    let output = repo.run(&["validate", "--format", "json"], &[]);
    assert!(output.status.success(), "{}", output_text(&output));
    repo.assert_calls(&["alpha", "zeta"], true);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["success"], true);
    assert_eq!(report["gateway"]["success"], true);
    assert_eq!(report["mesh"]["stdout"], "mesh checked\n");
}

#[test]
fn every_resource_kind_supplies_its_effective_namespace_to_both_runner_apis() {
    let repo = Repo::new(&[], None, None);
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "proxies": [{"id": "p", "namespace": "proxy-ns"}],
        "consumers": [{"id": "c", "username": "c", "namespace": "consumer-ns"}],
        "upstreams": [{"id": "u", "namespace": "upstream-ns", "targets": []}],
        "plugin_configs": [{
            "id": "pc", "plugin_name": "key_auth", "namespace": "plugin-ns", "scope": "global"
        }]
    }))
    .unwrap();
    let namespaces = ["proxy-ns", "consumer-ns", "upstream-ns", "plugin-ns"];
    repo.write("expected-namespaces", &namespaces.join("\n"));
    for with_report in [false, true] {
        repo.write("calls", "");
        let binary = repo.validator.to_str().unwrap();
        let result = if with_report {
            run_validation_with_report(&config, binary, &Default::default())
        } else {
            run_validation(&config, binary)
        }
        .unwrap();
        assert!(result.success, "{result:?}");
        repo.assert_calls(&namespaces, false);
    }
}

#[test]
fn api_apply_rejects_an_invalid_sibling_namespace_at_the_shared_validation_gate() {
    let repo = Repo::new(&["ferrum", "zeta"], Some("zeta"), None);
    let output = repo.run(
        &["apply", "--auto-approve"],
        &[("FERRUM_GATEWAY_MODE", "api")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output_text(&output).contains("Refusing to apply because validation failed"));
    repo.assert_calls(&["ferrum", "zeta"], false);
    assert!(!repo.published().exists());
}

#[test]
fn namespace_labels_are_scrubbed_along_with_child_diagnostics() {
    let repo = Repo::new(&[], None, None);
    let secret = "synthetic-namespace-secret-123456789";
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "consumers": [
            {"id": "public", "username": "public", "namespace": "alpha"},
            {
                "id": "private", "username": "private", "namespace": secret,
                "credentials": {"keyauth": [{"key": secret}]}
            }
        ]
    }))
    .unwrap();
    let result = run_validation(&config, repo.validator.to_str().unwrap()).unwrap();
    assert!(result.success, "{result:?}");
    assert!(result.stdout.contains("[REDACTED]"), "{result:?}");
    assert!(!result.stdout.contains(secret), "{result:?}");
    assert!(!result.stderr.contains(secret), "{result:?}");
    repo.assert_calls(&["alpha", secret], false);
}

#[test]
fn namespace_labels_do_not_change_annotation_severity() {
    let repo = Repo::new(&[], None, None);
    repo.write(
        "validator",
        "#!/bin/sh\necho accepted\necho 'warning: check this route' >&2\n",
    );
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "proxies": [
            {"id": "p", "namespace": "errors"},
            {"id": "p", "namespace": "tenant \"] errors"}
        ]
    }))
    .unwrap();
    let result = run_validation(&config, repo.validator.to_str().unwrap()).unwrap();
    assert!(result.success, "{result:?}");
    let annotations = format_result(&result, OutputFormat::GithubAnnotations);
    assert!(!annotations.contains("::error"), "{annotations}");
    assert_eq!(annotations.matches("::warning").count(), 2, "{annotations}");
    assert!(
        annotations.contains("[namespace \"errors\"]"),
        "{annotations}"
    );
}

fn real_validator() -> Option<PathBuf> {
    let Some(binary) = std::env::var_os("GITFORGEOPS_TEST_EDGE_BINARY") else {
        eprintln!("skipping real Edge contract: GITFORGEOPS_TEST_EDGE_BINARY is unset");
        return None;
    };
    let binary = PathBuf::from(binary);
    assert!(
        binary.is_file(),
        "configured Edge validator must exist: {binary:?}"
    );
    Some(binary)
}

#[test]
fn real_edge_valid_custom_namespace_on_all_shared_commands() {
    let Some(binary) = real_validator() else {
        return;
    };
    assert_command_contract(&["ferrum-audit-main"], None, Some(&binary));
}

#[test]
fn real_edge_invalid_custom_namespace_on_all_shared_commands() {
    let Some(binary) = real_validator() else {
        return;
    };
    assert_command_contract(
        &["ferrum-audit-main"],
        Some("ferrum-audit-main"),
        Some(&binary),
    );
}

#[test]
fn real_edge_multiple_namespaces_including_ferrum() {
    let Some(binary) = real_validator() else {
        return;
    };
    for invalid in [None, Some("ferrum"), Some("zeta")] {
        assert_command_contract(&["zeta", "ferrum"], invalid, Some(&binary));
    }
}

#[test]
fn real_edge_multiple_namespaces_excluding_ferrum() {
    let Some(binary) = real_validator() else {
        return;
    };
    for invalid in [None, Some("alpha"), Some("zeta")] {
        assert_command_contract(&["zeta", "alpha"], invalid, Some(&binary));
    }
}
