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
                    let published: GatewayConfig = gitforgeops::yaml::from_str(&yaml).unwrap();
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
fn overlay_selection_rejects_paths_before_loading_and_preserves_logical_environments() {
    let repo = Repo::new(&["alpha"], None, None);
    // These invalid selections all resolve to existing directories without the guard.
    std::fs::create_dir(repo.dir.path().join("overlays")).unwrap();
    for name in [".", "..", "../resources", repo.dir.path().to_str().unwrap()] {
        for source in ["environment", "repo"] {
            repo.write(
                ".gitforgeops/config.yaml",
                &serde_json::json!({"environments": {"logical-prod": {
                    "overlay": if source == "repo" { Some(name) } else { None }
                }}})
                .to_string(),
            );
            for args in [
                &["export", "--env", "logical-prod"][..],
                &["validate", "--env", "logical-prod"],
                &["apply", "--env", "logical-prod", "--auto-approve"],
            ] {
                let output = repo.run(args, &[("FERRUM_OVERLAY", name)]);
                assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
                assert!(output_text(&output).contains("overlay name"));
                assert_eq!(
                    std::fs::read_to_string(repo.dir.path().join("calls")).unwrap(),
                    ""
                );
                assert!(!repo.published().exists());
            }
        }
    }

    repo.write(
        ".gitforgeops/config.yaml",
        "environments:\n  logical-prod:\n    overlay: release_1-blue\n",
    );
    repo.write(
        "overlays/release_1-blue/alpha/proxies/app.yaml",
        "kind: Proxy\nspec:\n  id: app\n  backend_port: 9202\n",
    );
    let output = repo.run(&["export", "--env", "logical-prod"], &[]);
    assert!(output.status.success(), "{}", output_text(&output));
    let config: GatewayConfig =
        gitforgeops::yaml::from_str(std::str::from_utf8(&output.stdout).unwrap()).unwrap();
    assert_eq!(config.proxies[0].backend_port, 9202);

    std::os::unix::fs::symlink(
        repo.dir.path().join("overlays/release_1-blue"),
        repo.dir.path().join("overlays/link"),
    )
    .unwrap();
    repo.write(
        ".gitforgeops/config.yaml",
        "environments:\n  logical-prod:\n    overlay: link\n",
    );
    let output = repo.run(&["export", "--env", "logical-prod"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output_text(&output).contains("symbolic links are not allowed"));
}

#[test]
fn which_receives_literal_binary_names_after_the_option_terminator() {
    let repo = Repo::new(&["alpha"], None, None);
    let bin = repo.dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let which = bin.join("which");
    // Fixed work, shell builtins only; record actual argv in the CLI child without
    // changing the parallel test process's PATH. Missing names return immediately.
    std::fs::write(
        &which,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$#" "$@" > "$WHICH_ARGV_LOG"
[ "$#" = 2 ] && [ "$1" = -- ] || exit 0
case "$2" in
    --validator|--missing-after-probe|'validator;touch marker') printf '%s/%s\n' "$PATH" "$2" ;;
    *) exit 1 ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&which, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["--validator", "validator;touch marker"] {
        let path = bin.join(name);
        std::fs::write(
            &path,
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$VALIDATOR_ARGV_LOG\"\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let which_log = repo.dir.path().join("which-argv");
    let validator_log = repo.dir.path().join("validator-argv");
    for name in [
        "--help",
        "-n",
        "--missing-after-probe",
        "--validator",
        "validator;touch marker",
    ] {
        for command in ["validate", "plan", "review"] {
            let output = repo.run(
                &[command],
                &[
                    ("PATH", bin.to_str().unwrap()),
                    ("FERRUM_EDGE_BINARY_PATH", name),
                    ("WHICH_ARGV_LOG", which_log.to_str().unwrap()),
                    ("VALIDATOR_ARGV_LOG", validator_log.to_str().unwrap()),
                ],
            );
            let exists = matches!(name, "--validator" | "validator;touch marker");
            assert_eq!(output.status.success(), exists, "{}", output_text(&output));
            assert_eq!(
                std::fs::read_to_string(&which_log).unwrap(),
                format!("2\n--\n{name}\n")
            );
            if exists {
                let argv = std::fs::read_to_string(&validator_log).unwrap();
                assert!(argv.starts_with("validate\n-m\nfile\n-s\n"), "{argv}");
                let args: Vec<_> = argv.lines().collect();
                assert_eq!(args.len(), 7, "{argv}");
                assert_eq!(args[5], "-c", "{argv}");
            } else if command == "review" {
                assert!(output_text(&output).contains("Validation: ERROR"));
            }
            assert!(!repo.dir.path().join("marker").exists());
        }
    }
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

/// One run writes the spec and empty settings file once; every namespace pass
/// reads the same private pair and only `FERRUM_NAMESPACE` differs (#693).
#[test]
fn namespace_passes_share_one_spec_and_settings_file() {
    let repo = Repo::new(&[], None, None);
    repo.write(
        "validator",
        "#!/bin/sh\nprintf '%s %s %s\\n' \"$FERRUM_NAMESPACE\" \"$5\" \"$7\" >> \"$(dirname \"$0\")/files\"\n",
    );
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "proxies": [
            {"id": "a", "namespace": "alpha"},
            {"id": "z", "namespace": "zeta"}
        ]
    }))
    .unwrap();
    let result = run_validation(&config, repo.validator.to_str().unwrap()).unwrap();
    assert!(result.success, "{result:?}");
    let log = std::fs::read_to_string(repo.dir.path().join("files")).unwrap();
    let passes: Vec<Vec<&str>> = log.lines().map(|line| line.split(' ').collect()).collect();
    assert_eq!(passes.len(), 2, "{log}");
    assert_eq!(passes[0][0], "alpha", "{log}");
    assert_eq!(passes[1][0], "zeta", "{log}");
    assert_eq!(passes[0][1..], passes[1][1..], "{log}");
}

/// `api_spec_id` is admin-generated. The shared load boundary refuses a
/// repository-authored tag before any validator pass or publication.
#[test]
fn repository_authored_spec_ownership_is_refused_at_the_shared_load_boundary() {
    let repo = Repo::new(&["alpha"], None, None);
    repo.write(
        "resources/alpha/proxies/app.yaml",
        "kind: Proxy\nspec:\n  id: app\n  listen_path: /contract\n  backend_scheme: http\n  backend_host: 127.0.0.1\n  backend_port: 9101\n  api_spec_id: forged-spec-owner\n",
    );
    for args in [
        &["validate", "--format", "json"][..],
        &["plan", "--format", "json"],
        &["export"],
        &["apply", "--auto-approve"],
    ] {
        let output = repo.run(args, &[]);
        let text = output_text(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {text}");
        assert!(text.contains("admin-generated"), "{args:?}: {text}");
        assert_eq!(
            std::fs::read_to_string(repo.dir.path().join("calls")).unwrap(),
            "",
            "{args:?}: {text}"
        );
        assert!(!repo.published().exists(), "{args:?}: {text}");
    }
}

/// Outside import, GitForgeOps never turns a desired id into a filesystem
/// path; whether an id is acceptable is Edge's decision. A path-traversing id
/// therefore reaches the validator verbatim, and its refusal fails validation
/// and blocks file publication.
#[test]
fn path_traversing_ids_reach_the_validator_verbatim_and_block_publication() {
    let repo = Repo::new(&[], None, None);
    repo.write(
        "validator",
        "#!/bin/sh\nset -eu\n[ \"$3\" = file ] || exit 0\ncp \"$7\" \"$(dirname \"$0\")/validated.yaml\"\necho 'error: invalid proxy id' >&2\nexit 1\n",
    );
    repo.write(
        "resources/alpha/proxies/escaped.yaml",
        "kind: Proxy\nspec:\n  id: ../escaped\n  listen_path: /escaped\n  backend_scheme: http\n  backend_host: 127.0.0.1\n  backend_port: 9101\n",
    );
    let validated = repo.dir.path().join("validated.yaml");
    for args in [
        &["validate", "--format", "json"][..],
        &["apply", "--auto-approve"],
    ] {
        let output = repo.run(args, &[]);
        let text = output_text(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {text}");
        assert!(text.contains("invalid proxy id"), "{args:?}: {text}");
        assert!(!repo.published().exists(), "{args:?}: {text}");
        let document = std::fs::read_to_string(&validated).unwrap();
        let document: serde_json::Value = gitforgeops::yaml::from_str(&document).unwrap();
        assert_eq!(
            document["proxies"][0]["id"],
            serde_json::Value::from("../escaped"),
            "{args:?}"
        );
        std::fs::remove_file(&validated).unwrap();
    }
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

/// A brokered leaf of each plugin whose stand-in shape #744 / #745 fixed. The
/// non-brokered settings are taken from Ferrum Edge's own accepted test
/// configurations, so a failure here is a verdict on the stand-in.
fn brokered_standin_cases() -> Vec<(&'static str, serde_json::Value)> {
    const BROKERED: &str = "${gh-env-secret:alloc=require}";
    let introspection = |alg: &str| {
        serde_json::json!({"providers": [{
            "introspection_endpoint": "https://idp.example.com/introspect",
            "client_auth": {
                "method": "private_key_jwt",
                "client_id": "ferrum-edge",
                "private_key_jwt_alg": alg,
                "private_key_pem": BROKERED
            }
        }]})
    };
    let relying_party = |alg: &str| {
        serde_json::json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
                "client_id": "ferrum-gateway",
                "client_auth": {
                    "method": "private_key_jwt",
                    "private_key_jwt_alg": alg,
                    "private_key_pem": BROKERED
                },
                "scopes": ["openid", "profile"],
                "redirect_uri": "https://app.example.com/oauth/callback",
                "callback_path": "/oauth/callback",
                "logout_path": "/oauth/logout"
            }],
            "session": {
                "store": "cookie",
                "cookie_name": "ferrum_session",
                "encryption_secret": "9f3a7c1e5b2d8406a1c9e7f3b5d20486"
            },
            "behavior": {
                "trusted_redirect_hosts": ["app.example.com"],
                "post_login_redirect_param": "rd"
            }
        })
    };
    let mut cases = vec![
        (
            "rate_limiting",
            serde_json::json!({
                "limits": [{"scope": "default", "requests_per_minute": 10}],
                "sync_mode": "redis",
                "redis_url": BROKERED
            }),
        ),
        (
            "hmac_auth",
            serde_json::json!({
                "replay_scope": "shared",
                "sync_mode": "redis",
                "redis_url": BROKERED
            }),
        ),
        (
            "jwks_auth",
            serde_json::json!({
                "providers": [{
                    "jwks_uri": "https://idp.example.com/jwks",
                    "issuer": "https://idp.example.com",
                    "require_dpop": true,
                    "dpop_replay_scope": "shared"
                }],
                "sync_mode": "redis",
                "redis_url": BROKERED
            }),
        ),
        ("ws_logging", serde_json::json!({"endpoint_url": BROKERED})),
        (
            "serverless_function",
            serde_json::json!({
                "provider": "aws_lambda",
                "aws_region": "us-east-1",
                "aws_access_key_id": "AKIATEST",
                "aws_secret_access_key": "synthetic-aws-secret-access-key",
                "aws_function_name": "fn",
                "aws_endpoint_url": BROKERED
            }),
        ),
    ];
    // Ambient AWS credentials: the unresolved override is omitted, so Edge
    // validates the row against its default regional endpoint.
    for credentials in [
        serde_json::json!({"aws_credentials": "default_chain"}),
        serde_json::json!({"aws_credentials": "static"}),
    ] {
        let mut config = serde_json::json!({
            "provider": "aws_lambda",
            "aws_region": "us-east-1",
            "aws_function_name": "fn",
            "aws_endpoint_url": BROKERED
        });
        config["aws_credentials"] = credentials["aws_credentials"].clone();
        cases.push(("serverless_function", config));
    }
    cases.push((
        "ai_stream_router",
        serde_json::json!({"providers": [{
            "name": "gemini",
            "provider_type": "google_gemini",
            "endpoint": BROKERED,
            "api_key": BROKERED,
            "model_patterns": ["gemini-*"]
        }]}),
    ));
    for alg in ["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"] {
        cases.push(("oauth2_introspection", introspection(alg)));
        cases.push(("oidc_relying_party", relying_party(alg)));
    }
    // Every brokered OIDC field at once: the session secret and the provider
    // endpoints share the stand-in host, the key follows its algorithm.
    let mut brokered = relying_party("ES256");
    for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        brokered["providers"][0][field] = serde_json::json!(BROKERED);
    }
    brokered["session"]["encryption_secret"] = serde_json::json!(BROKERED);
    cases.push(("oidc_relying_party", brokered));
    cases
}

fn single_plugin(plugin_name: &str, config: serde_json::Value) -> GatewayConfig {
    serde_json::from_value(serde_json::json!({
        "plugin_configs": [{
            "id": "standin-contract",
            "namespace": "ferrum",
            "plugin_name": plugin_name,
            "scope": "global",
            "config": config
        }]
    }))
    .unwrap()
}

/// #744 / #745: the real gateway accepts every reshaped stand-in, so a
/// secretless PR run grades the configuration rather than the brokering.
#[test]
fn real_edge_accepts_brokered_plugin_stand_ins() {
    let Some(binary) = real_validator() else {
        return;
    };
    let binary = binary.to_str().unwrap();

    // Control: the validator really runs the plugin's admission checks.
    let control = single_plugin(
        "ws_logging",
        serde_json::json!({"endpoint_url": "https://collector.example/logs"}),
    );
    let result = run_validation(&control, binary).unwrap();
    assert!(!result.success, "a non-WebSocket URL must fail: {result:?}");

    for (plugin_name, config) in brokered_standin_cases() {
        let gateway = single_plugin(plugin_name, config.clone());
        let result = run_validation(&gateway, binary).unwrap();
        assert!(
            result.success,
            "{plugin_name} {config}: {}{}",
            result.stdout, result.stderr
        );
    }
}

/// Leaving an ambient-credential Lambda override out of the validator copy
/// must not let Edge fall back to the caller's `AWS_LAMBDA_ENDPOINT_URL`
/// (Edge reads it whenever `aws_endpoint_url` is absent), so the variable is
/// removed from the validator's environment then, and only then: a resolved
/// override reaches the validator as configured, beside whatever the caller
/// exported.
#[test]
fn an_omitted_lambda_override_does_not_inherit_the_endpoint_environment() {
    let repo = Repo::new(&[], None, None);
    repo.write(
        "validator",
        "#!/bin/sh\n[ \"$3\" = file ] || exit 0\necho \"env:${AWS_LAMBDA_ENDPOINT_URL-unset}\"\nif grep -q aws_endpoint_url \"$7\"; then echo override:present; else echo override:absent; fi\nexit 0\n",
    );
    let lambda = |endpoint: &str| {
        format!(
            "kind: PluginConfig\nspec:\n  id: lambda\n  plugin_name: serverless_function\n  scope: global\n  config:\n    provider: aws_lambda\n    aws_credentials: default_chain\n    aws_region: us-east-1\n    aws_function_name: fn\n    aws_endpoint_url: '{endpoint}'\n"
        )
    };
    let inherited = [("AWS_LAMBDA_ENDPOINT_URL", "http://localhost:4566/lambda")];

    repo.write(
        "resources/ferrum/plugins/lambda.yaml",
        &lambda("${gh-env-secret:alloc=require}"),
    );
    let output = repo.run(&["validate"], &inherited);
    let text = output_text(&output);
    assert!(text.contains("env:unset"), "{text}");
    assert!(text.contains("override:absent"), "{text}");

    repo.write(
        "resources/ferrum/plugins/lambda.yaml",
        &lambda("https://lambda-fips.us-east-1.amazonaws.com"),
    );
    let output = repo.run(&["validate"], &inherited);
    let text = output_text(&output);
    assert!(text.contains("env:http://localhost:4566/lambda"), "{text}");
    assert!(text.contains("override:present"), "{text}");
}
