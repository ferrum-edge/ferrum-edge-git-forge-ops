use gitforgeops::validate::{
    build_validate_args_for_mode, format_result, format_results, run_validation,
    scrubbed_env_names, OutputFormat, ValidationResult, GATEWAY_VALIDATE_MODE, MESH_VALIDATE_MODE,
};
use std::path::Path;

#[test]
fn github_annotations_escape_workflow_command_data() {
    let result = ValidationResult {
        success: false,
        exit_code: 1,
        stdout: String::new(),
        stderr: "error: bad value 100%".to_string(),
    };

    let output = format_result(&result, OutputFormat::GithubAnnotations);

    assert_eq!(output, "::error ::error: bad value 100%25\n");
}

#[test]
fn github_annotations_emit_generic_error_when_no_line_matches() {
    let result = ValidationResult {
        success: false,
        exit_code: 2,
        stdout: "schema rejected".to_string(),
        stderr: String::new(),
    };

    let output = format_result(&result, OutputFormat::GithubAnnotations);

    assert_eq!(output, "::error ::Validation failed with exit code 2\n");
}

#[cfg(unix)]
#[test]
fn validator_output_cannot_echo_literal_or_resolved_credentials() {
    use gitforgeops::config::schema::{Consumer, GatewayConfig};
    use std::os::unix::fs::PermissionsExt;

    let secret = "launch-secret-that-must-never-reach-diagnostics";
    let config = GatewayConfig {
        consumers: vec![Consumer {
            id: "app".to_string(),
            username: "app".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: std::collections::HashMap::from([(
                "keyauth".to_string(),
                serde_json::json!([{"key": secret}]),
            )]),
            acl_groups: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..GatewayConfig::default()
    };

    for exit_code in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let validator = dir.path().join(format!("echo-validator-{exit_code}"));
        std::fs::write(
            &validator,
            format!("#!/bin/sh\ncat \"$7\"\ncat \"$7\" >&2\nexit {exit_code}\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&validator).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&validator, permissions).unwrap();

        let result = run_validation(&config, validator.to_str().unwrap()).unwrap();
        assert!(!result.success);
        assert!(!result.stdout.contains(secret), "{}", result.stdout);
        assert!(!result.stderr.contains(secret), "{}", result.stderr);
        assert!(
            result.stderr.contains("diagnostics were suppressed"),
            "{}",
            result.stderr
        );
    }
}

#[cfg(unix)]
#[test]
fn validator_diagnostics_remain_available_for_placeholder_only_credentials() {
    use gitforgeops::config::schema::{Consumer, GatewayConfig};
    use std::os::unix::fs::PermissionsExt;

    let placeholder = "${gh-env-secret:alloc=require}";
    let config = GatewayConfig {
        consumers: vec![Consumer {
            id: "app".to_string(),
            username: "app".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: std::collections::HashMap::from([(
                "keyauth".to_string(),
                serde_json::json!([{"key": placeholder}]),
            )]),
            acl_groups: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }],
        ..GatewayConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let validator = dir.path().join("echo-validator");
    std::fs::write(&validator, "#!/bin/sh\ncat \"$7\" >&2\nexit 1\n").unwrap();
    let mut permissions = std::fs::metadata(&validator).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&validator, permissions).unwrap();

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();
    assert!(result.stderr.contains(placeholder), "{}", result.stderr);
}

fn args_as_strings(settings: &str, spec: &str) -> Vec<String> {
    build_validate_args_for_mode(GATEWAY_VALIDATE_MODE, Path::new(settings), Path::new(spec))
        .into_iter()
        .map(|a| a.to_string_lossy().to_string())
        .collect()
}

#[test]
fn validate_args_pin_file_mode_and_settings() {
    let args = args_as_strings("/tmp/empty.conf", "/tmp/spec.yaml");

    assert_eq!(
        args,
        vec![
            "validate".to_string(),
            "-m".to_string(),
            "file".to_string(),
            "-s".to_string(),
            "/tmp/empty.conf".to_string(),
            "-c".to_string(),
            "/tmp/spec.yaml".to_string(),
        ]
    );
}

#[test]
fn validate_args_never_pass_a_format_flag() {
    // `ferrum-edge validate` has no `--format` / `--json` flag; formatting is
    // done gitforgeops-side by the reporter.
    let args = args_as_strings("/tmp/empty.conf", "/tmp/spec.yaml");

    assert!(!args.iter().any(|a| a.starts_with("--format")));
    assert!(!args.iter().any(|a| a == "--json"));
}

#[test]
fn env_scrub_targets_only_ferrum_variables() {
    let names = [
        "FERRUM_MODE",
        "FERRUM_GATEWAY_URL",
        "FERRUM_ADMIN_JWT_SECRET",
        "PATH",
        "HOME",
        "TMPDIR",
        "FERRUMISH",
        "NOT_FERRUM_MODE",
        "ferrum_mode",
    ];

    let scrubbed = scrubbed_env_names(names);

    assert_eq!(
        scrubbed,
        vec![
            "FERRUM_MODE".to_string(),
            "FERRUM_GATEWAY_URL".to_string(),
            "FERRUM_ADMIN_JWT_SECRET".to_string(),
        ]
    );
}

#[test]
fn env_scrub_keeps_the_child_environment_usable() {
    let scrubbed = scrubbed_env_names(["PATH", "HOME", "LANG", "SSL_CERT_FILE"]);
    assert!(scrubbed.is_empty(), "{scrubbed:?}");
}

/// A mesh document is validated in a different ferrum-edge mode than a gateway
/// document, and the two are not interchangeable: under `-m mesh`, ferrum-edge
/// infers the localized-file protocol from the `{version?, mesh}` shape handed
/// to `-c` and runs the same parse + normalize + slice-derivation pipeline a
/// mesh node runs at startup.
#[test]
fn mesh_validate_args_pin_mesh_mode_and_settings() {
    let args: Vec<String> = build_validate_args_for_mode(
        MESH_VALIDATE_MODE,
        Path::new("/tmp/empty.conf"),
        Path::new("/tmp/mesh.yaml"),
    )
    .into_iter()
    .map(|a| a.to_string_lossy().to_string())
    .collect();

    assert_eq!(
        args,
        vec![
            "validate".to_string(),
            "-m".to_string(),
            "mesh".to_string(),
            // `-s` still pins settings to an empty file so ferrum.conf
            // auto-discovery cannot fail an otherwise-valid mesh document.
            "-s".to_string(),
            "/tmp/empty.conf".to_string(),
            "-c".to_string(),
            "/tmp/mesh.yaml".to_string(),
        ]
    );
}

#[test]
fn gateway_and_mesh_modes_are_distinct() {
    assert_eq!(GATEWAY_VALIDATE_MODE, "file");
    assert_eq!(MESH_VALIDATE_MODE, "mesh");
    assert_ne!(
        build_validate_args_for_mode(GATEWAY_VALIDATE_MODE, Path::new("s"), Path::new("c")),
        build_validate_args_for_mode(MESH_VALIDATE_MODE, Path::new("s"), Path::new("c")),
        "the two documents must not be validated in the same ferrum-edge mode"
    );
}

fn result(success: bool, stdout: &str, stderr: &str) -> ValidationResult {
    ValidationResult {
        success,
        exit_code: if success { 0 } else { 1 },
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}

/// A repo with no mesh config must see byte-identical output to what it saw
/// before mesh support existed.
#[test]
fn format_results_without_mesh_is_unchanged() {
    let gateway = result(true, "Spec: OK\n", "");

    for format in [
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::GithubAnnotations,
    ] {
        assert_eq!(
            format_results(&gateway, None, format.clone()),
            format_result(&gateway, format)
        );
    }
}

#[test]
fn format_results_text_labels_both_documents() {
    let output = format_results(
        &result(true, "Spec: OK\n", ""),
        Some(&result(
            false,
            "",
            "Mesh spec validation failed: bad selector\n",
        )),
        OutputFormat::Text,
    );

    assert!(output.contains("Gateway document:"), "{output}");
    assert!(output.contains("Mesh document:"), "{output}");
    assert!(output.contains("Validation passed."), "{output}");
    assert!(output.contains("Validation failed."), "{output}");
    assert!(output.contains("bad selector"), "{output}");
}

#[test]
fn format_results_json_conjoins_success() {
    let json: serde_json::Value = serde_json::from_str(&format_results(
        &result(true, "", ""),
        Some(&result(false, "", "boom")),
        OutputFormat::Json,
    ))
    .expect("valid json");

    // Overall success is the conjunction: both documents get published, and a
    // node refusing either one is a broken deploy.
    assert_eq!(json["success"], serde_json::Value::Bool(false));
    assert_eq!(json["gateway"]["success"], serde_json::Value::Bool(true));
    assert_eq!(json["mesh"]["success"], serde_json::Value::Bool(false));
    assert_eq!(json["mesh"]["stderr"], "boom");
}

#[test]
fn format_results_github_annotations_cover_both_documents() {
    let output = format_results(
        &result(false, "", "error: gateway is bad"),
        Some(&result(false, "", "error: mesh is bad")),
        OutputFormat::GithubAnnotations,
    );

    assert!(
        output.contains("::error ::error: gateway is bad"),
        "{output}"
    );
    assert!(output.contains("::error ::error: mesh is bad"), "{output}");
}
