use gitforgeops::validate::{
    build_validate_args, format_result, scrubbed_env_names, OutputFormat, ValidationResult,
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

fn args_as_strings(settings: &str, spec: &str) -> Vec<String> {
    build_validate_args(Path::new(settings), Path::new(spec))
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
