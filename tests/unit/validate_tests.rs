use gitforgeops::validate::{format_result, OutputFormat, ValidationResult};

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
