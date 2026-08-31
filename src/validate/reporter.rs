use super::runner::ValidationResult;

/// Output format for validation results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// Machine-readable JSON output.
    Json,
    /// GitHub Actions workflow annotations.
    GithubAnnotations,
}

impl OutputFormat {
    /// Parse from a string value (case-insensitive).
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            "github" | "github-annotations" | "github_annotations" => Self::GithubAnnotations,
            _ => Self::Text,
        }
    }
}

/// Format a `ValidationResult` for the given output mode.
pub fn format_result(result: &ValidationResult, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => format_text(result),
        OutputFormat::Json => format_json(result),
        OutputFormat::GithubAnnotations => format_github_annotations(result),
    }
}

/// Format a gateway result together with an optional mesh result.
///
/// With `mesh = None` the output is byte-identical to
/// [`format_result`] — a repo that declares no mesh config sees exactly what
/// it saw before mesh support existed. With a mesh result present, both are
/// reported and the caller's success decision is the conjunction: a mesh
/// document that fails `ferrum-edge validate -m mesh` is as fatal as a
/// gateway document that fails `-m file`, because both are published
/// artifacts a node will refuse to load.
pub fn format_results(
    gateway: &ValidationResult,
    mesh: Option<&ValidationResult>,
    format: OutputFormat,
) -> String {
    let Some(mesh) = mesh else {
        return format_result(gateway, format);
    };

    match format {
        OutputFormat::Text => {
            let mut output = String::from("Gateway document:\n");
            output.push_str(&indent_block(&format_text(gateway)));
            output.push_str("Mesh document:\n");
            output.push_str(&indent_block(&format_text(mesh)));
            output
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "success": gateway.success && mesh.success,
                "gateway": result_json(gateway),
                "mesh": result_json(mesh),
            });
            serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
        }
        OutputFormat::GithubAnnotations => {
            let mut output = format_github_annotations(gateway);
            output.push_str(&format_github_annotations(mesh));
            output
        }
    }
}

fn indent_block(block: &str) -> String {
    let mut output = String::with_capacity(block.len() + 8);
    for line in block.lines() {
        if line.is_empty() {
            output.push('\n');
        } else {
            output.push_str("  ");
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn format_text(result: &ValidationResult) -> String {
    let mut output = String::new();

    if result.success {
        output.push_str("Validation passed.\n");
    } else {
        output.push_str("Validation failed.\n");
    }

    if !result.stdout.is_empty() {
        output.push_str(&result.stdout);
        if !result.stdout.ends_with('\n') {
            output.push('\n');
        }
    }

    if !result.stderr.is_empty() {
        output.push_str(&result.stderr);
        if !result.stderr.ends_with('\n') {
            output.push('\n');
        }
    }

    output
}

fn result_json(result: &ValidationResult) -> serde_json::Value {
    serde_json::json!({
        "success": result.success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    })
}

fn format_json(result: &ValidationResult) -> String {
    // Safe: serde_json::to_string_pretty on a Value always succeeds
    serde_json::to_string_pretty(&result_json(result)).unwrap_or_else(|_| "{}".to_string())
}

fn format_github_annotations(result: &ValidationResult) -> String {
    let mut output = String::new();

    // Parse stderr lines for error/warning patterns and emit GitHub annotations
    for line in result.stderr.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if lower.contains("error") {
            output.push_str(&format!(
                "::error ::{}\n",
                escape_workflow_command_data(trimmed)
            ));
        } else if lower.contains("warn") {
            output.push_str(&format!(
                "::warning ::{}\n",
                escape_workflow_command_data(trimmed)
            ));
        }
    }

    // Also parse stdout for any error/warning patterns
    for line in result.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if lower.contains("error") {
            output.push_str(&format!(
                "::error ::{}\n",
                escape_workflow_command_data(trimmed)
            ));
        } else if lower.contains("warn") {
            output.push_str(&format!(
                "::warning ::{}\n",
                escape_workflow_command_data(trimmed)
            ));
        }
    }

    // If validation failed but no specific lines matched, emit a generic error
    if !result.success && output.is_empty() {
        output.push_str(&format!(
            "::error ::Validation failed with exit code {}\n",
            result.exit_code
        ));
    }

    output
}

fn escape_workflow_command_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}
