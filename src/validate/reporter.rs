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

fn format_json(result: &ValidationResult) -> String {
    let json = serde_json::json!({
        "success": result.success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    });

    // Safe: serde_json::to_string_pretty on a Value always succeeds
    serde_json::to_string_pretty(&json).unwrap_or_else(|_| "{}".to_string())
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
            output.push_str(&format!("::error ::{}\n", trimmed));
        } else if lower.contains("warn") {
            output.push_str(&format!("::warning ::{}\n", trimmed));
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
            output.push_str(&format!("::error ::{}\n", trimmed));
        } else if lower.contains("warn") {
            output.push_str(&format!("::warning ::{}\n", trimmed));
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
