use crate::diff::best_practice::BestPractice;
use crate::diff::breaking::BreakingChange;
use crate::diff::resource_diff::{DiffAction, ResourceDiff};
use crate::diff::security::SecurityFinding;

pub fn build_review_comment(
    validation_success: bool,
    validation_output: &str,
    diffs: &[ResourceDiff],
    breaking: &[BreakingChange],
    security: &[SecurityFinding],
    best_practices: &[BestPractice],
) -> String {
    let mut md = String::new();

    md.push_str("## Ferrum Edge Config Review\n\n");

    if validation_success {
        md.push_str("### Validation: PASSED\n\n");
    } else {
        md.push_str("### Validation: FAILED\n\n");
        md.push_str("```\n");
        md.push_str(validation_output);
        if !validation_output.ends_with('\n') {
            md.push('\n');
        }
        md.push_str("```\n\n");
    }

    if !diffs.is_empty() {
        md.push_str("### Changes\n\n");
        md.push_str("| Action | Kind | ID | Details |\n");
        md.push_str("|--------|------|----|---------|\n");
        for diff in diffs {
            let action = match diff.action {
                DiffAction::Add => "Add",
                DiffAction::Modify => "Modify",
                DiffAction::Delete => "Delete",
            };
            let details = if diff.details.is_empty() {
                String::from("-")
            } else {
                diff.details
                    .iter()
                    .map(|d| d.field.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            md.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                action, diff.kind, diff.id, details
            ));
        }
        md.push('\n');
    } else {
        md.push_str("### Changes: None (in sync)\n\n");
    }

    if !breaking.is_empty() {
        md.push_str("### Breaking Changes\n\n");
        for bc in breaking {
            md.push_str(&format!("- **{} `{}`**: {}\n", bc.kind, bc.id, bc.reason));
        }
        md.push('\n');
    }

    if !security.is_empty() {
        md.push_str("### Security Findings\n\n");
        for sf in security {
            let icon = if sf.severity == "error" {
                "ERROR"
            } else {
                "WARNING"
            };
            md.push_str(&format!(
                "- [{}] **{} `{}`**: {}\n",
                icon, sf.kind, sf.id, sf.message
            ));
        }
        md.push('\n');
    }

    if !best_practices.is_empty() {
        md.push_str("### Best Practice Recommendations\n\n");
        for bp in best_practices {
            md.push_str(&format!("- **{} `{}`**: {}\n", bp.kind, bp.id, bp.message));
        }
        md.push('\n');
    }

    md
}
