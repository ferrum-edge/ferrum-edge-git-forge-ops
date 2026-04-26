use crate::diff::best_practice::BestPractice;
use crate::diff::breaking::BreakingChange;
use crate::diff::resource_diff::{DiffAction, ResourceDiff, UnmanagedResource};
use crate::diff::security::SecurityFinding;
use crate::policy::config::OverrideConfig;
use crate::policy::PolicyFinding;
use crate::secrets::{ResolveReport, SlotStatus};

pub fn build_review_comment(
    validation_success: bool,
    validation_output: &str,
    diffs: &[ResourceDiff],
    breaking: &[BreakingChange],
    security: &[SecurityFinding],
    best_practices: &[BestPractice],
    comparison_error: Option<&str>,
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

    if let Some(reason) = comparison_error {
        md.push_str("### Changes: Skipped\n\n");
        md.push_str(reason);
        md.push_str("\n\n");
    } else if !diffs.is_empty() {
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

    if let Some(reason) = comparison_error {
        md.push_str("### Breaking Changes: Skipped\n\n");
        md.push_str(reason);
        md.push_str("\n\n");
    } else if !breaking.is_empty() {
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

#[allow(clippy::too_many_arguments)]
pub fn build_review_comment_v2(
    validation_success: bool,
    validation_output: &str,
    diffs: &[ResourceDiff],
    breaking: &[BreakingChange],
    security: &[SecurityFinding],
    best_practices: &[BestPractice],
    policy: &[PolicyFinding],
    unmanaged: &[UnmanagedResource],
    override_reason: Option<&str>,
    override_cfg: Option<&OverrideConfig>,
    comparison_error: Option<&str>,
    environment_note: Option<&str>,
    secrets: &ResolveReport,
    bundle_loaded: bool,
) -> String {
    let mut md = build_review_comment(
        validation_success,
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        comparison_error,
    );

    if let Some(note) = environment_note {
        md.insert_str(0, &format!("{note}\n\n"));
    }

    if !unmanaged.is_empty() {
        md.push_str("### Unmanaged Resources (shared mode)\n\n");
        md.push_str(
            "These resources exist on the gateway but were not applied by this repo. They will not be modified or deleted.\n\n",
        );
        for u in unmanaged {
            md.push_str(&format!(
                "- **{} `{}`** (`{}`)\n",
                u.kind, u.id, u.namespace
            ));
        }
        md.push('\n');
    }

    if !policy.is_empty() {
        md.push_str("### Policy Violations\n\n");
        let mut has_blocking = false;
        for pf in policy {
            let status_tag = match (&pf.overridden_by, pf.severity.blocks_apply()) {
                (Some(by), _) => format!(" · OVERRIDDEN by @{by}"),
                (None, true) => {
                    has_blocking = true;
                    " · BLOCKING".to_string()
                }
                (None, false) => String::new(),
            };
            md.push_str(&format!(
                "- [{}] `{}` on **{} `{}`** (`{}`): {}{}\n",
                pf.severity.as_str(),
                pf.rule_id,
                pf.kind,
                pf.id,
                pf.namespace,
                pf.message,
                status_tag
            ));
            if let Some(rem) = &pf.remediation {
                md.push_str(&format!("  - _{}_\n", rem));
            }
        }
        md.push('\n');
        if has_blocking {
            let default_label = "gitforgeops/policy-override".to_string();
            let default_perm = "write".to_string();
            let (label, perm) = match override_cfg {
                Some(cfg) => (&cfg.require_label, &cfg.required_permission),
                None => (&default_label, &default_perm),
            };
            md.push_str(&format!(
                "> **Apply is blocked** until the listed violations are resolved. To override, add the `{label}` label (requires `{perm}` permission on this repo).\n\n",
            ));
        }
        if let Some(reason) = override_reason {
            md.push_str(&format!("_Override status: {reason}_\n\n"));
        }
    }

    if !secrets.results.is_empty() {
        md.push_str("### Credential Slots\n\n");
        if !bundle_loaded {
            // PR review on a fork (or any context without environment-secret
            // access) sees no bundle, so every placeholder looks unresolved.
            // Without this disclaimer, a reviewer would think already-
            // allocated slots are missing and spam apply-first guidance.
            md.push_str(
                "_This CI context has no access to the credential bundle \
                 (typical for PRs from forks or runs without an environment \
                 binding). The table below shows which placeholders are \
                 declared; **actual allocation status is determined at apply \
                 time**, not here._\n\n",
            );
        }
        md.push_str("| Slot | Declared as |\n|------|-------------|\n");
        for r in &secrets.results {
            let label = if bundle_loaded {
                match r.status {
                    SlotStatus::Resolved => "resolved".to_string(),
                    SlotStatus::NeedsAllocation => {
                        "needs allocation (generated on apply)".to_string()
                    }
                    SlotStatus::MissingRequired => "**MISSING (required)**".to_string(),
                }
            } else {
                // Without a bundle, the only signal is the placeholder's alloc
                // mode. Show that rather than bundle-dependent status.
                format!("{:?}", r.placeholder.alloc)
            };
            md.push_str(&format!("| `{}` | {} |\n", r.slot, label));
        }
        md.push('\n');
    }

    md
}
