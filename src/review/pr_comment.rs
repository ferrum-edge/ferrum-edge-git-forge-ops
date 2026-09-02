use crate::diff::best_practice::BestPractice;
use crate::diff::breaking::BreakingChange;
use crate::diff::resource_diff::{DiffAction, ResourceDiff, SpecOwnedResource, UnmanagedResource};
use crate::diff::security::SecurityFinding;
use crate::policy::config::OverrideConfig;
use crate::policy::PolicyFinding;
use crate::secrets::{ResolveReport, SlotStatus};

/// GitHub accepts issue comments up to 65,536 characters. Keep a byte-based
/// safety margin so multi-byte UTF-8 and future envelope changes cannot turn a
/// successful trusted review into an API rejection.
pub const MAX_REVIEW_COMMENT_BYTES: usize = 60_000;
const MAX_SECTION_ITEMS: usize = 100;
const MAX_DETAILS_PER_DIFF: usize = 20;
const MAX_INLINE_BYTES: usize = 512;
const MAX_VALIDATION_BYTES: usize = 8_192;
const TRUNCATION_NOTICE_RESERVE: usize = 256;

pub fn build_review_comment(
    validation_success: bool,
    validation_output: &str,
    diffs: &[ResourceDiff],
    breaking: &[BreakingChange],
    security: &[SecurityFinding],
    best_practices: &[BestPractice],
    comparison_error: Option<&str>,
) -> String {
    finalize_comment(build_review_comment_inner(
        validation_success,
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        comparison_error,
    ))
}

fn build_review_comment_inner(
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
        let (validation_output, omitted) = truncate_utf8(validation_output, MAX_VALIDATION_BYTES);
        let validation_output = validation_output.replace("```", "``\u{200b}`");
        md.push_str(&validation_output);
        if !validation_output.ends_with('\n') {
            md.push('\n');
        }
        if omitted > 0 {
            md.push_str(&format!("... {omitted} validation byte(s) omitted\n"));
        }
        md.push_str("```\n\n");
    }

    if let Some(reason) = comparison_error {
        md.push_str("### Changes: Skipped\n\n");
        md.push_str(&bounded_inline(reason));
        md.push_str("\n\n");
    } else if !diffs.is_empty() {
        md.push_str("### Changes\n\n");
        md.push_str("| Action | Kind | ID | Details |\n");
        md.push_str("|--------|------|----|---------|\n");
        for diff in diffs.iter().take(MAX_SECTION_ITEMS) {
            let action = match diff.action {
                DiffAction::Add => "Add",
                DiffAction::Modify => "Modify",
                DiffAction::Delete => "Delete",
            };
            let details = if diff.details.is_empty() {
                String::from("-")
            } else {
                let mut fields = diff
                    .details
                    .iter()
                    .take(MAX_DETAILS_PER_DIFF)
                    .map(|d| bounded_inline(&d.field))
                    .collect::<Vec<_>>()
                    .join(", ");
                let omitted = diff.details.len().saturating_sub(MAX_DETAILS_PER_DIFF);
                if omitted > 0 {
                    fields.push_str(&format!(", … {omitted} more field(s)"));
                }
                fields
            };
            md.push_str(&format!(
                "| {} | {} | `{}` | {} |\n",
                action,
                bounded_inline(&diff.kind),
                bounded_inline(&diff.id),
                details
            ));
        }
        append_omitted_table_row(&mut md, diffs.len(), "change");
        md.push('\n');
    } else {
        md.push_str("### Changes: None (in sync)\n\n");
    }

    if let Some(reason) = comparison_error {
        md.push_str("### Breaking Changes: Skipped\n\n");
        md.push_str(&bounded_inline(reason));
        md.push_str("\n\n");
    } else if !breaking.is_empty() {
        md.push_str("### Breaking Changes\n\n");
        for bc in breaking.iter().take(MAX_SECTION_ITEMS) {
            md.push_str(&format!(
                "- **{} `{}`**: {}\n",
                bounded_inline(&bc.kind),
                bounded_inline(&bc.id),
                bounded_inline(&bc.reason)
            ));
        }
        append_omitted_list_item(&mut md, breaking.len(), "breaking change");
        md.push('\n');
    }

    if !security.is_empty() {
        md.push_str("### Security Findings\n\n");
        for sf in security.iter().take(MAX_SECTION_ITEMS) {
            let icon = if sf.severity == "error" {
                "ERROR"
            } else {
                "WARNING"
            };
            md.push_str(&format!(
                "- [{}] **{} `{}`** (`{}`): {}\n",
                icon,
                bounded_inline(&sf.kind),
                bounded_inline(&sf.id),
                bounded_inline(&sf.namespace),
                bounded_inline(&sf.message)
            ));
        }
        append_omitted_list_item(&mut md, security.len(), "security finding");
        md.push('\n');
    }

    if !best_practices.is_empty() {
        md.push_str("### Best Practice Recommendations\n\n");
        for bp in best_practices.iter().take(MAX_SECTION_ITEMS) {
            md.push_str(&format!(
                "- [{}] **{} `{}`** (`{}`): {}\n",
                bounded_inline(&bp.severity),
                bounded_inline(&bp.kind),
                bounded_inline(&bp.id),
                bounded_inline(&bp.namespace),
                bounded_inline(&bp.message)
            ));
        }
        append_omitted_list_item(&mut md, best_practices.len(), "recommendation");
        md.push('\n');
    }

    md
}

fn truncate_utf8(value: &str, max_bytes: usize) -> (&str, usize) {
    if value.len() <= max_bytes {
        return (value, 0);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], value.len().saturating_sub(end))
}

fn bounded_inline(value: &str) -> String {
    let normalized = value
        .replace(['\r', '\n'], " ")
        .replace('|', "\\|")
        .replace('`', "\\`");
    let (prefix, omitted) = truncate_utf8(&normalized, MAX_INLINE_BYTES);
    if omitted == 0 {
        prefix.to_string()
    } else {
        format!("{prefix}…")
    }
}

fn append_omitted_list_item(md: &mut String, total: usize, label: &str) {
    let omitted = total.saturating_sub(MAX_SECTION_ITEMS);
    if omitted > 0 {
        md.push_str(&format!("- _{omitted} additional {label}(s) omitted_\n"));
    }
}

fn append_omitted_table_row(md: &mut String, total: usize, label: &str) {
    let omitted = total.saturating_sub(MAX_SECTION_ITEMS);
    if omitted > 0 {
        md.push_str(&format!(
            "| … |  |  | _{omitted} additional {label}(s) omitted_ |\n"
        ));
    }
}

fn finalize_comment(md: String) -> String {
    if md.len() <= MAX_REVIEW_COMMENT_BYTES {
        return md;
    }

    let budget = MAX_REVIEW_COMMENT_BYTES.saturating_sub(TRUNCATION_NOTICE_RESERVE);
    let mut end = budget.min(md.len());
    while end > 0 && !md.is_char_boundary(end) {
        end -= 1;
    }
    if let Some(newline) = md[..end].rfind('\n') {
        end = newline;
    }
    let mut bounded = md[..end].to_string();
    let omitted = md.len().saturating_sub(end);
    bounded.push_str(&format!(
        "\n\n> Review output was truncated to fit GitHub's comment limit ({omitted} UTF-8 byte(s) omitted). Omitted details remain available in the workflow logs.\n"
    ));
    debug_assert!(bounded.len() <= MAX_REVIEW_COMMENT_BYTES);
    bounded
}

/// The "Spec-owned resources" section, or an empty string when there are none.
///
/// Split out from `build_review_comment_v2` so the wording is testable on its
/// own, and so conflicts (the repo declares a row an API spec owns) get louder
/// treatment than the merely-informational entries.
pub fn render_spec_owned(spec_owned: &[SpecOwnedResource]) -> String {
    if spec_owned.is_empty() {
        return String::new();
    }

    let mut md = String::from("### Spec-owned Resources\n\n");
    md.push_str(
        "These gateway resources carry an `api_spec_id`: they are provisioned by an OpenAPI \
         spec import, not by this repo. gitforgeops does not modify or prune them.\n\n",
    );

    let conflicts: Vec<&SpecOwnedResource> =
        spec_owned.iter().filter(|s| s.is_conflict()).collect();
    for s in spec_owned.iter().take(MAX_SECTION_ITEMS) {
        let note = if s.is_conflict() {
            " — **CONFLICT: this repo also declares it**"
        } else if s.pruned {
            " — will be DELETED (`--confirm-api-spec-deletion`)"
        } else {
            ""
        };
        md.push_str(&format!(
            "- **{} `{}`** (`{}`) owned by spec `{}`{}\n",
            bounded_inline(&s.kind),
            bounded_inline(&s.id),
            bounded_inline(&s.namespace),
            bounded_inline(&s.api_spec_id),
            note
        ));
    }
    append_omitted_list_item(&mut md, spec_owned.len(), "spec-owned resource");
    md.push('\n');

    if !conflicts.is_empty() {
        md.push_str(&format!(
            "> {} resource(s) are declared both here and by an API spec. The spec importer wins \
             on its next run, so the repo's version will be silently reverted. Remove the \
             resource file, or stop managing that spec through `/api-specs`.\n\n",
            conflicts.len()
        ));
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
    spec_owned: &[SpecOwnedResource],
    override_reason: Option<&str>,
    override_cfg: Option<&OverrideConfig>,
    comparison_error: Option<&str>,
    environment_note: Option<&str>,
    secrets: &ResolveReport,
    bundle_loaded: bool,
) -> String {
    let mut md = build_review_comment_inner(
        validation_success,
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        comparison_error,
    );

    if let Some(note) = environment_note {
        md.insert_str(0, &format!("{}\n\n", bounded_inline(note)));
    }

    if !unmanaged.is_empty() {
        md.push_str("### Unmanaged Resources (shared mode)\n\n");
        md.push_str(
            "These resources exist on the gateway but were not applied by this repo. They will not be modified or deleted.\n\n",
        );
        for u in unmanaged.iter().take(MAX_SECTION_ITEMS) {
            md.push_str(&format!(
                "- **{} `{}`** (`{}`)\n",
                bounded_inline(&u.kind),
                bounded_inline(&u.id),
                bounded_inline(&u.namespace)
            ));
        }
        append_omitted_list_item(&mut md, unmanaged.len(), "unmanaged resource");
        md.push('\n');
    }

    md.push_str(&render_spec_owned(spec_owned));

    if !policy.is_empty() {
        md.push_str("### Policy Violations\n\n");
        let mut has_blocking = false;
        for pf in policy.iter().take(MAX_SECTION_ITEMS) {
            let status_tag = match (&pf.overridden_by, pf.severity.blocks_apply()) {
                (Some(by), _) => format!(" · OVERRIDDEN by @{}", bounded_inline(by)),
                (None, true) => {
                    has_blocking = true;
                    " · BLOCKING".to_string()
                }
                (None, false) => String::new(),
            };
            md.push_str(&format!(
                "- [{}] `{}` on **{} `{}`** (`{}`): {}{}\n",
                pf.severity.as_str(),
                bounded_inline(&pf.rule_id),
                bounded_inline(&pf.kind),
                bounded_inline(&pf.id),
                bounded_inline(&pf.namespace),
                bounded_inline(&pf.message),
                status_tag
            ));
            if let Some(rem) = &pf.remediation {
                md.push_str(&format!("  - _{}_\n", bounded_inline(rem)));
            }
        }
        append_omitted_list_item(&mut md, policy.len(), "policy finding");
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
                label = bounded_inline(label),
                perm = bounded_inline(perm),
            ));
        }
        if let Some(reason) = override_reason {
            md.push_str(&format!(
                "_Override status: {}_\n\n",
                bounded_inline(reason)
            ));
        }
    }

    if !secrets.results.is_empty() {
        md.push_str("### Secret Broker Slots\n\n");
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
                 time**, not here. Only unresolved broker-controlled leaves in \
                 Consumer credentials and plugin config are excluded from the \
                 live diff; literal siblings, extra entries, shape changes, and \
                 nonsecret fields are still compared._\n\n",
            );
        }
        md.push_str("| Slot | Declared as |\n|------|-------------|\n");
        for r in secrets.results.iter().take(MAX_SECTION_ITEMS) {
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
            md.push_str(&format!(
                "| `{}` | {} |\n",
                bounded_inline(&r.slot),
                bounded_inline(&label)
            ));
        }
        append_omitted_table_row(&mut md, secrets.results.len(), "secret broker slot");
        md.push('\n');
    }

    finalize_comment(md)
}
