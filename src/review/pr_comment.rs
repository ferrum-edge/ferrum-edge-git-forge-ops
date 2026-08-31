use crate::diff::best_practice::BestPractice;
use crate::diff::breaking::BreakingChange;
use crate::diff::resource_diff::{DiffAction, ResourceDiff, SpecOwnedResource, UnmanagedResource};
use crate::diff::security::SecurityFinding;
use crate::policy::config::OverrideConfig;
use crate::policy::PolicyFinding;
use crate::secrets::{ResolveReport, SlotStatus};

fn is_unsafe_format_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

fn sanitize_markdown_inline(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.trim().chars() {
        if matches!(character, '\r' | '\n') {
            pending_space = true;
            continue;
        }
        if pending_space && !sanitized.ends_with(' ') {
            sanitized.push(' ');
        }
        pending_space = false;
        if is_unsafe_format_character(character) {
            sanitized.push('\u{fffd}');
            continue;
        }
        match character {
            '&' => sanitized.push_str("&amp;"),
            '<' => sanitized.push_str("&lt;"),
            '>' => sanitized.push_str("&gt;"),
            '`' => sanitized.push_str("&#96;"),
            '\\' => sanitized.push_str("&#92;"),
            '*' => sanitized.push_str("&#42;"),
            '_' => sanitized.push_str("&#95;"),
            '[' => sanitized.push_str("&#91;"),
            ']' => sanitized.push_str("&#93;"),
            '|' => sanitized.push_str("&#124;"),
            '#' => sanitized.push_str("&#35;"),
            '@' => sanitized.push_str("&#64;"),
            ':' => sanitized.push_str("&#58;"),
            '.' => sanitized.push_str("&#46;"),
            _ => sanitized.push(character),
        }
    }
    if sanitized.is_empty() {
        "(none)".to_string()
    } else {
        sanitized
    }
}

fn sanitize_code_span(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.trim().chars() {
        if matches!(character, '\r' | '\n') {
            pending_space = true;
            continue;
        }
        if pending_space && !sanitized.ends_with(' ') {
            sanitized.push(' ');
        }
        pending_space = false;
        if is_unsafe_format_character(character) {
            sanitized.push('\u{fffd}');
            continue;
        }
        match character {
            '`' => sanitized.push('\''),
            _ => sanitized.push(character),
        }
    }
    if sanitized.is_empty() {
        "(unnamed)".to_string()
    } else {
        sanitized
    }
}

fn sanitize_table_code_span(value: &str) -> String {
    sanitize_code_span(value).replace('|', "\\|")
}

pub fn markdown_comment_for_terminal(value: &str) -> String {
    value
        .replace("&#91;", "[")
        .replace("&#93;", "]")
        .replace("&#96;", "`")
        .replace("&#92;", "\\")
        .replace("&#42;", "*")
        .replace("&#95;", "_")
        .replace("&#124;", "|")
        .replace("&#35;", "#")
        .replace("&#64;", "@")
        .replace("&#58;", ":")
        .replace("&#46;", ".")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub struct EnvironmentNote(String);

impl EnvironmentNote {
    fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn render_environment_note(
    environment: &str,
    ownership: &str,
    strategy: &str,
) -> EnvironmentNote {
    EnvironmentNote(format!(
        "Environment: `{}` · Ownership: `{}` · Strategy: `{}`",
        sanitize_code_span(environment),
        sanitize_code_span(ownership),
        sanitize_code_span(strategy)
    ))
}

fn fenced_code(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if character != '\n' && is_unsafe_format_character(character) {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect();
    let mut longest_run = 0usize;
    let mut current_run = 0usize;
    for character in sanitized.chars() {
        if character == '`' {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    let fence = "`".repeat(longest_run.saturating_add(1).max(3));
    let separator = if sanitized.ends_with('\n') { "" } else { "\n" };
    format!("{fence}\n{sanitized}{separator}{fence}\n\n")
}

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
        md.push_str(&fenced_code(validation_output));
    }

    if let Some(reason) = comparison_error {
        md.push_str("### Changes: Skipped\n\n");
        md.push_str("_Reason:_ ");
        md.push_str(&sanitize_markdown_inline(reason));
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
                action,
                sanitize_markdown_inline(&diff.kind),
                sanitize_table_code_span(&diff.id),
                sanitize_markdown_inline(&details)
            ));
        }
        md.push('\n');
    } else {
        md.push_str("### Changes: None (in sync)\n\n");
    }

    if let Some(reason) = comparison_error {
        md.push_str("### Breaking Changes: Skipped\n\n");
        md.push_str("_Reason:_ ");
        md.push_str(&sanitize_markdown_inline(reason));
        md.push_str("\n\n");
    } else if !breaking.is_empty() {
        md.push_str("### Breaking Changes\n\n");
        for bc in breaking {
            md.push_str(&format!(
                "- **{} `{}`**: {}\n",
                sanitize_markdown_inline(&bc.kind),
                sanitize_code_span(&bc.id),
                sanitize_markdown_inline(&bc.reason)
            ));
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
                "- [{}] **{} `{}`** (`{}`): {}\n",
                icon,
                sanitize_markdown_inline(&sf.kind),
                sanitize_code_span(&sf.id),
                sanitize_code_span(&sf.namespace),
                sanitize_markdown_inline(&sf.message)
            ));
        }
        md.push('\n');
    }

    if !best_practices.is_empty() {
        md.push_str("### Best Practice Recommendations\n\n");
        for bp in best_practices {
            md.push_str(&format!(
                "- [{}] **{} `{}`** (`{}`): {}\n",
                sanitize_markdown_inline(&bp.severity),
                sanitize_markdown_inline(&bp.kind),
                sanitize_code_span(&bp.id),
                sanitize_code_span(&bp.namespace),
                sanitize_markdown_inline(&bp.message)
            ));
        }
        md.push('\n');
    }

    md
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
    for s in spec_owned {
        let note = if s.is_conflict() {
            " — **CONFLICT: this repo also declares it**"
        } else if s.pruned {
            " — will be DELETED (`--confirm-api-spec-deletion`)"
        } else {
            ""
        };
        md.push_str(&format!(
            "- **{} `{}`** (`{}`) owned by spec `{}`{}\n",
            sanitize_markdown_inline(&s.kind),
            sanitize_code_span(&s.id),
            sanitize_code_span(&s.namespace),
            sanitize_code_span(&s.api_spec_id),
            note
        ));
    }
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
    environment_note: Option<&EnvironmentNote>,
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
        // Callers construct this with `render_environment_note`, which escapes
        // each dynamic value while preserving the intentional code-span markup.
        md.insert_str(0, &format!("{}\n\n", note.as_str()));
    }

    if !unmanaged.is_empty() {
        md.push_str("### Unmanaged Resources (shared mode)\n\n");
        md.push_str(
            "These resources exist on the gateway but were not applied by this repo. They will not be modified or deleted.\n\n",
        );
        for u in unmanaged {
            md.push_str(&format!(
                "- **{} `{}`** (`{}`)\n",
                sanitize_markdown_inline(&u.kind),
                sanitize_code_span(&u.id),
                sanitize_code_span(&u.namespace)
            ));
        }
        md.push('\n');
    }

    md.push_str(&render_spec_owned(spec_owned));

    if !policy.is_empty() {
        md.push_str("### Policy Violations\n\n");
        let mut has_blocking = false;
        for pf in policy {
            let status_tag = match (&pf.overridden_by, pf.severity.blocks_apply()) {
                (Some(by), _) => {
                    format!(" · OVERRIDDEN by @{}", sanitize_markdown_inline(by))
                }
                (None, true) => {
                    has_blocking = true;
                    " · BLOCKING".to_string()
                }
                (None, false) => String::new(),
            };
            md.push_str(&format!(
                "- [{}] `{}` on **{} `{}`** (`{}`): {}{}\n",
                pf.severity.as_str(),
                sanitize_code_span(&pf.rule_id),
                sanitize_markdown_inline(&pf.kind),
                sanitize_code_span(&pf.id),
                sanitize_code_span(&pf.namespace),
                sanitize_markdown_inline(&pf.message),
                status_tag
            ));
            if let Some(rem) = &pf.remediation {
                md.push_str(&format!("  - _{}_\n", sanitize_markdown_inline(rem)));
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
                "> **Apply is blocked** until the listed violations are resolved. To override, add the `{}` label (requires `{}` permission on this repo).\n\n",
                sanitize_code_span(label),
                sanitize_code_span(perm),
            ));
        }
        if let Some(reason) = override_reason {
            md.push_str(&format!(
                "_Override status: {}_\n\n",
                sanitize_markdown_inline(reason)
            ));
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
            md.push_str(&format!(
                "| `{}` | {} |\n",
                sanitize_table_code_span(&r.slot),
                label
            ));
        }
        md.push('\n');
    }

    md
}
