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

/// Characters that carry no visible meaning in a review comment but can
/// misrepresent one: C0/C1 controls (terminal escapes among them), the bidi
/// overrides and isolates, zero-width and word joiners, the soft hyphen, the
/// byte-order mark, and the Unicode line/paragraph separators — which end a
/// line for some renderers while surviving a `\n`-based flattening.
///
/// A tab is exempt: it is ordinary layout in validator output and in resource
/// identifiers, and replacing it mangles the text without removing any
/// spoofing risk. Callers that must keep real line breaks (fenced validator
/// output) exempt `\n` themselves; the inline callers map `\r`/`\n` to a
/// space before consulting this predicate.
fn is_unsafe_format_character(character: char) -> bool {
    (character.is_control() && character != '\t')
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewValidationStatus {
    Passed,
    Rejected,
    ExecutionError,
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
    build_review_comment_with_status(
        if validation_success {
            ReviewValidationStatus::Passed
        } else {
            ReviewValidationStatus::Rejected
        },
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        comparison_error,
    )
}

pub fn build_review_comment_with_status(
    validation_status: ReviewValidationStatus,
    validation_output: &str,
    diffs: &[ResourceDiff],
    breaking: &[BreakingChange],
    security: &[SecurityFinding],
    best_practices: &[BestPractice],
    comparison_error: Option<&str>,
) -> String {
    finalize_comment(build_review_comment_inner(
        validation_status,
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        comparison_error,
    ))
}

fn build_review_comment_inner(
    validation_status: ReviewValidationStatus,
    validation_output: &str,
    diffs: &[ResourceDiff],
    breaking: &[BreakingChange],
    security: &[SecurityFinding],
    best_practices: &[BestPractice],
    comparison_error: Option<&str>,
) -> String {
    let mut md = String::new();

    md.push_str("## Ferrum Edge Config Review\n\n");

    match validation_status {
        ReviewValidationStatus::Passed => md.push_str("### Validation: PASSED\n\n"),
        ReviewValidationStatus::Rejected | ReviewValidationStatus::ExecutionError => {
            let label = if validation_status == ReviewValidationStatus::Rejected {
                "FAILED"
            } else {
                "ERROR"
            };
            md.push_str(&format!("### Validation: {label}\n\n"));
            let validation_output = bounded_validation_output(validation_output);
            let fence = markdown_fence(&validation_output);
            md.push_str(&fence);
            md.push('\n');
            md.push_str(&validation_output);
            if !validation_output.ends_with('\n') {
                md.push('\n');
            }
            md.push_str(&fence);
            md.push_str("\n\n");
        }
    }

    if let Some(reason) = comparison_error {
        md.push_str("### Changes: Skipped\n\n");
        // The label keeps the untrusted reason off column zero, where an
        // unescaped list bullet or setext underline would still open a block.
        md.push_str("_Reason:_ ");
        md.push_str(&bounded_markdown_text(reason));
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
                    .map(|detail| bounded_markdown_text(&detail.field))
                    .collect::<Vec<_>>()
                    .join(", ");
                let omitted = diff.details.len().saturating_sub(MAX_DETAILS_PER_DIFF);
                if omitted > 0 {
                    fields.push_str(&format!(", … {omitted} more field(s)"));
                }
                fields
            };
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                action,
                bounded_markdown_text(&diff.kind),
                bounded_inline_code(&diff.id),
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
        md.push_str("_Reason:_ ");
        md.push_str(&bounded_markdown_text(reason));
        md.push_str("\n\n");
    } else if !breaking.is_empty() {
        md.push_str("### Breaking Changes\n\n");
        for change in breaking.iter().take(MAX_SECTION_ITEMS) {
            md.push_str(&format!(
                "- **{} {}**: {}\n",
                bounded_markdown_text(&change.kind),
                bounded_inline_code(&change.id),
                bounded_markdown_text(&change.reason)
            ));
        }
        append_omitted_list_item(&mut md, breaking.len(), "breaking change");
        md.push('\n');
    }

    if !security.is_empty() {
        md.push_str("### Security Findings\n\n");
        for finding in security.iter().take(MAX_SECTION_ITEMS) {
            let icon = if finding.severity == "error" {
                "ERROR"
            } else {
                "WARNING"
            };
            md.push_str(&format!(
                "- [{}] **{} {}** ({}): {}\n",
                icon,
                bounded_markdown_text(&finding.kind),
                bounded_inline_code(&finding.id),
                bounded_inline_code(&finding.namespace),
                bounded_markdown_text(&finding.message)
            ));
        }
        append_omitted_list_item(&mut md, security.len(), "security finding");
        md.push('\n');
    }

    if !best_practices.is_empty() {
        md.push_str("### Best Practice Recommendations\n\n");
        for finding in best_practices.iter().take(MAX_SECTION_ITEMS) {
            md.push_str(&format!(
                "- [{}] **{} {}** ({}): {}\n",
                bounded_markdown_text(&finding.severity),
                bounded_markdown_text(&finding.kind),
                bounded_inline_code(&finding.id),
                bounded_inline_code(&finding.namespace),
                bounded_markdown_text(&finding.message)
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

/// Keep one hostile or runaway validator diagnostic from consuming GitHub's
/// entire comment limit. The dynamic fence prevents repository-controlled
/// backticks from terminating the code block, and the scrub keeps terminal
/// escapes and bidi overrides out of a block that is otherwise rendered
/// verbatim. Line feeds and tabs survive — they are the diagnostic's layout.
fn bounded_validation_output(output: &str) -> String {
    let scrubbed: String = output
        .chars()
        .map(|character| {
            if character != '\n' && is_unsafe_format_character(character) {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect();
    let (bounded, omitted) = truncate_utf8(&scrubbed, MAX_VALIDATION_BYTES);
    if omitted > 0 {
        format!("{bounded}\n[validator output truncated]\n[{omitted} UTF-8 byte(s) omitted]")
    } else {
        bounded.to_string()
    }
}

fn markdown_fence(output: &str) -> String {
    let longest_run = output
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    "`".repeat(longest_run.saturating_add(1).max(3))
}

/// Render untrusted prose without letting it open a Markdown block, table
/// cell, link, HTML tag, GitHub mention, or autolink. Newlines are flattened
/// because every caller places the value inside an existing paragraph, list
/// item, or table row.
///
/// Two escaping styles, deliberately: HTML entities where a backslash escape
/// would not help, and a backslash before the ASCII punctuation CommonMark
/// lets one neutralize. `@` kills user mentions and the email autolink; `:`
/// and `.` kill GFM's extended autolinks (`https://evil.example` needs the
/// colon, `www.evil.example` needs a dotted domain), so untrusted text can
/// never publish a clickable destination. Entities render as the original
/// character, so the reader still sees the message the tool wrote.
fn escape_markdown_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\r' | '\n' => escaped.push(' '),
            _ if is_unsafe_format_character(character) => escaped.push('\u{fffd}'),
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '@' => escaped.push_str("&#64;"),
            ':' => escaped.push_str("&#58;"),
            '.' => escaped.push_str("&#46;"),
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '#' | '|' | '!' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Surrounding whitespace is trimmed before escaping: four leading spaces at
/// the start of a line open an indented code block, and a value that is only
/// whitespace or only scrubbed formatting characters would otherwise render
/// as a hole in the sentence.
fn bounded_markdown_text(value: &str) -> String {
    let (bounded, omitted) = truncate_utf8(value.trim(), MAX_INLINE_BYTES);
    let mut escaped = escape_markdown_text(bounded);
    if omitted > 0 {
        escaped.push('…');
    }
    if escaped.is_empty() {
        "(none)".to_string()
    } else {
        escaped
    }
}

/// Dynamic inline-code fence for untrusted identifiers. A pipe is escaped for
/// GFM table parsing, and line breaks are flattened so an identifier cannot
/// terminate its surrounding list or row.
fn inline_code(value: &str) -> String {
    let value: String = value
        .replace("\r\n", " ")
        .trim()
        .chars()
        .map(|character| match character {
            '\r' | '\n' => ' ',
            // Bidi overrides and zero-width characters survive a code span,
            // so an identifier could still be displayed as one it is not.
            _ if is_unsafe_format_character(character) => '\u{fffd}',
            _ => character,
        })
        .collect();
    // An empty code span renders as an adjacent pair of backticks, which
    // swallows the text between it and the next one.
    let value = if value.is_empty() {
        "(unnamed)".to_string()
    } else {
        value
    };
    let value = value
        // GFM's table parser processes backslash escapes before deciding
        // whether a pipe ends the cell. Escape caller-supplied backslashes
        // first so an input `\|` cannot consume the escape we add for `|`.
        .replace('\\', "\\\\")
        .replace('|', "\\|");
    let longest_run = value
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest_run.saturating_add(1).max(1));
    if value.starts_with('`')
        || value.starts_with(' ')
        || value.ends_with('`')
        || value.ends_with(' ')
    {
        format!("{fence} {value} {fence}")
    } else {
        format!("{fence}{value}{fence}")
    }
}

/// Render the comment's own environment banner: which environment this preview
/// ran for, under which ownership mode and apply strategy.
///
/// gitforgeops writes this line itself, so it is markdown, not content —
/// running the assembled line through `bounded_markdown_text` escaped
/// gitforgeops' own backticks and rendered `Environment: \`default\`` with
/// literal backslashes. The three values are still fenced individually with
/// [`bounded_inline_code`] (an environment name is operator input), and the
/// caller inserts the result verbatim.
pub fn environment_header(env_name: &str, ownership_mode: &str, apply_strategy: &str) -> String {
    format!(
        "Environment: {} · Ownership: {} · Strategy: {}",
        bounded_inline_code(env_name),
        bounded_inline_code(ownership_mode),
        bounded_inline_code(apply_strategy),
    )
}

fn bounded_inline_code(value: &str) -> String {
    let (bounded, omitted) = truncate_utf8(value, MAX_INLINE_BYTES);
    if omitted > 0 {
        inline_code(&format!("{bounded}…"))
    } else {
        inline_code(bounded)
    }
}

/// Undo, for terminal display, exactly the escaping `escape_markdown_text`
/// applied.
///
/// The published comment is Markdown: GitHub renders `&#46;` back as `.` and
/// `\_` back as `_`, but a terminal shows both literally, so `plan`/`review`
/// stdout would read as escaped noise. Entities are decoded before the
/// backslash escapes, and `&amp;` last of all, so a decoded `&` can never
/// combine with the text after it into a second entity — the transform is the
/// exact inverse, and an input that literally contained `&#46;` still prints
/// as `&#46;`.
///
/// Fenced blocks are left alone. Validator output is placed in them verbatim,
/// never escaped, so decoding there would rewrite the tool's own text — and a
/// literal ``&#96;&#96;&#96;`` inside one would decode into a fence that
/// terminates the block early.
pub fn markdown_comment_for_terminal(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    let mut open_fence: Option<usize> = None;
    for line in value.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        let fence_run = markdown_fence_run(content);
        match (open_fence, fence_run) {
            (None, Some(run)) if !content.trim_start()[run..].contains('`') => {
                open_fence = Some(run);
                rendered.push_str(line);
            }
            (Some(open), Some(run))
                if run >= open && content.trim_start()[run..].trim().is_empty() =>
            {
                open_fence = None;
                rendered.push_str(line);
            }
            (Some(_), _) => rendered.push_str(line),
            (None, _) => rendered.push_str(&decode_markdown_escapes(line)),
        }
    }
    rendered
}

/// Length of a line's leading backtick run when the line is a fence marker.
fn markdown_fence_run(line: &str) -> Option<usize> {
    let run = line
        .trim_start()
        .chars()
        .take_while(|character| *character == '`')
        .count();
    (run >= 3).then_some(run)
}

fn decode_markdown_escapes(value: &str) -> String {
    let decoded = value
        .replace("&#64;", "@")
        .replace("&#58;", ":")
        .replace("&#46;", ".")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        // Last: an `&` decoded any earlier could form one of the sequences
        // above out of text that was never an entity.
        .replace("&amp;", "&");

    let mut rendered = String::with_capacity(decoded.len());
    let mut characters = decoded.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            rendered.push(character);
            continue;
        }
        match characters.next() {
            Some(escaped)
                if matches!(
                    escaped,
                    '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '#' | '|' | '!'
                ) =>
            {
                rendered.push(escaped)
            }
            Some(other) => {
                rendered.push('\\');
                rendered.push(other);
            }
            None => rendered.push('\\'),
        }
    }
    rendered
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

fn append_omitted_two_column_row(md: &mut String, total: usize, label: &str) {
    let omitted = total.saturating_sub(MAX_SECTION_ITEMS);
    if omitted > 0 {
        md.push_str(&format!(
            "| … | _{omitted} additional {label}(s) omitted_ |\n"
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

    let conflicts = spec_owned
        .iter()
        .filter(|resource| resource.is_conflict())
        .count();
    for resource in spec_owned.iter().take(MAX_SECTION_ITEMS) {
        let note = if resource.is_conflict() {
            " — **CONFLICT: this repo also declares it**"
        } else if resource.pruned {
            " — will be DELETED (`--confirm-api-spec-deletion`)"
        } else {
            ""
        };
        md.push_str(&format!(
            "- **{} {}** ({}) owned by spec {}{}\n",
            bounded_markdown_text(&resource.kind),
            bounded_inline_code(&resource.id),
            bounded_inline_code(&resource.namespace),
            bounded_inline_code(&resource.api_spec_id),
            note
        ));
    }
    append_omitted_list_item(&mut md, spec_owned.len(), "spec-owned resource");
    md.push('\n');

    if conflicts > 0 {
        md.push_str(&format!(
            "> {conflicts} resource(s) are declared both here and by an API spec. The spec importer wins \
             on its next run, so the repo's version will be silently reverted. Remove the \
             resource file, or stop managing that spec through `/api-specs`.\n\n"
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
    build_review_comment_v2_with_status(
        if validation_success {
            ReviewValidationStatus::Passed
        } else {
            ReviewValidationStatus::Rejected
        },
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        policy,
        unmanaged,
        spec_owned,
        override_reason,
        override_cfg,
        comparison_error,
        environment_note,
        secrets,
        bundle_loaded,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_review_comment_v2_with_status(
    validation_status: ReviewValidationStatus,
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
        validation_status,
        validation_output,
        diffs,
        breaking,
        security,
        best_practices,
        comparison_error,
    );

    // Already-rendered markdown from `environment_header` — gitforgeops'
    // own banner, whose untrusted components are fenced there. Escaping it
    // again here would print the fences as literal backslash-backticks.
    if let Some(note) = environment_note {
        md.insert_str(0, &format!("{note}\n\n"));
    }

    if !unmanaged.is_empty() {
        md.push_str("### Unmanaged Resources (shared mode)\n\n");
        md.push_str(
            "These resources exist on the gateway but were not applied by this repo. They will not be modified or deleted.\n\n",
        );
        for resource in unmanaged.iter().take(MAX_SECTION_ITEMS) {
            md.push_str(&format!(
                "- **{} {}** ({})\n",
                bounded_markdown_text(&resource.kind),
                bounded_inline_code(&resource.id),
                bounded_inline_code(&resource.namespace)
            ));
        }
        append_omitted_list_item(&mut md, unmanaged.len(), "unmanaged resource");
        md.push('\n');
    }

    md.push_str(&render_spec_owned(spec_owned));

    if !policy.is_empty() {
        md.push_str("### Policy Violations\n\n");
        let has_blocking = policy
            .iter()
            .any(|finding| finding.overridden_by.is_none() && finding.severity.blocks_apply());
        for finding in policy.iter().take(MAX_SECTION_ITEMS) {
            let status_tag = match (&finding.overridden_by, finding.severity.blocks_apply()) {
                (Some(by), _) => format!(" · OVERRIDDEN by {}", bounded_inline_code(by)),
                (None, true) => " · BLOCKING".to_string(),
                (None, false) => String::new(),
            };
            md.push_str(&format!(
                "- [{}] {} on **{} {}** ({}): {}{}\n",
                finding.severity.as_str(),
                bounded_inline_code(&finding.rule_id),
                bounded_markdown_text(&finding.kind),
                bounded_inline_code(&finding.id),
                bounded_inline_code(&finding.namespace),
                bounded_markdown_text(&finding.message),
                status_tag
            ));
            if let Some(remediation) = &finding.remediation {
                md.push_str(&format!("  - _{}_\n", bounded_markdown_text(remediation)));
            }
        }
        append_omitted_list_item(&mut md, policy.len(), "policy finding");
        md.push('\n');
        if has_blocking {
            let default_label = "gitforgeops/policy-override".to_string();
            let default_permission = "write".to_string();
            let (label, permission) = match override_cfg {
                Some(config) => (&config.require_label, &config.required_permission),
                None => (&default_label, &default_permission),
            };
            md.push_str(&format!(
                "> **Apply is blocked** until the listed violations are resolved. To override, add the {} label (requires {} permission on this repo).\n\n",
                bounded_inline_code(label),
                bounded_inline_code(permission),
            ));
        }
        if let Some(reason) = override_reason {
            md.push_str(&format!(
                "_Override status: {}_\n\n",
                bounded_markdown_text(reason)
            ));
        }
    }

    if !secrets.results.is_empty() {
        md.push_str("### Secret Broker Slots\n\n");
        if !bundle_loaded {
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
        for result in secrets.results.iter().take(MAX_SECTION_ITEMS) {
            let label = if bundle_loaded {
                match result.status {
                    SlotStatus::Resolved => "resolved".to_string(),
                    SlotStatus::NeedsAllocation => {
                        "needs allocation (generated on apply)".to_string()
                    }
                    SlotStatus::MissingRequired => "**MISSING (required)**".to_string(),
                }
            } else {
                format!("{:?}", result.placeholder.alloc)
            };
            md.push_str(&format!(
                "| {} | {} |\n",
                bounded_inline_code(&result.slot),
                label
            ));
        }
        append_omitted_two_column_row(&mut md, secrets.results.len(), "secret broker slot");
        md.push('\n');
    }

    finalize_comment(md)
}
