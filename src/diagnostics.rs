//! Sanitization for untrusted strings on their way to stdout, stderr and CI
//! job logs.
//!
//! Resource ids, namespaces, plugin names, YAML paths and gateway response
//! bodies are attacker-controlled in the only threat model that matters here:
//! `trusted-pr-review.yml` runs a default-branch binary over a fork PR's
//! resource YAML inside a job bound to the environment's secrets. That job's
//! premise is that PR content is *data*. A control character in one of those
//! strings breaks the premise — a `\n` puts attacker-chosen text at column 0
//! of the Actions log, where the runner parses `::…::` as a workflow command
//! (fabricated `::error::` annotations, `::stop-commands::` suppressing the
//! real ones the very next step emits, `::group::` folding output away).
//!
//! Every diagnostic that interpolates such a string therefore routes it
//! through this module at the point of interpolation. Two guarantees hold for
//! everything it returns:
//!
//! 1. no control character survives — each becomes [`REPLACEMENT`] (plus the
//!    Unicode line/paragraph separators, which are not `char::is_control` but
//!    are line breaks to plenty of downstream readers). [`sanitize_block`] is
//!    the one exception: it preserves `\n` because its input is already a
//!    multi-line diagnostic, and it neutralizes each line individually;
//! 2. no line begins with `::` after leading whitespace — the runner trims a
//!    command's indentation before parsing it, so `  ::stop-commands::x` is
//!    just as live as the unindented form.
//!
//! Output is bounded, because an id is as long as the PR author wants it to
//! be. Truncation appends [`TRUNCATION_MARKER`] so a shortened diagnostic
//! cannot be mistaken for a complete one.
//!
//! This is the generalization of `import::diagnostic_metadata`, which applied
//! the same treatment to import diagnostics alone; that function now delegates
//! here. The PR comment has its own, stricter escaping in
//! [`crate::review::pr_comment`] and does not use this module.

use std::fmt;
use std::path::Path;

/// Stand-in for a character that must not reach a log stream.
pub const REPLACEMENT: char = '\u{fffd}';

/// Appended when sanitization dropped the tail of a value.
pub const TRUNCATION_MARKER: &str = "[truncated]";

/// Character budget for a single interpolated scalar (an id, a namespace, a
/// YAML path). Generous for anything a human names, far below what an
/// attacker would need to bury the surrounding diagnostic.
pub const MAX_INLINE_CHARS: usize = 512;

/// Character budget for an already-composed diagnostic (a finding message, a
/// gateway error body, a validator's captured output). These legitimately run
/// long, so the bound only exists to stop unbounded log flooding.
pub const MAX_BLOCK_CHARS: usize = 64 * 1024;

/// A character that must never reach a log stream verbatim.
///
/// `char::is_control` covers C0/C1 and DEL. `U+2028`/`U+2029` are not control
/// characters but are line breaks to enough consumers to be worth folding in.
fn is_unsafe_log_char(character: char) -> bool {
    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
}

/// Replace unsafe characters in one line's worth of text.
///
/// Returns the sanitized text and whether the input ran past `max_chars`.
fn replace_unsafe(value: &str, max_chars: usize) -> (String, bool) {
    let mut characters = value.chars();
    let sanitized = characters
        .by_ref()
        .take(max_chars)
        .map(|character| {
            if is_unsafe_log_char(character) {
                REPLACEMENT
            } else {
                character
            }
        })
        .collect::<String>();
    (sanitized, characters.next().is_some())
}

/// Make a line that would otherwise parse as a workflow command inert.
///
/// The runner strips leading whitespace before looking for `::`, so the check
/// has to as well. Prefixing [`REPLACEMENT`] (not a space) is what breaks the
/// match, because whitespace would simply be trimmed again.
fn neutralize_command_prefix(line: &mut String) {
    if line.trim_start().starts_with("::") {
        line.insert(0, REPLACEMENT);
    }
}

/// Sanitize an untrusted scalar for interpolation into one line of output.
///
/// The result contains no line break of any kind and does not begin a
/// workflow command, so interpolating it cannot add a line to the log.
pub fn sanitize(value: &str) -> String {
    sanitize_single_line(value, MAX_INLINE_CHARS)
}

/// Sanitize an already-composed single-line diagnostic.
///
/// Same guarantees as [`sanitize`] with the larger [`MAX_BLOCK_CHARS`] budget:
/// these strings are written by this crate around untrusted fragments and are
/// routinely longer than a scalar, so the tighter bound would truncate the
/// remediation rather than the hostile input.
pub fn sanitize_line(value: &str) -> String {
    sanitize_single_line(value, MAX_BLOCK_CHARS)
}

fn sanitize_single_line(value: &str, max_chars: usize) -> String {
    let (mut sanitized, truncated) = replace_unsafe(value, max_chars);
    if truncated {
        sanitized.push_str(TRUNCATION_MARKER);
    }
    neutralize_command_prefix(&mut sanitized);
    sanitized
}

/// Sanitize a multi-line diagnostic, preserving its line structure.
///
/// For text that is *meant* to span lines — a captured validator stream, an
/// error whose Display carries a remediation paragraph. `\n` survives; every
/// other control character does not, and each resulting line is individually
/// prevented from starting a workflow command. A trailing `\r` is dropped
/// rather than replaced so CRLF input reads normally.
pub fn sanitize_block(value: &str) -> String {
    let mut characters = value.chars();
    let bounded = characters.by_ref().take(MAX_BLOCK_CHARS).collect::<String>();
    let truncated = characters.next().is_some();
    let mut output = String::with_capacity(bounded.len());
    for (index, line) in bounded.split('\n').enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        let (mut sanitized, _) = replace_unsafe(line, MAX_BLOCK_CHARS);
        neutralize_command_prefix(&mut sanitized);
        output.push_str(&sanitized);
    }
    if truncated {
        output.push_str(TRUNCATION_MARKER);
    }
    output
}

/// Display adapter applying [`sanitize`] to any `Display` value.
pub struct Safe<T>(T);

impl<T: fmt::Display> fmt::Display for Safe<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&sanitize(&self.0.to_string()))
    }
}

/// Interpolate an untrusted scalar into one line of log output.
pub fn safe<T: fmt::Display>(value: T) -> Safe<T> {
    Safe(value)
}

/// Display adapter applying [`sanitize_line`] to any `Display` value.
pub struct SafeLine<T>(T);

impl<T: fmt::Display> fmt::Display for SafeLine<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&sanitize_line(&self.0.to_string()))
    }
}

/// Interpolate an already-composed single-line diagnostic.
pub fn safe_line<T: fmt::Display>(value: T) -> SafeLine<T> {
    SafeLine(value)
}

/// Display adapter applying [`sanitize_block`] to any `Display` value.
pub struct SafeBlock<T>(T);

impl<T: fmt::Display> fmt::Display for SafeBlock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&sanitize_block(&self.0.to_string()))
    }
}

/// Interpolate a multi-line diagnostic (an error, a captured child stream).
pub fn safe_block<T: fmt::Display>(value: T) -> SafeBlock<T> {
    SafeBlock(value)
}

/// Display adapter for a path, which has no `Display` of its own.
pub struct SafePath<'a>(&'a Path);

impl fmt::Display for SafePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&sanitize(&self.0.display().to_string()))
    }
}

/// Interpolate a filesystem path that may carry untrusted components.
pub fn safe_path(path: &Path) -> SafePath<'_> {
    SafePath(path)
}
