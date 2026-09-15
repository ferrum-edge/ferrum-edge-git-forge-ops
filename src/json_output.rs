//! Shared JSON stdout helpers.
//!
//! `serde_json::{to_string, to_string_pretty}` omit a trailing newline. Every
//! `--format json` command therefore runs its document through this module so
//! the stream ends with exactly one `\n`.

/// Compact JSON (`serde_json::to_string`) ending with exactly one `\n`.
pub fn compact<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(terminate(serde_json::to_string(value)?))
}

/// Pretty JSON (`serde_json::to_string_pretty`) ending with exactly one `\n`.
pub fn pretty<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(terminate(serde_json::to_string_pretty(value)?))
}

/// Strip any trailing newlines, then append exactly one `\n`.
pub fn terminate(mut document: String) -> String {
    let end = document.trim_end_matches('\n').len();
    document.truncate(end);
    document.push('\n');
    document
}
