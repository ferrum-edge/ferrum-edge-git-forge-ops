//! Capture git identity at compile time for `gitforgeops version`.
//!
//! Invokes `git` only when this package root itself contains a `.git`
//! directory or worktree file. Source tarballs, Docker builds that omit `.git`
//! (see `.dockerignore`), and hosts without a `git` binary all fall back to
//! `unknown` instead of failing the build.
//!
//! It also collects the string literals of the non-test sources into
//! `$OUT_DIR/display_corpus.txt`: the display sink (`src/display.rs`) treats a
//! run of a secret that also occurs in the tool's own prose as public, the
//! same way it treats a run that occurs in the scrubbed configuration.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    write_display_corpus();

    emit_env("GITFORGEOPS_GIT_SHA", git_stdout(&["rev-parse", "HEAD"]));
    emit_env(
        "GITFORGEOPS_GIT_DESCRIBE",
        git_stdout(&["describe", "--always", "--dirty", "--tags"]),
    );

    // Once any `rerun-if-changed` is printed, Cargo watches only those paths,
    // so every input to the two values above has to be listed. `HEAD` alone
    // is not enough: on a branch it holds `ref: refs/heads/<branch>` and does
    // not change when a commit lands. The branch ref (loose or packed) moves
    // the SHA, tags move `describe`, and the index plus the package sources
    // move `--dirty`.
    let mut watched = vec![
        "HEAD".to_string(),
        "packed-refs".to_string(),
        "refs/tags".to_string(),
        "index".to_string(),
    ];
    if let Some(branch) = git_stdout(&["symbolic-ref", "-q", "HEAD"]) {
        watched.push(branch);
    }
    for name in watched {
        if let Some(path) = git_stdout(&["rev-parse", "--git-path", &name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if in_package_git_checkout() {
        for source in ["src", "Cargo.toml", "Cargo.lock"] {
            println!("cargo:rerun-if-changed={source}");
        }
    }
}

fn emit_env(key: &str, value: Option<String>) {
    let value = value
        .as_deref()
        .filter(|value| is_safe_env_value(value))
        .unwrap_or("unknown");
    println!("cargo:rustc-env={key}={value}");
}

fn git_stdout(args: &[&str]) -> Option<String> {
    if !in_package_git_checkout() {
        return None;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let output = Command::new("git")
        .args(args)
        .current_dir(&manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    if !is_safe_env_value(text) {
        return None;
    }
    Some(text.to_string())
}

fn in_package_git_checkout() -> bool {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    Path::new(&manifest_dir).join(".git").exists()
}

fn is_safe_env_value(value: &str) -> bool {
    !value.is_empty() && !value.contains('\0') && !value.contains('\n') && !value.contains('\r')
}

/// Write every string literal of the crate's non-test sources, one per line,
/// to `$OUT_DIR/display_corpus.txt`.
///
/// Each file is read up to its first `#[cfg(test)]`: test modules hold canary
/// secrets, which must not become "public" text. Cutting early only drops
/// literals, which makes the sink stricter, never laxer.
fn write_display_corpus() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let mut files = Vec::new();
    collect_rust_files(Path::new("src"), &mut files);
    files.sort();
    let mut corpus = String::new();
    for file in files {
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        let production = source
            .find("#[cfg(test)]")
            .map_or(source.as_str(), |end| &source[..end]);
        for literal in string_literals(production) {
            corpus.push_str(&literal);
            corpus.push('\n');
        }
    }
    std::fs::write(Path::new(&out_dir).join("display_corpus.txt"), corpus)
        .expect("write display corpus");
}

fn collect_rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The contents of every string literal (plain, byte and raw) in `source`,
/// as written: escapes are kept, which only adds runs. Comments and char
/// literals are skipped so a quote inside them does not start a string.
fn string_literals(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'\'' => {
                // A char literal ('x', '\n', '\u{..}') or a lifetime ('a).
                if bytes.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    let width = source[i + 1..].chars().next().map_or(1, char::len_utf8);
                    if bytes.get(i + 1 + width) == Some(&b'\'') {
                        i += 2 + width;
                    } else {
                        i += 1;
                    }
                }
            }
            b'r' if is_raw_string_start(bytes, i) => {
                let mut hashes = 0;
                let mut j = i + 1;
                while bytes[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                let start = j + 1;
                let mut closing = String::from("\"");
                closing.push_str(&"#".repeat(hashes));
                let end = source[start..]
                    .find(&closing)
                    .map_or(bytes.len(), |offset| start + offset);
                literals.push(source[start..end].to_string());
                i = end + closing.len();
            }
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += if bytes[j] == b'\\' { 2 } else { 1 };
                }
                let end = j.min(bytes.len());
                literals.push(source[start..end].to_string());
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    literals
}

/// `r"`, `r#"`, `br"` …, but not an identifier that merely ends in `r`.
fn is_raw_string_start(bytes: &[u8], i: usize) -> bool {
    let preceded_by_ident = i > 0
        && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')
        && !(bytes[i - 1] == b'b' && (i < 2 || !bytes[i - 2].is_ascii_alphanumeric()));
    if preceded_by_ident {
        return false;
    }
    let mut j = i + 1;
    while j < bytes.len() && bytes[j] == b'#' {
        j += 1;
    }
    bytes.get(j) == Some(&b'"')
}
