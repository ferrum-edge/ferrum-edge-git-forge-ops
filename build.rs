//! Capture git identity at compile time for `gitforgeops version`.
//!
//! Invokes `git` only when this package root itself contains a `.git`
//! directory or worktree file. Source tarballs, Docker builds that omit `.git`
//! (see `.dockerignore`), and hosts without a `git` binary all fall back to
//! `unknown` instead of failing the build.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    emit_env("GITFORGEOPS_GIT_SHA", git_stdout(&["rev-parse", "HEAD"]));
    emit_env(
        "GITFORGEOPS_GIT_DESCRIBE",
        git_stdout(&["describe", "--always", "--dirty", "--tags"]),
    );

    if let Some(head) = git_stdout(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
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
