//! Package version and build-time git identity for `--version` / `version`.
//!
//! Clap's standard `-V` / `--version` flag prints only `CARGO_PKG_VERSION`.
//! The `version` subcommand adds git metadata captured by `build.rs` via
//! `cargo:rustc-env`. `option_env!` keeps the binary compiling when the build
//! script did not run; missing values render as `unknown`.

use serde::Serialize;

use crate::json_output;

/// Identity printed by `gitforgeops version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildInfo {
    pub name: String,
    pub version: String,
    pub git_sha: String,
    pub git_describe: String,
}

impl BuildInfo {
    /// Values baked into this binary.
    pub fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: option_env!("GITFORGEOPS_GIT_SHA")
                .unwrap_or("unknown")
                .to_string(),
            git_describe: option_env!("GITFORGEOPS_GIT_DESCRIBE")
                .unwrap_or("unknown")
                .to_string(),
        }
    }

    /// Human-readable report ending with exactly one `\n`.
    pub fn render_text(&self) -> String {
        format!(
            "{} {}\ngit_sha: {}\ngit_describe: {}\n",
            self.name, self.version, self.git_sha, self.git_describe
        )
    }

    /// Compact JSON object ending with exactly one `\n`.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        json_output::compact(self)
    }
}
