use std::path::Path;

use super::env::{ApplyStrategy, EnvConfig};
use super::repo_config::{
    EnvironmentConfig, OwnershipConfig, OwnershipMode, RepoConfig, REPO_CONFIG_PATH,
};

/// Directory the overlay tree lives in, relative to the repository root.
pub const OVERLAYS_ROOT: &str = "./overlays";

/// Fully-resolved runtime settings for a single command invocation.
///
/// Combines the repo-level `.gitforgeops/config.yaml` environment entry (if any)
/// with process environment variables, resolving which overlay/strategy/ownership
/// apply to this run.
#[derive(Debug, Clone)]
pub struct ResolvedEnv {
    pub name: String,
    pub overlay: Option<String>,
    pub namespace_filter: Option<String>,
    pub apply_strategy: ApplyStrategy,
    pub ownership: OwnershipConfig,
}

impl ResolvedEnv {
    pub fn default_env_name() -> String {
        "default".to_string()
    }

    /// Enforce the invariants that `RepoConfig::validate` enforces on the
    /// YAML side, so the env-var-only path (no .gitforgeops/config.yaml) can't construct a
    /// configuration the YAML validator would reject. Run this at the end
    /// of resolve_env so both branches go through the same gate.
    pub fn validate(&self) -> crate::error::Result<()> {
        // Environment name is interpolated into `.state/<name>.json`. Reject
        // anything that could escape the .state/ directory — a `..` or `/`
        // in a repo-config YAML key or FERRUM_ENV var would let an apply
        // overwrite files outside .state/ (particularly dangerous in CI
        // runs that auto-commit bot changes back to main).
        validate_env_name_is_safe_path_component(&self.name)?;

        if matches!(self.ownership.mode, OwnershipMode::Shared)
            && matches!(self.apply_strategy, ApplyStrategy::FullReplace)
        {
            return Err(crate::error::Error::Config(format!(
                "environment '{}': apply_strategy='full_replace' is incompatible with ownership.mode='shared' (full_replace would wipe unmanaged resources). Set FERRUM_APPLY_STRATEGY=incremental, or define the env in .gitforgeops/config.yaml with ownership.mode='exclusive' + explicit namespaces.",
                self.name
            )));
        }
        if matches!(self.ownership.mode, OwnershipMode::Exclusive)
            && self
                .ownership
                .namespaces
                .as_ref()
                .map(|ns| ns.is_empty())
                .unwrap_or(true)
        {
            return Err(crate::error::Error::Config(format!(
                "environment '{}': ownership.mode='exclusive' requires ownership.namespaces to be non-empty",
                self.name
            )));
        }
        Ok(())
    }
}

/// Environment names flow through three untrusted surfaces: repo config
/// YAML keys, the FERRUM_ENV env var, and the `--env` CLI flag. They also
/// get interpolated into `.state/<name>.json` paths and (via
/// `gitforgeops envs --format json`) into CI matrix values that end up on
/// shell command lines. A strict allowlist is the safest enforcement.
///
/// Accepted: ASCII letters, digits, `-`, `_`. Length 1..=64. That's
/// enough for any sensible environment identifier and rejects shell
/// metacharacters, whitespace, path separators, and traversal segments by
/// construction.
pub fn validate_env_name_is_safe_path_component(name: &str) -> crate::error::Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(crate::error::Error::Config(format!(
            "environment name {name:?} must be 1..=64 characters."
        )));
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        return Err(crate::error::Error::Config(format!(
            "environment name {name:?} contains disallowed characters. \
             Accepted: ASCII letters, digits, '-', '_'."
        )));
    }
    Ok(())
}

/// Resolve the active environment for this run.
///
/// Precedence (highest first):
///   1. `env_name` (CLI `--env` flag or `FERRUM_ENV` env var) matched against repo config
///   2. `RepoConfig.default_environment`
///   3. Sole entry of `RepoConfig.environments` (if exactly one)
///   4. Synthetic "default" env built from env vars alone
///
/// When no repo config exists, a synthetic env is built from `FERRUM_OVERLAY`,
/// `FERRUM_NAMESPACE`, and `FERRUM_APPLY_STRATEGY`. Ownership defaults to `shared`
/// with drift reporting on.
pub fn resolve_env(
    repo: Option<&RepoConfig>,
    env_config: &EnvConfig,
    explicit_env: Option<&str>,
) -> crate::error::Result<ResolvedEnv> {
    let selected = explicit_env
        .map(|s| s.to_string())
        .or_else(|| env_config.env_name.clone());

    let resolved = match (repo, selected.as_deref()) {
        (Some(repo), Some(name)) => {
            let env = repo.environment(name).ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "environment '{name}' not found in {}",
                    super::repo_config::REPO_CONFIG_PATH
                ))
            })?;
            merge(name.to_string(), env, env_config)
        }
        (Some(repo), None) => {
            if let Some(default) = &repo.default_environment {
                let env = repo.environment(default).ok_or_else(|| {
                    crate::error::Error::Config(format!(
                        "default_environment '{default}' not found in {}",
                        super::repo_config::REPO_CONFIG_PATH
                    ))
                })?;
                merge(default.clone(), env, env_config)
            } else if repo.environments.len() == 1 {
                let (name, env) = repo.environments.iter().next().unwrap();
                merge(name.clone(), env, env_config)
            } else if repo.environments.is_empty() {
                synthetic_default(env_config, selected.as_deref())
            } else {
                let names = repo.environment_names().join(", ");
                return Err(crate::error::Error::Config(format!(
                    "multiple environments defined ({names}); specify --env or FERRUM_ENV, or set default_environment in {}",
                    super::repo_config::REPO_CONFIG_PATH
                )));
            }
        }
        (None, _) => synthetic_default(env_config, selected.as_deref()),
    };

    // Enforce shared + full_replace incompatibility (and other invariants)
    // on every path — the YAML validator guards the repo-config side but
    // the synthetic path picks up FERRUM_APPLY_STRATEGY=full_replace
    // env vars without going through that check.
    resolved.validate()?;
    Ok(resolved)
}

/// Fail before any resource is read when the selected environment names an
/// overlay directory the repository does not ship.
///
/// `assembler::apply_overlay` already refuses a missing overlay directory, but
/// it only names the path — an operator who copied
/// `.gitforgeops/config.example.yaml` and lost `overlays/sandbox/` gets a
/// mid-pipeline error that mentions neither the environment that selected it
/// nor the file that declared the selection. Since every command that touches
/// the resource tree resolves an environment first, checking here turns that
/// into one up-front message naming all three.
///
/// A `None` overlay (the common case) is a no-op: only a *configured* overlay
/// has to exist.
pub fn validate_overlay_selection(
    resolved: &ResolvedEnv,
    repo: Option<&RepoConfig>,
    overlays_root: &Path,
) -> crate::error::Result<()> {
    let Some(overlay) = resolved.overlay.as_deref() else {
        return Ok(());
    };

    let overlay_dir = overlays_root.join(overlay);
    if overlay_dir.is_dir() {
        return Ok(());
    }

    // Repo config wins over `FERRUM_OVERLAY` in `merge`, so the selection came
    // from the config file exactly when that file names this same overlay for
    // this environment.
    let declared_in_repo_config = repo
        .and_then(|repo| repo.environment(&resolved.name))
        .and_then(|env| env.overlay.as_deref())
        == Some(overlay);
    let source = if declared_in_repo_config {
        format!(
            "declared by environment '{}' in {REPO_CONFIG_PATH}",
            resolved.name
        )
    } else {
        "selected by FERRUM_OVERLAY".to_string()
    };

    Err(crate::error::Error::Config(format!(
        "environment '{}' selects overlay '{overlay}', which does not exist: expected a directory at {} ({source}). \
         Create it — an empty `{}/<namespace>/proxies/.gitkeep` is enough for git to track it — or drop the overlay from that environment.",
        resolved.name,
        overlay_dir.display(),
        overlay_dir.display(),
    )))
}

fn merge(name: String, env: &EnvironmentConfig, env_config: &EnvConfig) -> ResolvedEnv {
    // Repo config is authoritative; env vars are fallback when repo config leaves
    // a value unset. This lets operators override per-run without editing the repo.
    let overlay = env.overlay.clone().or_else(|| env_config.overlay.clone());
    let namespace_filter = env
        .namespace_filter
        .clone()
        .or_else(|| env_config.namespace_filter.clone());

    ResolvedEnv {
        name,
        overlay,
        namespace_filter,
        apply_strategy: env.apply_strategy.clone(),
        ownership: env.ownership.clone(),
    }
}

fn synthetic_default(env_config: &EnvConfig, explicit_env: Option<&str>) -> ResolvedEnv {
    // Precedence: explicit CLI/caller selection > FERRUM_ENV > "default".
    // Dropping `explicit_env` here let `--env prod` silently resolve as
    // `default` (or stale FERRUM_ENV), writing state to the wrong
    // `.state/<env>.json` and crossing ownership tracking between envs.
    let name = explicit_env
        .map(String::from)
        .or_else(|| env_config.env_name.clone())
        .unwrap_or_else(ResolvedEnv::default_env_name);
    ResolvedEnv {
        name,
        overlay: env_config.overlay.clone(),
        namespace_filter: env_config.namespace_filter.clone(),
        apply_strategy: env_config.apply_strategy.clone(),
        ownership: OwnershipConfig {
            mode: OwnershipMode::Shared,
            ..OwnershipConfig::default()
        },
    }
}
