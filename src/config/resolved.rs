use super::env::{ApplyStrategy, EnvConfig};
use super::repo_config::{EnvironmentConfig, OwnershipConfig, OwnershipMode, RepoConfig};

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
}

/// Resolve the active environment for this run.
///
/// Precedence (highest first):
///   1. `env_name` (CLI `--env` flag or `FERRUM_ENV` env var) matched against repo config
///   2. `RepoConfig.default_environment`
///   3. Sole entry of `RepoConfig.environments` (if exactly one)
///   4. Synthetic "default" env built from env vars alone (back-compat path)
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

    match (repo, selected.as_deref()) {
        (Some(repo), Some(name)) => {
            let env = repo.environment(name).ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "environment '{name}' not found in {}",
                    super::repo_config::REPO_CONFIG_PATH
                ))
            })?;
            Ok(merge(name.to_string(), env, env_config))
        }
        (Some(repo), None) => {
            if let Some(default) = &repo.default_environment {
                let env = repo.environment(default).ok_or_else(|| {
                    crate::error::Error::Config(format!(
                        "default_environment '{default}' not found in {}",
                        super::repo_config::REPO_CONFIG_PATH
                    ))
                })?;
                return Ok(merge(default.clone(), env, env_config));
            }
            if repo.environments.len() == 1 {
                let (name, env) = repo.environments.iter().next().unwrap();
                return Ok(merge(name.clone(), env, env_config));
            }
            if repo.environments.is_empty() {
                return Ok(synthetic_default(env_config));
            }
            let names = repo.environment_names().join(", ");
            Err(crate::error::Error::Config(format!(
                "multiple environments defined ({names}); specify --env or FERRUM_ENV, or set default_environment in {}",
                super::repo_config::REPO_CONFIG_PATH
            )))
        }
        (None, _) => Ok(synthetic_default(env_config)),
    }
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

fn synthetic_default(env_config: &EnvConfig) -> ResolvedEnv {
    ResolvedEnv {
        name: env_config
            .env_name
            .clone()
            .unwrap_or_else(ResolvedEnv::default_env_name),
        overlay: env_config.overlay.clone(),
        namespace_filter: env_config.namespace_filter.clone(),
        apply_strategy: env_config.apply_strategy.clone(),
        ownership: OwnershipConfig {
            mode: OwnershipMode::Shared,
            ..OwnershipConfig::default()
        },
    }
}
