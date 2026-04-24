use std::path::Path;

use serde::{Deserialize, Serialize};

use super::env::ApplyStrategy;

pub const REPO_CONFIG_PATH: &str = ".gitforgeops/config.yaml";
pub const DEFAULT_LARGE_PRUNE_THRESHOLD_PERCENT: u8 = 25;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OwnershipMode {
    Exclusive,
    #[default]
    Shared,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriftAlertOn {
    #[serde(default = "default_true")]
    pub managed_modified: bool,
    #[serde(default = "default_true")]
    pub managed_deleted: bool,
    #[serde(default)]
    pub unmanaged_added: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipConfig {
    #[serde(default)]
    pub mode: OwnershipMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub drift_report: bool,
    #[serde(default)]
    pub drift_alert_on: DriftAlertOn,
    #[serde(default = "default_large_prune_threshold")]
    pub large_prune_threshold_percent: u8,
}

fn default_large_prune_threshold() -> u8 {
    DEFAULT_LARGE_PRUNE_THRESHOLD_PERCENT
}

impl Default for OwnershipConfig {
    fn default() -> Self {
        Self {
            mode: OwnershipMode::default(),
            namespaces: None,
            drift_report: true,
            drift_alert_on: DriftAlertOn {
                managed_modified: true,
                managed_deleted: true,
                unmanaged_added: false,
            },
            large_prune_threshold_percent: DEFAULT_LARGE_PRUNE_THRESHOLD_PERCENT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub overlay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_filter: Option<String>,
    #[serde(default)]
    pub apply_strategy: ApplyStrategy,
    #[serde(default)]
    pub ownership: OwnershipConfig,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            overlay: None,
            namespace_filter: None,
            apply_strategy: ApplyStrategy::Incremental,
            ownership: OwnershipConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub environments: std::collections::BTreeMap<String, EnvironmentConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_environment: Option<String>,
}

fn default_version() -> u32 {
    1
}

impl RepoConfig {
    pub fn load_from_path(path: &Path) -> crate::error::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let contents =
            std::fs::read_to_string(path).map_err(|source| crate::error::Error::FileRead {
                path: path.to_path_buf(),
                source,
            })?;
        let config: RepoConfig =
            serde_yaml::from_str(&contents).map_err(|source| crate::error::Error::YamlParse {
                path: path.to_path_buf(),
                source,
            })?;
        config.validate()?;
        Ok(Some(config))
    }

    pub fn load() -> crate::error::Result<Option<Self>> {
        Self::load_from_path(Path::new(REPO_CONFIG_PATH))
    }

    pub fn environment(&self, name: &str) -> Option<&EnvironmentConfig> {
        self.environments.get(name)
    }

    pub fn environment_names(&self) -> Vec<String> {
        self.environments.keys().cloned().collect()
    }

    fn validate(&self) -> crate::error::Result<()> {
        for (name, env) in &self.environments {
            // Env name guards: reject anything that wouldn't be a safe
            // filesystem path component OR contains shell metacharacters.
            // `envs --format json` emits these names into CI matrix values
            // that may hit shell command lines before `ResolvedEnv::validate`
            // runs, so the guard belongs at load time too.
            super::resolved::validate_env_name_is_safe_path_component(name)?;

            if matches!(env.ownership.mode, OwnershipMode::Exclusive)
                && env
                    .ownership
                    .namespaces
                    .as_ref()
                    .map(|ns| ns.is_empty())
                    .unwrap_or(true)
            {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': ownership.mode is 'exclusive' but ownership.namespaces is empty or unset (required to bound the exclusive scope)"
                )));
            }

            if matches!(env.ownership.mode, OwnershipMode::Shared)
                && matches!(env.apply_strategy, ApplyStrategy::FullReplace)
            {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': apply_strategy='full_replace' is incompatible with ownership.mode='shared' (full_replace would wipe unmanaged resources)"
                )));
            }

            // `delete_pct` in cmd_apply is 0..=100. `u8` allows 0..=255, so
            // a value like `200` in the YAML would silently disable the
            // prune guard — `delete_pct > threshold` never fires.
            if env.ownership.large_prune_threshold_percent > 100 {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': ownership.large_prune_threshold_percent={} is out of range 0..=100",
                    env.ownership.large_prune_threshold_percent
                )));
            }
        }

        if let Some(default) = &self.default_environment {
            if !self.environments.contains_key(default) {
                return Err(crate::error::Error::Config(format!(
                    "default_environment '{default}' does not exist in environments map"
                )));
            }
        }

        Ok(())
    }
}
