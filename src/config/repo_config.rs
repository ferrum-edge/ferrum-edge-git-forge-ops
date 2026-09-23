use std::path::Path;

use serde::{Deserialize, Serialize};

use super::env::ApplyStrategy;

pub const REPO_CONFIG_PATH: &str = ".gitforgeops/config.yaml";
pub const DEFAULT_LARGE_PRUNE_THRESHOLD_PERCENT: u8 = 25;
/// The only `.gitforgeops/config.yaml` contract this release reads; it is
/// both what an absent `version:` means and what `validate` accepts.
pub const REPO_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OwnershipMode {
    Exclusive,
    #[default]
    Shared,
}

// Every struct in this file carries container-level `#[serde(default)]`, so
// a missing key is filled from the type's own `Default` impl. That impl is
// the only definition of a field's default. A per-field
// `#[serde(default = "...")]` would be a second one, and the two once
// disagreed: a derived `Default` (all `false`) silently muted the
// managed-modified and managed-deleted alerts for every config that declared
// `ownership:` without spelling out `drift_alert_on:`.
// `tests/unit/serde_default_tests.rs` asserts that `{}` deserializes to
// `T::default()` for each of these types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DriftAlertOn {
    pub managed_modified: bool,
    pub managed_deleted: bool,
    pub unmanaged_added: bool,
}

impl Default for DriftAlertOn {
    fn default() -> Self {
        Self {
            managed_modified: true,
            managed_deleted: true,
            unmanaged_added: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OwnershipConfig {
    pub mode: OwnershipMode,
    /// Exclusive scope: effective gateway namespaces and mesh directory namespaces.
    /// Checked after overlays and filtering; shared mode does not restrict either.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
    pub drift_report: bool,
    pub drift_alert_on: DriftAlertOn,
    pub large_prune_threshold_percent: u8,
}

impl Default for OwnershipConfig {
    fn default() -> Self {
        Self {
            mode: OwnershipMode::default(),
            namespaces: None,
            drift_report: true,
            drift_alert_on: DriftAlertOn::default(),
            large_prune_threshold_percent: DEFAULT_LARGE_PRUNE_THRESHOLD_PERCENT,
        }
    }
}

/// Reserved suffix for the GitHub Environment a scheduled drift check binds
/// when an environment opts into unattended monitoring.
///
/// The name is derived rather than configured so the same string is reachable
/// from the binary, `drift-check.yml`, `bootstrap_repo_settings.py` and
/// `audit_settings.py` without any of them parsing another's data. The audit
/// keys its narrow reviewer waiver on exactly this suffix, so a deployment
/// environment may never carry it.
pub const MONITORING_ENVIRONMENT_SUFFIX: &str = "-monitor";

/// Derive the monitoring environment name for a deployment environment.
pub fn monitoring_environment_name(environment: &str) -> String {
    format!("{environment}{MONITORING_ENVIRONMENT_SUFFIX}")
}

// `false` is the derived default here, so this type keeps `#[derive(Default)]`
// rather than the hand-written impl the neighbouring config structs need for
// their non-`false`/non-zero defaults. The container-level `#[serde(default)]`
// rule is unchanged: `{}` still deserializes to `MonitoringConfig::default()`,
// which `tests/unit/serde_default_tests.rs` asserts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MonitoringConfig {
    /// Run the scheduled drift check in `<environment>-monitor` instead of the
    /// deployment environment.
    ///
    /// A deployment environment requires a reviewer, and GitHub withholds an
    /// approval-gated environment's secrets until a human approves the job —
    /// so a nightly drift check bound to it parks in "waiting for approval"
    /// and inspects nothing. That is the approval boundary working as
    /// configured, which is why this is opt-in rather than a default: turning
    /// it on means provisioning a second GitHub Environment holding gateway
    /// *read* credentials and nothing else, and accepting that it runs
    /// unattended.
    ///
    /// Left `false`, monitoring stays bound to the deployment environment and
    /// the check reports `not_completed` (approval pending) rather than
    /// anything resembling "in sync".
    pub unattended: bool,
}

/// Staged promotion: this environment may not be applied until another one
/// has applied *and verified* the same source revision.
///
/// Independent environments are the default and stay the default. Declaring
/// `requires:` opts one environment out of the parallel matrix and into a
/// chain, which is a different capability rather than a stricter version of
/// the same one — parallel matrix jobs are not staged rollout, and describing
/// them as one is how "production was promoted from staging" gets believed
/// about a deployment that never waited for staging at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PromotionConfig {
    /// The environment whose successful apply and verification authorize this
    /// one, for the same source revision. `None` = deploy independently.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentConfig {
    pub overlay: Option<String>,
    /// Whether protected `workflow_run` jobs should compare PR resources to
    /// a live Admin API. File-mode environments should set this to false.
    pub live_review: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_filter: Option<String>,
    pub apply_strategy: ApplyStrategy,
    pub ownership: OwnershipConfig,
    pub monitoring: MonitoringConfig,

    pub promotion: PromotionConfig,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            overlay: None,
            live_review: true,
            namespace_filter: None,
            apply_strategy: ApplyStrategy::Incremental,
            ownership: OwnershipConfig::default(),
            monitoring: MonitoringConfig::default(),

            promotion: PromotionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RepoConfig {
    pub version: u32,
    pub environments: std::collections::BTreeMap<String, EnvironmentConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_environment: Option<String>,
}

// Serde's fill-in for absent keys, not a loadable config: `validate`
// rejects the empty `environments` map this produces.
impl Default for RepoConfig {
    fn default() -> Self {
        Self {
            version: REPO_CONFIG_VERSION,
            environments: std::collections::BTreeMap::new(),
            default_environment: None,
        }
    }
}

/// Environment routing data safe to hand to CI matrix construction.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EnvironmentScope {
    pub environment: String,
    pub live_review: bool,
    /// `None` means every protected-branch resource namespace. `Some` is an
    /// explicit filter/ownership allowlist that the caller must intersect
    /// with those directories.
    pub namespaces: Option<Vec<String>>,
    /// The GitHub Environment a scheduled drift check should bind for this
    /// deployment environment. Equal to `environment` unless the environment
    /// opted into unattended monitoring, in which case it is the derived
    /// `<environment>-monitor`. `drift-check.yml` binds this field directly,
    /// so an environment that has not opted in keeps every existing approval
    /// gate.
    pub monitoring_environment: String,
    /// Whether that monitoring environment is expected to run without a human
    /// approval. Reported in the drift check's outcome so an approval-gated
    /// run is never mistaken for a completed one.
    pub unattended_monitoring: bool,

    /// The environment whose applied-and-verified revision authorizes this
    /// one. `None` = this environment deploys independently, in the parallel
    /// matrix. `apply-on-merge.yml` splits its matrix on exactly this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promotion_requires: Option<String>,
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
        config.validate(path)?;
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

    pub fn environment_scopes(&self) -> Vec<EnvironmentScope> {
        self.environments
            .iter()
            .map(|(name, env)| {
                let mut namespaces = match &env.namespace_filter {
                    Some(namespace) => Some(vec![namespace.clone()]),
                    None if matches!(env.ownership.mode, OwnershipMode::Exclusive) => {
                        env.ownership.namespaces.clone()
                    }
                    None => None,
                };
                if let Some(values) = &mut namespaces {
                    values.sort();
                    values.dedup();
                }
                EnvironmentScope {
                    environment: name.clone(),
                    live_review: env.live_review,
                    namespaces,
                    monitoring_environment: if env.monitoring.unattended {
                        monitoring_environment_name(name)
                    } else {
                        name.clone()
                    },
                    unattended_monitoring: env.monitoring.unattended,

                    promotion_requires: env.promotion.requires.clone(),
                }
            })
            .collect()
    }

    fn validate(&self, path: &Path) -> crate::error::Result<()> {
        if self.version != REPO_CONFIG_VERSION {
            return Err(crate::error::Error::Config(format!(
                "unsupported repository config version {} in {}; expected version {}",
                self.version,
                path.display(),
                REPO_CONFIG_VERSION
            )));
        }

        // An empty `environments` map is almost always an operator
        // mistake (e.g., commenting out every entry). `cmd_envs` would
        // emit `[]`, and the matrix-job workflows gate on
        // `outputs.envs != '[]'`, so validate/apply/drift would silently
        // skip the entire pipeline with no error. Fail loudly here so the
        // misconfiguration surfaces at config load instead of as a
        // mysterious no-op deploy. Repos that genuinely don't want a
        // multi-env config should delete `.gitforgeops/config.yaml`
        // entirely; the synthetic-default path then provides a single
        // implicit env.
        if self.environments.is_empty() {
            return Err(crate::error::Error::Config(
                ".gitforgeops/config.yaml has an empty `environments` map. \
                 Define at least one environment, or delete the file to fall back to the single implicit env."
                    .to_string(),
            ));
        }

        for (name, env) in &self.environments {
            // Env name guards: reject anything that wouldn't be a safe
            // filesystem path component OR contains shell metacharacters.
            // `envs --format json` emits these names into CI matrix values
            // that may hit shell command lines before `ResolvedEnv::validate`
            // runs, so the guard belongs at load time too.
            super::resolved::validate_env_name_is_safe_path_component(name)?;
            if let Some(overlay) = &env.overlay {
                super::resolved::validate_overlay_name(overlay)?;
            }

            // `<name>-monitor` is the derived GitHub Environment a scheduled
            // drift check binds, and the settings audit waives the required-
            // reviewer rule for exactly that suffix. A deployment environment
            // named `staging-monitor` would inherit that waiver and become an
            // unreviewed gateway *write* target.
            if name.ends_with(MONITORING_ENVIRONMENT_SUFFIX) {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': the '{MONITORING_ENVIRONMENT_SUFFIX}' suffix is \
                     reserved for the drift-monitoring environment derived from a deployment \
                     environment of the same base name. Rename this environment; set \
                     `monitoring.unattended: true` on the deployment environment to create \
                     its monitoring target."
                )));
            }

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

        // A promotion chain that names a missing environment would emit a
        // matrix the workflow cannot satisfy, and a cycle would deadlock every
        // environment in it forever. Both are load-time errors rather than a
        // job that waits for a predecessor that will never run.
        for (name, env) in &self.environments {
            let Some(required) = &env.promotion.requires else {
                continue;
            };
            if required == name {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': promotion.requires names itself"
                )));
            }
            if !self.environments.contains_key(required) {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': promotion.requires '{required}' is not a declared environment"
                )));
            }
        }
        for name in self.environments.keys() {
            let mut seen = vec![name.as_str()];
            let mut cursor = name.as_str();
            while let Some(next) = self
                .environments
                .get(cursor)
                .and_then(|env| env.promotion.requires.as_deref())
            {
                if seen.contains(&next) {
                    return Err(crate::error::Error::Config(format!(
                        "environment '{name}': promotion.requires forms a cycle ({} -> {next})",
                        seen.join(" -> ")
                    )));
                }
                seen.push(next);
                cursor = next;
            }
        }
        // `apply-on-merge.yml` has exactly two phases: the independent matrix,
        // then one `promote` matrix whose jobs run in parallel. A predecessor
        // that is itself promoted runs in that same parallel phase, so its
        // successor would read for a record that has not been written yet and
        // refuse on every run — a configuration that loads and can never
        // deploy. Refuse it here, where the operator can still act on it.
        for (name, env) in &self.environments {
            let Some(required) = env.promotion.requires.as_deref() else {
                continue;
            };
            if let Some(grand) = self
                .environments
                .get(required)
                .and_then(|predecessor| predecessor.promotion.requires.as_deref())
            {
                return Err(crate::error::Error::Config(format!(
                    "environment '{name}': promotion.requires '{required}', which is itself \
                     promoted from '{grand}'. Promotion is one stage deep: a predecessor must \
                     deploy independently (no promotion.requires). Promote '{name}' from \
                     '{grand}' instead, or drop the chain."
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
