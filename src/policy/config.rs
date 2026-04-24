use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Severity;

pub const POLICY_CONFIG_PATH: &str = ".gitforgeops/policies.yaml";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimeoutBand {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimeoutBandsRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub connect_timeout_ms: TimeoutBand,
    #[serde(default)]
    pub read_timeout_ms: TimeoutBand,
    #[serde(default)]
    pub write_timeout_ms: TimeoutBand,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackendSchemeRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequireAuthPluginRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForbidTlsVerifyDisabledRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyRules {
    #[serde(default)]
    pub proxy_timeout_bands: TimeoutBandsRuleConfig,
    #[serde(default)]
    pub backend_scheme: BackendSchemeRuleConfig,
    #[serde(default)]
    pub require_auth_plugin: RequireAuthPluginRuleConfig,
    #[serde(default)]
    pub forbid_tls_verify_disabled: ForbidTlsVerifyDisabledRuleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideConfig {
    /// Label on the PR that flags an override request.
    #[serde(default = "default_override_label")]
    pub require_label: String,
    /// Minimum repo permission required on the account that added the label.
    /// One of: `admin`, `maintain`, `write`.
    #[serde(default = "default_required_permission")]
    pub required_permission: String,
}

fn default_override_label() -> String {
    "gitforgeops/policy-override".to_string()
}

fn default_required_permission() -> String {
    "write".to_string()
}

impl OverrideConfig {
    pub fn permission_rank(permission: &str) -> u8 {
        match permission {
            "admin" => 4,
            "maintain" => 3,
            "write" => 2,
            "triage" => 1,
            "read" => 0,
            _ => 0,
        }
    }

    pub fn is_sufficient(&self, actual: &str) -> bool {
        Self::permission_rank(actual) >= Self::permission_rank(&self.required_permission)
    }
}

impl Default for OverrideConfig {
    fn default() -> Self {
        Self {
            require_label: default_override_label(),
            required_permission: default_required_permission(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub policies: PolicyRules,
    #[serde(default)]
    pub overrides: OverrideConfig,
}

fn default_version() -> u32 {
    1
}

pub fn load_policies() -> crate::error::Result<Option<PolicyConfig>> {
    load_policies_from_path(Path::new(POLICY_CONFIG_PATH))
}

pub fn load_policies_from_path(path: &Path) -> crate::error::Result<Option<PolicyConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents =
        std::fs::read_to_string(path).map_err(|source| crate::error::Error::FileRead {
            path: path.to_path_buf(),
            source,
        })?;
    let config: PolicyConfig =
        serde_yaml::from_str(&contents).map_err(|source| crate::error::Error::YamlParse {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(Some(config))
}
