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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequireAuthPluginRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    /// Plugin names that count as authentication. Defaults cover the
    /// Ferrum Edge built-in auth plugins. The explicit allowlist accepts
    /// canonical auth plugin ids such as `jwt` and rejects unrelated plugin
    /// names that merely contain auth-like substrings.
    #[serde(default = "default_auth_plugin_names")]
    pub auth_plugin_names: Vec<String>,
}

impl Default for RequireAuthPluginRuleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            severity: Severity::default(),
            auth_plugin_names: default_auth_plugin_names(),
        }
    }
}

const DEFAULT_AUTH_PLUGIN_NAMES: &[&str] = &[
    "jwt",
    "basic_auth",
    "basic-auth",
    "basic auth",
    "basicauth",
    "key_auth",
    "key-auth",
    "keyauth",
    "oauth2",
    "oidc",
    "ldap_auth",
    "ldap-auth",
    "ldapauth",
    "hmac_auth",
    "hmac-auth",
    "hmacauth",
    "mtls_auth",
    "mtls-auth",
    "mtlsauth",
];

/// Ferrum Edge built-in auth plugin ids. Matching is case-insensitive against
/// the plugin's `plugin_name` field.
pub fn default_auth_plugin_names() -> Vec<String> {
    DEFAULT_AUTH_PLUGIN_NAMES
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

pub fn is_default_auth_plugin_name(plugin_name: &str) -> bool {
    let plugin_name = plugin_name.to_ascii_lowercase();
    DEFAULT_AUTH_PLUGIN_NAMES.contains(&plugin_name.as_str())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForbidTlsVerifyDisabledRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowedProxyPluginsRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub allowed_plugin_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowedBackendDomainsRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
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
    #[serde(default)]
    pub allowed_proxy_plugins: AllowedProxyPluginsRuleConfig,
    #[serde(default)]
    pub allowed_backend_domains: AllowedBackendDomainsRuleConfig,
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

/// The set of repo-permission strings GitHub's API returns, ordered from
/// weakest to strongest. Matches the /collaborators/{login}/permission
/// endpoint's possible responses.
pub const VALID_PERMISSIONS: &[&str] = &["read", "triage", "write", "maintain", "admin"];

impl OverrideConfig {
    /// Returns the rank of a permission string, or `None` for an unknown
    /// value. Caller decides how to handle unknowns — never treat them as
    /// rank 0 (same as "read"), because that would silently satisfy any
    /// required threshold that was misspelled in config.
    pub fn permission_rank(permission: &str) -> Option<u8> {
        VALID_PERMISSIONS
            .iter()
            .position(|p| *p == permission)
            .map(|i| i as u8)
    }

    /// Is the labeler's actual permission sufficient to satisfy the
    /// configured requirement?
    ///
    /// Fail-closed on either side:
    /// - Unknown `actual` (an API response we don't recognize) → false.
    /// - Unknown `required_permission` (misspelled config) → false.
    ///
    /// The load-time validator in [`validate_overrides`] should catch the
    /// misspelled-config case before this function ever runs, but
    /// fail-closed here is the defense-in-depth.
    pub fn is_sufficient(&self, actual: &str) -> bool {
        match (
            Self::permission_rank(actual),
            Self::permission_rank(&self.required_permission),
        ) {
            (Some(a), Some(r)) => a >= r,
            _ => false,
        }
    }
}

fn validate_overrides(cfg: &OverrideConfig) -> crate::error::Result<()> {
    if OverrideConfig::permission_rank(&cfg.required_permission).is_none() {
        return Err(crate::error::Error::Config(format!(
            "overrides.required_permission='{}' is not a valid GitHub repo permission. Must be one of: {}",
            cfg.required_permission,
            VALID_PERMISSIONS.join(", ")
        )));
    }
    Ok(())
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
    let loaded = load_raw(path)?;
    validate_overrides(&loaded.overrides)?;
    Ok(Some(loaded))
}

fn load_raw(path: &Path) -> crate::error::Result<PolicyConfig> {
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
    Ok(config)
}
