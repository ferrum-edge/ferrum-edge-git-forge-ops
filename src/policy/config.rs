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

/// Spellings that are not real `plugin_name` values but appear in
/// hand-written policy files and in this repo's own examples from before the
/// catalog was pinned down. Tolerated so an upgrade does not suddenly report
/// every proxy as unauthenticated, but they can never match a live plugin —
/// `plugin_name_is_known` flags them separately as unknown names.
const LEGACY_AUTH_PLUGIN_ALIASES: &[&str] = &[
    "jwt",
    "oauth2",
    "oidc",
    "basic-auth",
    "basic auth",
    "basicauth",
    "key-auth",
    "keyauth",
    "ldap-auth",
    "ldapauth",
    "hmac-auth",
    "hmacauth",
    "mtls-auth",
    "mtlsauth",
];

/// Ferrum Edge built-in auth plugin ids. Matching is case-insensitive against
/// the plugin's `plugin_name` field.
///
/// The canonical eleven come from [`crate::plugin_catalog::AUTH_PLUGIN_NAMES`]
/// so this list cannot drift from the gateway's registry; the legacy aliases
/// are appended for backwards compatibility with older policy files.
pub fn default_auth_plugin_names() -> Vec<String> {
    crate::plugin_catalog::AUTH_PLUGIN_NAMES
        .iter()
        .chain(LEGACY_AUTH_PLUGIN_ALIASES.iter())
        .map(|name| (*name).to_string())
        .collect()
}

pub fn is_default_auth_plugin_name(plugin_name: &str) -> bool {
    let plugin_name = plugin_name.to_ascii_lowercase();
    crate::plugin_catalog::AUTH_PLUGIN_NAMES.contains(&plugin_name.as_str())
        || LEGACY_AUTH_PLUGIN_ALIASES.contains(&plugin_name.as_str())
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

/// An exact `(namespace, id)` acknowledgment that weakens a destination check,
/// so a typo must fail loudly instead of silently acknowledging nothing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpstreamAllowance {
    pub namespace: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowedBackendDomainsRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Discovery-backed upstreams whose runtime destinations are constrained
    /// by an equivalent external egress control. Entries match exact resource
    /// identity so acknowledging one upstream cannot weaken the whole rule.
    #[serde(default)]
    pub allowed_service_discovery_upstreams: Vec<UpstreamAllowance>,
    /// Hosts or IP literals allowed for statically configured service-discovery
    /// control planes such as `consul.address`. When empty, control-plane hosts
    /// are checked against `allowed_domains`, which also permits those hosts as
    /// direct data-plane destinations; keep a dedicated list to avoid that.
    #[serde(default)]
    pub allowed_service_discovery_control_plane_addresses: Vec<String>,
    /// Upstreams that intentionally live outside this repository's desired
    /// document, such as shared-mode or OpenAPI-spec-owned resources. Entries
    /// match exact resource identity; their runtime destinations must be
    /// constrained by an equivalent external egress control.
    #[serde(default)]
    pub allowed_external_upstreams: Vec<UpstreamAllowance>,
    /// Exact IP literals allowed as per-proxy DNS pins. A pin must be an IP
    /// literal either way; when this list is empty the rule checks pins against
    /// the IP-literal entries of `allowed_domains` (plus a bare `*` catch-all),
    /// and reports a configuration finding when there are none.
    #[serde(default)]
    pub allowed_dns_override_addresses: Vec<String>,
}

/// `waf_enforcement` — a WAF that is attached but not blocking.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WafEnforcementRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    /// When set, also require `paranoia_level` to be at least this value
    /// (the gateway accepts 1-4 and defaults to 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_paranoia_level: Option<u8>,
}

fn default_ai_guardrail_names() -> Vec<String> {
    crate::plugin_catalog::AI_GUARDRAIL_PLUGIN_NAMES
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

/// `require_ai_guardrails` — AI routes must carry a content guardrail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequireAiGuardrailsRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
    /// Plugin names that satisfy the guardrail requirement.
    #[serde(default = "default_ai_guardrail_names")]
    pub guardrail_plugin_names: Vec<String>,
}

impl Default for RequireAiGuardrailsRuleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            severity: Severity::default(),
            guardrail_plugin_names: default_ai_guardrail_names(),
        }
    }
}

/// `rate_limit_completeness` — a rate limiter that declares no usable budget.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitCompletenessRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub severity: Severity,
}

/// `plugin_name_is_known` — the name must be one the gateway will load.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginNameIsKnownRuleConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Severity for a name that is merely unknown (a custom plugin the
    /// gateway build may or may not carry). Retired and reserved names are
    /// always reported at `error`: the gateway refuses to load them, so no
    /// configured severity can make them acceptable.
    #[serde(default)]
    pub severity: Severity,
    /// Custom plugin names compiled into this deployment's gateway build.
    /// Listing them here stops the rule reporting them as unknown.
    #[serde(default)]
    pub allowed_extra_plugin_names: Vec<String>,
}

/// `priority_override_range` — the gateway accepts 0..=10000.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PriorityOverrideRangeRuleConfig {
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
    #[serde(default)]
    pub allowed_proxy_plugins: AllowedProxyPluginsRuleConfig,
    #[serde(default)]
    pub allowed_backend_domains: AllowedBackendDomainsRuleConfig,
    #[serde(default)]
    pub waf_enforcement: WafEnforcementRuleConfig,
    #[serde(default)]
    pub require_ai_guardrails: RequireAiGuardrailsRuleConfig,
    #[serde(default)]
    pub rate_limit_completeness: RateLimitCompletenessRuleConfig,
    #[serde(default)]
    pub plugin_name_is_known: PluginNameIsKnownRuleConfig,
    #[serde(default)]
    pub priority_override_range: PriorityOverrideRangeRuleConfig,
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
