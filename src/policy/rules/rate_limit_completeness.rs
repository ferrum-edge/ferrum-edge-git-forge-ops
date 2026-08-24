use crate::config::schema::PluginConfig;
use crate::config::GatewayConfig;
use crate::plugin_catalog::{cfg_array, cfg_at, cfg_str};
use crate::policy::config::RateLimitCompletenessRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

/// Budget fields that used to live at the top level of a `rate_limiting`
/// config. The gateway now declares a closed top-level key set, so any of
/// these outside `limits[]` is a hard admission failure — a config that
/// applied cleanly before this gateway release now rejects outright.
const LEGACY_TOP_LEVEL_FIELDS: &[&str] = &[
    "requests_per_second",
    "requests_per_minute",
    "requests_per_hour",
    "window_seconds",
    "max_requests",
    "consumer_limits",
];

/// Per-rule budget spellings inside `limits[]`.
const RULE_BUDGET_FIELDS: &[&str] = &[
    "requests_per_second",
    "requests_per_minute",
    "requests_per_hour",
];

pub struct RateLimitCompletenessRule {
    config: RateLimitCompletenessRuleConfig,
}

impl RateLimitCompletenessRule {
    pub fn new(config: RateLimitCompletenessRuleConfig) -> Self {
        Self { config }
    }

    fn finding(
        &self,
        plugin: &PluginConfig,
        message: String,
        remediation: String,
    ) -> PolicyFinding {
        PolicyFinding {
            rule_id: "rate_limit_completeness".to_string(),
            severity: self.config.severity,
            kind: "PluginConfig".to_string(),
            id: plugin.id.clone(),
            namespace: plugin.namespace.clone(),
            message,
            remediation: Some(remediation),
            overridden_by: None,
        }
    }

    fn check_rate_limiting(&self, plugin: &PluginConfig, findings: &mut Vec<PolicyFinding>) {
        let legacy: Vec<&str> = LEGACY_TOP_LEVEL_FIELDS
            .iter()
            .copied()
            .filter(|field| cfg_at(&plugin.config, &[field]).is_some())
            .collect();
        if !legacy.is_empty() {
            findings.push(self.finding(
                plugin,
                format!(
                    "rate_limiting plugin {} in namespace {} sets {} at the top level of its config; the gateway now rejects unknown top-level keys",
                    plugin.id,
                    plugin.namespace,
                    legacy.join(", ")
                ),
                "Move the budget into a limits[] entry with scope: default (top-level budget fields were removed)"
                    .to_string(),
            ));
            // The legacy shape has no `limits`, so the checks below would only
            // repeat the same problem in different words.
            return;
        }

        let Some(limits) = cfg_array(&plugin.config, &["limits"]) else {
            findings.push(self.finding(
                plugin,
                format!(
                    "rate_limiting plugin {} in namespace {} has no limits[] array — the plugin loads but enforces nothing",
                    plugin.id, plugin.namespace
                ),
                "Add a limits[] entry with scope: default and either window_seconds+max_requests or requests_per_second/minute/hour"
                    .to_string(),
            ));
            return;
        };

        if limits.is_empty() {
            findings.push(self.finding(
                plugin,
                format!(
                    "rate_limiting plugin {} in namespace {} has an empty limits[] array",
                    plugin.id, plugin.namespace
                ),
                "Add a limits[] entry with scope: default".to_string(),
            ));
            return;
        }

        if !limits
            .iter()
            .any(|rule| cfg_str(rule, &["scope"]).as_deref() == Some("default"))
        {
            findings.push(self.finding(
                plugin,
                format!(
                    "rate_limiting plugin {} in namespace {} has no limits[] entry with scope: default — unlisted consumers are unlimited",
                    plugin.id, plugin.namespace
                ),
                "Add a limits[] entry with scope: default as the catch-all budget".to_string(),
            ));
        }

        for (idx, rule) in limits.iter().enumerate() {
            let has_window = cfg_at(rule, &["window_seconds"]).is_some()
                && cfg_at(rule, &["max_requests"]).is_some();
            let has_rate = RULE_BUDGET_FIELDS
                .iter()
                .any(|field| cfg_at(rule, &[field]).is_some());
            if !has_window && !has_rate {
                findings.push(self.finding(
                    plugin,
                    format!(
                        "rate_limiting plugin {} in namespace {} has limits[{idx}] with no budget — neither window_seconds+max_requests nor requests_per_second/minute/hour",
                        plugin.id, plugin.namespace
                    ),
                    format!("Give limits[{idx}] a window_seconds + max_requests pair, or a requests_per_* value"),
                ));
            }
        }
    }

    fn check_ai_rate_limiter(&self, plugin: &PluginConfig, findings: &mut Vec<PolicyFinding>) {
        if cfg_at(&plugin.config, &["token_limit"]).is_none() {
            findings.push(self.finding(
                plugin,
                format!(
                    "ai_rate_limiter plugin {} in namespace {} has no token_limit — the plugin's only budget is unset",
                    plugin.id, plugin.namespace
                ),
                "Set config.token_limit to the per-window token budget".to_string(),
            ));
        }

        if cfg_str(&plugin.config, &["on_unmetered_response"]).as_deref() == Some("charge_estimate")
        {
            findings.push(self.finding(
                plugin,
                format!(
                    "ai_rate_limiter plugin {} in namespace {} has on_unmetered_response: charge_estimate — responses without usage metadata are billed against a guess, not measured usage",
                    plugin.id, plugin.namespace
                ),
                "Use a metered provider or set config.on_unmetered_response to a fail-closed value"
                    .to_string(),
            ));
        }
    }
}

impl PolicyCheck for RateLimitCompletenessRule {
    fn rule_id(&self) -> &str {
        "rate_limit_completeness"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        for plugin in &cfg.plugin_configs {
            if !plugin.enabled {
                continue;
            }
            match plugin.plugin_name.as_str() {
                "rate_limiting" => self.check_rate_limiting(plugin, &mut findings),
                "ai_rate_limiter" => self.check_ai_rate_limiter(plugin, &mut findings),
                _ => continue,
            }

            // Both limiters can fall back to a per-process counter when Redis
            // is unreachable, which silently multiplies the effective budget by
            // the replica count.
            if cfg_str(&plugin.config, &["redis_failure_policy"]).as_deref()
                == Some("local_fallback")
            {
                findings.push(self.finding(
                    plugin,
                    format!(
                        "{} plugin {} in namespace {} has redis_failure_policy: local_fallback — a Redis outage degrades the shared budget to a per-replica one",
                        plugin.plugin_name, plugin.id, plugin.namespace
                    ),
                    "Set config.redis_failure_policy to the fail-closed value so the budget stays shared"
                        .to_string(),
                ));
            }
        }

        findings
    }
}
