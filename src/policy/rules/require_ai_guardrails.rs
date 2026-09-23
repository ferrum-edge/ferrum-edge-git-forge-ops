use crate::config::schema::PluginConfig;
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    allows_uninspectable_body, cfg_bool, cfg_str, effective_plugins, is_ai_plugin,
};
use crate::policy::config::RequireAiGuardrailsRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct RequireAiGuardrailsRule {
    config: RequireAiGuardrailsRuleConfig,
}

impl RequireAiGuardrailsRule {
    pub fn new(config: RequireAiGuardrailsRuleConfig) -> Self {
        Self { config }
    }

    /// A guardrail that is attached but configured to observe rather than
    /// refuse does not satisfy the requirement. Each escape hatch below flips
    /// a gateway default that fails closed.
    fn neutered_reason(plugin: &PluginConfig) -> Option<String> {
        let cfg = &plugin.config;
        if cfg_str(cfg, &["mode"]).as_deref() == Some("dry_run") {
            return Some("mode: dry_run".to_string());
        }
        if let Some(on_error) = cfg_str(cfg, &["on_error"]) {
            if on_error == "warn" || on_error == "allow" {
                return Some(format!("on_error: {on_error}"));
            }
        }
        if cfg_str(cfg, &["streaming_response"]).as_deref() == Some("skip") {
            return Some("streaming_response: skip".to_string());
        }
        if allows_uninspectable_body(cfg) {
            return Some("fail_on_uninspectable_body: false".to_string());
        }
        if cfg_bool(cfg, &["privacy", "log_raw_text"]) == Some(true) {
            return Some("privacy.log_raw_text: true".to_string());
        }
        if cfg_str(cfg, &["action"]).as_deref() == Some("warn") {
            return Some("action: warn".to_string());
        }
        if cfg_str(cfg, &["default_action"]).as_deref() == Some("allow") {
            return Some("default_action: allow".to_string());
        }
        if let Some(fail) = cfg_str(cfg, &["approval", "fail_on_error"]) {
            if fail == "warn" || fail == "allow" {
                return Some(format!("approval.fail_on_error: {fail}"));
            }
        }
        None
    }
}

impl PolicyCheck for RequireAiGuardrailsRule {
    fn rule_id(&self) -> &str {
        "require_ai_guardrails"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }
        if self
            .config
            .guardrail_plugin_names
            .iter()
            .all(|s| s.trim().is_empty())
        {
            return vec![crate::policy::empty_allowlist_finding(
                self.rule_id(),
                "guardrail_plugin_names",
            )];
        }

        let guardrails: Vec<String> = self
            .config
            .guardrail_plugin_names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        let guardrail_list = guardrails.join(", ");

        for proxy in &cfg.proxies {
            let effective = effective_plugins(cfg, proxy);
            if !effective
                .iter()
                .any(|plugin| is_ai_plugin(&plugin.plugin_name))
            {
                continue;
            }

            let attached: Vec<&&PluginConfig> = effective
                .iter()
                .filter(|plugin| guardrails.contains(&plugin.plugin_name.to_ascii_lowercase()))
                .collect();

            if attached.is_empty() {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: format!(
                        "proxy {} in namespace {} carries AI plugins but no content guardrail (none of: {guardrail_list})",
                        proxy.id, proxy.namespace
                    ),
                    remediation: Some(format!(
                        "Attach one of {guardrail_list} to proxy {} (or a global instance in namespace {})",
                        proxy.id, proxy.namespace
                    )),
                    overridden_by: None,
                });
                continue;
            }

            // The requirement is met by the route as a whole: one effective,
            // enforcing guardrail protects it, so an observing companion (a
            // dry-run firewall alongside an enforcing shield) is not a finding.
            // Only when every attached guardrail is neutered does the route lack
            // enforcement, and then one finding names each ineffective instance.
            let attached_count = attached.len();
            let ineffective: Vec<(&&PluginConfig, String)> = attached
                .into_iter()
                .filter_map(|plugin| Self::neutered_reason(plugin).map(|reason| (plugin, reason)))
                .collect();

            if ineffective.len() < attached_count {
                continue;
            }

            let plural = ineffective.len() > 1;
            let descriptions: Vec<String> = ineffective
                .iter()
                .map(|(plugin, reason)| {
                    format!("{} plugin {} has {reason}", plugin.plugin_name, plugin.id)
                })
                .collect();
            let plugin_ids: Vec<&str> = ineffective
                .iter()
                .map(|(plugin, _)| plugin.id.as_str())
                .collect();

            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: self.config.severity,
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                namespace: proxy.namespace.clone(),
                message: format!(
                    "proxy {} in namespace {} is guarded by {} — the guardrail{} observe{} instead of refusing",
                    proxy.id,
                    proxy.namespace,
                    descriptions.join("; "),
                    if plural { "s" } else { "" },
                    if plural { "" } else { "s" },
                ),
                remediation: Some(format!(
                    "Remove the escape hatch from plugin{} {} so {} keep{} the gateway's fail-closed default",
                    if plural { "s" } else { "" },
                    plugin_ids.join(", "),
                    if plural { "they" } else { "it" },
                    if plural { "" } else { "s" },
                )),
                overridden_by: None,
            });
        }

        findings
    }
}
