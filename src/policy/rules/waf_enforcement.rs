use crate::config::schema::PluginConfig;
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    cfg_u64, waf_has_enforcing_rule, waf_mode, waf_mode_is_passive, waf_skips_oversized_body,
};
use crate::policy::config::WafEnforcementRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct WafEnforcementRule {
    config: WafEnforcementRuleConfig,
}

impl WafEnforcementRule {
    pub fn new(config: WafEnforcementRuleConfig) -> Self {
        Self { config }
    }

    fn check_instance(&self, plugin: &PluginConfig, findings: &mut Vec<PolicyFinding>) {
        let mut push = |message: String, remediation: String| {
            findings.push(PolicyFinding {
                rule_id: "waf_enforcement".to_string(),
                severity: self.config.severity,
                kind: "PluginConfig".to_string(),
                id: plugin.id.clone(),
                namespace: plugin.namespace.clone(),
                message,
                remediation: Some(remediation),
                overridden_by: None,
            });
        };

        // `mode` defaults to `enforce` when absent.
        let mode = waf_mode(&plugin.config);
        match mode.as_str() {
            m if waf_mode_is_passive(m) => {
                push(
                    format!(
                        "waf plugin {} in namespace {} has mode: {mode} — matched requests are recorded but never rejected",
                        plugin.id, plugin.namespace
                    ),
                    "Set config.mode: enforce once the monitor-mode findings have been triaged"
                        .to_string(),
                );
            }
            _ => {
                if !waf_has_enforcing_rule(&plugin.config) {
                    push(
                        format!(
                            "waf plugin {} in namespace {} has mode: enforce but every built-in rule is monitor-only — no rule_modes, rule_overrides, custom_rules or default_rule_action promotes one to enforcement",
                            plugin.id, plugin.namespace
                        ),
                        "Set config.default_rule_action: enforce, or promote individual rules via config.rule_modes"
                            .to_string(),
                    );
                }
            }
        }

        // `paranoia_level` defaults to 1 (the narrowest, lowest-false-positive
        // rule selection).
        if let Some(min) = self.config.min_paranoia_level {
            let actual = cfg_u64(&plugin.config, &["paranoia_level"]).unwrap_or(1);
            if actual < u64::from(min) {
                push(
                    format!(
                        "waf plugin {} in namespace {} has paranoia_level {actual}, below the required minimum of {min}",
                        plugin.id, plugin.namespace
                    ),
                    format!("Set config.paranoia_level to at least {min} (the gateway accepts 1-4)"),
                );
            }
        }

        // `on_body_too_large` defaults to `fail_closed`; `skip` waves through a
        // body the scanner never looked at.
        if waf_skips_oversized_body(&plugin.config) {
            push(
                format!(
                    "waf plugin {} in namespace {} has on_body_too_large: skip — oversized bodies bypass inspection entirely",
                    plugin.id, plugin.namespace
                ),
                "Remove config.on_body_too_large (defaults to fail_closed) or raise config.max_scan_bytes"
                    .to_string(),
            );
        }
    }
}

impl PolicyCheck for WafEnforcementRule {
    fn rule_id(&self) -> &str {
        "waf_enforcement"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        for plugin in &cfg.plugin_configs {
            if plugin.plugin_name != "waf" || !plugin.enabled {
                continue;
            }
            self.check_instance(plugin, &mut findings);
        }

        findings
    }
}
