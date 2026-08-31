use crate::config::GatewayConfig;
use crate::plugin_catalog::MAX_PRIORITY_OVERRIDE;
use crate::policy::config::PriorityOverrideRangeRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct PriorityOverrideRangeRule {
    config: PriorityOverrideRangeRuleConfig,
}

impl PriorityOverrideRangeRule {
    pub fn new(config: PriorityOverrideRangeRuleConfig) -> Self {
        Self { config }
    }
}

impl PolicyCheck for PriorityOverrideRangeRule {
    fn rule_id(&self) -> &str {
        "priority_override_range"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        // gitforgeops models `priority_override` as a `u16`, so anything up to
        // 65535 round-trips locally. The gateway accepts 0..=10000 and rejects
        // the rest at admission, which is a failure that would otherwise only
        // surface at apply time.
        for plugin in &cfg.plugin_configs {
            let Some(priority) = plugin.priority_override else {
                continue;
            };
            if priority <= MAX_PRIORITY_OVERRIDE {
                continue;
            }
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: self.config.severity,
                kind: "PluginConfig".to_string(),
                id: plugin.id.clone(),
                namespace: plugin.namespace.clone(),
                message: format!(
                    "plugin {} in namespace {} has priority_override {priority}, above the gateway's maximum of {MAX_PRIORITY_OVERRIDE}",
                    plugin.id, plugin.namespace
                ),
                remediation: Some(format!(
                    "Set priority_override to a value in 0..={MAX_PRIORITY_OVERRIDE} (logging band starts at 9000)"
                )),
                overridden_by: None,
            });
        }

        findings
    }
}
