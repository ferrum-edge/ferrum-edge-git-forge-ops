use crate::config::GatewayConfig;
use crate::plugin_catalog::{is_builtin, is_reserved, is_retired};
use crate::policy::config::PluginNameIsKnownRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct PluginNameIsKnownRule {
    config: PluginNameIsKnownRuleConfig,
}

impl PluginNameIsKnownRule {
    pub fn new(config: PluginNameIsKnownRuleConfig) -> Self {
        Self { config }
    }
}

impl PolicyCheck for PluginNameIsKnownRule {
    fn rule_id(&self) -> &str {
        "plugin_name_is_known"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        // Custom plugin names are compared exactly, matching Ferrum Edge's
        // generated `create_custom_plugin` match arms: the gateway loads a
        // custom plugin only when the serialized `plugin_name` equals the
        // compiled stem, so a case variant is not loadable even when the
        // correctly cased name is allowed here.
        let extra: &[String] = &self.config.allowed_extra_plugin_names;

        for plugin in &cfg.plugin_configs {
            let name = plugin.plugin_name.as_str();

            // The always-on security audit owns these admission errors, even
            // for disabled instances/rules. Do not duplicate them as policy
            // findings or let an extra-name allowlist downgrade them.
            if is_retired(name) || is_reserved(name) {
                continue;
            }

            if is_builtin(name) || extra.iter().any(|allowed| allowed == name) {
                continue;
            }

            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: self.config.severity,
                kind: "PluginConfig".to_string(),
                id: plugin.id.clone(),
                namespace: plugin.namespace.clone(),
                message: format!(
                    "plugin {} in namespace {} uses plugin_name: {name}, which is not one of the gateway's built-in plugins",
                    plugin.id, plugin.namespace
                ),
                remediation: Some(
                    "Fix the spelling, or list the name under allowed_extra_plugin_names if it is a custom plugin compiled into your gateway build"
                        .to_string(),
                ),
                overridden_by: None,
            });
        }

        findings
    }
}
