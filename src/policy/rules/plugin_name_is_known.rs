use crate::config::GatewayConfig;
use crate::plugin_catalog::{is_builtin, is_reserved, is_retired, RETIRED_PLUGIN_NAMES};
use crate::policy::config::PluginNameIsKnownRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding, Severity};

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

        let extra: Vec<String> = self
            .config
            .allowed_extra_plugin_names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();

        for plugin in &cfg.plugin_configs {
            let name = plugin.plugin_name.as_str();

            // Retired and reserved names are load errors at the gateway, so
            // they are reported at `error` regardless of configured severity —
            // and regardless of `enabled`, because the name alone is fatal.
            if is_retired(name) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Error,
                    kind: "PluginConfig".to_string(),
                    id: plugin.id.clone(),
                    namespace: plugin.namespace.clone(),
                    message: format!(
                        "plugin {} in namespace {} uses plugin_name: {name}, which was retired ({}); the gateway fails to load a config that mentions it",
                        plugin.id,
                        plugin.namespace,
                        RETIRED_PLUGIN_NAMES.join(", ")
                    ),
                    remediation: Some(match name {
                        "oauth2_auth" => {
                            "Replace with oauth2_introspection or oidc_relying_party".to_string()
                        }
                        "semantic_ai_firewall" => "Rename to ai_semantic_firewall".to_string(),
                        _ => "Remove this plugin config".to_string(),
                    }),
                    overridden_by: None,
                });
                continue;
            }

            if is_reserved(name) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Error,
                    kind: "PluginConfig".to_string(),
                    id: plugin.id.clone(),
                    namespace: plugin.namespace.clone(),
                    message: format!(
                        "plugin {} in namespace {} uses plugin_name: {name}, which is reserved for mesh auto-injection and must not be configured by hand",
                        plugin.id, plugin.namespace
                    ),
                    remediation: Some(
                        "Delete this plugin config; the mesh data plane injects it when the topology requires it"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
                continue;
            }

            if is_builtin(name) || extra.contains(&name.to_ascii_lowercase()) {
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
