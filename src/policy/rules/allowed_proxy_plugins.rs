use std::collections::HashSet;

use crate::config::GatewayConfig;
use crate::plugin_catalog::effective_plugins;
use crate::policy::config::AllowedProxyPluginsRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct AllowedProxyPluginsRule {
    config: AllowedProxyPluginsRuleConfig,
}

impl AllowedProxyPluginsRule {
    pub fn new(config: AllowedProxyPluginsRuleConfig) -> Self {
        Self { config }
    }
}

impl PolicyCheck for AllowedProxyPluginsRule {
    fn rule_id(&self) -> &str {
        "allowed_proxy_plugins"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled || self.config.allowed_plugin_names.is_empty() {
            return findings;
        }

        let allowed: Vec<String> = self
            .config
            .allowed_plugin_names
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let allowed_for_message = allowed.join(", ");
        let plugin_keys: HashSet<(&str, &str)> = cfg
            .plugin_configs
            .iter()
            .map(|plugin| (plugin.namespace.as_str(), plugin.id.as_str()))
            .collect();

        for proxy in &cfg.proxies {
            for assoc in &proxy.plugins {
                if !plugin_keys
                    .contains(&(proxy.namespace.as_str(), assoc.plugin_config_id.as_str()))
                {
                    findings.push(PolicyFinding {
                        rule_id: self.rule_id().to_string(),
                        severity: self.config.severity,
                        kind: "Proxy".to_string(),
                        id: proxy.id.clone(),
                        namespace: proxy.namespace.clone(),
                        message: format!(
                            "plugin {} could not be resolved in namespace {}",
                            assoc.plugin_config_id, proxy.namespace
                        ),
                        remediation: Some(format!(
                            "Reference an existing plugin config in namespace {} whose plugin_name is one of: {allowed_for_message}",
                            proxy.namespace
                        )),
                        overridden_by: None,
                    });
                }
            }
            // Use the same enabled/global/scoped merge as runtime-facing rules.
            for plugin in effective_plugins(cfg, proxy) {
                let plugin_name = &plugin.plugin_name;
                let actual = plugin_name.to_ascii_lowercase();
                if allowed.iter().any(|name| name == &actual) {
                    continue;
                }

                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: format!(
                        "plugin {} uses plugin_name={plugin_name}, which is not in the allowed list ({})",
                        plugin.id,
                        allowed_for_message
                    ),
                    remediation: Some(format!(
                        "Use only effective plugins with plugin_name set to one of: {}",
                        allowed_for_message
                    )),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
