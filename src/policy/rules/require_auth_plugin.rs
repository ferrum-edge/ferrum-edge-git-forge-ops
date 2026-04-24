use crate::config::schema::{PluginConfig, PluginScope, Proxy};
use crate::config::GatewayConfig;
use crate::policy::config::RequireAuthPluginRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct RequireAuthPluginRule {
    config: RequireAuthPluginRuleConfig,
}

impl RequireAuthPluginRule {
    pub fn new(config: RequireAuthPluginRuleConfig) -> Self {
        Self { config }
    }

    fn proxy_has_auth(cfg: &GatewayConfig, proxy: &Proxy) -> bool {
        let in_scope = |plugin: &PluginConfig| -> bool {
            if !plugin.plugin_name.contains("auth") {
                return false;
            }
            if plugin.namespace != proxy.namespace {
                return false;
            }
            match plugin.scope {
                PluginScope::Global => true,
                PluginScope::Proxy => {
                    plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
                        && proxy
                            .plugins
                            .iter()
                            .any(|assoc| assoc.plugin_config_id == plugin.id)
                }
                PluginScope::ProxyGroup => proxy
                    .plugins
                    .iter()
                    .any(|assoc| assoc.plugin_config_id == plugin.id),
            }
        };
        cfg.plugin_configs.iter().any(in_scope)
    }
}

impl PolicyCheck for RequireAuthPluginRule {
    fn rule_id(&self) -> &str {
        "require_auth_plugin"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        for proxy in &cfg.proxies {
            if !Self::proxy_has_auth(cfg, proxy) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: "No authentication plugin attached to this proxy".to_string(),
                    remediation: Some(
                        "Attach an auth plugin (jwt, basic-auth, key-auth, etc.) or a global auth plugin in the same namespace"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
