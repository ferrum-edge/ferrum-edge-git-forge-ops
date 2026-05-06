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

    fn proxy_has_auth(&self, cfg: &GatewayConfig, proxy: &Proxy) -> bool {
        // Explicit allowlist matching keeps valid auth plugin ids such as
        // `jwt` accepted while rejecting unrelated names that merely contain
        // auth-like substrings. Matching is case-insensitive against the
        // allowlist entries.
        let allowlist: Vec<String> = self
            .config
            .auth_plugin_names
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();

        let in_scope = |plugin: &PluginConfig| -> bool {
            // A disabled auth plugin provides no authentication — the gateway
            // skips it on every request. Treating it as "satisfies auth"
            // would let an attacker commit a plugin with enabled=false and
            // pass this policy while the proxy actually accepts unauthenticated
            // traffic.
            if !plugin.enabled {
                return false;
            }
            if !allowlist.contains(&plugin.plugin_name.to_ascii_lowercase()) {
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
            if !self.proxy_has_auth(cfg, proxy) {
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
