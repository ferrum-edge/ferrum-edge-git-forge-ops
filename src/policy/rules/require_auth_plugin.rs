use crate::config::schema::Proxy;
use crate::config::GatewayConfig;
use crate::plugin_catalog::{effective_plugins, AUTH_PLUGIN_NAMES};
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
        // Explicit allowlist matching keeps valid auth plugin ids accepted
        // while rejecting unrelated names that merely contain auth-like
        // substrings. Matching is case-insensitive against the allowlist.
        //
        // Scope resolution (including the `enabled` guard, without which an
        // attacker could commit `enabled: false` on an auth plugin and pass
        // this policy while the proxy accepts unauthenticated traffic) is
        // delegated to the shared `effective_plugins` merge.
        let allowlist: Vec<String> = self
            .config
            .auth_plugin_names
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();

        effective_plugins(cfg, proxy)
            .into_iter()
            .any(|plugin| allowlist.contains(&plugin.plugin_name.to_ascii_lowercase()))
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
                    message: format!(
                        "proxy {} in namespace {} has no enabled authentication plugin in its effective plugin list",
                        proxy.id, proxy.namespace
                    ),
                    remediation: Some(format!(
                        "Attach an auth plugin ({}) to proxy {}, or add a global one in namespace {}",
                        AUTH_PLUGIN_NAMES.join(", "),
                        proxy.id,
                        proxy.namespace
                    )),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
