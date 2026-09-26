use crate::config::schema::{PluginConfig, Proxy};
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    auth_coverage, AuthCoverage, AUTH_PLUGIN_NAMES, STREAM_AUTH_PLUGIN_NAMES,
};
use crate::policy::config::RequireAuthPluginRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct RequireAuthPluginRule {
    config: RequireAuthPluginRuleConfig,
}

impl RequireAuthPluginRule {
    pub fn new(config: RequireAuthPluginRuleConfig) -> Self {
        Self { config }
    }

    /// Explicit allowlist matching keeps valid auth plugin ids accepted while
    /// rejecting unrelated names that merely contain auth-like substrings.
    /// Matching is case-insensitive against the allowlist.
    ///
    /// Scope resolution (including the `enabled` guard, without which an
    /// attacker could commit `enabled: false` on an auth plugin and pass this
    /// policy while the proxy accepts unauthenticated traffic) and protocol
    /// applicability (an HTTP-only authenticator never runs on a TCP or UDP
    /// listener) are delegated to the shared `auth_coverage` classification.
    fn coverage<'a>(&self, cfg: &'a GatewayConfig, proxy: &Proxy) -> AuthCoverage<'a> {
        auth_coverage(cfg, proxy, &self.config.normalized_auth_plugin_names())
    }
}

/// Finding text and remediation for a proxy that is not authenticated.
fn describe(proxy: &Proxy, coverage: &AuthCoverage<'_>) -> (String, String) {
    let id = proxy.id.as_str();
    let ns = proxy.namespace.as_str();
    let transport = coverage.transport.as_str();

    if !coverage.transport.is_stream() {
        return (
            format!(
                "proxy {id} in namespace {ns} has no enabled authentication plugin in its effective plugin list"
            ),
            format!(
                "Attach an auth plugin ({}) to proxy {id}, or add a global one in namespace {ns}",
                AUTH_PLUGIN_NAMES.join(", ")
            ),
        );
    }

    let terminate = "terminate TLS/DTLS on its listener (frontend_tls: true, passthrough: false)";
    if coverage.applicable.is_empty() {
        let skipped = if coverage.inapplicable.is_empty() {
            String::new()
        } else {
            format!(
                "; authenticators that do not run on {transport} listeners were ignored: {}",
                plugin_list(&coverage.inapplicable)
            )
        };
        return (
            format!(
                "{transport} stream proxy {id} in namespace {ns} has no enabled authentication plugin that runs on its listener{skipped}"
            ),
            format!(
                "Attach a stream authenticator ({}) to proxy {id} and {terminate}",
                STREAM_AUTH_PLUGIN_NAMES.join(", ")
            ),
        );
    }

    (
        format!(
            "{transport} stream proxy {id} in namespace {ns} carries stream authenticators ({}), but its listener does not terminate TLS/DTLS, so no client certificate reaches them and no identity is established",
            plugin_list(&coverage.applicable)
        ),
        format!("Configure proxy {id} to {terminate}"),
    )
}

fn plugin_list(plugins: &[&PluginConfig]) -> String {
    plugins
        .iter()
        .map(|plugin| format!("{} ({})", plugin.plugin_name, plugin.id))
        .collect::<Vec<_>>()
        .join(", ")
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
            let coverage = self.coverage(cfg, proxy);
            if coverage.is_authenticated() {
                continue;
            }
            let (message, remediation) = describe(proxy, &coverage);
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: self.config.severity,
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                namespace: proxy.namespace.clone(),
                message,
                remediation: Some(remediation),
                overridden_by: None,
            });
        }

        findings
    }
}
