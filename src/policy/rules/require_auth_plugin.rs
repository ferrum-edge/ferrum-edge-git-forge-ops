use crate::config::schema::Proxy;
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    auth_coverage, http_family_auth_plugin_names, plugin_instance_list, AuthCoverage,
    STREAM_AUTH_PLUGIN_NAMES,
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
    /// applicability (an authenticator only guards the request protocols the
    /// gateway runs it on) are delegated to the shared `auth_coverage`
    /// classification.
    fn coverage<'a>(&self, cfg: &'a GatewayConfig, proxy: &Proxy) -> AuthCoverage<'a> {
        auth_coverage(cfg, proxy, &self.config.auth_allowlist())
    }
}

/// `; authenticators that do not authenticate … were ignored: …`, or nothing.
fn ignored_suffix(coverage: &AuthCoverage<'_>, traffic: &str) -> String {
    if coverage.inapplicable.is_empty() {
        return String::new();
    }
    format!(
        "; authenticators that do not authenticate {traffic} were ignored: {}",
        plugin_instance_list(&coverage.inapplicable)
    )
}

/// Finding text and remediation for a proxy that is not authenticated.
fn describe(proxy: &Proxy, coverage: &AuthCoverage<'_>) -> (String, String) {
    let id = proxy.id.as_str();
    let ns = proxy.namespace.as_str();
    let transport = coverage.transport.as_str();
    let http_family = http_family_auth_plugin_names().join(", ");
    let custom = "or declare a custom authenticator's protocols under \
                  require_auth_plugin.custom_auth_plugin_protocols";

    if !coverage.transport.is_stream() {
        if coverage.applicable.is_empty() {
            let skipped = ignored_suffix(coverage, "its requests");
            return (
                format!(
                    "proxy {id} in namespace {ns} has no enabled authentication plugin in its effective plugin list{skipped}"
                ),
                format!(
                    "Attach an auth plugin ({http_family}) to proxy {id}, or add a global one in namespace {ns}"
                ),
            );
        }
        let uncovered = crate::plugin_catalog::protocol_list(&coverage.uncovered);
        return (
            format!(
                "proxy {id} in namespace {ns} has no enabled authentication plugin that runs on its {uncovered} requests; the gateway skips its authenticators ({}) for them, so they reach the backend unauthenticated",
                plugin_instance_list(&coverage.applicable)
            ),
            format!(
                "Attach an authenticator that runs on HTTP, gRPC and WebSocket requests ({http_family}) to proxy {id}, {custom}"
            ),
        );
    }

    let terminate = "terminate TLS/DTLS on its listener (frontend_tls: true, passthrough: false)";
    if coverage.applicable.is_empty() {
        let skipped = ignored_suffix(coverage, &format!("{transport} connections"));
        return (
            format!(
                "{transport} stream proxy {id} in namespace {ns} has no enabled authentication plugin that runs on its listener{skipped}"
            ),
            format!(
                "Attach a stream authenticator ({}) to proxy {id} and {terminate}, {custom}",
                STREAM_AUTH_PLUGIN_NAMES.join(", ")
            ),
        );
    }

    (
        format!(
            "{transport} stream proxy {id} in namespace {ns} carries stream authenticators ({}), but its listener does not terminate TLS/DTLS, so no client certificate reaches them and no identity is established",
            plugin_instance_list(&coverage.applicable)
        ),
        format!("Configure proxy {id} to {terminate}"),
    )
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
