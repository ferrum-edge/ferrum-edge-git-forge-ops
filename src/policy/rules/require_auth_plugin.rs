use crate::config::schema::Proxy;
use crate::config::{collect_namespaces, GatewayConfig};
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
    /// classification. So is the trigger guard: an authenticator carrying a
    /// `trigger` only runs on the requests it matches, so it never counts,
    /// and an intentionally public route needs a code-owned exemption.
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

/// `; conditional authenticators … were not counted …`, or nothing.
fn conditional_suffix(coverage: &AuthCoverage<'_>) -> String {
    if coverage.conditional.is_empty() {
        return String::new();
    }
    format!(
        "; conditional authenticators carrying a trigger were not counted, because requests their trigger does not match reach the backend unauthenticated: {}",
        plugin_instance_list(&coverage.conditional)
    )
}

/// Remediation clause for a proxy whose authenticators carry a trigger, or
/// nothing.
fn conditional_remedy(coverage: &AuthCoverage<'_>) -> &'static str {
    if coverage.conditional.is_empty() {
        return "";
    }
    ". Remove the trigger from the authenticator; an intentionally public route needs an exact \
     code-owned conditional-auth exemption"
}

/// Finding text and remediation for a proxy that is not authenticated.
fn describe(proxy: &Proxy, coverage: &AuthCoverage<'_>) -> (String, String) {
    let id = proxy.id.as_str();
    let ns = proxy.namespace.as_str();
    let transport = coverage.transport.as_str();
    let http_family = http_family_auth_plugin_names().join(", ");
    let custom = "or declare a custom authenticator's protocols under \
                  require_auth_plugin.custom_auth_plugin_protocols";
    let conditional = conditional_suffix(coverage);
    let remedy = conditional_remedy(coverage);

    if !coverage.transport.is_stream() {
        if coverage.applicable.is_empty() && coverage.conditional.is_empty() {
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
        if coverage.applicable.is_empty() {
            let skipped = ignored_suffix(coverage, "its requests");
            return (
                format!(
                    "proxy {id} in namespace {ns} has no enabled authentication plugin that runs on every request{conditional}{skipped}"
                ),
                format!(
                    "Attach an authenticator without a trigger ({http_family}) to proxy {id}{remedy}"
                ),
            );
        }
        let uncovered = crate::plugin_catalog::protocol_list(&coverage.uncovered);
        return (
            format!(
                "proxy {id} in namespace {ns} has no enabled authentication plugin that runs on its {uncovered} requests; the gateway skips its authenticators ({}) for them, so they reach the backend unauthenticated{conditional}",
                plugin_instance_list(&coverage.applicable)
            ),
            format!(
                "Attach an authenticator that runs on HTTP, gRPC and WebSocket requests ({http_family}) to proxy {id}, {custom}{remedy}"
            ),
        );
    }

    let terminate = "terminate TLS/DTLS on its listener (frontend_tls: true, passthrough: false)";
    if coverage.applicable.is_empty() {
        let skipped = ignored_suffix(coverage, &format!("{transport} connections"));
        return (
            format!(
                "{transport} stream proxy {id} in namespace {ns} has no enabled authentication plugin that runs on every connection to its listener{conditional}{skipped}"
            ),
            format!(
                "Attach a stream authenticator ({}) to proxy {id} and {terminate}, {custom}{remedy}",
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
        let namespaces = collect_namespaces(cfg);
        let auth = self.config.auth_allowlist();
        for exemption in &self.config.conditional_auth_exemptions {
            let (namespace, proxy_id) = exemption.split_once('/').unwrap_or(("", ""));
            if !namespaces.iter().any(|entry| entry == namespace) {
                continue;
            }
            let proxy = cfg
                .proxies
                .iter()
                .find(|proxy| proxy.namespace == namespace && proxy.id == proxy_id);
            let stale = match proxy {
                Some(proxy) => {
                    let coverage = self.coverage(cfg, proxy);
                    coverage.is_authenticated()
                        || coverage.conditional.is_empty()
                        || coverage.conditional_exemption_gap(&auth).is_some()
                }
                None => true,
            };
            if stale {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: crate::policy::Severity::Info,
                    kind: "PolicyConfig".to_string(),
                    id: exemption.clone(),
                    namespace: namespace.to_string(),
                    message: format!(
                        "stale conditional-auth exemption '{exemption}': the proxy is missing, no longer needs it, or has an authentication gap it does not cover"
                    ),
                    remediation: Some(format!(
                        "Remove '{exemption}' from require_auth_plugin.conditional_auth_exemptions"
                    )),
                    overridden_by: None,
                });
            }
        }

        if !self.config.enabled {
            return findings;
        }

        for proxy in &cfg.proxies {
            let coverage = self.coverage(cfg, proxy);
            if coverage.is_authenticated() {
                continue;
            }
            let (message, remediation) = describe(proxy, &coverage);
            let exemption_gap = coverage.conditional_exemption_gap(&auth);
            let listed = self
                .config
                .has_conditional_auth_exemption(&proxy.namespace, &proxy.id);
            let exempt = listed && !coverage.conditional.is_empty() && exemption_gap.is_none();
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: if exempt {
                    crate::policy::Severity::Info
                } else {
                    self.config.severity
                },
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                namespace: proxy.namespace.clone(),
                message: if exempt {
                    format!(
                        "{message}; permitted by conditional-auth exemption '{}/{}'",
                        proxy.namespace, proxy.id
                    )
                } else if listed {
                    format!(
                        concat!(
                            "{message}; conditional-auth exemption '{}/{}' does not ",
                            "cover this gap: {}"
                        ),
                        proxy.namespace,
                        proxy.id,
                        exemption_gap
                            .as_deref()
                            .unwrap_or("no conditional authenticator applies")
                    )
                } else {
                    message
                },
                remediation: if exempt {
                    Some(
                        "Keep this exact proxy identity in the code-owned conditional-auth exemption list; requests outside its trigger remain unauthenticated".to_string(),
                    )
                } else {
                    Some(remediation)
                },
                overridden_by: None,
            });
        }

        findings
    }
}
