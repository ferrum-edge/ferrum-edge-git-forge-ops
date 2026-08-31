use crate::config::GatewayConfig;
use crate::policy::config::AllowedBackendDomainsRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};
use std::collections::HashSet;

pub struct AllowedBackendDomainsRule {
    config: AllowedBackendDomainsRuleConfig,
}

impl AllowedBackendDomainsRule {
    pub fn new(config: AllowedBackendDomainsRuleConfig) -> Self {
        Self { config }
    }

    fn normalize_domain(value: &str) -> String {
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    }

    fn domain_matches(host: &str, pattern: &str) -> bool {
        if host.is_empty() || pattern.is_empty() {
            return false;
        }
        if pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return host
                .strip_suffix(suffix)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or(false);
        }
        host == pattern
    }

    fn is_allowed(host: &str, allowed_domains: &[String]) -> bool {
        let host = Self::normalize_domain(host);
        allowed_domains
            .iter()
            .any(|pattern| Self::domain_matches(&host, pattern))
    }
}

impl PolicyCheck for AllowedBackendDomainsRule {
    fn rule_id(&self) -> &str {
        "allowed_backend_domains"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled || self.config.allowed_domains.is_empty() {
            return findings;
        }

        let allowed_domains: Vec<String> = self
            .config
            .allowed_domains
            .iter()
            .map(|domain| Self::normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect();
        if allowed_domains.is_empty() {
            return findings;
        }
        let allowed = allowed_domains.join(", ");

        let declared_upstreams: HashSet<(&str, &str)> = cfg
            .upstreams
            .iter()
            .map(|upstream| (upstream.namespace.as_str(), upstream.id.as_str()))
            .collect();

        for proxy in &cfg.proxies {
            let upstream_id = proxy.upstream_id.as_deref();
            let uses_resolved_upstream = upstream_id.is_some_and(|upstream_id| {
                !upstream_id.trim().is_empty()
                    && declared_upstreams.contains(&(proxy.namespace.as_str(), upstream_id))
            });

            // When a proxy delegates to a declared upstream in the same
            // namespace, backend_host is schema filler rather than the routed
            // backend. Authored targets are checked below, and dynamic service
            // discovery is rejected because its runtime targets cannot be
            // proven against this static allowlist.
            if !uses_resolved_upstream && !Self::is_allowed(&proxy.backend_host, &allowed_domains) {
                let (message, remediation) = if let Some(upstream_id) = upstream_id {
                    (
                        format!(
                            "upstream_id '{upstream_id}' is not declared in namespace '{}'; fallback backend_host='{}' is not in the allowed domain list ({allowed})",
                            proxy.namespace, proxy.backend_host
                        ),
                        format!(
                            "Declare upstream_id '{upstream_id}' in namespace '{}' or use a backend_host matching one of these domains: {allowed}",
                            proxy.namespace
                        ),
                    )
                } else {
                    (
                        format!(
                            "backend_host='{}' is not in the allowed domain list ({allowed})",
                            proxy.backend_host
                        ),
                        format!("Use a backend_host matching one of these domains: {allowed}"),
                    )
                };
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

            if let Some(dns_override) = proxy.dns_override.as_deref() {
                if !Self::is_allowed(dns_override, &allowed_domains) {
                    findings.push(PolicyFinding {
                        rule_id: self.rule_id().to_string(),
                        severity: self.config.severity,
                        kind: "Proxy".to_string(),
                        id: proxy.id.clone(),
                        namespace: proxy.namespace.clone(),
                        message: format!(
                            "dns_override='{dns_override}' is an effective dial destination outside the allowed domain list ({allowed})"
                        ),
                        remediation: Some(format!(
                            "Remove dns_override or add its exact IP address to allowed_domains (currently: {allowed})"
                        )),
                        overridden_by: None,
                    });
                }
            }
        }

        for upstream in &cfg.upstreams {
            if upstream.service_discovery.is_some() {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Upstream".to_string(),
                    id: upstream.id.clone(),
                    namespace: upstream.namespace.clone(),
                    message: format!(
                        "service_discovery can publish runtime targets that cannot be verified against the allowed domain list ({allowed})"
                    ),
                    remediation: Some(
                        "Remove service_discovery and declare allowed targets statically, or use the reviewed policy override only after enforcing equivalent runtime egress controls"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
            }

            for target in &upstream.targets {
                if Self::is_allowed(&target.host, &allowed_domains) {
                    continue;
                }
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Upstream".to_string(),
                    id: upstream.id.clone(),
                    namespace: upstream.namespace.clone(),
                    message: format!(
                        "target host={} is not in the allowed domain list ({allowed})",
                        target.host
                    ),
                    remediation: Some(format!(
                        "Use upstream target hosts matching one of these domains: {allowed}"
                    )),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
