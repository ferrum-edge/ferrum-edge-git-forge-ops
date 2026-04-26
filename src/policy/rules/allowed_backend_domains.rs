use crate::config::GatewayConfig;
use crate::policy::config::AllowedBackendDomainsRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

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

        for proxy in &cfg.proxies {
            // When a proxy delegates to an upstream, backend_host is schema
            // filler rather than the routed backend. The upstream target loop
            // below enforces the actual destinations.
            if proxy.upstream_id.is_some() {
                continue;
            }
            if !Self::is_allowed(&proxy.backend_host, &allowed_domains) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: format!(
                        "backend_host={} is not in the allowed domain list ({allowed})",
                        proxy.backend_host
                    ),
                    remediation: Some(format!(
                        "Use a backend_host matching one of these domains: {allowed}"
                    )),
                    overridden_by: None,
                });
            }
        }

        for upstream in &cfg.upstreams {
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
