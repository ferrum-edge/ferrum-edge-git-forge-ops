use crate::config::GatewayConfig;
use crate::policy::config::AllowedBackendDomainsRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

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

    fn normalize_destination(value: &str) -> Option<String> {
        let normalized = Self::normalize_domain(value);
        if Self::parse_ip_literal(&normalized).is_some() {
            return Some(normalized);
        }
        if normalized.is_empty()
            || normalized.starts_with('.')
            || normalized.contains("..")
            || !normalized.chars().all(|character| {
                character.is_alphanumeric() || matches!(character, '.' | '-' | '_')
            })
        {
            return None;
        }
        if normalized.is_ascii() {
            return Some(normalized);
        }

        let parsed = reqwest::Url::parse(&format!("https://{normalized}/")).ok()?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.port().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        parsed.host_str().map(ToOwned::to_owned)
    }

    fn domain_matches(host: &str, pattern: &str) -> bool {
        if host.is_empty() || pattern.is_empty() {
            return false;
        }
        if pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if Self::parse_ip_literal(host).is_some() {
                return false;
            }
            return host
                .strip_suffix(suffix)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or(false);
        }
        match (
            Self::parse_ip_literal(host),
            Self::parse_ip_literal(pattern),
        ) {
            (Some(host), Some(pattern)) => host == pattern,
            _ => host == pattern,
        }
    }

    fn parse_ip_literal(value: &str) -> Option<IpAddr> {
        value
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(value)
            .parse::<IpAddr>()
            .ok()
    }

    fn is_allowed(host: &str, allowed_domains: &[String]) -> bool {
        let Some(host) = Self::normalize_destination(host) else {
            return false;
        };
        allowed_domains
            .iter()
            .any(|pattern| Self::domain_matches(&host, pattern))
    }

    fn classify_domain_allowlist(entries: &[String]) -> (Vec<String>, Vec<String>) {
        let mut valid = Vec::new();
        let mut invalid = Vec::new();
        for entry in entries {
            let trimmed = entry.trim();
            let suffix = trimmed.strip_prefix("*.");
            let candidate = suffix.unwrap_or(trimmed);
            let normalized_candidate = Self::normalize_destination(candidate);
            let normalized = normalized_candidate.as_ref().map(|candidate| {
                if suffix.is_some() {
                    format!("*.{candidate}")
                } else {
                    candidate.clone()
                }
            });
            let is_valid = if trimmed == "*" {
                true
            } else {
                normalized_candidate.is_some()
                    && !(suffix.is_some() && Self::parse_ip_literal(candidate).is_some())
            };
            if is_valid {
                valid.push(normalized.unwrap_or_else(|| "*".to_string()));
            } else {
                invalid.push(entry.clone());
            }
        }
        (valid, invalid)
    }

    fn url_destination_host(address: &str) -> Option<String> {
        let parsed = reqwest::Url::parse(address).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        parsed.host_str().map(ToOwned::to_owned)
    }
}

impl PolicyCheck for AllowedBackendDomainsRule {
    fn rule_id(&self) -> &str {
        "allowed_backend_domains"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        let (allowed_domains, invalid_domains) =
            Self::classify_domain_allowlist(&self.config.allowed_domains);
        if !invalid_domains.is_empty() {
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: crate::policy::Severity::Error,
                kind: "PolicyConfig".to_string(),
                id: self.rule_id().to_string(),
                namespace: "global".to_string(),
                message: format!(
                    "invalid allowed_domains entries were ignored: {}",
                    invalid_domains
                        .iter()
                        .map(|domain| format!("'{domain}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                remediation: Some(
                    "Remove malformed entries or replace them with exact hosts, nonempty '*.suffix' entries, or the literal '*' catch-all"
                        .to_string(),
                ),
                overridden_by: None,
            });
        }
        if allowed_domains.is_empty() {
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: crate::policy::Severity::Error,
                kind: "PolicyConfig".to_string(),
                id: self.rule_id().to_string(),
                namespace: "global".to_string(),
                message: "enabled policy has no valid allowed_domains entries".to_string(),
                remediation: Some(
                    "Add at least one exact host, a nonempty '*.suffix' entry, or the literal '*' catch-all"
                        .to_string(),
                ),
                overridden_by: None,
            });
            return findings;
        }
        let allowed = allowed_domains.join(", ");
        let allow_all = allowed_domains.iter().any(|domain| domain == "*");

        let (configured_control_plane_addresses, invalid_control_plane_addresses) =
            Self::classify_domain_allowlist(
                &self
                    .config
                    .allowed_service_discovery_control_plane_addresses,
            );
        if !invalid_control_plane_addresses.is_empty() {
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: crate::policy::Severity::Error,
                kind: "PolicyConfig".to_string(),
                id: self.rule_id().to_string(),
                namespace: "global".to_string(),
                message: format!(
                    "invalid allowed_service_discovery_control_plane_addresses entries: {}",
                    invalid_control_plane_addresses
                        .iter()
                        .map(|address| format!("'{address}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                remediation: Some(
                    "Use exact control-plane hosts, IP literals, nonempty '*.suffix' entries, or the literal '*' catch-all"
                        .to_string(),
                ),
                overridden_by: None,
            });
        }
        let allowed_control_plane_addresses = if self
            .config
            .allowed_service_discovery_control_plane_addresses
            .is_empty()
        {
            &allowed_domains
        } else {
            &configured_control_plane_addresses
        };
        let allowed_control_planes = allowed_control_plane_addresses.join(", ");

        let mut invalid_dns_override_addresses = Vec::new();
        let configured_dns_override_addresses: Vec<String> = self
            .config
            .allowed_dns_override_addresses
            .iter()
            .filter_map(|address| {
                let trimmed = address.trim();
                if trimmed != address || Self::parse_ip_literal(trimmed).is_none() {
                    invalid_dns_override_addresses.push(address.clone());
                    None
                } else {
                    Some(Self::normalize_domain(trimmed))
                }
            })
            .collect();
        if !invalid_dns_override_addresses.is_empty() {
            findings.push(PolicyFinding {
                rule_id: self.rule_id().to_string(),
                severity: crate::policy::Severity::Error,
                kind: "PolicyConfig".to_string(),
                id: self.rule_id().to_string(),
                namespace: "global".to_string(),
                message: format!(
                    "invalid allowed_dns_override_addresses entries: {}",
                    invalid_dns_override_addresses
                        .iter()
                        .map(|address| format!("'{address}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                remediation: Some(
                    "Use exact IPv4 or IPv6 literals without ports, padding, or wildcards"
                        .to_string(),
                ),
                overridden_by: None,
            });
        }
        let allowed_dns_override_addresses =
            if self.config.allowed_dns_override_addresses.is_empty() {
                &allowed_domains
            } else {
                &configured_dns_override_addresses
            };

        let mut upstream_key_counts: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        for upstream in &cfg.upstreams {
            *upstream_key_counts
                .entry((upstream.namespace.as_str(), upstream.id.as_str()))
                .or_default() += 1;
        }
        for ((namespace, id), count) in &upstream_key_counts {
            if *count > 1 {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: crate::policy::Severity::Error,
                    kind: "PolicyConfig".to_string(),
                    id: self.rule_id().to_string(),
                    namespace: "global".to_string(),
                    message: format!(
                        "duplicate upstream identity '{namespace}:Upstream:{id}' prevents unambiguous allowlist resolution"
                    ),
                    remediation: Some(
                        "Keep exactly one upstream for each (namespace, id) identity".to_string(),
                    ),
                    overridden_by: None,
                });
            }
        }
        let declared_upstreams: BTreeMap<(&str, &str), _> = cfg
            .upstreams
            .iter()
            .filter(|upstream| {
                upstream_key_counts.get(&(upstream.namespace.as_str(), upstream.id.as_str()))
                    == Some(&1)
            })
            .map(|upstream| {
                (
                    (upstream.namespace.as_str(), upstream.id.as_str()),
                    upstream,
                )
            })
            .collect();
        let mut allowed_service_discovery_upstreams = BTreeSet::new();
        for upstream in &self.config.allowed_service_discovery_upstreams {
            if upstream.namespace.trim() != upstream.namespace
                || upstream.id.trim() != upstream.id
                || upstream.namespace.is_empty()
                || upstream.id.is_empty()
            {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: crate::policy::Severity::Error,
                    kind: "PolicyConfig".to_string(),
                    id: self.rule_id().to_string(),
                    namespace: "global".to_string(),
                    message: format!(
                        "invalid allowed_service_discovery_upstreams identity {{ namespace: '{}', id: '{}' }}",
                        upstream.namespace, upstream.id
                    ),
                    remediation: Some(
                        "Use exact, nonblank, unpadded namespace and upstream id values"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
                continue;
            }
            allowed_service_discovery_upstreams
                .insert((upstream.namespace.as_str(), upstream.id.as_str()));
        }
        let mut allowed_external_upstreams = BTreeSet::new();
        for upstream in &self.config.allowed_external_upstreams {
            if upstream.namespace.trim() != upstream.namespace
                || upstream.id.trim() != upstream.id
                || upstream.namespace.is_empty()
                || upstream.id.is_empty()
            {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: crate::policy::Severity::Error,
                    kind: "PolicyConfig".to_string(),
                    id: self.rule_id().to_string(),
                    namespace: "global".to_string(),
                    message: format!(
                        "invalid allowed_external_upstreams identity {{ namespace: '{}', id: '{}' }}",
                        upstream.namespace, upstream.id
                    ),
                    remediation: Some(
                        "Use exact, nonblank, unpadded namespace and upstream id values"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
                continue;
            }
            allowed_external_upstreams.insert((upstream.namespace.as_str(), upstream.id.as_str()));
        }

        for &(namespace, id) in &allowed_service_discovery_upstreams {
            if !cfg.upstreams.iter().any(|upstream| {
                upstream.namespace == namespace
                    && upstream.id == id
                    && upstream.service_discovery.is_some()
            }) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: crate::policy::Severity::Info,
                    kind: "PolicyConfig".to_string(),
                    id: self.rule_id().to_string(),
                    namespace: "global".to_string(),
                    message: format!(
                        "stale allowed_service_discovery_upstreams identity {{ namespace: '{namespace}', id: '{id}' }} matches no discovery-backed upstream"
                    ),
                    remediation: Some(
                        "Remove the stale acknowledgment or correct it to an exact discovery-backed upstream identity"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
            }
        }
        for &(namespace, id) in &allowed_external_upstreams {
            let referenced_as_external = cfg.proxies.iter().any(|proxy| {
                proxy.namespace == namespace
                    && proxy.upstream_id.as_deref() == Some(id)
                    && !declared_upstreams.contains_key(&(namespace, id))
            });
            if !referenced_as_external {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: crate::policy::Severity::Info,
                    kind: "PolicyConfig".to_string(),
                    id: self.rule_id().to_string(),
                    namespace: "global".to_string(),
                    message: format!(
                        "stale allowed_external_upstreams identity {{ namespace: '{namespace}', id: '{id}' }} matches no unresolved proxy upstream reference"
                    ),
                    remediation: Some(
                        "Remove the stale acknowledgment or correct it to an exact unresolved upstream reference"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
            }
        }

        for proxy in &cfg.proxies {
            let upstream_id = proxy.upstream_id.as_deref();
            let resolved_upstream = upstream_id.and_then(|upstream_id| {
                if upstream_id.trim().is_empty() {
                    None
                } else {
                    declared_upstreams
                        .get(&(proxy.namespace.as_str(), upstream_id))
                        .copied()
                }
            });
            let uses_routable_upstream = resolved_upstream.is_some_and(|upstream| {
                !upstream.targets.is_empty() || upstream.service_discovery.is_some()
            });
            let uses_allowed_external_upstream = upstream_id.is_some_and(|upstream_id| {
                !upstream_id.trim().is_empty()
                    && resolved_upstream.is_none()
                    && allowed_external_upstreams.contains(&(proxy.namespace.as_str(), upstream_id))
            });

            // A blank backend_host is schema filler when a declared upstream
            // supplies a destination. Any nonblank fallback remains a possible
            // dial target and must independently satisfy the allowlist.
            let external_upstream_has_no_fallback =
                uses_allowed_external_upstream && proxy.backend_host.trim().is_empty();
            let routable_upstream_has_no_fallback =
                uses_routable_upstream && proxy.backend_host.trim().is_empty();
            if !external_upstream_has_no_fallback
                && !routable_upstream_has_no_fallback
                && !Self::is_allowed(&proxy.backend_host, &allowed_domains)
            {
                let (message, remediation) = if let Some(upstream_id) = upstream_id {
                    if uses_allowed_external_upstream {
                        (
                            format!(
                                "allowed external upstream_id '{upstream_id}' in namespace '{}' has fallback backend_host='{}' outside the allowed domain list ({allowed})",
                                proxy.namespace, proxy.backend_host
                            ),
                            format!(
                                "Leave backend_host empty for acknowledged external upstream_id '{upstream_id}', or use a fallback matching one of these domains: {allowed}"
                            ),
                        )
                    } else if uses_routable_upstream {
                        (
                            format!(
                                "upstream_id '{upstream_id}' in namespace '{}' has fallback backend_host='{}' outside the allowed domain list ({allowed})",
                                proxy.namespace, proxy.backend_host
                            ),
                            format!(
                                "Leave backend_host empty when upstream_id '{upstream_id}' is authoritative, or use a fallback matching one of these domains: {allowed}"
                            ),
                        )
                    } else if resolved_upstream.is_some() {
                        (
                            format!(
                                "upstream_id '{upstream_id}' in namespace '{}' has no static targets or service_discovery; fallback backend_host='{}' is not in the allowed domain list ({allowed})",
                                proxy.namespace, proxy.backend_host
                            ),
                            format!(
                                "Add an allowed static target or service_discovery to upstream_id '{upstream_id}', or use a backend_host matching one of these domains: {allowed}"
                            ),
                        )
                    } else {
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
                    }
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

            if let Some(dns_override) = proxy
                .dns_override
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let disallowed: Vec<&str> = dns_override
                    .split(',')
                    .map(str::trim)
                    .filter(|destination| !destination.is_empty())
                    .filter(|destination| {
                        !Self::is_allowed(destination, allowed_dns_override_addresses)
                    })
                    .collect();
                if !disallowed.is_empty() {
                    findings.push(PolicyFinding {
                        rule_id: self.rule_id().to_string(),
                        severity: self.config.severity,
                        kind: "Proxy".to_string(),
                        id: proxy.id.clone(),
                        namespace: proxy.namespace.clone(),
                        message: format!(
                            "dns_override contains effective dial destination(s) outside the configured DNS override list: {}",
                            disallowed
                                .iter()
                                .map(|destination| format!("'{destination}'"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        remediation: Some(
                            "Remove the disallowed dns_override destinations or add each exact IP to allowed_dns_override_addresses"
                                .to_string(),
                        ),
                        overridden_by: None,
                    });
                }
            }
        }

        for upstream in &cfg.upstreams {
            if let Some(consul) = upstream
                .service_discovery
                .as_ref()
                .and_then(|discovery| discovery.consul.as_ref())
            {
                let consul_host = Self::url_destination_host(&consul.address);
                if consul_host
                    .as_deref()
                    .is_none_or(|host| !Self::is_allowed(host, allowed_control_plane_addresses))
                {
                    findings.push(PolicyFinding {
                        rule_id: self.rule_id().to_string(),
                        severity: self.config.severity,
                        kind: "Upstream".to_string(),
                        id: upstream.id.clone(),
                        namespace: upstream.namespace.clone(),
                        message: format!(
                            "Consul discovery address='{}' has an invalid or disallowed control-plane destination ({allowed_control_planes})",
                            consul.address
                        ),
                        remediation: Some(format!(
                            "Use an http(s) Consul address whose host matches one of these control-plane addresses: {allowed_control_planes}"
                        )),
                        overridden_by: None,
                    });
                }
            }

            if upstream.service_discovery.is_some()
                && !allow_all
                && !allowed_service_discovery_upstreams
                    .contains(&(upstream.namespace.as_str(), upstream.id.as_str()))
            {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Upstream".to_string(),
                    id: upstream.id.clone(),
                    namespace: upstream.namespace.clone(),
                    message: format!(
                        "service_discovery can publish runtime targets that cannot be verified against the allowed domain list ({allowed})"
                    ),
                    remediation: Some(format!(
                        "Remove service_discovery and declare allowed targets statically, or add {{ namespace: '{}', id: '{}' }} to allowed_service_discovery_upstreams after enforcing equivalent runtime egress controls",
                        upstream.namespace, upstream.id
                    )),
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
                        "target host='{}' is not in the allowed domain list ({allowed})",
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
