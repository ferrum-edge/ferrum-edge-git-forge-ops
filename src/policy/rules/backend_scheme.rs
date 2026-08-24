use crate::config::schema::BackendScheme;
use crate::config::GatewayConfig;
use crate::policy::config::BackendSchemeRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

/// Scheme assumed when a proxy leaves `backend_scheme` unset. Mirrors
/// ferrum-edge's `effective_scheme()`, which normalizes an absent scheme to
/// `https` (an absent scheme on a stream proxy is rejected by the gateway
/// outright, so `https` is the only reachable default here).
const DEFAULT_SCHEME: BackendScheme = BackendScheme::Https;

pub struct BackendSchemeRule {
    config: BackendSchemeRuleConfig,
}

impl BackendSchemeRule {
    pub fn new(config: BackendSchemeRuleConfig) -> Self {
        Self { config }
    }

    fn scheme_name(scheme: Option<BackendScheme>) -> &'static str {
        scheme.unwrap_or(DEFAULT_SCHEME).as_str()
    }
}

impl PolicyCheck for BackendSchemeRule {
    fn rule_id(&self) -> &str {
        "backend_scheme"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled || self.config.allowed_protocols.is_empty() {
            return findings;
        }

        // Allowed entries are normalized through `BackendScheme::from_wire` so a
        // policy file still written against the legacy value set (`wss`, `grpcs`,
        // `tcp_tls`, …) keeps meaning the same thing it did before the rename.
        let mut allowed: Vec<String> = Vec::new();
        for entry in &self.config.allowed_protocols {
            let lowered = entry.to_lowercase();
            let canonical = BackendScheme::from_wire(&lowered)
                .map(|scheme| scheme.as_str().to_string())
                .unwrap_or(lowered);
            if !allowed.contains(&canonical) {
                allowed.push(canonical);
            }
        }

        for proxy in &cfg.proxies {
            let actual = Self::scheme_name(proxy.backend_scheme);
            if !allowed.iter().any(|a| a == actual) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: format!(
                        "backend_scheme={actual} is not in the allowed list ({})",
                        allowed.join(", ")
                    ),
                    remediation: Some(format!(
                        "Change backend_scheme to one of: {}",
                        allowed.join(", ")
                    )),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
