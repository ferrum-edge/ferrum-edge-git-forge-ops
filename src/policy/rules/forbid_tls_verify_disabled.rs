use crate::config::GatewayConfig;
use crate::policy::config::ForbidTlsVerifyDisabledRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct ForbidTlsVerifyDisabledRule {
    config: ForbidTlsVerifyDisabledRuleConfig,
}

impl ForbidTlsVerifyDisabledRule {
    pub fn new(config: ForbidTlsVerifyDisabledRuleConfig) -> Self {
        Self { config }
    }
}

impl PolicyCheck for ForbidTlsVerifyDisabledRule {
    fn rule_id(&self) -> &str {
        "forbid_tls_verify_disabled"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        for proxy in &cfg.proxies {
            if !proxy.backend_tls_verify_server_cert {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: "backend_tls_verify_server_cert is disabled".to_string(),
                    remediation: Some(
                        "Remove backend_tls_verify_server_cert: false; trust the backend certificate via a CA bundle instead"
                            .to_string(),
                    ),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
