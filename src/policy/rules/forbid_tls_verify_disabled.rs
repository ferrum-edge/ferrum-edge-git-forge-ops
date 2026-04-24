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

        // Proxy carries backend_tls_verify_server_cert. An Upstream also
        // carries the same field, and proxies can delegate to an upstream
        // rather than a direct backend — scanning proxies alone leaves a
        // bypass where an upstream sets it false and the proxy references
        // that upstream.
        let remediation = Some(
            "Remove backend_tls_verify_server_cert: false; trust the backend certificate via a CA bundle instead"
                .to_string(),
        );

        for proxy in &cfg.proxies {
            if !proxy.backend_tls_verify_server_cert {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: "backend_tls_verify_server_cert is disabled".to_string(),
                    remediation: remediation.clone(),
                    overridden_by: None,
                });
            }
        }

        for upstream in &cfg.upstreams {
            if !upstream.backend_tls_verify_server_cert {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Upstream".to_string(),
                    id: upstream.id.clone(),
                    namespace: upstream.namespace.clone(),
                    message: "backend_tls_verify_server_cert is disabled".to_string(),
                    remediation: remediation.clone(),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
