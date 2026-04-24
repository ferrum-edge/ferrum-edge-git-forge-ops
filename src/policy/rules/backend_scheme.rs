use crate::config::schema::BackendProtocol;
use crate::config::GatewayConfig;
use crate::policy::config::BackendSchemeRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct BackendSchemeRule {
    config: BackendSchemeRuleConfig,
}

impl BackendSchemeRule {
    pub fn new(config: BackendSchemeRuleConfig) -> Self {
        Self { config }
    }

    fn protocol_name(p: &BackendProtocol) -> &'static str {
        match p {
            BackendProtocol::Http => "http",
            BackendProtocol::Https => "https",
            BackendProtocol::Ws => "ws",
            BackendProtocol::Wss => "wss",
            BackendProtocol::Grpc => "grpc",
            BackendProtocol::Grpcs => "grpcs",
            BackendProtocol::H3 => "h3",
            BackendProtocol::Tcp => "tcp",
            BackendProtocol::TcpTls => "tcp_tls",
            BackendProtocol::Udp => "udp",
            BackendProtocol::Dtls => "dtls",
        }
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

        let allowed: Vec<String> = self
            .config
            .allowed_protocols
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        for proxy in &cfg.proxies {
            let actual = Self::protocol_name(&proxy.backend_protocol);
            if !allowed.iter().any(|a| a == actual) {
                findings.push(PolicyFinding {
                    rule_id: self.rule_id().to_string(),
                    severity: self.config.severity,
                    kind: "Proxy".to_string(),
                    id: proxy.id.clone(),
                    namespace: proxy.namespace.clone(),
                    message: format!(
                        "backend_protocol={actual} is not in the allowed list ({})",
                        allowed.join(", ")
                    ),
                    remediation: Some(format!(
                        "Change backend_protocol to one of: {}",
                        allowed.join(", ")
                    )),
                    overridden_by: None,
                });
            }
        }

        findings
    }
}
