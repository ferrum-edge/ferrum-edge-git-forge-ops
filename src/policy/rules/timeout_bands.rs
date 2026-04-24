use crate::config::GatewayConfig;
use crate::policy::config::{TimeoutBand, TimeoutBandsRuleConfig};
use crate::policy::{PolicyCheck, PolicyFinding, Severity};

pub struct TimeoutBandsRule {
    config: TimeoutBandsRuleConfig,
}

impl TimeoutBandsRule {
    pub fn new(config: TimeoutBandsRuleConfig) -> Self {
        Self { config }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_field(
        &self,
        rule_id: &str,
        field: &str,
        value: u64,
        band: &TimeoutBand,
        severity: Severity,
        proxy_id: &str,
        proxy_namespace: &str,
        findings: &mut Vec<PolicyFinding>,
    ) {
        if let Some(min) = band.min {
            if value < min {
                findings.push(PolicyFinding {
                    rule_id: rule_id.to_string(),
                    severity,
                    kind: "Proxy".to_string(),
                    id: proxy_id.to_string(),
                    namespace: proxy_namespace.to_string(),
                    message: format!("{field}={value} is below the minimum allowed ({min})"),
                    remediation: Some(format!("Set {field} to at least {min}")),
                    overridden_by: None,
                });
                return;
            }
        }
        if let Some(max) = band.max {
            if value > max {
                findings.push(PolicyFinding {
                    rule_id: rule_id.to_string(),
                    severity,
                    kind: "Proxy".to_string(),
                    id: proxy_id.to_string(),
                    namespace: proxy_namespace.to_string(),
                    message: format!("{field}={value} exceeds the maximum allowed ({max})"),
                    remediation: Some(format!("Set {field} to at most {max}")),
                    overridden_by: None,
                });
            }
        }
    }
}

impl PolicyCheck for TimeoutBandsRule {
    fn rule_id(&self) -> &str {
        "proxy_timeout_bands"
    }

    fn evaluate(&self, cfg: &GatewayConfig) -> Vec<PolicyFinding> {
        let mut findings = Vec::new();
        if !self.config.enabled {
            return findings;
        }

        for proxy in &cfg.proxies {
            self.check_field(
                "proxy_timeout_bands.connect_timeout_ms",
                "backend_connect_timeout_ms",
                proxy.backend_connect_timeout_ms,
                &self.config.connect_timeout_ms,
                self.config.severity,
                &proxy.id,
                &proxy.namespace,
                &mut findings,
            );
            self.check_field(
                "proxy_timeout_bands.read_timeout_ms",
                "backend_read_timeout_ms",
                proxy.backend_read_timeout_ms,
                &self.config.read_timeout_ms,
                self.config.severity,
                &proxy.id,
                &proxy.namespace,
                &mut findings,
            );
            self.check_field(
                "proxy_timeout_bands.write_timeout_ms",
                "backend_write_timeout_ms",
                proxy.backend_write_timeout_ms,
                &self.config.write_timeout_ms,
                self.config.severity,
                &proxy.id,
                &proxy.namespace,
                &mut findings,
            );
        }

        findings
    }
}
