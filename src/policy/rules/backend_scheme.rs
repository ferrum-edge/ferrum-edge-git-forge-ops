use crate::config::schema::BackendScheme;
use crate::config::GatewayConfig;
use crate::plugin_catalog::effective_scheme;
use crate::policy::config::BackendSchemeRuleConfig;
use crate::policy::{PolicyCheck, PolicyFinding};

pub struct BackendSchemeRule {
    config: BackendSchemeRuleConfig,
}

impl BackendSchemeRule {
    pub fn new(config: BackendSchemeRuleConfig) -> Self {
        Self { config }
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
            // Assembly normalizes a schemeless HTTP-family proxy to `https`
            // before any rule runs, so `backend_scheme` is usually already set.
            // `effective_scheme` still applies the gateway's own default here —
            // the rule is also evaluated on configs that did not come through
            // the assembler (imports, `--from-file`), and a stream proxy's
            // absent scheme has to resolve to the stream sentinel rather than
            // to `https`.
            let actual = effective_scheme(proxy).as_str();
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
