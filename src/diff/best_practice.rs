use crate::config::GatewayConfig;

#[derive(Debug, Clone)]
pub struct BestPractice {
    pub kind: String,
    pub id: String,
    pub message: String,
}

pub fn check_best_practices(config: &GatewayConfig) -> Vec<BestPractice> {
    let mut findings = Vec::new();

    for proxy in &config.proxies {
        let has_rate_limiting = proxy.plugins.iter().any(|assoc| {
            config
                .plugin_configs
                .iter()
                .any(|pc| pc.id == assoc.plugin_config_id && pc.plugin_name == "rate_limiting")
        });
        if !has_rate_limiting {
            findings.push(BestPractice {
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                message: "No rate_limiting plugin attached".to_string(),
            });
        }

        let has_logging = proxy.plugins.iter().any(|assoc| {
            config
                .plugin_configs
                .iter()
                .any(|pc| pc.id == assoc.plugin_config_id && pc.plugin_name.contains("logging"))
        });
        if !has_logging {
            findings.push(BestPractice {
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                message: "No logging plugin attached".to_string(),
            });
        }

        if proxy.backend_read_timeout_ms > 60000 {
            findings.push(BestPractice {
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                message: format!(
                    "backend_read_timeout_ms is {}ms (>60s)",
                    proxy.backend_read_timeout_ms
                ),
            });
        }
    }

    for upstream in &config.upstreams {
        if upstream.targets.len() == 1 {
            findings.push(BestPractice {
                kind: "Upstream".to_string(),
                id: upstream.id.clone(),
                message: "Only one target (no redundancy)".to_string(),
            });
        }
        if upstream.health_checks.is_none() {
            findings.push(BestPractice {
                kind: "Upstream".to_string(),
                id: upstream.id.clone(),
                message: "No health_checks configured".to_string(),
            });
        }
    }

    findings
}
