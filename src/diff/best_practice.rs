use crate::config::schema::{PluginConfig, PluginScope, Proxy};
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
        let has_rate_limiting = proxy_has_plugin(config, proxy, |plugin| {
            plugin.plugin_name == "rate_limiting"
        });
        if !has_rate_limiting {
            findings.push(BestPractice {
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                message: "No rate_limiting plugin attached".to_string(),
            });
        }

        let has_logging = proxy_has_plugin(config, proxy, |plugin| {
            plugin.plugin_name.contains("logging")
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

fn proxy_has_plugin(
    config: &GatewayConfig,
    proxy: &Proxy,
    predicate: impl Fn(&PluginConfig) -> bool,
) -> bool {
    config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.namespace == proxy.namespace)
        .any(|plugin| {
            if !predicate(plugin) {
                return false;
            }

            match plugin.scope {
                PluginScope::Global => true,
                PluginScope::Proxy => {
                    plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
                        && proxy
                            .plugins
                            .iter()
                            .any(|assoc| assoc.plugin_config_id == plugin.id)
                }
                PluginScope::ProxyGroup => proxy
                    .plugins
                    .iter()
                    .any(|assoc| assoc.plugin_config_id == plugin.id),
            }
        })
}
