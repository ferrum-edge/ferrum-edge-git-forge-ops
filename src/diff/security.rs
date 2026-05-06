use crate::config::schema::{PluginConfig, PluginScope, Proxy};
use crate::config::GatewayConfig;

#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub severity: String,
    pub kind: String,
    pub id: String,
    pub message: String,
}

pub fn audit_security(config: &GatewayConfig) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    for consumer in &config.consumers {
        for (cred_type, cred_value) in &consumer.credentials {
            check_literal_credentials(&consumer.id, cred_type, cred_value, &mut findings);
        }
    }

    for proxy in &config.proxies {
        let has_auth =
            proxy_has_plugin(config, proxy, |plugin| plugin.plugin_name.contains("auth"));
        if !has_auth {
            findings.push(SecurityFinding {
                severity: "warning".to_string(),
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                message: "No auth plugin attached".to_string(),
            });
        }

        if !proxy.backend_tls_verify_server_cert {
            findings.push(SecurityFinding {
                severity: "warning".to_string(),
                kind: "Proxy".to_string(),
                id: proxy.id.clone(),
                message: "backend_tls_verify_server_cert is false".to_string(),
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
            if !plugin.enabled {
                return false;
            }

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

fn check_literal_credentials(
    consumer_id: &str,
    cred_type: &str,
    value: &serde_json::Value,
    findings: &mut Vec<SecurityFinding>,
) {
    match value {
        serde_json::Value::String(s) if !s.starts_with("${") => {
            findings.push(SecurityFinding {
                severity: "error".to_string(),
                kind: "Consumer".to_string(),
                id: consumer_id.to_string(),
                message: format!("Literal credential in '{cred_type}' (use ${{...}} for secrets)"),
            });
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let nested_path = format!("{cred_type}.{k}");
                check_literal_credentials(consumer_id, &nested_path, v, findings);
            }
        }
        serde_json::Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                let nested_path = format!("{cred_type}[{idx}]");
                check_literal_credentials(consumer_id, &nested_path, item, findings);
            }
        }
        _ => {}
    }
}
