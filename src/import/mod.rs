pub mod from_api;
pub mod from_file;

pub use from_api::import_from_api;
pub use from_file::import_from_file;

use std::path::Path;

use crate::config::schema::{GatewayConfig, Resource};

#[derive(Debug, Default)]
pub struct ImportResult {
    pub proxies: usize,
    pub consumers: usize,
    pub upstreams: usize,
    pub plugin_configs: usize,
}

pub fn split_config(
    config: &GatewayConfig,
    output_dir: &Path,
) -> crate::error::Result<ImportResult> {
    let mut result = ImportResult::default();

    for proxy in &config.proxies {
        let dir = output_dir.join(&proxy.namespace).join("proxies");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::Proxy {
            spec: proxy.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = if proxy.id.is_empty() {
            "unnamed.yaml".to_string()
        } else {
            format!("{}.yaml", proxy.id)
        };
        std::fs::write(dir.join(filename), yaml)?;
        result.proxies += 1;
    }

    for consumer in &config.consumers {
        let dir = output_dir.join(&consumer.namespace).join("consumers");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::Consumer {
            spec: consumer.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = if consumer.id.is_empty() {
            "unnamed.yaml".to_string()
        } else {
            format!("{}.yaml", consumer.id)
        };
        std::fs::write(dir.join(filename), yaml)?;
        result.consumers += 1;
    }

    for upstream in &config.upstreams {
        let dir = output_dir.join(&upstream.namespace).join("upstreams");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::Upstream {
            spec: upstream.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = if upstream.id.is_empty() {
            "unnamed.yaml".to_string()
        } else {
            format!("{}.yaml", upstream.id)
        };
        std::fs::write(dir.join(filename), yaml)?;
        result.upstreams += 1;
    }

    for pc in &config.plugin_configs {
        let dir = output_dir.join(&pc.namespace).join("plugins");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::PluginConfig { spec: pc.clone() };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = if pc.id.is_empty() {
            "unnamed.yaml".to_string()
        } else {
            format!("{}.yaml", pc.id)
        };
        std::fs::write(dir.join(filename), yaml)?;
        result.plugin_configs += 1;
    }

    Ok(result)
}
