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
        let namespace = safe_path_component(&proxy.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("proxies");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::Proxy {
            spec: proxy.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&proxy.id, "id")?;
        std::fs::write(dir.join(filename), yaml)?;
        result.proxies += 1;
    }

    for consumer in &config.consumers {
        let namespace = safe_path_component(&consumer.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("consumers");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::Consumer {
            spec: consumer.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&consumer.id, "id")?;
        std::fs::write(dir.join(filename), yaml)?;
        result.consumers += 1;
    }

    for upstream in &config.upstreams {
        let namespace = safe_path_component(&upstream.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("upstreams");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::Upstream {
            spec: upstream.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&upstream.id, "id")?;
        std::fs::write(dir.join(filename), yaml)?;
        result.upstreams += 1;
    }

    for pc in &config.plugin_configs {
        let namespace = safe_path_component(&pc.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("plugins");
        std::fs::create_dir_all(&dir)?;
        let resource = Resource::PluginConfig { spec: pc.clone() };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&pc.id, "id")?;
        std::fs::write(dir.join(filename), yaml)?;
        result.plugin_configs += 1;
    }

    Ok(result)
}

/// Reject values that would break out of `output_dir` (path traversal, absolute
/// paths, null bytes). Resource identifiers originate from an admin API or
/// user YAML and must not be trusted as filesystem path components.
fn safe_path_component<'a>(value: &'a str, field: &str) -> crate::error::Result<&'a str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err(crate::error::Error::Config(format!(
            "unsafe {field} {value:?} — cannot use as filesystem path component"
        )));
    }
    Ok(value)
}

fn resource_filename(id: &str, field: &str) -> crate::error::Result<String> {
    if id.is_empty() {
        return Ok("unnamed.yaml".to_string());
    }
    let safe = safe_path_component(id, field)?;
    Ok(format!("{safe}.yaml"))
}
