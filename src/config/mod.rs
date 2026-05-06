pub mod assembler;
pub mod env;
pub mod loader;
pub mod repo_config;
pub mod resolved;
pub mod schema;

pub use assembler::{apply_overlay, assemble};
pub use env::{load_env_config, ApplyStrategy, EnvConfig, GatewayMode};
pub use loader::load_resources;
pub use repo_config::{
    EnvironmentConfig, OwnershipConfig, OwnershipMode, RepoConfig, REPO_CONFIG_PATH,
};
pub use resolved::{resolve_env, validate_env_name_is_safe_path_component, ResolvedEnv};
pub use schema::{GatewayConfig, Resource};

use std::collections::BTreeSet;

pub fn filter_config_by_namespace(config: &GatewayConfig, namespace: &str) -> GatewayConfig {
    GatewayConfig {
        version: config.version.clone(),
        proxies: config
            .proxies
            .iter()
            .filter(|proxy| proxy.namespace == namespace)
            .cloned()
            .collect(),
        consumers: config
            .consumers
            .iter()
            .filter(|consumer| consumer.namespace == namespace)
            .cloned()
            .collect(),
        plugin_configs: config
            .plugin_configs
            .iter()
            .filter(|plugin_config| plugin_config.namespace == namespace)
            .cloned()
            .collect(),
        upstreams: config
            .upstreams
            .iter()
            .filter(|upstream| upstream.namespace == namespace)
            .cloned()
            .collect(),
    }
}

pub fn select_config_namespace(
    config: &GatewayConfig,
    namespace_filter: Option<&str>,
) -> GatewayConfig {
    match namespace_filter {
        Some(namespace) => filter_config_by_namespace(config, namespace),
        None => config.clone(),
    }
}

pub fn collect_namespaces(config: &GatewayConfig) -> Vec<String> {
    let mut namespaces = BTreeSet::new();

    for proxy in &config.proxies {
        namespaces.insert(proxy.namespace.clone());
    }
    for consumer in &config.consumers {
        namespaces.insert(consumer.namespace.clone());
    }
    for upstream in &config.upstreams {
        namespaces.insert(upstream.namespace.clone());
    }
    for plugin_config in &config.plugin_configs {
        namespaces.insert(plugin_config.namespace.clone());
    }

    namespaces.into_iter().collect()
}

pub fn split_config_by_namespace(
    config: &GatewayConfig,
    namespace_filter: Option<&str>,
) -> Vec<(String, GatewayConfig)> {
    match namespace_filter {
        Some(namespace) => vec![(
            namespace.to_string(),
            filter_config_by_namespace(config, namespace),
        )],
        None => collect_namespaces(config)
            .into_iter()
            .map(|namespace| {
                let namespace_config = filter_config_by_namespace(config, &namespace);
                (namespace, namespace_config)
            })
            .collect(),
    }
}

pub fn validate_unique_resource_keys(config: &GatewayConfig) -> crate::error::Result<()> {
    let mut seen = BTreeSet::new();

    for proxy in &config.proxies {
        insert_resource_key(&mut seen, &proxy.namespace, "Proxy", &proxy.id)?;
    }
    for consumer in &config.consumers {
        insert_resource_key(&mut seen, &consumer.namespace, "Consumer", &consumer.id)?;
    }
    for upstream in &config.upstreams {
        insert_resource_key(&mut seen, &upstream.namespace, "Upstream", &upstream.id)?;
    }
    for plugin_config in &config.plugin_configs {
        insert_resource_key(
            &mut seen,
            &plugin_config.namespace,
            "PluginConfig",
            &plugin_config.id,
        )?;
    }

    Ok(())
}

fn insert_resource_key(
    seen: &mut BTreeSet<(String, &'static str, String)>,
    namespace: &str,
    kind: &'static str,
    id: &str,
) -> crate::error::Result<()> {
    let key = (namespace.to_string(), kind, id.to_string());
    if !seen.insert(key) {
        return Err(crate::error::Error::Config(format!(
            "duplicate resource key: namespace={namespace:?}, kind={kind}, id={id:?}"
        )));
    }
    Ok(())
}
