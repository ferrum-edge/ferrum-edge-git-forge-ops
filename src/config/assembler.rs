use std::path::Path;

use walkdir::WalkDir;

use super::schema::{GatewayConfig, Resource};

/// Assemble loaded resources into a `GatewayConfig`.
///
/// Sets each resource's `namespace` field to the directory-inferred namespace,
/// unless the spec already has a non-default namespace explicitly set.
pub fn assemble(resources: Vec<(String, Resource)>) -> GatewayConfig {
    let mut config = GatewayConfig::default();

    for (namespace, resource) in resources {
        match resource {
            Resource::Proxy { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.proxies.push(spec);
            }
            Resource::Consumer { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.consumers.push(spec);
            }
            Resource::Upstream { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.upstreams.push(spec);
            }
            Resource::PluginConfig { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.plugin_configs.push(spec);
            }
        }
    }

    config
}

/// Deep-merge overlay resources into the base set by matching on resource `id`.
///
/// Overlay files are **partial** — they only contain the fields to override,
/// not all required fields. This function parses them as raw YAML values
/// (not typed `Resource` structs) and merges into the base resource's JSON
/// representation.
pub fn apply_overlay(
    base: &mut [(String, Resource)],
    overlay_dir: &Path,
) -> crate::error::Result<()> {
    if !overlay_dir.is_dir() {
        return Ok(());
    }

    let overlay_fragments = load_overlay_fragments(overlay_dir)?;

    for (overlay_ns, overlay_value) in overlay_fragments {
        let overlay_id = overlay_value
            .get("spec")
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let base_entry = base
            .iter_mut()
            .find(|(_, base_res)| resource_id(base_res) == overlay_id);

        match base_entry {
            Some((ref mut base_ns, ref mut base_resource)) => {
                let base_value = serde_json::to_value(&*base_resource)?;
                let merged = deep_merge_values(base_value, overlay_value);
                *base_resource = serde_json::from_value(merged)?;

                if *base_ns == "ferrum" && overlay_ns != "ferrum" {
                    *base_ns = overlay_ns;
                }
            }
            None => {
                if !overlay_id.is_empty() {
                    return Err(crate::error::Error::OrphanOverlay {
                        id: overlay_id,
                        path: overlay_dir.to_path_buf(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Load overlay files as raw JSON values (not typed structs).
/// Overlay files are partial and may lack required fields.
fn load_overlay_fragments(
    overlay_dir: &Path,
) -> crate::error::Result<Vec<(String, serde_json::Value)>> {
    let mut results = Vec::new();

    let namespace_entries =
        std::fs::read_dir(overlay_dir).map_err(|source| crate::error::Error::FileRead {
            path: overlay_dir.to_path_buf(),
            source,
        })?;

    for ns_entry in namespace_entries {
        let ns_entry = ns_entry.map_err(|source| crate::error::Error::FileRead {
            path: overlay_dir.to_path_buf(),
            source,
        })?;

        let ns_path = ns_entry.path();
        if !ns_path.is_dir() {
            continue;
        }

        let namespace = ns_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ferrum")
            .to_string();

        for subdir in &["proxies", "consumers", "upstreams", "plugins"] {
            let subdir_path = ns_path.join(subdir);
            if !subdir_path.is_dir() {
                continue;
            }

            for entry in WalkDir::new(&subdir_path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext != "yaml" && ext != "yml" {
                    continue;
                }
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if file_name.starts_with('_') {
                    continue;
                }

                let contents = std::fs::read_to_string(path).map_err(|source| {
                    crate::error::Error::FileRead {
                        path: path.to_path_buf(),
                        source,
                    }
                })?;

                // Parse as raw YAML then convert to JSON Value
                let yaml_value: serde_yaml::Value =
                    serde_yaml::from_str(&contents).map_err(|source| {
                        crate::error::Error::YamlParse {
                            path: path.to_path_buf(),
                            source,
                        }
                    })?;
                let json_value: serde_json::Value =
                    serde_json::to_value(yaml_value).map_err(crate::error::Error::SerdeJson)?;

                results.push((namespace.clone(), json_value));
            }
        }
    }

    Ok(results)
}

fn resource_id(resource: &Resource) -> String {
    match resource {
        Resource::Proxy { spec } => spec.id.clone(),
        Resource::Consumer { spec } => spec.id.clone(),
        Resource::Upstream { spec } => spec.id.clone(),
        Resource::PluginConfig { spec } => spec.id.clone(),
    }
}

fn deep_merge_values(base: serde_json::Value, overlay: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;

    match (base, overlay) {
        (Value::Object(mut base_map), Value::Object(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                let merged = if let Some(base_val) = base_map.remove(&key) {
                    deep_merge_values(base_val, overlay_val)
                } else {
                    overlay_val
                };
                base_map.insert(key, merged);
            }
            Value::Object(base_map)
        }
        (_, overlay) => overlay,
    }
}
