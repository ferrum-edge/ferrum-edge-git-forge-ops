use std::collections::HashMap;
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

/// Deep-merge overlay resources into the base set by matching on resource
/// kind, effective namespace, and `id`.
///
/// Overlay files are **partial** — they only contain the fields to override,
/// not all required fields. This function parses them as raw YAML values
/// (not typed `Resource` structs) and merges into the base resource's JSON
/// representation. Arrays are merged rather than replaced so partial overlays
/// can add hosts, plugin associations, or upstream targets without dropping
/// entries from the base resource.
pub fn apply_overlay(
    base: &mut [(String, Resource)],
    overlay_dir: &Path,
) -> crate::error::Result<()> {
    if !overlay_dir.is_dir() {
        return Ok(());
    }

    let mut base_index = HashMap::new();
    for (idx, (base_ns, base_res)) in base.iter().enumerate() {
        let key = resource_key(base_ns, base_res);
        if let Some(previous) = base_index.insert(key.clone(), idx) {
            return Err(crate::error::Error::Config(format!(
                "duplicate base resource key for overlay lookup: {}/{}/{} at indexes {} and {}",
                key.namespace, key.kind, key.id, previous, idx
            )));
        }
    }

    let overlay_fragments = load_overlay_fragments(overlay_dir)?;

    for overlay in overlay_fragments {
        let overlay_id = overlay
            .value
            .get("spec")
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if overlay_id.is_empty() {
            continue;
        }

        let overlay_ns = overlay_effective_namespace(&overlay.value, &overlay.namespace);
        let overlay_key = ResourceKey {
            kind: overlay.kind,
            namespace: overlay_ns,
            id: overlay_id,
        };

        match base_index
            .get(&overlay_key)
            .copied()
            .map(|idx| &mut base[idx])
        {
            Some((ref mut base_ns, ref mut base_resource)) => {
                let base_value = serde_json::to_value(&*base_resource)?;
                let merged = deep_merge_values(base_value, overlay.value);
                *base_resource = serde_json::from_value(merged)?;

                if *base_ns == "ferrum" && overlay_key.namespace != "ferrum" {
                    *base_ns = overlay_key.namespace;
                }
            }
            None => {
                return Err(crate::error::Error::OrphanOverlay {
                    id: format!(
                        "{}/{}/{}",
                        overlay_key.namespace, overlay_key.kind, overlay_key.id
                    ),
                    path: overlay_dir.to_path_buf(),
                });
            }
        }
    }

    Ok(())
}

/// Load overlay files as raw JSON values (not typed structs).
/// Overlay files are partial and may lack required fields.
struct OverlayFragment {
    namespace: String,
    kind: &'static str,
    value: serde_json::Value,
}

fn load_overlay_fragments(overlay_dir: &Path) -> crate::error::Result<Vec<OverlayFragment>> {
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

        for (subdir, kind) in [
            ("proxies", "Proxy"),
            ("consumers", "Consumer"),
            ("upstreams", "Upstream"),
            ("plugins", "PluginConfig"),
        ] {
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
                if let Some(declared_kind) = json_value.get("kind").and_then(|v| v.as_str()) {
                    if declared_kind != kind {
                        return Err(crate::error::Error::Config(format!(
                            "overlay file {} declares kind {declared_kind:?} but is under {subdir}/ ({kind})",
                            path.display()
                        )));
                    }
                }

                results.push(OverlayFragment {
                    namespace: namespace.clone(),
                    kind,
                    value: json_value,
                });
            }
        }
    }

    Ok(results)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ResourceKey {
    kind: &'static str,
    namespace: String,
    id: String,
}

fn resource_key(directory_namespace: &str, resource: &Resource) -> ResourceKey {
    match resource {
        Resource::Proxy { spec } => ResourceKey {
            kind: "Proxy",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        Resource::Consumer { spec } => ResourceKey {
            kind: "Consumer",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        Resource::Upstream { spec } => ResourceKey {
            kind: "Upstream",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        Resource::PluginConfig { spec } => ResourceKey {
            kind: "PluginConfig",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
    }
}

fn effective_namespace(directory_namespace: &str, spec_namespace: &str) -> String {
    if spec_namespace == "ferrum" {
        directory_namespace.to_string()
    } else {
        spec_namespace.to_string()
    }
}

fn overlay_effective_namespace(value: &serde_json::Value, directory_namespace: &str) -> String {
    value
        .get("spec")
        .and_then(|s| s.get("namespace"))
        .and_then(|v| v.as_str())
        .map(|ns| effective_namespace(directory_namespace, ns))
        .unwrap_or_else(|| directory_namespace.to_string())
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
        (Value::Array(base_items), Value::Array(overlay_items)) => {
            merge_array_values(base_items, overlay_items)
        }
        (_, overlay) => overlay,
    }
}

fn merge_array_values(
    mut base_items: Vec<serde_json::Value>,
    overlay_items: Vec<serde_json::Value>,
) -> serde_json::Value {
    for overlay_item in overlay_items {
        if let Some(identity) = array_item_identity(&overlay_item) {
            if let Some(position) = base_items
                .iter()
                .position(|item| array_item_identity(item).as_ref() == Some(&identity))
            {
                let base_item =
                    std::mem::replace(&mut base_items[position], serde_json::Value::Null);
                base_items[position] = deep_merge_values(base_item, overlay_item);
            } else {
                base_items.push(overlay_item);
            }
        } else if !base_items.iter().any(|item| item == &overlay_item) {
            base_items.push(overlay_item);
        }
    }

    serde_json::Value::Array(base_items)
}

fn array_item_identity(value: &serde_json::Value) -> Option<String> {
    let map = value.as_object()?;

    for key in ["id", "plugin_config_id", "name"] {
        if let Some(value) = map.get(key).and_then(|value| value.as_str()) {
            return Some(format!("{key}:{value}"));
        }
    }

    if let (Some(host), Some(port)) = (
        map.get("host").and_then(|value| value.as_str()),
        map.get("port"),
    ) {
        let path = map
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        return Some(format!("target:{host}:{port}:{path}"));
    }

    None
}
