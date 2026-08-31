use std::path::Path;

use serde::de::DeserializeOwned;

use super::schema::Resource;

pub(crate) const RESOURCE_SUBDIRECTORIES: [(&str, &str); 5] = [
    ("proxies", "Proxy"),
    ("consumers", "Consumer"),
    ("upstreams", "Upstream"),
    ("plugins", "PluginConfig"),
    ("mesh", "MeshConfig"),
];

const NON_CONFIG_FILES: [&str; 4] = [
    "README",
    "README.md",
    ".gitkeep",
    crate::import::IMPORT_MANIFEST_FILENAME,
];

/// Decide whether a regular file inside a declarative configuration tree is
/// an enabled resource document. Only lowercase `.yaml`/`.yml` is executable
/// configuration. A leading underscore is the documented opt-out convention,
/// and a small explicit non-configuration allowlist stays non-executable. Every
/// other file fails closed so `api.YAML`, `api.yam`, or `api.yaml.bak` cannot be
/// silently omitted from desired state and trigger a prune.
pub(crate) fn enabled_yaml_file(path: &Path, tree_name: &str) -> crate::error::Result<bool> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            crate::error::Error::Config(format!(
                "{tree_name} file name is not valid UTF-8: {}",
                path.display()
            ))
        })?;
    if file_name.starts_with('_') || NON_CONFIG_FILES.contains(&file_name) {
        return Ok(false);
    }

    let extension = path.extension().and_then(|extension| extension.to_str());
    if matches!(extension, Some("yaml" | "yml")) {
        return Ok(true);
    }

    Err(crate::error::Error::Config(format!(
        "unsupported file in {tree_name}: {} (configuration must use lowercase .yaml or .yml; intentionally disabled files must start with '_'; non-configuration files are limited to README, README.md, .gitkeep, or {})",
        path.display(),
        crate::import::IMPORT_MANIFEST_FILENAME,
    )))
}

/// Reject configuration-looking content outside the five supported resource
/// directories. A misspelled directory would otherwise be silently omitted
/// from desired state, which can turn an input typo into a destructive prune.
pub(crate) fn validate_namespace_tree(
    namespace_dir: &Path,
    tree_name: &str,
) -> crate::error::Result<()> {
    let entries =
        std::fs::read_dir(namespace_dir).map_err(|source| crate::error::Error::FileRead {
            path: namespace_dir.to_path_buf(),
            source,
        })?;
    let mut entries = entries
        .map(|entry| {
            entry.map_err(|source| crate::error::Error::FileRead {
                path: namespace_dir.to_path_buf(),
                source,
            })
        })
        .collect::<crate::error::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| crate::error::Error::FileRead {
                path: path.clone(),
                source,
            })?;
        if file_type.is_symlink() {
            return Err(crate::error::Error::ConfigSymlink(path));
        }

        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            crate::error::Error::Config(format!(
                "{tree_name} entry is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        if file_type.is_dir()
            && !RESOURCE_SUBDIRECTORIES
                .iter()
                .any(|(allowed, _)| name == *allowed)
        {
            return Err(crate::error::Error::Config(format!(
                "unexpected directory in {tree_name} namespace: {} (expected one of: proxies, consumers, upstreams, plugins, mesh)",
                path.display()
            )));
        }

        if file_type.is_file()
            && RESOURCE_SUBDIRECTORIES
                .iter()
                .any(|(allowed, _)| name == *allowed)
        {
            return Err(crate::error::Error::ConfigNotDirectory(path));
        }

        if file_type.is_file() {
            if enabled_yaml_file(&path, tree_name)? {
                return Err(crate::error::Error::Config(format!(
                    "YAML file is outside a resource-kind directory in {tree_name}: {} (move it under proxies/, consumers/, upstreams/, plugins/, or mesh/)",
                    path.display()
                )));
            }
        } else if !file_type.is_dir() {
            return Err(crate::error::Error::Config(format!(
                "special filesystem entry is forbidden in {tree_name}: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

pub(crate) fn resource_kind(resource: &Resource) -> &'static str {
    match resource {
        Resource::Proxy { .. } => "Proxy",
        Resource::Consumer { .. } => "Consumer",
        Resource::Upstream { .. } => "Upstream",
        Resource::PluginConfig { .. } => "PluginConfig",
        Resource::MeshConfig { .. } => "MeshConfig",
    }
}

/// Parse one YAML resource without letting Serde's internally-tagged enum
/// buffering hide ignored fields.
///
/// We validate the small wrapper (`kind`, `spec`, optional mesh `id`)
/// ourselves, then deserialize `spec` directly into its concrete type through
/// `serde_ignored`. Direct concrete deserialization is important:
/// `#[serde(tag = "kind")]` buffers enum contents before the ignored-field
/// adapter sees them, which would recreate the original silent-drop bug.
pub(crate) fn resource_from_yaml(contents: &str, path: &Path) -> crate::error::Result<Resource> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(contents).map_err(|source| crate::error::Error::YamlParse {
            path: path.to_path_buf(),
            source,
        })?;
    let value = serde_json::to_value(yaml)?;
    resource_from_json_value(value, path)
}

/// Strictly deserialize a complete resource wrapper, including a fully merged
/// overlay document.
pub(crate) fn resource_from_json_value(
    value: serde_json::Value,
    source_path: &Path,
) -> crate::error::Result<Resource> {
    let object = value.as_object().ok_or_else(|| {
        crate::error::Error::Config(format!(
            "resource file {} must contain a YAML object",
            source_path.display()
        ))
    })?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| crate::error::Error::MissingKind {
            path: source_path.to_path_buf(),
        })?;
    let spec = object
        .get("spec")
        .cloned()
        .ok_or_else(|| crate::error::Error::MissingSpec {
            path: source_path.to_path_buf(),
        })?;

    let allowed_wrapper_keys: &[&str] = if kind == "MeshConfig" {
        &["kind", "id", "spec"]
    } else {
        &["kind", "spec"]
    };
    reject_unknown_paths(
        source_path,
        object
            .keys()
            .filter(|key| !allowed_wrapper_keys.contains(&key.as_str()))
            .map(|key| format!(".{key}")),
    )?;

    match kind {
        "Proxy" => Ok(Resource::Proxy {
            spec: deserialize_spec(spec, source_path)?,
        }),
        "Consumer" => Ok(Resource::Consumer {
            spec: deserialize_spec(spec, source_path)?,
        }),
        "Upstream" => Ok(Resource::Upstream {
            spec: deserialize_spec(spec, source_path)?,
        }),
        "PluginConfig" => Ok(Resource::PluginConfig {
            spec: deserialize_spec(spec, source_path)?,
        }),
        "MeshConfig" => {
            let id = match object.get("id") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(id)) => Some(id.clone()),
                Some(_) => {
                    return Err(crate::error::Error::Config(format!(
                        "resource file {} field `.id` must be a string",
                        source_path.display()
                    )))
                }
            };
            Ok(Resource::MeshConfig {
                id,
                spec: deserialize_spec(spec, source_path)?,
            })
        }
        unknown => Err(crate::error::Error::UnknownKind {
            kind: unknown.to_string(),
            path: source_path.to_path_buf(),
        }),
    }
}

fn deserialize_spec<T: DeserializeOwned>(
    value: serde_json::Value,
    source_path: &Path,
) -> crate::error::Result<T> {
    let bytes = serde_json::to_vec(&value)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let mut ignored = Vec::new();
    let parsed = serde_ignored::deserialize(&mut deserializer, |field| {
        let path = normalize_path(&field.to_string());
        ignored.push(format!(".spec{path}"));
    })
    .map_err(|error| {
        crate::error::Error::Config(format!(
            "invalid resource spec in {}: {error}",
            source_path.display()
        ))
    })?;
    reject_ignored(source_path, ignored)?;
    Ok(parsed)
}

pub(crate) fn reject_unknown_paths(
    source_path: &Path,
    paths: impl IntoIterator<Item = String>,
) -> crate::error::Result<()> {
    reject_ignored(source_path, paths.into_iter().collect())
}

fn reject_ignored(path: &Path, mut fields: Vec<String>) -> crate::error::Result<()> {
    if fields.is_empty() {
        return Ok(());
    }
    fields.sort();
    fields.dedup();
    Err(crate::error::Error::UnknownFields {
        path: path.to_path_buf(),
        fields: fields.join(", "),
    })
}

fn normalize_path(path: &str) -> String {
    // serde_ignored exposes `Option<T>` traversal as a synthetic `?` segment;
    // it is an implementation detail, not part of the operator's YAML path.
    let path = path.replace(".?.", ".").replace(".?", "");
    let mut normalized = String::new();
    for segment in path.trim_start_matches('.').split('.') {
        if segment.is_empty() {
            continue;
        }
        if segment.bytes().all(|byte| byte.is_ascii_digit()) {
            normalized.push('[');
            normalized.push_str(segment);
            normalized.push(']');
        } else if segment.starts_with('[') {
            normalized.push_str(segment);
        } else {
            normalized.push('.');
            normalized.push_str(segment);
        }
    }
    normalized
}
