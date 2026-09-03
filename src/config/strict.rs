use std::collections::BTreeMap;
use std::path::Path;

use serde::de::DeserializeOwned;

use super::schema::{PassthroughFields, Resource};

/// How strictly one load pass treats fields the typed mirror does not model.
///
/// Fail-closed is the default and stays the default: `LoadOptions::default()`
/// rejects every unknown field. The permissive variant is only ever reached by
/// an operator setting `FERRUM_ALLOW_UNKNOWN_FIELDS=true`, and even then it
/// only relaxes *top-level* `spec` fields — see
/// [`super::schema::PassthroughFields`].
///
/// This is a parameter rather than a process-global read so that the parse path
/// stays free of environment access: the flag is resolved once, in `main`, and
/// threaded down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// Keep unknown top-level `spec` fields verbatim instead of rejecting them.
    pub allow_unknown_fields: bool,
}

impl LoadOptions {
    /// The fail-closed default, spelled out at call sites that mean it.
    pub const STRICT: Self = Self {
        allow_unknown_fields: false,
    };

    /// Keep unknown top-level `spec` fields (`FERRUM_ALLOW_UNKNOWN_FIELDS`).
    pub const ALLOW_UNKNOWN_FIELDS: Self = Self {
        allow_unknown_fields: true,
    };
}

pub(crate) const RESOURCE_SUBDIRECTORIES: [(&str, &str); 5] = [
    ("proxies", "Proxy"),
    ("consumers", "Consumer"),
    ("upstreams", "Upstream"),
    ("plugins", "PluginConfig"),
    ("mesh", "MeshConfig"),
];

pub(crate) const NON_CONFIG_FILES: [&str; 4] = [
    "README",
    "README.md",
    ".gitkeep",
    crate::import::IMPORT_MANIFEST_FILENAME,
];

/// Files an operating system or file browser drops into a directory without
/// anyone asking, which carry no configuration and cannot be authored away.
///
/// These are skipped **silently**, unlike the [`NON_CONFIG_FILES`] allowlist:
/// there is nothing for an operator to fix, and a `.DS_Store` that Finder
/// re-creates the moment the folder is opened must not be able to fail a
/// validate-and-apply pipeline. Everything config-shaped — any `.y*ml`-ish,
/// `.json`, `.toml`, or extensionless file — stays fatal, because a file that
/// *looks* like a resource but is not loaded is how a typo turns into a prune.
///
/// Kept byte-identical to `NON_CONFIG_FILES` / `OS_ARTIFACT_FILES` in
/// `.github/scripts/pr_input.py`; the two allowlists gate the same trees on
/// either side of the trusted-review boundary, and a Python-side test
/// cross-checks them against this file.
pub(crate) const OS_ARTIFACT_FILES: [&str; 3] = [".DS_Store", "Thumbs.db", "desktop.ini"];

/// Decide whether a regular file inside a declarative configuration tree is
/// an enabled resource document. Only lowercase `.yaml`/`.yml` is executable
/// configuration. A leading underscore is the documented opt-out convention,
/// a small explicit non-configuration allowlist stays non-executable, and
/// well-known OS artifacts are ignored outright. Every other file fails closed
/// so `api.YAML`, `api.yam`, or `api.yaml.bak` cannot be silently omitted from
/// desired state and trigger a prune.
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
    if file_name.starts_with('_')
        || NON_CONFIG_FILES.contains(&file_name)
        || OS_ARTIFACT_FILES.contains(&file_name)
    {
        return Ok(false);
    }

    let extension = path.extension().and_then(|extension| extension.to_str());
    if matches!(extension, Some("yaml" | "yml")) {
        return Ok(true);
    }

    Err(crate::error::Error::Config(format!(
        "unsupported file in {tree_name}: {} (configuration must use lowercase .yaml or .yml; intentionally disabled files must start with '_'; non-configuration files are limited to README, README.md, .gitkeep, {}, or an OS artifact: {})",
        path.display(),
        crate::import::IMPORT_MANIFEST_FILENAME,
        OS_ARTIFACT_FILES.join(", "),
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
pub(crate) fn resource_from_yaml(
    contents: &str,
    path: &Path,
    options: LoadOptions,
) -> crate::error::Result<Resource> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(contents).map_err(|source| crate::error::Error::YamlParse {
            path: path.to_path_buf(),
            source,
        })?;
    reject_non_string_keys(&yaml, path)?;
    let value = serde_json::to_value(yaml)?;
    resource_from_json_value(value, path, options)
}

/// Reject YAML mapping keys that are not strings, naming the mapping they
/// appear in.
///
/// Every document takes a `serde_yaml::Value` → `serde_json::Value` hop before
/// it is deserialized, and the opaque islands gitforgeops carries verbatim
/// (a `PluginConfig.config`, a `Consumer.credentials` entry, a mesh workload)
/// are *JSON* values on the far side of it. JSON has string keys only, so a
/// YAML `2019: …` or `true: …` key is silently rewritten to `"2019"` / `"true"`
/// on the way through — a quiet change of meaning in exactly the sections
/// gitforgeops promises not to interpret. Rejecting them keeps "opaque" honest:
/// what survives the hop is JSON-shaped, and anything that would not survive it
/// is an error the author sees, not a rewrite they do not.
pub(crate) fn reject_non_string_keys(
    value: &serde_yaml::Value,
    source_path: &Path,
) -> crate::error::Result<()> {
    let mut path = String::new();
    walk_yaml_keys(value, &mut path, source_path)
}

fn walk_yaml_keys(
    value: &serde_yaml::Value,
    path: &mut String,
    source_path: &Path,
) -> crate::error::Result<()> {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let serde_yaml::Value::String(name) = key else {
                    let location = if path.is_empty() {
                        "the document root".to_string()
                    } else {
                        format!("`{path}`")
                    };
                    return Err(crate::error::Error::Config(format!(
                        "resource file {} has a non-string mapping key ({}) in {location}; \
                         configuration is JSON-shaped and only string keys survive parsing — \
                         quote the key to keep it",
                        source_path.display(),
                        describe_yaml_key(key),
                    )));
                };
                let restore = path.len();
                path.push('.');
                path.push_str(name);
                walk_yaml_keys(child, path, source_path)?;
                path.truncate(restore);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                let restore = path.len();
                path.push('[');
                path.push_str(&index.to_string());
                path.push(']');
                walk_yaml_keys(item, path, source_path)?;
                path.truncate(restore);
            }
        }
        serde_yaml::Value::Tagged(tagged) => walk_yaml_keys(&tagged.value, path, source_path)?,
        _ => {}
    }
    Ok(())
}

fn describe_yaml_key(key: &serde_yaml::Value) -> String {
    match key {
        serde_yaml::Value::Null => "null".to_string(),
        serde_yaml::Value::Bool(value) => format!("boolean `{value}`"),
        serde_yaml::Value::Number(value) => format!("number `{value}`"),
        serde_yaml::Value::Sequence(_) => "a sequence".to_string(),
        serde_yaml::Value::Mapping(_) => "a mapping".to_string(),
        serde_yaml::Value::Tagged(tagged) => format!("a `{}`-tagged value", tagged.tag),
        serde_yaml::Value::String(value) => format!("string `{value}`"),
    }
}

/// Strictly deserialize a complete resource wrapper, including a fully merged
/// overlay document.
pub(crate) fn resource_from_json_value(
    value: serde_json::Value,
    source_path: &Path,
    options: LoadOptions,
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
            spec: deserialize_gateway_spec(spec, source_path, options)?,
        }),
        "Consumer" => Ok(Resource::Consumer {
            spec: deserialize_gateway_spec(spec, source_path, options)?,
        }),
        "Upstream" => Ok(Resource::Upstream {
            spec: deserialize_gateway_spec(spec, source_path, options)?,
        }),
        "PluginConfig" => Ok(Resource::PluginConfig {
            spec: deserialize_gateway_spec(spec, source_path, options)?,
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

/// [`deserialize_spec`] for the four gateway kinds, which additionally carry a
/// `#[serde(flatten)]` map of unknown top-level fields.
///
/// `serde_ignored` never sees those: `flatten` captures an unrecognized key
/// into the map instead of asking the deserializer to ignore it. That is the
/// mechanism the pass-through relies on, and also why the fail-closed check has
/// to live here rather than in `reject_ignored` — the map is the only place an
/// unknown top-level field shows up. Nested unknowns are unaffected: known
/// fields are still deserialized straight from the map access, so
/// `serde_ignored` reports anything ignored inside them exactly as before.
fn deserialize_gateway_spec<T: DeserializeOwned + PassthroughFields>(
    value: serde_json::Value,
    source_path: &Path,
    options: LoadOptions,
) -> crate::error::Result<T> {
    let parsed: T = deserialize_spec(value, source_path)?;
    check_passthrough_fields(parsed.passthrough(), source_path, options)?;
    Ok(parsed)
}

/// Fail closed on unknown top-level `spec` fields, or announce them loudly when
/// the operator has opted into carrying them.
fn check_passthrough_fields(
    extra: &BTreeMap<String, serde_json::Value>,
    source_path: &Path,
    options: LoadOptions,
) -> crate::error::Result<()> {
    if extra.is_empty() {
        return Ok(());
    }

    let fields: Vec<String> = extra.keys().map(|key| format!(".spec.{key}")).collect();
    if !options.allow_unknown_fields {
        return reject_ignored(source_path, fields);
    }

    // stderr, never stdout: `gitforgeops export` writes the assembled YAML to
    // stdout and a warning interleaved into it would corrupt the document.
    eprintln!(
        "Warning: {}: {} unknown top-level field(s) kept verbatim because \
         FERRUM_ALLOW_UNKNOWN_FIELDS is set: {}. gitforgeops does not model these — the gateway \
         is the authority on whether they are valid.",
        source_path.display(),
        fields.len(),
        fields.join(", "),
    );
    Ok(())
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
