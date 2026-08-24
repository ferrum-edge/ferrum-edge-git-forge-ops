pub mod from_api;
pub mod from_file;

pub use from_api::import_from_api;
pub use from_file::import_from_file;

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::config::schema::{GatewayConfig, Resource};

#[derive(Debug, Default)]
pub struct ImportResult {
    /// Number of proxy files written.
    pub proxies: usize,
    /// Number of consumer files written.
    pub consumers: usize,
    /// Number of upstream files written.
    pub upstreams: usize,
    /// Number of plugin config files written.
    pub plugin_configs: usize,
    /// API spec documents present in the source backup but **not** written.
    /// `Resource` models four kinds; API specs are managed through the admin
    /// API (`/api-specs`) and have no GitOps representation here.
    pub skipped_api_specs: usize,
    /// Gateway trust-bundle records present in the source backup but not
    /// written, for the same reason.
    pub skipped_trust_bundles: usize,
    /// Proxies / upstreams / plugin configs that carry an `api_spec_id` and
    /// were therefore **not** written as repo files.
    ///
    /// The gateway's OpenAPI-spec ingestion owns these: it creates, updates and
    /// deletes them whenever the spec is re-imported. Writing them into
    /// `resources/` would declare the repo their owner too, and the two owners
    /// then fight — every spec re-import shows up as drift, and every apply
    /// tries to push the repo's stale copy back. `diff` already reports them in
    /// their own "spec-owned" section, which is where they belong.
    pub skipped_spec_owned: usize,
}

impl ImportResult {
    /// Operator-facing note about backup sections this tool does not import,
    /// or `None` when the backup carried none.
    pub fn unmanaged_sections_notice(&self) -> Option<String> {
        if self.skipped_api_specs == 0
            && self.skipped_trust_bundles == 0
            && self.skipped_spec_owned == 0
        {
            return None;
        }
        let mut notice = String::new();
        if self.skipped_api_specs > 0 || self.skipped_trust_bundles > 0 {
            notice.push_str(&format!(
                "Not imported: {} API spec(s) and {} gateway trust-bundle record(s). These are \
                 managed through the admin API (`/api-specs`, `/gateway-trust-bundles`), not \
                 through this repo, and are left untouched by `gitforgeops apply`.",
                self.skipped_api_specs, self.skipped_trust_bundles
            ));
        }
        if self.skipped_spec_owned > 0 {
            if !notice.is_empty() {
                notice.push(' ');
            }
            notice.push_str(&format!(
                "{} spec-provisioned resources skipped — managed by API spec ingestion. They carry \
                 an `api_spec_id`, so the gateway rewrites them on every spec import; committing \
                 them here would make the repo a second owner and produce permanent conflicts.",
                self.skipped_spec_owned
            ));
        }
        Some(notice)
    }
}

/// Split a flat gateway configuration into per-resource YAML files.
///
/// The function refuses unsafe path components, duplicate source resources that
/// would target the same path, and pre-existing output files. Callers should use
/// an empty output directory or clean it intentionally before importing.
///
/// # Spec-owned resources are skipped
///
/// A proxy, upstream or plugin config carrying an `api_spec_id` belongs to the
/// gateway's OpenAPI-spec ingestion, which recreates it from the spec on every
/// import. Writing it into `resources/` would give it a second owner: the next
/// spec import rewrites the live copy, `diff` reports the repo's now-stale copy
/// as drift, and `apply` pushes it back — a conflict no edit resolves. They are
/// counted in [`ImportResult::skipped_spec_owned`] instead, and surfaced by
/// [`ImportResult::unmanaged_sections_notice`].
pub fn split_config(
    config: &GatewayConfig,
    output_dir: &Path,
) -> crate::error::Result<ImportResult> {
    let mut result = ImportResult::default();
    let mut targets = BTreeSet::new();
    let mut planned_writes = Vec::new();

    for proxy in &config.proxies {
        if proxy.api_spec_id.is_some() {
            result.skipped_spec_owned += 1;
            continue;
        }
        let namespace = safe_path_component(&proxy.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("proxies");
        let resource = Resource::Proxy {
            spec: proxy.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&proxy.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.proxies += 1;
    }

    for consumer in &config.consumers {
        let namespace = safe_path_component(&consumer.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("consumers");
        let resource = Resource::Consumer {
            spec: consumer.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&consumer.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.consumers += 1;
    }

    for upstream in &config.upstreams {
        if upstream.api_spec_id.is_some() {
            result.skipped_spec_owned += 1;
            continue;
        }
        let namespace = safe_path_component(&upstream.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("upstreams");
        let resource = Resource::Upstream {
            spec: upstream.clone(),
        };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&upstream.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.upstreams += 1;
    }

    for pc in &config.plugin_configs {
        if pc.api_spec_id.is_some() {
            result.skipped_spec_owned += 1;
            continue;
        }
        let namespace = safe_path_component(&pc.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("plugins");
        let resource = Resource::PluginConfig { spec: pc.clone() };
        let yaml = serde_yaml::to_string(&resource)?;
        let filename = resource_filename(&pc.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.plugin_configs += 1;
    }

    for (path, yaml) in planned_writes {
        write_resource_file(&path, yaml)?;
    }

    Ok(result)
}

fn plan_resource_file(
    dir: &Path,
    filename: String,
    yaml: String,
    targets: &mut BTreeSet<std::path::PathBuf>,
    planned_writes: &mut Vec<(std::path::PathBuf, String)>,
) -> crate::error::Result<()> {
    let path = dir.join(filename);
    if !targets.insert(path.clone()) {
        return Err(crate::error::Error::Config(format!(
            "import would write multiple resources to {}; duplicate namespace/kind/id in source config",
            path.display()
        )));
    }
    if path.exists() {
        return Err(crate::error::Error::Config(format!(
            "refusing to overwrite existing import target {}; choose an empty output directory or remove the file first",
            path.display()
        )));
    }
    planned_writes.push((path, yaml));
    Ok(())
}

fn write_resource_file(path: &Path, yaml: String) -> crate::error::Result<()> {
    if path.exists() {
        return Err(crate::error::Error::Config(format!(
            "refusing to overwrite existing import target {}; choose an empty output directory or remove the file first",
            path.display()
        )));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(yaml.as_bytes())?;
    Ok(())
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
