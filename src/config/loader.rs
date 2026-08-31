use std::path::Path;

use walkdir::WalkDir;

use super::schema::Resource;

/// Walk `resources/<namespace>/` directories and parse each `.yaml`/`.yml` file
/// as a `Resource`. Returns `(namespace, Resource)` pairs.
///
/// Directory structure expected:
/// ```text
/// resources/
///   <namespace>/
///     proxies/    -> Proxy resources
///     consumers/  -> Consumer resources
///     upstreams/  -> Upstream resources
///     plugins/    -> PluginConfig resources
///     mesh/       -> MeshConfig fragments
/// ```
///
/// Files starting with `_` are skipped (convention for examples/templates).
///
/// `mesh/` differs from the four gateway directories: its files are
/// *fragments* of one shared mesh document rather than individually
/// addressable gateway resources, and a mesh document has no top-level
/// namespace of its own. The directory namespace is recorded for
/// `FERRUM_NAMESPACE` filtering and overlay matching only; the namespaces
/// that matter to the mesh live inside each workload / service / policy
/// entry. A mesh fragment with no explicit `id` is named after its file stem
/// so overlays have something stable to target.
pub fn load_resources(resources_dir: &Path) -> crate::error::Result<Vec<(String, Resource)>> {
    if !resources_dir.is_dir() {
        return Err(crate::error::Error::NoResourcesDir(
            resources_dir.to_path_buf(),
        ));
    }

    let mut results = Vec::new();

    // Iterate namespace directories directly under resources/
    let namespace_entries =
        std::fs::read_dir(resources_dir).map_err(|source| crate::error::Error::FileRead {
            path: resources_dir.to_path_buf(),
            source,
        })?;

    for ns_entry in namespace_entries {
        let ns_entry = ns_entry.map_err(|source| crate::error::Error::FileRead {
            path: resources_dir.to_path_buf(),
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

        // Walk subdirectories: proxies/, consumers/, upstreams/, plugins/, mesh/
        for subdir in &["proxies", "consumers", "upstreams", "plugins", "mesh"] {
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

                // Only process .yaml/.yml files
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext != "yaml" && ext != "yml" {
                    continue;
                }

                // Skip files starting with _
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

                let mut resource: Resource = serde_yaml::from_str(&contents).map_err(|source| {
                    crate::error::Error::YamlParse {
                        path: path.to_path_buf(),
                        source,
                    }
                })?;

                // Mesh fragments have no id inside the mesh schema, so an
                // unnamed one takes the file stem. Overlays match on that
                // name; without it, two fragments in the same namespace would
                // be indistinguishable to `apply_overlay`.
                if let Resource::MeshConfig { id, .. } = &mut resource {
                    if id.as_deref().map(str::trim).unwrap_or("").is_empty() {
                        *id = path
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .map(|stem| stem.to_string());
                    }
                }

                results.push((namespace.clone(), resource));
            }
        }
    }

    Ok(results)
}
