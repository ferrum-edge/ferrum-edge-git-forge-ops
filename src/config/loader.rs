use std::path::Path;

use walkdir::WalkDir;

use super::schema::Resource;
use super::strict::{self, LoadOptions};

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
    load_resources_with_options(resources_dir, LoadOptions::STRICT)
}

/// [`load_resources`] with an explicit unknown-field policy.
///
/// `main` passes the policy derived from `FERRUM_ALLOW_UNKNOWN_FIELDS`; every
/// other caller gets the fail-closed default from [`load_resources`].
pub fn load_resources_with_options(
    resources_dir: &Path,
    options: LoadOptions,
) -> crate::error::Result<Vec<(String, Resource)>> {
    let root_metadata = match std::fs::symlink_metadata(resources_dir) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::error::Error::NoResourcesDir(
                resources_dir.to_path_buf(),
            ));
        }
        Err(source) => {
            return Err(crate::error::Error::FileRead {
                path: resources_dir.to_path_buf(),
                source,
            });
        }
    };
    if root_metadata.file_type().is_symlink() {
        return Err(crate::error::Error::ConfigSymlink(
            resources_dir.to_path_buf(),
        ));
    }
    if !root_metadata.is_dir() {
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
    let mut namespace_entries = namespace_entries
        .map(|entry| {
            entry.map_err(|source| crate::error::Error::FileRead {
                path: resources_dir.to_path_buf(),
                source,
            })
        })
        .collect::<crate::error::Result<Vec<_>>>()?;
    namespace_entries.sort_by_key(std::fs::DirEntry::file_name);

    for ns_entry in namespace_entries {
        let ns_path = ns_entry.path();
        let ns_type = ns_entry
            .file_type()
            .map_err(|source| crate::error::Error::FileRead {
                path: ns_path.clone(),
                source,
            })?;
        if ns_type.is_symlink() {
            return Err(crate::error::Error::ConfigSymlink(ns_path));
        }
        if !ns_type.is_dir() {
            if ns_type.is_file() {
                if strict::enabled_yaml_file(&ns_path, "resource tree")? {
                    return Err(crate::error::Error::Config(format!(
                        "YAML file is outside a namespace directory in resource tree: {}",
                        ns_path.display()
                    )));
                }
            } else {
                return Err(crate::error::Error::Config(format!(
                    "special filesystem entry is forbidden in resource tree: {}",
                    ns_path.display()
                )));
            }
            continue;
        }

        let namespace = ns_path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "resource namespace directory is not valid UTF-8 or is empty: {}",
                    ns_path.display()
                ))
            })?
            .to_string();

        strict::validate_namespace_tree(&ns_path, "resource tree")?;

        // Walk subdirectories: proxies/, consumers/, upstreams/, plugins/, mesh/
        for (subdir, expected_kind) in strict::RESOURCE_SUBDIRECTORIES {
            let subdir_path = ns_path.join(subdir);
            let subdir_metadata = match std::fs::symlink_metadata(&subdir_path) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(crate::error::Error::FileRead {
                        path: subdir_path,
                        source,
                    })
                }
            };
            if subdir_metadata.file_type().is_symlink() {
                return Err(crate::error::Error::ConfigSymlink(subdir_path));
            }
            if !subdir_metadata.is_dir() {
                return Err(crate::error::Error::ConfigNotDirectory(subdir_path));
            }

            let mut paths = Vec::new();
            for entry in WalkDir::new(&subdir_path).follow_links(false) {
                let entry = entry.map_err(|source| {
                    let path = source
                        .path()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| subdir_path.clone());
                    crate::error::Error::WalkDir { path, source }
                })?;
                let path = entry.path();
                if entry.file_type().is_symlink() {
                    return Err(crate::error::Error::ConfigSymlink(path.to_path_buf()));
                }
                if !entry.file_type().is_file() {
                    if !entry.file_type().is_dir() {
                        return Err(crate::error::Error::Config(format!(
                            "special filesystem entry is forbidden in resource tree: {}",
                            path.display()
                        )));
                    }
                    continue;
                }

                if !strict::enabled_yaml_file(path, "resource tree")? {
                    continue;
                }

                paths.push(path.to_path_buf());
            }
            paths.sort();

            for path in paths {
                let contents = std::fs::read_to_string(&path).map_err(|source| {
                    crate::error::Error::FileRead {
                        path: path.clone(),
                        source,
                    }
                })?;

                let mut resource = strict::resource_from_yaml(&contents, &path, options)?;
                let declared_kind = strict::resource_kind(&resource);
                if declared_kind != expected_kind {
                    return Err(crate::error::Error::Config(format!(
                        "resource file {} declares kind {declared_kind:?} but is under {subdir}/ ({expected_kind})",
                        path.display()
                    )));
                }

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
