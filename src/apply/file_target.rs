use std::io::Write;
use std::path::Path;

use crate::config::GatewayConfig;

/// Top-level key holding the anti-truncation seal understood by ferrum-edge's
/// file-mode loader.
const RESOURCE_COUNTS_KEY: &str = "resource_counts";

/// Serialize `config` into the flat file-mode YAML document, including the
/// optional `resource_counts` integrity seal.
///
/// ferrum-edge's file-mode loader accepts an optional top-level
/// `resource_counts` mapping and checks it against the actual array lengths
/// before deserializing the document (the key is stripped first, so it never
/// reaches `GatewayConfig`). `proxies`, `consumers` and `plugin_configs` are
/// required inside the mapping; `upstreams` is optional and defaults to 0 —
/// we always emit all four. A truncated file (half-written, clipped by a
/// transport) then fails closed instead of silently loading a partial
/// configuration.
///
/// The seal is injected here, at the serialization layer, rather than as a
/// field on `GatewayConfig`: the struct mirrors what the admin API accepts,
/// and `resource_counts` is a file-mode-only artifact.
pub fn render_file_yaml(config: &GatewayConfig) -> crate::error::Result<String> {
    let value = serde_yaml::to_value(config)?;
    let serde_yaml::Value::Mapping(fields) = value else {
        // `GatewayConfig` always serializes as a mapping; if that ever stops
        // being true, emit the document unchanged rather than corrupting it.
        return Ok(serde_yaml::to_string(config)?);
    };

    let mut counts = serde_yaml::Mapping::new();
    counts.insert(
        serde_yaml::Value::from("proxies"),
        serde_yaml::Value::from(config.proxies.len() as u64),
    );
    counts.insert(
        serde_yaml::Value::from("consumers"),
        serde_yaml::Value::from(config.consumers.len() as u64),
    );
    counts.insert(
        serde_yaml::Value::from("plugin_configs"),
        serde_yaml::Value::from(config.plugin_configs.len() as u64),
    );
    counts.insert(
        serde_yaml::Value::from("upstreams"),
        serde_yaml::Value::from(config.upstreams.len() as u64),
    );

    // Keep `version` first and place the seal directly after it, so a human
    // (or a truncation-detecting eyeball) sees the document header before the
    // resource arrays. Remaining keys keep their original order.
    let version_key = serde_yaml::Value::from("version");
    let counts_key = serde_yaml::Value::from(RESOURCE_COUNTS_KEY);
    let mut sealed = serde_yaml::Mapping::with_capacity(fields.len() + 1);
    if let Some(version) = fields.get(&version_key) {
        sealed.insert(version_key.clone(), version.clone());
    }
    sealed.insert(counts_key.clone(), serde_yaml::Value::Mapping(counts));
    for (key, value) in fields {
        if key == version_key || key == counts_key {
            continue;
        }
        sealed.insert(key, value);
    }

    Ok(serde_yaml::to_string(&serde_yaml::Value::Mapping(sealed))?)
}

pub fn apply_file(config: &GatewayConfig, output_path: &str) -> crate::error::Result<()> {
    let path = Path::new(output_path);
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;

    let yaml = render_file_yaml(config)?;
    write_atomically(path, parent, yaml.as_bytes())
}

/// Publish `bytes` at `path` with write-temp → fsync → `rename(2)`.
///
/// ferrum-edge's file-mode loader has stable-file semantics: it re-stats the
/// candidate and performs a second independent read 20 ms later, requiring
/// byte-identical content, and fails closed after a handful of retries. A
/// truncate-and-rewrite in place is therefore visible to a concurrent reload
/// as a mid-update file and can cost a reload cycle (or wedge one). Renaming
/// a fully written, fsynced file over the destination makes the swap atomic
/// for readers.
///
/// The temp file is created in the destination's own directory so the rename
/// never crosses a filesystem boundary, and it is removed on drop if any step
/// before the rename fails.
fn write_atomically(path: &Path, parent: &Path, bytes: &[u8]) -> crate::error::Result<()> {
    let mut temp = tempfile::Builder::new()
        .prefix(".gitforgeops-")
        .suffix(".tmp")
        .tempfile_in(parent)?;

    temp.write_all(bytes)?;
    temp.flush()?;
    // Durability before the rename: a rename of a file whose contents are
    // still only in the page cache can survive a crash as an empty file.
    temp.as_file().sync_all()?;

    apply_destination_permissions(path, temp.path())?;

    temp.persist(path)
        .map_err(|err| crate::error::Error::Io(err.error))?;

    // Make the directory entry itself durable. Best-effort: a filesystem that
    // refuses to open a directory for this is not a reason to fail a
    // successful publish.
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Keep the published file's mode stable across republishes.
///
/// `tempfile` creates its files 0600, which would silently tighten the mode of
/// an output file the gateway (often a different user) has to read. Inherit
/// the destination's current mode when it already exists, otherwise fall back
/// to 0644 — what the previous `std::fs::write` produced under a default
/// umask.
#[cfg(unix)]
fn apply_destination_permissions(dest: &Path, temp: &Path) -> crate::error::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match std::fs::metadata(dest) {
        Ok(meta) => meta.permissions().mode() & 0o777,
        Err(_) => 0o644,
    };
    std::fs::set_permissions(temp, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_destination_permissions(_dest: &Path, _temp: &Path) -> crate::error::Result<()> {
    Ok(())
}
