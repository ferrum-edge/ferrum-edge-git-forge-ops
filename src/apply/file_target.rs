use std::io::Write;
use std::path::Path;

use crate::config::{GatewayConfig, MeshConfigSpec};

/// Top-level key holding the anti-truncation seal understood by ferrum-edge's
/// file-mode loader.
const RESOURCE_COUNTS_KEY: &str = "resource_counts";

/// The only `version` a mesh document may declare. ferrum-edge's mesh file
/// loader treats `version` as optional but rejects anything other than the
/// current config version — there are no mesh file migrations.
pub const MESH_DOCUMENT_VERSION: &str = "1";

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

/// Serialize `mesh` into the standalone mesh document a mesh-protocol node
/// loads from `FERRUM_MESH_FILE_CONFIG_PATH`.
///
/// The document carries **exactly two keys**, `version` and `mesh`, and
/// nothing else. ferrum-edge's `MeshFileDocument` is `deny_unknown_fields`
/// precisely so a document that also carries gateway resources fails loudly
/// instead of silently dropping them — so the mesh document is built key by
/// key here rather than by serializing a struct that might one day grow a
/// third field.
///
/// Conversely the gateway document never gains a `mesh:` key: gateway file
/// mode ignores it entirely, so writing it there would produce a config that
/// looks like it configures a mesh and does not.
pub fn render_mesh_yaml(mesh: &MeshConfigSpec) -> crate::error::Result<String> {
    let mut document = serde_yaml::Mapping::with_capacity(2);
    document.insert(
        serde_yaml::Value::from("version"),
        serde_yaml::Value::from(MESH_DOCUMENT_VERSION),
    );
    document.insert(serde_yaml::Value::from("mesh"), serde_yaml::to_value(mesh)?);
    Ok(serde_yaml::to_string(&serde_yaml::Value::Mapping(
        document,
    ))?)
}

pub fn apply_file(config: &GatewayConfig, output_path: &str) -> crate::error::Result<()> {
    publish_document(output_path, render_file_yaml(config)?.as_bytes())
}

/// Publish the standalone `{version, mesh}` document at `output_path`
/// (`FERRUM_MESH_FILE_OUTPUT_PATH`), with the same atomic-publish guarantees
/// as the gateway file: mesh nodes read their document through the identical
/// stable-file primitive (two reads, 20 ms apart, required byte-identical),
/// so an in-place rewrite can cost a mesh reload just as it can a gateway one.
pub fn apply_mesh_file(mesh: &MeshConfigSpec, output_path: &str) -> crate::error::Result<()> {
    publish_document(output_path, render_mesh_yaml(mesh)?.as_bytes())
}

/// What reconciling the mesh destination against the repository's desired
/// state does, or would do.
///
/// Mesh publication is a reconciliation, not an append-only write: a
/// repository that deletes its last `MeshConfig` fragment has to converge the
/// published document too, or every mesh node reading it keeps enforcing
/// policy the repository no longer declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshPublication {
    /// The repository declares at least one fragment; the merged document is
    /// the destination's content.
    Published,
    /// The repository declares no fragment and gitforgeops published the
    /// destination: it becomes the explicit empty document
    /// (`{version, mesh: {}}`).
    Retracted,
    /// Same as [`Self::Retracted`], but the destination already holds exactly
    /// that document. Nothing is written — a mesh node reloads on any content
    /// change, and a no-op republish is not worth one.
    AlreadyRetracted,
    /// The repository declares no fragment and never published this
    /// destination. Nothing to converge.
    NeverPublished,
    /// The repository declares no fragment, but the destination exists and is
    /// not a document gitforgeops published. Left untouched, and reported: the
    /// operator repointed `FERRUM_MESH_FILE_OUTPUT_PATH` at somebody else's
    /// file, or hand-edited this one.
    Unattributed,
    /// No fragment was *selected*, but the run is namespace-filtered, so
    /// absence is not evidence of deletion — the fragments may simply live in
    /// a namespace this run cannot see. Left untouched, and reported.
    NarrowedScope,
}

/// What a run is allowed to conclude from "the assembler produced no mesh".
#[derive(Debug, Clone, Copy)]
pub struct MeshRetractionScope {
    /// The state ledger records this destination as gitforgeops-published.
    pub ledger_attributed: bool,
    /// This run saw every `MeshConfig` fragment the repository declares — no
    /// `FERRUM_NAMESPACE` filter narrowed the selection. Retraction rewrites
    /// one mesh-wide document, so a filtered run that happens to select no
    /// fragment must never conclude the repository declares none.
    pub covers_repository: bool,
}

/// The document a retraction publishes: the mesh section, explicitly empty.
///
/// ferrum-edge's `MeshFileDocument` is `deny_unknown_fields` with a
/// **required** `mesh` field, and every field of the mesh model itself carries
/// `#[serde(default)]` — so `mesh: {}` is the loader's way of spelling "no
/// mesh policy", and it survives the same `ferrum-edge validate -m mesh` pass
/// a populated document does. Removing the file instead would not: the mesh
/// file source bails with `mesh configuration file not found` and refuses to
/// start, which turns a policy retraction into a node outage.
fn render_mesh_retraction() -> crate::error::Result<String> {
    render_mesh_yaml(&MeshConfigSpec::default())
}

/// The `{version, mesh}` shape, re-read to prove a destination is one of ours.
#[derive(serde::Deserialize)]
struct PublishedMeshDocument {
    version: String,
    mesh: MeshConfigSpec,
}

/// True when `path` holds bytes [`render_mesh_yaml`] itself produced.
///
/// The state ledger is the primary attribution record, but it only exists from
/// the first apply that ran a gitforgeops build carrying it — a repository
/// that published mesh documents under an older build, then removed its last
/// fragment, would otherwise never converge. Round-tripping the destination
/// through the very renderer that writes it is the second, offline signal:
/// byte-identity means the file carries exactly a `version` and a `mesh`
/// section this build would emit, with no extra keys, no comments and no
/// hand-formatting. Anything else — a foreign file, an operator's own
/// document, an unreadable path — answers `false` and is left alone.
fn is_self_published_mesh_document(path: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(document) = serde_yaml::from_str::<PublishedMeshDocument>(&contents) else {
        return false;
    };
    document.version == MESH_DOCUMENT_VERSION
        && render_mesh_yaml(&document.mesh).is_ok_and(|rendered| rendered == contents)
}

/// Decide what [`reconcile_mesh_file`] would do, without writing anything.
///
/// `plan` and `review` call this so a preview and the apply it previews cannot
/// disagree about a pending retraction. Reading the destination is the only
/// side effect.
pub fn plan_mesh_publication(
    mesh: Option<&MeshConfigSpec>,
    output_path: &str,
    scope: MeshRetractionScope,
) -> crate::error::Result<MeshPublication> {
    if mesh.is_some() {
        return Ok(MeshPublication::Published);
    }

    let path = Path::new(output_path);
    if !path.exists() {
        return Ok(MeshPublication::NeverPublished);
    }
    if !scope.covers_repository {
        return Ok(MeshPublication::NarrowedScope);
    }
    if !scope.ledger_attributed && !is_self_published_mesh_document(path) {
        return Ok(MeshPublication::Unattributed);
    }

    // An absent destination was handled above: there is nothing stale to
    // retract, and fabricating an empty document where the operator has none
    // would create a file no run ever asked for.
    let retraction = render_mesh_retraction()?;
    match std::fs::read(path) {
        Ok(existing) if existing == retraction.as_bytes() => Ok(MeshPublication::AlreadyRetracted),
        // An unreadable destination is deliberately *not* swallowed here: the
        // publish below fails loudly rather than reporting a retraction that
        // never happened.
        _ => Ok(MeshPublication::Retracted),
    }
}

/// Converge the mesh destination with the repository's desired state.
///
/// Unlike [`apply_mesh_file`] this is total over `mesh`: `None` (the assembler
/// found no `MeshConfig` fragment at all) retracts a document this repository
/// published instead of silently leaving deleted mesh policy on disk. It never
/// removes the destination and never rewrites one it cannot attribute to
/// gitforgeops.
pub fn reconcile_mesh_file(
    mesh: Option<&MeshConfigSpec>,
    output_path: &str,
    scope: MeshRetractionScope,
) -> crate::error::Result<MeshPublication> {
    let publication = plan_mesh_publication(mesh, output_path, scope)?;
    match (publication, mesh) {
        (MeshPublication::Published, Some(mesh)) => {
            publish_document(output_path, render_mesh_yaml(mesh)?.as_bytes())?;
        }
        (MeshPublication::Retracted, _) => {
            publish_document(output_path, render_mesh_retraction()?.as_bytes())?;
        }
        // `Published` without a document cannot happen — `plan_mesh_publication`
        // returns it only for `Some` — and the remaining outcomes write nothing
        // by definition.
        _ => {}
    }
    Ok(publication)
}

/// Atomically publish arbitrary export bytes with ordinary artifact
/// permissions. Used for placeholder-only YAML and age-encrypted output.
pub fn publish_export(output_path: &str, bytes: &[u8]) -> crate::error::Result<()> {
    publish_document_with_permissions(output_path, bytes, PublicationPermissions::Regular)
}

/// Atomically publish a plaintext materialized export. The payload contains
/// live consumer credentials, so its mode is forced to owner-read/write even
/// when replacing a more broadly-readable destination.
pub fn publish_private_export(output_path: &str, bytes: &[u8]) -> crate::error::Result<()> {
    publish_document_with_permissions(output_path, bytes, PublicationPermissions::Private)
}

/// Create the destination directory and atomically publish `bytes` into it.
fn publish_document(output_path: &str, bytes: &[u8]) -> crate::error::Result<()> {
    publish_document_with_permissions(output_path, bytes, PublicationPermissions::Regular)
}

#[derive(Debug, Clone, Copy)]
enum PublicationPermissions {
    Regular,
    Private,
}

fn publish_document_with_permissions(
    output_path: &str,
    bytes: &[u8],
    permissions: PublicationPermissions,
) -> crate::error::Result<()> {
    let path = Path::new(output_path);
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)?;

    write_atomically(path, parent, bytes, permissions)
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
///
/// For an ordinary artifact, a destination that already exists and is **not a
/// regular file** — the
/// canonical cases being `gitforgeops export --output /dev/null` and a named
/// pipe — takes the direct-write path instead. Atomic replacement is not
/// merely unnecessary there, it is impossible: `rename(2)` onto `/dev/null`
/// would replace the device node with a regular file, and the temp file has to
/// be created in `/dev` first, which an unprivileged process cannot do. What
/// the caller asked for is a write to that object, so write to it. Private
/// publications never take this path: their destination must be a regular
/// file so credential bytes cannot be streamed into an attacker-controlled
/// pipe or terminal.
fn write_atomically(
    path: &Path,
    parent: &Path,
    bytes: &[u8],
    permissions: PublicationPermissions,
) -> crate::error::Result<()> {
    if destination_needs_direct_write(path) {
        return match permissions {
            PublicationPermissions::Regular => write_directly(path, bytes),
            PublicationPermissions::Private => Err(crate::error::Error::Config(format!(
                "private export destination {} must be a regular file",
                path.display()
            ))),
        };
    }

    let mut temp = tempfile::Builder::new()
        .prefix(".gitforgeops-")
        .suffix(".tmp")
        .tempfile_in(parent)?;

    temp.write_all(bytes)?;
    temp.flush()?;
    // Durability before the rename: a rename of a file whose contents are
    // still only in the page cache can survive a crash as an empty file.
    temp.as_file().sync_all()?;

    apply_destination_permissions(path, temp.path(), permissions)?;

    temp.persist(path)
        .map_err(|err| crate::error::Error::Io(err.error))?;

    sync_parent_directory(parent, permissions)?;

    Ok(())
}

/// True when the destination exists and is something other than a regular
/// file. A missing destination is a regular-file publication (the atomic
/// path); a directory is left to the direct write, which fails with a clear
/// `Is a directory` rather than a puzzling rename error.
fn destination_needs_direct_write(path: &Path) -> bool {
    // Follows symlinks deliberately: `--output /dev/stdout` is usually a
    // symlink to a device, and what matters is what it points at.
    std::fs::metadata(path).is_ok_and(|meta| !meta.is_file())
}

/// Write straight to an existing non-regular destination. No temp file, no
/// rename, and no permission adjustment — the caller does not own the mode of
/// a device node or a pipe, and forcing 0600 on `/dev/null` would be both
/// futile and rude.
fn write_directly(path: &Path, bytes: &[u8]) -> crate::error::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    // A device or pipe has no durability to speak of and several of them
    // reject `fsync` outright; a failure here must not turn a completed write
    // into an error.
    let _ = file.sync_all();
    Ok(())
}

/// Make the new directory entry durable after a rename.
///
/// Fatal only for a [`PublicationPermissions::Private`] publication — a
/// materialized export of live credentials, where "the file is on disk" has to
/// be true rather than likely. For an ordinary artifact, a filesystem that
/// refuses to sync a directory (some network and container filesystems do,
/// with `EINVAL`) is not a reason to fail a publication whose bytes are
/// already written and renamed into place; warn instead.
#[cfg(unix)]
fn sync_parent_directory(
    parent: &Path,
    permissions: PublicationPermissions,
) -> crate::error::Result<()> {
    let synced = std::fs::File::open(parent).and_then(|directory| directory.sync_all());
    match (synced, permissions) {
        (Ok(()), _) => Ok(()),
        (Err(source), PublicationPermissions::Private) => Err(crate::error::Error::Io(source)),
        (Err(source), PublicationPermissions::Regular) => {
            eprintln!(
                "Warning: published {} but could not fsync its directory ({source}); the file is written and renamed into place, but its directory entry may not survive a host crash.",
                parent.display()
            );
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn sync_parent_directory(
    _parent: &Path,
    _permissions: PublicationPermissions,
) -> crate::error::Result<()> {
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
fn apply_destination_permissions(
    dest: &Path,
    temp: &Path,
    policy: PublicationPermissions,
) -> crate::error::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match policy {
        PublicationPermissions::Private => 0o600,
        PublicationPermissions::Regular => match std::fs::metadata(dest) {
            Ok(meta) => meta.permissions().mode() & 0o777,
            Err(_) => 0o644,
        },
    };
    std::fs::set_permissions(temp, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_destination_permissions(
    _dest: &Path,
    _temp: &Path,
    _policy: PublicationPermissions,
) -> crate::error::Result<()> {
    Ok(())
}
