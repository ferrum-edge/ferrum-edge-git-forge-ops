use std::path::Path;

use crate::http_client::BackupSnapshot;
use crate::import::{
    split_config_with_inventory, validate_migration_bundle_source, ImportInventory,
    ImportPassthroughPolicy, ImportResult, ImportSourceMetadata,
};

/// `passthrough_policy` carries the `--accept-unknown-field` acknowledgements
/// and `FERRUM_ALLOW_UNKNOWN_FIELDS`; `allow_plaintext_plugin_config` lists
/// `plugin_name`s whose unclassifiable config strings the operator has
/// reviewed and accepted as plaintext. Both are enforced before anything is
/// staged; see [`split_config_with_inventory`].
pub fn import_from_file(
    file_path: &Path,
    output_dir: &Path,
    credential_bundle_output: Option<&Path>,
    passthrough_policy: &ImportPassthroughPolicy,
    allow_plaintext_plugin_config: &[String],
) -> crate::error::Result<ImportResult> {
    import_from_file_selected(
        file_path,
        output_dir,
        None,
        credential_bundle_output,
        passthrough_policy,
        allow_plaintext_plugin_config,
    )
}

/// [`import_from_file`] under a namespace selection (`FERRUM_NAMESPACE` or the
/// environment's `namespace_filter`).
///
/// File import publishes the whole document: its count seal and source
/// provenance describe every row in it, so silently dropping rows would make
/// the manifest disagree with the tree. A selection is therefore honored by
/// refusing a document that carries any resource outside the selected
/// namespace, before anything is staged and before credentials are captured.
/// A document wholly inside the selection imports unchanged.
pub fn import_from_file_selected(
    file_path: &Path,
    output_dir: &Path,
    namespace_filter: Option<&str>,
    credential_bundle_output: Option<&Path>,
    passthrough_policy: &ImportPassthroughPolicy,
    allow_plaintext_plugin_config: &[String],
) -> crate::error::Result<ImportResult> {
    if let Some(bundle_path) = credential_bundle_output {
        validate_migration_bundle_source(bundle_path, file_path)?;
    }
    // An import document is a whole backup, so this bound is far above the
    // per-resource one — still finite, and enforced during the read itself
    // (one byte past the limit), so a crafted file cannot spend unbounded
    // memory before the refusal.
    const MAX_IMPORT_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;
    let contents = {
        use std::io::Read as _;
        let file =
            std::fs::File::open(file_path).map_err(|source| crate::error::Error::FileRead {
                path: file_path.to_path_buf(),
                source,
            })?;
        let mut bytes = Vec::new();
        file.take(MAX_IMPORT_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| crate::error::Error::FileRead {
                path: file_path.to_path_buf(),
                source,
            })?;
        if bytes.len() > MAX_IMPORT_DOCUMENT_BYTES {
            return Err(crate::error::Error::Config(format!(
                "import document exceeds the {MAX_IMPORT_DOCUMENT_BYTES}-byte limit; no tree or credential bundle was published"
            )));
        }
        String::from_utf8(bytes).map_err(|error| crate::error::Error::FileRead {
            path: file_path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })?
    };
    // YAML is a superset of the JSON returned by GET /backup. Decode to a JSON
    // value, then use the same envelope parser as API import so opaque sections
    // are inventoried consistently instead of being discarded by GatewayConfig.
    let value = crate::yaml::parse_value(&contents, crate::yaml::IMPORT_LIMITS).map_err(|_| {
        crate::error::Error::Config(
            "invalid import document; credential-bearing details withheld".to_string(),
        )
    })?;
    if value.get("conditional").is_some() {
        return Err(crate::error::Error::Config(
            "exact conditional exports require authenticated API import with response headers; \
             no tree or credential bundle was published"
                .to_string(),
        ));
    }
    let snapshot = BackupSnapshot::from_value(value)?;
    let namespaces = source_namespaces(&snapshot);
    if let Some(selected) = namespace_filter {
        let outside: Vec<&str> = namespaces
            .iter()
            .map(String::as_str)
            .filter(|namespace| *namespace != selected)
            .collect();
        if !outside.is_empty() {
            return Err(crate::error::Error::Config(format!(
                "the import document contains namespace(s) {outside:?} outside the selected \
                 namespace {selected:?}; file import publishes the whole document. Import a \
                 backup of the selected namespace only, use --from-api, or clear \
                 FERRUM_NAMESPACE and the environment's namespace_filter for this import; no \
                 tree or credential bundle was published"
            )));
        }
    }
    let source = ImportSourceMetadata::from_snapshot("file", namespaces, &snapshot);
    split_config_with_inventory(
        &snapshot.config,
        output_dir,
        ImportInventory {
            skipped_api_specs: snapshot.extras.api_spec_count(),
            skipped_trust_bundles: snapshot.extras.trust_bundle_count(),
            unsupported_sections: snapshot.unsupported_sections.clone(),
            sources: vec![source],
            unmodeled_nested_fields: snapshot.unmodeled_nested_fields.clone(),
        },
        credential_bundle_output,
        true,
        passthrough_policy,
        allow_plaintext_plugin_config,
    )
}

fn source_namespaces(snapshot: &BackupSnapshot) -> Vec<String> {
    snapshot
        .config
        .proxies
        .iter()
        .map(|resource| resource.namespace.clone())
        .chain(
            snapshot
                .config
                .consumers
                .iter()
                .map(|resource| resource.namespace.clone()),
        )
        .chain(
            snapshot
                .config
                .upstreams
                .iter()
                .map(|resource| resource.namespace.clone()),
        )
        .chain(
            snapshot
                .config
                .plugin_configs
                .iter()
                .map(|resource| resource.namespace.clone()),
        )
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
