use std::path::Path;

use crate::http_client::BackupSnapshot;
use crate::import::{
    split_config_with_inventory, validate_migration_bundle_source, ImportInventory, ImportResult,
    ImportSourceMetadata,
};

/// `allow_plaintext_plugin_config` lists `plugin_name`s whose unclassifiable
/// config strings the operator has reviewed and accepted as plaintext; see
/// [`split_config_with_inventory`].
pub fn import_from_file(
    file_path: &Path,
    output_dir: &Path,
    credential_bundle_output: Option<&Path>,
    allow_plaintext_plugin_config: &[String],
) -> crate::error::Result<ImportResult> {
    if let Some(bundle_path) = credential_bundle_output {
        validate_migration_bundle_source(bundle_path, file_path)?;
    }
    let contents =
        std::fs::read_to_string(file_path).map_err(|source| crate::error::Error::FileRead {
            path: file_path.to_path_buf(),
            source,
        })?;
    // YAML is a superset of the JSON returned by GET /backup. Decode to a JSON
    // value, then use the same envelope parser as API import so opaque sections
    // are inventoried consistently instead of being discarded by GatewayConfig.
    let value: serde_json::Value =
        serde_yaml::from_str(&contents).map_err(|source| crate::error::Error::YamlParse {
            path: file_path.to_path_buf(),
            source,
        })?;
    let snapshot = BackupSnapshot::from_value(value)?;
    let namespaces = source_namespaces(&snapshot);
    let source = ImportSourceMetadata::from_snapshot("file", namespaces, &snapshot);
    split_config_with_inventory(
        &snapshot.config,
        output_dir,
        ImportInventory {
            skipped_api_specs: snapshot.extras.api_spec_count(),
            skipped_trust_bundles: snapshot.extras.trust_bundle_count(),
            unsupported_sections: snapshot.unsupported_sections.clone(),
            sources: vec![source],
        },
        credential_bundle_output,
        true,
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
