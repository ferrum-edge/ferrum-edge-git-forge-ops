use std::path::Path;

use crate::config::GatewayConfig;
use crate::http_client::AdminClient;
use crate::import::{
    split_config_with_inventory, ImportInventory, ImportPassthroughPolicy, ImportResult,
    ImportSourceMetadata,
};

/// `passthrough_policy` carries the `--accept-unknown-field` acknowledgements
/// and `FERRUM_ALLOW_UNKNOWN_FIELDS`; `allow_plaintext_plugin_config` lists
/// `plugin_name`s whose unclassifiable config strings the operator has
/// reviewed and accepted as plaintext. Both are enforced before anything is
/// staged; see [`split_config_with_inventory`].
pub async fn import_from_api(
    client: &AdminClient,
    output_dir: &Path,
    namespace_filter: Option<&str>,
    credential_bundle_output: Option<&Path>,
    passthrough_policy: &ImportPassthroughPolicy,
    allow_plaintext_plugin_config: &[String],
) -> crate::error::Result<ImportResult> {
    let mut namespaces = match namespace_filter {
        Some(namespace) => vec![namespace.to_string()],
        None => client.list_namespaces().await?,
    };
    namespaces.sort();
    namespaces.dedup();

    // Fetch and validate the entire source before the first filesystem write.
    // This avoids a failure on namespace N leaving namespaces 1..N-1 stranded
    // in an output tree that a safe rerun refuses to overwrite.
    let mut combined = GatewayConfig::default();
    let mut backup_version: Option<String> = None;
    let mut skipped_api_specs = 0;
    let mut skipped_trust_bundles = 0;
    let mut unsupported_sections = std::collections::BTreeSet::new();
    let mut sources = Vec::new();

    for namespace in namespaces {
        let snapshot = client.get_backup_snapshot(&namespace).await?;
        if snapshot.cached {
            return Err(crate::error::Error::StaleGatewayView(format!(
                "refusing to import namespace '{namespace}' from X-Data-Source: cached: the snapshot may be stale and omits API-spec ownership metadata; wait for the config database to recover"
            )));
        }
        // Live reads treat a mismatched count seal as advisory so a single
        // gateway quirk cannot take `diff`/`plan`/`apply` down. Import is the
        // opposite case: this document becomes the repository's permanent
        // desired state, and a seal that disagrees means it may be truncated.
        if let Some(notice) = snapshot.seal_violation_notice() {
            return Err(crate::error::Error::Config(format!(
                "refusing to import namespace '{namespace}': the backup's count seal does not match the document it sealed ({notice}). The snapshot may be truncated; publishing it would make a partial configuration the repository's desired state."
            )));
        }
        validate_snapshot_namespace(&snapshot.config, &namespace)?;

        match &backup_version {
            Some(version) if version != &snapshot.config.version => {
                return Err(crate::error::Error::Config(format!(
                    "namespace '{namespace}' backup version {:?} does not match earlier namespace version {:?}",
                    snapshot.config.version, version
                )));
            }
            None => backup_version = Some(snapshot.config.version.clone()),
            _ => {}
        }

        sources.push(ImportSourceMetadata::from_snapshot(
            "api",
            vec![namespace.clone()],
            &snapshot,
        ));

        combined.proxies.extend(snapshot.config.proxies);
        combined.consumers.extend(snapshot.config.consumers);
        combined.upstreams.extend(snapshot.config.upstreams);
        combined
            .plugin_configs
            .extend(snapshot.config.plugin_configs);

        // API specs and gateway trust bundles live outside the four resource
        // kinds this repo models, so they are counted and reported rather than
        // written out as resource files that `apply` could never round-trip.
        skipped_api_specs += snapshot.extras.api_spec_count();
        skipped_trust_bundles += snapshot.extras.trust_bundle_count();
        unsupported_sections.extend(snapshot.unsupported_sections);
    }

    if let Some(version) = backup_version {
        combined.version = version;
    }
    split_config_with_inventory(
        &combined,
        output_dir,
        ImportInventory {
            skipped_api_specs,
            skipped_trust_bundles,
            unsupported_sections: unsupported_sections.into_iter().collect(),
            sources,
        },
        credential_bundle_output,
        true,
        passthrough_policy,
        allow_plaintext_plugin_config,
    )
}

fn validate_snapshot_namespace(
    config: &GatewayConfig,
    requested_namespace: &str,
) -> crate::error::Result<()> {
    for (kind, id, actual_namespace) in config
        .proxies
        .iter()
        .map(|resource| ("Proxy", resource.id.as_str(), resource.namespace.as_str()))
        .chain(config.consumers.iter().map(|resource| {
            (
                "Consumer",
                resource.id.as_str(),
                resource.namespace.as_str(),
            )
        }))
        .chain(config.upstreams.iter().map(|resource| {
            (
                "Upstream",
                resource.id.as_str(),
                resource.namespace.as_str(),
            )
        }))
        .chain(config.plugin_configs.iter().map(|resource| {
            (
                "PluginConfig",
                resource.id.as_str(),
                resource.namespace.as_str(),
            )
        }))
    {
        if actual_namespace != requested_namespace {
            return Err(crate::error::Error::Config(format!(
                "namespace-scoped backup for {requested_namespace:?} returned {kind} {id:?} in namespace {actual_namespace:?}; refusing to publish a cross-namespace import"
            )));
        }
    }
    Ok(())
}
