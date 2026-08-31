use std::path::Path;

use crate::http_client::AdminClient;
use crate::import::{split_config, ImportResult};

pub async fn import_from_api(
    client: &AdminClient,
    output_dir: &Path,
    namespace_filter: Option<&str>,
) -> crate::error::Result<ImportResult> {
    let namespaces = match namespace_filter {
        Some(namespace) => vec![namespace.to_string()],
        None => client.list_namespaces().await?,
    };

    let mut result = ImportResult::default();

    for namespace in namespaces {
        let snapshot = client.get_backup_snapshot(&namespace).await?;
        if snapshot.cached {
            // The cached fallback omits `api_specs` entirely and can lag the
            // database; an import from it silently produces an incomplete repo.
            eprintln!(
                "Warning: namespace '{namespace}' was exported from the gateway's in-memory cache \
                 (X-Data-Source: cached). The config database was unavailable, so this snapshot may \
                 be stale and omits API specs."
            );
        }

        let namespace_result = split_config(&snapshot.config, output_dir)?;
        result.proxies += namespace_result.proxies;
        result.consumers += namespace_result.consumers;
        result.upstreams += namespace_result.upstreams;
        result.plugin_configs += namespace_result.plugin_configs;

        // API specs and gateway trust bundles live outside the four resource
        // kinds this repo models, so they are counted and reported rather than
        // written out as resource files that `apply` could never round-trip.
        result.skipped_api_specs += snapshot.extras.api_spec_count();
        result.skipped_trust_bundles += snapshot.extras.trust_bundle_count();
    }

    Ok(result)
}
