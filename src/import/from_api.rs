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
        let config = client.get_backup(&namespace).await?;
        let namespace_result = split_config(&config, output_dir)?;
        result.proxies += namespace_result.proxies;
        result.consumers += namespace_result.consumers;
        result.upstreams += namespace_result.upstreams;
        result.plugin_configs += namespace_result.plugin_configs;
    }

    Ok(result)
}
