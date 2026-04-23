use std::path::Path;

use crate::http_client::AdminClient;
use crate::import::{split_config, ImportResult};

pub async fn import_from_api(
    client: &AdminClient,
    output_dir: &Path,
    namespace: &str,
) -> crate::error::Result<ImportResult> {
    let config = client.get_backup(namespace).await?;
    split_config(&config, output_dir)
}
