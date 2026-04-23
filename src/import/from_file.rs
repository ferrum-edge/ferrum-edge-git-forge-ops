use std::path::Path;

use crate::config::GatewayConfig;
use crate::import::{split_config, ImportResult};

pub fn import_from_file(file_path: &Path, output_dir: &Path) -> crate::error::Result<ImportResult> {
    let contents =
        std::fs::read_to_string(file_path).map_err(|source| crate::error::Error::FileRead {
            path: file_path.to_path_buf(),
            source,
        })?;
    let config: GatewayConfig =
        serde_yaml::from_str(&contents).map_err(|source| crate::error::Error::YamlParse {
            path: file_path.to_path_buf(),
            source,
        })?;
    split_config(&config, output_dir)
}
