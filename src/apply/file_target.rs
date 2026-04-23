use std::path::Path;

use crate::config::GatewayConfig;

pub fn apply_file(config: &GatewayConfig, output_path: &str) -> crate::error::Result<()> {
    let path = Path::new(output_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let yaml = serde_yaml::to_string(config)?;
    std::fs::write(path, yaml)?;
    Ok(())
}
