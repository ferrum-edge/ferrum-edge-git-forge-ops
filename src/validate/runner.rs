use std::io::Write;
use std::process::Command;

use crate::config::GatewayConfig;

/// Result of running `ferrum-edge validate`.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Assemble a temporary YAML file from `GatewayConfig`, shell out to
/// `ferrum-edge validate -c <temp_file>`, and return the validation result.
pub fn run_validation(
    config: &GatewayConfig,
    binary_path: &str,
) -> crate::error::Result<ValidationResult> {
    // Check that the binary exists / is callable
    let which_result = Command::new("which").arg(binary_path).output();
    let binary_exists = match which_result {
        Ok(output) => output.status.success(),
        Err(_) => {
            // "which" might not exist (Windows); try running the binary directly
            Command::new(binary_path)
                .arg("--help")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    };

    if !binary_exists {
        // Also check if it's a direct path that exists
        if !std::path::Path::new(binary_path).exists() {
            return Err(crate::error::Error::BinaryNotFound(binary_path.to_string()));
        }
    }

    // Serialize config to YAML
    let yaml = serde_yaml::to_string(config)?;

    // Write to a temp file
    let temp_dir = std::env::temp_dir();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let temp_path = temp_dir.join(format!("gitforgeops-validate-{}.yaml", timestamp));

    let mut file =
        std::fs::File::create(&temp_path).map_err(|source| crate::error::Error::FileRead {
            path: temp_path.clone(),
            source,
        })?;
    file.write_all(yaml.as_bytes())?;
    drop(file);

    // Run ferrum-edge validate
    let output = Command::new(binary_path)
        .arg("validate")
        .arg("-c")
        .arg(&temp_path)
        .output();

    // Clean up temp file regardless of outcome
    let _ = std::fs::remove_file(&temp_path);

    let output = output?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ValidationResult {
        success: output.status.success(),
        stdout,
        stderr,
        exit_code,
    })
}
