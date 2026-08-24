use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::config::GatewayConfig;

/// Result of running `ferrum-edge validate`.
///
/// `ferrum-edge validate` has no machine-readable output mode — it prints
/// plain text and exits 0 (success) or 1 (failure). Everything structured
/// (text / JSON / GitHub annotations) is produced gitforgeops-side by
/// [`crate::validate::reporter`] from these raw fields.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Prefix of every environment variable that can steer `ferrum-edge`'s own
/// configuration resolution (mode, settings paths, TLS material, ...).
const FERRUM_ENV_PREFIX: &str = "FERRUM_";

/// Build the argument vector for `ferrum-edge validate`.
///
/// The real CLI is
/// `ferrum-edge validate [-s|--settings <PATH>] [-c|--spec <PATH>] [-m|--mode <MODE>] [-v...]`.
/// There is **no `--format` flag**; do not add one.
///
/// Two of these arguments are load-bearing for correctness:
///
/// * `-m file` — ferrum-edge only parses and validates the *spec* when the
///   resolved mode is `file`. Mode precedence is CLI `--mode` > env
///   `FERRUM_MODE` > `ferrum.conf` > file-mode inference, so without an
///   explicit `-m file` an inherited `FERRUM_MODE` (or a stray `ferrum.conf`
///   declaring a mode) makes validation a silent fail-open no-op that still
///   exits 0.
/// * `-s <path>` — when omitted, ferrum-edge auto-discovers `./ferrum.conf`,
///   `./config/ferrum.conf` or `/etc/ferrum/ferrum.conf` and validates those
///   settings too, so an unrelated file in the checkout can fail the run.
///   Pointing `-s` at an empty settings file pins settings to defaults.
pub fn build_validate_args(settings_path: &Path, spec_path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("validate"),
        OsString::from("-m"),
        OsString::from("file"),
        OsString::from("-s"),
        settings_path.as_os_str().to_os_string(),
        OsString::from("-c"),
        spec_path.as_os_str().to_os_string(),
    ]
}

/// Select the environment variable names that must be removed from the
/// `ferrum-edge validate` child process.
///
/// We deliberately scrub by name (`Command::env_remove`) rather than calling
/// `Command::env_clear`: the child still needs a working ambient environment
/// (`PATH` to resolve linked libraries and helper binaries, `HOME`, `TMPDIR`,
/// locale and terminal variables, proxy/CA variables used by the platform TLS
/// stack). Clearing everything and re-adding a guessed allow-list would break
/// the binary in ways that are invisible until a specific deployment hits
/// them. The only variables that can change how `validate` interprets our
/// inputs all live in the `FERRUM_*` namespace, so removing exactly those
/// keeps the child functional while making the run hermetic with respect to
/// gitforgeops' own configuration.
pub fn scrubbed_env_names<I, S>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    names
        .into_iter()
        .filter(|name| name.as_ref().starts_with(FERRUM_ENV_PREFIX))
        .map(|name| name.as_ref().to_string())
        .collect()
}

/// True when `path` names an existing regular file that is actually
/// executable. `which` failing does not by itself mean the binary is missing
/// (Windows, stripped-down containers), but a plain `Path::exists()` check
/// would happily accept a non-executable file and produce a confusing
/// `Permission denied` at spawn time instead of `BinaryNotFound`.
fn is_executable_file(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => executable_bits_set(&meta),
        _ => false,
    }
}

#[cfg(unix)]
fn executable_bits_set(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_bits_set(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Create a temp file with owner-only permissions on unix.
fn private_temp_file(
    prefix: &str,
    suffix: &str,
) -> std::io::Result<tempfile::NamedTempFile<std::fs::File>> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix).suffix(suffix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }
    builder.tempfile()
}

/// Assemble a temporary YAML spec from `GatewayConfig`, shell out to
/// `ferrum-edge validate -m file -s <empty settings> -c <spec>`, and return
/// the validation result.
///
/// The spec is written through `tempfile` (0600 on unix, unpredictable name,
/// removed on drop along every path) because callers resolve credential
/// placeholders *before* validating — the document on disk can contain live
/// consumer credentials and must never land in a world-readable shared temp
/// file under a guessable name.
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
        // Also check if it's a direct path to an executable file
        if !is_executable_file(Path::new(binary_path)) {
            return Err(crate::error::Error::BinaryNotFound(binary_path.to_string()));
        }
    }

    // Serialize config to YAML. The `.yaml` suffix matters: ferrum-edge
    // selects its parser from the spec file extension.
    let yaml = serde_yaml::to_string(config)?;

    let mut spec_file = private_temp_file("gitforgeops-spec-", ".yaml")?;
    spec_file.write_all(yaml.as_bytes())?;
    spec_file.flush()?;

    // An empty settings file defeats ferrum-edge's `ferrum.conf`
    // auto-discovery: settings fall back to their defaults instead of picking
    // up whatever happens to sit in the working directory or /etc/ferrum.
    let settings_file = private_temp_file("gitforgeops-settings-", ".conf")?;

    let mut command = Command::new(binary_path);
    command.args(build_validate_args(settings_file.path(), spec_file.path()));
    for name in scrubbed_env_names(std::env::vars().map(|(name, _)| name)) {
        command.env_remove(name);
    }

    let output = command.output();

    // Both temp files are removed when the handles drop, on every path
    // including the error return below.
    drop(spec_file);
    drop(settings_file);

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
