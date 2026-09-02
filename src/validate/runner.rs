use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::config::GatewayConfig;
use crate::secrets::SecretScrubber;

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

/// `-m` value that makes ferrum-edge validate a flat gateway document.
pub const GATEWAY_VALIDATE_MODE: &str = "file";

/// `-m` value that makes ferrum-edge validate a standalone
/// `{version, mesh}` document.
///
/// Under `-m mesh`, ferrum-edge's `prepare_validate_file_source` inspects the
/// document handed to `-c`: a localized `{version?, mesh}` shape infers
/// `FERRUM_MESH_CONFIG_PROTOCOL=file` and validates it as a mesh slice
/// (parse + normalize + `validate_mesh_fields` + slice derivation), the same
/// pipeline a mesh node runs at startup. A gateway document handed to this
/// mode fails, and a mesh document handed to `-m file` fails — the two are
/// not interchangeable, which is why they are separate invocations rather
/// than one document with a `mesh:` key.
pub const MESH_VALIDATE_MODE: &str = "mesh";

/// Build the argument vector for `ferrum-edge validate` in an explicit mode —
/// [`GATEWAY_VALIDATE_MODE`] for a flat gateway document, [`MESH_VALIDATE_MODE`]
/// for a standalone mesh document.
///
/// The real CLI is
/// `ferrum-edge validate [-s|--settings <PATH>] [-c|--spec <PATH>] [-m|--mode <MODE>] [-v...]`.
/// There is **no `--format` flag**; do not add one.
///
/// Two of these arguments are load-bearing for correctness:
///
/// * `-m <mode>` — ferrum-edge only parses and validates the *spec* when the
///   resolved mode matches the document. Mode precedence is CLI `--mode` > env
///   `FERRUM_MODE` > `ferrum.conf` > file-mode inference, so without an
///   explicit `-m` an inherited `FERRUM_MODE` (or a stray `ferrum.conf`
///   declaring a mode) makes validation a silent fail-open no-op that still
///   exits 0. This is why the mode is always passed explicitly rather than
///   defaulted by a wrapper.
/// * `-s <path>` — when omitted, ferrum-edge auto-discovers `./ferrum.conf`,
///   `./config/ferrum.conf` or `/etc/ferrum/ferrum.conf` and validates those
///   settings too, so an unrelated file in the checkout can fail the run.
///   Pointing `-s` at an empty settings file pins settings to defaults.
pub fn build_validate_args_for_mode(
    mode: &str,
    settings_path: &Path,
    spec_path: &Path,
) -> Vec<OsString> {
    vec![
        OsString::from("validate"),
        OsString::from("-m"),
        OsString::from(mode),
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
///
/// The same resolution is why the child's output is passed through a
/// [`SecretScrubber`] built from `config`: `ferrum-edge validate` quotes the
/// document it was handed, so on a bundle-loaded run every credential in a
/// diagnostic is a live value. Only those exact byte sequences are replaced
/// with `[REDACTED]`; every other diagnostic — the proxy typo that actually
/// failed the run — is returned intact.
///
/// Credential leaves that are *still* placeholders (no bundle loaded, as on a
/// fork PR) are replaced with [`crate::validate::validation_standin`] values
/// in the temp spec only, so shape checks such as ferrum-edge's 32-character
/// `jwt`/`hmac_auth` floor grade the repo's structure instead of failing on
/// the 30-character placeholder literal.
pub fn run_validation(
    config: &GatewayConfig,
    binary_path: &str,
) -> crate::error::Result<ValidationResult> {
    let scrubber = SecretScrubber::from_gateway_config(config);
    // Stand-ins are fabricated here and go no further than `spec_file` below.
    let standins = crate::validate::standin::with_validation_standins(config);
    let yaml = serde_yaml::to_string(standins.as_ref().unwrap_or(config))?;
    run_validate_command(GATEWAY_VALIDATE_MODE, &yaml, binary_path, &scrubber)
}

/// Validate the standalone mesh document with
/// `ferrum-edge validate -m mesh -s <empty settings> -c <mesh doc>`.
///
/// The document is rendered by `apply::render_mesh_yaml`, so what is
/// validated is byte-for-byte what `apply` / `export` publish — including the
/// `version` stamp, which the mesh loader checks.
///
/// Mesh documents hold no credential material (the gh-env-secret broker only
/// walks consumer credentials), but the temp file is still 0600 with an
/// unpredictable name: mesh documents do carry SPIFFE identities, trust
/// bundles and workload addresses, which is not information to leave in a
/// world-readable shared temp directory either.
pub fn run_mesh_validation(
    mesh: &crate::config::MeshConfigSpec,
    binary_path: &str,
) -> crate::error::Result<ValidationResult> {
    let yaml = crate::apply::render_mesh_yaml(mesh)?;
    // A mesh document carries no brokered credential material — the
    // gh-env-secret broker walks consumer credentials and plugin config, and
    // neither exists in a mesh slice — so there is nothing to redact and
    // every diagnostic is printed verbatim.
    run_validate_command(
        MESH_VALIDATE_MODE,
        &yaml,
        binary_path,
        &SecretScrubber::default(),
    )
}

/// Emitted in place of the validator's own output when, and only when,
/// redaction provably failed. See [`crate::secrets::MIN_SCRUB_LENGTH`]: a
/// credential shorter than the substring-replacement floor cannot be removed
/// from a diagnostic without corrupting it, so the diagnostic goes instead.
const SUPPRESSED_NOTICE: &str = "Validator diagnostics were withheld: a credential value survived redaction, so the output could not be shown without leaking it. Credentials shorter than 8 bytes cannot be redacted from a diagnostic without mangling it — lengthen the credential, or move the literal value into the ${gh-env-secret:...} broker.\n";

/// Shared body of [`run_validation`] and [`run_mesh_validation`]: locate the
/// binary, write `yaml` to a private temp file, and run `validate` in `mode`
/// with a scrubbed environment and pinned settings.
///
/// `scrubber` holds the secret byte sequences to remove from the child's
/// stdout and stderr before either is returned. Everything else the validator
/// said — schema errors on proxies, upstreams, plugins, the lot — survives,
/// which is the whole point: a bundle-loaded apply run must still be able to
/// report a proxy typo.
fn run_validate_command(
    mode: &str,
    yaml: &str,
    binary_path: &str,
    scrubber: &SecretScrubber,
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

    // The `.yaml` suffix matters: ferrum-edge selects its parser from the
    // spec file extension.
    let mut spec_file = private_temp_file("gitforgeops-spec-", ".yaml")?;
    spec_file.write_all(yaml.as_bytes())?;
    spec_file.flush()?;

    // An empty settings file defeats ferrum-edge's `ferrum.conf`
    // auto-discovery: settings fall back to their defaults instead of picking
    // up whatever happens to sit in the working directory or /etc/ferrum.
    let settings_file = private_temp_file("gitforgeops-settings-", ".conf")?;

    let mut command = Command::new(binary_path);
    command.args(build_validate_args_for_mode(
        mode,
        settings_file.path(),
        spec_file.path(),
    ));
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
    let mut stdout = scrubber.scrub(&String::from_utf8_lossy(&output.stdout));
    let mut stderr = scrubber.scrub(&String::from_utf8_lossy(&output.stderr));

    // Last resort. Substring replacement removes every secret at or above
    // `MIN_SCRUB_LENGTH`, so reaching here means a credential too short to
    // replace safely was echoed back. Drop the stream rather than print it.
    if scrubber.leaks(&stdout) || scrubber.leaks(&stderr) {
        stdout = String::new();
        stderr = SUPPRESSED_NOTICE.to_string();
    }

    // ferrum-edge validate's public contract is 0 for accepted input and 1
    // for schema rejection. Any other code (including -1 for termination by
    // signal) means the validator itself failed; treating that as an ordinary
    // rejected document would hide a broken release gate.
    if !matches!(exit_code, 0 | 1) {
        return Err(crate::error::Error::ValidateProcess {
            code: exit_code,
            stderr: bounded_process_diagnostic(&stderr),
        });
    }

    Ok(ValidationResult {
        success: output.status.success(),
        stdout,
        stderr,
        exit_code,
    })
}

fn bounded_process_diagnostic(diagnostic: &str) -> String {
    const MAX_CHARS: usize = 4_000;
    let mut chars = diagnostic.chars();
    let bounded = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{bounded}\n[validator diagnostic truncated]")
    } else {
        bounded
    }
}
