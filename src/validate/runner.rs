use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::config::{collect_namespaces, GatewayConfig};
use crate::secrets::SecretScrubber;

/// Result of running `ferrum-edge validate`.
///
/// `ferrum-edge validate` has no machine-readable output mode — it prints
/// plain text and exits 0 (success) or 1 (failure). Everything structured
/// (text / JSON / GitHub annotations) is produced gitforgeops-side by
/// [`crate::validate::reporter`] from these fields. Child streams are secret
/// scrubbed; a recognized resource-label rejection also prepends an actionable
/// compatibility error to stderr, retaining the original Edge diagnostic.
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

/// The validation-only identity opt-out gitforgeops sets *itself* on a
/// validator child, and only under [`MESH_VALIDATE_MODE`].
///
/// ferrum-edge's `-m mesh` resolution runs the same identity gate a mesh node
/// runs at startup: with no file-based gateway SVID material
/// (`FERRUM_GATEWAY_SVID_CERT_PATH` / `_KEY_PATH` / `_TRUST_BUNDLE_PATH`) it
/// refuses with *"mesh mode has no workload identity"* — before it ever looks
/// at the document handed to `-c`. A CI runner grading a pull request has no
/// mesh node's identity and must not be asked to have one, so a repository
/// declaring any `MeshConfig` fragment would fail every `validate`, `plan`,
/// `review` and file-mode `apply` on the execution context rather than on its
/// own content.
///
/// `FERRUM_MESH_ALLOW_NO_CA=true` is ferrum-edge's own documented
/// validation-only opt-out for exactly that: it relaxes the workload-identity
/// requirement while leaving the mesh document's parse → normalize →
/// `validate_mesh_fields` → slice-derivation pipeline untouched, so a
/// malformed policy or schema is still rejected.
pub const MESH_ALLOW_NO_CA_ENV: &str = "FERRUM_MESH_ALLOW_NO_CA";

/// The explicit, trusted validation-only context for a validator child in
/// `mode`, applied **after** [`scrubbed_env_names`] has removed every
/// inherited `FERRUM_*` variable.
///
/// This is an allow-list of constants, not a pass-through: the parent's own
/// `FERRUM_MESH_ALLOW_NO_CA` is scrubbed like everything else and cannot
/// influence the child either way. Gateway validation gets no constant
/// identity overrides — `-m file` has no identity gate. Its `FERRUM_NAMESPACE`
/// is set separately from the assembled document, never the parent's filter.
///
/// Nothing here reaches `apply`'s runtime settings: it is set on the
/// `ferrum-edge validate` child process only, and the published mesh document
/// is byte-for-byte unaffected. If an older or newer ferrum-edge rejects the
/// variable, that refusal is the child's own stderr and is surfaced unchanged.
pub fn validation_context_env(mode: &str) -> Vec<(&'static str, &'static str)> {
    if mode == MESH_VALIDATE_MODE {
        vec![(MESH_ALLOW_NO_CA_ENV, "true")]
    } else {
        Vec::new()
    }
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
/// the validation result. Every namespace present in the assembled gateway
/// document gets an explicit child `FERRUM_NAMESPACE`, in lexical order.
/// Edge filters before checking cross-resource references and uniqueness, so
/// validating only its default `ferrum` slice would leave other slices unchecked.
/// An empty document still gets one pass under an explicit `ferrum` context.
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
/// Where the substitution cannot be trusted — a secret that an emitter would
/// re-encode (a multi-line PEM key, a value carrying quotes), a value that
/// survived it, or a surviving fragment of one — both streams are withheld
/// with a notice naming the reason. See [`crate::secrets::SecretScrubber`].
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
    run_gateway_validation(config, binary_path, &scrubber, None)
}

/// Validate a resolved snapshot using both literal-secret classification and
/// the corresponding resolver report as redaction and stand-in provenance.
/// Resolved and unreported slots are validated verbatim, even if their actual
/// values have placeholder syntax. Only reported unresolved slots get fakes.
pub fn run_validation_with_report(
    config: &GatewayConfig,
    binary_path: &str,
    report: &crate::secrets::ResolveReport,
) -> crate::error::Result<ValidationResult> {
    let scrubber = SecretScrubber::from_gateway_config_with_report(config, report);
    run_gateway_validation(config, binary_path, &scrubber, Some(report))
}

fn run_gateway_validation(
    config: &GatewayConfig,
    binary_path: &str,
    scrubber: &SecretScrubber,
    report: Option<&crate::secrets::ResolveReport>,
) -> crate::error::Result<ValidationResult> {
    // Stand-ins are fabricated here and go no further than `spec_file` below.
    let standins = crate::validate::standin::with_validation_standins_for_report(config, report);
    let yaml = serde_yaml::to_string(standins.as_ref().unwrap_or(config))?;
    let mut namespaces = collect_namespaces(config);
    if namespaces.is_empty() {
        // Empty documents still need schema/settings validation. This does
        // not acknowledge a typoed parent filter: NamespaceScope owns that gate.
        namespaces.push("ferrum".to_string());
    }
    let annotate_namespace = namespaces.len() > 1;
    let mut combined = ValidationResult {
        success: true,
        stdout: String::new(),
        stderr: String::new(),
        exit_code: 0,
    };
    for namespace in namespaces {
        // Keep the full document: Edge owns both pre-filter field validation
        // and post-filter graph validation. Never opt out of its empty filter gate.
        let result = run_validate_command(
            GATEWAY_VALIDATE_MODE,
            &yaml,
            binary_path,
            scrubber,
            Some(&namespace),
            annotate_namespace,
        )?;
        if !result.success {
            combined.success = false;
            combined.exit_code = result.exit_code;
        }
        combined.stdout.push_str(&result.stdout);
        combined.stderr.push_str(&result.stderr);
    }
    Ok(combined)
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
///
/// This is the one invocation that carries a [`validation_context_env`]
/// entry: `-m mesh` refuses on the absence of a workload identity before it
/// reads the document, and a CI runner is not a mesh node. See
/// [`MESH_ALLOW_NO_CA_ENV`].
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
        None,
        false,
    )
}

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
    namespace: Option<&str>,
    annotate_namespace: bool,
) -> crate::error::Result<ValidationResult> {
    // Check that the binary exists / is callable
    let which_result = Command::new("which").arg(binary_path).output();
    // Reuse the existing lookup for diagnostics; no version subprocess or
    // version-number assumption can establish resource-label capability.
    let binary_in_use = which_result
        .as_ref()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| std::str::from_utf8(&output.stdout).ok())
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .unwrap_or(binary_path);
    let binary_exists = match &which_result {
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
    // Order is load-bearing: every inherited `FERRUM_*` name is removed
    // first, then this mode's own validation-only context is set, so the
    // child sees only our constants and document-derived namespace.
    for (name, value) in validation_context_env(mode) {
        command.env(name, value);
    }
    if let Some(namespace) = namespace {
        command.env("FERRUM_NAMESPACE", namespace);
    }

    let output = command.output();

    // Both temp files are removed when the handles drop, on every path
    // including the error return below.
    drop(spec_file);
    drop(settings_file);

    let output = output?;

    let exit_code = output.status.code().unwrap_or(-1);
    // One decision point for scrub-or-withhold: a secret that cannot be
    // matched reliably in re-encoded output, a value that survived verbatim,
    // or a surviving fragment of one all withhold both streams and say which
    // it was. Everything else comes back scrubbed and readable.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Label every diagnostic line in a multi-namespace run so text, JSON and
    // GitHub annotations retain its context. Label before scrubbing: even a
    // namespace can coincide with a credential. Single-pass output is unchanged.
    let scrubbed = match namespace.filter(|_| annotate_namespace) {
        Some(namespace) => scrubber.scrub_streams(
            &namespace_output(namespace, &stdout),
            &namespace_output(namespace, &stderr),
        ),
        None => scrubber.scrub_streams(&stdout, &stderr),
    };
    let stdout = scrubbed.stdout;
    let mut stderr = scrubbed.stderr;

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

    if mode == GATEWAY_VALIDATE_MODE && exit_code == 1 {
        if let Some(diagnostic) =
            super::compatibility::resource_labels_diagnostic(&stdout, &stderr, binary_in_use)
        {
            stderr = diagnostic;
        }
    }

    Ok(ValidationResult {
        success: output.status.success(),
        stdout,
        stderr,
        exit_code,
    })
}

fn namespace_output(namespace: &str, output: &str) -> String {
    let mut labeled = String::new();
    for line in output.lines() {
        // Debug quoting keeps hostile newlines in a namespace on one line.
        labeled.push_str(&format!("[namespace {namespace:?}] {line}\n"));
    }
    labeled
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
