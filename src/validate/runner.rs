use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
///
/// Names are OS strings and the prefix is matched on their raw encoded bytes:
/// the process environment may hold entries that are not valid UTF-8, and
/// neither an unrelated such entry nor a non-UTF-8 `FERRUM_*` name may abort
/// validation (`std::env::vars` panics on them) or escape the scrub.
pub fn scrubbed_env_names<I, S>(names: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    names
        .into_iter()
        .filter(|name| {
            name.as_ref()
                .as_encoded_bytes()
                .starts_with(FERRUM_ENV_PREFIX.as_bytes())
        })
        .map(|name| name.as_ref().to_os_string())
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

/// How long one validator invocation may run, and how much it may print on
/// one stream. `Command::output` bounds neither: a wedged or hostile
/// validator binary could park CI forever or exhaust memory.
const VALIDATOR_TIMEOUT: Duration = Duration::from_secs(300);
const VALIDATOR_STREAM_CAP: usize = 16 * 1024 * 1024;

fn output_bounded(command: &mut Command) -> std::io::Result<std::process::Output> {
    output_bounded_with(command, VALIDATOR_TIMEOUT, VALIDATOR_STREAM_CAP)
}

/// Kill the validator and, on unix, its whole process group: killing only
/// the direct child leaves descendants holding the output pipes (and
/// running) after a refusal.
fn kill_validator_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The child was spawned as a process-group leader, so its pid is
        // the group id. `kill` here is the POSIX shell's builtin, run by
        // absolute path with an empty environment, so neither `PATH` nor a
        // missing `kill` executable can turn group cleanup into a no-op. If
        // even `/bin/sh` cannot run, the direct kill below still does.
        let _ = Command::new("/bin/sh")
            .args(["-c", "kill -s KILL -- \"-$1\"", "sh"])
            .arg(child.id().to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn output_bounded_with(
    command: &mut Command,
    timeout: Duration,
    stream_cap: usize,
) -> std::io::Result<std::process::Output> {
    // Readers report over a channel instead of being joined: a descendant
    // that inherits a pipe can delay EOF arbitrarily past the child's exit,
    // and the deadline must cover drain completion, not just exit.
    fn drain<R: Read + Send + 'static>(
        pipe: R,
        cap: usize,
        is_stdout: bool,
        done: std::sync::mpsc::Sender<(bool, Vec<u8>)>,
    ) {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            // Read one byte past the cap so overflow is detectable.
            let _ = pipe.take(cap as u64 + 1).read_to_end(&mut bytes);
            let _ = done.send((is_stdout, bytes));
        });
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    drain(
        child.stdout.take().expect("stdout is piped"),
        stream_cap,
        true,
        sender.clone(),
    );
    drain(
        child.stderr.take().expect("stderr is piped"),
        stream_cap,
        false,
        sender,
    );

    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut stdout: Option<Vec<u8>> = None;
    let mut stderr: Option<Vec<u8>> = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        if let (Some(status), Some(stdout), Some(stderr)) = (status, &stdout, &stderr) {
            return Ok(std::process::Output {
                status,
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            });
        }
        if Instant::now() >= deadline {
            kill_validator_tree(&mut child);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("validator exceeded the {}s time limit", timeout.as_secs()),
            ));
        }
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok((is_stdout, bytes)) => {
                if bytes.len() > stream_cap {
                    kill_validator_tree(&mut child);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("validator output exceeded the {stream_cap}-byte limit"),
                    ));
                }
                if is_stdout {
                    stdout = Some(bytes);
                } else {
                    stderr = Some(bytes);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Both readers ended without reporting (thread panic): fill
                // whatever is missing so the child-status path can finish
                // instead of waiting for reports that will never arrive.
                stdout.get_or_insert_with(Vec::new);
                stderr.get_or_insert_with(Vec::new);
            }
        }
    }
}

/// Run `command`, retrying a spawn that failed with `ETXTBSY`.
///
/// Linux refuses to execute a file while any process holds it open for
/// writing. A validator binary that was written moments ago — an installer
/// replacing it, or a stub in the test suite — can still have its write
/// descriptor inherited by a process another thread forked and has not yet
/// `exec`ed, which clears within milliseconds. Every other spawn error is
/// returned immediately.
fn output_retrying_busy_executable(command: &mut Command) -> std::io::Result<std::process::Output> {
    const ATTEMPTS: u32 = 6;
    let mut attempt = 0;
    loop {
        match output_bounded(command) {
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && attempt + 1 < ATTEMPTS =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10 << attempt));
                attempt += 1;
            }
            result => return result,
        }
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
#[cfg(unix)]
fn private_temp_file(
    prefix: &str,
    suffix: &str,
) -> std::io::Result<tempfile::NamedTempFile<std::fs::File>> {
    use std::os::unix::fs::PermissionsExt;
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix).suffix(suffix);
    builder.permissions(std::fs::Permissions::from_mode(0o600));
    builder.tempfile()
}

/// The assembled spec can contain resolved live credentials. Off Unix
/// there is no owner-only mode to establish before those bytes land, so
/// fail closed instead of writing them under an inherited ACL.
#[cfg(not(unix))]
fn private_temp_file(
    _prefix: &str,
    _suffix: &str,
) -> std::io::Result<tempfile::NamedTempFile<std::fs::File>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "validating a credential-bearing spec requires owner-only temp files this platform cannot enforce",
    ))
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
    // Bounded like every other subprocess here: a PATH-resolved `which`
    // wrapper must not stall or flood validation either. A limit failure is
    // an `Err`, which falls through to the (also bounded) direct probe.
    let which_result = output_bounded(Command::new("which").arg("--").arg(binary_path));
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
            // Bounded like the validation run itself: a wedged or flooding
            // binary must not stall or exhaust memory in this probe either.
            output_bounded(Command::new(binary_path).arg("--help"))
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
    for name in scrubbed_env_names(std::env::vars_os().map(|(name, _)| name)) {
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

    let output = output_retrying_busy_executable(&mut command);

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

#[cfg(test)]
mod bounded_output_tests {
    use super::*;

    #[test]
    fn validator_timeout_kills_a_wedged_child() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let error = output_bounded_with(&mut command, Duration::from_millis(100), 1024)
            .expect_err("a wedged validator must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn validator_stream_cap_refuses_unbounded_output() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'x%.0s' $(seq 1 5000)"]);
        let error = output_bounded_with(&mut command, Duration::from_secs(30), 1024)
            .expect_err("output past the cap must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn validator_deadline_covers_descendants_holding_the_pipes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sleep 30 & echo $! > \"$1\"; echo started; exit 0",
                "sh",
            ])
            .arg(&pid_file);
        let started = Instant::now();
        let error = output_bounded_with(&mut command, Duration::from_millis(200), 1024)
            .expect_err("a descendant holding stdout open must not outlive the deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "deadline must bound drain completion, took {:?}",
            started.elapsed()
        );

        // The descendant itself must be gone, not just no longer waited on.
        // It is reparented once its shell dies; a zombie awaiting that reap
        // counts as dead.
        let descendant = std::fs::read_to_string(&pid_file).unwrap();
        let descendant = descendant.trim();
        let alive = || {
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "kill -0 \"$1\" 2>/dev/null || exit 1; \
                     case \"$(ps -o stat= -p \"$1\" 2>/dev/null)\" in Z*) exit 1;; esac",
                    "sh",
                    descendant,
                ])
                .status()
                .unwrap()
                .success()
        };
        let reaped_by = Instant::now() + Duration::from_secs(5);
        while alive() && Instant::now() < reaped_by {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive(), "descendant {descendant} survived the deadline");
    }

    #[test]
    fn validator_output_within_bounds_is_returned() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf hello"]);
        let output = output_bounded_with(&mut command, Duration::from_secs(30), 1024)
            .expect("bounded output is returned");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello");
    }
}
