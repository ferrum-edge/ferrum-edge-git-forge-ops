//! Untrusted strings must not be able to write a line of their own into a CI
//! job log.
//!
//! Resource ids, namespaces, plugin names, YAML paths and gateway response
//! bodies all originate outside this repository — in the threat model that
//! matters, from a fork PR whose YAML a trusted, default-branch-built binary
//! reads inside a secret-bound job. A `\n` in one of them puts attacker text
//! at column 0 of the Actions log, where `::…::` is a workflow command: a
//! forged `::error::` annotation, or a `::stop-commands::` that silences the
//! real annotations a later step writes.
//!
//! Every assertion here is the same pair: the rendered diagnostic carries no
//! line break of its own, and no line of it begins a workflow command.

use std::process::{Command, Output};

use gitforgeops::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use gitforgeops::diagnostics::{sanitize, sanitize_block, sanitize_line, MAX_INLINE_CHARS};
use gitforgeops::diff::security::audit_security;
use gitforgeops::error::Error;

use tempfile::TempDir;

/// The payload an attacker would put in a resource id: a line break, then a
/// workflow command that suppresses every later one.
const HOSTILE: &str = "evil\n::stop-commands::7c6d\n::error::forged";

/// No rendered scalar or single-line diagnostic may contain a line break.
fn assert_single_line(rendered: &str, context: &str) {
    assert!(
        !rendered.contains('\n') && !rendered.contains('\r'),
        "{context}: rendered diagnostic contains a line break: {rendered:?}"
    );
}

/// No line of any rendered output may parse as a workflow command. The runner
/// trims a command's leading whitespace before parsing it, so this does too.
fn assert_no_workflow_command(rendered: &str, context: &str) {
    for (index, line) in rendered.lines().enumerate() {
        assert!(
            !line.trim_start().starts_with("::"),
            "{context}: line {index} parses as a workflow command: {line:?}"
        );
    }
}

/// A JSON-quoted form of [`HOSTILE`], which is also a valid YAML scalar.
fn quoted_hostile() -> String {
    serde_json::to_string(HOSTILE).expect("quote hostile payload")
}

#[test]
fn sanitize_folds_control_characters_and_bounds_length() {
    let rendered = sanitize("a\nb\tc\r\u{2028}d\u{0}e");
    assert_eq!(rendered, "a\u{fffd}b\u{fffd}c\u{fffd}\u{fffd}d\u{fffd}e");
    assert_single_line(&rendered, "control characters");

    let long = "x".repeat(MAX_INLINE_CHARS + 10);
    let bounded = sanitize(&long);
    assert!(bounded.ends_with("[truncated]"), "{bounded}");
    let expected = MAX_INLINE_CHARS + "[truncated]".len();
    assert_eq!(bounded.chars().count(), expected);

    // A value needing neither treatment is returned unchanged, so ordinary
    // diagnostics read exactly as they did before.
    assert_eq!(sanitize("ferrum/orders"), "ferrum/orders");
}

#[test]
fn sanitize_neutralizes_a_workflow_command_prefix() {
    for candidate in ["::error::forged", "  ::stop-commands::7c6d"] {
        let rendered = sanitize(candidate);
        assert_no_workflow_command(&rendered, candidate);
    }
}

#[test]
fn sanitize_block_keeps_line_structure_but_not_commands() {
    let hostile = "first\n::error::forged\n  ::endgroup::\nlast\ttab";
    let rendered = sanitize_block(hostile);
    assert_eq!(rendered.lines().count(), 4);
    assert!(rendered.starts_with("first\n"), "{rendered}");
    assert!(rendered.ends_with("last\u{fffd}tab"), "{rendered}");
    assert_no_workflow_command(&rendered, "block");

    // CRLF input reads normally rather than growing a replacement character.
    assert_eq!(sanitize_block("one\r\ntwo\r\n"), "one\ntwo\n");
}

/// A composed message keeps its length; only the hostile bytes change.
#[test]
fn sanitize_line_keeps_long_messages_whole() {
    let message = format!("proxy {HOSTILE} in namespace ferrum has no auth");
    let rendered = sanitize_line(&message);
    assert_single_line(&rendered, "finding message");
    assert!(rendered.starts_with("proxy evil"), "{rendered}");
    assert!(rendered.ends_with("has no auth"), "{rendered}");
}

#[test]
fn unknown_fields_error_cannot_emit_a_workflow_command() {
    let error = Error::UnknownFields {
        path: std::path::PathBuf::from("resources/ferrum/proxies/app.yaml"),
        fields: format!(".spec.{HOSTILE}"),
    };
    let rendered = error.to_string();
    assert_single_line(&rendered, "UnknownFields");
    assert_no_workflow_command(&rendered, "UnknownFields");
    assert!(rendered.contains('\u{fffd}'), "{rendered}");
}

/// Every `Error` variant that carries repository- or gateway-sourced text.
///
/// A variant added later with an unsanitized payload fails here rather than
/// in an Actions log.
#[test]
fn untrusted_error_variants_cannot_emit_a_workflow_command() {
    let bad = HOSTILE.to_string();
    let path = std::path::PathBuf::from(format!("resources/{HOSTILE}/app.yaml"));

    let check = |name: &str, error: Error| {
        let rendered = error.to_string();
        assert_no_workflow_command(&rendered, name);
        assert!(
            rendered.contains('\u{fffd}'),
            "{name}: payload rendered verbatim: {rendered:?}"
        );
    };

    let unknown_fields = Error::UnknownFields {
        path: path.clone(),
        fields: bad.clone(),
    };
    let unknown_kind = Error::UnknownKind {
        kind: bad.clone(),
        path: path.clone(),
    };
    let orphan_overlay = Error::OrphanOverlay {
        id: bad.clone(),
        path: path.clone(),
    };
    let api_error = Error::ApiError {
        status: 400,
        message: bad.clone(),
    };
    let validate_process = Error::ValidateProcess {
        code: 1,
        stderr: bad.clone(),
    };

    check("UnknownFields", unknown_fields);
    check("UnknownKind", unknown_kind);
    check("OrphanOverlay", orphan_overlay);
    check("ApiError", api_error);
    check("ValidateProcess", validate_process);
    check("ConfigSymlink", Error::ConfigSymlink(path.clone()));
    check("NoResourcesDir", Error::NoResourcesDir(path));
    check("Config", Error::Config(bad.clone()));
    check("BackupNamespace", Error::BackupNamespace(bad.clone()));
    check("StaleGatewayView", Error::StaleGatewayView(bad.clone()));
    check("AmbiguousMutation", Error::AmbiguousMutation(bad.clone()));
    check("GatewayReadOnly", Error::GatewayReadOnly(bad.clone()));
    check("HttpClient", Error::HttpClient(bad.clone()));
    check(
        "CredentialSlotRemap",
        Error::CredentialSlotRemap(bad.clone()),
    );

    // Scalar-only variants additionally stay on one line: a hostile id must
    // not be able to split the diagnostic that names it.
    let scalar = Error::UnknownKind {
        kind: bad,
        path: std::path::PathBuf::from("resources/ferrum/app.yaml"),
    };
    assert_single_line(&scalar.to_string(), "UnknownKind");
}

fn hostile_proxy() -> Proxy {
    let id = quoted_hostile();
    let yaml = format!("id: {id}\nnamespace: {id}\nbackend_host: h.internal\nbackend_port: 8080\n");
    serde_yaml::from_str(&yaml).expect("hostile proxy")
}

fn hostile_upstream() -> Upstream {
    let id = quoted_hostile();
    let yaml = format!(
        "id: {id}\nnamespace: ferrum\ntargets: []\nbackend_tls_verify_server_cert: false\n"
    );
    serde_yaml::from_str(&yaml).expect("hostile upstream")
}

fn hostile_plugin() -> PluginConfig {
    let id = quoted_hostile();
    let yaml = format!("id: {id}\nnamespace: ferrum\nplugin_name: {id}\nscope: global\n");
    serde_yaml::from_str(&yaml).expect("hostile plugin")
}

fn hostile_consumer() -> Consumer {
    let id = quoted_hostile();
    let yaml = format!("id: {id}\nnamespace: ferrum\nusername: app\n");
    let mut consumer: Consumer = serde_yaml::from_str(&yaml).expect("consumer");
    consumer.credentials.insert(
        "keyauth".to_string(),
        serde_json::json!([{"key": "literal-committed-secret"}]),
    );
    consumer
}

/// The security audit interpolates ids, namespaces, plugin names and config
/// paths into every message it builds, and `plan` / `apply` print those
/// messages straight to stdout and stderr.
#[test]
fn security_findings_cannot_emit_a_workflow_command() {
    let config = GatewayConfig {
        proxies: vec![hostile_proxy()],
        upstreams: vec![hostile_upstream()],
        plugin_configs: vec![hostile_plugin()],
        consumers: vec![hostile_consumer()],
        ..GatewayConfig::default()
    };

    let findings = audit_security(&config);
    assert!(!findings.is_empty(), "fixture produced no findings");
    for finding in &findings {
        let check_field = |field: &str, value: &str| {
            assert_single_line(value, field);
            assert_no_workflow_command(value, field);
        };
        check_field("kind", &finding.kind);
        check_field("id", &finding.id);
        check_field("namespace", &finding.namespace);
        check_field("message", &finding.message);
        // The whole line a printer emits, not only its parts.
        let rendered = format!(
            "  [{}] {} {} ({}): {}",
            finding.severity, finding.kind, finding.id, finding.namespace, finding.message
        );
        assert_single_line(&rendered, "finding line");
        assert_no_workflow_command(&rendered, "finding line");
    }
    let sanitized = findings.iter().any(|f| f.id.contains('\u{fffd}'));
    assert!(sanitized, "hostile id was recorded verbatim");
}

// ---------------------------------------------------------------------------
// CLI level: the bytes the binary actually writes to the job log.
// ---------------------------------------------------------------------------

/// A repository tree holding one hostile resource file.
struct Repo {
    dir: TempDir,
    scratch: TempDir,
}

impl Repo {
    fn new(relative: &str, contents: String) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(relative);
        let parent = path.parent().expect("resource parent");
        std::fs::create_dir_all(parent).expect("resource tree");
        std::fs::write(&path, contents).expect("write repo file");
        Self {
            dir,
            scratch: TempDir::new().expect("scratch tempdir"),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        // Keep the hosted coverage collector's destination alive across
        // `env_clear()`, resolving it before the child changes directory.
        let profile_path = std::env::var_os("LLVM_PROFILE_FILE")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| self.scratch.path().join("default_%m_%p.profraw"));
        let profile_path = std::env::current_dir()
            .expect("test working directory")
            .join(profile_path);
        command.env("LLVM_PROFILE_FILE", profile_path);
        command.env("FERRUM_GATEWAY_MODE", "file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let validator = self.scratch.path().join("validator-stub");
            let script = "#!/bin/sh\nexit 0\n";
            std::fs::write(&validator, script).expect("stub");
            let mode = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&validator, mode).expect("chmod");
            command.env("FERRUM_EDGE_BINARY_PATH", validator);
        }
        command.output().expect("run gitforgeops")
    }
}

/// One proxy whose id is hostile. It attaches no auth plugin, so the security
/// audit reports it and `plan` prints the id.
fn hostile_proxy_yaml() -> String {
    let id = quoted_hostile();
    format!("kind: Proxy\nspec:\n  id: {id}\n  backend_host: h.internal\n  backend_port: 8080\n")
}

/// One proxy carrying an unknown `spec` field whose *key* is hostile. The
/// strict loader refuses it, and the refusal is what reaches the log.
fn hostile_field_yaml() -> String {
    let key = quoted_hostile();
    format!(
        "kind: Proxy\nspec:\n  id: app\n  backend_host: h.internal\n  backend_port: 8080\n  {key}: true\n"
    )
}

#[cfg(unix)]
#[test]
fn plan_output_carries_no_workflow_command() {
    let repo = Repo::new("resources/ferrum/proxies/app.yaml", hostile_proxy_yaml());
    let output = repo.run(&["plan"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert_no_workflow_command(&stdout, "plan stdout");
    assert_no_workflow_command(&stderr, "plan stderr");
    assert!(
        stdout.contains("Security Findings"),
        "plan printed no findings:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains('\u{fffd}'),
        "hostile id reached stdout verbatim:\n{stdout}"
    );
}

/// The top-level error printer is the last thing a failing run writes.
#[test]
fn error_output_carries_no_workflow_command() {
    let repo = Repo::new("resources/ferrum/proxies/app.yaml", hostile_field_yaml());
    let output = repo.run(&["validate"]);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(!output.status.success(), "should fail: {stderr}");
    assert_no_workflow_command(&stderr, "validate stderr");
    assert!(
        stderr.contains("unknown configuration field"),
        "unexpected failure:\n{stderr}"
    );
    assert!(
        stderr.contains('\u{fffd}'),
        "hostile YAML key reached stderr verbatim:\n{stderr}"
    );
}
