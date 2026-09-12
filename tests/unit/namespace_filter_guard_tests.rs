//! Empty-namespace-filter guard (issue #208).
//!
//! A mistyped `FERRUM_NAMESPACE` used to make `validate`, `plan`, and
//! `diff --exit-on-drift` succeed against an empty desired set. These tests
//! cover the shared diagnosis and each command path.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use gitforgeops::config::{GatewayConfig, NamespaceScope, EMPTY_NAMESPACE_EXIT_CODE};
use gitforgeops::policy::Severity;
use tempfile::TempDir;

const PROXY: &str = r#"kind: Proxy
spec:
  id: "app"
  listen_path: "/app"
  backend_scheme: https
  backend_host: "app.internal"
  backend_port: 8080
"#;

const JWT_SECRET: &str = "namespace-filter-test-secret-at-least-32";

fn backup(proxies: serde_json::Value) -> String {
    serde_json::json!({
        "proxies": proxies,
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    })
    .to_string()
}

fn live_proxy(id: &str, namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_scheme": "https",
        "backend_host": "app.internal",
        "backend_port": 8080,
    })
}

fn namespaces_page(names: &[&str]) -> String {
    serde_json::json!({
        "data": names,
        "pagination": {"offset": 0, "limit": 1000, "total": names.len()}
    })
    .to_string()
}

#[test]
fn zero_survivors_is_an_error_severity_finding() {
    let scope = NamespaceScope::with_desired(
        Some("does-not-exist"),
        vec!["ferrum".to_string()],
        3,
        &GatewayConfig::default(),
        0,
    );
    assert!(scope.empty_desired_mismatch());
    let finding = scope.desired_finding(false).expect("mismatch");
    assert_eq!(finding.severity, Severity::Error);
    assert!(finding.is_error());
    assert!(finding.message.contains("does-not-exist"), "{}", finding.message);
    assert!(finding.message.contains("ferrum"), "{}", finding.message);
    assert!(finding.message.contains("on_disk=3"), "{}", finding.message);
    assert!(finding.message.contains("desired=0"), "{}", finding.message);
    assert_eq!(EMPTY_NAMESPACE_EXIT_CODE, 1);
}

#[test]
fn allow_empty_namespace_downgrades_to_warning() {
    let scope = NamespaceScope::with_desired(
        Some("does-not-exist"),
        vec!["ferrum".to_string()],
        1,
        &GatewayConfig::default(),
        0,
    );
    let finding = scope.desired_finding(true).expect("mismatch");
    assert_eq!(finding.severity, Severity::Warning);
    assert!(!finding.is_error());
}

#[test]
fn matching_namespace_is_not_a_mismatch() {
    let scope = NamespaceScope::with_desired(
        Some("ferrum"),
        vec!["ferrum".to_string()],
        1,
        &GatewayConfig::default(),
        1,
    );
    assert!(!scope.empty_desired_mismatch());
    assert!(scope.desired_finding(false).is_none());
    assert_eq!(scope.desired_count, 1);
}

#[test]
fn empty_tree_is_not_a_mismatch() {
    let scope = NamespaceScope::with_desired(
        Some("does-not-exist"),
        Vec::new(),
        0,
        &GatewayConfig::default(),
        0,
    );
    assert!(!scope.empty_desired_mismatch());
    assert!(scope.desired_finding(false).is_none());
}

#[test]
fn unfiltered_run_is_not_a_mismatch() {
    let scope = NamespaceScope::with_desired(
        None,
        vec!["ferrum".to_string()],
        2,
        &GatewayConfig::default(),
        0,
    );
    assert!(!scope.empty_desired_mismatch());
}

#[test]
fn live_filter_matched_nothing_is_a_warning() {
    let mut scope = NamespaceScope::with_desired(
        Some("typo"),
        vec!["ferrum".to_string()],
        1,
        &GatewayConfig::default(),
        0,
    );
    scope.set_live_count(0);
    scope.set_live_namespaces(vec!["ferrum".to_string()]);
    assert!(scope.live_filter_matched_nothing());
    let warning = scope.live_warning().expect("live warning");
    assert!(warning.contains("typo"), "{warning}");
    assert!(warning.contains("ferrum"), "{warning}");
}

#[test]
fn live_empty_matching_namespace_is_not_a_miss() {
    let mut scope = NamespaceScope::with_desired(
        Some("ferrum"),
        vec!["ferrum".to_string()],
        1,
        &GatewayConfig::default(),
        0,
    );
    scope.set_live_count(0);
    scope.set_live_namespaces(vec!["ferrum".to_string()]);
    assert!(!scope.live_filter_matched_nothing());
    assert!(scope.live_warning().is_none());
}

#[test]
fn from_loaded_counts_resources() {
    let scope = NamespaceScope::from_loaded(None, &[], &GatewayConfig::default(), 0);
    assert_eq!(scope.on_disk_count, 0);
    assert!(scope.on_disk_namespaces.is_empty());
    assert!(!scope.empty_desired_mismatch());
}
    let mut scope = NamespaceScope::with_desired(
        Some("typo"),
        vec!["ferrum".to_string()],
        2,
        &GatewayConfig::default(),
        0,
    );
    scope.set_live_count(0);
    let fields = scope.json_fields();
    assert_eq!(fields["namespace"], "typo");
    assert_eq!(fields["desired_count"], 0);
    assert_eq!(fields["live_count"], 0);
    assert_eq!(fields["on_disk_count"], 2);
    assert_eq!(fields["on_disk_namespaces"], serde_json::json!(["ferrum"]));
}

#[test]
fn merge_scope_json_does_not_rename_existing_fields() {
    let original = r#"{
  "success": true,
  "exit_code": 0,
  "stdout": "ok",
  "stderr": ""
}"#;
    let scope = NamespaceScope::with_desired(
        Some("typo"),
        vec!["ferrum".to_string()],
        1,
        &GatewayConfig::default(),
        0,
    );
    let finding = scope.desired_finding(false);
    let merged = gitforgeops::config::merge_scope_json(original, &scope, finding.as_ref());
    let value: serde_json::Value = serde_json::from_str(&merged).unwrap();
    assert_eq!(value["success"], true);
    assert_eq!(value["exit_code"], 0);
    assert_eq!(value["stdout"], "ok");
    assert_eq!(value["stderr"], "");
    assert_eq!(value["namespace"], "typo");
    assert_eq!(value["desired_count"], 0);
    assert_eq!(value["empty_namespace_filter"], "error");
}

struct Repo {
    dir: TempDir,
    validator: PathBuf,
}

impl Repo {
    fn with_files(files: &[(&str, &str)]) -> Self {
        let dir = TempDir::new().expect("tempdir");
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("resource tree");
            }
            std::fs::write(&path, contents).expect("write repo file");
        }
        if !dir.path().join("resources").exists() {
            std::fs::create_dir_all(dir.path().join("resources")).expect("resources");
        }
        let validator = dir.path().join("ferrum-edge-stub");
        std::fs::write(&validator, "#!/bin/sh\nexit 0\n").expect("stub");
        set_executable(&validator);
        Self { dir, validator }
    }

    fn with_proxy() -> Self {
        Self::with_files(&[("resources/ferrum/proxies/app.yaml", PROXY)])
    }

    fn empty_tree() -> Self {
        Self::with_files(&[])
    }

    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        command
            .env("FERRUM_GATEWAY_MODE", "file")
            .env(
                "FERRUM_FILE_OUTPUT_PATH",
                self.dir.path().join("published/resources.yaml"),
            )
            .env("FERRUM_EDGE_BINARY_PATH", &self.validator);
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command.output().expect("run gitforgeops")
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_mismatch_text(output: &Output) {
    let combined = format!("{}{}", stdout(output), stderr(output));
    assert!(
        combined.contains("does-not-exist"),
        "active namespace missing: {combined}"
    );
    assert!(
        combined.contains("ferrum"),
        "on-disk namespace missing: {combined}"
    );
    assert!(
        combined.contains("desired=0") || combined.contains("\"desired_count\": 0"),
        "desired count missing: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn validate_zero_survivors_exits_error() {
    let repo = Repo::with_proxy();
    let output = repo.run(
        &["validate"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(!output.status.success(), "{}", stdout(&output));
    assert_eq!(output.status.code(), Some(EMPTY_NAMESPACE_EXIT_CODE));
    assert_mismatch_text(&output);
}

#[cfg(unix)]
#[test]
fn validate_opt_out_is_a_warning() {
    let repo = Repo::with_proxy();
    let output = repo.run(
        &["validate", "--allow-empty-namespace"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(combined.contains("Warning"), "{combined}");
    assert!(combined.contains("does-not-exist"), "{combined}");
}

#[cfg(unix)]
#[test]
fn validate_matching_namespace_is_unchanged() {
    let repo = Repo::with_proxy();
    let output = repo.run(&["validate"], &[("FERRUM_NAMESPACE", "ferrum")]);
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(stdout(&output).contains("Validation passed"), "{}", stdout(&output));
    assert!(!stderr(&output).contains("selected 0 desired resources"));
}

#[cfg(unix)]
#[test]
fn validate_empty_tree_is_not_a_mismatch() {
    let repo = Repo::empty_tree();
    let output = repo.run(
        &["validate"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(!stderr(&output).contains("selected 0 desired resources"));
}

#[cfg(unix)]
#[test]
fn validate_json_includes_namespace_counts() {
    let repo = Repo::with_proxy();
    let output = repo.run(
        &["validate", "--format", "json"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(value["success"], false);
    assert_eq!(value["namespace"], "does-not-exist");
    assert_eq!(value["desired_count"], 0);
    assert_eq!(value["on_disk_count"], 1);
    assert_eq!(value["on_disk_namespaces"], serde_json::json!(["ferrum"]));
    assert_eq!(value["empty_namespace_filter"], "error");
    assert!(value.get("exit_code").is_some());
    assert!(value.get("stdout").is_some());
}

#[cfg(unix)]
#[test]
fn plan_zero_survivors_exits_error() {
    let repo = Repo::with_proxy();
    let output = repo.run(&["plan"], &[("FERRUM_NAMESPACE", "does-not-exist")]);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert_eq!(output.status.code(), Some(EMPTY_NAMESPACE_EXIT_CODE));
    assert_mismatch_text(&output);
    assert!(
        stdout(&output).contains("empty-namespace-filter")
            || stderr(&output).contains("selected 0 desired resources"),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
}

#[cfg(unix)]
#[test]
fn plan_opt_out_is_a_warning() {
    let repo = Repo::with_proxy();
    let output = repo.run(
        &["plan", "--allow-empty-namespace"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(combined.contains("warning") || combined.contains("Warning"), "{combined}");
}

#[cfg(unix)]
#[test]
fn plan_matching_namespace_is_unchanged() {
    let repo = Repo::with_proxy();
    let output = repo.run(&["plan"], &[("FERRUM_NAMESPACE", "ferrum")]);
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(!stderr(&output).contains("selected 0 desired resources"));
}

#[cfg(unix)]
#[test]
fn plan_empty_tree_is_not_a_mismatch() {
    let repo = Repo::empty_tree();
    let output = repo.run(&["plan"], &[("FERRUM_NAMESPACE", "does-not-exist")]);
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(!stderr(&output).contains("selected 0 desired resources"));
}

#[cfg(unix)]
#[test]
fn plan_json_includes_namespace_counts() {
    let repo = Repo::with_proxy();
    let output = repo.run(
        &["plan", "--format", "json"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(!output.status.success());
    let body = stdout(&output);
    let json_at = body.rfind("\n{").map(|idx| idx + 1).unwrap_or(0);
    let value: serde_json::Value =
        serde_json::from_str(body[json_at..].trim()).expect("trailing json");
    assert_eq!(value["namespace"], "does-not-exist");
    assert_eq!(value["desired_count"], 0);
    assert_eq!(value["on_disk_count"], 1);
    assert_eq!(value["empty_namespace_filter"], "error");
}

struct LiveRepo {
    dir: TempDir,
    url: String,
    validator: PathBuf,
}

impl LiveRepo {
    fn new(
        files: &[(&str, &str)],
        backups: Vec<(String, String)>,
        listed_namespaces: Vec<String>,
    ) -> Self {
        let dir = TempDir::new().expect("tempdir");
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("resource tree");
            }
            std::fs::write(&path, contents).expect("write repo file");
        }
        if !dir.path().join("resources").exists() {
            std::fs::create_dir_all(dir.path().join("resources")).expect("resources");
        }
        let validator = dir.path().join("ferrum-edge-stub");
        std::fs::write(&validator, "#!/bin/sh\nexit 0\n").expect("stub");
        set_executable(&validator);
        let url = spawn_live_stub(backups, listed_namespaces, Arc::new(Mutex::new(Vec::new())));
        Self { dir, url, validator }
    }

    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        command
            .env("FERRUM_GATEWAY_MODE", "api")
            .env("FERRUM_GATEWAY_URL", &self.url)
            .env("FERRUM_ALLOW_INSECURE_HTTP", "true")
            .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
            .env("FERRUM_GATEWAY_MAX_RETRIES", "0")
            .env("FERRUM_EDGE_BINARY_PATH", &self.validator);
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command.output().expect("run gitforgeops")
    }
}

fn spawn_live_stub(
    namespaces: Vec<(String, String)>,
    listed: Vec<String>,
    requests: Arc<Mutex<Vec<String>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let namespaces = namespaces.clone();
            let listed = listed.clone();
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || loop {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let mut buf = [0_u8; 8192];
                let mut n = 0;
                while !buf[..n].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let now = std::time::Instant::now();
                    let remaining = deadline.saturating_duration_since(now);
                    if n == buf.len()
                        || remaining.is_zero()
                        || stream.set_read_timeout(Some(remaining)).is_err()
                    {
                        return;
                    }
                    match stream.read(&mut buf[n..]) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => n += read,
                    }
                }
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                requests.lock().unwrap().push(request.clone());
                let body = if request.contains("GET /namespaces") {
                    namespaces_page(
                        &listed.iter().map(String::as_str).collect::<Vec<_>>(),
                    )
                } else {
                    namespaces
                        .iter()
                        .find(|(namespace, _)| {
                            request.contains(&format!("x-ferrum-namespace: {namespace}"))
                                || request.contains(&format!("X-Ferrum-Namespace: {namespace}"))
                        })
                        .map(|(_, body)| body.clone())
                        .unwrap_or_else(|| backup(serde_json::json!([])))
                };
                if write!(
                    stream,
                    "HTTP/1.1 200 STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    format!("http://{addr}")
}

#[cfg(unix)]
#[test]
fn diff_zero_survivors_exits_error() {
    let repo = LiveRepo::new(
        &[("resources/ferrum/proxies/app.yaml", PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([live_proxy("app", "ferrum")])),
        )],
        vec!["ferrum".to_string()],
    );
    let output = repo.run(
        &["diff", "--exit-on-drift"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(!output.status.success(), "{}", stdout(&output));
    assert_eq!(output.status.code(), Some(EMPTY_NAMESPACE_EXIT_CODE));
    assert_mismatch_text(&output);
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        combined.contains("matched 0 live") || combined.contains("live_filter_matched_nothing"),
        "live miss must be named: {combined}"
    );
}

#[cfg(unix)]
#[test]
fn diff_opt_out_is_a_warning() {
    let repo = LiveRepo::new(
        &[("resources/ferrum/proxies/app.yaml", PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([live_proxy("app", "ferrum")])),
        )],
        vec!["ferrum".to_string()],
    );
    let output = repo.run(
        &["diff", "--allow-empty-namespace"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(combined.contains("Warning"), "{combined}");
}

#[cfg(unix)]
#[test]
fn diff_matching_namespace_is_unchanged() {
    let repo = LiveRepo::new(
        &[("resources/ferrum/proxies/app.yaml", PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([live_proxy("app", "ferrum")])),
        )],
        vec!["ferrum".to_string()],
    );
    let output = repo.run(&["diff"], &[("FERRUM_NAMESPACE", "ferrum")]);
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(!stderr(&output).contains("selected 0 desired resources"));
    assert!(!stdout(&output).contains("empty-namespace-filter"));
}

#[cfg(unix)]
#[test]
fn diff_empty_tree_is_not_a_mismatch() {
    let repo = LiveRepo::new(&[], Vec::new(), Vec::new());
    let output = repo.run(
        &["diff", "--exit-on-drift"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    assert!(!stderr(&output).contains("selected 0 desired resources"));
}

#[cfg(unix)]
#[test]
fn diff_json_includes_namespace_and_live_counts() {
    let repo = LiveRepo::new(
        &[("resources/ferrum/proxies/app.yaml", PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([live_proxy("app", "ferrum")])),
        )],
        vec!["ferrum".to_string()],
    );
    let output = repo.run(
        &["diff", "--format", "json"],
        &[("FERRUM_NAMESPACE", "does-not-exist")],
    );
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(value["namespace"], "does-not-exist");
    assert_eq!(value["desired_count"], 0);
    assert_eq!(value["on_disk_count"], 1);
    assert_eq!(value["live_count"], 0);
    assert_eq!(value["empty_namespace_filter"], "error");
    assert_eq!(value["live_filter_matched_nothing"], true);
    assert_eq!(value["live_namespaces"], serde_json::json!(["ferrum"]));
}

#[cfg(unix)]
#[test]
fn plan_live_filter_miss_is_named_when_desired_matches() {
    let repo = LiveRepo::new(
        &[("resources/ferrum/proxies/app.yaml", PROXY)],
        vec![(
            "other".to_string(),
            backup(serde_json::json!([live_proxy("other", "other")])),
        )],
        vec!["other".to_string()],
    );
    let output = repo.run(&["plan"], &[("FERRUM_NAMESPACE", "ferrum")]);
    assert!(
        output.status.success(),
        "{} {}",
        stdout(&output),
        stderr(&output)
    );
    let combined = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        combined.contains("matched 0 live") || combined.contains("filter matched nothing"),
        "{combined}"
    );
    assert!(!combined.contains("empty-namespace-filter (1)"));
}
