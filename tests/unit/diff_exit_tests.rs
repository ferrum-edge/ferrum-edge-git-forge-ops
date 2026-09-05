//! `diff --exit-on-drift` end to end, against a stub `/backup`.
//!
//! The verdict itself is a pure function covered in `verdict_tests.rs`; what
//! only the binary can show is that the process actually exits with the drift
//! code, that the finding is printed alongside it, and that an
//! `api_spec_id`-tagged row the repository also declares reaches the verdict
//! at all — the diff engine deliberately suppresses its Modify, so nothing in
//! the ordinary change list stands in for it.
//!
//! Hermetic: a loopback TCP stub answers `GET /backup` per namespace, and the
//! child inherits only the variables named here.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

use tempfile::TempDir;

/// JWT signing secret. The stub ignores the token, but `AdminClient` refuses
/// to build below 32 characters.
const JWT_SECRET: &str = "diff-exit-test-secret-at-least-32-chars";

/// Repository proxy in namespace `ferrum`.
const FERRUM_PROXY: &str = r#"kind: Proxy
spec:
  id: "app"
  backend_host: "app.internal"
  backend_port: 8080
"#;

/// Repository proxy in namespace `team-b`, on a port the live gateway
/// disagrees with — ordinary managed drift in a second namespace.
const TEAM_B_PROXY: &str = r#"kind: Proxy
spec:
  id: "other"
  backend_host: "other.internal"
  backend_port: 9090
"#;

/// Every drift-alert category muted. A spec-ownership conflict must survive
/// this: `apply` refuses the namespace over it, so it is not drift noise an
/// operator may mute.
const MUTED_DRIFT_CONFIG: &str = r#"version: 1
environments:
  staging:
    ownership:
      drift_alert_on:
        managed_modified: false
        managed_deleted: false
        unmanaged_added: false
"#;

/// One `/backup` document.
fn backup(proxies: serde_json::Value) -> String {
    serde_json::json!({
        "proxies": proxies,
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    })
    .to_string()
}

/// One live `/backup` row. `backend_scheme` is spelled out because the
/// assembler resolves a schemeless repository proxy to `https`, and a live row
/// that left it null would compare as an ordinary Modify — drift from the
/// fixture rather than from the property under test.
fn live_proxy(
    id: &str,
    namespace: &str,
    port: u16,
    api_spec_id: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_scheme": "https",
        "backend_host": if namespace == "ferrum" { "app.internal" } else { "other.internal" },
        "backend_port": port,
        "api_spec_id": api_spec_id,
    })
}

/// Serve `GET /backup` per `X-Ferrum-Namespace`, returning the base URL.
///
/// Routing on the namespace header rather than the path is what the admin API
/// itself does — `/backup` is one endpoint and the namespace is a header — so
/// a multi-namespace run is exercised the way production drives it.
fn spawn_backup_stub(namespaces: Vec<(String, String)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let namespaces = namespaces.clone();
            std::thread::spawn(move || loop {
                let mut buf = [0_u8; 8192];
                let n = match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = namespaces
                    .iter()
                    .find(|(namespace, _)| {
                        request.contains(&format!("x-ferrum-namespace: {namespace}"))
                            || request.contains(&format!("X-Ferrum-Namespace: {namespace}"))
                    })
                    .map(|(_, body)| body.clone())
                    .unwrap_or_else(|| backup(serde_json::json!([])));
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

struct Repo {
    dir: TempDir,
    url: String,
}

impl Repo {
    fn new(files: &[(&str, &str)], namespaces: Vec<(String, String)>) -> Self {
        let dir = TempDir::new().expect("tempdir");
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("resource tree");
            }
            std::fs::write(&path, contents).expect("write repo file");
        }
        Self {
            dir,
            url: spawn_backup_stub(namespaces),
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
        command
            .env("FERRUM_GATEWAY_MODE", "api")
            .env("FERRUM_GATEWAY_URL", &self.url)
            // The stub speaks cleartext on loopback; the CLI refuses http://
            // gateways unless this says so explicitly.
            .env("FERRUM_ALLOW_INSECURE_HTTP", "true")
            .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
            .env("FERRUM_GATEWAY_MAX_RETRIES", "0");
        command.output().expect("run gitforgeops")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// The documented drift exit code.
fn assert_drift_exit(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected the drift exit code; stdout={} stderr={}",
        stdout(output),
        stderr(output)
    );
}

#[test]
fn a_spec_ownership_conflict_with_identical_fields_exits_with_the_drift_code() {
    // The issue-131 reproduction: the repo declares Proxy `app`, the live row
    // carries `api_spec_id`, and its ordinary fields match exactly. The diff
    // engine suppresses the Modify, so without the conflict in the verdict the
    // nightly monitor saw a clean run on a namespace apply refuses.
    let repo = Repo::new(
        &[("resources/ferrum/proxies/app.yaml", FERRUM_PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([live_proxy(
                "app",
                "ferrum",
                8080,
                Some("spec-1")
            )])),
        )],
    );

    let output = repo.run(&["diff", "--exit-on-drift"]);

    assert_drift_exit(&output);
    let out = stdout(&output);
    assert!(
        out.contains("Proxy app (ferrum) spec=spec-1")
            && out.contains("CONFLICT: also declared in this repo"),
        "the conflict must still be printed: {out}"
    );
    assert!(
        out.contains("API-spec ownership conflicts"),
        "the verdict must say why it exited: {out}"
    );

    // Without the flag, `diff` stays a report: same finding, exit 0.
    let reported = repo.run(&["diff"]);
    assert!(
        reported.status.success(),
        "stdout={} stderr={}",
        stdout(&reported),
        stderr(&reported)
    );
    assert!(
        stdout(&reported).contains("CONFLICT"),
        "{}",
        stdout(&reported)
    );
}

#[test]
fn a_spec_ownership_conflict_with_changed_fields_exits_with_the_drift_code() {
    // Same conflict, live fields deliberately different. The Modify is still
    // suppressed — the repo must not fight the spec importer — so the conflict
    // is the only thing that can carry the verdict.
    let repo = Repo::new(
        &[("resources/ferrum/proxies/app.yaml", FERRUM_PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([live_proxy(
                "app",
                "ferrum",
                18080,
                Some("spec-1")
            )])),
        )],
    );

    let output = repo.run(&["diff", "--exit-on-drift"]);

    assert_drift_exit(&output);
    let out = stdout(&output);
    assert!(out.contains("CONFLICT"), "{out}");
    assert!(
        !out.contains("MODIFY Proxy app"),
        "the Modify must stay suppressed; the conflict is the finding: {out}"
    );
}

#[test]
fn a_spec_ownership_conflict_survives_every_drift_alert_being_muted() {
    // `drift_alert_on` mutes categories an operator has decided are noise.
    // Two owners writing one row is not one of them.
    // `team-b` carries an ordinary managed modification, which the muted
    // config *does* suppress — that is what proves the config was loaded and
    // that the conflict is not riding along on someone else's category.
    let repo = Repo::new(
        &[
            ("resources/ferrum/proxies/app.yaml", FERRUM_PROXY),
            ("resources/team-b/proxies/other.yaml", TEAM_B_PROXY),
            (".gitforgeops/config.yaml", MUTED_DRIFT_CONFIG),
        ],
        vec![
            (
                "ferrum".to_string(),
                backup(serde_json::json!([live_proxy(
                    "app",
                    "ferrum",
                    8080,
                    Some("spec-1")
                )])),
            ),
            (
                "team-b".to_string(),
                backup(serde_json::json!([live_proxy(
                    "other", "team-b", 19090, None
                )])),
            ),
        ],
    );

    let output = repo.run(&["diff", "--exit-on-drift"]);

    assert_drift_exit(&output);
    let out = stdout(&output);
    assert!(out.contains("CONFLICT"), "{out}");
    assert!(
        out.contains("MODIFY Proxy other (team-b)"),
        "the muted category is still reported, just not alerted on: {out}"
    );
    assert!(
        out.contains("Drift detected (API-spec ownership conflicts)"),
        "the conflict must be the only category in the verdict: {out}"
    );
}

#[test]
fn an_undeclared_spec_owned_row_is_informational_and_exits_zero() {
    // The control. A spec-owned resource the repo does not declare is a stable
    // steady state: reported, never drift. Calling it drift meant any gateway
    // that ingests API specs could never report in sync.
    let repo = Repo::new(
        &[("resources/ferrum/proxies/app.yaml", FERRUM_PROXY)],
        vec![(
            "ferrum".to_string(),
            backup(serde_json::json!([
                live_proxy("app", "ferrum", 8080, None),
                live_proxy("spec-app", "ferrum", 8080, Some("spec-1")),
            ])),
        )],
    );

    let output = repo.run(&["diff", "--exit-on-drift"]);

    assert!(
        output.status.success(),
        "an informational spec-owned row is not drift; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(
        out.contains("Proxy spec-app (ferrum) spec=spec-1"),
        "it must still be reported: {out}"
    );
    assert!(
        !out.contains("CONFLICT"),
        "the repo does not declare it: {out}"
    );
}

#[test]
fn other_namespaces_are_still_compared_alongside_a_conflict() {
    // A conflict in one namespace must not short-circuit the comparison of
    // the rest: the drift report is the only view the nightly monitor has.
    let repo = Repo::new(
        &[
            ("resources/ferrum/proxies/app.yaml", FERRUM_PROXY),
            ("resources/team-b/proxies/other.yaml", TEAM_B_PROXY),
        ],
        vec![
            (
                "ferrum".to_string(),
                backup(serde_json::json!([live_proxy(
                    "app",
                    "ferrum",
                    8080,
                    Some("spec-1")
                )])),
            ),
            (
                "team-b".to_string(),
                backup(serde_json::json!([live_proxy(
                    "other", "team-b", 19090, None
                )])),
            ),
        ],
    );

    let output = repo.run(&["diff", "--exit-on-drift"]);

    assert_drift_exit(&output);
    let out = stdout(&output);
    assert!(
        out.contains("MODIFY Proxy other (team-b)"),
        "the second namespace must still be compared: {out}"
    );
    assert!(
        out.contains("Proxy app (ferrum) spec=spec-1") && out.contains("CONFLICT"),
        "{out}"
    );
    assert!(
        out.contains("managed resources added or modified")
            && out.contains("API-spec ownership conflicts"),
        "the verdict must name both categories: {out}"
    );
}
