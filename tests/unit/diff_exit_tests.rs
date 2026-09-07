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
use std::sync::{Arc, Mutex};

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
fn spawn_backup_stub(
    namespaces: Vec<(String, String)>,
    requests: Arc<Mutex<Vec<String>>>,
    cached: bool,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let namespaces = namespaces.clone();
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || loop {
                let mut buf = [0_u8; 8192];
                let n = match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                requests.lock().unwrap().push(request.clone());
                let body = namespaces
                    .iter()
                    .find(|(namespace, _)| {
                        request.contains(&format!("x-ferrum-namespace: {namespace}"))
                            || request.contains(&format!("X-Ferrum-Namespace: {namespace}"))
                    })
                    .map(|(_, body)| body.clone())
                    .unwrap_or_else(|| backup(serde_json::json!([])));
                let provenance = if cached {
                    "x-data-source: cached\r\n"
                } else {
                    ""
                };
                if write!(
                    stream,
                    "HTTP/1.1 200 STUB\r\n{provenance}content-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
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
    requests: Arc<Mutex<Vec<String>>>,
}

impl Repo {
    fn new(files: &[(&str, &str)], namespaces: Vec<(String, String)>) -> Self {
        Self::with_cache(files, namespaces, false)
    }

    fn with_cache(files: &[(&str, &str)], namespaces: Vec<(String, String)>, cached: bool) -> Self {
        let dir = TempDir::new().expect("tempdir");
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("resource tree");
            }
            std::fs::write(&path, contents).expect("write repo file");
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        Self {
            dir,
            url: spawn_backup_stub(namespaces, Arc::clone(&requests), cached),
            requests,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_env(args, &[])
    }

    fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        // Keep coverage profiles outside the repository whose bytes we assert
        // are unchanged. Preserve the hosted collector's destination despite
        // env_clear(), resolving relative paths before changing the child cwd.
        let profile_dir = TempDir::new().expect("profile tempdir");
        let profile_path = std::env::var_os("LLVM_PROFILE_FILE")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| profile_dir.path().join("default_%m_%p.profraw"));
        let profile_path = std::env::current_dir()
            .expect("test working directory")
            .join(profile_path);
        command.env("LLVM_PROFILE_FILE", profile_path);
        command
            .env("FERRUM_GATEWAY_MODE", "api")
            .env("FERRUM_GATEWAY_URL", &self.url)
            // The stub speaks cleartext on loopback; the CLI refuses http://
            // gateways unless this says so explicitly.
            .env("FERRUM_ALLOW_INSECURE_HTTP", "true")
            .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
            .env("FERRUM_GATEWAY_MAX_RETRIES", "0");
        #[cfg(unix)]
        let validator_dir = TempDir::new().unwrap();
        #[cfg(unix)]
        if matches!(args.first().copied(), Some("plan" | "review" | "apply")) {
            use std::os::unix::fs::PermissionsExt;
            let validator = validator_dir.path().join("validator-stub");
            std::fs::write(&validator, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&validator, std::fs::Permissions::from_mode(0o700)).unwrap();
            command.env("FERRUM_EDGE_BINARY_PATH", validator);
        }
        command.envs(env.iter().copied());
        command.output().expect("run gitforgeops")
    }

    fn snapshot(&self) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        walkdir::WalkDir::new(self.dir.path())
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                (
                    entry
                        .path()
                        .strip_prefix(self.dir.path())
                        .unwrap()
                        .to_owned(),
                    std::fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Issue #179: exercise the actual resolver + command gates, not just the
/// masking primitive. CI runs these children against synthetic loopback data.
#[cfg(unix)]
#[test]
fn unresolved_leaf_cli_matrix_preserves_real_drift_and_read_only_behavior() {
    let consumer = serde_json::json!({
        "kind": "Consumer",
        "spec": {
            "id": "app", "username": "app",
            "credentials": {
                "keyauth": [{"key": "${gh-env-secret:alloc=require}"}],
                "basicauth": [{
                    "username": "alice",
                    "password_hash": "${gh-env-secret:alloc=require}"
                }]
            }
        }
    })
    .to_string();
    let plugin = serde_json::json!({
        "kind": "PluginConfig",
        "spec": {
            "id": "otel", "plugin_name": "otel_tracing", "scope": "global",
            "config": {
                "authorization": "${gh-env-secret:alloc=require}",
                "protocol": "grpc"
            }
        }
    })
    .to_string();
    for transport in ["absent", "inline", "file"] {
        for population in ["empty", "unrelated", "partial", "full"] {
            if transport == "absent" && population != "empty" {
                continue;
            }
            for change in [
                "none",
                "resolved",
                "literal",
                "literal_secret",
                "extra",
                "removed",
                "plugin",
            ] {
                if change == "resolved" && !matches!(population, "partial" | "full") {
                    continue;
                }
                let mut live = serde_json::json!({
                    "proxies": [], "upstreams": [],
                    "consumers": [{
                        "id": "app", "namespace": "ferrum", "username": "app",
                        "credentials": {
                            "keyauth": [{"key": "synthetic-key-value-0001"}],
                            "basicauth": [{
                                "username": "alice",
                                "password_hash": "synthetic-hash-value-0001"
                            }]
                        }
                    }],
                    "plugin_configs": [{
                        "id": "otel", "namespace": "ferrum", "plugin_name": "otel_tracing",
                        "scope": "global",
                        "config": {"authorization": "synthetic-bearer-0001", "protocol": "grpc"}
                    }]
                });
                match change {
                    "resolved" => {
                        live["consumers"][0]["credentials"]["keyauth"][0]["key"] =
                            serde_json::json!("synthetic-different-key");
                    }
                    "literal" => {
                        live["consumers"][0]["credentials"]["basicauth"][0]["username"] =
                            serde_json::json!("bob");
                    }
                    "extra" => {
                        live["consumers"][0]["credentials"]["keyauth"]
                            .as_array_mut()
                            .unwrap()
                            .push(serde_json::json!({"key": "synthetic-extra-key"}));
                    }
                    "removed" => {
                        live["consumers"][0]["credentials"]["keyauth"] = serde_json::json!([]);
                    }
                    "plugin" => {
                        live["plugin_configs"][0]["config"]["protocol"] =
                            serde_json::json!("http/protobuf");
                    }
                    _ => {}
                }
                let mut slots = serde_json::Map::new();
                if population != "empty" {
                    slots.insert(
                        "other/other/keyauth/key".into(),
                        "synthetic-unrelated".into(),
                    );
                }
                if matches!(population, "partial" | "full") {
                    slots.insert(
                        "ferrum/app/keyauth/key".into(),
                        "synthetic-key-value-0001".into(),
                    );
                }
                if population == "full" {
                    slots.insert(
                        "ferrum/app/basicauth/password_hash".into(),
                        "synthetic-hash-value-0001".into(),
                    );
                    slots.insert(
                        "ferrum/otel/@plugin-config/config/authorization".into(),
                        "synthetic-bearer-0001".into(),
                    );
                }
                let bundle = serde_json::json!({"FERRUM_CREDS_BUNDLE": slots}).to_string();
                // Match the hosted extractor's exact empty outer-object case.
                let bundle = if population == "empty" { "{}" } else { &bundle };
                let mut declared: serde_json::Value = serde_json::from_str(&consumer).unwrap();
                if change == "literal_secret" {
                    declared["spec"]["credentials"]["basicauth"][0]["password_hash"] =
                        serde_json::json!("synthetic-literal-hash");
                }
                let declared = declared.to_string();
                let repo = Repo::new(
                    &[
                        ("resources/ferrum/consumers/app.yaml", &declared),
                        ("resources/ferrum/plugins/otel.yaml", &plugin),
                    ],
                    vec![("ferrum".into(), live.to_string())],
                );
                let bundle_file = repo.dir.path().join("bundle.json");
                std::fs::write(&bundle_file, bundle).unwrap();
                let env = match transport {
                    "inline" => vec![("FERRUM_CREDS_JSON", bundle)],
                    "file" => vec![("FERRUM_CREDS_JSON_FILE", bundle_file.to_str().unwrap())],
                    _ => vec![],
                };
                let before = repo.snapshot();
                for args in [&["diff", "--exit-on-drift"][..], &["plan"], &["review"]] {
                    let output = repo.run_with_env(args, &env);
                    let out = stdout(&output);
                    let diagnostics = format!("{out}\n{}", stderr(&output));
                    let context =
                        format!("{transport}/{population}/{change}/{args:?}: {diagnostics}");
                    let expected_code = match args[0] {
                        "diff" => i32::from(change != "none") * 2,
                        "plan" => i32::from(population != "full" || change == "literal_secret"),
                        _ => 0,
                    };
                    assert_eq!(output.status.code(), Some(expected_code), "{context}");
                    let in_sync = if args[0] == "diff" {
                        out.contains("No differences found")
                    } else {
                        out.contains("None (in sync)")
                    };
                    assert_eq!(in_sync, change == "none", "{context}");
                    assert_eq!(
                        diagnostics.contains("remain unresolved"),
                        population != "full",
                        "{context}"
                    );
                    assert!(!diagnostics.contains("no credential bundle is available"));
                    for secret in [
                        "synthetic-key-value-0001",
                        "synthetic-hash-value-0001",
                        "synthetic-bearer-0001",
                        "synthetic-different-key",
                        "synthetic-extra-key",
                        "synthetic-unrelated",
                        "synthetic-literal-hash",
                    ] {
                        assert!(!diagnostics.contains(secret), "{context}");
                    }
                    assert_eq!(repo.snapshot(), before, "{context}");
                    assert!(!repo.dir.path().join(".state").exists(), "{context}");
                }
                {
                    let requests = repo.requests.lock().unwrap();
                    assert!(!requests.is_empty());
                    assert!(requests
                        .iter()
                        .all(|request| request.starts_with("GET /backup ")));
                }
                if population != "full" && change == "none" {
                    repo.requests.lock().unwrap().clear();
                    let output = repo.run_with_env(&["apply", "--auto-approve"], &env);
                    assert_eq!(output.status.code(), Some(1));
                    assert!(stderr(&output).contains("required credential slots are missing"));
                    assert!(repo.requests.lock().unwrap().is_empty());
                    // Apply may create a lock file, but must never publish a ledger.
                    let after = repo.snapshot();
                    for (path, bytes) in &before {
                        assert_eq!(after.get(path), Some(bytes));
                    }
                    assert!(after.keys().all(|path| {
                        before.contains_key(path)
                            || (path.starts_with(".state")
                                && path.extension().is_some_and(|ext| ext == "lock"))
                    }));
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn empty_bundle_does_not_make_cached_comparisons_authoritative() {
    let consumer = r#"kind: Consumer
spec:
  id: app
  username: app
  credentials:
    keyauth: [{key: "${gh-env-secret:alloc=require}"}]
"#;
    let live = serde_json::json!({
        "consumers": [{
            "id": "app", "namespace": "ferrum", "username": "app",
            "credentials": {"keyauth": [{"key": "synthetic-cached-key"}]}
        }]
    });
    let repo = Repo::with_cache(
        &[("resources/ferrum/consumers/app.yaml", consumer)],
        vec![("ferrum".into(), live.to_string())],
        true,
    );
    let before = repo.snapshot();
    let env = [("FERRUM_CREDS_JSON", "{}")];
    let approximate = repo.run_with_env(&["diff"], &env);
    assert_eq!(approximate.status.code(), Some(0));
    assert!(stdout(&approximate).contains("MODIFY Consumer"));
    assert!(stderr(&approximate).contains("approximate"));
    assert!(!stderr(&approximate).contains("remain unresolved"));
    assert!(!stdout(&approximate).contains("synthetic-cached-key"));
    assert!(!stderr(&approximate).contains("synthetic-cached-key"));
    assert_eq!(repo.snapshot(), before);
    let strict = repo.run_with_env(&["diff", "--exit-on-drift"], &env);
    assert_eq!(strict.status.code(), Some(1));
    assert!(stderr(&strict).contains("requires an authoritative backup"));
    assert_eq!(repo.snapshot(), before);
    // --require-live needs a PR number to reach the live comparison. The child
    // has no GITHUB_TOKEN or GITHUB_REPOSITORY after env_clear(), so delivery
    // fails locally before constructing an HTTP client; no comment is posted.
    for args in [&["plan"][..], &["review", "--require-live", "--pr", "1"]] {
        let output = repo.run_with_env(args, &env);
        assert_eq!(output.status.code(), Some(1));
        assert!(!stdout(&output).contains("None (in sync)"));
        if args[0] == "plan" {
            assert!(stdout(&output).contains("Live comparison skipped: cached backup data"));
            assert!(stdout(&output).contains("SKIPPED (no live config available)"));
        } else {
            assert!(stderr(&output).contains("Cached backup data was served"));
            assert!(stderr(&output)
                .contains("trusted PR review requires a complete live gateway comparison"));
            assert!(stdout(&output).contains("Changes: Skipped"));
        }
        assert!(!stdout(&output).contains("synthetic-cached-key"));
        assert!(!stderr(&output).contains("synthetic-cached-key"));
        assert_eq!(repo.snapshot(), before);
    }
    assert_eq!(repo.snapshot(), before);
    assert!(repo
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET /backup ")));
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

#[cfg(unix)]
#[test]
fn plan_fails_only_for_conflicting_live_spec_ownership() {
    for (live_id, expected_code) in [("app", 1), ("spec-app", 0)] {
        let repo = Repo::new(
            &[("resources/ferrum/proxies/app.yaml", FERRUM_PROXY)],
            vec![(
                "ferrum".to_string(),
                backup(serde_json::json!([live_proxy(
                    live_id,
                    "ferrum",
                    8080,
                    Some("spec-1")
                )])),
            )],
        );
        let output = repo.run(&["plan"]);
        let out = stdout(&output);
        assert_eq!(
            output.status.code(),
            Some(expected_code),
            "{out} {}",
            stderr(&output)
        );
        assert!(out.contains("Spec-owned Resources"), "{out}");
        assert_eq!(
            out.contains("=== Apply Blockers ==="),
            expected_code == 1,
            "{out}"
        );
        if expected_code == 1 {
            assert!(
                out.contains("API-spec ownership conflicts block apply in namespace(s): ferrum"),
                "{out}"
            );
        }
    }
}
