//! The documented exit-code contract (CLAUDE.md, "Exit codes"), one table.
//!
//! Workflows, the drift monitor and operators branch on the process status
//! alone, so a refactor of `main.rs` dispatch must not silently move a code.
//! Every row spawns the real binary and pins one `(command, input) → code`
//! pair; the per-command modules (`diff_exit_tests.rs`, `verify_exit_tests.rs`,
//! `apply_gate_tests.rs`, `namespace_filter_guard_tests.rs`, ...) pin the
//! behaviour behind each code in depth. This module's job is breadth: every
//! documented code is reachable, and each command returns the documented one.
//!
//! Hermetic: the child starts from `env_clear()` and receives only `PATH`,
//! `HOME`, `TMPDIR`, the coverage profile path and the variables a row names,
//! so no inherited `FERRUM_*`, `GITFORGEOPS_*` or `GITHUB_*` value reaches it.
//! Gateways and data planes are loopback stubs from the sibling modules; the
//! validator is a shell stub, which is why the matrix is Unix-only.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use gitforgeops::config::EMPTY_NAMESPACE_EXIT_CODE;
use gitforgeops::doctor::DOCTOR_FAILED_EXIT_CODE;
use gitforgeops::verdict::{DRIFT_EXIT_CODE, SECRETS_UNVERIFIED_EXIT_CODE};
use gitforgeops::verify::{VERIFY_FAILED_EXIT_CODE, VERIFY_SKIPPED_EXIT_CODE};
use tempfile::TempDir;

use super::diff_exit_tests::{
    backup, config_export, live_proxy, spawn_backup_stub, EXPORT_KEY_ID, FERRUM_PROXY, JWT_SECRET,
    KEYAUTH_CONSUMER, VIEWER_ONLY,
};
use super::verify_exit_tests::{closed_port, data_plane, STAGING_ONLY};

/// A Consumer with a literal (non-placeholder) secret: the offline `Security`
/// apply blocker, decidable without a gateway.
const LITERAL_CONSUMER: &str = r#"kind: Consumer
spec:
  id: "literal"
  username: "literal"
  credentials:
    keyauth: [{key: "literal-secret-value-123456"}]
"#;

/// The only closed repository-config version is 1.
const BAD_REPO_CONFIG: &str = "version: 99\n";

/// The repository the child runs in.
#[derive(Clone, Copy)]
enum Tree {
    /// `resources/ferrum/proxies/app.yaml`, matching the live row the
    /// `/backup` stub serves on port 8080.
    Proxy,
    /// No `resources/` directory at all.
    NoResources,
    /// [`Tree::Proxy`] plus an unsupported `.gitforgeops/config.yaml`.
    BadRepoConfig,
    /// [`Tree::Proxy`] plus a Consumer with a literal secret.
    LiteralCredential,
    /// A Consumer with a brokered key, for the viewer `/config/export` read.
    BrokeredConsumer,
    /// [`Tree::Proxy`] plus a populated validator digest allowlist, so every
    /// local doctor check passes or is skipped.
    DoctorReady,
    /// [`Tree::Proxy`] plus `.gitforgeops/smoke.yaml` declaring checks for
    /// `staging` only.
    StagingSmoke,
}

impl Tree {
    fn files(self) -> Vec<(&'static str, &'static str)> {
        let proxy = ("resources/ferrum/proxies/app.yaml", FERRUM_PROXY);
        match self {
            Tree::Proxy => vec![proxy],
            Tree::NoResources => vec![],
            Tree::BadRepoConfig => vec![proxy, (".gitforgeops/config.yaml", BAD_REPO_CONFIG)],
            Tree::LiteralCredential => vec![
                proxy,
                ("resources/ferrum/consumers/literal.yaml", LITERAL_CONSUMER),
            ],
            Tree::BrokeredConsumer => {
                vec![("resources/ferrum/consumers/app.yaml", KEYAUTH_CONSUMER)]
            }
            Tree::DoctorReady => vec![
                proxy,
                (
                    ".github/ferrum-edge-checksums.txt",
                    "0000000000000000000000000000000000000000000000000000000000000000  ferrum-edge\n",
                ),
            ],
            Tree::StagingSmoke => vec![proxy, (".gitforgeops/smoke.yaml", STAGING_ONLY)],
        }
    }
}

/// What answers the child's network requests.
#[derive(Clone, Copy)]
enum Live {
    /// Nothing: no gateway or data-plane variable is set.
    Offline,
    /// `GET /backup` for `ferrum` serves Proxy `app` on this port; `cached`
    /// marks the response `X-Data-Source: cached`.
    Backup { port: u16, cached: bool },
    /// `GET /config/export` for `ferrum` serves a fingerprinted Consumer, read
    /// with the viewer key only.
    ViewerExport,
    /// A data plane answering every request with this status.
    DataPlane(u16),
    /// A data-plane URL nothing listens on.
    ClosedDataPlane,
}

/// One row of the contract.
struct Case {
    /// Shown on failure.
    name: &'static str,
    tree: Tree,
    live: Live,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    expected: i32,
    /// A substring of stdout + stderr proving the code came from the intended
    /// path rather than an unrelated early failure.
    evidence: &'static str,
}

/// A usage or parse error is an ordinary error (1). It must never be clap's
/// default 2, which is `DRIFT_EXIT_CODE`: the drift monitor reads 2 from
/// `diff --exit-on-drift` as "drift found", so a mistyped flag would be
/// reported as drift instead of a failed check.
const USAGE_ERROR_EXIT_CODE: i32 = 1;

const VALIDATOR_ACCEPTS: &str = "#!/bin/sh\nexit 0\n";
const VALIDATOR_REJECTS: &str = "#!/bin/sh\necho 'stub rejection' >&2\nexit 1\n";

fn cases() -> Vec<Case> {
    use Live::*;
    use Tree::*;
    vec![
        // -- 0: success ---------------------------------------------------
        Case {
            name: "--version",
            tree: Proxy,
            live: Offline,
            args: &["--version"],
            env: &[],
            expected: 0,
            evidence: env!("CARGO_PKG_VERSION"),
        },
        Case {
            name: "--help",
            tree: Proxy,
            live: Offline,
            args: &["--help"],
            env: &[],
            expected: 0,
            evidence: "Usage:",
        },
        Case {
            name: "version",
            tree: Proxy,
            live: Offline,
            args: &["version"],
            env: &[],
            expected: 0,
            evidence: env!("CARGO_PKG_VERSION"),
        },
        Case {
            name: "version --format json",
            tree: Proxy,
            live: Offline,
            args: &["version", "--format", "json"],
            env: &[],
            expected: 0,
            evidence: "\"version\"",
        },
        Case {
            name: "validate on a valid tree",
            tree: Proxy,
            live: Offline,
            args: &["validate"],
            env: &[],
            expected: 0,
            evidence: "",
        },
        Case {
            name: "export",
            tree: Proxy,
            live: Offline,
            args: &["export"],
            env: &[],
            expected: 0,
            evidence: "app.internal",
        },
        Case {
            name: "envs",
            tree: Proxy,
            live: Offline,
            args: &["envs"],
            env: &[],
            expected: 0,
            evidence: "\"default\"",
        },
        Case {
            name: "plan without a gateway and without blockers",
            tree: Proxy,
            live: Offline,
            args: &["plan"],
            env: &[],
            expected: 0,
            evidence: "gateway URL not configured",
        },
        Case {
            name: "diff --exit-on-drift in sync",
            tree: Proxy,
            live: Backup {
                port: 8080,
                cached: false,
            },
            args: &["diff", "--exit-on-drift"],
            env: &[],
            expected: 0,
            evidence: "No differences found",
        },
        Case {
            name: "diff --exit-on-drift --accept-unverified-secrets",
            tree: BrokeredConsumer,
            live: ViewerExport,
            args: &["diff", "--exit-on-drift", "--accept-unverified-secrets"],
            env: &VIEWER_ONLY,
            expected: 0,
            evidence: "Fingerprinted secret fields were not verified",
        },
        Case {
            name: "diff without --exit-on-drift reports drift and exits 0",
            tree: Proxy,
            live: Backup {
                port: 9999,
                cached: false,
            },
            args: &["diff"],
            env: &[],
            expected: 0,
            evidence: "MODIFY",
        },
        Case {
            name: "doctor --scope local on a ready tree",
            tree: DoctorReady,
            live: Offline,
            args: &["doctor", "--scope", "local"],
            env: &[],
            expected: 0,
            evidence: "No blocking problems found.",
        },
        Case {
            name: "verify with a passing check",
            tree: StagingSmoke,
            live: DataPlane(200),
            args: &["verify"],
            env: &[("FERRUM_ENV", "staging")],
            expected: 0,
            evidence: "",
        },
        Case {
            name: "review stays 0 on an offline blocker",
            tree: LiteralCredential,
            live: Offline,
            args: &["review"],
            env: &[],
            expected: 0,
            evidence: "Live gateway comparison failed",
        },
        // -- 1: error -----------------------------------------------------
        Case {
            name: "export without a resources directory",
            tree: NoResources,
            live: Offline,
            args: &["export"],
            env: &[],
            expected: 1,
            evidence: "no resources directory found",
        },
        Case {
            name: "validate without a resources directory",
            tree: NoResources,
            live: Offline,
            args: &["validate"],
            env: &[],
            expected: 1,
            evidence: "no resources directory found",
        },
        Case {
            name: "envs with an unsupported repository config",
            tree: BadRepoConfig,
            live: Offline,
            args: &["envs"],
            env: &[],
            expected: 1,
            evidence: "unsupported repository config version 99",
        },
        Case {
            name: "export with an unsupported repository config",
            tree: BadRepoConfig,
            live: Offline,
            args: &["export"],
            env: &[],
            expected: 1,
            evidence: "unsupported repository config version 99",
        },
        Case {
            name: "invalid enum env var",
            tree: Proxy,
            live: Offline,
            args: &["export"],
            env: &[("FERRUM_GATEWAY_MODE", "bogus")],
            expected: 1,
            evidence: "invalid FERRUM_GATEWAY_MODE value",
        },
        Case {
            name: "invalid boolean env var",
            tree: Proxy,
            live: Offline,
            args: &["export"],
            env: &[("FERRUM_ALLOW_UNKNOWN_FIELDS", "maybe")],
            expected: 1,
            evidence: "invalid FERRUM_ALLOW_UNKNOWN_FIELDS value",
        },
        Case {
            name: "invalid review boolean env var",
            tree: Proxy,
            live: Offline,
            args: &["review"],
            env: &[("GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS", "bogus")],
            expected: 1,
            evidence: "invalid GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS value",
        },
        Case {
            name: "validate with a rejecting validator",
            tree: Proxy,
            live: Offline,
            args: &["validate"],
            env: &[("FERRUM_EDGE_BINARY_PATH", "<rejecting validator>")],
            expected: 1,
            evidence: "stub rejection",
        },
        Case {
            name: "validate without a validator binary",
            tree: Proxy,
            live: Offline,
            args: &["validate"],
            env: &[("FERRUM_EDGE_BINARY_PATH", "/nonexistent/ferrum-edge")],
            expected: 1,
            evidence: "ferrum-edge binary not found",
        },
        Case {
            name: "validate: empty-namespace refusal is 1, not 2",
            tree: Proxy,
            live: Offline,
            args: &["validate"],
            env: &[("FERRUM_NAMESPACE", "nothing")],
            expected: EMPTY_NAMESPACE_EXIT_CODE,
            evidence: "namespace filter 'nothing' selected 0 desired resources",
        },
        Case {
            name: "plan: empty-namespace refusal is 1, not 2",
            tree: Proxy,
            live: Offline,
            args: &["plan"],
            env: &[("FERRUM_NAMESPACE", "nothing")],
            expected: EMPTY_NAMESPACE_EXIT_CODE,
            evidence: "namespace filter 'nothing' selected 0 desired resources",
        },
        Case {
            name: "diff: empty-namespace refusal is 1, not 2",
            tree: Proxy,
            live: Offline,
            args: &["diff"],
            env: &[("FERRUM_NAMESPACE", "nothing")],
            expected: EMPTY_NAMESPACE_EXIT_CODE,
            evidence: "namespace filter 'nothing' selected 0 desired resources",
        },
        Case {
            name: "diff --exit-on-drift: empty-namespace refusal is 1, not 2",
            tree: Proxy,
            live: Offline,
            args: &["diff", "--exit-on-drift"],
            env: &[("FERRUM_NAMESPACE", "nothing")],
            expected: EMPTY_NAMESPACE_EXIT_CODE,
            evidence: "namespace filter 'nothing' selected 0 desired resources",
        },
        Case {
            name: "plan with an offline apply blocker",
            tree: LiteralCredential,
            live: Offline,
            args: &["plan"],
            env: &[],
            expected: 1,
            evidence: "=== Apply Blockers ===",
        },
        Case {
            name: "review --fail-on-blockers with an offline blocker",
            tree: LiteralCredential,
            live: Offline,
            args: &["review", "--fail-on-blockers"],
            env: &[],
            expected: 1,
            evidence: "apply is blocked by 1 class(es): security",
        },
        Case {
            name: "review with GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS=true and an offline blocker",
            tree: LiteralCredential,
            live: Offline,
            args: &["review"],
            env: &[("GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS", "true")],
            expected: 1,
            evidence: "apply is blocked by 1 class(es): security",
        },
        Case {
            name: "apply refuses a literal credential before any gateway call",
            tree: LiteralCredential,
            live: Offline,
            args: &["apply", "--auto-approve"],
            env: &[],
            expected: 1,
            evidence: "Refusing to apply: 1 error-severity security finding",
        },
        Case {
            name: "import from a missing file",
            tree: Proxy,
            live: Offline,
            args: &[
                "import",
                "--from-file",
                "does-not-exist.yaml",
                "--output-dir",
                "imported",
            ],
            env: &[],
            expected: 1,
            evidence: "failed to read file does-not-exist.yaml",
        },
        Case {
            name: "diff --exit-on-drift on a cached backup",
            tree: Proxy,
            live: Backup {
                port: 9999,
                cached: true,
            },
            args: &["diff", "--exit-on-drift"],
            env: &[],
            expected: 1,
            evidence: "requires an authoritative backup",
        },
        Case {
            name: "verify with declared checks and no data-plane URL",
            tree: StagingSmoke,
            live: Offline,
            args: &["verify"],
            env: &[("FERRUM_ENV", "staging")],
            expected: 1,
            evidence: "FERRUM_VERIFY_BASE_URL",
        },
        // -- 2: drift -----------------------------------------------------
        Case {
            name: "diff --exit-on-drift with managed drift",
            tree: Proxy,
            live: Backup {
                port: 9999,
                cached: false,
            },
            args: &["diff", "--exit-on-drift"],
            env: &[],
            expected: DRIFT_EXIT_CODE,
            evidence: "MODIFY",
        },
        // -- 1 (clap): usage errors are errors, never DRIFT_EXIT_CODE -----
        Case {
            name: "no subcommand",
            tree: Proxy,
            live: Offline,
            args: &[],
            env: &[],
            expected: USAGE_ERROR_EXIT_CODE,
            evidence: "Usage:",
        },
        Case {
            name: "unknown subcommand",
            tree: Proxy,
            live: Offline,
            args: &["bogus"],
            env: &[],
            expected: USAGE_ERROR_EXIT_CODE,
            evidence: "unrecognized subcommand 'bogus'",
        },
        Case {
            name: "unknown flag",
            tree: Proxy,
            live: Offline,
            args: &["validate", "--bogus"],
            env: &[],
            expected: USAGE_ERROR_EXIT_CODE,
            evidence: "unexpected argument '--bogus'",
        },
        Case {
            name: "unknown flag on diff --exit-on-drift",
            tree: Proxy,
            live: Offline,
            args: &["diff", "--exit-on-drift", "--bogus"],
            env: &[],
            expected: USAGE_ERROR_EXIT_CODE,
            evidence: "unexpected argument '--bogus'",
        },
        Case {
            name: "invalid enum flag value",
            tree: Proxy,
            live: Offline,
            args: &["doctor", "--scope", "bogus"],
            env: &[],
            expected: USAGE_ERROR_EXIT_CODE,
            evidence: "invalid value 'bogus'",
        },
        // -- 3: doctor blocker --------------------------------------------
        Case {
            name: "doctor --scope local without the validator digest allowlist",
            tree: Proxy,
            live: Offline,
            args: &["doctor", "--scope", "local"],
            env: &[],
            expected: DOCTOR_FAILED_EXIT_CODE,
            evidence: "Validator digest allowlist is populated",
        },
        Case {
            name: "doctor --scope local without a resources directory",
            tree: NoResources,
            live: Offline,
            args: &["doctor", "--scope", "local", "--format", "json"],
            env: &[],
            expected: DOCTOR_FAILED_EXIT_CODE,
            evidence: "\"resources\"",
        },
        // -- 4: verify failed ---------------------------------------------
        Case {
            name: "verify with a check answered by the wrong status",
            tree: StagingSmoke,
            live: DataPlane(503),
            args: &["verify"],
            env: &[("FERRUM_ENV", "staging")],
            expected: VERIFY_FAILED_EXIT_CODE,
            evidence: "",
        },
        Case {
            name: "verify with an unreachable data plane",
            tree: StagingSmoke,
            live: ClosedDataPlane,
            args: &["verify"],
            env: &[("FERRUM_ENV", "staging")],
            expected: VERIFY_FAILED_EXIT_CODE,
            evidence: "",
        },
        // -- 5: verify skipped --------------------------------------------
        Case {
            name: "verify with no declared check for the environment",
            tree: StagingSmoke,
            live: Offline,
            args: &["verify"],
            env: &[("FERRUM_ENV", "production")],
            expected: VERIFY_SKIPPED_EXIT_CODE,
            evidence: "skipped: no smoke checks declared for production",
        },
        Case {
            name: "verify with no smoke file",
            tree: Proxy,
            live: Offline,
            args: &["verify"],
            env: &[],
            expected: VERIFY_SKIPPED_EXIT_CODE,
            evidence: "not a pass",
        },
        // -- 6: secrets unverified ----------------------------------------
        Case {
            name: "diff --exit-on-drift in sync with unverified secrets",
            tree: BrokeredConsumer,
            live: ViewerExport,
            args: &["diff", "--exit-on-drift"],
            env: &VIEWER_ONLY,
            expected: SECRETS_UNVERIFIED_EXIT_CODE,
            evidence: "(in sync, secrets unverified)",
        },
    ]
}

fn write_tree(root: &Path, tree: Tree) {
    for (relative, contents) in tree.files() {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create repository directory");
        }
        std::fs::write(&path, contents).expect("write repository file");
    }
}

fn executable(dir: &Path, name: &str, script: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, script).expect("write validator stub");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("chmod validator stub");
    path
}

/// The variables a [`Live`] setup contributes.
fn live_env(live: Live) -> Vec<(String, String)> {
    let gateway = |url: String| {
        vec![
            ("FERRUM_GATEWAY_MODE".to_string(), "api".to_string()),
            ("FERRUM_GATEWAY_URL".to_string(), url),
            // The stubs speak cleartext on loopback.
            ("FERRUM_ALLOW_INSECURE_HTTP".to_string(), "true".to_string()),
            (
                "FERRUM_ADMIN_JWT_SECRET".to_string(),
                JWT_SECRET.to_string(),
            ),
            ("FERRUM_GATEWAY_MAX_RETRIES".to_string(), "0".to_string()),
        ]
    };
    let data_plane_env = |url: String| {
        vec![
            ("FERRUM_VERIFY_BASE_URL".to_string(), url),
            ("FERRUM_ALLOW_INSECURE_HTTP".to_string(), "true".to_string()),
        ]
    };
    let requests = Arc::new(Mutex::new(Vec::new()));
    match live {
        Live::Offline => Vec::new(),
        Live::Backup { port, cached } => gateway(spawn_backup_stub(
            vec![(
                "ferrum".to_string(),
                backup(serde_json::json!([live_proxy("app", "ferrum", port, None)])),
            )],
            requests,
            cached,
        )),
        Live::ViewerExport => gateway(spawn_backup_stub(
            vec![("ferrum".to_string(), config_export(EXPORT_KEY_ID, &['a']))],
            requests,
            false,
        )),
        Live::DataPlane(status) => data_plane_env(data_plane(status)),
        Live::ClosedDataPlane => data_plane_env(closed_port()),
    }
}

/// The validator stubs, written once before any child runs.
struct Validators {
    accepts: PathBuf,
    rejects: PathBuf,
}

fn run(case: &Case, scratch: &Path, validators: &Validators) -> Output {
    let repo = TempDir::new().expect("repository tempdir");
    write_tree(repo.path(), case.tree);

    let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
    command.args(case.args).current_dir(repo.path()).env_clear();
    for name in ["PATH", "HOME", "TMPDIR"] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    // Keep coverage profiles outside the repository, preserving the hosted
    // collector's destination despite env_clear().
    let profile_path = std::env::var_os("LLVM_PROFILE_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| scratch.join("default_%m_%p.profraw"));
    let profile_path = std::env::current_dir()
        .expect("test working directory")
        .join(profile_path);
    command.env("LLVM_PROFILE_FILE", profile_path);
    command.env("FERRUM_EDGE_BINARY_PATH", &validators.accepts);
    command.envs(live_env(case.live));
    for (name, value) in case.env {
        if *value == "<rejecting validator>" {
            command.env(name, &validators.rejects);
        } else {
            command.env(name, value);
        }
    }
    command.output().expect("run gitforgeops")
}

#[test]
fn every_documented_exit_code_is_returned_by_the_command_that_documents_it() {
    let scratch = TempDir::new().expect("scratch tempdir");
    let validators = Validators {
        accepts: executable(scratch.path(), "validator-accepts", VALIDATOR_ACCEPTS),
        rejects: executable(scratch.path(), "validator-rejects", VALIDATOR_REJECTS),
    };
    let mut failures = Vec::new();
    let mut reached = BTreeSet::new();
    for case in cases() {
        let output = run(&case, scratch.path(), &validators);
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let code = output.status.code();
        if code != Some(case.expected) || !shown.contains(case.evidence) {
            failures.push(format!(
                "{} (gitforgeops {}): expected exit {} with {:?}, got {:?}\n{}",
                case.name,
                case.args.join(" "),
                case.expected,
                case.evidence,
                code,
                shown
            ));
        }
        reached.insert(case.expected);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n---\n"));
    // Every row of the documented table has at least one witness.
    assert_eq!(reached, (0..=6).collect::<BTreeSet<i32>>());
}

/// The table in CLAUDE.md names these numbers; the constants are what `main`
/// exits with. A renumbered constant must fail here, not only in the matrix.
#[test]
fn exit_code_constants_match_the_documented_table() {
    assert_eq!(EMPTY_NAMESPACE_EXIT_CODE, 1);
    assert_eq!(DRIFT_EXIT_CODE, 2);
    assert_eq!(DOCTOR_FAILED_EXIT_CODE, 3);
    assert_eq!(VERIFY_FAILED_EXIT_CODE, 4);
    assert_eq!(VERIFY_SKIPPED_EXIT_CODE, 5);
    assert_eq!(SECRETS_UNVERIFIED_EXIT_CODE, 6);
    // A usage error must stay distinguishable from drift.
    assert_ne!(USAGE_ERROR_EXIT_CODE, DRIFT_EXIT_CODE);
}
