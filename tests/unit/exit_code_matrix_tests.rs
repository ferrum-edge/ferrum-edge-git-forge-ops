//! The documented exit-code contract (CLAUDE.md, "Exit codes"), one table.
//!
//! Workflows, the drift monitor and operators branch on the process status
//! alone, so a refactor of `main.rs` dispatch must not silently move a code.
//! Every row spawns the real binary and pins one `(command, input) → code`
//! pair, plus evidence on one named stream (and its absence from the other)
//! proving the code came from the intended path. The per-command modules
//! (`diff_exit_tests.rs`, `verify_exit_tests.rs`, `apply_gate_tests.rs`,
//! `namespace_filter_guard_tests.rs`, ...) pin the behaviour behind each code
//! in depth. This module's job is breadth: every documented code is
//! reachable, and each command returns the documented one.
//!
//! Hermetic: the child starts from `env_clear()` and receives only `PATH`,
//! `TMPDIR`, a per-row `HOME`, the coverage profile path and the variables a
//! row names, so no inherited `FERRUM_*`, `GITFORGEOPS_*` or `GITHUB_*` value
//! reaches it. Gateways and data planes are loopback stubs; the validator is
//! a shell stub, which is why the matrix is Unix-only.

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
use super::verify_exit_tests::{data_plane, hang_up_data_plane, STAGING_ONLY};

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

/// A populated validator digest allowlist, so doctor's pin check passes.
const VALIDATOR_PIN: (&str, &str) = (
    ".github/ferrum-edge-checksums.txt",
    "0000000000000000000000000000000000000000000000000000000000000000  ferrum-edge\n",
);

/// A usage or parse error is an ordinary error (1). It must never be clap's
/// default 2, which is `DRIFT_EXIT_CODE`: the drift monitor reads 2 from
/// `diff --exit-on-drift` as "drift found", so a mistyped flag would be
/// reported as drift instead of a failed check.
const USAGE_ERROR_EXIT_CODE: i32 = 1;

const VALIDATOR_ACCEPTS: &str = "#!/bin/sh\nexit 0\n";
const VALIDATOR_REJECTS: &str = "#!/bin/sh\necho 'stub rejection' >&2\nexit 1\n";

/// The value in a row's `env` that stands for the rejecting validator stub.
const REJECTING_VALIDATOR: &str = "<rejecting validator>";

const TOP_LEVEL_USAGE: &str = "Usage: gitforgeops [OPTIONS] <COMMAND>";
const DIFF_USAGE: &str = "Usage: gitforgeops diff [OPTIONS]";
const VERSION_LINE: &str = concat!("gitforgeops ", env!("CARGO_PKG_VERSION"));
/// The `Error:` line on stderr; `validate` and `plan` also list the finding
/// as `[error] ...` in their stdout report.
const EMPTY_SELECTION: &str = "Error: namespace filter 'nothing' selected 0 desired resources";

/// The repository the child runs in.
#[derive(Clone, Copy)]
enum Tree {
    /// `resources/ferrum/proxies/app.yaml`, matching the live row the
    /// `/backup` stub serves on port 8080.
    Proxy,
    /// No `resources/` directory at all.
    NoResources,
    /// No `resources/` directory, but a populated validator allowlist, so the
    /// resource-tree check is doctor's only failure.
    PinnedNoResources,
    /// [`Tree::Proxy`] plus an unsupported `.gitforgeops/config.yaml`.
    BadRepoConfig,
    /// [`Tree::Proxy`] plus a Consumer with a literal secret.
    LiteralCredential,
    /// A Consumer with a brokered key, for the viewer `/config/export` read.
    BrokeredConsumer,
    /// [`Tree::Proxy`] plus a populated validator allowlist, so every local
    /// doctor check passes or is skipped.
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
            Tree::PinnedNoResources => vec![VALIDATOR_PIN],
            Tree::BadRepoConfig => vec![proxy, (".gitforgeops/config.yaml", BAD_REPO_CONFIG)],
            Tree::LiteralCredential => vec![
                proxy,
                ("resources/ferrum/consumers/literal.yaml", LITERAL_CONSUMER),
            ],
            Tree::BrokeredConsumer => {
                vec![("resources/ferrum/consumers/app.yaml", KEYAUTH_CONSUMER)]
            }
            Tree::DoctorReady => vec![proxy, VALIDATOR_PIN],
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
    /// A data plane that accepts each connection and closes it unanswered.
    HangUpDataPlane,
}

/// The stream a row's evidence must appear on.
#[derive(Clone, Copy, Debug)]
enum Stream {
    Stdout,
    Stderr,
}
use Stream::{Stderr, Stdout};

/// One row of the contract.
struct Case {
    /// Shown on failure.
    name: &'static str,
    tree: Tree,
    live: Live,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    expected: i32,
    /// Where the evidence must appear. The other stream must not carry it, so
    /// swapping `out!` and `eout!` fails the row.
    stream: Stream,
    /// Non-empty substrings proving the code came from the intended path
    /// rather than an unrelated early failure.
    evidence: &'static [&'static str],
}

impl Case {
    fn new(
        name: &'static str,
        args: &'static [&'static str],
        expected: i32,
        stream: Stream,
        evidence: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            tree: Tree::Proxy,
            live: Live::Offline,
            args,
            env: &[],
            expected,
            stream,
            evidence,
        }
    }

    fn tree(mut self, tree: Tree) -> Self {
        self.tree = tree;
        self
    }

    fn live(mut self, live: Live) -> Self {
        self.live = live;
        self
    }

    fn env(mut self, env: &'static [(&'static str, &'static str)]) -> Self {
        self.env = env;
        self
    }

    /// A clap usage or parse error: exit 1, message on stderr only.
    fn usage_error(
        name: &'static str,
        args: &'static [&'static str],
        message: &'static [&'static str],
    ) -> Self {
        Self::new(name, args, USAGE_ERROR_EXIT_CODE, Stderr, message)
    }
}

fn cases() -> Vec<Case> {
    use Live::*;
    use Tree::*;
    let in_sync = Backup {
        port: 8080,
        cached: false,
    };
    let drifted = Backup {
        port: 9999,
        cached: false,
    };
    let staging = &[("FERRUM_ENV", "staging")];
    vec![
        // -- 0: success ---------------------------------------------------
        Case::new("--version", &["--version"], 0, Stdout, &[VERSION_LINE]),
        Case::new("-V", &["-V"], 0, Stdout, &[VERSION_LINE]),
        Case::new("--help", &["--help"], 0, Stdout, &[TOP_LEVEL_USAGE]),
        Case::new("-h", &["-h"], 0, Stdout, &[TOP_LEVEL_USAGE]),
        Case::new("help", &["help"], 0, Stdout, &[TOP_LEVEL_USAGE]),
        Case::new("help diff", &["help", "diff"], 0, Stdout, &[DIFF_USAGE]),
        Case::new("diff --help", &["diff", "--help"], 0, Stdout, &[DIFF_USAGE]),
        Case::new("version", &["version"], 0, Stdout, &[VERSION_LINE]),
        Case::new(
            "version --format json",
            &["version", "--format", "json"],
            0,
            Stdout,
            &["\"version\""],
        ),
        Case::new(
            "validate on a valid tree",
            &["validate"],
            0,
            Stdout,
            &["Validation passed."],
        ),
        Case::new("export", &["export"], 0, Stdout, &["app.internal"]),
        Case::new("envs", &["envs"], 0, Stdout, &["[\"default\"]"]),
        Case::new(
            "plan without a gateway and without blockers",
            &["plan"],
            0,
            Stderr,
            &["gateway URL not configured"],
        ),
        Case::new(
            "diff --exit-on-drift in sync",
            &["diff", "--exit-on-drift"],
            0,
            Stdout,
            &["No differences found"],
        )
        .live(in_sync),
        Case::new(
            "diff --exit-on-drift --accept-unverified-secrets",
            &["diff", "--exit-on-drift", "--accept-unverified-secrets"],
            0,
            Stdout,
            &["Fingerprinted secret fields were not verified"],
        )
        .tree(BrokeredConsumer)
        .live(ViewerExport)
        .env(&VIEWER_ONLY),
        Case::new(
            "diff without --exit-on-drift reports drift and exits 0",
            &["diff"],
            0,
            Stdout,
            &["MODIFY Proxy app"],
        )
        .live(drifted),
        Case::new(
            "doctor --scope local on a ready tree",
            &["doctor", "--scope", "local"],
            0,
            Stdout,
            &["No blocking problems found."],
        )
        .tree(DoctorReady),
        Case::new(
            "verify with a passing check",
            &["verify"],
            0,
            Stdout,
            &["1 of 1 checks passed."],
        )
        .tree(StagingSmoke)
        .live(DataPlane(200))
        .env(staging),
        Case::new(
            "review stays 0 on an offline blocker",
            &["review"],
            0,
            Stdout,
            &["Apply is blocked", "1 blocking"],
        )
        .tree(LiteralCredential),
        // -- 1: error -----------------------------------------------------
        Case::new(
            "export without a resources directory",
            &["export"],
            1,
            Stderr,
            &["no resources directory found"],
        )
        .tree(NoResources),
        Case::new(
            "validate without a resources directory",
            &["validate"],
            1,
            Stderr,
            &["no resources directory found"],
        )
        .tree(NoResources),
        Case::new(
            "rotate without a provisioning repository",
            &["rotate", "--consumer", "x", "--credential", "keyauth/key"],
            1,
            Stderr,
            &["Error: GITHUB_REPOSITORY not set"],
        ),
        Case::new(
            "envs with an unsupported repository config",
            &["envs"],
            1,
            Stderr,
            &["unsupported repository config version 99"],
        )
        .tree(BadRepoConfig),
        Case::new(
            "export with an unsupported repository config",
            &["export"],
            1,
            Stderr,
            &["unsupported repository config version 99"],
        )
        .tree(BadRepoConfig),
        Case::new(
            "invalid enum env var",
            &["export"],
            1,
            Stderr,
            &["invalid FERRUM_GATEWAY_MODE value"],
        )
        .env(&[("FERRUM_GATEWAY_MODE", "bogus")]),
        Case::new(
            "invalid boolean env var",
            &["export"],
            1,
            Stderr,
            &["invalid FERRUM_ALLOW_UNKNOWN_FIELDS value"],
        )
        .env(&[("FERRUM_ALLOW_UNKNOWN_FIELDS", "maybe")]),
        Case::new(
            "invalid review boolean env var",
            &["review"],
            1,
            Stderr,
            &["invalid GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS value"],
        )
        .env(&[("GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS", "bogus")]),
        Case::new(
            "validate with a rejecting validator",
            &["validate"],
            1,
            Stdout,
            &["stub rejection"],
        )
        .env(&[("FERRUM_EDGE_BINARY_PATH", REJECTING_VALIDATOR)]),
        Case::new(
            "validate without a validator binary",
            &["validate"],
            1,
            Stderr,
            &["ferrum-edge binary not found"],
        )
        .env(&[("FERRUM_EDGE_BINARY_PATH", "/nonexistent/ferrum-edge")]),
        Case::new(
            "validate: empty-namespace refusal is 1, not 2",
            &["validate"],
            EMPTY_NAMESPACE_EXIT_CODE,
            Stderr,
            &[EMPTY_SELECTION],
        )
        .env(&[("FERRUM_NAMESPACE", "nothing")]),
        Case::new(
            "plan: empty-namespace refusal is 1, not 2",
            &["plan"],
            EMPTY_NAMESPACE_EXIT_CODE,
            Stderr,
            &[EMPTY_SELECTION],
        )
        .env(&[("FERRUM_NAMESPACE", "nothing")]),
        Case::new(
            "diff: empty-namespace refusal is 1, not 2",
            &["diff"],
            EMPTY_NAMESPACE_EXIT_CODE,
            Stderr,
            &[EMPTY_SELECTION],
        )
        .env(&[("FERRUM_NAMESPACE", "nothing")]),
        Case::new(
            "diff --exit-on-drift: empty-namespace refusal is 1, not 2",
            &["diff", "--exit-on-drift"],
            EMPTY_NAMESPACE_EXIT_CODE,
            Stderr,
            &[EMPTY_SELECTION],
        )
        .env(&[("FERRUM_NAMESPACE", "nothing")]),
        Case::new(
            "plan with an offline apply blocker",
            &["plan"],
            1,
            Stdout,
            &["=== Apply Blockers ==="],
        )
        .tree(LiteralCredential),
        Case::new(
            "review --fail-on-blockers with an offline blocker",
            &["review", "--fail-on-blockers"],
            1,
            Stderr,
            &["apply is blocked by 1 class(es): security"],
        )
        .tree(LiteralCredential),
        Case::new(
            "review with GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS=true and an offline blocker",
            &["review"],
            1,
            Stderr,
            &["apply is blocked by 1 class(es): security"],
        )
        .tree(LiteralCredential)
        .env(&[("GITFORGEOPS_REVIEW_FAIL_ON_BLOCKERS", "true")]),
        Case::new(
            "apply refuses a literal credential before any gateway call",
            &["apply", "--auto-approve"],
            1,
            Stderr,
            &["Refusing to apply: 1 error-severity security finding"],
        )
        .tree(LiteralCredential),
        Case::new(
            "import from a missing file",
            &[
                "import",
                "--from-file",
                "does-not-exist.yaml",
                "--output-dir",
                "imported",
            ],
            1,
            Stderr,
            &["failed to read file does-not-exist.yaml"],
        ),
        Case::new(
            "diff --exit-on-drift on a cached backup",
            &["diff", "--exit-on-drift"],
            1,
            Stderr,
            &["requires an authoritative backup"],
        )
        .live(Backup {
            port: 9999,
            cached: true,
        }),
        Case::new(
            "verify with declared checks and no data-plane URL",
            &["verify"],
            1,
            Stderr,
            &["FERRUM_VERIFY_BASE_URL"],
        )
        .tree(StagingSmoke)
        .env(staging),
        // -- 1 (clap): usage errors are errors, never DRIFT_EXIT_CODE -----
        Case::new(
            "no subcommand",
            &[],
            USAGE_ERROR_EXIT_CODE,
            Stderr,
            &[TOP_LEVEL_USAGE],
        ),
        Case::usage_error(
            "unknown subcommand",
            &["bogus"],
            &["error: unrecognized subcommand 'bogus'"],
        ),
        Case::usage_error(
            "help for an unknown subcommand",
            &["help", "bogus"],
            &["error: unrecognized subcommand 'bogus'"],
        ),
        Case::usage_error(
            "unknown flag",
            &["validate", "--bogus"],
            &["error: unexpected argument '--bogus' found"],
        ),
        Case::usage_error(
            "unknown flag on diff --exit-on-drift",
            &["diff", "--exit-on-drift", "--bogus"],
            &["error: unexpected argument '--bogus' found"],
        ),
        Case::usage_error(
            "invalid enum flag value",
            &["doctor", "--scope", "bogus"],
            &["error: invalid value 'bogus' for '--scope <SCOPE>'"],
        ),
        Case::usage_error(
            "value that fails validation",
            &["review", "--pr", "abc"],
            &["error: invalid value 'abc' for '--pr <PR>'"],
        ),
        Case::usage_error(
            "missing value for an enum flag",
            &["validate", "--format"],
            &["error: a value is required for '--format <FORMAT>'"],
        ),
        Case::usage_error(
            "missing value for a path flag",
            &["diff", "--fingerprint-baseline"],
            &["error: a value is required for '--fingerprint-baseline <PATH>'"],
        ),
        Case::usage_error(
            "missing required argument",
            &["import", "--from-api"],
            &["error: the following required arguments were not provided"],
        ),
        Case::usage_error(
            "missing required arguments",
            &["rotate"],
            &["error: the following required arguments were not provided"],
        ),
        Case::usage_error(
            "conflicting arguments",
            &[
                "import",
                "--from-api",
                "--from-file",
                "x",
                "--output-dir",
                "y",
            ],
            &["error: the argument '--from-api' cannot be used with '--from-file <FROM_FILE>'"],
        ),
        // -- 2: drift -----------------------------------------------------
        Case::new(
            "diff --exit-on-drift with managed drift",
            &["diff", "--exit-on-drift"],
            DRIFT_EXIT_CODE,
            Stdout,
            &["MODIFY Proxy app"],
        )
        .live(drifted),
        // -- 3: doctor blocker --------------------------------------------
        Case::new(
            "doctor --scope local without the validator digest allowlist",
            &["doctor", "--scope", "local"],
            DOCTOR_FAILED_EXIT_CODE,
            Stdout,
            &[
                "FAIL    Validator digest allowlist is populated",
                ", 1 failed,",
            ],
        ),
        Case::new(
            "doctor --scope local without a resources directory",
            &["doctor", "--scope", "local"],
            DOCTOR_FAILED_EXIT_CODE,
            Stdout,
            &["FAIL    Resource tree is present", ", 1 failed,"],
        )
        .tree(PinnedNoResources),
        // -- 4: verify failed ---------------------------------------------
        Case::new(
            "verify with a check answered by the wrong status",
            &["verify"],
            VERIFY_FAILED_EXIT_CODE,
            Stdout,
            &[
                "UNEXPECTED  orders route answers",
                "expected 200, got 503",
                "0 of 1 checks passed.",
            ],
        )
        .tree(StagingSmoke)
        .live(DataPlane(503))
        .env(staging),
        Case::new(
            "verify against a data plane that hangs up",
            &["verify"],
            VERIFY_FAILED_EXIT_CODE,
            Stdout,
            &[
                "UNREACHABLE orders route answers",
                "expected 200, request failed after 1 attempt(s)",
                "0 of 1 checks passed.",
            ],
        )
        .tree(StagingSmoke)
        .live(HangUpDataPlane)
        .env(staging),
        // -- 5: verify skipped --------------------------------------------
        Case::new(
            "verify with no declared check for the environment",
            &["verify"],
            VERIFY_SKIPPED_EXIT_CODE,
            Stdout,
            &["skipped: no smoke checks declared for production in .gitforgeops/smoke.yaml"],
        )
        .tree(StagingSmoke)
        .env(&[("FERRUM_ENV", "production")]),
        Case::new(
            // `staging` has checks in `Tree::StagingSmoke`; here the same
            // environment skips only because the file is absent.
            "verify with no smoke file",
            &["verify"],
            VERIFY_SKIPPED_EXIT_CODE,
            Stdout,
            &["skipped: no smoke checks declared for staging in .gitforgeops/smoke.yaml"],
        )
        .env(staging),
        // -- 6: secrets unverified ----------------------------------------
        Case::new(
            "diff --exit-on-drift in sync with unverified secrets",
            &["diff", "--exit-on-drift"],
            SECRETS_UNVERIFIED_EXIT_CODE,
            Stderr,
            &["(in sync, secrets unverified)"],
        )
        .tree(BrokeredConsumer)
        .live(ViewerExport)
        .env(&VIEWER_ONLY),
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
        Live::HangUpDataPlane => data_plane_env(hang_up_data_plane()),
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
    let home = TempDir::new().expect("home tempdir");

    let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
    command
        .args(case.args)
        .current_dir(repo.path())
        .env_clear()
        .env("HOME", home.path());
    for name in ["PATH", "TMPDIR"] {
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
        if *value == REJECTING_VALIDATOR {
            command.env(name, &validators.rejects);
        } else {
            command.env(name, value);
        }
    }
    command.output().expect("run gitforgeops")
}

/// Why `output` does not satisfy `case`, if it does not.
fn mismatch(case: &Case, output: &Output) -> Option<String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let (expected, other) = match case.stream {
        Stdout => (&stdout, &stderr),
        Stderr => (&stderr, &stdout),
    };
    let mut problems = Vec::new();
    if output.status.code() != Some(case.expected) {
        problems.push(format!(
            "expected exit {}, got {:?}",
            case.expected,
            output.status.code()
        ));
    }
    for evidence in case.evidence {
        if !expected.contains(evidence) {
            problems.push(format!("{:?} missing from {:?}", evidence, case.stream));
        }
        if other.contains(evidence) {
            problems.push(format!("{:?} also on the other stream", evidence));
        }
    }
    (!problems.is_empty()).then(|| {
        format!(
            "{} (gitforgeops {}): {}\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
            case.name,
            case.args.join(" "),
            problems.join("; ")
        )
    })
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
        // A row without evidence would pass on any output with the right code.
        assert!(
            !case.evidence.is_empty() && case.evidence.iter().all(|e| !e.is_empty()),
            "row {:?} needs non-empty evidence",
            case.name
        );
        let output = run(&case, scratch.path(), &validators);
        failures.extend(mismatch(&case, &output));
        reached.insert(case.expected);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n=====\n"));
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
