//! `gitforgeops doctor` as the binary runs it: how `cmd_doctor` reads the
//! process environment, which scopes run which checks, and what it hands the
//! bundled settings auditor.
//!
//! Hermetic, like `exit_code_matrix_tests.rs`: the child starts from
//! `env_clear()`, and `python3` on its `PATH` is a shell stub that records the
//! argv and `GH_TOKEN` it was given, so no test reaches GitHub. Unix-only for
//! the stub.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output};

use gitforgeops::doctor::github::AUDIT_SUCCESS_LINE;
use tempfile::TempDir;

const PROXY: &str = r#"kind: Proxy
spec:
  id: "app"
  backend_host: "app.internal"
  backend_port: 8080
"#;

const REPO_CONFIG: &str = "version: 1\nenvironments:\n  production: {}\n";

struct Doctor {
    repo: TempDir,
    scratch: TempDir,
}

impl Doctor {
    fn new(files: &[(&str, &str)]) -> Self {
        let repo = TempDir::new().expect("repository tempdir");
        for (relative, contents) in files {
            let path = repo.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create repository directory");
            }
            std::fs::write(&path, contents).expect("write repository file");
        }
        let scratch = TempDir::new().expect("scratch tempdir");
        std::fs::create_dir_all(scratch.path().join("bin")).expect("stub bin");
        std::fs::create_dir_all(scratch.path().join("home")).expect("home");
        let doctor = Self { repo, scratch };
        doctor.python_stub("0", true);
        doctor
    }

    fn argv_path(&self) -> PathBuf {
        self.scratch.path().join("python-argv")
    }

    fn token_path(&self) -> PathBuf {
        self.scratch.path().join("python-token")
    }

    /// Install the `python3` stub: it records its argv (NUL-separated) and
    /// `GH_TOKEN`, prints the auditor's evidence, optionally its success
    /// line, and exits with `status`.
    fn python_stub(&self, status: &str, success_line: bool) {
        use std::os::unix::fs::PermissionsExt;
        let success = if success_line {
            format!("echo '{AUDIT_SUCCESS_LINE}'\n")
        } else {
            String::new()
        };
        let script = format!(
            "#!/bin/sh\n\
             for arg in \"$@\"; do printf '%s\\0' \"$arg\"; done > '{argv}'\n\
             printf '%s' \"${{GH_TOKEN:-}}\" > '{token}'\n\
             echo 'Repository protection evidence:'\n\
             echo '  PASS: stub control'\n\
             {success}exit {status}\n",
            argv = self.argv_path().display(),
            token = self.token_path().display(),
        );
        let path = self.scratch.path().join("bin").join("python3");
        std::fs::write(&path, script).expect("write python stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("chmod python stub");
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command
            .arg("doctor")
            .args(args)
            .current_dir(self.repo.path())
            .env_clear()
            .env("HOME", self.scratch.path().join("home"))
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    self.scratch.path().join("bin").display()
                ),
            );
        if let Ok(value) = std::env::var("TMPDIR") {
            command.env("TMPDIR", value);
        }
        // Keep coverage profiles outside the repository, as the exit-code
        // matrix does.
        let profile_path = std::env::var_os("LLVM_PROFILE_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.scratch.path().join("default_%m_%p.profraw"));
        let profile_path = std::env::current_dir()
            .expect("test working directory")
            .join(profile_path);
        command.env("LLVM_PROFILE_FILE", profile_path);
        command.envs(env.iter().copied());
        command.output().expect("run gitforgeops doctor")
    }

    /// The argv the auditor stub received, or `None` when it never ran.
    fn auditor_argv(&self) -> Option<Vec<String>> {
        let bytes = std::fs::read(self.argv_path()).ok()?;
        Some(
            bytes
                .split(|byte| *byte == 0)
                .filter(|arg| !arg.is_empty())
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect(),
        )
    }

    fn auditor_token(&self) -> Option<String> {
        std::fs::read_to_string(self.token_path()).ok()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn has_arg(argv: &[String], flag: &str) -> bool {
    argv.iter().any(|arg| arg == flag)
}

fn arg_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.iter()
        .position(|arg| arg == flag)
        .and_then(|index| argv.get(index + 1))
        .map(String::as_str)
}

const GITHUB_READY: &[(&str, &str)] = &[
    ("GH_TOKEN", "doctor-test-token"),
    ("GITHUB_REPOSITORY", "acme/repo"),
    ("GITFORGEOPS_STATE_APP_ID", "42"),
];

// -- 1: template mode comes from GITFORGEOPS_TEMPLATE_REPO -------------------

#[test]
fn a_repository_without_config_is_audited_as_a_deployment_unless_the_variable_says_template() {
    // settings-audit.yml decides template mode from the repository variable
    // GITFORGEOPS_TEMPLATE_REPO, never from whether config.yaml exists.
    let doctor = Doctor::new(&[("resources/ferrum/proxies/app.yaml", PROXY)]);
    let output = doctor.run(&["--scope", "github"], GITHUB_READY);
    let argv = doctor.auditor_argv().expect("the auditor ran");
    assert!(!has_arg(&argv, "--template-repo"), "{argv:?}");
    assert_eq!(arg_value(&argv, "--state-writer-app-id"), Some("42"));
    assert_eq!(arg_value(&argv, "--repo"), Some("acme/repo"));
    // The workflow always audits the repository's default branch; doctor
    // leaves `--branch` out so the auditor reads it from the repository.
    assert!(!has_arg(&argv, "--branch"), "{argv:?}");
    assert!(
        stdout(&output).contains("PASS    Repository settings match the launch baseline"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn the_template_variable_selects_template_mode_and_drops_the_app_id_like_the_workflow() {
    let doctor = Doctor::new(&[
        (".gitforgeops/config.yaml", REPO_CONFIG),
        ("resources/ferrum/proxies/app.yaml", PROXY),
    ]);
    let mut env = GITHUB_READY.to_vec();
    // The workflow lowercases the value before comparing it.
    env.push(("GITFORGEOPS_TEMPLATE_REPO", "TRUE"));
    doctor.run(&["--scope", "github"], &env);
    let argv = doctor.auditor_argv().expect("the auditor ran");
    assert!(has_arg(&argv, "--template-repo"), "{argv:?}");
    assert!(!has_arg(&argv, "--state-writer-app-id"), "{argv:?}");
}

#[test]
fn a_template_variable_that_is_not_true_is_a_deployment_audit() {
    let doctor = Doctor::new(&[]);
    let mut env = GITHUB_READY.to_vec();
    env.push(("GITFORGEOPS_TEMPLATE_REPO", "yes"));
    doctor.run(&["--scope", "github"], &env);
    let argv = doctor.auditor_argv().expect("the auditor ran");
    assert!(!has_arg(&argv, "--template-repo"), "{argv:?}");
    assert_eq!(arg_value(&argv, "--state-writer-app-id"), Some("42"));
}

// -- 4: process-env is a local check ----------------------------------------

#[test]
fn the_process_environment_check_runs_only_in_the_local_scope() {
    let doctor = Doctor::new(&[]);
    let bogus = [("FERRUM_GATEWAY_MODE", "bogus")];
    let output = doctor.run(&["--scope", "github"], &bogus);
    let text = stdout(&output);
    assert!(!text.contains("Process environment parses"), "{text}");
    // The github scope alone (no repository slug here) is not blocked by a
    // gateway setting it never reads.
    assert_eq!(output.status.code(), Some(0), "{text}");

    let output = doctor.run(&["--scope", "local"], &bogus);
    let text = stdout(&output);
    assert!(
        text.contains("FAIL    Process environment parses"),
        "{text}"
    );
}

// -- 5: the gateway scope on a template or in file mode ----------------------

#[test]
fn the_gateway_scope_on_a_template_without_credentials_is_skipped() {
    let doctor = Doctor::new(&[("resources/ferrum/proxies/app.yaml", PROXY)]);
    let output = doctor.run(&["--scope", "gateway"], &[]);
    let text = stdout(&output);
    assert!(text.contains("SKIP    Gateway is reachable"), "{text}");
    assert!(!text.contains("UNKNOWN"), "{text}");
}

#[test]
fn the_template_variable_skips_the_gateway_scope() {
    let doctor = Doctor::new(&[
        (".gitforgeops/config.yaml", REPO_CONFIG),
        ("resources/ferrum/proxies/app.yaml", PROXY),
    ]);
    let output = doctor.run(
        &["--scope", "gateway"],
        &[
            ("GITFORGEOPS_TEMPLATE_REPO", "true"),
            ("FERRUM_GATEWAY_URL", "https://gateway.invalid:8443"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "doctor-test-signing-secret-long-enough-0000",
            ),
        ],
    );
    let text = stdout(&output);
    assert!(text.contains("SKIP    Gateway is reachable"), "{text}");
    assert!(!text.contains("UNKNOWN"), "{text}");
}

#[test]
fn file_mode_skips_the_gateway_scope_before_assembling_the_tree() {
    // A tree that does not load would make the token-scope resolution fail;
    // file mode has no Admin API, so it must not get that far.
    let doctor = Doctor::new(&[
        (".gitforgeops/config.yaml", REPO_CONFIG),
        (
            "resources/ferrum/proxies/app.yaml",
            "kind: Proxy\nspec: [\n",
        ),
    ]);
    let output = doctor.run(&["--scope", "gateway"], &[("FERRUM_GATEWAY_MODE", "file")]);
    let text = stdout(&output);
    assert!(text.contains("SKIP    Gateway is reachable"), "{text}");
    assert!(!text.contains("token scope"), "{text}");
    assert!(!text.contains("UNKNOWN"), "{text}");
}

// -- 7: blank variables are unset ------------------------------------------

#[test]
fn a_blank_gh_token_falls_back_to_github_token() {
    let doctor = Doctor::new(&[]);
    let output = doctor.run(
        &["--scope", "github"],
        &[
            // Empty, as a workflow's `GH_TOKEN: ${{ secrets.UNSET }}` is. (A
            // whitespace-only token is refused earlier, by the display
            // sink's minimum-length registration.)
            ("GH_TOKEN", ""),
            ("GITHUB_TOKEN", "fallback-token"),
            ("GITHUB_REPOSITORY", "acme/repo"),
            ("GITFORGEOPS_STATE_APP_ID", "42"),
        ],
    );
    assert!(
        doctor.auditor_argv().is_some(),
        "the auditor never ran: {}{}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(doctor.auditor_token().as_deref(), Some("fallback-token"));
}

#[test]
fn a_blank_github_repository_is_unset_rather_than_an_empty_slug() {
    let doctor = Doctor::new(&[]);
    let output = doctor.run(
        &["--scope", "github"],
        &[
            ("GH_TOKEN", "doctor-test-token"),
            ("GITHUB_REPOSITORY", ""),
            ("GITFORGEOPS_STATE_APP_ID", "42"),
        ],
    );
    let text = stdout(&output);
    assert!(doctor.auditor_argv().is_none(), "the auditor ran: {text}");
    assert!(text.contains("no repository slug"), "{text}");

    // A blank `--repo` is no flag either.
    let output = doctor.run(
        &["--scope", "github", "--repo", " "],
        &[
            ("GH_TOKEN", "doctor-test-token"),
            ("GITFORGEOPS_STATE_APP_ID", "42"),
        ],
    );
    assert!(
        stdout(&output).contains("no repository slug"),
        "{}",
        stdout(&output)
    );
}

// -- 6 and 10 through the binary --------------------------------------------

#[test]
fn a_non_integer_app_id_fails_without_running_the_auditor() {
    let doctor = Doctor::new(&[]);
    let output = doctor.run(
        &["--scope", "github"],
        &[
            ("GH_TOKEN", "doctor-test-token"),
            ("GITHUB_REPOSITORY", "acme/repo"),
            ("GITFORGEOPS_STATE_APP_ID", "app-42"),
        ],
    );
    assert!(doctor.auditor_argv().is_none());
    let text = stdout(&output);
    assert!(text.contains("FAIL"), "{text}");
    assert!(text.contains("GITFORGEOPS_STATE_APP_ID"), "{text}");
    assert_eq!(
        output.status.code(),
        Some(gitforgeops::doctor::DOCTOR_FAILED_EXIT_CODE)
    );
}

#[test]
fn an_auditor_exit_zero_without_its_success_line_is_not_a_pass() {
    let doctor = Doctor::new(&[]);
    doctor.python_stub("0", false);
    let output = doctor.run(&["--scope", "github"], GITHUB_READY);
    let text = stdout(&output);
    assert!(
        text.contains("UNKNOWN Repository settings match the launch baseline"),
        "{text}"
    );
}
