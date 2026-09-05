//! End-to-end gate tests that only the binary can demonstrate.
//!
//! `apply` refusing to publish, and `plan` exiting non-zero, are properties of
//! the *command*, not of any library function: the point is that nothing is
//! written and the process reports failure. Both are exercised in file mode so
//! the whole run is hermetic — no gateway, no GitHub, no network — with a stub
//! validator standing in for `ferrum-edge` (absent in Rust CI).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// Consumer declaring a committed, literal API key. This is the shape
/// `import` used to produce and the one `apply` must refuse.
const LITERAL_CONSUMER: &str = r#"kind: Consumer
spec:
  id: "app"
  username: "app"
  credentials:
    keyauth:
      - key: "live-secret"
"#;

/// The same consumer in the only supported on-disk form.
const BROKERED_CONSUMER: &str = r#"kind: Consumer
spec:
  id: "app"
  username: "app"
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=require}"
"#;

/// Bundle holding the value for the brokered consumer's single slot.
/// Namespace and consumer id come from the directory and the spec; index 0 is
/// elided, so the slot is `ferrum/app/keyauth/key`.
const BUNDLE: &str = r#"{"FERRUM_CREDS_BUNDLE": {"ferrum/app/keyauth/key": "bundle-value"}}"#;

/// The same consumer after the *first* of two `keyauth` entries was deleted.
/// The survivor shifts into the elided slot and inherits the deleted entry's
/// value; `[1]` is left orphaned in the bundle below.
const SHRUNK_CONSUMER: &str = BROKERED_CONSUMER;

/// Bundle from before the shrink: both entries were allocated.
const TWO_SLOT_BUNDLE: &str = r#"{"FERRUM_CREDS_BUNDLE": {
    "ferrum/app/keyauth/key": "first-entry-value",
    "ferrum/app/keyauth/[1]/key": "second-entry-value"
}}"#;

/// A throwaway repository checkout plus a stub validator.
struct Repo {
    dir: TempDir,
    validator: PathBuf,
}

impl Repo {
    /// Build a checkout from `(relative path, contents)` pairs.
    fn with_files(files: &[(&str, &str)]) -> Self {
        let dir = TempDir::new().expect("tempdir");
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("resource tree");
            }
            std::fs::write(&path, contents).expect("write repo file");
        }

        // `ferrum-edge validate` is not installed in Rust CI, and these tests
        // are about the gates that run around it rather than about schema
        // validation. A stub that accepts everything keeps a refusal
        // attributable to the gate under test.
        let validator = dir.path().join("ferrum-edge-stub");
        std::fs::write(&validator, "#!/bin/sh\nexit 0\n").expect("stub");
        set_executable(&validator);

        Self { dir, validator }
    }

    fn with_consumer(consumer_yaml: &str) -> Self {
        Self::with_files(&[("resources/ferrum/consumers/app.yaml", consumer_yaml)])
    }

    fn published(&self) -> PathBuf {
        self.dir.path().join("published/resources.yaml")
    }

    /// Run the binary in the repository, hermetically: the child inherits only
    /// PATH/HOME/TMPDIR plus the `FERRUM_*` variables named here, so an
    /// ambient `FERRUM_GATEWAY_URL` in a developer shell cannot make a
    /// file-mode test talk to a gateway.
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
            .env("FERRUM_FILE_OUTPUT_PATH", self.published())
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn apply_refuses_a_literal_consumer_credential_and_publishes_nothing() {
    let repo = Repo::with_consumer(LITERAL_CONSUMER);

    let output = repo.run(&["apply", "--auto-approve"], &[]);

    assert!(
        !output.status.success(),
        "apply must refuse a committed credential; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("Literal credential"),
        "the refusal must name the finding: {stderr}"
    );
    assert!(
        stderr.contains("Refusing to apply"),
        "the refusal must say it refused: {stderr}"
    );
    assert!(
        !repo.published().exists(),
        "a refused apply must publish nothing, but {} exists",
        repo.published().display()
    );
}

#[test]
fn apply_publishes_a_brokered_consumer_resolved_from_the_bundle() {
    let repo = Repo::with_consumer(BROKERED_CONSUMER);

    let output = repo.run(
        &["apply", "--auto-approve"],
        &[("FERRUM_CREDS_JSON", BUNDLE)],
    );

    assert!(
        output.status.success(),
        "a brokered consumer is the supported form and must apply; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let published = std::fs::read_to_string(repo.published()).expect("published document");
    // File mode publishes the placeholder-preserving document: the resolved
    // value belongs in the separate materialize step, never in the artifact
    // this command writes.
    assert!(
        published.contains("gh-env-secret"),
        "file mode must publish placeholders, got: {published}"
    );
    assert!(
        !published.contains("bundle-value"),
        "the resolved value must not reach the published document"
    );
}

#[test]
fn plan_exits_nonzero_on_a_literal_consumer_credential() {
    let repo = Repo::with_consumer(LITERAL_CONSUMER);

    let output = repo.run(&["plan"], &[]);

    assert!(
        !output.status.success(),
        "plan's verdict must match apply's; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let stdout = stdout(&output);
    assert!(
        stdout.contains("Security Findings") && stdout.contains("Literal credential"),
        "the finding must still be printed, not just signalled by the exit code: {stdout}"
    );
    assert!(
        stdout.contains("block apply"),
        "plan must say the finding is terminal: {stdout}"
    );
}

#[test]
fn plan_exits_zero_for_a_brokered_consumer() {
    let repo = Repo::with_consumer(BROKERED_CONSUMER);

    let output = repo.run(&["plan"], &[("FERRUM_CREDS_JSON", BUNDLE)]);

    assert!(
        output.status.success(),
        "a placeholder is repository data, not a finding; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn apply_refuses_a_credential_array_shrink_that_reassigns_a_stored_slot() {
    let repo = Repo::with_consumer(SHRUNK_CONSUMER);

    let output = repo.run(
        &["apply", "--auto-approve"],
        &[("FERRUM_CREDS_JSON", TWO_SLOT_BUNDLE)],
    );

    assert!(
        !output.status.success(),
        "a shrink that re-owns a stored slot must not apply; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("ferrum/app/keyauth/[1]/key"),
        "the refusal must name the orphaned slot: {stderr}"
    );
    assert!(
        !stderr.contains("first-entry-value") && !stderr.contains("second-entry-value"),
        "a refusal must never echo bundle values: {stderr}"
    );
    assert!(
        !repo.published().exists(),
        "a refused apply must leave the bundle and the published document untouched"
    );
}

#[test]
fn apply_accepts_a_shrink_when_the_remap_is_explicitly_allowed() {
    let repo = Repo::with_consumer(SHRUNK_CONSUMER);

    let output = repo.run(
        &["apply", "--auto-approve", "--allow-credential-slot-remap"],
        &[("FERRUM_CREDS_JSON", TWO_SLOT_BUNDLE)],
    );

    assert!(
        output.status.success(),
        "the documented shrink-then-rotate sequence must stay reachable; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        repo.published().exists(),
        "an accepted apply publishes as usual"
    );
    assert!(
        stderr(&output).contains("ferrum/app/keyauth/[1]/key"),
        "the hazard is accepted, not hidden: {}",
        stderr(&output)
    );
}

#[test]
fn plan_exits_nonzero_on_an_unacknowledged_credential_slot_remap() {
    let repo = Repo::with_consumer(SHRUNK_CONSUMER);

    let output = repo.run(&["plan"], &[("FERRUM_CREDS_JSON", TWO_SLOT_BUNDLE)]);

    assert!(
        !output.status.success(),
        "plan's verdict must match apply's; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let planned = stdout(&output);
    assert!(
        planned.contains("Credential Slot Remaps")
            && planned.contains("ferrum/app/keyauth/[1]/key"),
        "the hazard must be rendered in plan output, not only on stderr: {planned}"
    );
    assert!(
        planned.contains("block apply"),
        "plan must say the finding is terminal: {planned}"
    );

    // Acknowledged, the same repository plans clean.
    let allowed = repo.run(
        &["plan", "--allow-credential-slot-remap"],
        &[("FERRUM_CREDS_JSON", TWO_SLOT_BUNDLE)],
    );
    assert!(
        allowed.status.success(),
        "stdout={} stderr={}",
        stdout(&allowed),
        stderr(&allowed)
    );
    assert!(
        stdout(&allowed).contains("Accepted via --allow-credential-slot-remap"),
        "{}",
        stdout(&allowed)
    );
}

/// The issue-128 mTLS consumer: one identity leaf, nothing else.
const MTLS_IDENTITY_CONSUMER: &str = r#"kind: Consumer
spec:
  id: "app"
  username: "app"
  credentials:
    mtls_auth:
      - identity: client.example
"#;

/// The issue-128 Basic-auth consumer as `import` writes it: a legible
/// username beside a brokered secret half.
const BASICAUTH_IDENTITY_CONSUMER: &str = r#"kind: Consumer
spec:
  id: "app"
  username: "app"
  credentials:
    basicauth:
      - username: alice
        password_hash: "${gh-env-secret:alloc=require}"
"#;

/// Bundle seeding the Basic-auth consumer's one brokered slot.
const BASICAUTH_BUNDLE: &str = r#"{"FERRUM_CREDS_BUNDLE": {
    "ferrum/app/basicauth/password_hash": "hmac_sha256:0123456789abcdef"
}}"#;

/// The same Basic-auth consumer with the hash committed instead of brokered.
const BASICAUTH_LITERAL_HASH_CONSUMER: &str = r#"kind: Consumer
spec:
  id: "app"
  username: "app"
  credentials:
    basicauth:
      - username: alice
        password_hash: "hmac_sha256:0123456789abcdef"
"#;

#[test]
fn apply_accepts_credential_identity_fields_without_an_override() {
    // Regression for #128: `mtls_auth[].identity` and `basicauth[].username`
    // are the public halves of their credentials, produced verbatim by this
    // repo's own `import`. Treating them as committed secrets refused
    // supported configurations before the validator ever ran.
    for (name, consumer, bundle) in [
        ("mtls_auth identity", MTLS_IDENTITY_CONSUMER, None),
        (
            "basicauth username",
            BASICAUTH_IDENTITY_CONSUMER,
            Some(BASICAUTH_BUNDLE),
        ),
    ] {
        let repo = Repo::with_consumer(consumer);
        let env: Vec<(&str, &str)> = bundle
            .map(|b| vec![("FERRUM_CREDS_JSON", b)])
            .unwrap_or_default();

        let planned = repo.run(&["plan"], &env);
        assert!(
            planned.status.success(),
            "{name} must plan clean; stdout={} stderr={}",
            stdout(&planned),
            stderr(&planned)
        );
        assert!(
            !stdout(&planned).contains("Literal credential"),
            "{name} must not be reported as a literal secret: {}",
            stdout(&planned)
        );

        let applied = repo.run(&["apply", "--auto-approve"], &env);
        assert!(
            applied.status.success(),
            "{name} must apply; stdout={} stderr={}",
            stdout(&applied),
            stderr(&applied)
        );
        assert!(
            repo.published().exists(),
            "{name} must reach the published document"
        );
    }
}

#[test]
fn apply_still_refuses_a_committed_secret_beside_an_identity() {
    // The exemption is per-leaf. A Basic-auth consumer whose username is
    // legible and whose hash is committed is still a committed secret.
    let repo = Repo::with_consumer(BASICAUTH_LITERAL_HASH_CONSUMER);

    let output = repo.run(&["apply", "--auto-approve"], &[]);

    assert!(
        !output.status.success(),
        "a committed password_hash must still block; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("basicauth[0].password_hash"),
        "the refusal must name the secret leaf: {stderr}"
    );
    assert!(
        !stderr.contains("basicauth[0].username"),
        "the identity half must not be reported: {stderr}"
    );
    assert!(
        !repo.published().exists(),
        "a refused apply must publish nothing"
    );
}
