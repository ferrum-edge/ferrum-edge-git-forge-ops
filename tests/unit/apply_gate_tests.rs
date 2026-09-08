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

/// Proxy dialing an `http` backend. Rejected by the `backend_scheme` policy
/// below, accepted by every default (all policy rules ship disabled).
const HTTP_PROXY: &str = r#"kind: Proxy
spec:
  id: "app"
  listen_path: "/app"
  backend_scheme: http
  backend_host: "app.internal"
  backend_port: 8080
"#;

/// The same proxy on the scheme the policy allows.
const HTTPS_PROXY: &str = r#"kind: Proxy
spec:
  id: "app"
  listen_path: "/app"
  backend_scheme: https
  backend_host: "app.internal"
  backend_port: 443
"#;

/// `backend_scheme` at error severity: an `http` backend blocks apply.
const HTTPS_ONLY_POLICY: &str = r#"version: 1
policies:
  backend_scheme:
    enabled: true
    severity: error
    allowed_protocols: [https]
"#;

/// The same rule demoted to a warning, which apply does not refuse on.
const HTTPS_ONLY_POLICY_WARNING: &str = r#"version: 1
policies:
  backend_scheme:
    enabled: true
    severity: warning
    allowed_protocols: [https]
"#;

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

#[cfg(unix)]
#[test]
fn identity_broker_cli_refuses_before_validator_network_or_file_side_effects() {
    for (kind, leaf) in [("basicauth", "username"), ("mtls_auth", "identity")] {
        for alloc in ["require", "generate", "rotate"] {
            for seeded in [false, true] {
                let consumer = format!(
                    "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials:\n    keyauth:\n      - key: '${{gh-env-secret:alloc=generate}}'\n    {kind}:\n      - {leaf}: public-first\n      - {leaf}: '${{gh-env-secret:alloc={alloc}}}'\n"
                );
                let repo = Repo::with_consumer(&consumer);
                std::fs::write(
                    &repo.validator,
                    "#!/bin/sh\ntouch validator-ran\ncat \"$7\"\ncat \"$7\" >&2\nexit 1\n",
                )
                .unwrap();
                let slot = format!("ferrum/app/{kind}/[1]/{leaf}");
                let bundle = if seeded {
                    serde_json::json!({"FERRUM_CREDS_BUNDLE": {
                        (slot.clone()): "synthetic-identity-bundle-value",
                        "ferrum/app/keyauth/key": "synthetic-sibling-bundle-value"
                    }})
                } else {
                    serde_json::json!({})
                }
                .to_string();
                let bundle_path = repo.dir.path().join("bundle.json");
                std::fs::write(&bundle_path, &bundle).unwrap();
                std::fs::create_dir_all(repo.published().parent().unwrap()).unwrap();
                std::fs::write(repo.published(), "existing output must survive").unwrap();
                // All remote requests, including GitHub key discovery and PR
                // delivery, are trapped on loopback. Refusal must send none.
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let endpoint = format!("http://{}", listener.local_addr().unwrap());
                for mode in ["api", "file"] {
                    for args in [
                        vec!["validate"],
                        vec!["validate", "--format", "json"],
                        vec!["validate", "--format", "github-annotations"],
                        vec!["plan"],
                        vec!["diff", "--exit-on-drift"],
                        vec!["review", "--pr", "1"],
                        // No --auto-approve: exercise inspect-only apply too.
                        vec!["apply"],
                        vec!["apply", "--auto-approve"],
                        vec!["export", "--output", "export.yaml"],
                        vec!["export", "--materialize", "--output", "export.yaml"],
                        vec!["export", "--materialize", "--encrypt-to", "fixture"],
                        vec![
                            "rotate",
                            "--consumer",
                            "app",
                            "--credential",
                            "keyauth/key",
                            "--recipient",
                            "fixture",
                        ],
                    ] {
                        let output = repo.run(
                            &args,
                            &[
                                ("FERRUM_GATEWAY_MODE", mode),
                                ("FERRUM_GATEWAY_URL", &endpoint),
                                ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
                                (
                                    "FERRUM_ADMIN_JWT_SECRET",
                                    "synthetic-admin-secret-at-least-32-bytes",
                                ),
                                ("FERRUM_CREDS_JSON_FILE", bundle_path.to_str().unwrap()),
                                ("GITHUB_REPOSITORY", "test/fixture"),
                                ("GITHUB_TOKEN", "synthetic-token"),
                                ("FERRUM_GH_PROVISIONER_TOKEN", "synthetic-token"),
                                ("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", "1"),
                                ("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "1"),
                                ("HTTPS_PROXY", &endpoint),
                                ("HTTP_PROXY", &endpoint),
                                ("ALL_PROXY", &endpoint),
                                ("NO_PROXY", ""),
                            ],
                        );
                        let diagnostic = format!("{}{}", stdout(&output), stderr(&output));
                        assert!(!output.status.success(), "{mode} {args:?}: {diagnostic}");
                        assert!(diagnostic.contains(&slot), "{mode} {args:?}: {diagnostic}");
                        assert!(diagnostic.contains("supplied literally"), "{diagnostic}");
                        assert!(!diagnostic.contains("synthetic-"), "{diagnostic}");
                        assert!(!repo.dir.path().join("validator-ran").exists());
                        assert!(!repo.dir.path().join(".state/default.json").exists());
                        assert!(!repo.dir.path().join("export.yaml").exists());
                        assert_eq!(
                            std::fs::read_to_string(repo.published()).unwrap(),
                            "existing output must survive"
                        );
                        assert_eq!(std::fs::read_to_string(&bundle_path).unwrap(), bundle);
                        assert_eq!(
                            std::fs::read_to_string(
                                repo.dir.path().join("resources/ferrum/consumers/app.yaml")
                            )
                            .unwrap(),
                            consumer
                        );
                        assert_eq!(
                            listener.accept().unwrap_err().kind(),
                            std::io::ErrorKind::WouldBlock,
                            "{mode} {args:?} must refuse before GitHub/gateway traffic"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn literal_identity_cli_diagnostics_remain_readable_with_a_loaded_bundle() {
    for (consumer, identity, bundle) in [
        (BASICAUTH_IDENTITY_CONSUMER, "alice", BASICAUTH_BUNDLE),
        (MTLS_IDENTITY_CONSUMER, "client.example", "{}"),
    ] {
        // Stale, unused identity slots must not make literal identities secret
        // by value association with the bundle. Only substituted slots count.
        let mut bundle: serde_json::Value = serde_json::from_str(bundle).unwrap();
        if bundle.get("FERRUM_CREDS_BUNDLE").is_none() {
            bundle["FERRUM_CREDS_BUNDLE"] = serde_json::json!({});
        }
        let key = if identity == "alice" {
            "ferrum/app/basicauth/username"
        } else {
            "ferrum/app/mtls_auth/identity"
        };
        bundle["FERRUM_CREDS_BUNDLE"][key] = serde_json::json!(identity);
        let bundle = bundle.to_string();
        for mode in ["api", "file"] {
            let repo = Repo::with_consumer(consumer);
            std::fs::write(
                &repo.validator,
                "#!/bin/sh\ntouch validator-ran\ncat \"$7\"\necho 'error: synthetic schema rejection' >&2\ncat \"$7\" >&2\nexit 1\n",
            )
            .unwrap();
            for args in [
                vec!["validate"],
                vec!["plan"],
                vec!["review"],
                vec!["apply", "--auto-approve"],
            ] {
                let output = repo.run(
                    &args,
                    &[
                        ("FERRUM_GATEWAY_MODE", mode),
                        ("FERRUM_CREDS_JSON", &bundle),
                    ],
                );
                let diagnostic = format!("{}{}", stdout(&output), stderr(&output));
                // Ordinary review reports a schema rejection in its comment
                // and only fails the command for a validator execution error.
                if args[0] != "review" {
                    assert!(!output.status.success(), "stub validator must reject");
                }
                assert!(repo.dir.path().join("validator-ran").exists());
                assert!(
                    diagnostic.contains(identity),
                    "{mode} {args:?}: {diagnostic}"
                );
                assert!(
                    diagnostic.contains("synthetic schema rejection"),
                    "{diagnostic}"
                );
                assert!(
                    !diagnostic.contains("hmac_sha256:0123456789abcdef"),
                    "{diagnostic}"
                );
                assert!(!diagnostic.contains("Literal credential"), "{diagnostic}");
                assert!(!repo.published().exists());
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn cli_validator_uses_resolution_provenance_for_every_substituted_leaf() {
    let repo = Repo::with_files(&[
        ("resources/ferrum/consumers/app.yaml", MTLS_IDENTITY_CONSUMER),
        (
            "resources/ferrum/plugins/opaque.yaml",
            "kind: PluginConfig\nspec:\n  id: opaque\n  plugin_name: custom_fixture\n  scope: global\n  config:\n    display_mode: '${gh-env-secret:alloc=require}'\n",
        ),
    ]);
    std::fs::write(
        &repo.validator,
        "#!/bin/sh\ncat \"$7\"\necho 'error: synthetic schema rejection' >&2\ncat \"$7\" >&2\nexit 1\n",
    )
    .unwrap();
    // This value lives in an otherwise nonsensitive field. Only provenance
    // proves it came from the bundle; classifying the resolved field cannot.
    let bundle = r#"{"FERRUM_CREDS_BUNDLE": {
        "ferrum/opaque/@plugin-config/config/display_mode": "synthetic-provenance-only-value"
    }}"#;
    for mode in ["api", "file"] {
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["review"],
            vec!["apply", "--auto-approve"],
        ] {
            if mode == "file" && args[0] == "apply" {
                continue; // File apply validates its unresolved publication document.
            }
            let output = repo.run(
                &args,
                &[("FERRUM_GATEWAY_MODE", mode), ("FERRUM_CREDS_JSON", bundle)],
            );
            let diagnostic = format!("{}{}", stdout(&output), stderr(&output));
            if args[0] != "review" {
                assert!(!output.status.success());
            }
            assert!(
                !diagnostic.contains("synthetic-provenance-only-value"),
                "{diagnostic}"
            );
            assert!(
                diagnostic.contains("[REDACTED]"),
                "{mode} {args:?}: {diagnostic}"
            );
            assert!(diagnostic.contains("client.example"), "{diagnostic}");
            assert!(
                diagnostic.contains("synthetic schema rejection"),
                "{diagnostic}"
            );
            assert!(!repo.published().exists());
        }
    }
}

#[test]
fn supplied_pr_and_revision_cannot_authorize_any_caller_without_evidence() {
    let repo = Repo::with_files(&[
        ("resources/ferrum/consumers/app.yaml", LITERAL_CONSUMER),
        ("resources/ferrum/proxies/app.yaml", HTTP_PROXY),
        (".gitforgeops/policies.yaml", HTTPS_ONLY_POLICY),
    ]);
    let head = "a".repeat(40);
    let context = [
        ("GITFORGEOPS_PR_NUMBER", "7"),
        ("GITHUB_SHA", head.as_str()),
        ("GITHUB_REPOSITORY", "fixture/repo"),
        ("GITFORGEOPS_OVERRIDE_SOURCE", "/unrelated/checkout"),
    ];
    let apply = repo.run(&["apply", "--auto-approve"], &context);
    assert!(!apply.status.success());
    assert!(stderr(&apply).contains("unresolved security findings"));
    assert!(!repo.published().exists());
    assert!(!repo.dir.path().join(".state/default.json").exists());
    let plan = repo.run(&["plan"], &context);
    assert!(!plan.status.success());
    assert!(stdout(&plan).contains("Apply Blockers"));
    let review = repo.run(&["review", "--pr", "7"], &context);
    assert!(stdout(&review).contains("Apply is blocked"));
    assert!(stdout(&review).contains("backend_scheme"));
    assert!(!stdout(&review).contains("OVERRIDDEN by"));
    assert!(!repo.published().exists());
    assert!(!repo.dir.path().join(".state/default.json").exists());
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

#[cfg(unix)]
#[test]
fn file_apply_standins_validate_the_publication_document_not_the_resolved_report() {
    let consumer = "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials:\n    jwt:\n      - secret: '${gh-env-secret:alloc=require}'\n";
    let plugin = "kind: PluginConfig\nspec:\n  id: ldap\n  plugin_name: ldap_auth\n  scope: global\n  config:\n    ldap_url: '${gh-env-secret:alloc=require}'\n";
    let bundle = r#"{"FERRUM_CREDS_BUNDLE": {
        "ferrum/app/jwt/secret": "${gh-env-secret:alloc=require}",
        "ferrum/ldap/@plugin-config/config/ldap_url": "${gh-env-secret:alloc=require}"
    }}"#;
    let repo = Repo::with_files(&[
        ("resources/ferrum/consumers/app.yaml", consumer),
        ("resources/ferrum/plugins/ldap.yaml", plugin),
    ]);
    std::fs::write(
        &repo.validator,
        r#"#!/bin/sh
cp "$7" validator-input.yaml || exit 2
secret=$(sed -n 's/.*secret: *//p' "$7" | tr -d '"' | tr -d "'")
url=$(sed -n 's/.*ldap_url: *//p' "$7" | tr -d '"' | tr -d "'")
if [ "${#secret}" -lt 32 ]; then
  echo 'error: jwt secret too short' >&2
  exit 1
fi
case "$url" in
  ldaps://?*) exit 0 ;;
  *) echo 'error: ldap_url invalid' >&2; exit 1 ;;
esac
"#,
    )
    .unwrap();
    // Validate uses the resolved snapshot even in file mode, so the actual
    // placeholder-shaped bundle value must fail the validator's shape check.
    let validation = repo.run(&["validate"], &[("FERRUM_CREDS_JSON", bundle)]);
    assert!(!validation.status.success());
    assert!(stdout(&validation).contains("jwt secret too short"));
    let captured = std::fs::read_to_string(repo.dir.path().join("validator-input.yaml")).unwrap();
    assert!(captured.contains("${gh-env-secret:alloc=require}"));
    assert!(!captured.contains("gitforgeops-validation-standin"));
    assert!(!repo.published().exists());

    let apply = repo.run(
        &["apply", "--auto-approve"],
        &[("FERRUM_CREDS_JSON", bundle)],
    );
    assert!(
        apply.status.success(),
        "{}{}",
        stdout(&apply),
        stderr(&apply)
    );
    let captured = std::fs::read_to_string(repo.dir.path().join("validator-input.yaml")).unwrap();
    assert!(captured.contains("secret: gitforgeops-validation-standin-"));
    assert!(captured.contains("ldap_url: ldaps://gitforgeops-validation-standin.invalid/"));
    assert!(!captured.contains("${gh-env-secret:"));
    let published = std::fs::read_to_string(repo.published()).unwrap();
    assert!(published.contains("${gh-env-secret:alloc=require}"));
    assert!(!published.contains("gitforgeops-validation-standin"));
    assert_eq!(
        std::fs::read_to_string(repo.dir.path().join("resources/ferrum/consumers/app.yaml"))
            .unwrap(),
        consumer
    );
    assert_eq!(
        std::fs::read_to_string(repo.dir.path().join("resources/ferrum/plugins/ldap.yaml"))
            .unwrap(),
        plugin
    );
}

#[test]
fn placeholder_lookalikes_are_refused_before_file_or_api_publication() {
    for value in [
        "${{ secrets.SYNTHETIC_KEY }}",
        "${gh-env-secret:alloc=generate} ",
        "${gh-env-secret:alloc=generate",
        "${GH-ENV-SECRET:alloc=generate}",
        "${env:SYNTHETIC_KEY}",
        "${gh-env-secret:alloc=synthetic-secret}",
        "${gh-env-secret:len=synthetic-secret}",
        "${gh-env-secret:synthetic-secret}",
        "${gh-env-secret:synthetic-secret=value}",
    ] {
        let consumer = BROKERED_CONSUMER.replace("${gh-env-secret:alloc=require}", value);
        for args in [vec!["plan"], vec!["apply", "--auto-approve"]] {
            let repo = Repo::with_consumer(&consumer);
            let output = repo.run(&args, &[]);
            assert!(!output.status.success());
            let diagnostics = format!("{}{}", stdout(&output), stderr(&output));
            assert!(!diagnostics.contains(value), "{diagnostics}");
            assert!(!diagnostics.contains("synthetic-secret"), "{diagnostics}");
            assert!(!repo.published().exists());
        }

        // The security gate precedes every gateway call. Keep a listener open
        // and verify the CLI never even connects, rather than merely checking
        // that a failed API response prevented a write.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let repo = Repo::with_consumer(&consumer);
        let output = repo.run(
            &["apply", "--auto-approve"],
            &[
                ("FERRUM_GATEWAY_MODE", "api"),
                ("FERRUM_GATEWAY_URL", &url),
                ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
                (
                    "FERRUM_ADMIN_JWT_SECRET",
                    "synthetic-admin-signing-key-at-least-32-bytes",
                ),
                ("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "1"),
                ("FERRUM_GATEWAY_MAX_RETRIES", "0"),
            ],
        );
        assert!(!output.status.success());
        let diagnostics = format!("{}{}", stdout(&output), stderr(&output));
        assert!(diagnostics.contains("Literal credential"), "{diagnostics}");
        assert!(!diagnostics.contains(value), "{diagnostics}");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn plan_and_apply_refuse_literal_plugin_secrets_without_publication() {
    const PLUGIN: &str = r#"kind: PluginConfig
spec:
  id: "otel"
  plugin_name: "otel_tracing"
  scope: global
  config:
    authorization: "Bearer synthetic-plugin-value"
"#;
    for args in [vec!["plan"], vec!["apply", "--auto-approve"]] {
        let repo = Repo::with_files(&[("resources/ferrum/plugins/otel.yaml", PLUGIN)]);
        let output = repo.run(&args, &[]);
        assert!(!output.status.success());
        let diagnostics = format!("{}{}", stdout(&output), stderr(&output));
        assert!(diagnostics.contains("Literal plugin-config secret"));
        assert!(diagnostics.contains("config.authorization"));
        assert!(!diagnostics.contains("synthetic-plugin-value"));
        assert!(!repo.published().exists());
    }
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

#[test]
fn plan_exits_nonzero_on_a_blocking_policy_violation() {
    // Issue-130 reproduction 1: an error-severity policy rule fires, apply
    // refuses, and plan used to print the finding and exit 0.
    let repo = Repo::with_files(&[
        ("resources/ferrum/proxies/app.yaml", HTTP_PROXY),
        (".gitforgeops/policies.yaml", HTTPS_ONLY_POLICY),
    ]);

    let planned = repo.run(&["plan"], &[]);

    assert!(
        !planned.status.success(),
        "plan must refuse what apply refuses; stdout={} stderr={}",
        stdout(&planned),
        stderr(&planned)
    );
    let out = stdout(&planned);
    assert!(
        out.contains("Policy Violations") && out.contains("backend_scheme"),
        "the violation must still be printed: {out}"
    );
    assert!(
        out.contains("Apply Blockers") && out.contains("policy (1)"),
        "the verdict must name the blocker class and its count: {out}"
    );
    assert!(
        out.contains("apply is blocked by 1 class(es)"),
        "plan must print the summary line: {out}"
    );

    // And apply agrees, which is the property the shared computation exists
    // to keep true.
    let applied = repo.run(&["apply", "--auto-approve"], &[]);
    assert!(
        !applied.status.success(),
        "stdout={} stderr={}",
        stdout(&applied),
        stderr(&applied)
    );
    assert!(
        stderr(&applied).contains("unresolved policy violation"),
        "{}",
        stderr(&applied)
    );
}

#[test]
fn plan_exits_zero_for_a_warning_only_policy_and_for_a_satisfied_one() {
    // Warning severity never blocks apply, so it must never block plan.
    let warned = Repo::with_files(&[
        ("resources/ferrum/proxies/app.yaml", HTTP_PROXY),
        (".gitforgeops/policies.yaml", HTTPS_ONLY_POLICY_WARNING),
    ]);
    let output = warned.run(&["plan"], &[]);
    assert!(
        output.status.success(),
        "a warning is advisory; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("backend_scheme"),
        "the advisory must still be rendered: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("Apply Blockers"),
        "nothing blocks, so no blocker section: {}",
        stdout(&output)
    );

    // The same error-severity rule, satisfied.
    let satisfied = Repo::with_files(&[
        ("resources/ferrum/proxies/app.yaml", HTTPS_PROXY),
        (".gitforgeops/policies.yaml", HTTPS_ONLY_POLICY),
    ]);
    let output = satisfied.run(&["plan"], &[]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn plan_exits_nonzero_when_a_required_credential_slot_has_no_value() {
    // Issue-130 reproduction 2: `alloc=require` with an empty bundle. Apply
    // refuses before touching the gateway; plan printed `[MISSING (required)]`
    // and exited 0.
    let repo = Repo::with_consumer(BROKERED_CONSUMER);

    let planned = repo.run(&["plan"], &[]);

    assert!(
        !planned.status.success(),
        "plan must refuse a missing required slot; stdout={} stderr={}",
        stdout(&planned),
        stderr(&planned)
    );
    let out = stdout(&planned);
    assert!(
        out.contains("[MISSING (required)] ferrum/app/keyauth/key"),
        "the slot must still be named: {out}"
    );
    assert!(
        out.contains("required-credentials (1)"),
        "the verdict must name the blocker class: {out}"
    );

    // Apply agrees.
    let applied = repo.run(&["apply", "--auto-approve"], &[]);
    assert!(!applied.status.success());
    assert!(
        stderr(&applied).contains("required credential slots are missing"),
        "{}",
        stderr(&applied)
    );

    // Seeded, the same repository plans clean — the control that keeps this
    // from being satisfied by "plan always fails".
    let seeded = repo.run(&["plan"], &[("FERRUM_CREDS_JSON", BUNDLE)]);
    assert!(
        seeded.status.success(),
        "stdout={} stderr={}",
        stdout(&seeded),
        stderr(&seeded)
    );
}

#[test]
fn a_slot_pending_generation_is_not_an_apply_blocker() {
    // `alloc=generate` with an empty bundle is ordinary first-apply work the
    // allocator performs. Confusing it with `alloc=require` would make every
    // brand-new credential fail its own plan.
    let repo = Repo::with_consumer(
        r#"kind: Consumer
spec:
  id: "app"
  username: "app"
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=generate}"
"#,
    );

    let output = repo.run(
        &["plan"],
        &[
            ("FERRUM_GH_PROVISIONER_TOKEN", "synthetic-provisioner"),
            ("GITHUB_REPOSITORY", "example/repository"),
        ],
    );

    assert!(
        output.status.success(),
        "pending generation is not a blocker; stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stdout(&output).contains("[needs-allocation] ferrum/app/keyauth/key"),
        "the pending slot must still be shown: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("Apply Blockers"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn offline_commands_enforce_exclusive_ownership_before_validation_or_export() {
    for (mode, owned, filter, expected_error) in [
        ("exclusive", "[ferrum]", None, Some("outside that list")),
        (
            "exclusive",
            "[ferrum]",
            Some("platform"),
            Some("namespace_filter 'platform'"),
        ),
        ("exclusive", "[ferrum, platform]", None, None),
        ("shared", "[ferrum]", None, None),
    ] {
        let config = format!(
            "version: 1\ndefault_environment: production\nenvironments:\n  production:\n    overlay: staging\n    ownership:\n      mode: {mode}\n      namespaces: {owned}\n"
        );
        let other_proxy = HTTPS_PROXY.replace("app", "other");
        let repo = Repo::with_files(&[
            (".gitforgeops/config.yaml", &config),
            ("resources/ferrum/proxies/app.yaml", HTTPS_PROXY),
            ("resources/platform/proxies/other.yaml", &other_proxy),
        ]);
        std::fs::create_dir_all(repo.dir.path().join("overlays/staging")).unwrap();
        std::fs::write(&repo.validator, "#!/bin/sh\ntouch validator-ran\nexit 0\n").unwrap();
        let marker = repo.dir.path().join("validator-ran");
        let artifact = repo.dir.path().join("export.yaml");
        for args in [
            vec!["validate"],
            vec!["export", "--output", "export.yaml"],
            vec!["export", "--materialize", "--output", "export.yaml"],
        ] {
            std::fs::write(&artifact, "existing artifact").unwrap();
            let mut env = Vec::new();
            if let Some(filter) = filter {
                env.push(("FERRUM_NAMESPACE", filter));
            }
            if expected_error.is_some() {
                // Scope rejection must happen before credential parsing too.
                env.push(("FERRUM_CREDS_JSON", "not valid JSON"));
            }
            let output = repo.run(&args, &env);
            assert_eq!(
                output.status.success(),
                expected_error.is_none(),
                "{mode} {owned} {filter:?} {args:?}: {} {}",
                stdout(&output),
                stderr(&output)
            );
            if let Some(expected) = expected_error {
                assert!(stderr(&output).contains(expected), "{}", stderr(&output));
                assert!(!marker.exists(), "scope rejection must precede validation");
                assert_eq!(
                    std::fs::read_to_string(&artifact).unwrap(),
                    "existing artifact"
                );
            } else if args[0] == "export" {
                let exported = std::fs::read_to_string(&artifact).unwrap();
                assert!(exported.contains("platform"));
                assert!(exported.contains("ferrum"));
            } else {
                assert!(marker.exists(), "valid scope must reach the validator");
            }
        }
    }
}

#[test]
fn empty_enabled_allowlists_block_plan_and_apply_before_publication() {
    for (rule, key) in [
        ("backend_scheme", "allowed_protocols"),
        ("allowed_proxy_plugins", "allowed_plugin_names"),
        ("require_ai_guardrails", "guardrail_plugin_names"),
    ] {
        let policy = format!(
            "version: 1\npolicies:\n  {rule}:\n    enabled: true\n    severity: warning\n    {key}: []\n"
        );
        for args in [vec!["plan"], vec!["apply", "--auto-approve"]] {
            let repo = Repo::with_files(&[
                ("resources/ferrum/proxies/app.yaml", HTTPS_PROXY),
                (".gitforgeops/policies.yaml", &policy),
            ]);
            let output = repo.run(&args, &[]);
            assert!(!output.status.success());
            let diagnostics = format!("{}{}", stdout(&output), stderr(&output));
            assert!(diagnostics.contains(key), "{diagnostics}");
            assert!(diagnostics.contains("no nonblank"), "{diagnostics}");
            assert!(!repo.published().exists());
            assert!(!repo.dir.path().join(".state/default.json").exists());
        }
    }
}

const SCOPE_MESH: &str = "kind: MeshConfig\nspec:\n  istio_root_namespace: mesh-root\n";
const OTHER_SCOPE_MESH: &str = "kind: MeshConfig\nid: outside-fragment\nspec: {}\n";
const SCOPE_OVERLAY: &str =
    "kind: MeshConfig\nid: outside-fragment\nspec:\n  outbound_traffic_policy:\n    mode: ALLOW_ANY\n";

fn mesh_scope_repo(mode: &str, owned: &str, filter: Option<&str>) -> Repo {
    let filter = filter
        .map(|filter| format!("    namespace_filter: {filter}\n"))
        .unwrap_or_default();
    let config = format!(
        "version: 1\ndefault_environment: production\nenvironments:\n  production:\n    overlay: staging\n{filter}    ownership:\n      mode: {mode}\n      namespaces: {owned}\n"
    );
    let repo = Repo::with_files(&[
        (".gitforgeops/config.yaml", &config),
        ("resources/ferrum/proxies/app.yaml", HTTPS_PROXY),
        ("resources/ferrum/mesh/core.yaml", SCOPE_MESH),
        ("resources/platform/mesh/extra.yaml", OTHER_SCOPE_MESH),
        ("overlays/staging/platform/mesh/extra.yaml", SCOPE_OVERLAY),
    ]);
    std::fs::write(&repo.validator, "#!/bin/sh\ntouch validator-ran\nexit 0\n").unwrap();
    repo
}

#[test]
fn mesh_scope_refusal_precedes_command_side_effects() {
    for args in [
        vec!["validate"],
        vec!["plan"],
        vec!["review", "--pr", "160", "--require-live"],
        vec!["diff"],
        vec!["export", "--output", "export.yaml"],
        vec!["export", "--materialize", "--output", "export.yaml"],
        vec!["apply", "--auto-approve"],
    ] {
        for existing in [false, true] {
            let repo = mesh_scope_repo("exclusive", "[ferrum]", None);
            let paths = [
                repo.published(),
                repo.dir.path().join("mesh.yaml"),
                repo.dir.path().join("export.yaml"),
                repo.dir.path().join(".state/production.json"),
            ];
            if existing {
                for path in &paths {
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, "unchanged sentinel").unwrap();
                }
            }
            let output = repo.run(
                &args,
                &[
                    ("FERRUM_MESH_FILE_OUTPUT_PATH", "mesh.yaml"),
                    ("FERRUM_CREDS_JSON", "invalid bundle: must not be read"),
                ],
            );
            let error = stderr(&output);
            assert!(!output.status.success(), "{args:?}: {error}");
            assert!(error.contains("ownership.namespaces"), "{error}");
            assert!(error.contains("namespace 'platform'"), "{error}");
            assert!(error.contains("platform/mesh/outside-fragment"), "{error}");
            assert!(!repo.dir.path().join("validator-ran").exists());
            for path in &paths {
                if existing {
                    assert_eq!(std::fs::read_to_string(path).unwrap(), "unchanged sentinel");
                } else {
                    assert!(!path.exists(), "{}", path.display());
                }
            }
            assert!(!repo.dir.path().join(".state/production.lock").exists());
        }
    }
}

#[test]
fn mesh_scope_preserves_shared_owned_and_filtered_publication() {
    for (mode, owned, repo_filter, env_filter, includes_platform) in [
        ("exclusive", "[ferrum, platform]", None, None, true),
        ("shared", "[ferrum]", None, None, true),
        ("exclusive", "[ferrum]", Some("ferrum"), None, false),
        ("exclusive", "[ferrum]", None, Some("ferrum"), false),
        ("shared", "[ferrum]", None, Some("ferrum"), false),
    ] {
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["export", "--output", "export.yaml"],
            vec!["export", "--materialize", "--output", "export.yaml"],
            vec!["apply", "--auto-approve"],
        ] {
            let repo = mesh_scope_repo(mode, owned, repo_filter);
            let mut env = vec![("FERRUM_MESH_FILE_OUTPUT_PATH", "mesh.yaml")];
            if let Some(filter) = env_filter {
                env.push(("FERRUM_NAMESPACE", filter));
            }
            let output = repo.run(&args, &env);
            assert!(
                output.status.success(),
                "{mode} {owned} {repo_filter:?} {env_filter:?} {args:?}: {} {}",
                stdout(&output),
                stderr(&output)
            );
            if matches!(args[0], "export" | "apply") {
                let mesh = std::fs::read_to_string(repo.dir.path().join("mesh.yaml")).unwrap();
                assert!(mesh.contains("mesh-root"), "{mesh}");
                assert_eq!(mesh.contains("ALLOW_ANY"), includes_platform, "{mesh}");
            } else {
                assert!(repo.dir.path().join("validator-ran").exists());
            }
        }
    }
}

#[test]
fn mesh_scope_rejects_unowned_filters_even_for_an_empty_selection() {
    for filter_in_config in [false, true] {
        let repo = mesh_scope_repo(
            "exclusive",
            "[ferrum]",
            filter_in_config.then_some("missing"),
        );
        let mut env = vec![("FERRUM_MESH_FILE_OUTPUT_PATH", "mesh.yaml")];
        if !filter_in_config {
            env.push(("FERRUM_NAMESPACE", "missing"));
        }
        let output = repo.run(&["export", "--output", "export.yaml"], &env);
        assert!(!output.status.success());
        assert!(stderr(&output).contains("namespace_filter 'missing'"));
        assert!(!repo.dir.path().join("mesh.yaml").exists());
        assert!(!repo.dir.path().join("export.yaml").exists());
    }
}

#[test]
fn mesh_scope_refusal_precedes_admin_api_connections() {
    for args in [
        vec!["plan"],
        vec!["diff"],
        vec!["review", "--pr", "160", "--require-live"],
        vec!["apply", "--auto-approve"],
    ] {
        let repo = mesh_scope_repo("exclusive", "[ferrum]", None);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let output = repo.run(
            &args,
            &[
                ("FERRUM_GATEWAY_MODE", "api"),
                ("FERRUM_GATEWAY_URL", &url),
                ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
                (
                    "FERRUM_ADMIN_JWT_SECRET",
                    "synthetic-scope-test-signing-key",
                ),
                ("FERRUM_GATEWAY_REQUEST_TIMEOUT_SECS", "1"),
                ("FERRUM_GATEWAY_MAX_RETRIES", "0"),
            ],
        );
        assert!(!output.status.success());
        let stderr = stderr(&output);
        assert!(
            stderr.contains("platform/mesh/outside-fragment"),
            "{stderr}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!repo.dir.path().join("validator-ran").exists());
        assert!(!repo.dir.path().join(".state").exists());
    }
}

#[test]
fn rotate_namespace_selection_respects_resolved_scope_and_explicit_precedence() {
    for (configured, environment, explicit, expected) in [
        (None, None, None, "ferrum"),
        (Some("platform"), None, None, "platform"),
        (None, Some("platform"), None, "platform"),
        (Some("platform"), Some("operations"), None, "platform"),
        (Some("platform"), None, Some("explicit"), "explicit"),
        (None, Some("platform"), Some("explicit"), "explicit"),
    ] {
        let scope = configured
            .map(|namespace| format!("    namespace_filter: {namespace}\n"))
            .unwrap_or_default();
        let config = format!(
            "version: 1\ndefault_environment: production\nenvironments:\n  production:\n    overlay: staging\n{scope}"
        );
        let repo = Repo::with_files(&[
            (".gitforgeops/config.yaml", &config),
            ("resources/ferrum/proxies/app.yaml", HTTPS_PROXY),
        ]);
        std::fs::create_dir_all(repo.dir.path().join("overlays/staging")).unwrap();
        let mut args = vec![
            "rotate",
            "--consumer",
            "missing-consumer",
            "--credential",
            "keyauth/key",
        ];
        if let Some(namespace) = explicit {
            args.extend(["--namespace", namespace]);
        }
        let mut env = vec![
            ("FERRUM_GATEWAY_MODE", "api"),
            ("GITHUB_REPOSITORY", "test/fixture"),
            ("FERRUM_GH_PROVISIONER_TOKEN", "unused-test-token"),
            ("FERRUM_CREDS_JSON", "{}"),
        ];
        if let Some(namespace) = environment {
            env.push(("FERRUM_NAMESPACE", namespace));
        }
        // No consumer or placeholder exists, so preflight must refuse before
        // any provisioning, credential delivery, or gateway request.
        let output = repo.run(&args, &env);
        assert!(!output.status.success());
        let diagnostic = stderr(&output);
        assert!(
            diagnostic.contains(&format!("slot '{expected}/missing-consumer/keyauth/key'")),
            "{configured:?} {environment:?} {explicit:?}: {diagnostic}"
        );
        assert!(!repo.published().exists());
    }
}

#[test]
fn rotate_checks_target_generation_before_any_network_or_state_publication() {
    // The Upstream and PluginConfig deliberately share the Consumer id.
    // An HTTPS proxy trap catches all GitHub traffic, including key discovery;
    // the gateway uses the same loopback listener. Nothing reaches production.
    for (credential, credentials, expected) in [
        (
            "@service-discovery/consul/token",
            r#"{"keyauth":[{"key":"${gh-env-secret:alloc=require}"}]}"#,
            "Consul ACL token",
        ),
        (
            "@plugin-config/config/api_key",
            r#"{"keyauth":[{"key":"${gh-env-secret:alloc=require}"}]}"#,
            "PluginConfig and Upstream slots cannot be published",
        ),
        (
            "basicauth/password_hash",
            r#"{"basicauth":[{"username":"app","password_hash":"${gh-env-secret:alloc=require}"}]}"#,
            "cannot generate a basicauth password_hash",
        ),
        (
            "basicauth/[1]/password_hash",
            r#"{"basicauth":[{"username":"one","password_hash":"${gh-env-secret:alloc=require}"},{"username":"two","password_hash":"${gh-env-secret:alloc=require}"}]}"#,
            "cannot generate a basicauth password_hash",
        ),
        (
            "jwt/secret",
            r#"{"jwt":[{"secret":"${gh-env-secret:alloc=require|len=16}"}]}"#,
            "at least 32 characters",
        ),
        (
            "keyauth/key",
            r#"{"keyauth":[{"key":"literal-value"}]}"#,
            "no `${gh-env-secret:...}` placeholder",
        ),
        (
            "mtls_auth/identity",
            r#"{"mtls_auth":[{"identity":"${gh-env-secret:alloc=require}"}]}"#,
            "identity fields",
        ),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let consumer = format!(
            "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials: {credentials}\n"
        );
        let repo = Repo::with_files(&[
            ("resources/platform/consumers/app.yaml", &consumer),
            (
                "resources/platform/upstreams/app.yaml",
                "kind: Upstream\nspec:\n  id: app\n  targets: []\n  service_discovery:\n    provider: consul\n    consul:\n      address: https://consul.invalid\n      service_name: orders\n      token: '${gh-env-secret:alloc=require}'\n",
            ),
            (
                "resources/platform/plugins/app.yaml",
                "kind: PluginConfig\nspec:\n  id: app\n  plugin_name: custom\n  scope: global\n  config:\n    api_key: '${gh-env-secret:alloc=require}'\n",
            ),
        ]);
        let bundle = serde_json::json!({
            "FERRUM_CREDS_BUNDLE": {
                format!("platform/app/{credential}"): "existing-sensitive-value"
            }
        })
        .to_string();
        let bundle_path = repo.dir.path().join("bundle.json");
        std::fs::write(&bundle_path, &bundle).unwrap();
        let output = repo.run(
            &[
                "rotate",
                "--consumer",
                "app",
                "--credential",
                credential,
                "--recipient",
                "recipient",
            ],
            &[
                ("FERRUM_GATEWAY_MODE", "api"),
                ("FERRUM_NAMESPACE", "platform"),
                ("FERRUM_GATEWAY_URL", &endpoint),
                ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
                (
                    "FERRUM_ADMIN_JWT_SECRET",
                    "synthetic-admin-secret-at-least-32-bytes",
                ),
                ("GITHUB_REPOSITORY", "test/fixture"),
                ("FERRUM_GH_PROVISIONER_TOKEN", "synthetic-token"),
                ("FERRUM_CREDS_JSON_FILE", bundle_path.to_str().unwrap()),
                ("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", "1"),
                ("HTTPS_PROXY", &endpoint),
                ("HTTP_PROXY", &endpoint),
                ("ALL_PROXY", &endpoint),
                ("NO_PROXY", ""),
            ],
        );
        let diagnostic = stderr(&output);
        assert!(!output.status.success(), "{credential}");
        assert!(diagnostic.contains(expected), "{credential}: {diagnostic}");
        assert!(diagnostic.contains("platform/app/"), "{diagnostic}");
        assert!(!diagnostic.contains("existing-sensitive-value"));
        assert!(!stdout(&output).contains("existing-sensitive-value"));
        assert_eq!(std::fs::read_to_string(bundle_path).unwrap(), bundle);
        assert!(!repo.published().exists());
        assert!(!repo.dir.path().join(".state/default.json").exists());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "refusal must precede every GitHub/gateway request"
        );
    }
}

#[test]
fn rotate_supported_credentials_in_resolved_namespace_reach_provisioning() {
    // Positive controls end at the local proxy, before any secret write.
    // An unrelated invalid JWT must not block this Consumer's preflight.
    for (kind, field) in [
        ("keyauth", "key"),
        ("jwt", "secret"),
        ("hmac_auth", "secret"),
        ("basicauth", "password"),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let credential = format!("{kind}/[1]/{field}");
        let consumer = format!(
            "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials:\n    {kind}:\n      - {field}: existing-sibling-value\n        username: first\n      - {field}: '${{gh-env-secret:alloc=require}}'\n        username: second\n"
        );
        let repo = Repo::with_files(&[
            ("resources/platform/consumers/app.yaml", &consumer),
            (
                "resources/platform/consumers/unrelated.yaml",
                "kind: Consumer\nspec:\n  id: unrelated\n  username: unrelated\n  credentials:\n    jwt:\n      - secret: '${gh-env-secret:alloc=generate|len=16}'\n",
            ),
        ]);
        let output = repo.run(
            &["rotate", "--consumer", "app", "--credential", &credential],
            &[
                ("FERRUM_GATEWAY_MODE", "api"),
                ("FERRUM_NAMESPACE", "platform"),
                ("FERRUM_GATEWAY_URL", &endpoint),
                ("FERRUM_ALLOW_INSECURE_HTTP", "true"),
                (
                    "FERRUM_ADMIN_JWT_SECRET",
                    "synthetic-admin-secret-at-least-32-bytes",
                ),
                ("GITHUB_REPOSITORY", "test/fixture"),
                ("FERRUM_GH_PROVISIONER_TOKEN", "synthetic-token"),
                ("FERRUM_CREDS_JSON", "{}"),
                ("FERRUM_GITHUB_REQUEST_TIMEOUT_SECS", "1"),
                ("HTTPS_PROXY", &endpoint),
                ("HTTP_PROXY", &endpoint),
                ("ALL_PROXY", &endpoint),
                ("NO_PROXY", ""),
            ],
        );
        assert!(
            !output.status.success(),
            "the proxy deliberately never responds"
        );
        assert!(
            listener.accept().is_ok(),
            "{credential} must reach provisioning in platform: {}",
            stderr(&output)
        );
        assert!(!repo.dir.path().join(".state/default.json").exists());
    }
}

#[test]
fn pending_allocation_requires_provisioning_environment_in_plan_and_review() {
    let consumer = BROKERED_CONSUMER.replace("alloc=require", "alloc=generate");
    let repo = Repo::with_consumer(&consumer);
    for token_present in [false, true] {
        for repository_present in [false, true] {
            let mut env = Vec::new();
            if token_present {
                env.push(("FERRUM_GH_PROVISIONER_TOKEN", "synthetic-provisioner"));
            }
            if repository_present {
                env.push(("GITHUB_REPOSITORY", "example/repository"));
            }
            for command in ["plan", "review"] {
                let output = repo.run(&[command], &env);
                let out = stdout(&output);
                assert_eq!(
                    output.status.success(),
                    token_present && repository_present,
                    "{command}: {out} {}",
                    stderr(&output)
                );
                assert_eq!(out.contains("provisioner-token"), !token_present, "{out}");
                assert_eq!(
                    out.contains("provisioning-repository"),
                    !repository_present,
                    "{out}"
                );
            }
            if !token_present || !repository_present {
                let output = repo.run(&["apply", "--auto-approve"], &env);
                assert!(!output.status.success());
                let expected = if token_present {
                    "GITHUB_REPOSITORY not set; cannot write to GitHub Environment Secrets"
                } else {
                    "FERRUM_GH_PROVISIONER_TOKEN not set; cannot allocate credential slots"
                };
                assert!(stderr(&output).contains(expected), "{}", stderr(&output));
            }
            assert!(!repo.published().exists());
            assert!(!repo.dir.path().join(".state/default.json").exists());
        }
    }
    let seeded = repo.run(&["plan"], &[("FERRUM_CREDS_JSON", BUNDLE)]);
    assert!(seeded.status.success(), "{}", stdout(&seeded));
    assert!(!stdout(&seeded).contains("Apply Blockers"));
}
