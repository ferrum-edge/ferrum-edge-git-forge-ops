//! Offline refusals `validate`, `plan` and `apply` share before any
//! publication, state write or broker write.
//!
//! * The gateway and mesh documents must be published to distinct files. A
//!   file-mode apply writes one and then the other, so a shared destination —
//!   however it is spelled — keeps only the last write while the ledger records
//!   the gateway rows as applied.
//! * `.gitforgeops/smoke.yaml` is read by `verify` only after `apply` changed
//!   the gateway, so a malformed check must fail the preview commands and
//!   refuse `apply` before it mutates anything.
//!
//! `review` reports both as offline apply blockers instead: the comment is
//! still produced, default `review` exits 0, and `review --fail-on-blockers`
//! exits 1 exactly as `plan` does.
//!
//! The CLI cases run the real binary hermetically in file mode against a stub
//! validator; no gateway is involved.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gitforgeops::apply::ensure_distinct_publication_paths;
use tempfile::TempDir;

const PROXY: &str = r#"kind: Proxy
spec:
  id: "api"
  listen_path: "/api"
  backend_scheme: https
  backend_host: "api.internal"
  backend_port: 443
"#;

const CONDITIONAL_AUTH_PROXY: &str = r#"kind: Proxy
spec:
  id: "api"
  listen_path: "/api"
  backend_scheme: https
  backend_host: "api.internal"
  backend_port: 443
  plugins:
    - plugin_config_id: conditional-key-auth
"#;

const CONDITIONAL_AUTH_PLUGIN: &str = r#"kind: PluginConfig
spec:
  id: conditional-key-auth
  plugin_name: key_auth
  scope: proxy
  proxy_id: api
  trigger:
    when:
      match:
        method: [POST]
"#;

const REQUIRE_AUTH_POLICY: &str = r#"version: 1
policies:
  require_auth_plugin:
    enabled: true
    severity: error
"#;

const MESH_FRAGMENT: &str = r#"kind: MeshConfig
spec:
  istio_root_namespace: istio-system
  workloads:
    - spiffe_id: spiffe://cluster.local/ns/ferrum/sa/api
      service_name: api
      namespace: ferrum
      trust_domain: cluster.local
      selector:
        static: api
"#;

const SENTINEL: &str = "unchanged sentinel\n";

// -- path identity ----------------------------------------------------------

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf-8 temp path")
}

#[test]
fn identical_destinations_are_refused() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("assembled/out.yaml");

    let error = ensure_distinct_publication_paths(path_str(&target), path_str(&target))
        .expect_err("identical destinations");

    assert!(
        error.to_string().contains("resolve to the same file"),
        "{error}"
    );
    assert!(!target.exists(), "the check published something");
}

#[test]
fn equivalent_spellings_of_one_destination_are_refused() {
    let dir = TempDir::new().unwrap();
    let plain = dir.path().join("assembled/out.yaml");
    let dotted = dir.path().join("assembled/./missing/../out.yaml");

    for (gateway, mesh) in [(&plain, &dotted), (&dotted, &plain)] {
        let error = ensure_distinct_publication_paths(path_str(gateway), path_str(mesh))
            .expect_err("equivalent spellings");
        assert!(
            error.to_string().contains("resolve to the same file"),
            "{error}"
        );
    }
    assert!(!dir.path().join("assembled").exists());
}

#[cfg(unix)]
#[test]
fn destinations_aliased_through_a_symlinked_parent_are_refused() {
    let dir = TempDir::new().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    for existing in [false, true] {
        if existing {
            std::fs::write(real.join("out.yaml"), SENTINEL).unwrap();
        }
        let error = ensure_distinct_publication_paths(
            path_str(&real.join("out.yaml")),
            path_str(&link.join("out.yaml")),
        )
        .expect_err("symlinked parent");
        assert!(
            error.to_string().contains("resolve to the same file"),
            "{error}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(real.join("out.yaml")).unwrap(),
        SENTINEL
    );
}

#[test]
fn distinct_destinations_are_accepted() {
    let dir = TempDir::new().unwrap();
    let gateway = dir.path().join("assembled/resources.yaml");
    let mesh = dir.path().join("assembled/mesh.yaml");
    ensure_distinct_publication_paths(path_str(&gateway), path_str(&mesh))
        .expect("distinct destinations");

    // Same file name, different directories.
    let other = dir.path().join("other/resources.yaml");
    ensure_distinct_publication_paths(path_str(&gateway), path_str(&other))
        .expect("same name in another directory");
}

// -- CLI --------------------------------------------------------------------

struct Repo {
    dir: TempDir,
    validator: PathBuf,
}

impl Repo {
    fn new(smoke: Option<&str>) -> Self {
        Self::with_files(smoke, &[])
    }

    fn with_files(smoke: Option<&str>, extra: &[(&str, &str)]) -> Self {
        let dir = TempDir::new().expect("repo tempdir");
        let mut files = vec![
            ("resources/ferrum/proxies/api.yaml", PROXY),
            ("resources/ferrum/mesh/core.yaml", MESH_FRAGMENT),
        ];
        files.extend_from_slice(extra);
        if let Some(smoke) = smoke {
            files.push((".gitforgeops/smoke.yaml", smoke));
        }
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).expect("fixture dir");
            std::fs::write(&path, contents).expect("fixture file");
        }
        let validator = dir.path().join("ferrum-edge-stub");
        std::fs::write(&validator, "#!/bin/sh\nexit 0\n").expect("stub");
        set_executable(&validator);
        Self { dir, validator }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    /// Hermetic: only PATH/HOME/TMPDIR and the variables named here reach the
    /// child, so an ambient `FERRUM_GATEWAY_URL` cannot turn this into a live
    /// run.
    fn run(&self, args: &[&str], gateway: &str, mesh: &str) -> Output {
        self.run_with(args, gateway, mesh, &[])
    }

    /// [`Repo::run`] with `vars` set, such as the operator's
    /// `FERRUM_VERIFY_PROBE_CONSUMERS`.
    fn run_with(&self, args: &[&str], gateway: &str, mesh: &str, vars: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
        command.args(args).current_dir(self.dir.path()).env_clear();
        for name in ["PATH", "HOME", "TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        // Keep coverage profiles outside the repository, preserving the hosted
        // collector's destination despite env_clear().
        let profile_dir = TempDir::new().expect("profile tempdir");
        let profile_path = std::env::var_os("LLVM_PROFILE_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| profile_dir.path().join("default_%m_%p.profraw"));
        let profile_path = std::env::current_dir()
            .expect("test working directory")
            .join(profile_path);
        command
            .env("LLVM_PROFILE_FILE", profile_path)
            .env("FERRUM_GATEWAY_MODE", "file")
            .env("FERRUM_FILE_OUTPUT_PATH", gateway)
            .env("FERRUM_MESH_FILE_OUTPUT_PATH", mesh)
            .env("FERRUM_EDGE_BINARY_PATH", &self.validator);
        command.envs(vars.iter().copied());
        command.output().expect("run gitforgeops")
    }

    fn assert_no_state(&self, context: &str) {
        assert!(
            !self.path(".state/default.json").exists(),
            "{context}: ledger written"
        );
        assert!(
            !self.path(".state/default.lock").exists(),
            "{context}: state lock taken"
        );
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}

#[cfg(unix)]
#[test]
fn cli_refuses_a_shared_gateway_and_mesh_destination_before_any_write() {
    for existing in [false, true] {
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["apply", "--auto-approve"],
        ] {
            let repo = Repo::new(None);
            let shared = repo.path("assembled/out.yaml");
            if existing {
                std::fs::create_dir_all(shared.parent().unwrap()).unwrap();
                std::fs::write(&shared, SENTINEL).unwrap();
            }

            let output = repo.run(&args, "assembled/out.yaml", "./assembled/out.yaml");

            let text = combined(&output);
            assert!(!output.status.success(), "{args:?}: {text}");
            assert!(
                text.contains("resolve to the same file"),
                "{args:?}: {text}"
            );
            if existing {
                assert_eq!(std::fs::read_to_string(&shared).unwrap(), SENTINEL);
            } else {
                assert!(!shared.exists(), "{args:?} published a document");
            }
            repo.assert_no_state(&format!("{args:?}"));
        }
    }
}

/// Default `review` exits 0 and `--fail-on-blockers` exits 1, with the blocker
/// named in the comment either way.
fn assert_review_blocker(repo: &Repo, gateway: &str, mesh: &str, label: &str, detail: &str) {
    for fail_on_blockers in [false, true] {
        let mut args = vec!["review"];
        if fail_on_blockers {
            args.push("--fail-on-blockers");
        }

        let output = repo.run(&args, gateway, mesh);

        let text = combined(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(i32::from(fail_on_blockers)),
            "{args:?}: {text}"
        );
        assert!(text.contains(detail), "{args:?}: {text}");
        assert!(stdout.contains("Apply blocked"), "{args:?}: {text}");
        if fail_on_blockers {
            assert!(text.contains(label), "{args:?}: {text}");
        }
        repo.assert_no_state(&format!("{args:?}"));
    }
}

#[cfg(unix)]
#[test]
fn cli_review_reports_a_shared_destination_as_an_apply_blocker() {
    let repo = Repo::new(None);

    assert_review_blocker(
        &repo,
        "assembled/out.yaml",
        "./assembled/out.yaml",
        "publication-path-collision",
        "resolve to the same file",
    );
    assert!(!repo.path("assembled/out.yaml").exists());
}

#[cfg(unix)]
#[test]
fn cli_export_refuses_an_output_that_is_the_mesh_destination() {
    let repo = Repo::new(None);

    let output = repo.run(
        &["export", "--output", "./assembled/mesh.yaml"],
        "assembled/resources.yaml",
        "assembled/mesh.yaml",
    );

    let text = combined(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("resolve to the same file"), "{text}");
    assert!(!repo.path("assembled/mesh.yaml").exists());
}

#[cfg(unix)]
#[test]
fn cli_distinct_destinations_keep_publishing_both_documents() {
    let repo = Repo::new(None);

    let output = repo.run(
        &["apply", "--auto-approve"],
        "assembled/resources.yaml",
        "assembled/mesh.yaml",
    );

    assert!(output.status.success(), "{}", combined(&output));
    let gateway = std::fs::read_to_string(repo.path("assembled/resources.yaml")).unwrap();
    let mesh = std::fs::read_to_string(repo.path("assembled/mesh.yaml")).unwrap();
    assert!(gateway.contains("proxies"), "{gateway}");
    assert!(mesh.contains("sa/api"), "{mesh}");
}

const SMOKE_ZERO_ATTEMPTS: &str = r#"version: 1
environments:
  default:
    checks:
      - name: broken
        path: /ready
        expect_status: 200
        attempts: 0
"#;

const SMOKE_UNKNOWN_FIELD: &str = r#"version: 1
environments:
  default:
    checks:
      - name: shell
        path: /ready
        expect_status: 200
        run: ./x
"#;

/// Malformed checks in an environment this run does not select still fail:
/// `verify` loads the whole file, so the preview must too.
const SMOKE_BAD_OTHER_ENVIRONMENT: &str = r#"version: 1
environments:
  production:
    checks:
      - name: no leading slash
        path: ready
        expect_status: 200
"#;

/// Every check within its own limits, but the environment's worst case is
/// 2 x 10 x 60s = 20 minutes: a deployment held long after the gateway
/// changed (GHSA-p95x-q89j-hrhv).
const SMOKE_OVER_BUDGET: &str = r#"version: 1
environments:
  default:
    checks:
      - name: slow one
        path: /ready
        expect_status: 200
        attempts: 10
        timeout_secs: 60
        retry_backoff_ms: 0
      - name: slow two
        path: /ready
        expect_status: 200
        attempts: 10
        timeout_secs: 60
        retry_backoff_ms: 0
"#;

/// A plugin's upstream credential is never a traffic-check credential
/// (GHSA-8mhw-ghx8-9m63).
const SMOKE_PLUGIN_SLOT: &str = r#"version: 2
environments:
  default:
    checks:
      - name: spends a plugin secret
        path: /ready
        expect_status: 200
        headers:
          Authorization:
            slot: ferrum/upstream-auth/@plugin/http_logging/config/token
"#;

const SMOKE_VALID: &str = r#"version: 1
environments:
  default:
    checks:
      - name: ready
        path: /ready
        expect_status: 200
"#;

#[cfg(unix)]
#[test]
fn cli_refuses_a_malformed_smoke_file_before_any_write() {
    for (smoke, expected) in [
        (SMOKE_ZERO_ATTEMPTS, "attempts must be at least 1"),
        (SMOKE_UNKNOWN_FIELD, "run"),
        (SMOKE_BAD_OTHER_ENVIRONMENT, "path must start with '/'"),
        (SMOKE_OVER_BUDGET, "worst-case duration"),
        (SMOKE_PLUGIN_SLOT, "not a Consumer credential type"),
    ] {
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["apply", "--auto-approve"],
        ] {
            let repo = Repo::new(Some(smoke));

            let output = repo.run(&args, "assembled/resources.yaml", "assembled/mesh.yaml");

            let text = combined(&output);
            assert!(!output.status.success(), "{args:?}: {text}");
            assert!(text.contains("smoke.yaml"), "{args:?}: {text}");
            assert!(text.contains(expected), "{args:?}: {text}");
            assert!(!repo.path("assembled/resources.yaml").exists(), "{args:?}");
            assert!(!repo.path("assembled/mesh.yaml").exists(), "{args:?}");
            repo.assert_no_state(&format!("{args:?}"));
        }
    }
}

#[cfg(unix)]
#[test]
fn cli_review_reports_a_malformed_smoke_file_as_an_apply_blocker() {
    for (smoke, expected) in [
        (SMOKE_ZERO_ATTEMPTS, "attempts must be at least 1"),
        (SMOKE_UNKNOWN_FIELD, "run"),
        (SMOKE_BAD_OTHER_ENVIRONMENT, "path must start with '/'"),
        (SMOKE_OVER_BUDGET, "worst-case duration"),
        (SMOKE_PLUGIN_SLOT, "not a Consumer credential type"),
    ] {
        let repo = Repo::new(Some(smoke));

        assert_review_blocker(
            &repo,
            "assembled/resources.yaml",
            "assembled/mesh.yaml",
            "invalid-smoke-checks",
            expected,
        );
        assert!(!repo.path("assembled/resources.yaml").exists());
        assert!(!repo.path("assembled/mesh.yaml").exists());
    }
}

#[cfg(unix)]
#[test]
fn cli_accepts_a_valid_or_absent_smoke_file() {
    for smoke in [None, Some(SMOKE_VALID)] {
        let repo = Repo::new(smoke);
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["review", "--fail-on-blockers"],
            vec!["apply", "--auto-approve"],
        ] {
            let output = repo.run(&args, "assembled/resources.yaml", "assembled/mesh.yaml");
            assert!(
                output.status.success(),
                "{smoke:?} {args:?}: {}",
                combined(&output)
            );
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("Apply blocked"),
                "{smoke:?} {args:?}: {}",
                combined(&output)
            );
        }
        assert!(repo.path("assembled/resources.yaml").exists());
        assert!(repo.path(".state/default.json").exists());
    }
}

// -- the probe-credential binding (GHSA-8mhw-ghx8-9m63) ---------------------

const PROBE_CONSUMER: &str = r#"kind: Consumer
spec:
  id: orders-probe
  username: orders-probe
  labels:
    gitforgeops/verify-probe: "true"
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=require}"
"#;

const CUSTOMER_CONSUMER: &str = r#"kind: Consumer
spec:
  id: orders-client
  username: orders-client
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=require}"
"#;

/// The customer after a pull request added the probe label.
const LABELLED_CUSTOMER_CONSUMER: &str = r#"kind: Consumer
spec:
  id: orders-client
  username: orders-client
  labels:
    gitforgeops/verify-probe: "true"
  credentials:
    keyauth:
      - key: "${gh-env-secret:alloc=require}"
"#;

const PROBE_SLOT: &str = "ferrum/orders-probe/keyauth/key";
const CUSTOMER_SLOT: &str = "ferrum/orders-client/keyauth/key";
const PROBE_VALUE: &str = "probe-value-0001";
const CUSTOMER_VALUE: &str = "customer-value-0002";
const ALLOWLIST: &str = "FERRUM_VERIFY_PROBE_CONSUMERS";

/// A `default` check sending `slot` as `X-API-Key`.
fn smoke_sending(slot: &str) -> String {
    format!(
        "version: 2\nenvironments:\n  default:\n    checks:\n      - name: probe\n\
         \n        path: /api\n        expect_status: 200\n        headers:\n\
         \n          X-API-Key:\n            slot: {slot}\n"
    )
}

/// A repository with the probe and a customer Consumer, `customer` being
/// either spelling, and a check sending `slot`.
fn probe_repo(slot: &str, customer: &str) -> Repo {
    let smoke = smoke_sending(slot);
    Repo::with_files(
        Some(&smoke),
        &[
            ("resources/ferrum/consumers/orders-probe.yaml", PROBE_CONSUMER),
            ("resources/ferrum/consumers/orders-client.yaml", customer),
        ],
    )
}

fn credential_bundle() -> String {
    format!(
        "{{\"FERRUM_CREDS_BUNDLE\": {{\"{PROBE_SLOT}\": \"{PROBE_VALUE}\", \
         \"{CUSTOMER_SLOT}\": \"{CUSTOMER_VALUE}\"}}}}"
    )
}

/// Output with every synthetic bundle value masked, for assertion messages.
fn shown(output: &Output) -> String {
    combined(output)
        .replace(PROBE_VALUE, "[probe value]")
        .replace(CUSTOMER_VALUE, "[customer value]")
}

#[cfg(unix)]
#[test]
fn cli_refuses_a_slot_verify_would_refuse_before_any_write() {
    // `verify` enforces the binding only after `apply` changed the gateway.
    // `validate`, `plan` and `apply` refuse the same slot first.
    let none: &[(&str, &str)] = &[];
    let lists_probe: &[(&str, &str)] = &[(ALLOWLIST, "ferrum/orders-probe")];
    let lists_other: &[(&str, &str)] = &[(ALLOWLIST, "ferrum/someone-else")];
    for (slot, customer, vars, expected) in [
        // A customer Consumer with no probe label.
        (CUSTOMER_SLOT, CUSTOMER_CONSUMER, none, "not labelled"),
        // A customer a pull request labelled, which the operator's list
        // (visible to this run) does not name.
        (
            CUSTOMER_SLOT,
            LABELLED_CUSTOMER_CONSUMER,
            lists_probe,
            "the operator does not list",
        ),
        // The probe itself, when the operator lists someone else.
        (
            PROBE_SLOT,
            CUSTOMER_CONSUMER,
            lists_other,
            "the operator does not list",
        ),
        // A Consumer the environment does not declare.
        (
            "ferrum/ghost/keyauth/key",
            CUSTOMER_CONSUMER,
            none,
            "is not a brokered secret",
        ),
    ] {
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["apply", "--auto-approve"],
        ] {
            let repo = probe_repo(slot, customer);

            let output = repo.run_with(
                &args,
                "assembled/resources.yaml",
                "assembled/mesh.yaml",
                vars,
            );

            let text = shown(&output);
            assert!(!output.status.success(), "{slot} {args:?}: {text}");
            assert!(text.contains("smoke.yaml"), "{slot} {args:?}: {text}");
            assert!(text.contains(slot), "{slot} {args:?}: {text}");
            assert!(text.contains(expected), "{slot} {args:?}: {text}");
            assert!(!repo.path("assembled/resources.yaml").exists(), "{args:?}");
            assert!(!repo.path("assembled/mesh.yaml").exists(), "{args:?}");
            repo.assert_no_state(&format!("{slot} {args:?}"));
        }
    }
}

#[cfg(unix)]
#[test]
fn cli_validate_accepts_a_labelled_probe_the_operator_lists_or_cannot_be_seen() {
    // A pull request's run cannot see the operator's list; the label half is
    // still judged there, and `verify` judges the rest.
    let bundle = credential_bundle();
    let unset = [("FERRUM_CREDS_JSON", bundle.as_str())];
    let listed = [
        ("FERRUM_CREDS_JSON", bundle.as_str()),
        (ALLOWLIST, "ferrum/orders-probe"),
    ];
    for (label, vars) in [("unset", &unset[..]), ("listed", &listed[..])] {
        let repo = probe_repo(PROBE_SLOT, CUSTOMER_CONSUMER);
        let output = repo.run_with(
            &["validate"],
            "assembled/resources.yaml",
            "assembled/mesh.yaml",
            vars,
        );
        assert!(output.status.success(), "{label}: {}", shown(&output));
    }
}

#[cfg(unix)]
#[test]
fn cli_review_shows_which_consumer_each_slot_would_spend() {
    let bundle = credential_bundle();

    // Approved: labelled and listed. The section names the check, header,
    // slot and Consumer, and never a value.
    let repo = probe_repo(PROBE_SLOT, CUSTOMER_CONSUMER);
    let vars = [
        (ALLOWLIST, "ferrum/orders-probe"),
        ("FERRUM_CREDS_JSON", bundle.as_str()),
    ];
    let output = repo.run_with(
        &["review"],
        "assembled/resources.yaml",
        "assembled/mesh.yaml",
        &vars,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}", shown(&output));
    for expected in [
        "Traffic-check credentials",
        PROBE_SLOT,
        "ferrum/orders-probe",
        "X-API-Key",
        "approved probe credential",
        "Consumers labelled",
    ] {
        assert!(stdout.contains(expected), "{expected}: {}", shown(&output));
    }
    assert!(!stdout.contains("names a credential verify would refuse"));
    assert!(!stdout.contains("is not visible to this review"));
    let all = combined(&output);
    for value in [PROBE_VALUE, CUSTOMER_VALUE] {
        assert!(!all.contains(value), "review printed a value");
    }

    // A labelled customer the operator does not list is an apply blocker
    // before the merge, and its Consumer is named.
    let repo = probe_repo(CUSTOMER_SLOT, LABELLED_CUSTOMER_CONSUMER);
    for fail_on_blockers in [false, true] {
        let mut args = vec!["review"];
        if fail_on_blockers {
            args.push("--fail-on-blockers");
        }
        let output = repo.run_with(
            &args,
            "assembled/resources.yaml",
            "assembled/mesh.yaml",
            &vars,
        );
        let text = shown(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if fail_on_blockers {
            assert_eq!(output.status.code(), Some(1), "{text}");
            assert!(text.contains("invalid-smoke-checks"), "{text}");
        } else {
            assert_eq!(output.status.code(), Some(0), "{text}");
        }
        for expected in [
            "Apply blocked",
            "names a credential verify would refuse",
            CUSTOMER_SLOT,
            "ferrum/orders-client",
            "refused",
        ] {
            assert!(stdout.contains(expected), "{expected}: {text}");
        }
        let all = combined(&output);
        assert!(!all.contains(CUSTOMER_VALUE), "review printed a value");
    }

    // Without the variable, the review says the list half was not checked.
    let repo = probe_repo(PROBE_SLOT, CUSTOMER_CONSUMER);
    let args = ["review"];
    let output = repo.run(&args, "assembled/resources.yaml", "assembled/mesh.yaml");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}", shown(&output));
    assert!(
        stdout.contains("is not visible to this review"),
        "{}",
        shown(&output)
    );
}

#[cfg(unix)]
#[test]
fn cli_refuses_a_conditional_authenticator_before_validator_or_publication() {
    let repo = Repo::new(None);
    std::fs::create_dir_all(repo.path("resources/ferrum/plugins")).unwrap();
    std::fs::create_dir_all(repo.path(".gitforgeops")).unwrap();
    std::fs::write(
        repo.path("resources/ferrum/proxies/api.yaml"),
        CONDITIONAL_AUTH_PROXY,
    )
    .unwrap();
    std::fs::write(
        repo.path("resources/ferrum/plugins/auth.yaml"),
        CONDITIONAL_AUTH_PLUGIN,
    )
    .unwrap();
    std::fs::write(repo.path(".gitforgeops/policies.yaml"), REQUIRE_AUTH_POLICY).unwrap();
    std::fs::write(&repo.validator, "#!/bin/sh\ntouch validator-ran\nexit 0\n").unwrap();
    set_executable(&repo.validator);

    let output = repo.run(
        &["apply", "--auto-approve"],
        "assembled/resources.yaml",
        "assembled/mesh.yaml",
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("unresolved policy violations"), "{stderr}");
    assert!(stderr.contains("require_auth_plugin"), "{stderr}");
    assert!(!stderr.contains("after credential resolution"), "{stderr}");
    assert!(
        !repo.path("validator-ran").exists(),
        "validator was invoked"
    );
    assert!(!repo.path("assembled/resources.yaml").exists());
    assert!(!repo.path("assembled/mesh.yaml").exists());
    assert!(!repo.path(".state/default.json").exists());
}
