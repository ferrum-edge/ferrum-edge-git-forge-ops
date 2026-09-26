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
        let dir = TempDir::new().expect("repo tempdir");
        let mut files = vec![
            ("resources/ferrum/proxies/api.yaml", PROXY),
            ("resources/ferrum/mesh/core.yaml", MESH_FRAGMENT),
        ];
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
fn cli_accepts_a_valid_or_absent_smoke_file() {
    for smoke in [None, Some(SMOKE_VALID)] {
        let repo = Repo::new(smoke);
        for args in [
            vec!["validate"],
            vec!["plan"],
            vec!["apply", "--auto-approve"],
        ] {
            let output = repo.run(&args, "assembled/resources.yaml", "assembled/mesh.yaml");
            assert!(
                output.status.success(),
                "{smoke:?} {args:?}: {}",
                combined(&output)
            );
        }
        assert!(repo.path("assembled/resources.yaml").exists());
        assert!(repo.path(".state/default.json").exists());
    }
}
