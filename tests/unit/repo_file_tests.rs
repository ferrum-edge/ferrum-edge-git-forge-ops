//! Bounded reads of the repository-controlled `.gitforgeops/*.yaml` files.
//!
//! `config.yaml`, `policies.yaml` and `smoke.yaml` all read through
//! `read_bounded_repo_file`; the loader-level refusals live beside each
//! loader's other tests.

use gitforgeops::config::{read_bounded_repo_file, MAX_REPO_CONFIG_FILE_BYTES};

#[test]
fn bounded_read_returns_none_when_the_file_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");

    let contents = read_bounded_repo_file(&path, MAX_REPO_CONFIG_FILE_BYTES).unwrap();
    assert!(contents.is_none());
}

#[test]
fn bounded_read_accepts_a_regular_file_at_the_cap() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(&path, "a".repeat(64)).unwrap();

    let contents = read_bounded_repo_file(&path, 64).unwrap();
    assert_eq!(contents.as_deref(), Some("a".repeat(64).as_str()));
}

#[test]
fn bounded_read_refuses_a_file_over_the_cap() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(&path, "a".repeat(65)).unwrap();

    let error = read_bounded_repo_file(&path, 64).unwrap_err().to_string();
    assert!(error.contains("exceeds the 64 byte limit"), "{error}");
    assert!(error.contains("config.yaml"), "{error}");
}

#[test]
fn bounded_read_refuses_a_directory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::create_dir(&path).unwrap();

    let error = read_bounded_repo_file(&path, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a regular file"), "{error}");
}

#[test]
fn bounded_read_refuses_invalid_utf8() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();

    let error = read_bounded_repo_file(&path, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("failed to read file"), "{error}");
}

#[cfg(unix)]
#[test]
fn bounded_read_refuses_a_symlink_to_a_regular_file() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.yaml");
    std::fs::write(&target, "version: 1\n").unwrap();
    let link = directory.path().join("config.yaml");
    symlink(&target, &link).unwrap();

    let error = read_bounded_repo_file(&link, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic links"), "{error}");
}

#[cfg(unix)]
#[test]
fn bounded_read_refuses_a_dangling_symlink_instead_of_reporting_absence() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("config.yaml");
    symlink(directory.path().join("missing.yaml"), &link).unwrap();

    let error = read_bounded_repo_file(&link, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic links"), "{error}");
}

#[cfg(unix)]
#[test]
fn bounded_read_refuses_a_device_node() {
    let path = std::path::Path::new("/dev/null");
    let error = read_bounded_repo_file(path, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a regular file"), "{error}");
}

/// A checkout whose `.gitforgeops` is a symbolic link to a directory outside
/// it, which holds regular `config.yaml`, `policies.yaml` and `smoke.yaml`
/// files (GHSA-hfxp-g32w-pf8f).
#[cfg(unix)]
fn checkout_with_symlinked_gitforgeops() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("config.yaml"), "version: 1\n").unwrap();
    std::fs::write(outside.join("policies.yaml"), "version: 1\n").unwrap();
    std::fs::write(outside.join("smoke.yaml"), "version: 2\n").unwrap();
    let checkout = directory.path().join("checkout");
    std::fs::create_dir_all(&checkout).unwrap();
    symlink(&outside, checkout.join(".gitforgeops")).unwrap();
    (directory, checkout)
}

#[cfg(unix)]
#[test]
fn bounded_read_refuses_a_file_under_a_symlinked_directory() {
    let (_directory, checkout) = checkout_with_symlinked_gitforgeops();
    let path = checkout.join(".gitforgeops/config.yaml");

    let error = read_bounded_repo_file(&path, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic links"), "{error}");
    assert!(error.contains(".gitforgeops"), "{error}");
}

#[cfg(unix)]
#[test]
fn every_gitforgeops_loader_refuses_a_symlinked_gitforgeops_directory() {
    use gitforgeops::config::RepoConfig;
    use gitforgeops::policy::config::load_policies_from_path;
    use gitforgeops::verify::SmokeConfig;

    let (_directory, checkout) = checkout_with_symlinked_gitforgeops();
    let gitforgeops = checkout.join(".gitforgeops");

    let errors = [
        RepoConfig::load_from_path(&gitforgeops.join("config.yaml"))
            .map(|_| ())
            .expect_err("config.yaml through a symlinked .gitforgeops must be refused")
            .to_string(),
        load_policies_from_path(&gitforgeops.join("policies.yaml"))
            .map(|_| ())
            .expect_err("policies.yaml through a symlinked .gitforgeops must be refused")
            .to_string(),
        SmokeConfig::load_from_path(&gitforgeops.join("smoke.yaml"))
            .map(|_| ())
            .expect_err("smoke.yaml through a symlinked .gitforgeops must be refused")
            .to_string(),
    ];
    for error in errors {
        assert!(error.contains("symbolic links"), "{error}");
    }
}

/// The CLI reads `.gitforgeops/config.yaml` relative to the working
/// directory, so every directory a relative path names is checked. The test
/// builds such a path from the working directory to a temporary checkout
/// (canonicalized, so the host's own `/var` or `/tmp` links on macOS are not
/// on it).
#[cfg(unix)]
#[test]
fn bounded_read_checks_every_directory_of_a_relative_path() {
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    fn relative_from_cwd(target: &Path) -> PathBuf {
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let target = target.canonicalize().unwrap();
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(target.strip_prefix("/").unwrap());
        relative
    }

    let directory = tempfile::tempdir().unwrap();
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(outside.join("gitforgeops")).unwrap();
    std::fs::write(outside.join("gitforgeops/config.yaml"), "version: 1\n").unwrap();
    let checkout = directory.path().join("checkout");
    std::fs::create_dir_all(&checkout).unwrap();
    // A link two directories above the file: only a walk over every
    // component of the relative path finds it.
    symlink(&outside, checkout.join("nested")).unwrap();

    let relative = relative_from_cwd(&checkout).join("nested/gitforgeops/config.yaml");
    assert!(relative.is_relative());
    let error = read_bounded_repo_file(&relative, MAX_REPO_CONFIG_FILE_BYTES)
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic links"), "{error}");
    assert!(error.contains("nested"), "{error}");

    // The same layout without the link reads normally.
    let plain = directory.path().join("plain");
    std::fs::create_dir_all(plain.join("nested/gitforgeops")).unwrap();
    std::fs::write(plain.join("nested/gitforgeops/config.yaml"), "version: 1\n").unwrap();
    let relative = relative_from_cwd(&plain).join("nested/gitforgeops/config.yaml");
    let contents = read_bounded_repo_file(&relative, MAX_REPO_CONFIG_FILE_BYTES).unwrap();
    assert_eq!(contents.as_deref(), Some("version: 1\n"));
}
