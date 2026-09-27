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
