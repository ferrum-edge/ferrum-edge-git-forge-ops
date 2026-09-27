//! Bounded reads of repository-controlled configuration files.
//!
//! `.gitforgeops/config.yaml`, `.gitforgeops/policies.yaml` and
//! `.gitforgeops/smoke.yaml` arrive with a pull request. Only the unprivileged
//! validate job (and a local run on a hostile checkout) reads those
//! PR-authored copies; the privileged review substitutes the default branch's
//! copies of `.gitforgeops`. A symbolic link would let that file name point
//! anywhere on the runner, and a device, FIFO or arbitrarily large file would
//! stall or exhaust the job before a single diagnostic is printed. Every such
//! loader reads through [`read_bounded_repo_file`], which accepts only a
//! regular file no larger than the stated cap.

use std::fs::Metadata;
use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};

/// Upper bound for one repository-controlled configuration file.
pub const MAX_REPO_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

/// Read `path` as UTF-8 text, or `Ok(None)` when nothing exists there.
///
/// Refuses a symbolic link (even one whose target is a regular file), any
/// non-regular file, a file that is replaced between inspection and opening,
/// and more than `max_bytes` bytes — the last both by the inspected length and
/// by the bytes actually read, so a file that grows after inspection is still
/// refused.
pub fn read_bounded_repo_file(path: &Path, max_bytes: u64) -> Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(file_read_error(path, source)),
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::Config(format!(
            "{}: symbolic links are not allowed for repository configuration files",
            path.display()
        )));
    }
    if !file_type.is_file() {
        return Err(Error::Config(format!(
            "{}: not a regular file; repository configuration files must be regular files",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(oversized_error(path, max_bytes));
    }

    let read_error = |source: std::io::Error| file_read_error(path, source);
    let file = std::fs::File::open(path).map_err(read_error)?;
    let opened = file.metadata().map_err(read_error)?;
    if !opened.is_file() || !same_file(&metadata, &opened) {
        return Err(Error::Config(format!(
            "{}: changed while it was being opened; refusing to read it",
            path.display()
        )));
    }

    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.len() as u64 > max_bytes {
        return Err(oversized_error(path, max_bytes));
    }
    match String::from_utf8(bytes) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) => {
            let source = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
            Err(file_read_error(path, source))
        }
    }
}

fn file_read_error(path: &Path, source: std::io::Error) -> Error {
    Error::FileRead {
        path: path.to_path_buf(),
        source,
    }
}

fn oversized_error(path: &Path, max_bytes: u64) -> Error {
    Error::Config(format!(
        "{}: exceeds the {max_bytes} byte limit for repository configuration files",
        path.display()
    ))
}

#[cfg(unix)]
fn same_file(inspected: &Metadata, opened: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    inspected.dev() == opened.dev() && inspected.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(_inspected: &Metadata, _opened: &Metadata) -> bool {
    true
}
