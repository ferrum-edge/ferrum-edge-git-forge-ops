//! Bind authorization to the bytes this process reads, including trusted
//! review's split source/data checkout. No caller-supplied SHA alone is proof.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

#[derive(Deserialize)]
struct Tree {
    truncated: bool,
    tree: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    path: String,
    mode: String,
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

pub fn is_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn generated(path: &str) -> bool {
    path.starts_with(".state/") || path.starts_with("assembled/")
}

fn input(path: &str) -> bool {
    ((path.starts_with("resources/") || path.starts_with("overlays/"))
        && (path.ends_with(".yaml") || path.ends_with(".yml")))
        || matches!(path, ".gitforgeops/config.yaml" | ".gitforgeops/policies.yaml")
}

fn git(source: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"])
        .args(args)
        .current_dir(source)
        .output()
        .map_err(|_| "cannot inspect override source checkout")?;
    if !output.status.success() {
        return Err("cannot prove override source revision or clean input".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "non-UTF-8 override source paths".into())
}

fn source_blob(source: &Path, path: &str, mode: &str) -> Result<String, String> {
    let file = source.join(path);
    let metadata = std::fs::symlink_metadata(&file).map_err(|_| "missing executable input")?;
    if mode == "120000" && metadata.file_type().is_symlink() {
        let target = std::fs::read_link(&file).map_err(|_| "cannot read source symlink")?;
        let target = target.to_str().ok_or("non-UTF-8 source symlink")?;
        let mut child = Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null", "hash-object", "--stdin"])
            .current_dir(source)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot hash source symlink")?;
        child
            .stdin
            .take()
            .ok_or("cannot hash source symlink")?
            .write_all(target.as_bytes())
            .map_err(|_| "cannot hash source symlink")?;
        let output = child
            .wait_with_output()
            .map_err(|_| "cannot hash source symlink")?;
        if !output.status.success() {
            return Err("cannot hash source symlink".into());
        }
        return String::from_utf8(output.stdout).map_err(|_| "invalid source hash".into());
    }
    if !metadata.is_file() || !matches!(mode, "100644" | "100755") {
        return Err("unsupported or changed executable input type".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (metadata.permissions().mode() & 0o111 != 0) != (mode == "100755") {
            return Err("executable input mode differs from reviewed revision".into());
        }
    }
    let file = file.to_str().ok_or("non-UTF-8 executable path")?;
    git(source, &["hash-object", "--no-filters", "--", file])
}

pub fn verify_current_input(
    tree: &serde_json::Value,
    merged: bool,
    merge_revision: Option<&str>,
    review_context: bool,
) -> Result<String, String> {
    let data = std::env::current_dir().map_err(|_| "cannot locate desired input")?;
    let source = review_context
        .then(|| std::env::var_os("GITFORGEOPS_OVERRIDE_SOURCE"))
        .flatten()
        .map(PathBuf::from)
        .unwrap_or_else(|| data.clone());
    let revision = verify_input(tree, &source, &data, merged, merge_revision)?;
    // Workflow attribution must describe the checkout actually inspected.
    // workflow_run's ambient SHA describes the workflow, so split review uses
    // its verified trusted checkout instead. A plain CLI need not set a SHA.
    if !review_context && std::env::var("GITHUB_SHA").is_ok_and(|sha| sha != revision) {
        return Err("GITHUB_SHA does not match the actual source checkout".into());
    }
    Ok(revision)
}

/// Public for hosted regression fixtures; production always obtains the tree
/// from the fixed GitHub API and the PR's current head.
pub fn verify_input(
    value: &serde_json::Value,
    source: &Path,
    data: &Path,
    merged: bool,
    merge_revision: Option<&str>,
) -> Result<String, String> {
    let source_root = source.canonicalize().map_err(|_| "missing source checkout")?;
    let data_root = data.canonicalize().map_err(|_| "missing desired input")?;
    let source = source_root.as_path();
    let data = data_root.as_path();
    let tree: Tree =
        serde_json::from_value(value.clone()).map_err(|_| "missing authorized tree evidence")?;
    if tree.truncated || tree.tree.is_empty() {
        return Err("incomplete authorized tree evidence".into());
    }
    let root = git(source, &["rev-parse", "--show-toplevel"])?;
    if source.canonicalize().ok() != Path::new(root.trim()).canonicalize().ok() {
        return Err("override source must be a repository root".into());
    }
    let revision = git(source, &["rev-parse", "HEAD"])?;
    let revision = revision.trim();
    if !is_revision(revision) {
        return Err("missing actual source revision".into());
    }
    if merged {
        let merge = merge_revision
            .filter(|sha| is_revision(sha))
            .ok_or("missing merged PR revision")?;
        git(source, &["merge-base", "--is-ancestor", merge, revision])?;
    }

    let mut expected_source = BTreeMap::new();
    let mut expected_input = BTreeMap::new();
    for entry in tree.tree {
        if entry.kind == "tree" || generated(&entry.path) {
            continue;
        }
        if !is_revision(&entry.sha) {
            return Err("invalid authorized object identity".into());
        }
        if input(&entry.path) {
            if entry.kind != "blob" || !matches!(entry.mode.as_str(), "100644" | "100755") {
                return Err("authorized desired input is not a regular file".into());
            }
            expected_input.insert(entry.path, entry.sha);
        } else {
            expected_source.insert(entry.path, (entry.mode, entry.kind, entry.sha));
        }
    }
    let listing = git(source, &["ls-tree", "-rz", "--full-tree", "HEAD"])?;
    let mut actual_source = BTreeMap::new();
    for row in listing.split('\0').filter(|row| !row.is_empty()) {
        let (metadata, path) = row.split_once('\t').ok_or("invalid source tree")?;
        if generated(path) || input(path) {
            continue;
        }
        let fields: Vec<_> = metadata.split_whitespace().collect();
        if fields.len() != 3 {
            return Err("invalid source tree entry".into());
        }
        actual_source.insert(
            path.to_string(),
            (fields[0].into(), fields[1].into(), fields[2].into()),
        );
    }
    if actual_source != expected_source {
        return Err("executable or repository inputs differ from the reviewed revision".into());
    }
    // Hash raw working bytes, not the index or Git's stat cache. This catches
    // assume-unchanged/skip-worktree edits too and never invokes clean filters,
    // textconv, diff drivers, or any other repository executable.
    for (path, (mode, kind, expected)) in &expected_source {
        if kind != "blob" || source_blob(source, path, mode)?.trim() != expected {
            return Err("uncommitted executable or repository input".into());
        }
    }
    let unknown = git(source, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let indexed = git(source, &["ls-files", "--cached", "-z"])?;
    if unknown
        .split('\0')
        .chain(indexed.split('\0'))
        .any(|path| {
            !path.is_empty()
                && !generated(path)
                && !input(path)
                && !expected_source.contains_key(path)
        })
    {
        return Err("uncommitted executable or repository input".into());
    }

    let mut actual_input = BTreeMap::new();
    for directory in ["resources", "overlays", ".gitforgeops"] {
        let start = data.join(directory);
        if !start.exists() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&start).follow_links(false) {
            let entry = entry.map_err(|_| "cannot enumerate desired input")?;
            if entry.file_type().is_symlink() {
                return Err("symlink in desired input".into());
            }
            if entry.file_type().is_dir() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(data)
                .map_err(|_| "desired input escapes its root")?;
            let relative = relative.to_str().ok_or("non-UTF-8 desired path")?;
            if !input(relative) {
                continue;
            }
            if !entry.file_type().is_file() {
                return Err("non-regular desired input".into());
            }
            let path = entry.path().to_str().ok_or("non-UTF-8 desired path")?;
            let hash = git(source, &["hash-object", "--no-filters", "--", path])?;
            actual_input.insert(relative.to_string(), hash.trim().to_string());
        }
    }
    if actual_input != expected_input {
        return Err("actual desired or policy input differs from the reviewed revision".into());
    }
    Ok(revision.to_string())
}
