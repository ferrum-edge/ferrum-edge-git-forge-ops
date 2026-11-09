//! The runtime image runs Git from a copied Bookworm build whose libraries the
//! image scan cannot see (`Dockerfile`, override Git). Its CVE assessment holds
//! only while the CLI's Git calls compile no regular expression and never
//! write through zlib's gzFile layer.
//!
//! Scope: the runtime CLI in `src/`. `build.rs` runs the build host's Git at
//! compile time (the image build context excludes `.git`), and
//! `code-scanning.yml` runs the image's Git as a fixed `config` command; both
//! are outside this scan.
//!
//! This scan pins every process the CLI can start and every Git call exactly.
//! Any new or changed spawn, including one that resolves Git by variable,
//! constant or shell, fails until the pins are updated, which sends the change
//! back to that assessment. The Git rules below also refuse, on their own, a
//! computed subcommand, a subcommand outside the assessed set, regex-taking
//! options, revision regex searches and unassessed `-c` settings.

use std::path::{Path, PathBuf};

/// Every Git subcommand the CLI may run. Before adding one, re-check the
/// Dockerfile's assessment of the copied Git libraries for it.
const ALLOWED_GIT_SUBCOMMANDS: &[&str] = &[
    "hash-object",
    "ls-files",
    "ls-tree",
    "merge-base",
    "rev-parse",
];

/// Git global options a spawn may pass before its subcommand.
const ALLOWED_LEADING_OPTIONS: &[&str] = &["--no-replace-objects"];

/// The only `-c` setting a spawn may pass.
const ALLOWED_CONFIG: &str = "core.hooksPath=/dev/null";

/// The one helper that spawns Git with its caller's arguments; its call sites
/// are checked instead.
const HELPER_FILE: &str = "policy/override_input.rs";

/// Options that make Git compile a pattern (PCRE2 with `-P`, or a
/// `grep.patternType` choice the inspected repository can set).
const REGEX_OPTIONS: &[&str] = &[
    "-P",
    "-G",
    "-E",
    "-F",
    "--perl-regexp",
    "--extended-regexp",
    "--basic-regexp",
    "--fixed-strings",
    "--all-match",
    "--invert-grep",
];

/// Revision syntax that searches commit messages or the reflog by regex.
const REGEX_REVISIONS: &[&str] = &[":/", "@{/", "^{/"];

/// Every process the CLI can start: file under `src/`, then the
/// whitespace-free builder chain from `Command::new(` to its terminator.
const PINNED_SPAWNS: &[(&str, &str)] = &[
    ("doctor/github.rs", r#"Command::new("python3")"#),
    (
        "policy/override_input.rs",
        r#"Command::new("git").args(["-c","core.hooksPath=/dev/null","--no-replace-objects"]).args(args).current_dir(source)"#,
    ),
    (
        "policy/override_input.rs",
        r#"Command::new("git").args(["-c","core.hooksPath=/dev/null","hash-object","--stdin"]).current_dir(source).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())"#,
    ),
    (
        "state.rs",
        r#"Command::new("git").args(["rev-parse","HEAD"])"#,
    ),
    ("validate/runner.rs", r#"Command::new("/bin/sh")"#),
    ("validate/runner.rs", r#"Command::new("/bin/sh")"#),
    ("validate/runner.rs", r#"Command::new("/bin/sh")"#),
    ("validate/runner.rs", r#"Command::new("/bin/sh")"#),
    (
        "validate/runner.rs",
        r#"Command::new("/bin/sh").args(["-c","kill-0\"$1\"2>/dev/null||exit1;\case\"$(ps-ostat=-p\"$1\"2>/dev/null)\"inZ*)exit1;;esac","sh",descendant,])"#,
    ),
    (
        "validate/runner.rs",
        r#"Command::new("/bin/sh").args(["-c","kill-sKILL--\"-$1\"","sh"]).arg(child.id().to_string()).env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())"#,
    ),
    (
        "validate/runner.rs",
        r#"Command::new("which").arg("--").arg(binary_path)"#,
    ),
    ("validate/runner.rs", r#"Command::new(binary_path)"#),
    (
        "validate/runner.rs",
        r#"Command::new(binary_path).arg("--help")"#,
    ),
];

const PINNED_GIT_CALLS: &[(&str, &str)] = &[
    (
        "policy/override_input.rs",
        r#"source,&["hash-object","--no-filters","--",file]"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["hash-object","--no-filters","--",path]"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["ls-files","--cached","-z"]"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["ls-files","--others","--exclude-standard","-z"],"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["ls-tree","-rz","--full-tree","HEAD"]"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["merge-base","--is-ancestor",merge,revision]"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["rev-parse","--show-toplevel"]"#,
    ),
    (
        "policy/override_input.rs",
        r#"source,&["rev-parse","HEAD"]"#,
    ),
];

const TERMINATORS: &[&str] = &[".output()", ".spawn()", ".status()"];

/// End of the expression that starts at `start`: a top-level `;` or
/// terminator, or the bracket that closes an enclosing call. String literals
/// are skipped, so their contents never end it.
fn expression_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    let mut i = start;
    while i < bytes.len() {
        let byte = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if depth == 0
            && (byte == b';'
                || TERMINATORS
                    .iter()
                    .any(|t| bytes[i..].starts_with(t.as_bytes())))
        {
            return i;
        } else if matches!(byte, b'(' | b'[' | b'{') {
            depth += 1;
        } else if matches!(byte, b')' | b']' | b'}') {
            if depth == 0 {
                return i;
            }
            depth -= 1;
        }
        i += 1;
    }
    i
}

/// Top-level comma-separated items of an argument list.
fn items(list: &str) -> Vec<&str> {
    let bytes = list.as_bytes();
    let (mut depth, mut in_string, mut escaped, mut from) = (0usize, false, false, 0);
    let mut out = Vec::new();
    for (i, &byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if matches!(byte, b'(' | b'[' | b'{') {
            depth += 1;
        } else if matches!(byte, b')' | b']' | b'}') {
            depth = depth.saturating_sub(1);
        } else if byte == b',' && depth == 0 {
            out.push(&list[from..i]);
            from = i + 1;
        }
    }
    out.push(&list[from..]);
    out.into_iter().filter(|item| !item.is_empty()).collect()
}

/// The value of a plain string literal item, or `None` for an expression.
fn literal(item: &str) -> Option<&str> {
    (item.len() >= 2 && item.starts_with('"') && item.ends_with('"'))
        .then(|| &item[1..item.len() - 1])
}

#[derive(Default)]
struct Scan {
    spawns: Vec<(String, String)>,
    git_calls: Vec<(String, String)>,
    subcommands: Vec<String>,
    helper_spawns: usize,
    violations: Vec<String>,
}

impl Scan {
    fn refuse(&mut self, file: &str, why: &str, text: &str) {
        self.violations.push(format!("{file}: {why}: {text}"));
    }

    /// Checks one Git argument list. `leading` allows global options and
    /// `-c` before the subcommand (a direct spawn); a helper call must start
    /// with it. Returns whether a subcommand was found.
    fn check_git_arguments(&mut self, file: &str, list: &str, leading: bool) -> bool {
        let items = items(list);
        let mut index = 0;
        let mut subcommand = None;
        while index < items.len() {
            match literal(items[index]) {
                Some("-c") if leading => {
                    if literal(items.get(index + 1).copied().unwrap_or("")) != Some(ALLOWED_CONFIG)
                    {
                        self.refuse(file, "unassessed or computed `-c` setting", list);
                        return true;
                    }
                    index += 2;
                }
                Some(option) if leading && option.starts_with('-') => {
                    if !ALLOWED_LEADING_OPTIONS.contains(&option) {
                        self.refuse(file, "unassessed Git global option", list);
                        return true;
                    }
                    index += 1;
                }
                Some(found) => {
                    subcommand = Some(found);
                    index += 1;
                    break;
                }
                None => {
                    self.refuse(file, "computed argument before the Git subcommand", list);
                    return true;
                }
            }
        }
        let Some(subcommand) = subcommand else {
            return false;
        };
        if !ALLOWED_GIT_SUBCOMMANDS.contains(&subcommand) {
            self.refuse(file, "Git subcommand outside the assessed set", list);
        }
        for item in &items[index..] {
            if let Some(value) = literal(item) {
                if REGEX_OPTIONS.contains(&value)
                    || value.starts_with("--grep")
                    || REGEX_REVISIONS.iter().any(|r| value.contains(r))
                {
                    self.refuse(file, "Git argument that compiles a pattern", list);
                }
            }
        }
        self.subcommands.push(subcommand.to_string());
        true
    }

    fn check_spawn(&mut self, file: &str, chain: &str) {
        let program = chain
            .strip_prefix("Command::new(")
            .map(|rest| &rest[..expression_end(rest, 0)])
            .unwrap_or("");
        let is_git = match literal(program) {
            Some(name) => name == "git" || name.ends_with("/git"),
            None => false,
        };
        if !is_git {
            return;
        }
        if program != "\"git\"" {
            self.refuse(file, "Git spawned by path", chain);
            return;
        }
        let rest = &chain["Command::new(\"git\")".len()..];
        let Some(after) = rest.strip_prefix(".args([") else {
            self.refuse(file, "Git spawn without a literal argument list", chain);
            return;
        };
        let end = expression_end(after, 0);
        let (list, tail) = (&after[..end], after[end..].strip_prefix("])").unwrap_or(""));
        let found = self.check_git_arguments(file, list, true);
        if !found {
            if file == HELPER_FILE && tail.starts_with(".args(args)") {
                self.helper_spawns += 1;
            } else {
                self.refuse(file, "Git spawn with no literal subcommand", chain);
            }
        } else if tail.contains(".arg(") || tail.contains(".args(") {
            self.refuse(file, "Git arguments added after the literal list", chain);
        }
    }

    fn check_git_call(&mut self, file: &str, call: &str) {
        let list = items(call)
            .into_iter()
            .nth(1)
            .and_then(|second| second.strip_prefix("&["))
            .and_then(|list| list.strip_suffix(']'));
        match list {
            Some(list) if self.check_git_arguments(file, list, false) => {}
            _ => self.refuse(file, "`git(` call without a literal subcommand", call),
        }
    }

    fn scan_source(&mut self, file: &str, source: &str) {
        // Whitespace-free, so a call split across lines reads as one run.
        let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.contains("Commandas") {
            self.refuse(file, "aliased `Command` import", "Command as");
        }
        for (at, _) in compact.match_indices("Command::new(") {
            let chain = compact[at..expression_end(&compact, at)].to_string();
            self.check_spawn(file, &chain);
            self.spawns.push((file.to_string(), chain));
        }
        for (at, _) in compact.match_indices("git(") {
            if compact[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue; // `fn git(`, `digit(`, ...
            }
            let start = at + "git(".len();
            let call = compact[start..expression_end(&compact, start)].to_string();
            self.check_git_call(file, &call);
            self.git_calls.push((file.to_string(), call));
        }
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn sorted(pins: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut pins: Vec<(String, String)> = pins
        .iter()
        .map(|(file, text)| (file.to_string(), text.to_string()))
        .collect();
    pins.sort();
    pins
}

#[test]
fn the_cli_starts_only_the_pinned_processes_and_git_calls() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let mut scan = Scan::default();
    for file in &files {
        let name = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        scan.scan_source(&name, &std::fs::read_to_string(file).unwrap());
    }
    assert!(scan.violations.is_empty(), "{}", scan.violations.join("\n"));
    scan.spawns.sort();
    scan.git_calls.sort();
    assert_eq!(
        scan.spawns,
        sorted(PINNED_SPAWNS),
        "a process spawn changed: if it can reach Git, re-check the Dockerfile's \
         override Git CVE assessment, then update PINNED_SPAWNS"
    );
    assert_eq!(
        scan.git_calls,
        sorted(PINNED_GIT_CALLS),
        "a Git call changed: re-check the Dockerfile's override Git CVE \
         assessment, then update PINNED_GIT_CALLS"
    );
    // Not vacuous: the helper and every assessed subcommand are still seen.
    assert_eq!(
        scan.helper_spawns, 1,
        "the override Git helper was not found"
    );
    let mut seen = scan.subcommands.clone();
    seen.sort();
    seen.dedup();
    assert_eq!(seen, ALLOWED_GIT_SUBCOMMANDS);
}

#[test]
fn the_rules_refuse_unassessed_git_use_on_their_own() {
    let refused = [
        // A computed subcommand ahead of an allowed-looking literal.
        r#"Command::new("git").args([sub, "-P", pattern, "--", "rev-parse"]);"#,
        r#"Command::new("git").args(["-c", value, "rev-parse"]);"#,
        r#"Command::new("git").args(["-c", "grep.patternType=perl", "rev-parse"]);"#,
        r#"Command::new("git").args(["-C", "repo", "rev-parse"]);"#,
        r#"Command::new("git").args(["grep", "-P", "x"]);"#,
        r#"Command::new("git").args(["rev-parse", ":/fix"]);"#,
        r#"Command::new("git").args(["rev-parse", "HEAD^{/fix}"]);"#,
        r#"Command::new("git").args(["rev-parse"]).arg(revision);"#,
        r#"Command::new("git").arg("rev-parse");"#,
        r#"Command::new("/usr/bin/git").args(["rev-parse"]);"#,
        r#"Command::new("git").args(["-c", "core.hooksPath=/dev/null"]).args(args);"#,
        "git(\n    source,\n    &[\"log\", \"--perl-regexp\"],\n)?;",
        r#"git(source, &[sub, "x"]);"#,
        r#"git(source, args);"#,
        "use std::process::Command as Cmd;",
    ];
    for snippet in refused {
        let mut scan = Scan::default();
        scan.scan_source("other.rs", snippet);
        assert!(!scan.violations.is_empty(), "accepted: {snippet}");
    }

    let mut scan = Scan::default();
    scan.scan_source(
        HELPER_FILE,
        r#"Command::new("git").args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"]).args(args).current_dir(source).output();
           git(source, &["merge-base", "--is-ancestor", merge, revision])?;
           git(source, &["hash-object", "--no-filters", "--", file])"#,
    );
    assert!(scan.violations.is_empty(), "{:?}", scan.violations);
    assert_eq!(scan.helper_spawns, 1);
    assert_eq!(scan.subcommands, ["merge-base", "hash-object"]);
}
