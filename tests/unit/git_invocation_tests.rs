//! The runtime image runs Git from a copied Bookworm build whose libraries the
//! image scan cannot see (`Dockerfile`, override Git). Its CVE assessment holds
//! only while the CLI's Git calls compile no regular expression and never
//! write through zlib's gzFile layer.
//!
//! This is a tripwire, not a proof. It pins, as exact whitespace-free text,
//! every `Command::new(` builder chain in `src/` up to its first terminator
//! and every call of the override `git()` helper, so a new or changed spawn
//! chain or Git call fails until someone re-checks that assessment and updates
//! the pins. On its own, it also refuses Git argument lists with a computed
//! item before the subcommand, a subcommand outside the assessed set,
//! unassessed global options or `-c` settings, regex options, revision regex
//! searches, and arguments chained after the literal list.
//!
//! The assessment names the copied Git and zlib versions, which come from the
//! builder image digest, so `the_assessment_names_the_pinned_builder` fails
//! when that digest changes until the assessment is redone. The validation
//! `is_revision` performs on the variable `merge-base` operands is pinned too.
//!
//! What it does not see, reviewed by hand instead:
//! - arguments added to a command in later statements. Two launches do this:
//!   the validator (`validate/runner.rs`, the operator-configured
//!   `ferrum-edge` binary with `build_validate_args_for_mode`) and doctor's
//!   `python3` (`doctor/github.rs`). For doctor this is covered:
//!   `doctor_runs_only_the_bundled_auditor` pins that it runs the embedded
//!   `audit_settings.py`, and `the_bundled_auditor_runs_only_gh` pins that
//!   script's one subprocess. The validator launch stays reviewed by hand;
//! - a spawn hidden from the text scan: a type alias or macro that expands to
//!   `Command::new`, or code included from outside `src/`. None exists today;
//! - `build.rs`, which runs the build host's Git at compile time (the image
//!   build context excludes `.git`);
//! - `code-scanning.yml`, which runs the image's Git as fixed `config` and
//!   `rev-parse HEAD` probes and runs the override regression binary inside
//!   the image, whose fixtures call `init`, `config`, `add`, `commit`,
//!   `ls-tree`, `rev-parse`, `status` and `update-index`
//!   (`tests/unit/override_tests.rs`). All are fixed CI inputs; none compiles
//!   a pattern (`status` matches with wildmatch) or writes a gzFile, though
//!   `status` and `update-index` may rewrite the uncompressed index.

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

/// Every process construction in `src/`: the file, then the whitespace-free
/// builder chain from `Command::new(` to its first terminator. Arguments added
/// in later statements are not part of the chain.
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

/// Doctor's `python3` launch runs exactly the bundled settings auditor: the
/// constant embeds `audit_settings.py`, the launch passes it as `-I -c`'s
/// program, and nothing else reads or rebinds it. The spawn pin sees only
/// `Command::new("python3")`, so this binding is what makes
/// `the_bundled_auditor_runs_only_gh` describe what doctor executes.
fn doctor_runs_the_bundled_auditor(doctor_source: &str) -> bool {
    let compact: String = doctor_source.chars().filter(|c| !c.is_whitespace()).collect();
    compact
        .matches(r#"constBUNDLED_AUDITOR:&str=include_str!("../../.github/scripts/audit_settings.py");"#)
        .count()
        == 1
        && compact
            .matches(r#".arg("-I").arg("-c").arg(BUNDLED_AUDITOR).arg("--repo")"#)
            .count()
            == 1
        && compact.matches("BUNDLED_AUDITOR").count() == 2
}

#[test]
fn doctor_runs_only_the_bundled_auditor() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/doctor/github.rs");
    let source = std::fs::read_to_string(path).unwrap();
    assert!(
        doctor_runs_the_bundled_auditor(&source),
        "doctor's python3 launch no longer runs exactly the bundled \
         audit_settings.py: re-check it for Git use, then update this pin"
    );
    for (from, to) in [
        ("audit_settings.py", "other_script.py"),
        (".arg(BUNDLED_AUDITOR)", ".arg(OTHER_SCRIPT)"),
        (".arg(\"-c\")", ".arg(\"-m\")"),
    ] {
        assert!(source.contains(from), "{from}");
        assert!(
            !doctor_runs_the_bundled_auditor(&source.replace(from, to)),
            "accepted a rebinding of {from}"
        );
    }
    let rebound = format!("{source}\nconst BUNDLED_AUDITOR_COPY: &str = BUNDLED_AUDITOR;\n");
    assert!(!doctor_runs_the_bundled_auditor(&rebound));
}

#[test]
fn the_bundled_auditor_runs_only_gh() {
    // Doctor runs this script with `python3 -I -c` (pinned by
    // `doctor_runs_only_the_bundled_auditor`); its own subprocess use is
    // pinned here.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/scripts/audit_settings.py");
    let source = std::fs::read_to_string(path).unwrap();
    for api in [
        "os.system",
        "os.popen",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "pty.",
        "create_subprocess",
        "\"git\"",
        "'git'",
    ] {
        assert!(!source.contains(api), "the bundled auditor uses {api}");
    }
    assert_eq!(source.matches("subprocess.run(").count(), 1);
    assert!(source.contains(r#"command = ["gh", "api", path]"#));
}

/// The builder whose Git and libraries the Dockerfile's override Git
/// assessment describes (Git 2.39.5, zlib1g 1:1.2.13.dfsg-1).
const ASSESSED_BUILDER: &str = "FROM rust:1.99.1-bookworm@sha256:\
9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS builder";

#[test]
fn the_assessment_names_the_pinned_builder() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Dockerfile");
    let dockerfile = std::fs::read_to_string(path).unwrap();
    assert!(
        dockerfile.lines().any(|line| line == ASSESSED_BUILDER),
        "the builder image changed: redo the Dockerfile's override Git CVE \
         assessment for the new Git and library versions, then update \
         ASSESSED_BUILDER"
    );
}

#[test]
fn the_merge_base_operands_stay_hex_validated() {
    // The pinned `merge-base` call passes `merge` and `revision`; they are safe
    // revision operands only because this check admits 40 hex digits alone.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/policy/override_input.rs");
    let compact: String = std::fs::read_to_string(path)
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(compact.contains(
        "pubfnis_revision(value:&str)->bool{value.len()==40&&value.bytes().all(|b|b.is_ascii_hexdigit())}"
    ));
    assert!(compact.contains("if!is_revision(revision){"));
    assert!(compact.contains("letmerge=merge_revision.filter(|sha|is_revision(sha))"));
}
