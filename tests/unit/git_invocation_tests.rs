//! The runtime image runs Git from a copied Bookworm build whose libraries the
//! image scan cannot see (`Dockerfile`, override Git). Its CVE assessment holds
//! only while the CLI runs Git subcommands that compile no regular expression
//! and never write through zlib's gzFile layer. This scan of `src/` pins that
//! set: a new subcommand must be added here, which sends the change back to
//! that assessment.

use std::path::{Path, PathBuf};

/// Every Git subcommand the CLI may run. Before adding one, re-check the
/// Dockerfile's assessment of the copied Git libraries (PCRE2 JIT patterns,
/// zlib gz* file functions) for it.
const ALLOWED_GIT_SUBCOMMANDS: &[&str] = &[
    "hash-object",
    "ls-files",
    "ls-tree",
    "merge-base",
    "rev-parse",
];

/// The one helper that spawns Git with caller-supplied arguments; its call
/// sites are checked instead of its spawn.
const HELPER_FILE: &str = "override_input.rs";

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

/// The string literals of an `[...]` argument list, in order.
fn literals(list: &str) -> Vec<&str> {
    list.split('"').skip(1).step_by(2).collect()
}

/// The subcommand among Git's leading arguments: skip `-c <value>` and options.
fn subcommand<'a>(arguments: &[&'a str]) -> Option<&'a str> {
    let mut iter = arguments.iter();
    while let Some(argument) = iter.next() {
        if *argument == "-c" {
            iter.next();
        } else if !argument.starts_with('-') {
            return Some(argument);
        }
    }
    None
}

struct Scan {
    subcommands: Vec<(String, String)>,
    helper_spawns: usize,
    violations: Vec<String>,
}

fn scan_source(name: &str, source: &str, scan: &mut Scan) {
    // Whitespace-free, so a call split across lines reads as one token run.
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();

    for (at, _) in compact.match_indices("Command::new(\"") {
        let rest = &compact[at + "Command::new(\"".len()..];
        let Some(end) = rest.find("\")") else { continue };
        let program = &rest[..end];
        if program != "git" && !program.ends_with("/git") {
            continue;
        }
        if program != "git" {
            scan.violations.push(format!("{name}: spawns Git by path {program:?}"));
            continue;
        }
        let chain = &rest[end + 2..];
        let Some(list) = chain
            .strip_prefix(".args([")
            .and_then(|list| list.find("])").map(|close| &list[..close]))
        else {
            scan.violations
                .push(format!("{name}: Git spawn without a literal leading argument list"));
            continue;
        };
        match subcommand(&literals(list)) {
            Some(found) => scan.subcommands.push((name.to_string(), found.to_string())),
            None if name == HELPER_FILE
                && chain[".args([".len() + list.len() + 2..].starts_with(".args(args)") =>
            {
                scan.helper_spawns += 1;
            }
            None => scan
                .violations
                .push(format!("{name}: Git spawn whose subcommand is not a literal")),
        }
    }

    for (at, _) in compact.match_indices("git(") {
        if compact[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue; // `fn git(`, `digit(`, ...
        }
        let rest = &compact[at + "git(".len()..];
        let literal_list = rest
            .find(',')
            .map(|comma| &rest[comma + 1..])
            .and_then(|args| args.strip_prefix("&["))
            .and_then(|list| list.find(']').map(|close| &list[..close]));
        match literal_list.and_then(|list| subcommand(&literals(list))) {
            Some(found) if list_starts_with_literal(literal_list) => {
                scan.subcommands.push((name.to_string(), found.to_string()));
            }
            _ => scan
                .violations
                .push(format!("{name}: `git(` call whose subcommand is not a literal")),
        }
    }
}

fn list_starts_with_literal(list: Option<&str>) -> bool {
    list.is_some_and(|list| list.starts_with('"'))
}

#[test]
fn the_cli_runs_only_the_assessed_git_subcommands() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let mut scan = Scan {
        subcommands: Vec::new(),
        helper_spawns: 0,
        violations: Vec::new(),
    };
    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        scan_source(&name, &std::fs::read_to_string(file).unwrap(), &mut scan);
    }
    for (file, found) in &scan.subcommands {
        if !ALLOWED_GIT_SUBCOMMANDS.contains(&found.as_str()) {
            scan.violations.push(format!(
                "{file}: runs `git {found}`, outside the assessed set; re-check the \
                 Dockerfile's override Git CVE assessment, then extend the allowlist"
            ));
        }
    }
    assert!(scan.violations.is_empty(), "{}", scan.violations.join("\n"));
    // Not vacuous: the scan still sees the known call sites.
    assert_eq!(scan.helper_spawns, 1, "the override Git helper was not found");
    let mut seen: Vec<&str> = scan.subcommands.iter().map(|(_, s)| s.as_str()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen, ALLOWED_GIT_SUBCOMMANDS);
}

#[test]
fn the_scan_refuses_a_new_or_computed_subcommand() {
    let mut scan = Scan {
        subcommands: Vec::new(),
        helper_spawns: 0,
        violations: Vec::new(),
    };
    scan_source(
        "x.rs",
        "Command::new(\"git\")\n    .args([\"-c\", \"a=b\", \"grep\", \"-P\"]);\n\
         git(\n    source,\n    &[\"log\", \"--perl-regexp\"],\n)?;",
        &mut scan,
    );
    let found: Vec<&str> = scan.subcommands.iter().map(|(_, s)| s.as_str()).collect();
    assert_eq!(found, ["grep", "log"]);

    let mut scan = Scan {
        subcommands: Vec::new(),
        helper_spawns: 0,
        violations: Vec::new(),
    };
    scan_source(
        "x.rs",
        "Command::new(\"git\").args(args);\n\
         Command::new(\"/usr/bin/git\").args([\"status\"]);\n\
         git(source, &[sub, \"x\"]);\n\
         Command::new(\"git\").args([\"-c\", \"a=b\"]).args(args);",
        &mut scan,
    );
    assert_eq!(scan.violations.len(), 4, "{:?}", scan.violations);
    assert!(scan.subcommands.is_empty());
}
