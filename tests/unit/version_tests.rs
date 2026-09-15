use clap::Parser;
use gitforgeops::cli::{Cli, Commands, ReportFormat};
use gitforgeops::version::BuildInfo;

#[test]
fn cli_version_flag_prints_the_cargo_package_version() {
    for argv in [["gitforgeops", "--version"], ["gitforgeops", "-V"]] {
        let err = match Cli::try_parse_from(argv) {
            Err(err) => err,
            Ok(_) => panic!("{argv:?} must take the clap version path"),
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        let rendered = err.to_string();
        assert!(
            rendered.contains(env!("CARGO_PKG_VERSION")),
            "{argv:?} rendered {rendered:?}"
        );
    }
}

#[test]
fn cli_version_subcommand_defaults_to_text() {
    let cli = Cli::try_parse_from(["gitforgeops", "version"]).unwrap();
    match cli.command {
        Commands::Version { format } => assert!(matches!(format, ReportFormat::Text)),
        _ => panic!("expected version command"),
    }
}

#[test]
fn cli_version_subcommand_accepts_json_format() {
    let cli = Cli::try_parse_from(["gitforgeops", "version", "--format", "json"]).unwrap();
    match cli.command {
        Commands::Version { format } => assert!(matches!(format, ReportFormat::Json)),
        _ => panic!("expected version command"),
    }
}

#[test]
fn cli_version_subcommand_rejects_unknown_format_values() {
    assert!(Cli::try_parse_from(["gitforgeops", "version", "--format", "yaml"]).is_err());
}

#[test]
fn version_text_names_the_package_and_git_slots() {
    let info = sample_info();
    let rendered = info.render_text();
    assert_eq!(
        rendered,
        "gitforgeops 0.1.0\ngit_sha: abcdef\ngit_describe: v0.1.0-1-gabcdef\n"
    );
}

#[test]
fn version_json_is_compact_and_ends_with_one_newline() {
    let rendered = sample_info().render_json().unwrap();
    assert!(rendered.ends_with('\n'), "{rendered:?}");
    assert!(!rendered.ends_with("\n\n"), "{rendered:?}");
    assert_eq!(rendered.matches('\n').count(), 1, "{rendered:?}");

    let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(value["name"], "gitforgeops");
    assert_eq!(value["version"], "0.1.0");
    assert_eq!(value["git_sha"], "abcdef");
    assert_eq!(value["git_describe"], "v0.1.0-1-gabcdef");
}

#[test]
fn version_current_uses_the_baked_package_and_git_env() {
    let info = BuildInfo::current();
    assert_eq!(info.name, env!("CARGO_PKG_NAME"));
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        info.git_sha,
        option_env!("GITFORGEOPS_GIT_SHA").unwrap_or("unknown")
    );
    assert_eq!(
        info.git_describe,
        option_env!("GITFORGEOPS_GIT_DESCRIBE").unwrap_or("unknown")
    );
    assert!(!info.git_sha.is_empty());
    assert!(!info.git_describe.is_empty());

    let json = info.render_json().unwrap();
    assert!(json.ends_with('\n'), "{json:?}");
    serde_json::from_str::<serde_json::Value>(&json).unwrap();
}

fn sample_info() -> BuildInfo {
    BuildInfo {
        name: "gitforgeops".to_string(),
        version: "0.1.0".to_string(),
        git_sha: "abcdef".to_string(),
        git_describe: "v0.1.0-1-gabcdef".to_string(),
    }
}
