use clap::Parser;
use gitforgeops::cli::{Cli, Commands, EnvsFormat, ValidateFormat};

#[test]
fn cli_import_from_api_is_a_flag() {
    let cli = Cli::try_parse_from(["gitforgeops", "import", "--from-api"]).unwrap();

    match cli.command {
        Commands::Import {
            from_api,
            from_file,
            output_dir,
        } => {
            assert!(from_api);
            assert!(from_file.is_none());
            assert_eq!(output_dir, "./resources");
        }
        _ => panic!("expected import command"),
    }
}

#[test]
fn cli_rejects_conflicting_import_sources() {
    let err = match Cli::try_parse_from([
        "gitforgeops",
        "import",
        "--from-api",
        "--from-file",
        "resources.yaml",
    ]) {
        Err(err) => err,
        Ok(_) => panic!("expected conflicting import source parse error"),
    };

    assert!(err.to_string().contains("cannot be used with"));
}

#[test]
fn cli_rejects_unknown_format_values() {
    assert!(Cli::try_parse_from(["gitforgeops", "validate", "--format", "jsn"]).is_err());
    assert!(Cli::try_parse_from(["gitforgeops", "envs", "--format", "yaml"]).is_err());
}

#[test]
fn cli_accepts_documented_format_values() {
    let validate =
        Cli::try_parse_from(["gitforgeops", "validate", "--format", "github-annotations"]).unwrap();
    match validate.command {
        Commands::Validate { format } => {
            assert!(matches!(format, ValidateFormat::GithubAnnotations))
        }
        _ => panic!("expected validate command"),
    }

    let envs = Cli::try_parse_from(["gitforgeops", "envs", "--format", "text"]).unwrap();
    match envs.command {
        Commands::Envs { format } => assert!(matches!(format, EnvsFormat::Text)),
        _ => panic!("expected envs command"),
    }
}

#[test]
fn cli_accepts_global_env_before_or_after_subcommand() {
    let before = Cli::try_parse_from(["gitforgeops", "--env", "production", "validate"]).unwrap();
    assert_eq!(before.env.as_deref(), Some("production"));

    let after = Cli::try_parse_from(["gitforgeops", "validate", "--env", "staging"]).unwrap();
    assert_eq!(after.env.as_deref(), Some("staging"));
}
