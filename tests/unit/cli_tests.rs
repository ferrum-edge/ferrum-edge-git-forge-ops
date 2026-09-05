use clap::Parser;
use gitforgeops::cli::{Cli, Commands, EnvsFormat, ValidateFormat};

#[test]
fn cli_import_from_api_is_a_flag() {
    let cli = Cli::try_parse_from([
        "gitforgeops",
        "import",
        "--from-api",
        "--output-dir",
        "/tmp/scratch-import",
    ])
    .unwrap();

    match cli.command {
        Commands::Import {
            accept_unknown_field: _,
            from_api,
            from_file,
            output_dir,
            credential_bundle_output,
        } => {
            assert!(from_api);
            assert!(from_file.is_none());
            assert_eq!(output_dir, "/tmp/scratch-import");
            assert!(credential_bundle_output.is_none());
        }
        _ => panic!("expected import command"),
    }
}

/// F3: the old `./resources` default could never succeed — import refuses a
/// non-empty destination and this repo ships `_example.yaml` files there — so
/// the destination has to be named.
#[test]
fn cli_requires_an_explicit_import_output_dir() {
    let err = match Cli::try_parse_from(["gitforgeops", "import", "--from-api"]) {
        Err(err) => err,
        Ok(_) => panic!("expected a missing --output-dir parse error"),
    };

    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    assert!(err.to_string().contains("--output-dir"), "{err}");
}

#[test]
fn cli_accepts_a_private_import_bundle_path() {
    let cli = Cli::try_parse_from([
        "gitforgeops",
        "import",
        "--from-file",
        "backup.yaml",
        "--output-dir",
        "/tmp/scratch-import",
        "--credential-bundle-output",
        "/tmp/migration.json",
    ])
    .unwrap();

    match cli.command {
        Commands::Import {
            credential_bundle_output,
            ..
        } => assert_eq!(
            credential_bundle_output.as_deref(),
            Some("/tmp/migration.json")
        ),
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
        Commands::Envs {
            format,
            include_scopes,
        } => {
            assert!(matches!(format, EnvsFormat::Text));
            assert!(!include_scopes);
        }
        _ => panic!("expected envs command"),
    }

    let scoped = Cli::try_parse_from([
        "gitforgeops",
        "envs",
        "--format",
        "json",
        "--include-scopes",
    ])
    .unwrap();
    match scoped.command {
        Commands::Envs { include_scopes, .. } => assert!(include_scopes),
        _ => panic!("expected envs command"),
    }

    let review = Cli::try_parse_from(["gitforgeops", "review", "--require-live"]).unwrap();
    match review.command {
        Commands::Review { require_live, .. } => assert!(require_live),
        _ => panic!("expected review command"),
    }
}

#[test]
fn cli_accepts_global_env_before_or_after_subcommand() {
    let before = Cli::try_parse_from(["gitforgeops", "--env", "production", "validate"]).unwrap();
    assert_eq!(before.env.as_deref(), Some("production"));

    let after = Cli::try_parse_from(["gitforgeops", "validate", "--env", "staging"]).unwrap();
    assert_eq!(after.env.as_deref(), Some("staging"));
}

#[test]
fn cli_apply_exposes_the_api_spec_deletion_opt_in() {
    // Default: API specs are preserved by carrying the live section through
    // the restore. Deleting them has to be asked for explicitly.
    let default = Cli::try_parse_from(["gitforgeops", "apply", "--auto-approve"]).unwrap();
    match default.command {
        Commands::Apply {
            auto_approve,
            allow_large_prune,
            confirm_api_spec_deletion,
        } => {
            assert!(auto_approve);
            assert!(!allow_large_prune);
            assert!(!confirm_api_spec_deletion);
        }
        _ => panic!("expected apply command"),
    }

    let destructive = Cli::try_parse_from([
        "gitforgeops",
        "apply",
        "--auto-approve",
        "--allow-large-prune",
        "--confirm-api-spec-deletion",
    ])
    .unwrap();
    match destructive.command {
        Commands::Apply {
            allow_large_prune,
            confirm_api_spec_deletion,
            ..
        } => {
            assert!(allow_large_prune);
            assert!(confirm_api_spec_deletion);
        }
        _ => panic!("expected apply command"),
    }
}

#[test]
fn cli_exposes_the_credential_slot_remap_opt_in_globally() {
    // The refusal comes from credential resolution, which plan, apply,
    // review, export --materialize and rotate all go through, so the
    // acknowledgement has to be reachable from any of them — before or after
    // the subcommand.
    let default = Cli::try_parse_from(["gitforgeops", "apply", "--auto-approve"]).unwrap();
    assert!(
        !default.allow_credential_slot_remap,
        "a slot reassignment must be refused unless explicitly accepted"
    );

    for argv in [
        vec!["gitforgeops", "apply", "--allow-credential-slot-remap"],
        vec!["gitforgeops", "--allow-credential-slot-remap", "apply"],
        vec!["gitforgeops", "plan", "--allow-credential-slot-remap"],
        vec![
            "gitforgeops",
            "rotate",
            "--consumer",
            "app",
            "--credential",
            "keyauth/[1]/key",
            "--allow-credential-slot-remap",
        ],
        vec![
            "gitforgeops",
            "export",
            "--materialize",
            "--allow-credential-slot-remap",
        ],
    ] {
        let cli = Cli::try_parse_from(argv.clone())
            .unwrap_or_else(|e| panic!("{argv:?} must parse: {e}"));
        assert!(cli.allow_credential_slot_remap, "{argv:?}");
    }
}
