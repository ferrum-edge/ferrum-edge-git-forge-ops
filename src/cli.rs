use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "gitforgeops",
    about = "GitOps for Ferrum Edge gateway configuration"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[arg(long)]
    pub no_color: bool,

    /// Select an environment declared in `.gitforgeops/config.yaml`.
    /// Overrides `FERRUM_ENV` if both are set.
    #[arg(long, global = true)]
    pub env: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    Validate {
        #[arg(long, value_enum, default_value_t = ValidateFormat::Text)]
        format: ValidateFormat,
    },
    Export {
        #[arg(long, short)]
        output: Option<String>,
        /// Replace `${gh-env-secret:...}` placeholders with resolved values from
        /// the credential bundle. Without this flag, placeholders are preserved
        /// verbatim so the output is safe to commit.
        #[arg(long)]
        materialize: bool,
        /// Age-encrypt the output to this GitHub user's SSH public key before
        /// writing. Requires `--materialize` — encrypting placeholders is
        /// pointless. The encrypted output is safe to store in workflow
        /// artifacts or comments; the recipient decrypts with their SSH key.
        #[arg(long)]
        encrypt_to: Option<String>,
    },
    Diff {
        #[arg(long)]
        exit_on_drift: bool,
    },
    Plan {},
    Apply {
        #[arg(long)]
        auto_approve: bool,
        /// Allow apply even when the plan would delete more than
        /// `ownership.large_prune_threshold_percent` of managed resources.
        #[arg(long)]
        allow_large_prune: bool,
    },
    Import {
        #[arg(long, conflicts_with = "from_file")]
        from_api: bool,
        #[arg(long, conflicts_with = "from_api")]
        from_file: Option<String>,
        #[arg(long, default_value = "./resources")]
        output_dir: String,
    },
    Review {
        #[arg(long)]
        pr: Option<u64>,
    },
    /// Emit JSON listing environments declared in repo config (used by CI matrix).
    Envs {
        #[arg(long, value_enum, default_value_t = EnvsFormat::Json)]
        format: EnvsFormat,
    },
    /// Rotate a specific credential slot. Requires provisioner token.
    Rotate {
        #[arg(long)]
        consumer: String,
        #[arg(long)]
        credential: String,
        #[arg(long)]
        namespace: Option<String>,
        /// GitHub login to deliver the rotated credential to (age-encrypted).
        #[arg(long)]
        recipient: Option<String>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ValidateFormat {
    Text,
    Json,
    Github,
    GithubAnnotations,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum EnvsFormat {
    Json,
    Text,
}
