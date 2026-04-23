use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gitforgeops",
    about = "GitOps for Ferrum Edge gateway configuration"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Assemble and validate resources via ferrum-edge validate
    Validate {
        /// Output format: text, json, github-annotations
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Assemble resources into a single flat YAML file
    Export {
        /// Output file path (default: stdout)
        #[arg(long, short)]
        output: Option<String>,
    },
    /// Semantic diff against live gateway
    Diff {},
    /// Full analysis: validate + diff + breaking changes + security
    Plan {},
    /// Apply configuration to gateway
    Apply {
        /// Skip interactive confirmation
        #[arg(long)]
        auto_approve: bool,
    },
    /// Import config from live gateway into resource files
    Import {},
    /// Generate PR review comment
    Review {
        /// PR number
        #[arg(long)]
        pr: Option<u64>,
    },
}
