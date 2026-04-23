use clap::{Parser, Subcommand};

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
}

#[derive(Subcommand)]
pub enum Commands {
    Validate {
        #[arg(long, default_value = "text")]
        format: String,
    },
    Export {
        #[arg(long, short)]
        output: Option<String>,
    },
    Diff {
        #[arg(long)]
        exit_on_drift: bool,
    },
    Plan {},
    Apply {
        #[arg(long)]
        auto_approve: bool,
    },
    Import {
        #[arg(long)]
        from_api: Option<String>,
        #[arg(long)]
        from_file: Option<String>,
        #[arg(long, default_value = "./resources")]
        output_dir: String,
    },
    Review {
        #[arg(long)]
        pr: Option<u64>,
    },
}
