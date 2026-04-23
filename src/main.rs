mod cli;

use std::io::Write;
use std::path::PathBuf;
use std::process;

use clap::Parser;

use gitforgeops::config::{self, GatewayConfig};
use gitforgeops::validate;

fn main() {
    let cli = cli::Cli::parse();

    let result = match cli.command {
        cli::Commands::Validate { format } => cmd_validate(&format),
        cli::Commands::Export { output } => cmd_export(output.as_deref()),
        cli::Commands::Diff {} => {
            eprintln!("diff: not yet implemented");
            process::exit(1);
        }
        cli::Commands::Plan {} => {
            eprintln!("plan: not yet implemented");
            process::exit(1);
        }
        cli::Commands::Apply { .. } => {
            eprintln!("apply: not yet implemented");
            process::exit(1);
        }
        cli::Commands::Import {} => {
            eprintln!("import: not yet implemented");
            process::exit(1);
        }
        cli::Commands::Review { .. } => {
            eprintln!("review: not yet implemented");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn load_and_assemble() -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();

    let resources_dir = PathBuf::from("./resources");
    let mut resources = config::load_resources(&resources_dir)?;

    // Apply overlay if configured
    if let Some(ref overlay_name) = env_config.overlay {
        let overlay_dir = PathBuf::from("./overlays").join(overlay_name);
        if overlay_dir.is_dir() {
            config::apply_overlay(&mut resources, &overlay_dir)?;
        }
    }

    let gateway_config = config::assemble(resources);
    Ok(gateway_config)
}

fn cmd_validate(format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();
    let gateway_config = load_and_assemble()?;

    let result = validate::run_validation(&gateway_config, &env_config.edge_binary_path)?;
    let output_format = validate::OutputFormat::from_str_lossy(format);
    let formatted = validate::format_result(&result, output_format);

    print!("{}", formatted);

    if !result.success {
        process::exit(result.exit_code);
    }

    Ok(())
}

fn cmd_export(output_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let gateway_config = load_and_assemble()?;
    let yaml = serde_yaml::to_string(&gateway_config)?;

    match output_path {
        Some(path) => {
            // Ensure parent directory exists
            if let Some(parent) = PathBuf::from(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::File::create(path)?;
            file.write_all(yaml.as_bytes())?;
            eprintln!("Exported to {}", path);
        }
        None => {
            print!("{}", yaml);
        }
    }

    Ok(())
}
