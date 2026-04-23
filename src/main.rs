mod cli;

use std::io::Write;
use std::path::PathBuf;
use std::process;

use clap::Parser;

use gitforgeops::apply;
use gitforgeops::config::{self, GatewayConfig, GatewayMode};
use gitforgeops::diff;
use gitforgeops::http_client::AdminClient;
use gitforgeops::import;
use gitforgeops::review;
use gitforgeops::state::StateFile;
use gitforgeops::validate;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    let result = match cli.command {
        cli::Commands::Validate { format } => cmd_validate(&format),
        cli::Commands::Export { output } => cmd_export(output.as_deref()),
        cli::Commands::Diff { exit_on_drift } => cmd_diff(exit_on_drift).await,
        cli::Commands::Plan {} => cmd_plan().await,
        cli::Commands::Apply { auto_approve } => cmd_apply(auto_approve).await,
        cli::Commands::Import {
            from_api,
            from_file,
            output_dir,
        } => cmd_import(from_api.as_deref(), from_file.as_deref(), &output_dir).await,
        cli::Commands::Review { pr } => cmd_review(pr).await,
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

async fn cmd_diff(exit_on_drift: bool) -> Result<(), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();
    let desired = load_and_assemble()?;
    let client = AdminClient::new(&env_config)?;
    let namespace = env_config.namespace_filter.as_deref().unwrap_or("ferrum");
    let actual = client.get_backup(namespace).await?;

    let diffs = diff::compute_diff(&desired, &actual);

    if diffs.is_empty() {
        println!("No differences found. Configuration is in sync.");
        return Ok(());
    }

    println!("Found {} difference(s):\n", diffs.len());
    for d in &diffs {
        let action = match d.action {
            diff::DiffAction::Add => "ADD",
            diff::DiffAction::Modify => "MODIFY",
            diff::DiffAction::Delete => "DELETE",
        };
        println!("  {} {} {}", action, d.kind, d.id);
        for change in &d.details {
            println!(
                "    {}: {} -> {}",
                change.field, change.old_value, change.new_value
            );
        }
    }

    if exit_on_drift {
        process::exit(2);
    }

    Ok(())
}

async fn cmd_plan() -> Result<(), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();
    let desired = load_and_assemble()?;

    println!("=== Validation ===");
    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path);
    let validation_ok = match &val_result {
        Ok(r) => {
            if r.success {
                println!("PASSED\n");
            } else {
                println!("FAILED");
                print!("{}", r.stderr);
                println!();
            }
            r.success
        }
        Err(e) => {
            println!("SKIPPED ({})\n", e);
            true
        }
    };

    let client = AdminClient::new(&env_config);
    let namespace = env_config.namespace_filter.as_deref().unwrap_or("ferrum");

    let (diffs, breaking, actual_available) = match &client {
        Ok(c) => match c.get_backup(namespace).await {
            Ok(actual) => {
                let d = diff::compute_diff(&desired, &actual);
                let b = diff::detect_breaking_changes(&d, &desired, &actual);
                (d, b, true)
            }
            Err(e) => {
                eprintln!("Could not fetch live config: {}", e);
                (Vec::new(), Vec::new(), false)
            }
        },
        Err(e) => {
            eprintln!("Could not create API client: {}", e);
            (Vec::new(), Vec::new(), false)
        }
    };

    println!("=== Changes ===");
    if !actual_available {
        println!("SKIPPED (no live config available)\n");
    } else if diffs.is_empty() {
        println!("None (in sync)\n");
    } else {
        for d in &diffs {
            let action = match d.action {
                diff::DiffAction::Add => "ADD",
                diff::DiffAction::Modify => "MODIFY",
                diff::DiffAction::Delete => "DELETE",
            };
            println!("  {} {} {}", action, d.kind, d.id);
        }
        println!();
    }

    if !breaking.is_empty() {
        println!("=== Breaking Changes ===");
        for bc in &breaking {
            println!("  {} {}: {}", bc.kind, bc.id, bc.reason);
        }
        println!();
    }

    let security_findings = diff::audit_security(&desired);
    if !security_findings.is_empty() {
        println!("=== Security Findings ===");
        for sf in &security_findings {
            println!("  [{}] {} {}: {}", sf.severity, sf.kind, sf.id, sf.message);
        }
        println!();
    }

    let bp_findings = diff::check_best_practices(&desired);
    if !bp_findings.is_empty() {
        println!("=== Best Practice Recommendations ===");
        for bp in &bp_findings {
            println!("  {} {}: {}", bp.kind, bp.id, bp.message);
        }
        println!();
    }

    if !validation_ok {
        process::exit(1);
    }

    Ok(())
}

async fn cmd_apply(auto_approve: bool) -> Result<(), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();
    let desired = load_and_assemble()?;

    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path);
    if let Ok(ref r) = val_result {
        if !r.success {
            eprintln!("Validation failed. Fix errors before applying.");
            process::exit(1);
        }
    }

    match env_config.gateway_mode {
        GatewayMode::Api => {
            let client = AdminClient::new(&env_config)?;
            let namespace = env_config.namespace_filter.as_deref().unwrap_or("ferrum");

            if !auto_approve {
                let actual = client.get_backup(namespace).await?;
                let diffs = diff::compute_diff(&desired, &actual);
                if diffs.is_empty() {
                    println!("No changes to apply.");
                    return Ok(());
                }
                println!("Will apply {} change(s):", diffs.len());
                for d in &diffs {
                    let action = match d.action {
                        diff::DiffAction::Add => "ADD",
                        diff::DiffAction::Modify => "MODIFY",
                        diff::DiffAction::Delete => "DELETE",
                    };
                    println!("  {} {} {}", action, d.kind, d.id);
                }
                println!("\nUse --auto-approve to skip this check.");
                process::exit(0);
            }

            let result = apply::apply_api(
                &desired,
                &client,
                env_config.apply_strategy.clone(),
                env_config.namespace_filter.as_deref(),
            )
            .await?;

            println!(
                "Applied: {} created, {} updated, {} deleted",
                result.created, result.updated, result.deleted
            );
            if !result.errors.is_empty() {
                eprintln!("Errors:");
                for e in &result.errors {
                    eprintln!("  {}", e);
                }
            }
        }
        GatewayMode::File => {
            apply::apply_file(&desired, &env_config.file_output_path)?;
            println!("Written to {}", env_config.file_output_path);
        }
    }

    let mut state = StateFile::load();
    state.record(&desired);
    state.save()?;

    Ok(())
}

async fn cmd_import(
    from_api: Option<&str>,
    from_file: Option<&str>,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = PathBuf::from(output_dir);

    let result = if from_api.is_some() {
        let env_config = config::load_env_config();
        let client = AdminClient::new(&env_config)?;
        let namespace = env_config.namespace_filter.as_deref().unwrap_or("ferrum");
        import::import_from_api(&client, &output_path, namespace).await?
    } else if let Some(file_path) = from_file {
        import::import_from_file(&PathBuf::from(file_path), &output_path)?
    } else {
        eprintln!("Specify --from-api or --from-file <PATH>");
        process::exit(1);
    };

    println!(
        "Imported: {} proxies, {} consumers, {} upstreams, {} plugin_configs",
        result.proxies, result.consumers, result.upstreams, result.plugin_configs
    );

    Ok(())
}

async fn cmd_review(pr: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();
    let desired = load_and_assemble()?;

    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path);
    let (validation_ok, validation_output) = match &val_result {
        Ok(r) => (r.success, format!("{}{}", r.stdout, r.stderr)),
        Err(e) => (true, format!("Validation skipped: {}", e)),
    };

    let client = AdminClient::new(&env_config);
    let namespace = env_config.namespace_filter.as_deref().unwrap_or("ferrum");

    let (diffs, breaking) = match &client {
        Ok(c) => match c.get_backup(namespace).await {
            Ok(actual) => {
                let d = diff::compute_diff(&desired, &actual);
                let b = diff::detect_breaking_changes(&d, &desired, &actual);
                (d, b)
            }
            Err(_) => (Vec::new(), Vec::new()),
        },
        Err(_) => (Vec::new(), Vec::new()),
    };

    let security_findings = diff::audit_security(&desired);
    let bp_findings = diff::check_best_practices(&desired);

    let comment = review::build_review_comment(
        validation_ok,
        &validation_output,
        &diffs,
        &breaking,
        &security_findings,
        &bp_findings,
    );

    match pr {
        Some(pr_number) => {
            review::post_pr_comment(pr_number, &comment).await?;
            println!("Posted review comment to PR #{}", pr_number);
        }
        None => {
            print!("{}", comment);
        }
    }

    Ok(())
}
