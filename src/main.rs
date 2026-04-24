mod cli;

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use reqwest::Client;

use gitforgeops::apply;
use gitforgeops::config::{
    self, resolve_env, EnvConfig, GatewayConfig, GatewayMode, OwnershipMode, RepoConfig,
    ResolvedEnv,
};
use gitforgeops::diff;
use gitforgeops::http_client::AdminClient;
use gitforgeops::import;
use gitforgeops::policy;
use gitforgeops::review;
use gitforgeops::secrets;
use gitforgeops::state::StateFile;
use gitforgeops::validate;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    let explicit_env = cli.env.clone();

    let result = match cli.command {
        cli::Commands::Validate { format } => cmd_validate(&format, explicit_env.as_deref()),
        cli::Commands::Export {
            output,
            materialize,
            encrypt_to,
        } => {
            cmd_export(
                output.as_deref(),
                materialize,
                encrypt_to.as_deref(),
                explicit_env.as_deref(),
            )
            .await
        }
        cli::Commands::Diff { exit_on_drift } => {
            cmd_diff(exit_on_drift, explicit_env.as_deref()).await
        }
        cli::Commands::Plan {} => cmd_plan(explicit_env.as_deref()).await,
        cli::Commands::Apply {
            auto_approve,
            allow_large_prune,
        } => cmd_apply(auto_approve, allow_large_prune, explicit_env.as_deref()).await,
        cli::Commands::Import {
            from_api,
            from_file,
            output_dir,
        } => {
            cmd_import(
                from_api.as_deref(),
                from_file.as_deref(),
                &output_dir,
                explicit_env.as_deref(),
            )
            .await
        }
        cli::Commands::Review { pr } => cmd_review(pr, explicit_env.as_deref()).await,
        cli::Commands::Envs { format } => cmd_envs(&format),
        cli::Commands::Rotate {
            consumer,
            credential,
            namespace,
            recipient,
        } => {
            cmd_rotate(
                &consumer,
                &credential,
                namespace.as_deref(),
                recipient.as_deref(),
                explicit_env.as_deref(),
            )
            .await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn load_repo_config() -> Result<Option<RepoConfig>, Box<dyn std::error::Error>> {
    Ok(RepoConfig::load()?)
}

fn resolve_runtime(
    explicit_env: Option<&str>,
) -> Result<(EnvConfig, ResolvedEnv, Option<RepoConfig>), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config();
    let repo = load_repo_config()?;
    let resolved = resolve_env(repo.as_ref(), &env_config, explicit_env)?;
    Ok((env_config, resolved, repo))
}

fn load_and_assemble_for(
    resolved: &ResolvedEnv,
) -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    let resources_dir = PathBuf::from("./resources");
    let mut resources = config::load_resources(&resources_dir)?;

    if let Some(ref overlay_name) = resolved.overlay {
        let overlay_dir = PathBuf::from("./overlays").join(overlay_name);
        if overlay_dir.is_dir() {
            config::apply_overlay(&mut resources, &overlay_dir)?;
        }
    }

    let gateway_config = config::assemble(resources);
    let gateway_config =
        config::select_config_namespace(&gateway_config, resolved.namespace_filter.as_deref());
    Ok(gateway_config)
}

fn load_credential_bundles(
    env_config: &EnvConfig,
) -> Result<
    (
        secrets::CredentialBundle,
        BTreeMap<u32, secrets::CredentialBundle>,
    ),
    Box<dyn std::error::Error>,
> {
    // Prefer the file-path form. At scale (many shards × 48 KB), the
    // inline env-var form collides with OS env-block size limits; the
    // file path skips that bound entirely.
    if let Some(path) = &env_config.creds_bundle_json_file {
        if !path.trim().is_empty() {
            let raw = std::fs::read_to_string(path).map_err(|source| {
                gitforgeops::error::Error::FileRead {
                    path: std::path::PathBuf::from(path),
                    source,
                }
            })?;
            if !raw.trim().is_empty() {
                return Ok(secrets::load_bundles_from_env(&raw)?);
            }
        }
    }
    match &env_config.creds_bundle_json {
        Some(raw) if !raw.trim().is_empty() => Ok(secrets::load_bundles_from_env(raw)?),
        _ => Ok((BTreeMap::new(), BTreeMap::new())),
    }
}

/// Resolve credentials for read-only paths (diff, plan, review, validate).
///
/// Uses `resolve_secrets_including_rotate` so `alloc=rotate` placeholders get
/// substituted with their bundle values — otherwise the placeholder literal
/// `${gh-env-secret:alloc=rotate}` would be compared against the live gateway
/// value on every diff and surface as persistent false drift (and fail
/// `drift-check.yml --exit-on-drift`).
///
/// `cmd_apply` calls `resolve_secrets` directly (not through this helper)
/// because its first pass deliberately keeps rotate placeholders in place so
/// the allocator can generate fresh values.
fn resolve_credentials(
    cfg: &mut GatewayConfig,
    env_config: &EnvConfig,
) -> Result<secrets::ResolveReport, Box<dyn std::error::Error>> {
    let (bundle, _) = load_credential_bundles(env_config)?;
    Ok(secrets::resolve_secrets_including_rotate(cfg, &bundle)?)
}

fn resolved_namespaces(
    resolved: &ResolvedEnv,
    desired: &GatewayConfig,
    state: &StateFile,
) -> Vec<String> {
    match resolved.ownership.mode {
        OwnershipMode::Exclusive => {
            let owned = resolved.ownership.namespaces.clone().unwrap_or_default();
            // Honor namespace_filter as an intersection. Without this,
            // `FERRUM_NAMESPACE=ferrum` on an env with
            // `ownership.namespaces: [ferrum, platform]` would still iterate
            // `platform` — but `desired` has been filtered to `ferrum` only,
            // so `platform` shows up as an all-deletions diff and prunes
            // resources outside the operator's requested scope.
            // The mismatched-filter case (namespace_filter not in owned set)
            // is rejected upstream by `enforce_exclusive_scope`. If we reach
            // here with a filter set, it's guaranteed to be in the allowed
            // list.
            match resolved.namespace_filter.as_deref() {
                Some(ns) => vec![ns.to_string()],
                None => owned,
            }
        }
        OwnershipMode::Shared => match resolved.namespace_filter.as_deref() {
            Some(ns) => vec![ns.to_string()],
            None => {
                // Shared mode: iterate every namespace the repo *currently*
                // declares AND every namespace it has previously managed.
                // Missing the latter means a PR that removes the last resource
                // from a namespace silently stops reconciling it — the gateway
                // keeps the orphan forever.
                use std::collections::BTreeSet;
                let mut set: BTreeSet<String> =
                    config::collect_namespaces(desired).into_iter().collect();
                for key in state.resources.keys() {
                    // state key format: "<namespace>:<Kind>:<id>"
                    if let Some((ns, _)) = key.split_once(':') {
                        set.insert(ns.to_string());
                    }
                }
                set.into_iter().collect()
            }
        },
    }
}

/// In `exclusive` mode, every resource in `desired` must live in a namespace
/// declared in `ownership.namespaces`, and any `namespace_filter` must be one
/// of those allowed namespaces. Otherwise the repo would be silently pushing
/// resources the ownership contract never signed for — or a filter typo
/// would produce a "successful" no-op apply that still mutates the local
/// state baseline to reflect a desired set that never reached the gateway.
fn enforce_exclusive_scope(
    resolved: &ResolvedEnv,
    desired: &GatewayConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(resolved.ownership.mode, OwnershipMode::Exclusive) {
        return Ok(());
    }
    let owned: Vec<String> = resolved.ownership.namespaces.clone().unwrap_or_default();
    let allowed: std::collections::HashSet<&str> = owned.iter().map(String::as_str).collect();

    // Reject namespace_filter outside the ownership list BEFORE we touch
    // anything else. Letting it through would produce an empty reconcile
    // scope while state.record still ran against the already-filtered
    // desired — a no-op apply that still drifts the local baseline.
    if let Some(filter) = resolved.namespace_filter.as_deref() {
        if !allowed.contains(filter) {
            return Err(format!(
                "namespace_filter '{filter}' is not in ownership.namespaces {owned:?} for env '{}'. \
                 Apply would reconcile nothing but still record state, which desyncs ownership tracking. \
                 Either add '{filter}' to ownership.namespaces, remove FERRUM_NAMESPACE, or target a different env.",
                resolved.name
            )
            .into());
        }
    }

    let mut violations = Vec::new();
    let mut check = |ns: &str, kind: &str, id: &str| {
        if !allowed.contains(ns) {
            violations.push(format!("{kind} {id} in namespace '{ns}'"));
        }
    };
    for p in &desired.proxies {
        check(&p.namespace, "Proxy", &p.id);
    }
    for c in &desired.consumers {
        check(&c.namespace, "Consumer", &c.id);
    }
    for u in &desired.upstreams {
        check(&u.namespace, "Upstream", &u.id);
    }
    for p in &desired.plugin_configs {
        check(&p.namespace, "PluginConfig", &p.id);
    }
    if !violations.is_empty() {
        return Err(format!(
            "exclusive env '{}' declares ownership.namespaces={:?}, but desired resources include namespaces outside that list:\n  {}\nEither add the namespace to ownership.namespaces, remove the resource, or switch ownership.mode to 'shared'.",
            resolved.name,
            resolved.ownership.namespaces.as_deref().unwrap_or(&[]),
            violations.join("\n  ")
        )
        .into());
    }
    Ok(())
}

/// Resolve the active PR number for the current command invocation.
///
/// Order:
///   1. `GITFORGEOPS_PR_NUMBER` env var (set explicitly by review workflows).
///   2. For post-merge applies: the PR associated with `GITHUB_SHA` via the
///      `/repos/{repo}/commits/{sha}/pulls` endpoint. Requires GITHUB_TOKEN.
async fn resolve_pr_number(env_config: &EnvConfig) -> Option<u64> {
    if let Some(n) = std::env::var("GITFORGEOPS_PR_NUMBER")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Some(n);
    }
    let token = env_config.github_token.as_deref()?;
    let repo = env_config.github_repository.as_deref()?;
    let sha = std::env::var("GITHUB_SHA").ok()?;
    let client = reqwest::Client::builder()
        .user_agent("gitforgeops/0.1")
        .build()
        .ok()?;
    let url = format!("https://api.github.com/repos/{repo}/commits/{sha}/pulls");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let prs: Vec<serde_json::Value> = resp.json().await.ok()?;
    prs.first()
        .and_then(|pr| pr.get("number"))
        .and_then(|n| n.as_u64())
}

/// Generate + publish any credentials that need allocation or rotation, deliver
/// them to the PR author (or workflow actor), and re-resolve placeholders so
/// `desired` carries the real values for this apply run.
///
/// Returns the allocation outcome (or `None` if nothing needed allocation) and
/// the final post-allocation shard map (for state-file updates).
#[allow(clippy::too_many_arguments)]
/// Field names whose diff values must never be printed verbatim. These
/// carry secret material — consumer credentials hold API keys, JWT
/// signing keys, HMAC secrets, etc. Once resolved from the bundle, the
/// values ARE the secret. `cmd_diff` echoes to stdout which is captured
/// in CI logs (especially drift-check.yml), so printing them would
/// exfiltrate secrets through a side channel.
fn is_sensitive_field(kind: &str, field: &str) -> bool {
    matches!((kind, field), ("Consumer", "credentials"))
}

/// Append `comment` to `$GITHUB_STEP_SUMMARY` when running under GitHub
/// Actions. The step summary is always writable, so this is a reliable
/// fallback when PR comment posting is blocked (fork PRs, read-only
/// tokens). No-op when the env var is unset (local runs).
fn write_review_to_step_summary(comment: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = match std::env::var("GITHUB_STEP_SUMMARY") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return Ok(()),
    };
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(
        file,
        "> _PR comment posting was blocked (typical on fork PRs). The review is shown below as a step summary fallback._\n"
    )?;
    file.write_all(comment.as_bytes())?;
    if !comment.ends_with('\n') {
        writeln!(file)?;
    }
    Ok(())
}

/// Emit the age-armored ciphertext for each newly-allocated slot so the
/// recipient can decrypt. Without this, the allocator produced encrypted
/// blobs and the binary logged only the recipient's SSH fingerprint — the
/// actual ciphertext was dropped, so the "delivery" was recorded in state
/// but never reached the user.
///
/// Delivery routing:
/// - If `GITFORGEOPS_PR_NUMBER`, `GITHUB_TOKEN`, and `GITHUB_REPOSITORY` are
///   all set, post as a PR comment (so the PR author sees it even after
///   merge).
/// - Otherwise, print to stdout with decrypt instructions. Local runs and
///   non-PR-driven applies (direct push to main) take this path.
async fn surface_delivered_credentials(
    env_config: &EnvConfig,
    outcome: &secrets::AllocateOutcome,
) -> Result<(), Box<dyn std::error::Error>> {
    if outcome.allocated.is_empty() {
        return Ok(());
    }

    let mut body = String::from("## GitForgeOps — New Credentials Allocated\n\n");
    body.push_str(
        "The credentials below were generated during apply. Each blob is age-encrypted to the recipient's GitHub-published SSH key. Decrypt locally:\n\n",
    );
    body.push_str("```\nage -d -i ~/.ssh/id_ed25519 < blob.age\n```\n\n");

    let mut undelivered: Vec<&str> = Vec::new();

    for slot in &outcome.allocated {
        body.push_str(&format!("### `{}`\n\n", slot.slot));
        match &slot.delivered {
            Some(d) => {
                body.push_str(&format!(
                    "Encrypted to **@{}** (SSH fingerprint `{}`):\n\n",
                    d.login, d.key_fingerprint
                ));
                body.push_str("```\n");
                body.push_str(&d.encrypted_b64);
                if !d.encrypted_b64.ends_with('\n') {
                    body.push('\n');
                }
                body.push_str("```\n\n");
            }
            None => {
                undelivered.push(slot.slot.as_str());
                body.push_str(
                    "**NOT DELIVERED** — the recipient had no SSH key on file or was not provided. Run `gitforgeops rotate` after adding an SSH key to deliver the value.\n\n",
                );
            }
        }
    }

    let pr_number = std::env::var("GITFORGEOPS_PR_NUMBER")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let can_post_pr = pr_number.is_some()
        && env_config.github_token.is_some()
        && env_config.github_repository.is_some();

    if let (Some(pr), true) = (pr_number, can_post_pr) {
        match review::post_pr_comment(env_config, pr, &body).await {
            Ok(()) => {
                eprintln!(
                    "Posted encrypted credential delivery to PR #{pr} ({} slot(s)).",
                    outcome.allocated.len()
                );
                return Ok(());
            }
            Err(e) => {
                // Fall through to stdout — losing the blob is worse than
                // double-printing it.
                eprintln!(
                    "Warning: failed to post credentials to PR #{pr}: {e}. Falling back to stdout."
                );
            }
        }
    }

    // Stdout fallback. Also warn if any slots weren't delivered at all.
    println!();
    println!("{}", body);
    if !undelivered.is_empty() {
        eprintln!(
            "Warning: {} slot(s) could not be delivered (no recipient SSH key): {}",
            undelivered.len(),
            undelivered.join(", ")
        );
    }
    Ok(())
}

async fn allocate_if_needed(
    desired: &mut GatewayConfig,
    env_config: &EnvConfig,
    resolved: &ResolvedEnv,
    report: &secrets::ResolveReport,
    per_shard: &mut BTreeMap<u32, secrets::CredentialBundle>,
    shard_count: &mut u32,
) -> Result<Option<secrets::AllocateOutcome>, Box<dyn std::error::Error>> {
    if report.needs_allocation().is_empty() {
        return Ok(None);
    }

    let token = env_config
        .github_provisioner_token
        .as_deref()
        .ok_or("FERRUM_GH_PROVISIONER_TOKEN not set; cannot allocate credential slots")?;
    let repo = env_config
        .github_repository
        .as_deref()
        .ok_or("GITHUB_REPOSITORY not set; cannot write to GitHub Environment Secrets")?;

    let recipient = std::env::var("GITFORGEOPS_ACTOR").ok();

    let client = reqwest::Client::builder()
        .user_agent("gitforgeops/0.1")
        .build()
        .map_err(|e| gitforgeops::error::Error::HttpClient(e.to_string()))?;

    let outcome = secrets::allocate_and_deliver(
        &client,
        repo,
        &resolved.name,
        token,
        recipient.as_deref(),
        report,
        per_shard,
        shard_count,
    )
    .await?;

    // Re-resolve so desired picks up the generated values. Use the rotate-
    // aware variant: the initial resolve left rotate placeholders in place so
    // the allocator could produce a fresh value; now that the bundle has
    // fresh values, rotate placeholders are safe to replace.
    let merged = secrets::merge_bundles(per_shard);
    let _ = secrets::resolve_secrets_including_rotate(desired, &merged)?;

    Ok(Some(outcome))
}

/// Load per-namespace (desired, actual) pairs from the gateway for the given
/// namespace list.
///
/// Unlike the old `namespace_filter`-based walk, this iterates an explicit
/// list, so exclusive-mode apply can reconcile namespaces that the repo has
/// emptied (still need to fetch gateway state to prune). For shared mode, the
/// caller passes the namespaces present in `desired` (or a single-element list
/// for a namespace filter).
async fn load_namespace_pairs_for(
    client: &AdminClient,
    desired: &GatewayConfig,
    namespaces: &[String],
) -> gitforgeops::error::Result<Vec<(String, GatewayConfig, GatewayConfig)>> {
    let mut pairs = Vec::new();
    for namespace in namespaces {
        let desired_namespace = config::filter_config_by_namespace(desired, namespace);
        let actual_namespace = client.get_backup(namespace).await?;
        pairs.push((namespace.clone(), desired_namespace, actual_namespace));
    }
    Ok(pairs)
}

fn compute_namespace_diffs(
    namespace_pairs: &[(String, GatewayConfig, GatewayConfig)],
    previously_managed: Option<&HashSet<String>>,
) -> (
    Vec<diff::ResourceDiff>,
    Vec<diff::BreakingChange>,
    Vec<diff::UnmanagedResource>,
) {
    let mut diffs = Vec::new();
    let mut breaking = Vec::new();
    let mut unmanaged = Vec::new();

    for (_, desired_namespace, actual_namespace) in namespace_pairs {
        let result = diff::compute_diff_with_ownership(
            desired_namespace,
            actual_namespace,
            previously_managed,
        );
        let namespace_breaking =
            diff::detect_breaking_changes(&result.diffs, desired_namespace, actual_namespace);

        diffs.extend(result.diffs);
        unmanaged.extend(result.unmanaged);
        breaking.extend(namespace_breaking);
    }

    (diffs, breaking, unmanaged)
}

fn previously_managed(resolved: &ResolvedEnv, state: &StateFile) -> Option<HashSet<String>> {
    match resolved.ownership.mode {
        OwnershipMode::Shared => Some(state.previously_managed_keys()),
        OwnershipMode::Exclusive => None,
    }
}

fn fmt_resolution_note(resolved: &ResolvedEnv, report: &secrets::ResolveReport) -> Option<String> {
    if report.results.is_empty() {
        return None;
    }
    let mut lines = vec![format!("Credential slots (env {}):", resolved.name)];
    for r in &report.results {
        let status = match r.status {
            secrets::SlotStatus::Resolved => "resolved",
            secrets::SlotStatus::NeedsAllocation => "needs-allocation",
            secrets::SlotStatus::NeedsRotation => "needs-rotation",
            secrets::SlotStatus::MissingRequired => "MISSING (required)",
        };
        lines.push(format!("  [{status}] {}", r.slot));
    }
    Some(lines.join("\n"))
}

fn cmd_validate(
    format: &str,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let mut gateway_config = load_and_assemble_for(&resolved)?;
    let _ = resolve_credentials(&mut gateway_config, &env_config)?;

    let result = validate::run_validation(&gateway_config, &env_config.edge_binary_path)?;
    let output_format = validate::OutputFormat::from_str_lossy(format);
    let formatted = validate::format_result(&result, output_format);

    print!("{}", formatted);

    if !result.success {
        process::exit(result.exit_code);
    }

    Ok(())
}

async fn cmd_export(
    output_path: Option<&str>,
    materialize: bool,
    encrypt_to: Option<&str>,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if encrypt_to.is_some() && !materialize {
        return Err(
            "`--encrypt-to` requires `--materialize` (encrypting placeholders is pointless)".into(),
        );
    }

    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let mut gateway_config = load_and_assemble_for(&resolved)?;

    if materialize {
        // Fail fast if credentials cannot be fully resolved — we don't want
        // to hand an admin a file that still has `${gh-env-secret:...}`
        // strings in it, and we won't allocate fresh secrets during export
        // (that's the job of `apply`).
        //
        // Resolve with the rotate-aware variant so a rotate placeholder
        // with a valid bundle entry is replaced (the prior `apply` wrote
        // the value into the bundle). Rotate placeholders that still have
        // no bundle entry stay in place and show up as "remaining" below.
        //
        // Don't trust the pre-resolve report's NeedsAllocation/NeedsRotation
        // classification for the pending check: `alloc=rotate` is always
        // classified as NeedsRotation regardless of whether the bundle
        // carries a value, so keying the check off that status would block
        // materialization forever on any config using rotate. Instead, run
        // the post-resolve config back through report_secrets with an
        // empty bundle — any placeholder still present in the config is a
        // truly-unresolved slot.
        let (bundle, _) = load_credential_bundles(&env_config)?;
        let _ = secrets::resolve_secrets_including_rotate(&mut gateway_config, &bundle)?;
        let remaining = secrets::report_secrets(&gateway_config, &BTreeMap::new())?;
        if !remaining.results.is_empty() {
            return Err(format!(
                "refusing to materialize: {} credential slot(s) have no value yet — run `gitforgeops apply` to allocate/rotate, then retry:\n  {}",
                remaining.results.len(),
                remaining
                    .results
                    .iter()
                    .map(|r| r.slot.as_str())
                    .collect::<Vec<_>>()
                    .join("\n  ")
            )
            .into());
        }
    }
    // When `!materialize`: skip resolve entirely so placeholder strings
    // remain as `${gh-env-secret:...}`. Output is safe to commit.

    let yaml = serde_yaml::to_string(&gateway_config)?;

    let payload: Vec<u8> = if let Some(login) = encrypt_to {
        let client = reqwest::Client::builder()
            .user_agent("gitforgeops/0.1")
            .build()
            .map_err(|e| gitforgeops::error::Error::HttpClient(e.to_string()))?;
        match secrets::deliver_to_author(&client, login, yaml.as_bytes()).await? {
            Some(delivery) => {
                eprintln!(
                    "Encrypted to @{} (ssh key {})",
                    delivery.login, delivery.key_fingerprint
                );
                delivery.encrypted_b64.into_bytes()
            }
            None => {
                return Err(format!(
                    "@{login} has no compatible SSH public keys on GitHub; cannot encrypt. Ask them to add an Ed25519 or RSA key at https://github.com/settings/keys."
                )
                .into());
            }
        }
    } else {
        yaml.into_bytes()
    };

    match output_path {
        Some(path) => {
            if let Some(parent) = PathBuf::from(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::File::create(path)?;
            file.write_all(&payload)?;
            eprintln!("Exported to {}", path);
        }
        None => {
            std::io::stdout().write_all(&payload)?;
        }
    }

    Ok(())
}

async fn cmd_diff(
    exit_on_drift: bool,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let mut desired = load_and_assemble_for(&resolved)?;
    enforce_exclusive_scope(&resolved, &desired)?;
    let _ = resolve_credentials(&mut desired, &env_config)?;
    let client = AdminClient::new(&env_config)?;
    let state = StateFile::load(&resolved.name);
    let managed = previously_managed(&resolved, &state);
    let namespaces = resolved_namespaces(&resolved, &desired, &state);
    let namespace_pairs = load_namespace_pairs_for(&client, &desired, &namespaces).await?;
    let (diffs, _breaking, unmanaged) = compute_namespace_diffs(&namespace_pairs, managed.as_ref());

    if diffs.is_empty() && unmanaged.is_empty() {
        println!("No differences found. Configuration is in sync.");
        return Ok(());
    }

    if !diffs.is_empty() {
        println!("Found {} difference(s):\n", diffs.len());
        for d in &diffs {
            let action = match d.action {
                diff::DiffAction::Add => "ADD",
                diff::DiffAction::Modify => "MODIFY",
                diff::DiffAction::Delete => "DELETE",
            };
            println!("  {} {} {} ({})", action, d.kind, d.id, d.namespace);
            for change in &d.details {
                if is_sensitive_field(&d.kind, &change.field) {
                    // Credentials carry actual secret material (rotated
                    // values, generated keys). Printing them here would
                    // leak to CI logs — drift-check.yml echoes stdout
                    // into the workflow log, which is viewable by anyone
                    // with read access to the run.
                    println!("    {}: [REDACTED] -> [REDACTED]", change.field);
                } else {
                    println!(
                        "    {}: {} -> {}",
                        change.field, change.old_value, change.new_value
                    );
                }
            }
        }
    }

    if !unmanaged.is_empty() && resolved.ownership.drift_report {
        println!(
            "\nUnmanaged resources (mode: {:?}, not touched by apply):",
            resolved.ownership.mode
        );
        for u in &unmanaged {
            println!("  {} {} ({})", u.kind, u.id, u.namespace);
        }
    }

    // Honor drift_alert_on flags so operators can selectively suppress
    // categories (e.g. a noisy staging env where only destructive changes
    // should alert). Only categories with their flag set contribute to the
    // drift decision.
    let alert = &resolved.ownership.drift_alert_on;
    let managed_modify_or_add = diffs
        .iter()
        .any(|d| matches!(d.action, diff::DiffAction::Modify | diff::DiffAction::Add));
    let managed_delete = diffs
        .iter()
        .any(|d| matches!(d.action, diff::DiffAction::Delete));
    let has_drift = (alert.managed_modified && managed_modify_or_add)
        || (alert.managed_deleted && managed_delete)
        || (alert.unmanaged_added && !unmanaged.is_empty());

    if exit_on_drift && has_drift {
        process::exit(2);
    }

    Ok(())
}

async fn cmd_plan(explicit_env: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let mut desired = load_and_assemble_for(&resolved)?;
    // Plan must see the same scope/validation errors as apply would hit, so
    // the preview matches reality. Without this, a plan could print "None
    // (in sync)" for an exclusive env whose filter doesn't match ownership —
    // apply would then fail when the operator tries to act on the preview.
    enforce_exclusive_scope(&resolved, &desired)?;
    // Audit security BEFORE resolving credentials. audit_security flags
    // literal (non-placeholder) credential strings as a security issue
    // ("use ${...} for secrets"). If we resolve first, placeholders are
    // replaced with real values — which, post-substitution, look like
    // literals to the auditor. Running pre-resolve keeps the audit on
    // the repo's actual committed state.
    let security_findings = diff::audit_security(&desired);
    let secret_report = resolve_credentials(&mut desired, &env_config)?;

    println!("=== Environment ===");
    println!(
        "name={}  overlay={}  namespace_filter={}  strategy={:?}  ownership={:?}",
        resolved.name,
        resolved.overlay.as_deref().unwrap_or("<none>"),
        resolved.namespace_filter.as_deref().unwrap_or("<all>"),
        resolved.apply_strategy,
        resolved.ownership.mode,
    );
    println!();

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

    if let Some(note) = fmt_resolution_note(&resolved, &secret_report) {
        println!("=== Credentials ===");
        println!("{}\n", note);
    }

    let client = AdminClient::new(&env_config);
    let state = StateFile::load(&resolved.name);
    let managed = previously_managed(&resolved, &state);
    let namespaces = resolved_namespaces(&resolved, &desired, &state);
    let (diffs, breaking, unmanaged, actual_available) = match &client {
        Ok(c) => match load_namespace_pairs_for(c, &desired, &namespaces).await {
            Ok(namespace_pairs) => {
                let (d, b, u) = compute_namespace_diffs(&namespace_pairs, managed.as_ref());
                (d, b, u, true)
            }
            Err(e) => {
                eprintln!("Could not fetch live config: {}", e);
                (Vec::new(), Vec::new(), Vec::new(), false)
            }
        },
        Err(e) => {
            eprintln!("Could not create API client: {}", e);
            (Vec::new(), Vec::new(), Vec::new(), false)
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

    if !unmanaged.is_empty() && resolved.ownership.drift_report {
        println!("=== Unmanaged Resources ===");
        println!(
            "(mode={:?}; these exist on the gateway but were never managed by this repo)",
            resolved.ownership.mode
        );
        for u in &unmanaged {
            println!("  {} {} ({})", u.kind, u.id, u.namespace);
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

    // security_findings was computed pre-resolve above; reuse it here.
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

    if let Some(policy_cfg) = policy::load_policies()? {
        let policy_findings = policy::evaluate_policies(&desired, &policy_cfg);
        if !policy_findings.is_empty() {
            println!("=== Policy Violations ===");
            for pf in &policy_findings {
                println!(
                    "  [{}] {}: {} {} ({}): {}",
                    pf.severity.as_str(),
                    pf.rule_id,
                    pf.kind,
                    pf.id,
                    pf.namespace,
                    pf.message
                );
            }
            println!();
        }
    }

    if !validation_ok {
        process::exit(1);
    }

    Ok(())
}

async fn cmd_apply(
    auto_approve: bool,
    allow_large_prune: bool,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let mut desired = load_and_assemble_for(&resolved)?;

    // Exclusive ownership: enforce namespace scope before anything else so the
    // operator fails fast on a misconfigured resource, not deep in apply.
    enforce_exclusive_scope(&resolved, &desired)?;

    let mut state = StateFile::load(&resolved.name);

    // First resolve: classify placeholders with the current bundle.
    //
    // In file mode we MUST NOT mutate `desired`: the file-mode branch below
    // serializes `desired` to a committed-to-repo YAML, and replacing
    // placeholders with real bundle values here would leak credentials into
    // the committed artifact. `report_secrets` walks and classifies without
    // touching `cfg`.
    //
    // In api mode we want the mutation: apply_api pushes `desired` to the
    // gateway, which needs real values for already-allocated slots. The
    // allocator handles `alloc=generate` / `alloc=rotate` gaps afterward.
    let (_merged, mut per_shard) = load_credential_bundles(&env_config)?;
    let mut shard_count = state.credential_shard_count.max(1);
    let initial_bundle = secrets::merge_bundles(&per_shard);
    let secret_report = match env_config.gateway_mode {
        GatewayMode::File => secrets::report_secrets(&desired, &initial_bundle)?,
        GatewayMode::Api => secrets::resolve_secrets(&mut desired, &initial_bundle)?,
    };

    // Missing required credentials → fail fast before we touch the gateway.
    let missing = secret_report.missing_required();
    if !missing.is_empty() {
        eprintln!(
            "Refusing to apply: {} required credential slot(s) have no value:",
            missing.len()
        );
        for m in missing {
            eprintln!("  {}", m.slot);
        }
        process::exit(1);
    }

    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path);
    if let Ok(ref r) = val_result {
        if !r.success {
            eprintln!("Validation failed. Fix errors before applying.");
            process::exit(1);
        }
    }

    // Policy enforcement (with optional override). Overridden rule_ids are
    // captured here and written into state after a successful apply so audits
    // can see which blocking findings were bypassed by whom.
    let mut overridden_for_audit: Vec<(String, String)> = Vec::new();
    if let Some(policy_cfg) = policy::load_policies()? {
        let mut findings = policy::evaluate_policies(&desired, &policy_cfg);
        let pr_number = resolve_pr_number(&env_config).await;
        let override_decision = if let Some(pr) = pr_number {
            let d = policy::check_override(&env_config, &policy_cfg.overrides, pr).await?;
            policy::github_override::apply_override(&mut findings, &d);
            Some(d)
        } else {
            None
        };

        if let Some(d) = &override_decision {
            if d.active {
                if let Some(approver) = &d.approver {
                    for f in &findings {
                        if f.overridden_by.is_some() {
                            overridden_for_audit.push((f.rule_id.clone(), approver.clone()));
                        }
                    }
                }
            }
        }

        let blockers: Vec<_> = findings.iter().filter(|f| f.is_blocking()).collect();
        if !blockers.is_empty() {
            eprintln!(
                "Refusing to apply: {} unresolved policy violation(s):",
                blockers.len()
            );
            for b in blockers {
                eprintln!("  [{}] {}: {}", b.severity.as_str(), b.rule_id, b.message);
            }
            if let Some(d) = &override_decision {
                if !d.active {
                    eprintln!("(override inactive: {})", d.reason);
                }
            } else {
                eprintln!("(no PR associated with this commit; overrides not evaluated)");
            }
            process::exit(1);
        }
    }

    let is_first_apply = StateFile::is_first_apply(&resolved.name);
    if is_first_apply && matches!(resolved.ownership.mode, OwnershipMode::Shared) {
        eprintln!(
            "Notice: first apply for environment '{}' in shared mode. Resources on the gateway but not in this repo will be treated as unmanaged and left alone.",
            resolved.name
        );
    }

    let namespaces = resolved_namespaces(&resolved, &desired, &state);
    // Populated by both mode arms after their respective gates. State-record
    // reads this after the match to persist credential metadata.
    #[allow(unused_assignments)]
    let mut allocation: Option<secrets::AllocateOutcome> = None;

    match env_config.gateway_mode {
        GatewayMode::Api => {
            let client = AdminClient::new(&env_config)?;
            let managed = previously_managed(&resolved, &state);

            if !auto_approve {
                let namespace_pairs =
                    load_namespace_pairs_for(&client, &desired, &namespaces).await?;
                let (diffs, _, unmanaged) =
                    compute_namespace_diffs(&namespace_pairs, managed.as_ref());

                if diffs.is_empty()
                    && unmanaged.is_empty()
                    && secret_report.needs_allocation().is_empty()
                {
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
                if !unmanaged.is_empty() {
                    println!(
                        "\n{} unmanaged resource(s) on gateway (not touched in shared mode).",
                        unmanaged.len()
                    );
                }
                let pending_creds = secret_report.needs_allocation();
                if !pending_creds.is_empty() {
                    println!(
                        "\n{} credential slot(s) would be allocated/rotated on apply:",
                        pending_creds.len()
                    );
                    for r in pending_creds {
                        let kind = match r.status {
                            secrets::SlotStatus::NeedsAllocation => "new",
                            secrets::SlotStatus::NeedsRotation => "rotate",
                            _ => "",
                        };
                        println!("  [{kind}] {}", r.slot);
                    }
                }
                println!("\nUse --auto-approve to skip this check.");
                process::exit(0);
            }

            // Large-prune safety check runs BEFORE allocation. The check
            // inspects the diff against the placeholder-containing desired
            // (allocation would only replace string values, not change which
            // resources exist), so pruning behavior is unaffected. Placing
            // allocation after this gate means a blocked apply leaves GitHub
            // env secrets untouched — otherwise we'd burn a generated value
            // that the gateway never receives.
            let namespace_pairs = load_namespace_pairs_for(&client, &desired, &namespaces).await?;
            let (diffs, _, _) = compute_namespace_diffs(&namespace_pairs, managed.as_ref());
            let delete_count = diffs
                .iter()
                .filter(|d| matches!(d.action, diff::DiffAction::Delete))
                .count();
            // Only count managed resources in the namespaces we are actually
            // reconciling. A scoped apply (FERRUM_NAMESPACE=ferrum) that
            // deletes 100% of its namespace's resources would otherwise show
            // a tiny percentage of the cross-namespace total and slip under
            // the threshold — exactly the case the guard exists to catch.
            let managed_total = {
                let ns_set: std::collections::HashSet<&str> =
                    namespaces.iter().map(String::as_str).collect();
                state
                    .resources
                    .keys()
                    .filter(|k| {
                        let ns = k.split_once(':').map(|(n, _)| n).unwrap_or("");
                        ns_set.contains(ns)
                    })
                    .count()
                    .max(1)
            };
            let delete_pct = (delete_count * 100) / managed_total;
            let threshold = resolved.ownership.large_prune_threshold_percent as usize;
            if delete_pct > threshold && !allow_large_prune {
                eprintln!(
                    "Refusing to apply: would delete {}% of managed resources (threshold {}%). Re-run with --allow-large-prune to proceed.",
                    delete_pct, threshold
                );
                process::exit(1);
            }

            // All safety gates passed — now allocate/rotate credentials.
            allocation = allocate_if_needed(
                &mut desired,
                &env_config,
                &resolved,
                &secret_report,
                &mut per_shard,
                &mut shard_count,
            )
            .await?;

            if let Some(outcome) = &allocation {
                eprintln!(
                    "Allocated/rotated {} credential slot(s):",
                    outcome.allocated.len()
                );
                for slot in &outcome.allocated {
                    match &slot.delivered {
                        Some(d) => eprintln!(
                            "  {} -> @{} (ssh {})",
                            slot.slot, d.login, d.key_fingerprint
                        ),
                        None => eprintln!(
                            "  {} -> NOT DELIVERED (no recipient or no compatible SSH key)",
                            slot.slot
                        ),
                    }
                }
            }

            let result = apply::apply_api(
                &desired,
                &client,
                resolved.apply_strategy.clone(),
                &namespaces,
                managed.as_ref(),
            )
            .await?
            .into_result()?;

            println!(
                "Applied: {} created, {} updated, {} deleted, {} unmanaged skipped",
                result.created, result.updated, result.deleted, result.unmanaged_skipped
            );

            // Apply succeeded — now surface the encrypted delivery blobs.
            // `allocate_if_needed` already produced the age-armored ciphertext
            // for each new/rotated slot; without this step it was logged and
            // discarded, so the recipient never had a way to retrieve the
            // secret. Prefer PR comment (post-merge PR still accepts
            // comments); fall back to stdout for local runs.
            if let Some(outcome) = &allocation {
                surface_delivered_credentials(&env_config, outcome).await?;
            }
        }
        GatewayMode::File => {
            // File mode has no gateway diff or auto-approve gate in the
            // normal sense, but it DOES have a side-effecting allocation
            // step. Preserve the same plan-preview semantics so a dry-run
            // can inspect pending allocations without writing to GitHub.
            let pending = secret_report.needs_allocation();
            if !auto_approve && !pending.is_empty() {
                println!(
                    "Would write placeholder file to {} and allocate/rotate {} credential slot(s):",
                    env_config.file_output_path,
                    pending.len()
                );
                for r in pending {
                    let kind = match r.status {
                        secrets::SlotStatus::NeedsAllocation => "new",
                        secrets::SlotStatus::NeedsRotation => "rotate",
                        _ => "",
                    };
                    println!("  [{kind}] {}", r.slot);
                }
                println!("\nUse --auto-approve to proceed.");
                process::exit(0);
            }

            // Write the placeholder-preserving file FIRST. `desired` still
            // has `${gh-env-secret:...}` strings because the initial resolve
            // doesn't replace rotate placeholders and the allocator hasn't
            // run yet. This is the committed-to-repo form; the real values
            // come via the separate `materialize-file.yml` workflow.
            apply::apply_file(&desired, &env_config.file_output_path)?;
            println!("Written to {}", env_config.file_output_path);

            // Now allocate. The in-memory mutation after the disk write is
            // harmless — the file has already been serialized with
            // placeholders intact, and the allocated values go to the
            // GitHub Env Secret for `materialize` to consume.
            allocation = allocate_if_needed(
                &mut desired,
                &env_config,
                &resolved,
                &secret_report,
                &mut per_shard,
                &mut shard_count,
            )
            .await?;

            if let Some(outcome) = &allocation {
                surface_delivered_credentials(&env_config, outcome).await?;
            }
        }
    }

    // Scoped record: only overwrite entries for namespaces we just
    // reconciled. In shared mode with multiple namespaces and a scoped
    // apply (e.g. FERRUM_NAMESPACE=ferrum), the previous clear-all
    // behavior dropped managed-resource hashes for every other namespace
    // — next diff would classify those as unmanaged and stop reconciling.
    state.record(&desired, &namespaces);
    state.credential_shard_count = shard_count;
    if let Some(outcome) = &allocation {
        let run_id = std::env::var("GITHUB_RUN_ID").ok();
        for slot in &outcome.allocated {
            state.record_credential(
                &slot.slot,
                slot.shard,
                &slot.value,
                slot.delivered.as_ref().map(|d| d.login.as_str()),
                run_id.as_deref(),
            );
        }
    }
    if !overridden_for_audit.is_empty() {
        let commit = state
            .last_applied_commit
            .clone()
            .or_else(|| std::env::var("GITHUB_SHA").ok())
            .unwrap_or_default();
        for (rule_id, approver) in &overridden_for_audit {
            state.record_override(rule_id, &commit, approver);
        }
    }
    state.save()?;

    Ok(())
}

async fn cmd_import(
    from_api: Option<&str>,
    from_file: Option<&str>,
    output_dir: &str,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = PathBuf::from(output_dir);
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;

    let result = if from_api.is_some() {
        let client = AdminClient::new(&env_config)?;
        import::import_from_api(&client, &output_path, resolved.namespace_filter.as_deref()).await?
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

async fn cmd_review(
    pr: Option<u64>,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let mut desired = load_and_assemble_for(&resolved)?;
    // PR review preview must match apply's real validation surface, so a
    // reviewer looking at the comment sees the same errors the post-merge
    // apply would produce.
    enforce_exclusive_scope(&resolved, &desired)?;
    // Audit pre-resolve so placeholder-resolved values aren't misreported as
    // literal credentials (see cmd_plan for full rationale).
    let security_findings = diff::audit_security(&desired);
    let secret_report = resolve_credentials(&mut desired, &env_config)?;

    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path);
    let (validation_ok, validation_output) = match &val_result {
        Ok(r) => (r.success, format!("{}{}", r.stdout, r.stderr)),
        Err(e) => (true, format!("Validation skipped: {}", e)),
    };

    let client = AdminClient::new(&env_config);
    let state = StateFile::load(&resolved.name);
    let managed = previously_managed(&resolved, &state);
    let namespaces = resolved_namespaces(&resolved, &desired, &state);

    let (diffs, breaking, unmanaged, comparison_error) = match &client {
        Ok(c) => match load_namespace_pairs_for(c, &desired, &namespaces).await {
            Ok(namespace_pairs) => {
                let (d, b, u) = compute_namespace_diffs(&namespace_pairs, managed.as_ref());
                (d, b, u, None)
            }
            Err(e) => (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Some(format!("Live gateway comparison skipped: {}", e)),
            ),
        },
        Err(e) => (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(format!("Live gateway comparison skipped: {}", e)),
        ),
    };

    // security_findings was computed pre-resolve above; reuse it here.
    let bp_findings = diff::check_best_practices(&desired);

    let (policy_findings, override_reason, override_cfg) = match policy::load_policies()? {
        Some(policy_cfg) => {
            let mut findings = policy::evaluate_policies(&desired, &policy_cfg);
            let decision = match pr {
                Some(pr_number) => {
                    let d = policy::check_override(&env_config, &policy_cfg.overrides, pr_number)
                        .await?;
                    policy::github_override::apply_override(&mut findings, &d);
                    Some(d)
                }
                None => None,
            };
            (
                findings,
                decision.map(|d| d.reason),
                Some(policy_cfg.overrides),
            )
        }
        None => (Vec::new(), None, None),
    };

    let ownership_note = format!(
        "Environment: `{}` · Ownership: `{:?}` · Strategy: `{:?}`",
        resolved.name, resolved.ownership.mode, resolved.apply_strategy
    );

    let bundle_loaded = env_config
        .creds_bundle_json_file
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        || env_config
            .creds_bundle_json
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

    let comment = review::build_review_comment_v2(
        validation_ok,
        &validation_output,
        &diffs,
        &breaking,
        &security_findings,
        &bp_findings,
        &policy_findings,
        &unmanaged,
        override_reason.as_deref(),
        override_cfg.as_ref(),
        comparison_error.as_deref(),
        Some(&ownership_note),
        &secret_report,
        bundle_loaded,
    );

    match pr {
        Some(pr_number) => {
            // Fork PRs: GITHUB_TOKEN is downgraded to read-only by GitHub
            // regardless of the workflow's `permissions:` block, so the
            // POST to /issues/{n}/comments returns 403. We still want the
            // review content visible, so fall back to $GITHUB_STEP_SUMMARY
            // (which the runner always lets us write) and to stdout.
            // Never fail the job on a delivery-channel error — the
            // validation itself succeeded; only the report delivery didn't.
            match review::post_pr_comment(&env_config, pr_number, &comment).await {
                Ok(()) => {
                    println!("Posted review comment to PR #{}", pr_number);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: could not post PR comment (typical on fork PRs where GITHUB_TOKEN is read-only): {e}"
                    );
                    write_review_to_step_summary(&comment)?;
                    print!("{}", comment);
                }
            }
        }
        None => {
            print!("{}", comment);
        }
    }

    let _ = !secret_report.results.is_empty();
    Ok(())
}

fn cmd_envs(format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let repo = load_repo_config()?;
    let names = match repo {
        Some(r) => r.environment_names(),
        None => vec![ResolvedEnv::default_env_name()],
    };
    match format {
        "text" => {
            for n in names {
                println!("{n}");
            }
        }
        _ => {
            println!("{}", serde_json::to_string(&names)?);
        }
    }
    Ok(())
}

async fn cmd_rotate(
    consumer: &str,
    credential: &str,
    namespace: Option<&str>,
    recipient: Option<&str>,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;

    let repo = env_config
        .github_repository
        .clone()
        .ok_or_else(|| gitforgeops::error::Error::Config("GITHUB_REPOSITORY not set".into()))?;
    let token = env_config.github_provisioner_token.clone().ok_or_else(|| {
        gitforgeops::error::Error::Config("FERRUM_GH_PROVISIONER_TOKEN not set".into())
    })?;

    // Load current bundle to know shard layout.
    // Use the shared helper so both FERRUM_CREDS_JSON (inline) and
    // FERRUM_CREDS_JSON_FILE (path) are honored. The workflow uses the file
    // form — reading only the inline var left per_shard empty, and
    // rotate_and_deliver would then write a shard containing ONLY the
    // rotated slot, overwriting every other slot in that shard on GitHub.
    let (_merged, mut per_shard) = load_credential_bundles(&env_config)?;

    let mut state = StateFile::load(&resolved.name);
    let ns = namespace.unwrap_or("ferrum");
    let slot = secrets::resolver::slot_path(ns, consumer, credential);

    // ALL preflight checks must run BEFORE rotate_and_deliver mutates the
    // GitHub Environment Secret. If any of these fire after the secret is
    // written, we've corrupted the store for a rotation that can't complete
    // — the new value lives in GitHub, the gateway still has the old one,
    // and the state file isn't updated because the push eventually fails.
    //
    // Preflight 1: gateway mode must be api. File mode has no gateway to
    // push to; rotation in file mode has no completion path.
    if !matches!(env_config.gateway_mode, GatewayMode::Api) {
        return Err(
            "Refusing to rotate: gateway_mode is 'file'. Rotation requires a live Admin API to push the new value. Use the materialize-file.yml workflow to get a new flat file for file-mode gateways."
                .into(),
        );
    }

    let desired_for_check = load_and_assemble_for(&resolved)?;

    // Preflight 2: target slot corresponds to an actual placeholder in the
    // repo. A typo in --credential or pointing at a literal value would
    // otherwise write random bytes into an orphaned Env Secret with no
    // gateway-side reference.
    let empty_bundle = BTreeMap::new();
    let placeholder_report = secrets::report_secrets(&desired_for_check, &empty_bundle)?;
    let target_placeholder = placeholder_report.results.iter().find(|r| r.slot == slot);
    let placeholder_length = match target_placeholder {
        Some(r) => r.placeholder.length_bytes,
        None => {
            return Err(format!(
                "Refusing to rotate: no `${{gh-env-secret:...}}` placeholder at slot '{slot}'.\n\
                 Rotate only operates on consumer credential fields that reference a placeholder in\n\
                 the repo. Check that consumer '{consumer}' in namespace '{ns}' has a credential\n\
                 key '{credential}' whose value is a gh-env-secret placeholder."
            )
            .into());
        }
    };

    // Preflight 3: target consumer is declared in the repo. Without this,
    // rotate_and_deliver writes a secret the gateway push will then refuse
    // because there's no consumer to update.
    let target_consumer_exists = desired_for_check
        .consumers
        .iter()
        .any(|c| c.namespace == ns && c.id == consumer);
    if !target_consumer_exists {
        return Err(format!(
            "Refusing to rotate: consumer '{ns}/{consumer}' is not present in repo desired state. Add the consumer to resources/ first."
        )
        .into());
    }

    // Preflight 4: no OTHER placeholders on this consumer remain unresolved
    // against the current bundle. If they did, push_rotated_consumer_to_gateway
    // would fail (by design) and leave the store/gateway split — mutating
    // GitHub before running the check just guarantees that split happens.
    let current_bundle = secrets::merge_bundles(&per_shard);
    let sibling_consumer = desired_for_check
        .consumers
        .iter()
        .find(|c| c.namespace == ns && c.id == consumer)
        .cloned();
    if let Some(mut c) = sibling_consumer {
        let mut single = gitforgeops::config::GatewayConfig::default();
        // Note: replace the target slot as if it were already rotated, so
        // sibling-placeholder detection doesn't flag the slot we're about
        // to rotate.
        let mut shim_bundle = current_bundle.clone();
        shim_bundle.insert(slot.clone(), "__rotate-preflight-shim__".to_string());
        single.consumers.push(c.clone());
        let _ = secrets::resolve_secrets_including_rotate(&mut single, &shim_bundle)?;
        c = single.consumers.remove(0);
        let mut remaining_cfg = gitforgeops::config::GatewayConfig::default();
        remaining_cfg.consumers.push(c);
        let sibling_report = secrets::report_secrets(&remaining_cfg, &BTreeMap::new())?;
        if !sibling_report.results.is_empty() {
            return Err(format!(
                "Refusing to rotate: consumer '{ns}/{consumer}' has {} other unresolved placeholder(s):\n  {}\n\
                 Run `gitforgeops apply` to allocate missing slots before rotating — otherwise the gateway push would fail after the new secret is already written.",
                sibling_report.results.len(),
                sibling_report.results.iter().map(|r| r.slot.as_str()).collect::<Vec<_>>().join("\n  ")
            )
            .into());
        }
    }

    let mut shard_count = state.credential_shard_count.max(1);

    let client = Client::builder()
        .user_agent("gitforgeops/0.1")
        .build()
        .map_err(|e| gitforgeops::error::Error::HttpClient(e.to_string()))?;

    let outcome = secrets::rotate_and_deliver(
        &client,
        &repo,
        &resolved.name,
        &token,
        recipient,
        &slot,
        placeholder_length,
        &mut per_shard,
        &mut shard_count,
    )
    .await?;

    // The rotation wrote a fresh value to the GitHub Environment Secret and
    // (optionally) delivered it to the recipient. The live gateway still
    // validates the OLD value until we push the new one. Push the updated
    // consumer now so the rotation is immediately usable — skipping this
    // step locks the recipient out until someone else triggers apply.
    let push_status =
        push_rotated_consumer_to_gateway(&env_config, &resolved, &per_shard, ns, consumer).await;

    // Persist rotation state ONLY on full success. Saving before the gateway
    // push check would claim the rotation completed even when the gateway
    // never received the new value — audits would show "rotated at T" while
    // the old credential kept authenticating. On failure, leave state alone;
    // the next successful `gitforgeops apply` (which picks up the fresh
    // bundle value naturally) or re-rotate will record accurate metadata.
    match push_status {
        Ok(()) => {
            state.credential_shard_count = shard_count;
            state.record_credential(
                &slot,
                outcome.shard,
                &outcome.value,
                outcome.delivered.as_ref().map(|d| d.login.as_str()),
                std::env::var("GITHUB_RUN_ID").ok().as_deref(),
            );
            state.save()?;
            println!("Rotated slot {slot} in shard {}", outcome.shard);
            println!("Gateway consumer '{}/{}' updated.", ns, consumer);
        }
        Err(e) => {
            // Hard-fail: the credential store and gateway are out of sync.
            // We already delivered the new value to the recipient; returning
            // Ok would trick the caller into thinking rotation succeeded.
            return Err(format!(
                "Rotated credential stored (GitHub Env Secret) + delivered, but gateway push FAILED: {e}\n\
                 State NOT persisted (the gateway still has the old value). The new value lives\n\
                 in the GitHub Env Secret; run `gitforgeops apply` to push it through and record\n\
                 rotation metadata. If the recipient tries to authenticate with the new value\n\
                 before apply runs, they will be rejected."
            )
            .into());
        }
    }

    match outcome.delivered {
        Some(d) => {
            println!(
                "Delivered age-encrypted blob to @{} (ssh key {}):\n",
                d.login, d.key_fingerprint
            );
            println!("{}", d.encrypted_b64);
        }
        None => {
            if recipient.is_some() {
                println!("Warning: recipient had no compatible SSH keys; secret written but not delivered.");
            }
        }
    }

    Ok(())
}

/// Push just the rotated consumer to the live gateway so the new credential
/// is immediately usable. Loads desired config, resolves placeholders against
/// the post-rotation bundle (including rotate slots), finds the target
/// consumer, and calls `update_consumer`.
async fn push_rotated_consumer_to_gateway(
    env_config: &EnvConfig,
    resolved: &ResolvedEnv,
    per_shard: &BTreeMap<u32, secrets::CredentialBundle>,
    namespace: &str,
    consumer_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(env_config.gateway_mode, GatewayMode::Api) {
        return Err("rotate requires gateway_mode=api; file-mode cannot push credentials".into());
    }

    let mut desired = load_and_assemble_for(resolved)?;
    let merged = secrets::merge_bundles(per_shard);
    // Use the rotate-aware variant so rotate placeholders pick up the fresh
    // value that rotate_and_deliver just wrote into the bundle.
    let _ = secrets::resolve_secrets_including_rotate(&mut desired, &merged)?;

    let consumer = desired
        .consumers
        .iter()
        .find(|c| c.namespace == namespace && c.id == consumer_id)
        .ok_or_else(|| {
            format!(
                "consumer '{namespace}/{consumer_id}' not present in repo desired state; cannot push rotated credential. Add the consumer to resources/ first, or if it was intentionally removed, rotation has no consumer to update."
            )
        })?;

    // Guard: the consumer may carry OTHER credentials besides the one we
    // just rotated. If any of those other credentials are placeholders
    // without a bundle value (e.g. alloc=require that was never
    // pre-populated, or alloc=generate never run through apply), pushing
    // the consumer now would send a literal `${gh-env-secret:...}` string
    // to the gateway as a credential value — breaking auth for that
    // credential. Refuse and tell the operator to run apply first.
    let single_consumer_cfg = gitforgeops::config::GatewayConfig {
        consumers: vec![consumer.clone()],
        ..Default::default()
    };
    let remaining = secrets::report_secrets(&single_consumer_cfg, &BTreeMap::new())?;
    if !remaining.results.is_empty() {
        return Err(format!(
            "refusing to push rotated consumer '{namespace}/{consumer_id}': {} unresolved placeholder(s) remain on this consumer:\n  {}\n\
             Run `gitforgeops apply` to allocate missing slots before rotating (or pre-populate FERRUM_CREDS_JSON).",
            remaining.results.len(),
            remaining.results.iter().map(|r| r.slot.as_str()).collect::<Vec<_>>().join("\n  ")
        ).into());
    }

    let client = AdminClient::new(env_config)?;
    client.update_consumer(consumer, namespace).await?;
    Ok(())
}
