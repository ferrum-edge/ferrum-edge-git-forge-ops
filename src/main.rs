use std::collections::{BTreeMap, HashSet};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process;

use clap::Parser;

use gitforgeops::apply;
use gitforgeops::cli;
use gitforgeops::config::{
    self, resolve_env, EnvConfig, GatewayConfig, GatewayMode, OwnershipMode, RepoConfig,
    ResolvedEnv,
};
use gitforgeops::diff;
use gitforgeops::http_client::AdminClient;
use gitforgeops::import;
use gitforgeops::policy;
use gitforgeops::reconcile::{previously_managed, resolved_namespaces};
use gitforgeops::review;
use gitforgeops::secrets;
use gitforgeops::state::StateFile;
use gitforgeops::validate;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = cli::Cli::parse();
    let explicit_env = cli.env.clone();

    let result = match cli.command {
        cli::Commands::Validate { format } => {
            cmd_validate(validate_format(format), explicit_env.as_deref())
        }
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
            confirm_api_spec_deletion,
        } => {
            cmd_apply(
                auto_approve,
                allow_large_prune,
                confirm_api_spec_deletion,
                explicit_env.as_deref(),
            )
            .await
        }
        cli::Commands::Import {
            from_api,
            from_file,
            output_dir,
            credential_bundle_output,
        } => {
            cmd_import(
                from_api,
                from_file.as_deref(),
                &output_dir,
                credential_bundle_output.as_deref(),
                explicit_env.as_deref(),
            )
            .await
        }
        cli::Commands::Review { pr, require_live } => {
            cmd_review(pr, require_live, explicit_env.as_deref()).await
        }
        cli::Commands::Envs {
            format,
            include_scopes,
        } => cmd_envs(format, include_scopes),
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

fn validate_format(format: cli::ValidateFormat) -> validate::OutputFormat {
    match format {
        cli::ValidateFormat::Text => validate::OutputFormat::Text,
        cli::ValidateFormat::Json => validate::OutputFormat::Json,
        cli::ValidateFormat::Github | cli::ValidateFormat::GithubAnnotations => {
            validate::OutputFormat::GithubAnnotations
        }
    }
}

fn load_repo_config() -> Result<Option<RepoConfig>, Box<dyn std::error::Error>> {
    Ok(RepoConfig::load()?)
}

fn resolve_runtime(
    explicit_env: Option<&str>,
) -> Result<(EnvConfig, ResolvedEnv, Option<RepoConfig>), Box<dyn std::error::Error>> {
    let env_config = config::load_env_config()?;
    let repo = load_repo_config()?;
    let resolved = resolve_env(repo.as_ref(), &env_config, explicit_env)?;
    Ok((env_config, resolved, repo))
}

/// Load, overlay and assemble the repo into the gateway document plus the
/// optional standalone mesh document.
///
/// Most commands only care about the gateway half and take `.gateway`;
/// `validate`, `plan`, `export` and file-mode `apply` also act on `.mesh`.
fn load_and_assemble_all(
    resolved: &ResolvedEnv,
) -> Result<config::AssembledOutput, Box<dyn std::error::Error>> {
    let resources_dir = PathBuf::from("./resources");
    let mut resources = config::load_resources(&resources_dir)?;

    if let Some(ref overlay_name) = resolved.overlay {
        let overlay_dir = PathBuf::from("./overlays").join(overlay_name);
        config::apply_overlay(&mut resources, &overlay_dir)?;
    }

    // The namespace filter is applied to mesh fragments during assembly (a
    // mesh fragment's directory is its only namespace handle) and to gateway
    // resources afterwards, on their effective namespace (which a spec may
    // override).
    let assembled =
        config::assemble_with_namespace_filter(resources, resolved.namespace_filter.as_deref())?;
    let gateway_config =
        config::select_config_namespace(&assembled.gateway, resolved.namespace_filter.as_deref());
    config::validate_unique_resource_keys(&gateway_config)?;
    // `api_spec_id` is generated by the gateway's API-spec importer. Reject a
    // repository-authored tag at the shared load boundary so validate, plan,
    // diff, review, export and file-mode apply fail on the originating PR,
    // instead of waiting for post-merge API apply to discover it.
    apply::validate_no_desired_spec_tags(&gateway_config)?;
    Ok(config::AssembledOutput {
        gateway: gateway_config,
        mesh: assembled.mesh,
    })
}

/// [`load_and_assemble_all`] for the commands that only reconcile gateway
/// resources. Mesh config has no live admin API, so `diff`, `review` and
/// `rotate` have nothing to do with it.
fn load_and_assemble_for(
    resolved: &ResolvedEnv,
) -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    Ok(load_and_assemble_all(resolved)?.gateway)
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
/// `alloc=rotate` placeholders are resolved with their stored bundle values,
/// identical to `alloc=generate` — otherwise the placeholder literal
/// `${gh-env-secret:alloc=rotate}` would compare as modified against every
/// live gateway value on every diff and surface as persistent false drift
/// (and fail `drift-check.yml --exit-on-drift`). Rotation is now always
/// explicit via `gitforgeops rotate`, so there's no two-pass allocate-then-
/// replace dance to preserve.
fn resolve_credentials(
    cfg: &mut GatewayConfig,
    env_config: &EnvConfig,
) -> Result<secrets::ResolveReport, Box<dyn std::error::Error>> {
    let (bundle, _) = load_credential_bundles(env_config)?;
    Ok(secrets::resolve_secrets(cfg, &bundle)?)
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
    let client = build_github_api_client(env_config).ok()?;
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
/// Build a reqwest::Client configured to hit api.github.com with the
/// `FERRUM_GITHUB_*_TIMEOUT_SECS` bounds applied. Every GitHub-API call
/// site in the binary (PR lookup, override check, secret provisioning,
/// SSH-key fetch, review comment post) must use this — a bare client
/// with no timeouts can hang an apply indefinitely on a stalled endpoint
/// and block deployment. The admin-gateway client has its own timeouts
/// (see `http_client.rs`) and uses a different env-var pair.
fn build_github_api_client(
    env_config: &EnvConfig,
) -> Result<reqwest::Client, gitforgeops::error::Error> {
    use std::time::Duration;
    reqwest::Client::builder()
        .user_agent("gitforgeops/0.1")
        .connect_timeout(Duration::from_secs(env_config.github_connect_timeout_secs))
        .timeout(Duration::from_secs(env_config.github_request_timeout_secs))
        .build()
        .map_err(|e| gitforgeops::error::Error::HttpClient(e.to_string()))
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

    let client = build_github_api_client(env_config)?;

    let outcome = match secrets::allocate_and_deliver(
        &client,
        repo,
        &resolved.name,
        token,
        recipient.as_deref(),
        report,
        per_shard,
        shard_count,
    )
    .await
    {
        Ok(o) => o,
        Err(failure) => {
            // Shard-atomic commit failed partway through: the shards in
            // `failure.partial.allocated` were successfully PUT to GitHub
            // before the failure, so their new values are live on the
            // gateway side. Surface those ciphertexts NOW — if we let the
            // error propagate without surfacing, recipients for already-
            // committed shards have no decryption material and the next
            // apply will see the slot as resolved (bundle has the value)
            // so no re-delivery fires. Subsequent shards in the batch are
            // not in `partial.allocated` (their PUT never succeeded), so
            // they'll show up as NeedsAllocation on the next apply.
            if !failure.partial.allocated.is_empty() {
                surface_delivered_credentials(env_config, &failure.partial).await?;
            }
            return Err(failure.source.into());
        }
    };

    // Re-resolve so `desired` picks up freshly allocated values. The
    // allocator only produces values for slots classified as NeedsAllocation
    // (first-apply generate OR first-apply rotate). Already-allocated
    // placeholders were resolved in the initial `resolve_secrets` pass.
    let merged = secrets::merge_bundles(per_shard);
    let _ = secrets::resolve_secrets(desired, &merged)?;

    Ok(Some(outcome))
}

/// One namespace's desired/live pair, plus the backup-only sections that came
/// down with the live fetch.
///
/// `extras` (`api_specs`, `gateway_trust_bundles`) rides along because
/// `full_replace` has to hand them straight back to `/restore` — carrying them
/// from the fetch the caller already performed saves a second full `/backup`
/// download per namespace inside `apply_api`.
struct NamespaceSnapshot {
    namespace: String,
    desired: GatewayConfig,
    actual: GatewayConfig,
    extras: gitforgeops::http_client::BackupExtras,
    cached: bool,
}

/// Load per-namespace (desired, actual) snapshots from the gateway for the
/// given namespace list.
///
/// Iterates an explicit namespace list so exclusive-mode apply can reconcile
/// namespaces that the repo has emptied (still need to fetch gateway state to
/// prune). For shared mode, the caller passes the namespaces present in
/// `desired` (or a single-element list for a namespace filter).
async fn load_namespace_pairs_for(
    client: &AdminClient,
    desired: &GatewayConfig,
    namespaces: &[String],
) -> gitforgeops::error::Result<Vec<NamespaceSnapshot>> {
    let mut pairs = Vec::new();
    for namespace in namespaces {
        let desired_namespace = config::filter_config_by_namespace(desired, namespace);
        let snapshot = client.get_backup_snapshot(namespace).await?;
        pairs.push(NamespaceSnapshot {
            namespace: namespace.clone(),
            desired: desired_namespace,
            actual: snapshot.config,
            extras: snapshot.extras,
            cached: snapshot.cached,
        });
    }
    Ok(pairs)
}

fn cached_namespace_names(namespace_pairs: &[NamespaceSnapshot]) -> Vec<String> {
    namespace_pairs
        .iter()
        .filter(|pair| pair.cached)
        .map(|pair| pair.namespace.clone())
        .collect()
}

/// `options` mirrors the apply-time decisions that change which entries the
/// diff materializes. Preview-only commands (`diff`, `plan`, `review`) pass the
/// default; `apply` passes its own `--confirm-api-spec-deletion` so the preview
/// it prints and the large-prune guard it evaluates describe the run that is
/// about to happen. Computing the preview with the default while applying with
/// the flag hid spec-owned deletions from both.
fn compute_namespace_diffs(
    namespace_pairs: &[NamespaceSnapshot],
    previously_managed: Option<&HashSet<String>>,
    options: diff::DiffOptions,
) -> (
    Vec<diff::ResourceDiff>,
    Vec<diff::BreakingChange>,
    Vec<diff::UnmanagedResource>,
    Vec<diff::SpecOwnedResource>,
) {
    let mut diffs = Vec::new();
    let mut breaking = Vec::new();
    let mut unmanaged = Vec::new();
    let mut spec_owned = Vec::new();

    let ownership_scope = match previously_managed {
        Some(previously_managed) => diff::OwnershipScope::Shared { previously_managed },
        None => diff::OwnershipScope::Exclusive,
    };

    for pair in namespace_pairs {
        let result =
            diff::compute_diff_with_options(&pair.desired, &pair.actual, ownership_scope, options);
        let namespace_breaking =
            diff::detect_breaking_changes(&result.diffs, &pair.desired, &pair.actual);

        diffs.extend(result.diffs);
        unmanaged.extend(result.unmanaged);
        spec_owned.extend(result.spec_owned);
        breaking.extend(namespace_breaking);
    }

    (diffs, breaking, unmanaged, spec_owned)
}

/// True when the spec-owned bucket holds something an operator must resolve
/// before the repo and the gateway can agree.
///
/// A plain spec-owned row is *informational*: the resource has a third owner
/// and this run stays off it, which is a stable, correct steady state. Treating
/// the bucket's mere non-emptiness as drift meant any gateway that ingests API
/// specs could never report "in sync" and interactive `apply` prompted on every
/// no-op run. Only a conflict — the repo declaring a row the spec importer owns
/// — actually needs a human.
fn spec_owned_blocks_sync(spec_owned: &[diff::SpecOwnedResource]) -> bool {
    spec_owned.iter().any(|s| s.is_conflict())
}

/// Render the spec-owned bucket for `diff` / `plan` stdout.
///
/// Mirrors the unmanaged block: a header, then one line per resource. Unlike
/// unmanaged, it is NOT gated on `ownership.drift_report` — a repo declaring a
/// resource an API spec owns is a correctness problem in both ownership modes,
/// not drift noise an operator may want muted.
fn print_spec_owned(spec_owned: &[diff::SpecOwnedResource]) {
    if spec_owned.is_empty() {
        return;
    }
    println!("=== Spec-owned Resources ===");
    // With `--confirm-api-spec-deletion` these are not "never touched" — the
    // run is about to delete the non-conflicting ones, and they appear as
    // DELETE entries in the change list above. Saying otherwise while deleting
    // them is the worst of both.
    if spec_owned.iter().any(|s| s.pruned) {
        println!(
            "(carry an `api_spec_id`; --confirm-api-spec-deletion is set, so the ones marked \
             DELETE below WILL be deleted by this run)"
        );
    } else {
        println!(
            "(carry an `api_spec_id`; provisioned by an OpenAPI spec import, never touched here)"
        );
    }
    for s in spec_owned {
        let note = if s.declared_in_repo {
            "  [CONFLICT: also declared in this repo]"
        } else if s.pruned {
            "  [DELETE: --confirm-api-spec-deletion]"
        } else {
            ""
        };
        println!(
            "  {} {} ({}) spec={}{}",
            s.kind, s.id, s.namespace, s.api_spec_id, note
        );
    }
    println!();
}

/// Reserved rule id recorded in the state file's override ledger when a
/// maintainer overrides the pre-resolve security audit.
///
/// Policy findings carry their own `rule_id`; the audit is one gate rather
/// than a registry of rules, so a bypass of it is recorded under a single id
/// that cannot collide with a policy rule (`.` is not used in rule ids).
const SECURITY_AUDIT_RULE_ID: &str = "diff.security";

/// Print the pre-resolve security audit for `apply`, blockers first.
///
/// Written to stderr rather than stdout: `apply`'s stdout carries the change
/// list an operator (or a workflow step summary) reads back, and a refusal has
/// to survive being piped away from it.
fn print_security_findings(findings: &[diff::SecurityFinding]) {
    if findings.is_empty() {
        return;
    }
    eprintln!("=== Security Findings ===");
    let blockers = diff::security_blockers(findings);
    for finding in &blockers {
        eprintln!(
            "  [{}] {} {} ({}): {}",
            finding.severity, finding.kind, finding.id, finding.namespace, finding.message
        );
    }
    for finding in findings
        .iter()
        .filter(|finding| finding.severity != diff::BLOCKING_SEVERITY)
    {
        eprintln!(
            "  [{}] {} {} ({}): {}",
            finding.severity, finding.kind, finding.id, finding.namespace, finding.message
        );
    }
    eprintln!();
}

/// Best-effort post-apply convergence line. Never fails an apply — a gateway
/// that cannot answer `GET /cluster` (older build, DP/CP not in play, network
/// blip) produces one "unavailable" line and nothing else.
async fn convergence_line(client: &AdminClient) -> String {
    match client.get_cluster().await {
        Ok(status) => gitforgeops::http_client::convergence_summary(&status),
        Err(_) => gitforgeops::http_client::CONVERGENCE_UNAVAILABLE.to_string(),
    }
}

fn fmt_resolution_note(resolved: &ResolvedEnv, report: &secrets::ResolveReport) -> Option<String> {
    if report.results.is_empty() {
        return None;
    }
    let mut lines = vec![format!("Secret broker slots (env {}):", resolved.name)];
    for r in &report.results {
        let status = match r.status {
            secrets::SlotStatus::Resolved => "resolved",
            secrets::SlotStatus::NeedsAllocation => "needs-allocation",
            secrets::SlotStatus::MissingRequired => "MISSING (required)",
        };
        lines.push(format!("  [{status}] {}", r.slot));
    }
    Some(lines.join("\n"))
}

/// One-line inventory of a merged mesh document.
///
/// Mesh resources never reach the gateway diff — there is no mesh admin API
/// to compare against, and every mesh node derives its own slice from the
/// same published document — so counts are the honest limit of what a preview
/// can say about them.
fn mesh_summary_line(mesh: &config::MeshConfigSpec) -> String {
    let summary = mesh.summary();
    if summary.is_empty() {
        "empty mesh document".to_string()
    } else {
        summary
    }
}

/// Print one document's plan-time validation verdict and return whether it
/// counts as passing.
///
/// Failure to start or execute `ferrum-edge` is an ERROR, not a successful
/// skip. A plan is a launch safety signal and must fail closed when the
/// authoritative validator did not run.
fn report_plan_validation(
    label: &str,
    result: &Result<validate::ValidationResult, gitforgeops::error::Error>,
) -> bool {
    match result {
        Ok(r) => {
            if r.success {
                println!("{label}: PASSED");
            } else {
                println!("{label}: FAILED");
                print!("{}", r.stderr);
            }
            r.success
        }
        Err(e) => {
            println!("{label}: ERROR ({e})");
            false
        }
    }
}

fn cmd_validate(
    output_format: validate::OutputFormat,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let assembled = load_and_assemble_all(&resolved)?;
    let mut gateway_config = assembled.gateway;
    let _ = resolve_credentials(&mut gateway_config, &env_config)?;

    let result = validate::run_validation(&gateway_config, &env_config.edge_binary_path)?;

    // Mesh config is a second, independently-loaded document with its own
    // validator mode. Only run it when the repo actually declares mesh
    // resources — otherwise behavior (and output) is exactly as before.
    let mesh_result = match &assembled.mesh {
        Some(mesh) => Some(validate::run_mesh_validation(
            mesh,
            &env_config.edge_binary_path,
        )?),
        None => None,
    };

    let formatted = validate::format_results(&result, mesh_result.as_ref(), output_format);
    print!("{}", formatted);

    // A failure in either document is a failure overall: both get published,
    // and a node refusing either one is a broken deploy.
    if !result.success {
        process::exit(result.exit_code);
    }
    if let Some(mesh_result) = &mesh_result {
        if !mesh_result.success {
            process::exit(mesh_result.exit_code);
        }
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
    if materialize
        && encrypt_to.is_none()
        && output_path.is_none()
        && std::io::stdout().is_terminal()
    {
        return Err(
            "refusing to print materialized credentials to an interactive terminal; use --output PATH (written mode 0600) or --encrypt-to LOGIN"
                .into(),
        );
    }

    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let assembled = load_and_assemble_all(&resolved)?;
    let mut gateway_config = assembled.gateway;

    if materialize {
        // Fail fast if credentials cannot be fully resolved — we don't want
        // to hand an admin a file that still has `${gh-env-secret:...}`
        // strings in it, and we won't allocate fresh secrets during export
        // (that's the job of `apply`).
        //
        // After resolve, any placeholder still present in the config is a
        // truly-unresolved slot. We run the post-resolve config through
        // report_secrets with an empty bundle as a defensive re-scan rather
        // than trusting the pre-resolve report's NeedsAllocation
        // classification, since that classification is computed against the
        // PRE-resolve bundle snapshot.
        let (bundle, _) = load_credential_bundles(&env_config)?;
        let _ = secrets::resolve_secrets(&mut gateway_config, &bundle)?;
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

    // Route through the file-target renderer so exported YAML carries the
    // `resource_counts` anti-truncation seal that ferrum-edge's file-mode
    // loader checks. Both output paths below (plain and age-encrypted) derive
    // from this one document, so the seal travels with either — a materialized
    // export is exactly the artifact a file-mode gateway consumes.
    let yaml = apply::render_file_yaml(&gateway_config)?;

    // The mesh document is a separate artifact with a separate destination —
    // it cannot ride inside the gateway document (the mesh loader is
    // deny_unknown_fields and would reject `proxies:`), and `--output` names
    // the gateway file. It also carries no credential placeholders, so
    // `--materialize` / `--encrypt-to` have nothing to act on: it is always
    // published verbatim to FERRUM_MESH_FILE_OUTPUT_PATH.
    if let Some(mesh) = &assembled.mesh {
        apply::apply_mesh_file(mesh, &env_config.mesh_file_output_path)?;
        eprintln!(
            "Exported mesh document to {} ({})",
            env_config.mesh_file_output_path,
            mesh_summary_line(mesh)
        );
    }

    let plaintext_materialized = materialize && encrypt_to.is_none();
    let payload: Vec<u8> = if let Some(login) = encrypt_to {
        let client = build_github_api_client(&env_config)?;
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
            if plaintext_materialized {
                apply::publish_private_export(path, &payload)?;
            } else {
                apply::publish_export(path, &payload)?;
            }
            eprintln!("Exported to {}", path);
        }
        None => {
            if plaintext_materialized {
                eprintln!(
                    "WARNING: writing plaintext materialized credentials to non-interactive stdout; ensure the receiving process and destination are private. Prefer --output PATH (mode 0600) or --encrypt-to LOGIN."
                );
            }
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
    let state = StateFile::load(&resolved.name)?;
    let managed = previously_managed(&resolved, &state);
    let namespaces = resolved_namespaces(&resolved, &desired, &state);
    let client = AdminClient::new_scoped(&env_config, &namespaces)?;
    let namespace_pairs = load_namespace_pairs_for(&client, &desired, &namespaces).await?;
    let cached_namespaces = cached_namespace_names(&namespace_pairs);
    if !cached_namespaces.is_empty() {
        eprintln!(
            "Warning: diff is approximate because cached backup data was served for namespace(s) {}. API-spec ownership metadata is unavailable, so spec-owned/conflict classification is incomplete; no authoritative sync or drift decision is possible until the configuration database returns.",
            cached_namespaces.join(", ")
        );
        if exit_on_drift {
            return Err(gitforgeops::error::Error::StaleGatewayView(format!(
                "--exit-on-drift requires an authoritative backup, but namespace(s) {} were served from cache; refusing to return either the in-sync (0) or drift (2) result",
                cached_namespaces.join(", ")
            ))
            .into());
        }
    }
    let (diffs, _breaking, unmanaged, spec_owned) = compute_namespace_diffs(
        &namespace_pairs,
        managed.as_ref(),
        diff::DiffOptions::default(),
    );

    if diffs.is_empty() && unmanaged.is_empty() && !spec_owned_blocks_sync(&spec_owned) {
        // Spec-owned rows are still reported — an operator should know a third
        // owner is in play — but they do not make the configuration
        // out-of-sync on their own.
        print_spec_owned(&spec_owned);
        if cached_namespaces.is_empty() {
            println!("No differences found. Configuration is in sync.");
        } else {
            println!(
                "No differences found in the cached snapshot. Authoritative sync status is unavailable."
            );
        }
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
                if diff::is_sensitive_diff_field(&d.kind, &change.field) {
                    // Consumer credentials and plugin config can carry actual
                    // secret material. Printing them here would leak to CI
                    // logs, which are visible to anyone with run access.
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

    if !spec_owned.is_empty() {
        println!();
        print_spec_owned(&spec_owned);
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
    let assembled = load_and_assemble_all(&resolved)?;
    let desired_mesh = assembled.mesh;
    let mut desired = assembled.gateway;
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
    let policy_cfg = policy::load_policies()?;
    let security_findings = diff::audit_security_with_policy(&desired, policy_cfg.as_ref());
    let secret_report = resolve_credentials(&mut desired, &env_config)?;
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
    let mut validation_ok = report_plan_validation("gateway", &val_result);
    if let Some(mesh) = &desired_mesh {
        let mesh_result = validate::run_mesh_validation(mesh, &env_config.edge_binary_path);
        validation_ok &= report_plan_validation("mesh", &mesh_result);
    }
    println!();

    if let Some(mesh) = &desired_mesh {
        // Counts only: mesh resources have no live gateway API to diff
        // against, so they never appear under "=== Changes ===".
        println!("=== Mesh ===");
        println!(
            "mesh: {} (published to {})\n",
            mesh_summary_line(mesh),
            env_config.mesh_file_output_path
        );
    }

    if let Some(note) = fmt_resolution_note(&resolved, &secret_report) {
        println!("=== Credentials ===");
        println!("{}\n", note);
        if !bundle_loaded {
            println!(
                "Unresolved broker-controlled Consumer credential and plugin-config leaves are excluded from the live diff because no secret bundle is available; literal siblings, extra entries, shape changes, and nonsecret fields are still compared.\n"
            );
        }
    }

    let state = StateFile::load(&resolved.name)?;
    let managed = previously_managed(&resolved, &state);
    let namespaces = resolved_namespaces(&resolved, &desired, &state);
    let client = AdminClient::new_scoped(&env_config, &namespaces);
    let (diffs, breaking, unmanaged, spec_owned, actual_available, provenance_note) = match &client
    {
        Ok(c) => match load_namespace_pairs_for(c, &desired, &namespaces).await {
            Ok(mut namespace_pairs) => {
                let cached = cached_namespace_names(&namespace_pairs);
                if cached.is_empty() {
                    if !bundle_loaded {
                        for pair in &mut namespace_pairs {
                            diff::mask_indeterminate_secret_values(&desired, &mut pair.actual);
                        }
                    }
                    let (d, b, u, s) = compute_namespace_diffs(
                        &namespace_pairs,
                        managed.as_ref(),
                        diff::DiffOptions::default(),
                    );
                    (d, b, u, s, true, None)
                } else {
                    (
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        false,
                        Some(format!(
                            "Live comparison skipped: cached backup data was served for namespace(s) {}. API-spec ownership is unknown until the gateway configuration database recovers.",
                            cached.join(", ")
                        )),
                    )
                }
            }
            Err(e) => {
                eprintln!("Could not fetch live config: {}", e);
                (Vec::new(), Vec::new(), Vec::new(), Vec::new(), false, None)
            }
        },
        Err(e) => {
            eprintln!("Could not create API client: {}", e);
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), false, None)
        }
    };

    if let Some(note) = &provenance_note {
        println!("=== Live Data Provenance ===");
        println!("WARNING: {note}\n");
    }

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

    print_spec_owned(&spec_owned);

    if !breaking.is_empty() {
        println!("=== Breaking Changes ===");
        for bc in &breaking {
            println!("  {} {}: {}", bc.kind, bc.id, bc.reason);
        }
        println!();
    }

    // security_findings was computed pre-resolve above; reuse it here.
    let security_blockers = diff::security_blockers(&security_findings);
    let security_blocked = !security_blockers.is_empty();
    if !security_findings.is_empty() {
        println!("=== Security Findings ===");
        for sf in &security_findings {
            println!("  [{}] {} {}: {}", sf.severity, sf.kind, sf.id, sf.message);
        }
        if security_blocked {
            // Same set `apply` refuses on, so the preview and the post-merge
            // apply cannot disagree about whether this repo is applyable.
            println!(
                "\n{} error-severity finding(s) block apply. Consumer credentials belong in the \
                 broker as ${{gh-env-secret:...}} placeholders; a literal value in repository YAML \
                 is a committed secret.",
                security_blockers.len()
            );
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

    if let Some(policy_cfg) = policy_cfg {
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

    // Plan's exit code is the preview's verdict: nonzero for anything that
    // would stop `apply`. Schema validation and the error-severity security
    // audit are both in that set, and both have already been printed in full
    // above — the exit code carries no information the operator has not seen.
    if !validation_ok || security_blocked {
        process::exit(1);
    }

    Ok(())
}

async fn cmd_apply(
    auto_approve: bool,
    allow_large_prune: bool,
    confirm_api_spec_deletion: bool,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;
    let assembled = load_and_assemble_all(&resolved)?;
    let desired_mesh = assembled.mesh;
    let mut desired = assembled.gateway;

    // Exclusive ownership: enforce namespace scope before anything else so the
    // operator fails fast on a misconfigured resource, not deep in apply.
    enforce_exclusive_scope(&resolved, &desired)?;

    // Literal consumer credentials block apply; they are not an advisory.
    //
    // The audit must see the UNRESOLVED document. `check_literal_credentials`
    // calls any credential string that is not a `${gh-env-secret:...}`
    // placeholder a committed secret, so auditing after resolution would flag
    // every correctly brokered value and miss nothing else. Running it here —
    // before the state lock, before the credential bundle is read, and before
    // any gateway call, health preflight, credential allocation or file
    // publish — is what makes it impossible for an apply to publish a secret
    // that was committed to the repository.
    let policy_cfg = policy::load_policies()?;
    let security_findings = diff::audit_security_with_policy(&desired, policy_cfg.as_ref());
    print_security_findings(&security_findings);
    let security_blocked = !diff::security_blockers(&security_findings).is_empty();

    // One override decision serves both fail-closed reporters: the same PR
    // label, added by the same sufficiently-permissioned account, clears the
    // security audit and the policy rules. Resolved once so apply makes at
    // most one round trip, and only when something could actually be
    // overridden.
    let override_cfg = policy_cfg
        .as_ref()
        .map(|cfg| cfg.overrides.clone())
        .unwrap_or_default();
    let override_decision = if security_blocked || policy_cfg.is_some() {
        match resolve_pr_number(&env_config).await {
            Some(pr) => Some(policy::check_override(&env_config, &override_cfg, pr).await?),
            None => None,
        }
    } else {
        None
    };
    let override_approver = override_decision
        .as_ref()
        .filter(|decision| decision.active)
        .and_then(|decision| decision.approver.clone());

    // Overridden rule ids are captured as they are cleared and written into
    // state after apply, so an audit can see which blocking findings were
    // bypassed and by whom.
    let mut overridden_for_audit: Vec<(String, String)> = Vec::new();

    if security_blocked {
        let blocker_count = diff::security_blockers(&security_findings).len();
        match &override_approver {
            Some(approver) => {
                eprintln!(
                    "{blocker_count} error-severity security finding(s) overridden by @{approver}; continuing."
                );
                overridden_for_audit.push((SECURITY_AUDIT_RULE_ID.to_string(), approver.clone()));
            }
            None => {
                eprintln!(
                    "Refusing to apply: {blocker_count} error-severity security finding(s) listed above. \
                     Consumer credentials belong in the broker as ${{gh-env-secret:...}} placeholders; a literal \
                     value in repository YAML is a committed secret and applying it publishes it to the gateway. \
                     To override, add the '{}' label to the PR from an account with '{}' permission.",
                    override_cfg.require_label, override_cfg.required_permission
                );
                match &override_decision {
                    Some(decision) if !decision.active => {
                        eprintln!("(override inactive: {})", decision.reason)
                    }
                    Some(_) => {}
                    None => {
                        eprintln!("(no PR associated with this commit; overrides not evaluated)")
                    }
                }
                return Err("unresolved security findings".into());
            }
        }
    }

    let _state_lock = StateFile::lock(&resolved.name)?;
    let mut state = StateFile::load(&resolved.name)?;

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
    // allocator fills in first-apply gaps (generate or rotate with no
    // existing value) afterward; rotation of an already-allocated slot is
    // an explicit `gitforgeops rotate` operation, not something apply does.
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
        return Err("required credential slots are missing".into());
    }

    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path)?;
    if !val_result.success {
        let formatted = validate::format_result(&val_result, validate::OutputFormat::Text);
        eprint!("{}", formatted);
        eprintln!("Refusing to apply because validation failed.");
        return Err("validation failed".into());
    }

    // The mesh document is published by the file-mode arm below, so it must
    // clear the same gate the gateway document does. Checked here, before any
    // credential allocation or gateway write, so a bad mesh document cannot
    // half-apply an environment.
    if let Some(mesh) = &desired_mesh {
        let mesh_result = validate::run_mesh_validation(mesh, &env_config.edge_binary_path)?;
        if !mesh_result.success {
            let formatted = validate::format_result(&mesh_result, validate::OutputFormat::Text);
            eprint!("{}", formatted);
            eprintln!("Refusing to apply because mesh validation failed.");
            return Err("mesh validation failed".into());
        }
        if matches!(env_config.gateway_mode, GatewayMode::Api) {
            // There is no mesh admin API — no push endpoint, no `mesh`
            // section on /backup or /restore. Say so rather than letting an
            // api-mode apply look like it delivered the mesh document.
            eprintln!(
                "Notice: {} mesh fragment(s) assembled, but FERRUM_GATEWAY_MODE=api has no mesh push path (ferrum-edge exposes no mesh admin API). Run `gitforgeops export` or a file-mode apply to publish {} for mesh nodes.",
                mesh_summary_line(mesh),
                env_config.mesh_file_output_path
            );
        }
    }

    // Policy enforcement, sharing the override decision resolved before the
    // security gate. Overridden rule_ids are captured here and written into
    // state after a successful apply so audits can see which blocking findings
    // were bypassed by whom.
    if let Some(policy_cfg) = &policy_cfg {
        let mut findings = policy::evaluate_policies(&desired, policy_cfg);
        if let Some(d) = &override_decision {
            policy::github_override::apply_override(&mut findings, d);
        }

        if let Some(approver) = &override_approver {
            for f in &findings {
                if f.overridden_by.is_some() {
                    overridden_for_audit.push((f.rule_id.clone(), approver.clone()));
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
            return Err("unresolved policy violations".into());
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
    let mut allocation_state_persisted = false;

    // Stash partial-failure errors from apply_api so state.record/save runs
    // BEFORE we propagate. In shared ownership this is critical: if some
    // resources were created/updated successfully and we exit on error
    // without recording, those resources lose their managed flag, the next
    // apply classifies them as unmanaged, and future removals stop being
    // pruned. See apply_api comments — per-resource errors are aggregated
    // (record-and-continue) rather than aborting the batch, precisely so
    // partial successes can be observed.
    let mut deferred_apply_error: Option<gitforgeops::error::Error> = None;

    // Per-op success records from apply_api. cmd_apply uses these to update
    // state.resources INCREMENTALLY (only for ops that actually landed),
    // not by full-replace from `desired`. The full-replace approach drops
    // failed-Delete keys from state — in shared mode that orphans the
    // resource (next diff classifies it as unmanaged, no more delete
    // retries). File mode leaves these empty, and the file-mode state path
    // below stamps everything from `desired` as managed (no per-op concept
    // — the file write is atomic, success means everything's recorded).
    let mut successful_ops: Vec<apply::AppliedOp> = Vec::new();
    let mut fully_replaced: Vec<String> = Vec::new();

    match env_config.gateway_mode {
        GatewayMode::Api => {
            // The shared repository-load boundary already rejected
            // `api_spec_id`; repeat the invariant here for defense in depth
            // before any API-side effect. The API target also enforces it for
            // library callers.
            apply::validate_no_desired_spec_tags(&desired)?;
            let client = AdminClient::new_scoped(&env_config, &namespaces)?;

            // The preview must be computed with the same options the apply
            // will run under, or it describes a different run: with
            // `--confirm-api-spec-deletion` the spec-owned prunes are real
            // DELETEs, and leaving them out of the preview asked the operator
            // to approve a change set that understated what would happen.
            let diff_options = diff::DiffOptions {
                prune_spec_owned: confirm_api_spec_deletion,
            };

            if !auto_approve {
                let managed = previously_managed(&resolved, &state);
                let namespace_pairs =
                    load_namespace_pairs_for(&client, &desired, &namespaces).await?;
                if let Some(message) = apply::stale_view_block(client.served_from_cache()) {
                    return Err(gitforgeops::error::Error::StaleGatewayView(message).into());
                }
                let (mut diffs, _, unmanaged, spec_owned) =
                    compute_namespace_diffs(&namespace_pairs, managed.as_ref(), diff_options);
                for pair in &namespace_pairs {
                    diffs.extend(apply::pending_create_assertion_diffs(
                        &pair.desired,
                        &pair.actual,
                        &state.pending_creates,
                        &pair.namespace,
                    ));
                }
                let diffs = apply::order_diffs(diffs);

                if diffs.is_empty()
                    && unmanaged.is_empty()
                    && !spec_owned_blocks_sync(&spec_owned)
                    && secret_report.needs_allocation().is_empty()
                {
                    // Informational spec-owned rows are reported but do not
                    // manufacture a change to approve.
                    print_spec_owned(&spec_owned);
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
                if !spec_owned.is_empty() {
                    println!();
                    print_spec_owned(&spec_owned);
                }
                let pending_creds = secret_report.needs_allocation();
                if !pending_creds.is_empty() {
                    println!(
                        "\n{} credential slot(s) would be allocated on apply:",
                        pending_creds.len()
                    );
                    for r in pending_creds {
                        println!("  [new] {}", r.slot);
                    }
                }
                println!("\nUse --auto-approve to skip this check.");
                return Ok(());
            }

            // Large-prune safety check runs BEFORE allocation. The check
            // inspects the diff against the placeholder-containing desired
            // (allocation would only replace string values, not change which
            // resources exist), so pruning behavior is unaffected. Placing
            // allocation after this gate means a blocked apply leaves GitHub
            // env secrets untouched — otherwise we'd burn a generated value
            // that the gateway never receives.
            let namespace_pairs = load_namespace_pairs_for(&client, &desired, &namespaces).await?;
            if let Some(message) = apply::stale_view_block(client.served_from_cache()) {
                // This gate intentionally precedes credential allocation. A
                // cached backup omits API-spec ownership metadata, so no
                // mutation is safe and no unrelated GitHub secret should be
                // allocated for a run that cannot proceed.
                return Err(gitforgeops::error::Error::StaleGatewayView(message).into());
            }
            let actual_by_namespace: BTreeMap<String, GatewayConfig> = namespace_pairs
                .iter()
                .map(|pair| (pair.namespace.clone(), pair.actual.clone()))
                .collect();
            // `/backup` was just read for every namespace in scope. Preserve
            // each config/extras pair from the same response so full-replace
            // preflight never combines two different gateway snapshots.
            let extras_by_namespace: BTreeMap<String, gitforgeops::http_client::BackupExtras> =
                namespace_pairs
                    .iter()
                    .map(|pair| (pair.namespace.clone(), pair.extras.clone()))
                    .collect();

            // This boundary precedes every external credential write and
            // state journal mutation. It rejects read-only planes,
            // API-spec ownership conflicts, unsupported restore sections,
            // and every namespace's deterministic full-replace error before
            // any unrelated side effect can occur. apply_api repeats the
            // preflight immediately before its first gateway mutation.
            apply::preflight_api_apply(
                &desired,
                &client,
                &namespaces,
                Some(&actual_by_namespace),
                Some(&extras_by_namespace),
                &apply::ApplyOptions {
                    strategy: resolved.apply_strategy.clone(),
                    pending_create_assertions: state.pending_creates.clone(),
                    confirm_api_spec_deletion,
                },
            )
            .await?;

            // Recover any create whose non-idempotent POST may have committed
            // before a prior process died. Pending rows are not deletion
            // authority: an exact desired row remains pending until the API
            // target asserts ownership with an idempotent PUT. If the
            // declaration disappeared while a row is live, reconciliation
            // fails closed instead of guessing who created it.
            let reconciled_pending =
                state.reconcile_pending_creates(&desired, &actual_by_namespace)?;
            let reconciled_absent =
                state.reconcile_absent_managed_resources(&desired, &actual_by_namespace);
            if reconciled_pending + reconciled_absent > 0 {
                state.save()?;
            }
            let managed = previously_managed(&resolved, &state);
            let (diffs, _, _, _) =
                compute_namespace_diffs(&namespace_pairs, managed.as_ref(), diff_options);
            let delete_count = diffs
                .iter()
                .filter(|d| matches!(d.action, diff::DiffAction::Delete))
                .count();
            // Pick the denominator from the same set the diff uses to
            // bound deletes — otherwise the percentage gets diluted by
            // resources the diff would never touch.
            //
            //   - Shared mode: deletes only target previously-managed
            //     resources (compute_diff_with_ownership filters on the
            //     `previously_managed` set). Denominator = managed set in
            //     scope. CLAUDE.md defines large_prune_threshold_percent
            //     against managed resources for this reason: deleting 8 of
            //     10 managed should report 80%, not get diluted to 8% just
            //     because 90 admin-added resources also exist on the
            //     gateway.
            //
            //   - Exclusive mode: every live resource in scope that this run
            //     may prune is in the denominator. API-spec-owned rows stay
            //     outside it unless their deletion was explicitly confirmed;
            //     otherwise untouchable rows could dilute the safety guard.
            //
            // Both branches naturally cap at 100% (delete_count is bounded
            // by the same set used as the denominator), so threshold = 100
            // disables the guard as documented.
            let denominator = match managed.as_ref() {
                Some(managed_set) => {
                    let ns_set: std::collections::HashSet<&str> =
                        namespaces.iter().map(String::as_str).collect();
                    managed_set
                        .iter()
                        .filter(|k| {
                            diff::resource_diff::state_key_namespace(k)
                                .map(|ns| ns_set.contains(ns.as_str()))
                                .unwrap_or(false)
                        })
                        .count()
                }
                None => namespace_pairs
                    .iter()
                    .map(|pair| {
                        apply::exclusive_prune_denominator(&pair.actual, confirm_api_spec_deletion)
                    })
                    .sum(),
            };
            // No managed resources (shared bootstrap) or no live resources
            // (exclusive bootstrap with empty gateway) → no delete is
            // possible; skip the guard rather than dividing by zero.
            if delete_count > 0 && denominator > 0 {
                let threshold = resolved.ownership.large_prune_threshold_percent;
                if apply::large_prune_exceeds_threshold(delete_count, denominator, threshold)
                    && !allow_large_prune
                {
                    let scope_label = if managed.is_some() {
                        "managed resources"
                    } else {
                        "live resources"
                    };
                    let delete_pct = apply::format_prune_percentage(delete_count, denominator);
                    return Err(format!(
                        "Refusing to apply: would delete {}% of {} in scope ({}/{}, threshold {}%). Re-run with --allow-large-prune to proceed.",
                        delete_pct, scope_label, delete_count, denominator, threshold
                    )
                    .into());
                }
            }

            // All safety gates passed — now allocate credentials. Rotation
            // on an already-allocated slot is a separate explicit operation
            // (`gitforgeops rotate`); apply never re-rotates automatically.
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
                eprintln!("Allocated {} credential slot(s):", outcome.allocated.len());
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

            // The GitHub Environment Secret write is an external commit of
            // its own. Persist its shard and delivery metadata immediately so
            // a later gateway or reporting failure cannot leave the ledger
            // claiming the slot was never allocated.
            state.credential_shard_count = shard_count;
            if let Some(outcome) = &allocation {
                let run_id = std::env::var("GITHUB_RUN_ID").ok();
                for slot in &outcome.allocated {
                    state.record_credential(
                        &slot.slot,
                        slot.shard,
                        slot.delivered.as_ref().map(|d| d.login.as_str()),
                        run_id.as_deref(),
                    );
                }
                state.save()?;
                allocation_state_persisted = true;
            }

            // Surface the encrypted delivery blob BEFORE apply_api. The
            // allocator has already written the new value to the GitHub
            // Env Secret, so if apply_api fails here, the bundle will be
            // treated as resolved on the next run and no later delivery
            // attempt will happen — the recipient would be permanently
            // locked out. By surfacing first, we guarantee the ciphertext
            // reaches the recipient (PR comment or stdout) regardless of
            // whether the gateway push succeeds. A failed gateway push
            // just means a subsequent apply will pick up the already-
            // committed bundle value and push it again.
            if let Some(outcome) = &allocation {
                surface_delivered_credentials(&env_config, outcome).await?;
            }

            // Write-ahead journal for non-idempotent creates. This must be
            // durable before the first POST, but it deliberately does not
            // grant deletion authority. A later authoritative backup either
            // leads to an idempotent ownership assertion, leaves the pending
            // Add retryable, or blocks if ownership is ambiguous.
            if state.reserve_adds(&diffs, &desired)? > 0 {
                state.save()?;
            }

            let mut raw = apply::apply_api(
                &desired,
                &client,
                &namespaces,
                match managed.as_ref() {
                    Some(previously_managed) => diff::OwnershipScope::Shared { previously_managed },
                    None => diff::OwnershipScope::Exclusive,
                },
                Some(&actual_by_namespace),
                Some(&extras_by_namespace),
                &apply::ApplyOptions {
                    strategy: resolved.apply_strategy.clone(),
                    pending_create_assertions: state.pending_creates.clone(),
                    confirm_api_spec_deletion,
                },
            )
            .await?;

            // Print counts up front so partial-success runs surface what
            // landed even when we're about to propagate an error.
            println!(
                "Applied: {} created, {} updated, {} deleted, {} unmanaged skipped, {} spec-owned skipped",
                raw.created,
                raw.updated,
                raw.deleted,
                raw.unmanaged_skipped,
                raw.spec_owned_skipped
            );

            // Pull the per-op records out before `into_result()` consumes
            // `raw`. These drive the incremental state update below.
            successful_ops = std::mem::take(&mut raw.applied_incremental);
            fully_replaced = std::mem::take(&mut raw.fully_replaced_namespaces);

            // Defer propagation: record state for the successful portion
            // first, then surface the failure summary at the end of cmd_apply.
            // This is the *only* path a failure takes now — apply_api reports
            // even a run-stopping error (a read-only plane, a stale view, a
            // restore needing recovery) on the result rather than returning
            // early, precisely so the namespaces that already landed reach the
            // state file before we exit non-zero.
            deferred_apply_error = raw.into_result().err();

            // Convergence is a read-only, advisory postscript: with a CP/DP
            // deployment the admin write lands on the control plane and the
            // data planes pick it up asynchronously, so "apply succeeded" is
            // not yet "the fleet is serving it". Only reported on a clean run
            // — after a partial failure the divergence question is moot until
            // the errors above are dealt with.
            if deferred_apply_error.is_none() {
                println!("{}", convergence_line(&client).await);
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
                    "Would write placeholder file to {} and allocate {} credential slot(s):",
                    env_config.file_output_path,
                    pending.len()
                );
                for r in pending {
                    println!("  [new] {}", r.slot);
                }
                println!("\nUse --auto-approve to proceed.");
                return Ok(());
            }

            // Write the placeholder-preserving file FIRST. `desired` still
            // has `${gh-env-secret:...}` strings because the initial resolve
            // doesn't replace rotate placeholders and the allocator hasn't
            // run yet. This is the committed-to-repo form; the real values
            // come via the separate `materialize-file.yml` workflow.
            apply::apply_file(&desired, &env_config.file_output_path)?;
            println!("Written to {}", env_config.file_output_path);

            // The mesh document goes to its own path as its own
            // `{version, mesh}` document. It is never folded into the gateway
            // file: gateway file mode ignores a `mesh:` key entirely, and the
            // mesh node's loader rejects a document that carries gateway
            // resources. Mesh config holds no credential placeholders, so
            // there is no materialize step for it — what is written here is
            // final.
            if let Some(mesh) = &desired_mesh {
                apply::apply_mesh_file(mesh, &env_config.mesh_file_output_path)?;
                println!(
                    "Written mesh document to {} ({})",
                    env_config.mesh_file_output_path,
                    mesh_summary_line(mesh)
                );
            }

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

    // Update state.resources from what actually succeeded, not from
    // `desired`. A wholesale rewrite from `desired` would drop the entry
    // for any failed Delete (the resource is absent from `desired`, so
    // its key gets removed from state) — in shared mode that orphans the
    // still-live resource: the next compute_diff_with_ownership would
    // classify it as unmanaged and stop retrying the deletion.
    //
    //   - File mode: no per-op concept. The file write is atomic, success
    //     means the entire desired set is recorded. Use record() with the
    //     full namespaces scope.
    //   - Api mode incremental: walk successful_ops; Add/Modify update the
    //     hash from desired, Delete removes the key. Failed ops are never
    //     in this list, so their state entries persist untouched.
    //   - Api mode full_replace: any namespace that completed gets a clean
    //     rebuild from desired (atomic /restore semantics). Namespaces
    //     that failed full_replace are NOT in `fully_replaced` and so are
    //     left alone.
    match env_config.gateway_mode {
        GatewayMode::File => {
            state.record(&desired, &namespaces);
        }
        GatewayMode::Api => {
            for ns in &fully_replaced {
                state.record_full_replace(ns, &desired);
            }
            for op in &successful_ops {
                state.record_op(op, &desired)?;
            }
            state.stamp_last_applied_if_clean(deferred_apply_error.is_none());
        }
    }
    state.credential_shard_count = shard_count;
    if !allocation_state_persisted {
        if let Some(outcome) = &allocation {
            let run_id = std::env::var("GITHUB_RUN_ID").ok();
            for slot in &outcome.allocated {
                state.record_credential(
                    &slot.slot,
                    slot.shard,
                    slot.delivered.as_ref().map(|d| d.login.as_str()),
                    run_id.as_deref(),
                );
            }
        }
    }
    if !overridden_for_audit.is_empty() {
        // An override belongs to the attempted commit even when the apply is
        // partial. Prefer the workflow's immutable input SHA; falling back to
        // last_applied first would misattribute a failed attempt to the prior
        // successfully landed commit.
        let commit = std::env::var("GITHUB_SHA")
            .ok()
            .or_else(|| state.last_applied_commit.clone())
            .unwrap_or_default();
        for (rule_id, approver) in &overridden_for_audit {
            state.record_override(rule_id, &commit, approver);
        }
    }
    state.save()?;

    if let Some(e) = deferred_apply_error {
        return Err(e.into());
    }

    Ok(())
}

async fn cmd_import(
    from_api: bool,
    from_file: Option<&str>,
    output_dir: &str,
    credential_bundle_output: Option<&str>,
    explicit_env: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = PathBuf::from(output_dir);
    let credential_bundle_path = credential_bundle_output.map(PathBuf::from);
    let (env_config, resolved, _repo) = resolve_runtime(explicit_env)?;

    let result = if from_api {
        // On a namespace-claim gateway, an unscoped discovery token gets an
        // intentionally empty `/namespaces` response. Treating that as a
        // successful all-namespace import could atomically publish an empty
        // tree. Require one explicit scope so the token and every backup read
        // carry the exact same namespace authority.
        let namespace = resolved.namespace_filter.as_deref().ok_or_else(|| {
            gitforgeops::error::Error::Config(
                "API import requires an explicit namespace. Set FERRUM_NAMESPACE or the selected environment's namespace filter, then import one namespace at a time."
                    .to_string(),
            )
        })?;
        let client = AdminClient::new_scoped(&env_config, [namespace])?;
        import::import_from_api(
            &client,
            &output_path,
            Some(namespace),
            credential_bundle_path.as_deref(),
        )
        .await?
    } else if let Some(file_path) = from_file {
        import::import_from_file(
            &PathBuf::from(file_path),
            &output_path,
            credential_bundle_path.as_deref(),
        )?
    } else {
        eprintln!("Specify --from-api or --from-file <PATH>");
        process::exit(1);
    };

    println!(
        "Imported: {} proxies, {} consumers, {} upstreams, {} plugin_configs",
        result.proxies, result.consumers, result.upstreams, result.plugin_configs
    );
    println!(
        "Import manifest: {}",
        output_path.join(import::IMPORT_MANIFEST_FILENAME).display()
    );
    if let Some(path) = credential_bundle_path {
        println!(
            "Secret migration bundle: {} (private mode 0600; seed the listed FERRUM_CREDS_BUNDLE* environment secrets, then securely delete the local file)",
            path.display()
        );
    }
    if let Some(notice) = result.source_metadata_notice() {
        println!("{notice}");
    }
    if let Some(notice) = result.unmanaged_sections_notice() {
        println!("{notice}");
    }

    Ok(())
}

async fn cmd_review(
    pr: Option<u64>,
    require_live: bool,
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
    let policy_cfg = policy::load_policies()?;
    let security_findings = diff::audit_security_with_policy(&desired, policy_cfg.as_ref());
    let secret_report = resolve_credentials(&mut desired, &env_config)?;
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

    let val_result = validate::run_validation(&desired, &env_config.edge_binary_path);
    let (validation_status, validation_output, validation_execution_error) = match &val_result {
        Ok(r) if r.success => (
            review::ReviewValidationStatus::Passed,
            format!("{}{}", r.stdout, r.stderr),
            None,
        ),
        Ok(r) => (
            review::ReviewValidationStatus::Rejected,
            format!("{}{}", r.stdout, r.stderr),
            None,
        ),
        Err(e) => {
            let message = format!("Validator execution error: {e}");
            (
                review::ReviewValidationStatus::ExecutionError,
                message,
                Some(e.to_string()),
            )
        }
    };

    let state = StateFile::load(&resolved.name)?;
    let managed = previously_managed(&resolved, &state);
    let namespaces = resolved_namespaces(&resolved, &desired, &state);
    let client = AdminClient::new_scoped(&env_config, &namespaces);

    let (diffs, breaking, unmanaged, spec_owned, comparison_error) = match &client {
        Ok(c) => match load_namespace_pairs_for(c, &desired, &namespaces).await {
            Ok(mut namespace_pairs) => {
                let cached = cached_namespace_names(&namespace_pairs);
                if cached.is_empty() {
                    if !bundle_loaded {
                        for pair in &mut namespace_pairs {
                            diff::mask_indeterminate_secret_values(&desired, &mut pair.actual);
                        }
                    }
                    let (d, b, u, s) = compute_namespace_diffs(
                        &namespace_pairs,
                        managed.as_ref(),
                        diff::DiffOptions::default(),
                    );
                    (d, b, u, s, None)
                } else {
                    (
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Some(format!(
                            "Live gateway comparison skipped: cached backup data was served for namespace(s) {}. API-spec ownership is unknown until the gateway configuration database recovers.",
                            cached.join(", ")
                        )),
                    )
                }
            }
            Err(e) => (
                Vec::new(),
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
            Vec::new(),
            Some(format!("Live gateway comparison skipped: {}", e)),
        ),
    };

    // security_findings was computed pre-resolve above; reuse it here.
    let bp_findings = diff::check_best_practices(&desired);

    let (policy_findings, override_reason, override_cfg) = match policy_cfg {
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

    let comment = review::build_review_comment_v2_with_status(
        validation_status,
        &validation_output,
        &diffs,
        &breaking,
        &security_findings,
        &bp_findings,
        &policy_findings,
        &unmanaged,
        &spec_owned,
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
            // Ordinary/fork review keeps the historical step-summary fallback.
            // Trusted `--require-live` review treats comment delivery as part
            // of the required reviewer-facing result and fails after writing
            // the same fallback evidence.
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
                    review::enforce_required_comment_delivery(require_live, &e.to_string())?;
                }
            }
        }
        None => {
            print!("{}", comment);
        }
    }

    if require_live {
        if let Some(error) = comparison_error {
            return Err(gitforgeops::error::Error::Config(format!(
                "trusted PR review requires a complete live gateway comparison: {error}"
            ))
            .into());
        }
    }

    let _ = !secret_report.results.is_empty();
    if let Some(error) = validation_execution_error {
        return Err(format!("validator execution failed during review: {error}").into());
    }
    Ok(())
}

fn cmd_envs(
    format: cli::EnvsFormat,
    include_scopes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo = load_repo_config()?;
    if include_scopes {
        if !matches!(format, cli::EnvsFormat::Json) {
            return Err(gitforgeops::error::Error::Config(
                "envs --include-scopes requires --format json".to_string(),
            )
            .into());
        }
        let scopes = match repo {
            Some(r) => r.environment_scopes(),
            None => vec![gitforgeops::config::repo_config::EnvironmentScope {
                environment: ResolvedEnv::default_env_name(),
                namespaces: None,
            }],
        };
        println!("{}", serde_json::to_string(&scopes)?);
        return Ok(());
    }
    let names = match repo {
        Some(r) => r.environment_names(),
        None => vec![ResolvedEnv::default_env_name()],
    };
    match format {
        cli::EnvsFormat::Text => {
            for n in names {
                println!("{n}");
            }
        }
        cli::EnvsFormat::Json => {
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

    let _state_lock = StateFile::lock(&resolved.name)?;
    let mut state = StateFile::load(&resolved.name)?;
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

    // Preflight 1b: in exclusive mode, the same ownership-scope rules
    // apply/diff/plan/review enforce must apply here too. A manual rotate
    // on an exclusive env targeting a consumer whose namespace isn't in
    // `ownership.namespaces` would push a consumer the ownership contract
    // never signed for — exactly the violation enforce_exclusive_scope
    // exists to prevent.
    enforce_exclusive_scope(&resolved, &desired_for_check)?;

    // Preflight 2: target slot corresponds to an actual placeholder in the
    // repo. A typo in --credential or pointing at a literal value would
    // otherwise write random bytes into an orphaned Env Secret with no
    // gateway-side reference.
    let empty_bundle = BTreeMap::new();
    // Lenient: this scan only answers "does a placeholder exist at this slot",
    // so a generation-constraint complaint about some *other* slot must not
    // abort a rotation that has nothing to do with it.
    let placeholder_report = secrets::report_secrets_lenient(&desired_for_check, &empty_bundle)?;
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
        let _ = secrets::resolve_secrets(&mut single, &shim_bundle)?;
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

    let client = build_github_api_client(&env_config)?;

    let outcome = match secrets::rotate_and_deliver(
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
    .await
    {
        Ok(outcome) => outcome,
        Err(failure) => {
            if !failure.partial.allocated.is_empty() {
                surface_delivered_credentials(&env_config, &failure.partial).await?;
            }
            return Err(failure.source.into());
        }
    };

    // Emit the encrypted delivery blob FIRST, before attempting the
    // gateway push. rotate_and_deliver has already written the new value
    // to the GitHub Env Secret; if we returned Err from the push without
    // having printed the ciphertext, the recipient would have no way to
    // recover the value — the bundle's new entry would be treated as
    // resolved on subsequent runs and the allocator wouldn't re-deliver.
    //
    // A gateway push failure after successful delivery is recoverable:
    // the next `gitforgeops apply` picks up the bundle value and pushes
    // it through. Lost blob is not recoverable; order must be delivery
    // first.
    match &outcome.delivered {
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

    // Now push to the gateway.
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
                outcome.delivered.as_ref().map(|d| d.login.as_str()),
                std::env::var("GITHUB_RUN_ID").ok().as_deref(),
            );
            state.save()?;
            println!("Rotated slot {slot} in shard {}", outcome.shard);
            println!("Gateway consumer '{}/{}' updated.", ns, consumer);
        }
        Err(e) => {
            // Hard-fail: the credential store and gateway are out of sync.
            // The recipient has the blob (printed above), so they're not
            // stranded; run apply to close the gap.
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
    // `rotate_and_deliver` just wrote the fresh value into the bundle; this
    // resolve picks it up for the consumer being pushed to the gateway.
    let _ = secrets::resolve_secrets(&mut desired, &merged)?;

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

    let client = AdminClient::new_scoped(env_config, [namespace])?;
    client.update_consumer(consumer, namespace).await?;
    Ok(())
}
