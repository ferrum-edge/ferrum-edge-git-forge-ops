use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::config::ApplyStrategy;
use crate::diff::resource_diff::{
    compute_diff_with_options, state_key, DiffAction, DiffOptions, DiffResult, OwnershipScope,
    ResourceDiff, SpecOwnedResource,
};
use crate::http_client::{
    self, AdminClient, BackupExtras, BatchCreate, DeleteOutcome, BATCH_MAX_BODY_BYTES,
};

/// A single per-resource operation that completed successfully against the
/// gateway. cmd_apply uses this to update `state.resources` incrementally,
/// so partial-failure runs don't touch state for failed ops. Critical for
/// shared mode: a failed Delete must NOT drop the resource from state, or
/// `compute_diff_with_ownership` will reclassify it as unmanaged on the
/// next run and stop retrying the deletion.
#[derive(Debug, Clone)]
pub struct AppliedOp {
    pub kind: String,
    pub namespace: String,
    pub id: String,
    pub action: DiffAction,
}

/// Caller-selected behaviour for a single apply run.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    pub strategy: ApplyStrategy,
    /// Write-ahead create keys that still need an idempotent repository-owned
    /// PUT before they may enter the managed delete fence.
    pub pending_create_assertions: BTreeSet<String>,
    /// `--confirm-api-spec-deletion`. Full replace may proceed against a
    /// namespace with API specs only with this explicit destructive opt-in;
    /// an exclusive incremental apply may prune live resources tagged with an
    /// `api_spec_id`. Without it, spec-owned resources are reported and
    /// skipped, and non-empty spec namespaces reject full replacement.
    pub confirm_api_spec_deletion: bool,
}

#[derive(Debug, Default)]
pub struct ApplyResult {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    /// Deletes the gateway answered with 404. Tolerated individually (the
    /// resource is gone either way), but counted so an all-404 namespace can
    /// be called out — see [`all_deletes_missing_warning`].
    pub deletes_missing: usize,
    pub unmanaged_skipped: usize,
    /// Live resources owned by an API-spec import that this run deliberately
    /// left alone (see [`spec_owned_skip_messages`]).
    pub spec_owned_skipped: usize,
    pub errors: Vec<String>,
    /// A failure that stopped the run rather than being recorded and stepped
    /// over: a read-only admin plane, a stale gateway view, a restore that
    /// needs manual recovery.
    ///
    /// Carried on the result instead of being returned as `Err` so the caller
    /// still receives everything that *did* land. Returning early threw the
    /// aggregate away, and with it the per-op records `cmd_apply` writes into
    /// the state file — so a run that successfully reconciled namespaces 0..N
    /// before namespace N+1 hit a read-only plane recorded none of it, and the
    /// next run re-derived those resources as unmanaged. The caller persists
    /// state from [`ApplyResult::applied_incremental`], then propagates this
    /// through its deferred-error path so the run still exits non-zero.
    pub fatal_error: Option<String>,
    /// Per-resource operations that succeeded in `apply_incremental`.
    /// Empty for `apply_full_replace` runs — see `fully_replaced_namespaces`.
    pub applied_incremental: Vec<AppliedOp>,
    /// Namespaces where `apply_full_replace` completed successfully.
    /// /restore is atomic per namespace, so on success the entire
    /// namespace's desired state is now live and state.resources for that
    /// namespace can be rebuilt from desired without per-op tracking.
    pub fully_replaced_namespaces: Vec<String>,
}

impl ApplyResult {
    pub fn into_result(mut self) -> crate::error::Result<Self> {
        let fatal = self.fatal_error.take();
        let counts = format!(
            "{} created, {} updated, {} deleted",
            self.created, self.updated, self.deleted
        );

        match (fatal, self.errors.is_empty()) {
            (None, true) => Ok(self),
            (None, false) => Err(crate::error::Error::Config(format!(
                "Apply failed after partial success: {counts}, {} failed\n{}",
                self.errors.len(),
                self.errors.join("\n")
            ))),
            (Some(fatal), true) => Err(crate::error::Error::Config(format!(
                "Apply stopped: {fatal}\nCompleted before stopping: {counts}."
            ))),
            (Some(fatal), false) => Err(crate::error::Error::Config(format!(
                "Apply stopped: {fatal}\nCompleted before stopping: {counts}, {} failed\n{}",
                self.errors.len(),
                self.errors.join("\n")
            ))),
        }
    }
}

/// Warn when a namespace's deletes *all* came back 404.
///
/// One 404 is routine — the gateway cascades deletes server-side, so a
/// diff-driven follow-up legitimately finds nothing. Every delete 404ing is a
/// different story: it is what a run pointed at the wrong gateway, or sending
/// the wrong `X-Ferrum-Namespace`, looks like. The state entries are removed
/// either way (the resources are absent from the view we were given), so the
/// next run will not retry them — which makes this the only moment the
/// operator can catch it.
pub fn all_deletes_missing_warning(
    namespace: &str,
    deleted: usize,
    deletes_missing: usize,
) -> Option<String> {
    if deleted == 0 || deletes_missing < deleted {
        return None;
    }
    Some(format!(
        "[{namespace}] all {deleted} delete(s) returned 404 — the resources were already absent. \
         Verify FERRUM_GATEWAY_URL and the namespace routing for this environment; state entries \
         were still removed."
    ))
}

/// Order in which a diff entry must be issued against the admin API.
///
/// The gateway enforces referential integrity, so the naive per-kind order
/// (Proxy → Consumer → Upstream → PluginConfig) rejects a new proxy that
/// references a new upstream: `"upstream_id '…' does not exist in namespace
/// '…'"`.
///
/// Adds and modifies run first, in dependency order, then deletes in reverse:
///
/// | Rank | Operations                                  |
/// |------|---------------------------------------------|
/// | 0    | Add/Modify Upstream, Add/Modify Consumer    |
/// | 1    | Add/Modify Proxy                            |
/// | 2    | Add/Modify PluginConfig                     |
/// | 3    | Delete PluginConfig                         |
/// | 4    | Delete Proxy                                |
/// | 5    | Delete Upstream, Delete Consumer            |
///
/// Deletes go *after* adds/modifies rather than before: an upstream can only
/// be removed once nothing references it, and the proxy modify that drops the
/// reference has to land first (`DELETE /upstreams/{id}` answers 409 while a
/// proxy still points at it). The cost is that a delete-then-recreate on a
/// contended unique value (a listen address, say) now conflicts — rare, and
/// visible as a 409 rather than a silent wrong result.
pub fn operation_rank(action: &DiffAction, kind: &str) -> u8 {
    match action {
        DiffAction::Add | DiffAction::Modify => match kind {
            "Upstream" | "Consumer" => 0,
            "Proxy" => 1,
            "PluginConfig" => 2,
            _ => 2,
        },
        DiffAction::Delete => match kind {
            "PluginConfig" => 3,
            "Proxy" => 4,
            "Upstream" | "Consumer" => 5,
            _ => 3,
        },
    }
}

/// Sort a computed diff into admin-API application order.
///
/// Stable, so resources sharing a rank keep the diff's original (deterministic)
/// ordering. Applied here in the api target rather than in `compute_diff` —
/// the diff is also consumed by `plan`/`diff` output where the grouping by kind
/// is the more readable presentation.
pub fn order_diffs(mut diffs: Vec<ResourceDiff>) -> Vec<ResourceDiff> {
    diffs.sort_by_key(|d| operation_rank(&d.action, &d.kind));
    diffs
}

/// Apply configuration to the gateway via the admin API.
///
/// Iterates `namespaces` explicitly rather than inferring them from `desired`.
/// This matters for `exclusive` ownership: a namespace the repo manages but no
/// longer declares resources in still needs to be reconciled (to prune the
/// resources that were removed). The caller decides the scope (typically
/// `ownership.namespaces` for exclusive, or the namespaces present in
/// `desired` for shared).
///
/// In shared ownership mode, only resources in the caller-provided managed set
/// can be deleted; admin-added resources are reported in `unmanaged_skipped`
/// but not touched. Exclusive mode treats every live resource in scope as owned.
///
/// **Preflight:** an authenticated `GET /health` runs before the first
/// mutation. A gateway that reports `admin_writes_enabled: false` (or runs in
/// file/dp/mesh/node_agent mode) fails the whole run with one clear error
/// instead of N per-resource 403s.
///
/// **Atomicity:** both strategies are **per-namespace**, not environment-wide.
/// `full_replace` delegates to the gateway's `/restore?confirm=true` endpoint
/// which is atomic for the single namespace it targets, but when the scope
/// spans multiple namespaces each namespace is restored in its own API call;
/// a failure on namespace N leaves namespaces 0..N already restored. To make
/// the per-namespace failure visible rather than swallowing subsequent
/// namespaces, a restore error is recorded in `ApplyResult::errors` and the
/// loop continues to the next namespace. The overall call still returns Err
/// via `into_result()` so the workflow fails, but the error message now
/// enumerates every namespace that failed (and implicitly, every one that
/// succeeded). Operators running cross-namespace full_replace should
/// understand this: partial restores need manual remediation.
///
/// **Fatal errors** (see [`is_fatal`]) stop the loop but do *not* discard the
/// aggregate: they are recorded in [`ApplyResult::fatal_error`] and returned as
/// `Ok`, so the caller can persist state for everything that already landed
/// before propagating the failure. `into_result()` still turns it into an
/// `Err`, so the run exits non-zero either way.
#[derive(Debug, Default)]
struct PreparedApply {
    actuals: BTreeMap<String, GatewayConfig>,
    full_replaces: BTreeMap<String, PreparedFullReplace>,
    /// Namespaces that cannot be reconciled this run, keyed to the reason.
    ///
    /// A repository declaration colliding with an API-spec-owned row is a
    /// property of *that* namespace, not of the gateway or of the run, so it
    /// stops writes to that namespace only. Every other namespace still
    /// reconciles, and the reason lands in `ApplyResult::errors` so the run
    /// exits non-zero with the conflict named.
    blocked: BTreeMap<String, String>,
}

#[derive(Debug)]
struct PreparedFullReplace {
    config: GatewayConfig,
    extras: BackupExtras,
}

/// Run every deterministic and remote write-capability preflight without
/// mutating the gateway.
///
/// `cmd_apply` calls this before credential allocation. `apply_api` repeats it
/// immediately before writes so a library caller cannot bypass the boundary
/// and a plane that became read-only while credentials were delivered still
/// fails before the first gateway mutation.
pub async fn preflight_api_apply(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&BTreeMap<String, BackupExtras>>,
    options: &ApplyOptions,
) -> crate::error::Result<()> {
    let _prepared = prepare_apply(
        desired,
        client,
        namespaces,
        actual_by_namespace,
        extras_by_namespace,
        options,
    )
    .await?;
    preflight_writes(client).await
}

pub async fn apply_api(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&BTreeMap<String, BackupExtras>>,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
    let prepared = prepare_apply(
        desired,
        client,
        namespaces,
        actual_by_namespace,
        extras_by_namespace,
        options,
    )
    .await?;
    preflight_writes(client).await?;

    let mut aggregate = ApplyResult::default();

    for namespace in namespaces {
        if let Some(reason) = prepared.blocked.get(namespace) {
            eprintln!("[{namespace}] {reason}");
            aggregate.errors.push(format!("[{namespace}] {reason}"));
            continue;
        }
        let desired_namespace = crate::config::filter_config_by_namespace(desired, namespace);
        let namespace_result = match options.strategy {
            ApplyStrategy::FullReplace => {
                // Record-and-continue on error so a multi-namespace restore
                // reports every failing namespace, not just the first. The
                // gateway's `/restore` is already atomic per-namespace, so
                // a failure here doesn't cascade into the next namespace;
                // the worst case is that namespaces 0..N restored and
                // namespace N failed, which operators see in the aggregate
                // error listing.
                let Some(full_replace) = prepared.full_replaces.get(namespace) else {
                    return Err(crate::error::Error::Config(format!(
                        "internal error: full-replace payload for namespace `{namespace}` was not prebuilt"
                    )));
                };
                match apply_full_replace(
                    full_replace,
                    client,
                    namespace,
                    &desired_namespace,
                    options,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) if is_fatal(&e) => {
                        aggregate.fatal_error = Some(format!("[{namespace}] {e}"));
                        break;
                    }
                    Err(e) => {
                        aggregate.errors.push(format!("[{namespace}] {e}"));
                        continue;
                    }
                }
            }
            ApplyStrategy::Incremental => {
                let actual = prepared.actuals.get(namespace);
                match apply_incremental(
                    &desired_namespace,
                    client,
                    namespace,
                    ownership_scope,
                    actual,
                    options,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) if is_fatal(&e) => {
                        aggregate.fatal_error = Some(format!("[{namespace}] {e}"));
                        break;
                    }
                    Err(e) => {
                        aggregate.errors.push(format!("[{namespace}] {e}"));
                        continue;
                    }
                }
            }
        };

        if let Some(warning) = all_deletes_missing_warning(
            namespace,
            namespace_result.deleted,
            namespace_result.deletes_missing,
        ) {
            eprintln!("Warning: {warning}");
        }

        aggregate.created += namespace_result.created;
        aggregate.updated += namespace_result.updated;
        aggregate.deleted += namespace_result.deleted;
        aggregate.deletes_missing += namespace_result.deletes_missing;
        aggregate.unmanaged_skipped += namespace_result.unmanaged_skipped;
        aggregate.spec_owned_skipped += namespace_result.spec_owned_skipped;
        aggregate
            .applied_incremental
            .extend(namespace_result.applied_incremental);
        aggregate
            .fully_replaced_namespaces
            .extend(namespace_result.fully_replaced_namespaces);
        aggregate.errors.extend(
            namespace_result
                .errors
                .into_iter()
                .map(|error| format!("[{namespace}] {error}")),
        );

        // A mid-namespace stop (a read-only plane refusing the Nth resource)
        // reaches us on the result rather than as an Err. Everything above has
        // been folded into the aggregate; stop before the next namespace,
        // which would fail identically.
        if let Some(fatal) = namespace_result.fatal_error {
            aggregate.fatal_error = Some(format!("[{namespace}] {fatal}"));
            break;
        }
    }

    Ok(aggregate)
}

/// Materialize the complete live view and every full-replace body before a
/// write is possible. This prevents a deterministic error in a later
/// namespace from appearing only after an earlier namespace was restored.
async fn prepare_apply(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&BTreeMap<String, BackupExtras>>,
    options: &ApplyOptions,
) -> crate::error::Result<PreparedApply> {
    validate_no_desired_spec_tags(desired)?;
    let mut prepared = PreparedApply::default();
    let mut extras = BTreeMap::new();

    for namespace in namespaces {
        let supplied_actual = actual_by_namespace.and_then(|items| items.get(namespace));
        let supplied_extras = extras_by_namespace.and_then(|items| items.get(namespace));
        let needs_paired_snapshot = matches!(options.strategy, ApplyStrategy::FullReplace)
            && (supplied_actual.is_none() || supplied_extras.is_none());

        if needs_paired_snapshot || supplied_actual.is_none() {
            let snapshot = client.get_backup_snapshot(namespace).await?;
            if snapshot.cached {
                return Err(crate::error::Error::StaleGatewayView(stale_view_message()));
            }
            prepared.actuals.insert(namespace.clone(), snapshot.config);
            extras.insert(namespace.clone(), snapshot.extras);
        } else if let Some(actual) = supplied_actual {
            prepared.actuals.insert(namespace.clone(), actual.clone());
            if let Some(value) = supplied_extras {
                extras.insert(namespace.clone(), value.clone());
            }
        }
    }

    // A cached backup deliberately omits API-spec documents and clears
    // `api_spec_id` tags. That makes every derived mutation unsafe, not just
    // deletes. The flag is sticky across namespaces, so fail before any
    // conflict or payload decision can trust that incomplete classification.
    ensure_authoritative_view(client)?;

    for namespace in namespaces {
        let desired_namespace = crate::config::filter_config_by_namespace(desired, namespace);
        let actual = prepared.actuals.get(namespace).ok_or_else(|| {
            crate::error::Error::Config(format!(
                "internal error: authoritative backup for namespace `{namespace}` was not prepared"
            ))
        })?;
        if let Some(conflict) = spec_owned_conflict_block(&desired_namespace, actual, namespace) {
            prepared.blocked.insert(namespace.clone(), conflict);
            continue;
        }

        if matches!(options.strategy, ApplyStrategy::FullReplace) {
            let live_extras = extras.get(namespace).ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "internal error: backup extras for namespace `{namespace}` were not prepared"
                ))
            })?;
            ensure_restore_sections_supported(namespace, live_extras)?;
            prepared.full_replaces.insert(
                namespace.clone(),
                prepare_full_replace(&desired_namespace, actual, live_extras, namespace, options)?,
            );
        }
    }

    Ok(prepared)
}

/// A repository declaration and a live API-spec-owned row are two writers for
/// one identity. Skipping the row and exiting green falsely reports a
/// successful convergence, so the namespace is taken out of the run entirely.
///
/// The block is namespace-scoped on purpose. The conflict says nothing about
/// any other namespace's rows, and stopping the whole run turned one team's
/// mis-declared proxy into an outage for every other team sharing the
/// environment. `Some(reason)` means "reconcile nothing in this namespace and
/// report this"; the caller records it as a per-namespace error, so the run
/// still exits non-zero.
fn spec_owned_conflict_block(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    namespace: &str,
) -> Option<String> {
    let result = compute_diff_with_options(
        desired,
        actual,
        OwnershipScope::Exclusive,
        DiffOptions::default(),
    );
    let conflicts = result
        .spec_conflicts()
        .map(|resource| {
            format!(
                "{} `{}` (API spec `{}`)",
                resource.kind, resource.id, resource.api_spec_id
            )
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        return None;
    }
    Some(format!(
        "refusing apply for namespace `{namespace}`: repository declarations conflict with live API-spec-owned resources: {}. Remove the repository declaration or manage the row through the API spec importer. No resource in this namespace was written; other namespaces were reconciled normally",
        conflicts.join(", ")
    ))
}

/// Errors that make continuing to the next namespace pointless or unsafe.
///
/// A read-only plane refuses every namespace identically, and a stale gateway
/// view is stale for all of them. Restore rollback damage needs a human before
/// anything else is attempted.
fn is_fatal(error: &crate::error::Error) -> bool {
    matches!(
        error,
        crate::error::Error::GatewayReadOnly(_)
            | crate::error::Error::StaleGatewayView(_)
            | crate::error::Error::RestoreNeedsManualRecovery(_)
            | crate::error::Error::UnsupportedBackupSections(_)
            | crate::error::Error::CommittedNotLive { .. }
            | crate::error::Error::AmbiguousMutation(_)
    )
}

/// Ask the gateway whether it will accept config mutations at all.
///
/// A gateway that cannot be reached for `/health` is not treated as a blocker:
/// older builds and restricted deployments may not serve the authenticated
/// projection, and failing an apply on a preflight that is itself advisory
/// would be worse than letting the first real mutation report the truth.
async fn preflight_writes(client: &AdminClient) -> crate::error::Result<()> {
    match client.get_health().await {
        Ok(health) => match http_client::write_block_reason(&health) {
            Some(reason) => Err(crate::error::Error::GatewayReadOnly(reason)),
            None => Ok(()),
        },
        Err(crate::error::Error::GatewayReadOnly(reason)) => {
            Err(crate::error::Error::GatewayReadOnly(reason))
        }
        Err(e) => {
            eprintln!("Warning: admin preflight GET /health failed ({e}); continuing.");
            Ok(())
        }
    }
}

/// Build one restore body without mutating the gateway.
///
/// `POST /restore` validates the API-spec ownership graph *as one unit* before
/// it deletes anything (ferrum-edge `src/admin/backup.rs`,
/// `validate_restore_api_specs_section_with_total_limit`): every
/// `api_specs.items` entry must name an owning proxy that is present in the
/// same payload and carries the matching `api_spec_id`, and every tagged
/// proxy/upstream/plugin config must name a spec that is present in
/// `api_specs.items`. Restore re-creates the spec documents verbatim after the
/// config resources and never re-extracts resources from them, so carrying the
/// live graph through cannot duplicate rows. A payload that omits one half of
/// the graph is a `400` — which is exactly what a desired-only body is for a
/// namespace with an ingested spec.
///
/// So the non-destructive path sends the repository's desired rows *plus* the
/// authoritative live spec-owned rows, and hands the live `api_specs` section
/// back for [`http_client::build_restore_body`] to splice in.
///
/// Two deliberate omissions:
///
/// - **An empty `api_specs` section is not sent.** The gateway answers `409`
///   when a payload without the section targets a namespace that holds specs,
///   which is the only thing that catches a spec created between our backup
///   and the restore. Sending `items: []` is defined as an intentional wipe
///   and would silently delete it instead.
/// - **`gateway_trust_bundles` is never sent.** The gateway defines an absent
///   section as "leave trust exactly as it is", so omitting it preserves the
///   live roots without the lost-update window that replaying a possibly-stale
///   snapshot would open.
fn prepare_full_replace(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    live_extras: &BackupExtras,
    namespace: &str,
    options: &ApplyOptions,
) -> crate::error::Result<PreparedFullReplace> {
    if options.confirm_api_spec_deletion {
        // Deliberate destruction of the spec graph: desired rows only, with
        // `confirm_api_spec_deletion=true` on the query so the gateway's
        // existing-spec guard stands down. Trust bundles still stay absent, so
        // the namespace's roots survive the wipe.
        return Ok(PreparedFullReplace {
            config: desired.clone(),
            extras: BackupExtras::default(),
        });
    }

    // Validate both directions even for an empty/absent section so dangling
    // ownership tags cannot be stripped accidentally by treating a malformed
    // snapshot as legacy data.
    let config = preserve_spec_owned_graph(desired, actual, live_extras, namespace)?;
    Ok(PreparedFullReplace {
        config,
        extras: BackupExtras {
            api_specs: live_extras.api_specs.clone(),
            ..BackupExtras::default()
        },
    })
}

async fn apply_full_replace(
    prepared: &PreparedFullReplace,
    client: &AdminClient,
    namespace: &str,
    desired: &GatewayConfig,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
    client
        .post_restore(
            &prepared.config,
            namespace,
            &prepared.extras,
            options.confirm_api_spec_deletion,
        )
        .await?;

    Ok(ApplyResult {
        created: desired.proxies.len()
            + desired.consumers.len()
            + desired.upstreams.len()
            + desired.plugin_configs.len(),
        // /restore is atomic for the namespace — on success, the entire
        // namespace's desired state is live. cmd_apply rebuilds
        // state.resources for this namespace from `desired` without per-op
        // tracking.
        fully_replaced_namespaces: vec![namespace.to_string()],
        ..Default::default()
    })
}

fn ensure_restore_sections_supported(
    namespace: &str,
    extras: &BackupExtras,
) -> crate::error::Result<()> {
    if extras.unsupported_sections.is_empty() {
        return Ok(());
    }
    Err(crate::error::Error::UnsupportedBackupSections(format!(
        "namespace {namespace:?} returned unsupported top-level backup section(s) {:?}; use incremental apply or upgrade gitforgeops before restoring this namespace",
        extras.unsupported_sections
    )))
}

/// Merge the authoritative live API-spec-owned graph into a full-replace
/// payload while leaving the repository-owned desired graph authoritative.
///
/// API spec documents and their tagged resources are an indivisible backup
/// unit. Carrying one without the other fails gateway restore validation; an
/// ID collision would instead give two owners the same row. This helper
/// validates both directions before any POST is attempted.
pub fn preserve_spec_owned_graph(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    extras: &BackupExtras,
    namespace: &str,
) -> crate::error::Result<GatewayConfig> {
    validate_no_desired_spec_tags(desired)?;
    let api_specs = parse_api_spec_owners(extras, namespace)?;
    let api_spec_ids = api_specs.keys().cloned().collect::<BTreeSet<_>>();
    let mut referenced_spec_ids = BTreeSet::new();
    let mut merged = desired.clone();

    for p in &actual.proxies {
        let Some(spec_id) = p.api_spec_id.as_deref() else {
            continue;
        };
        validate_preserved_owner(
            &api_spec_ids,
            &mut referenced_spec_ids,
            spec_id,
            "Proxy",
            &p.id,
            &p.namespace,
            namespace,
        )?;
        if desired
            .proxies
            .iter()
            .any(|candidate| candidate.namespace == p.namespace && candidate.id == p.id)
        {
            return Err(spec_owned_conflict("Proxy", &p.id, spec_id, namespace));
        }
        merged.proxies.push(p.clone());
    }

    for u in &actual.upstreams {
        let Some(spec_id) = u.api_spec_id.as_deref() else {
            continue;
        };
        validate_preserved_owner(
            &api_spec_ids,
            &mut referenced_spec_ids,
            spec_id,
            "Upstream",
            &u.id,
            &u.namespace,
            namespace,
        )?;
        if desired
            .upstreams
            .iter()
            .any(|candidate| candidate.namespace == u.namespace && candidate.id == u.id)
        {
            return Err(spec_owned_conflict("Upstream", &u.id, spec_id, namespace));
        }
        merged.upstreams.push(u.clone());
    }

    for pc in &actual.plugin_configs {
        let Some(spec_id) = pc.api_spec_id.as_deref() else {
            continue;
        };
        validate_preserved_owner(
            &api_spec_ids,
            &mut referenced_spec_ids,
            spec_id,
            "PluginConfig",
            &pc.id,
            &pc.namespace,
            namespace,
        )?;
        if desired
            .plugin_configs
            .iter()
            .any(|candidate| candidate.namespace == pc.namespace && candidate.id == pc.id)
        {
            return Err(spec_owned_conflict(
                "PluginConfig",
                &pc.id,
                spec_id,
                namespace,
            ));
        }
        merged.plugin_configs.push(pc.clone());
    }

    if api_spec_ids != referenced_spec_ids {
        let missing = api_spec_ids
            .difference(&referenced_spec_ids)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(crate::error::Error::Config(format!(
            "refusing full_replace for namespace `{namespace}`: the authoritative backup contains API spec document(s) with no tagged proxy/upstream/plugin resource ({missing}). The complete ownership graph cannot be proven; retry after the gateway configuration database is healthy."
        )));
    }

    validate_complete_spec_owned_graph(&api_specs, &merged, namespace)?;

    Ok(merged)
}

fn parse_api_spec_owners(
    extras: &BackupExtras,
    namespace: &str,
) -> crate::error::Result<BTreeMap<String, String>> {
    let Some(section) = extras.api_specs.as_ref() else {
        return Ok(BTreeMap::new());
    };
    let items = section
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            crate::error::Error::Config(
                "refusing full_replace: backup `api_specs` is not an object with an `items` array; the ownership graph cannot be proven complete"
                    .to_string(),
            )
        })?;
    let mut specs = BTreeMap::new();
    for item in items {
        let id = item
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                crate::error::Error::Config(
                    "refusing full_replace: an `api_specs.items` entry has no non-empty string `id`; the ownership graph cannot be proven complete"
                        .to_string(),
                )
            })?;
        let proxy_id = item
            .get("proxy_id")
            .and_then(serde_json::Value::as_str)
            .filter(|proxy_id| !proxy_id.is_empty())
            .ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "refusing full_replace: API spec `{id}` has no non-empty string `proxy_id`; the ownership graph cannot be proven complete"
                ))
            })?;
        let item_namespace = item
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("ferrum");
        if item_namespace != namespace {
            return Err(crate::error::Error::Config(format!(
                "refusing full_replace for namespace `{namespace}`: API spec `{id}` declares namespace `{item_namespace}`"
            )));
        }
        if specs.insert(id.to_string(), proxy_id.to_string()).is_some() {
            return Err(crate::error::Error::Config(format!(
                "refusing full_replace: backup `api_specs` contains duplicate id `{id}`"
            )));
        }
    }
    Ok(specs)
}

/// Validate the ownership relationships the gateway enforces on restore,
/// before issuing the destructive POST. The payload still passes through the
/// gateway's authoritative validator; this preflight makes an incomplete or
/// internally inconsistent backup fail early with actionable resource ids.
fn validate_complete_spec_owned_graph(
    api_specs: &BTreeMap<String, String>,
    config: &GatewayConfig,
    namespace: &str,
) -> crate::error::Result<()> {
    for (spec_id, owning_proxy_id) in api_specs {
        let tagged_proxies = config
            .proxies
            .iter()
            .filter(|proxy| proxy.api_spec_id.as_deref() == Some(spec_id.as_str()))
            .collect::<Vec<_>>();
        if tagged_proxies.len() != 1 || tagged_proxies[0].id != *owning_proxy_id {
            return Err(crate::error::Error::Config(format!(
                "refusing full_replace for namespace `{namespace}`: API spec `{spec_id}` must have exactly one tagged owning proxy `{owning_proxy_id}`, but the authoritative backup does not contain that graph"
            )));
        }
        let owning_proxy = tagged_proxies[0];

        let owned_upstreams = config
            .upstreams
            .iter()
            .filter(|upstream| upstream.api_spec_id.as_deref() == Some(spec_id.as_str()))
            .collect::<Vec<_>>();
        if owned_upstreams.len() > 1 {
            return Err(crate::error::Error::Config(format!(
                "refusing full_replace for namespace `{namespace}`: API spec `{spec_id}` has {} tagged upstreams; the gateway supports at most one",
                owned_upstreams.len()
            )));
        }
        for upstream in owned_upstreams {
            if let Some(foreign_proxy) = config.proxies.iter().find(|proxy| {
                proxy.id != *owning_proxy_id
                    && proxy.upstream_id.as_deref() == Some(upstream.id.as_str())
            }) {
                return Err(crate::error::Error::Config(format!(
                    "refusing full_replace for namespace `{namespace}`: spec-owned upstream `{}` for API spec `{spec_id}` is referenced by foreign proxy `{}`",
                    upstream.id, foreign_proxy.id
                )));
            }
        }

        let associated_plugins = owning_proxy
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect::<BTreeSet<_>>();
        for plugin in config
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.api_spec_id.as_deref() == Some(spec_id.as_str()))
        {
            let scope_valid = match plugin.scope {
                crate::config::schema::PluginScope::Global => false,
                crate::config::schema::PluginScope::Proxy => {
                    plugin.proxy_id.as_deref() == Some(owning_proxy_id.as_str())
                }
                crate::config::schema::PluginScope::ProxyGroup => plugin.proxy_id.is_none(),
            };
            if !scope_valid || !associated_plugins.contains(plugin.id.as_str()) {
                return Err(crate::error::Error::Config(format!(
                    "refusing full_replace for namespace `{namespace}`: spec-owned plugin config `{}` is not a valid association on API spec `{spec_id}` owning proxy `{owning_proxy_id}`",
                    plugin.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_preserved_owner(
    api_spec_ids: &BTreeSet<String>,
    referenced_spec_ids: &mut BTreeSet<String>,
    spec_id: &str,
    kind: &str,
    id: &str,
    resource_namespace: &str,
    namespace: &str,
) -> crate::error::Result<()> {
    if resource_namespace != namespace {
        return Err(crate::error::Error::Config(format!(
            "refusing full_replace for namespace `{namespace}`: live {kind} `{id}` declares namespace `{resource_namespace}` in the same backup snapshot"
        )));
    }
    if spec_id.is_empty() || !api_spec_ids.contains(spec_id) {
        return Err(crate::error::Error::Config(format!(
            "refusing full_replace for namespace `{namespace}`: live {kind} `{id}` is tagged with API spec `{spec_id}`, but that document is absent from the same authoritative backup"
        )));
    }
    referenced_spec_ids.insert(spec_id.to_string());
    Ok(())
}

fn spec_owned_conflict(
    kind: &str,
    id: &str,
    spec_id: &str,
    namespace: &str,
) -> crate::error::Error {
    crate::error::Error::Config(format!(
        "refusing full_replace for namespace `{namespace}`: repo-owned {kind} `{id}` conflicts with the live resource owned by API spec `{spec_id}`. Remove the repo declaration or manage the row through the API spec importer."
    ))
}

fn hand_authored_spec_tag(kind: &str, id: &str, namespace: &str) -> crate::error::Error {
    crate::error::Error::Config(format!(
        "refusing repository configuration for namespace `{namespace}`: desired {kind} `{id}` contains an `api_spec_id`. That ownership tag is admin-generated and cannot be declared by the repository."
    ))
}

/// Reject repository declarations that forge the gateway's API-spec
/// ownership marker. The marker is admin-generated and must never influence
/// either incremental or full-replace mutations from a Git tree, including a
/// full replace where spec deletion was explicitly confirmed.
pub fn validate_no_desired_spec_tags(desired: &GatewayConfig) -> crate::error::Result<()> {
    for proxy in &desired.proxies {
        if proxy.api_spec_id.is_some() {
            return Err(hand_authored_spec_tag("Proxy", &proxy.id, &proxy.namespace));
        }
    }
    for upstream in &desired.upstreams {
        if upstream.api_spec_id.is_some() {
            return Err(hand_authored_spec_tag(
                "Upstream",
                &upstream.id,
                &upstream.namespace,
            ));
        }
    }
    for plugin in &desired.plugin_configs {
        if plugin.api_spec_id.is_some() {
            return Err(hand_authored_spec_tag(
                "PluginConfig",
                &plugin.id,
                &plugin.namespace,
            ));
        }
    }
    Ok(())
}

async fn apply_incremental(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespace: &str,
    ownership_scope: OwnershipScope<'_>,
    actual: Option<&GatewayConfig>,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
    let fetched_actual;
    let actual = match actual {
        Some(actual) => actual,
        None => {
            fetched_actual = client.get_backup(namespace).await?;
            &fetched_actual
        }
    };
    ensure_authoritative_view(client)?;
    let DiffResult {
        mut diffs,
        unmanaged,
        spec_owned,
    } = compute_diff_with_options(
        desired,
        actual,
        ownership_scope,
        DiffOptions {
            prune_spec_owned: options.confirm_api_spec_deletion,
        },
    );
    let assertions = pending_create_assertion_diffs(
        desired,
        actual,
        &options.pending_create_assertions,
        namespace,
    );
    for assertion in &assertions {
        eprintln!(
            "[{namespace}] asserting repository ownership of pending {} `{}` with an idempotent update",
            assertion.kind, assertion.id
        );
    }
    diffs.extend(assertions);
    let diffs = order_diffs(diffs);

    for message in spec_owned_skip_messages(&spec_owned) {
        eprintln!("[{namespace}] {message}");
    }
    let spec_owned_skipped = spec_owned.iter().filter(|s| !s.pruned).count();

    let mut result = ApplyResult {
        unmanaged_skipped: unmanaged.len(),
        spec_owned_skipped,
        ..Default::default()
    };

    let index = DesiredIndex::build(desired);

    // Pure-Add namespaces take the transactional bulk path. `POST /batch` is
    // create-only and all-or-nothing (never 207), so any Modify or Delete in
    // the set disqualifies it.
    if !diffs.is_empty() && diffs.iter().all(|d| matches!(d.action, DiffAction::Add)) {
        match try_batch_create(&diffs, &index, client, namespace).await? {
            Some(batched) => {
                return Ok(ApplyResult {
                    unmanaged_skipped: result.unmanaged_skipped,
                    spec_owned_skipped: result.spec_owned_skipped,
                    ..batched
                })
            }
            // 501: standalone-MongoDB gateway with no multi-document
            // transaction. Fall through to per-resource CRUD.
            None => eprintln!(
                "[{namespace}] gateway does not support POST /batch (501); \
                 falling back to per-resource creates."
            ),
        }
    }

    for diff in &diffs {
        let key = (diff.namespace.as_str(), diff.id.as_str());
        let outcome = match (&diff.action, diff.kind.as_str()) {
            (DiffAction::Add, "Proxy") => match index.proxies.get(&key) {
                Some(p) => create_with_reconciliation(client, namespace, CreateResource::Proxy(p))
                    .await
                    .map(applied),
                None => continue,
            },
            (DiffAction::Modify, "Proxy") => match index.proxies.get(&key) {
                Some(p) => client.update_proxy(p, namespace).await.map(applied),
                None => continue,
            },
            (DiffAction::Delete, "Proxy") => client
                .delete_proxy(&diff.id, namespace)
                .await
                .map(OpOutcome::from),

            (DiffAction::Add, "Consumer") => match index.consumers.get(&key) {
                Some(c) => {
                    create_with_reconciliation(client, namespace, CreateResource::Consumer(c))
                        .await
                        .map(applied)
                }
                None => continue,
            },
            (DiffAction::Modify, "Consumer") => match index.consumers.get(&key) {
                Some(c) => client.update_consumer(c, namespace).await.map(applied),
                None => continue,
            },
            (DiffAction::Delete, "Consumer") => client
                .delete_consumer(&diff.id, namespace)
                .await
                .map(OpOutcome::from),

            (DiffAction::Add, "Upstream") => match index.upstreams.get(&key) {
                Some(u) => {
                    create_with_reconciliation(client, namespace, CreateResource::Upstream(u))
                        .await
                        .map(applied)
                }
                None => continue,
            },
            (DiffAction::Modify, "Upstream") => match index.upstreams.get(&key) {
                Some(u) => client.update_upstream(u, namespace).await.map(applied),
                None => continue,
            },
            (DiffAction::Delete, "Upstream") => client
                .delete_upstream(&diff.id, namespace)
                .await
                .map(OpOutcome::from),

            (DiffAction::Add, "PluginConfig") => match index.plugin_configs.get(&key) {
                Some(p) => {
                    create_with_reconciliation(client, namespace, CreateResource::PluginConfig(p))
                        .await
                        .map(applied)
                }
                None => continue,
            },
            (DiffAction::Modify, "PluginConfig") => match index.plugin_configs.get(&key) {
                Some(p) => client.update_plugin_config(p, namespace).await.map(applied),
                None => continue,
            },
            (DiffAction::Delete, "PluginConfig") => client
                .delete_plugin_config(&diff.id, namespace)
                .await
                .map(OpOutcome::from),

            _ => continue,
        };

        match outcome {
            Ok(op) => {
                match diff.action {
                    DiffAction::Add => result.created += 1,
                    DiffAction::Modify => result.updated += 1,
                    DiffAction::Delete => {
                        result.deleted += 1;
                        if op == OpOutcome::AlreadyGone {
                            result.deletes_missing += 1;
                        }
                    }
                }
                // Track per-op success so cmd_apply updates state.resources
                // only for ops that actually landed. Failed ops leave their
                // state entry untouched — for shared mode, this preserves
                // the managed flag on resources whose Delete failed (so the
                // next run retries deletion instead of orphaning them).
                result.applied_incremental.push(AppliedOp {
                    kind: diff.kind.clone(),
                    namespace: diff.namespace.clone(),
                    id: diff.id.clone(),
                    action: diff.action.clone(),
                });
            }
            // The whole admin plane refuses writes — every remaining resource
            // (in this namespace and every later one) would fail identically.
            // Record it as the run's fatal stop, keeping the partial successes,
            // and let apply_api unwind. Pushing it onto `errors` instead made
            // it indistinguishable from a per-resource failure, so the run
            // carried on into the next namespace collecting the same 403 over
            // and over.
            Err(e @ crate::error::Error::GatewayReadOnly(_)) => {
                result.fatal_error = Some(e.to_string());
                return Ok(result);
            }
            Err(
                e @ (crate::error::Error::CommittedNotLive { .. }
                | crate::error::Error::AmbiguousMutation(_)),
            ) => {
                result.fatal_error = Some(e.to_string());
                return Ok(result);
            }
            Err(e) => {
                result.errors.push(format!(
                    "{} {} {}: {}",
                    diff.kind,
                    diff.id,
                    match diff.action {
                        DiffAction::Add => "create",
                        DiffAction::Modify => "update",
                        DiffAction::Delete => "delete",
                    },
                    e
                ));
            }
        }
    }

    Ok(result)
}

/// What a single successful admin call actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpOutcome {
    Applied,
    /// A DELETE the gateway answered 404 — tolerated, but counted.
    AlreadyGone,
}

impl From<DeleteOutcome> for OpOutcome {
    fn from(outcome: DeleteOutcome) -> Self {
        match outcome {
            DeleteOutcome::Deleted => OpOutcome::Applied,
            DeleteOutcome::NotFound => OpOutcome::AlreadyGone,
        }
    }
}

/// `map` adaptor for the create/update calls, which return `()` on success.
fn applied(_: ()) -> OpOutcome {
    OpOutcome::Applied
}

/// `(namespace, id)`-keyed view over the desired config.
///
/// The diff and the desired document are both O(n); pairing them by scanning
/// the relevant `Vec` per diff entry made the apply loop O(n²), which shows up
/// as real time on namespaces with a few thousand resources. Built once per
/// namespace and shared by the per-resource path and the batch collector.
struct DesiredIndex<'a> {
    proxies: HashMap<(&'a str, &'a str), &'a Proxy>,
    consumers: HashMap<(&'a str, &'a str), &'a Consumer>,
    upstreams: HashMap<(&'a str, &'a str), &'a Upstream>,
    plugin_configs: HashMap<(&'a str, &'a str), &'a PluginConfig>,
}

impl<'a> DesiredIndex<'a> {
    fn build(desired: &'a GatewayConfig) -> Self {
        Self {
            proxies: desired
                .proxies
                .iter()
                .map(|p| ((p.namespace.as_str(), p.id.as_str()), p))
                .collect(),
            consumers: desired
                .consumers
                .iter()
                .map(|c| ((c.namespace.as_str(), c.id.as_str()), c))
                .collect(),
            upstreams: desired
                .upstreams
                .iter()
                .map(|u| ((u.namespace.as_str(), u.id.as_str()), u))
                .collect(),
            plugin_configs: desired
                .plugin_configs
                .iter()
                .map(|p| ((p.namespace.as_str(), p.id.as_str()), p))
                .collect(),
        }
    }
}

/// Borrowed desired resource used by the non-idempotent create recovery path.
#[derive(Clone, Copy)]
enum CreateResource<'a> {
    Proxy(&'a Proxy),
    Consumer(&'a Consumer),
    Upstream(&'a Upstream),
    PluginConfig(&'a PluginConfig),
}

impl<'a> CreateResource<'a> {
    fn kind(self) -> &'static str {
        match self {
            Self::Proxy(_) => "Proxy",
            Self::Consumer(_) => "Consumer",
            Self::Upstream(_) => "Upstream",
            Self::PluginConfig(_) => "PluginConfig",
        }
    }

    fn id(self) -> &'a str {
        match self {
            Self::Proxy(resource) => &resource.id,
            Self::Consumer(resource) => &resource.id,
            Self::Upstream(resource) => &resource.id,
            Self::PluginConfig(resource) => &resource.id,
        }
    }

    async fn create(self, client: &AdminClient, namespace: &str) -> crate::error::Result<()> {
        match self {
            Self::Proxy(resource) => client.create_proxy(resource, namespace).await,
            Self::Consumer(resource) => client.create_consumer(resource, namespace).await,
            Self::Upstream(resource) => client.create_upstream(resource, namespace).await,
            Self::PluginConfig(resource) => client.create_plugin_config(resource, namespace).await,
        }
    }

    /// Idempotently assert that the repository, rather than a racing external
    /// writer, authored the exact live row observed after an uncertain POST.
    async fn assert_ownership(
        self,
        client: &AdminClient,
        namespace: &str,
    ) -> crate::error::Result<()> {
        match self {
            Self::Proxy(resource) => client.update_proxy(resource, namespace).await,
            Self::Consumer(resource) => client.update_consumer(resource, namespace).await,
            Self::Upstream(resource) => client.update_upstream(resource, namespace).await,
            Self::PluginConfig(resource) => client.update_plugin_config(resource, namespace).await,
        }
    }

    fn exact_desired_is_live(self, actual: &GatewayConfig) -> bool {
        matches!(self.live_match(actual), LiveMatch::Exact)
    }

    /// Classify what an authoritative backup says about this resource.
    ///
    /// The three answers are not interchangeable after an ambiguous create:
    /// `Absent` proves the write did not commit, `Different` proves *something*
    /// holds the identity but not what we sent, and `Exact` is the only one
    /// that permits recording the create as landed.
    fn live_match(self, actual: &GatewayConfig) -> LiveMatch {
        fn classify<T: serde::Serialize>(live: Option<&T>, desired: &T) -> LiveMatch {
            match live {
                None => LiveMatch::Absent,
                Some(live) if resource_values_match(desired, live) => LiveMatch::Exact,
                Some(_) => LiveMatch::Different,
            }
        }

        match self {
            Self::Proxy(desired) => classify(
                actual.proxies.iter().find(|candidate| {
                    candidate.namespace == desired.namespace && candidate.id == desired.id
                }),
                desired,
            ),
            Self::Consumer(desired) => classify(
                actual.consumers.iter().find(|candidate| {
                    candidate.namespace == desired.namespace && candidate.id == desired.id
                }),
                desired,
            ),
            Self::Upstream(desired) => classify(
                actual.upstreams.iter().find(|candidate| {
                    candidate.namespace == desired.namespace && candidate.id == desired.id
                }),
                desired,
            ),
            Self::PluginConfig(desired) => classify(
                actual.plugin_configs.iter().find(|candidate| {
                    candidate.namespace == desired.namespace && candidate.id == desired.id
                }),
                desired,
            ),
        }
    }
}

/// What an authoritative `GET /backup` says about one desired resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveMatch {
    /// No row holds the `(namespace, id)` at all.
    Absent,
    /// A row exists but is not byte-for-byte the resource we sent.
    Different,
    /// The exact desired resource is live, apart from server timestamps.
    Exact,
}

/// Send one create exactly once. If its response is ambiguous, perform an
/// authoritative read-after-write and convert it to success only when the
/// exact desired resource (apart from server timestamps) is live *and* a
/// subsequent idempotent update explicitly asserts repository ownership.
///
/// The readback has three outcomes and they get three different severities:
///
/// - **Exact row live** → assert ownership with an idempotent PUT, record the
///   create.
/// - **Row absent** from a fresh, database-backed backup → the write provably
///   did not commit. That is an ordinary per-resource failure: it is recorded
///   in [`ApplyResult::errors`], the remaining resources and namespaces are
///   still reconciled, and the next run retries the create. Treating it as
///   fatal meant one transient 502 stopped every later namespace even though
///   the gateway had told us, authoritatively, that nothing happened.
/// - **Row present but different**, or no usable verification at all (the
///   read failed, or came back `X-Data-Source: cached`) → the write may have
///   committed. That stays a run-stopping [`crate::error::Error::AmbiguousMutation`].
///
/// Caveat, stated because it bounds the "provably did not commit" claim: this
/// trusts `GET /backup` to be read from the gateway's primary. Ferrum Edge
/// serves it from the config database and flags a degraded in-memory fallback
/// with `X-Data-Source: cached`, which is rejected above — but an operator who
/// fronts the admin API with something that answers reads from a lagging
/// replica would turn a committed write into an "absent" verdict, and the
/// next run would re-send the create and get a 409.
async fn create_with_reconciliation(
    client: &AdminClient,
    namespace: &str,
    resource: CreateResource<'_>,
) -> crate::error::Result<()> {
    match resource.create(client, namespace).await {
        Ok(()) => Ok(()),
        Err(error) if create_outcome_is_ambiguous(&error) => {
            let original = error.to_string();
            let snapshot = client
                .get_backup_snapshot(namespace)
                .await
                .map_err(|verification| {
                    crate::error::Error::AmbiguousMutation(format!(
                        "{} `{}` in namespace `{namespace}` returned `{original}`, and the authoritative verification read failed: {verification}",
                        resource.kind(),
                        resource.id(),
                    ))
                })?;
            if snapshot.cached {
                return Err(crate::error::Error::AmbiguousMutation(format!(
                    "{} `{}` in namespace `{namespace}` returned `{original}`, and verification produced only a cached backup with incomplete ownership metadata",
                    resource.kind(),
                    resource.id(),
                )));
            }
            match resource.live_match(&snapshot.config) {
                LiveMatch::Exact => {
                    resource
                        .assert_ownership(client, namespace)
                        .await
                        .map_err(|assertion| {
                            crate::error::Error::AmbiguousMutation(format!(
                                "{} `{}` in namespace `{namespace}` returned `{original}`; an authoritative backup found the exact desired row, but the idempotent ownership assertion failed: {assertion}. The row remains outside the managed delete fence.",
                                resource.kind(),
                                resource.id(),
                            ))
                        })?;
                    eprintln!(
                        "[{namespace}] {} `{}` returned an ambiguous response; an authoritative backup found the exact desired resource live and an idempotent update asserted repository ownership without replaying the create",
                        resource.kind(),
                        resource.id(),
                    );
                    Ok(())
                }
                // Proven not to have committed. Ordinary failure: report it,
                // keep reconciling everything else, retry next run.
                LiveMatch::Absent => Err(crate::error::Error::Config(format!(
                    "returned `{original}`, and an authoritative (non-cached) backup proves no row holds that id, so the write did not commit. Nothing was replayed; the next run recreates it."
                ))),
                LiveMatch::Different => Err(crate::error::Error::AmbiguousMutation(format!(
                    "{} `{}` in namespace `{namespace}` returned `{original}`, and an authoritative backup found a row under that id that is not the resource we sent. It may be a partially applied write or another writer's row. Re-run diff before retrying.",
                    resource.kind(),
                    resource.id(),
                ))),
            }
        }
        Err(error) => Err(error),
    }
}

fn create_outcome_is_ambiguous(error: &crate::error::Error) -> bool {
    match error {
        crate::error::Error::ApiError { status, .. } => {
            matches!(status, 408 | 429) || (500..=599).contains(status)
        }
        crate::error::Error::HttpClient(_) => true,
        _ => false,
    }
}

/// Does the live row carry everything the repository asked for?
///
/// Deliberately a *subset* test, not equality. The question this answers is
/// "did the gateway store what we sent?", and the gateway is entitled to add
/// things we never declared: server timestamps, and any optional field it
/// populates itself (which `skip_serializing_if = "Option::is_none"` keeps out
/// of the desired document entirely). Under strict equality every one of those
/// reads as "this is not our row", which turned a successful write into an
/// unresolvable ambiguity — and, before the journal was made non-blocking,
/// into a state file that needed hand-editing.
///
/// So: every key the desired document serializes must be present in the live
/// row with the same value, recursively through nested objects. Arrays and
/// scalars still compare exactly — a differing target list or timeout is a
/// real difference, not a gateway default. Extra keys on the live side are
/// ignored. `created_at` / `updated_at` are dropped outright because the
/// desired side fabricates them at deserialize time.
///
/// This is not an ownership proof and is never used as one: the callers follow
/// a positive match with an idempotent PUT that overwrites the row with the
/// desired content before anything enters the managed delete fence.
fn resource_values_match<T: serde::Serialize>(desired: &T, live: &T) -> bool {
    fn without_server_timestamps<T: serde::Serialize>(value: &T) -> Option<serde_json::Value> {
        let mut value = serde_json::to_value(value).ok()?;
        if let Some(map) = value.as_object_mut() {
            map.remove("created_at");
            map.remove("updated_at");
        }
        Some(value)
    }

    match (
        without_server_timestamps(desired),
        without_server_timestamps(live),
    ) {
        (Some(desired), Some(live)) => json_contains(&desired, &live),
        _ => false,
    }
}

/// `live` carries every key/value in `desired`, recursively.
fn json_contains(desired: &serde_json::Value, live: &serde_json::Value) -> bool {
    match (desired, live) {
        (serde_json::Value::Object(desired), serde_json::Value::Object(live)) => {
            desired.iter().all(|(key, value)| {
                live.get(key)
                    .is_some_and(|found| json_contains(value, found))
            })
        }
        // Arrays are ordered, meaningful config (targets, plugin
        // associations, credential entries); a shorter or reordered live list
        // is a real difference.
        (desired, live) => desired == live,
    }
}

/// Exact pending rows need an idempotent PUT even though their ordinary diff
/// is empty. Equality proves the desired state is live, but not whether our
/// uncertain POST or a racing external writer created it.
pub fn pending_create_assertion_diffs(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    pending: &BTreeSet<String>,
    namespace: &str,
) -> Vec<ResourceDiff> {
    let mut assertions = Vec::new();
    let mut add = |kind: &str, id: &str| {
        assertions.push(ResourceDiff {
            action: DiffAction::Modify,
            kind: kind.to_string(),
            id: id.to_string(),
            namespace: namespace.to_string(),
            details: Vec::new(),
        });
    };

    for resource in &desired.upstreams {
        let key = state_key(&resource.namespace, "Upstream", &resource.id);
        if pending.contains(&key)
            && CreateResource::Upstream(resource).exact_desired_is_live(actual)
        {
            add("Upstream", &resource.id);
        }
    }
    for resource in &desired.consumers {
        let key = state_key(&resource.namespace, "Consumer", &resource.id);
        if pending.contains(&key)
            && CreateResource::Consumer(resource).exact_desired_is_live(actual)
        {
            add("Consumer", &resource.id);
        }
    }
    for resource in &desired.proxies {
        let key = state_key(&resource.namespace, "Proxy", &resource.id);
        if pending.contains(&key) && CreateResource::Proxy(resource).exact_desired_is_live(actual) {
            add("Proxy", &resource.id);
        }
    }
    for resource in &desired.plugin_configs {
        let key = state_key(&resource.namespace, "PluginConfig", &resource.id);
        if pending.contains(&key)
            && CreateResource::PluginConfig(resource).exact_desired_is_live(actual)
        {
            add("PluginConfig", &resource.id);
        }
    }

    assertions
}

/// One operator-facing line per spec-owned live resource the run touched.
///
/// Three shapes, because there are three ways a spec-owned row shows up:
///
/// - the repo declares the same id (an ownership conflict — the repo and the
///   `/api-specs` importer are both trying to own one row),
/// - the run is leaving it alone (the default), or
/// - the run is deleting it because `--confirm-api-spec-deletion` was passed.
///
/// Pure so the wording is testable without a gateway.
pub fn spec_owned_skip_messages(spec_owned: &[SpecOwnedResource]) -> Vec<String> {
    spec_owned
        .iter()
        .map(|s| {
            if s.declared_in_repo {
                format!(
                    "conflict: {} `{}` is owned by API spec `{}` but this repo also declares it. \
                     Skipping — the next spec import would revert the change. Remove the resource \
                     file, or stop managing the spec through /api-specs.",
                    s.kind, s.id, s.api_spec_id
                )
            } else if s.pruned {
                format!(
                    "deleting {} `{}` owned by API spec `{}` (--confirm-api-spec-deletion)",
                    s.kind, s.id, s.api_spec_id
                )
            } else {
                format!(
                    "skipping {} `{}`: owned by API spec `{}`. Re-run with \
                     --confirm-api-spec-deletion to prune spec-owned resources.",
                    s.kind, s.id, s.api_spec_id
                )
            }
        })
        .collect()
}

/// Refuse every mutation derived from a cached (potentially stale) backup.
///
/// Ferrum Edge's cached fallback omits API spec documents and clears
/// `api_spec_id` tags because ownership cannot be proven. That makes adds and
/// modifies unsafe too: a desired row can collide with a resource that only
/// *appears* hand-owned in the degraded view.
pub fn stale_view_block(served_from_cache: bool) -> Option<String> {
    served_from_cache.then(stale_view_message)
}

fn stale_view_message() -> String {
    "Refusing to apply: the gateway served GET /backup from its in-memory cache \
     (X-Data-Source: cached). Cached backups omit authoritative API-spec ownership metadata, \
     so no POST, PUT, DELETE, batch, or restore can be proven safe. Wait for the gateway's \
     configuration database to recover and retry. `--allow-large-prune` does not bypass this \
     ownership-safety gate."
        .to_string()
}

fn ensure_authoritative_view(client: &AdminClient) -> crate::error::Result<()> {
    match stale_view_block(client.served_from_cache()) {
        Some(message) => Err(crate::error::Error::StaleGatewayView(message)),
        None => Ok(()),
    }
}

/// Exact large-prune decision using overflow-safe rational comparison.
///
/// An exact threshold match is allowed; any fraction above it is blocked.
pub fn large_prune_exceeds_threshold(
    delete_count: usize,
    denominator: usize,
    threshold_percent: u8,
) -> bool {
    denominator > 0
        && (delete_count as u128) * 100 > (threshold_percent as u128) * (denominator as u128)
}

/// Count the exclusive-mode live resources that the current diff is actually
/// allowed to delete. API-spec-owned rows are outside gitforgeops' ownership
/// unless the operator explicitly confirms their deletion; including them in
/// the denominator would dilute the guard with untouchable resources.
pub fn exclusive_prune_denominator(
    actual: &GatewayConfig,
    confirm_api_spec_deletion: bool,
) -> usize {
    let eligible = |api_spec_id: Option<&str>| confirm_api_spec_deletion || api_spec_id.is_none();

    actual.consumers.len()
        + actual
            .proxies
            .iter()
            .filter(|resource| eligible(resource.api_spec_id.as_deref()))
            .count()
        + actual
            .upstreams
            .iter()
            .filter(|resource| eligible(resource.api_spec_id.as_deref()))
            .count()
        + actual
            .plugin_configs
            .iter()
            .filter(|resource| eligible(resource.api_spec_id.as_deref()))
            .count()
}

/// Human-readable percentage with two decimal places, kept separate from the
/// exact decision above so display rounding can never weaken the guard.
pub fn format_prune_percentage(delete_count: usize, denominator: usize) -> String {
    if denominator == 0 {
        return "0.00".to_string();
    }
    let basis_points = (delete_count as u128) * 10_000 / (denominator as u128);
    format!("{}.{:02}", basis_points / 100, basis_points % 100)
}

/// Collect a pure-Add diff into a `POST /batch` payload and send it.
///
/// Returns `Ok(None)` when the gateway answered 501 on the *first* chunk
/// (standalone MongoDB has no multi-document transaction and nothing landed),
/// signalling the caller to fall back to per-resource creates for the whole
/// namespace.
///
/// A documented, definitive rejection (400/409/413/422) proves the transaction
/// did not commit, so that chunk and the remainder may be decomposed into named
/// per-resource creates. An ambiguous transport/5xx/timeout outcome is never
/// replayed: an authoritative backup must prove the entire exact chunk live,
/// otherwise the run stops for reconciliation.
async fn try_batch_create(
    diffs: &[ResourceDiff],
    index: &DesiredIndex<'_>,
    client: &AdminClient,
    namespace: &str,
) -> crate::error::Result<Option<ApplyResult>> {
    let batch = collect_batch(diffs, index);
    if batch.is_empty() {
        return Ok(Some(ApplyResult::default()));
    }

    let total = batch.len();
    let chunks = http_client::split_batch(batch, BATCH_MAX_BODY_BYTES)?;
    let mut result = ApplyResult::default();
    let mut replay_from: Option<usize> = None;

    for (position, chunk) in chunks.iter().enumerate() {
        match client.post_batch(chunk, namespace).await {
            Ok(Some(_counts)) => {
                // `/batch` is all-or-nothing and never answers 207, so a
                // non-error response means the whole chunk landed.
                result.created += chunk.len();
                result
                    .applied_incremental
                    .extend(chunk_ops(chunk, namespace));
            }
            // 501 on the first chunk: nothing landed anywhere, so the caller
            // can take the whole namespace down the per-resource path.
            Ok(None) if position == 0 => return Ok(None),
            Ok(None) => {
                eprintln!(
                    "[{namespace}] gateway returned 501 for POST /batch after {} resource(s); \
                     creating the remaining {} resource(s) individually.",
                    result.created,
                    total.saturating_sub(result.created),
                );
                replay_from = Some(position);
                break;
            }
            // A read-only admin plane refuses every chunk and every
            // per-resource create identically; replaying would just collect
            // the same 403 N times.
            Err(e @ crate::error::Error::GatewayReadOnly(_)) => {
                result.fatal_error = Some(e.to_string());
                note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                return Ok(Some(result));
            }

            Err(e) if batch_rejection_allows_replay(&e) => {
                eprintln!(
                    "[{namespace}] POST /batch chunk {} was definitively rejected ({e}); creating the remaining {} resource(s) individually so each failure is reported on its own.",
                    position + 1,
                    total.saturating_sub(result.created),
                );
                replay_from = Some(position);
                break;
            }
            Err(e) if create_outcome_is_ambiguous(&e) => {
                let original = e.to_string();
                let snapshot = match client.get_backup_snapshot(namespace).await {
                    Ok(snapshot) if snapshot.cached => {
                        result.fatal_error = Some(
                            crate::error::Error::AmbiguousMutation(format!(
                                "POST /batch chunk {} in namespace `{namespace}` returned `{original}`, and verification returned only a cached backup with incomplete ownership metadata. No individual create was replayed; re-run diff before retrying.",
                                position + 1,
                            ))
                            .to_string(),
                        );
                        note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                        return Ok(Some(result));
                    }
                    Ok(snapshot) => snapshot,
                    Err(verification) => {
                        result.fatal_error = Some(
                            crate::error::Error::AmbiguousMutation(format!(
                                "POST /batch chunk {} in namespace `{namespace}` returned `{original}`, and the authoritative verification read failed: {verification}. No individual create was replayed.",
                                position + 1,
                            ))
                            .to_string(),
                        );
                        note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                        return Ok(Some(result));
                    }
                };

                match batch_live_match(chunk, &snapshot.config) {
                    LiveMatch::Exact => {
                        let errors_before = result.errors.len();
                        assert_batch_ownership(chunk, client, namespace, &mut result).await;
                        if result.fatal_error.is_some() || result.errors.len() > errors_before {
                            note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                            return Ok(Some(result));
                        }
                        eprintln!(
                            "[{namespace}] POST /batch chunk {} returned an ambiguous response; an authoritative backup found all {} exact desired resources live and idempotent updates asserted repository ownership without replaying the batch",
                            position + 1,
                            chunk.len(),
                        );
                    }
                    // `/batch` is one transaction: no row live means it did
                    // not commit. That is an ordinary failure — report the
                    // chunk, keep going, retry it next run.
                    LiveMatch::Absent => {
                        result.errors.push(format!(
                            "POST /batch chunk {} ({} resource(s)) returned `{original}`, and an authoritative (non-cached) backup proves none of them are live, so the transaction did not commit. Nothing was replayed; the next run recreates them.",
                            position + 1,
                            chunk.len(),
                        ));
                    }
                    LiveMatch::Different => {
                        result.fatal_error = Some(
                            crate::error::Error::AmbiguousMutation(format!(
                                "POST /batch chunk {} in namespace `{namespace}` returned `{original}`, and an authoritative backup proved neither that the whole chunk landed nor that none of it did. No individual create was replayed; re-run diff before retrying.",
                                position + 1,
                            ))
                            .to_string(),
                        );
                        note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                        return Ok(Some(result));
                    }
                }
            }
            Err(e) => {
                result.fatal_error = Some(format!(
                    "POST /batch chunk {} failed ({e}); the response is not a documented all-or-nothing validation rejection, so no per-resource replay was attempted",
                    position + 1,
                ));
                note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                return Ok(Some(result));
            }
        }
    }

    if let Some(start) = replay_from {
        create_individually(&chunks[start..], client, namespace, &mut result).await;
    }

    Ok(Some(result))
}

fn batch_rejection_allows_replay(error: &crate::error::Error) -> bool {
    matches!(
        error,
        crate::error::Error::ApiError {
            status: 400 | 409 | 413 | 422,
            ..
        }
    )
}

/// Classify a whole `/batch` chunk against an authoritative backup.
///
/// `/batch` is one transaction, so the chunk only has three honest answers:
/// every row landed exactly as sent (`Exact`), no row landed at all
/// (`Absent`, which proves the transaction did not commit), or the live view
/// is some third thing (`Different`) that no read can reconcile automatically.
fn batch_live_match(batch: &BatchCreate, actual: &GatewayConfig) -> LiveMatch {
    let mut any_exact = false;
    let mut any_absent = false;
    let mut any_different = false;

    let mut record = |outcome: LiveMatch| match outcome {
        LiveMatch::Exact => any_exact = true,
        LiveMatch::Absent => any_absent = true,
        LiveMatch::Different => any_different = true,
    };

    for resource in &batch.proxies {
        record(CreateResource::Proxy(resource).live_match(actual));
    }
    for resource in &batch.consumers {
        record(CreateResource::Consumer(resource).live_match(actual));
    }
    for resource in &batch.upstreams {
        record(CreateResource::Upstream(resource).live_match(actual));
    }
    for resource in &batch.plugin_configs {
        record(CreateResource::PluginConfig(resource).live_match(actual));
    }

    match (any_exact, any_absent, any_different) {
        // An empty chunk cannot reach here (`try_batch_create` short-circuits
        // an empty batch), but treat it as unprovable rather than as success.
        (false, false, false) => LiveMatch::Different,
        (true, false, false) => LiveMatch::Exact,
        (false, true, false) => LiveMatch::Absent,
        _ => LiveMatch::Different,
    }
}

/// Name the chunks a stopped batch never attempted.
///
/// Returning silently left those resources neither created nor mentioned
/// anywhere, so an operator reading the failure had no way to know how much of
/// the namespace was still outstanding.
fn note_unattempted_chunks(
    chunks: &[BatchCreate],
    next_position: usize,
    namespace: &str,
    result: &mut ApplyResult,
) {
    let remaining: usize = chunks
        .iter()
        .skip(next_position)
        .map(BatchCreate::len)
        .sum();
    if remaining == 0 {
        return;
    }
    result.errors.push(format!(
        "{} further POST /batch chunk(s) covering {remaining} resource(s) in namespace `{namespace}` were not attempted after the failure above; re-run apply once it is resolved",
        chunks.len().saturating_sub(next_position),
    ));
}

async fn assert_batch_ownership(
    batch: &BatchCreate,
    client: &AdminClient,
    namespace: &str,
    result: &mut ApplyResult,
) {
    for resource in &batch.upstreams {
        let outcome = client.update_upstream(resource, namespace).await;
        record_create(result, outcome, "Upstream", &resource.id, namespace);
        if result.fatal_error.is_some() {
            return;
        }
    }
    for resource in &batch.consumers {
        let outcome = client.update_consumer(resource, namespace).await;
        record_create(result, outcome, "Consumer", &resource.id, namespace);
        if result.fatal_error.is_some() {
            return;
        }
    }
    for resource in &batch.proxies {
        let outcome = client.update_proxy(resource, namespace).await;
        record_create(result, outcome, "Proxy", &resource.id, namespace);
        if result.fatal_error.is_some() {
            return;
        }
    }
    for resource in &batch.plugin_configs {
        let outcome = client.update_plugin_config(resource, namespace).await;
        record_create(result, outcome, "PluginConfig", &resource.id, namespace);
        if result.fatal_error.is_some() {
            return;
        }
    }
}

/// Gather the desired resources a pure-Add diff names into a batch payload,
/// in dependency order.
fn collect_batch(diffs: &[ResourceDiff], index: &DesiredIndex<'_>) -> BatchCreate {
    let mut batch = BatchCreate::default();
    for diff in diffs {
        let key = (diff.namespace.as_str(), diff.id.as_str());
        match diff.kind.as_str() {
            "Upstream" => {
                if let Some(u) = index.upstreams.get(&key) {
                    batch.upstreams.push((*u).clone());
                }
            }
            "Consumer" => {
                if let Some(c) = index.consumers.get(&key) {
                    batch.consumers.push((*c).clone());
                }
            }
            "Proxy" => {
                if let Some(p) = index.proxies.get(&key) {
                    batch.proxies.push((*p).clone());
                }
            }
            "PluginConfig" => {
                if let Some(p) = index.plugin_configs.get(&key) {
                    batch.plugin_configs.push((*p).clone());
                }
            }
            _ => {}
        }
    }
    batch
}

/// Replay chunks as per-resource `POST`s, in the same dependency order the
/// batch packer used (upstreams and consumers, then proxies, then plugin
/// configs), so a proxy never precedes the upstream it references.
///
/// Stops early on a run-wide or ambiguous mutation failure; ordinary
/// per-resource validation failures are recorded and the walk continues.
async fn create_individually(
    chunks: &[BatchCreate],
    client: &AdminClient,
    namespace: &str,
    result: &mut ApplyResult,
) {
    for chunk in chunks {
        for u in &chunk.upstreams {
            let outcome =
                create_with_reconciliation(client, namespace, CreateResource::Upstream(u)).await;
            record_create(result, outcome, "Upstream", &u.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        for c in &chunk.consumers {
            let outcome =
                create_with_reconciliation(client, namespace, CreateResource::Consumer(c)).await;
            record_create(result, outcome, "Consumer", &c.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        for p in &chunk.proxies {
            let outcome =
                create_with_reconciliation(client, namespace, CreateResource::Proxy(p)).await;
            record_create(result, outcome, "Proxy", &p.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        for pc in &chunk.plugin_configs {
            let outcome =
                create_with_reconciliation(client, namespace, CreateResource::PluginConfig(pc))
                    .await;
            record_create(result, outcome, "PluginConfig", &pc.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
    }
}

fn record_create(
    result: &mut ApplyResult,
    outcome: crate::error::Result<()>,
    kind: &str,
    id: &str,
    namespace: &str,
) {
    match outcome {
        Ok(()) => {
            result.created += 1;
            result.applied_incremental.push(AppliedOp {
                kind: kind.to_string(),
                namespace: namespace.to_string(),
                id: id.to_string(),
                action: DiffAction::Add,
            });
        }
        Err(e @ crate::error::Error::GatewayReadOnly(_)) => {
            result.fatal_error = Some(e.to_string());
        }
        Err(
            e @ (crate::error::Error::CommittedNotLive { .. }
            | crate::error::Error::AmbiguousMutation(_)),
        ) => {
            result.fatal_error = Some(e.to_string());
        }
        Err(e) => result.errors.push(format!("{kind} {id} create: {e}")),
    }
}

/// The `AppliedOp` records for the resources a landed chunk carried.
///
/// Built straight from the chunk: every entry in it is an Add that just
/// succeeded in `namespace`, so the id and kind are all the chunk needs to
/// carry — the earlier round-trip through a keyed map of pre-built ops was
/// re-deriving facts already present.
fn chunk_ops(chunk: &BatchCreate, namespace: &str) -> Vec<AppliedOp> {
    let op = |kind: &str, id: &str| AppliedOp {
        kind: kind.to_string(),
        namespace: namespace.to_string(),
        id: id.to_string(),
        action: DiffAction::Add,
    };
    chunk
        .upstreams
        .iter()
        .map(|u| op("Upstream", &u.id))
        .chain(chunk.consumers.iter().map(|c| op("Consumer", &c.id)))
        .chain(chunk.proxies.iter().map(|p| op("Proxy", &p.id)))
        .chain(
            chunk
                .plugin_configs
                .iter()
                .map(|p| op("PluginConfig", &p.id)),
        )
        .collect()
}
