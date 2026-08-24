use std::collections::BTreeMap;

use crate::config::schema::GatewayConfig;
use crate::config::ApplyStrategy;
use crate::diff::resource_diff::{
    compute_diff_with_scope, DiffAction, DiffResult, OwnershipScope, ResourceDiff,
};
use crate::http_client::{self, AdminClient, BackupExtras, BatchCreate, BATCH_MAX_BODY_BYTES};

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
    /// `--allow-large-prune`. Doubles as the explicit acknowledgement that
    /// pruning against a *stale* (`X-Data-Source: cached`) gateway view is
    /// acceptable — both are "I accept that this apply may delete more than it
    /// should" decisions.
    pub allow_large_prune: bool,
    /// `--confirm-api-spec-deletion`. Full replace drops the namespace's
    /// `api_specs` section instead of carrying it through.
    pub confirm_api_spec_deletion: bool,
}

#[derive(Debug, Default)]
pub struct ApplyResult {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unmanaged_skipped: usize,
    pub errors: Vec<String>,
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
    pub fn into_result(self) -> crate::error::Result<Self> {
        if self.errors.is_empty() {
            return Ok(self);
        }

        Err(crate::error::Error::Config(format!(
            "Apply failed after partial success: {} created, {} updated, {} deleted, {} failed\n{}",
            self.created,
            self.updated,
            self.deleted,
            self.errors.len(),
            self.errors.join("\n")
        )))
    }
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
pub async fn apply_api(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
    preflight_writes(client).await?;

    let mut aggregate = ApplyResult::default();

    for namespace in namespaces {
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
                match apply_full_replace(&desired_namespace, client, namespace, options).await {
                    Ok(r) => r,
                    Err(e) if is_fatal(&e) => return Err(e),
                    Err(e) => {
                        aggregate.errors.push(format!("[{namespace}] {e}"));
                        continue;
                    }
                }
            }
            ApplyStrategy::Incremental => {
                let actual = actual_by_namespace.and_then(|actuals| actuals.get(namespace));
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
                    Err(e) if is_fatal(&e) => return Err(e),
                    Err(e) => {
                        aggregate.errors.push(format!("[{namespace}] {e}"));
                        continue;
                    }
                }
            }
        };

        aggregate.created += namespace_result.created;
        aggregate.updated += namespace_result.updated;
        aggregate.deleted += namespace_result.deleted;
        aggregate.unmanaged_skipped += namespace_result.unmanaged_skipped;
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
    }

    Ok(aggregate)
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

async fn apply_full_replace(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespace: &str,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
    // A bare `GatewayConfig` restore omits `api_specs`, which the gateway
    // reads as "delete every API spec in this namespace" — it answers 409
    // rather than doing it. Read the live sections first and hand them back
    // verbatim so a full replace only replaces what this repo manages.
    let extras = if options.confirm_api_spec_deletion {
        BackupExtras::default()
    } else {
        let snapshot = client.get_backup_snapshot(namespace).await?;
        if !snapshot.extras.is_empty() {
            eprintln!(
                "[{namespace}] carrying {} API spec(s) and {} trust-bundle record(s) through the restore unchanged",
                snapshot.extras.api_spec_count(),
                snapshot.extras.trust_bundle_count(),
            );
        }
        snapshot.extras
    };

    client
        .post_restore(
            desired,
            namespace,
            &extras,
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
    let DiffResult { diffs, unmanaged } = compute_diff_with_scope(desired, actual, ownership_scope);
    let diffs = order_diffs(diffs);

    let delete_count = diffs
        .iter()
        .filter(|d| matches!(d.action, DiffAction::Delete))
        .count();
    if let Some(message) = stale_view_block(
        client.served_from_cache(),
        delete_count,
        options.allow_large_prune,
    ) {
        return Err(crate::error::Error::StaleGatewayView(message));
    }
    if client.served_from_cache() {
        eprintln!(
            "Warning: [{namespace}] the gateway served /backup from its in-memory cache \
             (X-Data-Source: cached) — the live view may be stale."
        );
    }

    let mut result = ApplyResult {
        unmanaged_skipped: unmanaged.len(),
        ..Default::default()
    };

    // Pure-Add namespaces take the transactional bulk path. `POST /batch` is
    // create-only and all-or-nothing (never 207), so any Modify or Delete in
    // the set disqualifies it.
    if !diffs.is_empty() && diffs.iter().all(|d| matches!(d.action, DiffAction::Add)) {
        match try_batch_create(&diffs, desired, client, namespace).await? {
            Some(batched) => {
                return Ok(ApplyResult {
                    unmanaged_skipped: result.unmanaged_skipped,
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
        let outcome = match (&diff.action, diff.kind.as_str()) {
            (DiffAction::Add, "Proxy") => {
                let proxy = desired
                    .proxies
                    .iter()
                    .find(|p| p.id == diff.id && p.namespace == diff.namespace);
                match proxy {
                    Some(p) => client.create_proxy(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "Proxy") => {
                let proxy = desired
                    .proxies
                    .iter()
                    .find(|p| p.id == diff.id && p.namespace == diff.namespace);
                match proxy {
                    Some(p) => client.update_proxy(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "Proxy") => client.delete_proxy(&diff.id, namespace).await,

            (DiffAction::Add, "Consumer") => {
                let consumer = desired
                    .consumers
                    .iter()
                    .find(|c| c.id == diff.id && c.namespace == diff.namespace);
                match consumer {
                    Some(c) => client.create_consumer(c, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "Consumer") => {
                let consumer = desired
                    .consumers
                    .iter()
                    .find(|c| c.id == diff.id && c.namespace == diff.namespace);
                match consumer {
                    Some(c) => client.update_consumer(c, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "Consumer") => client.delete_consumer(&diff.id, namespace).await,

            (DiffAction::Add, "Upstream") => {
                let upstream = desired
                    .upstreams
                    .iter()
                    .find(|u| u.id == diff.id && u.namespace == diff.namespace);
                match upstream {
                    Some(u) => client.create_upstream(u, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "Upstream") => {
                let upstream = desired
                    .upstreams
                    .iter()
                    .find(|u| u.id == diff.id && u.namespace == diff.namespace);
                match upstream {
                    Some(u) => client.update_upstream(u, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "Upstream") => client.delete_upstream(&diff.id, namespace).await,

            (DiffAction::Add, "PluginConfig") => {
                let pc = desired
                    .plugin_configs
                    .iter()
                    .find(|p| p.id == diff.id && p.namespace == diff.namespace);
                match pc {
                    Some(p) => client.create_plugin_config(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "PluginConfig") => {
                let pc = desired
                    .plugin_configs
                    .iter()
                    .find(|p| p.id == diff.id && p.namespace == diff.namespace);
                match pc {
                    Some(p) => client.update_plugin_config(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "PluginConfig") => {
                client.delete_plugin_config(&diff.id, namespace).await
            }

            _ => continue,
        };

        match outcome {
            Ok(()) => {
                match diff.action {
                    DiffAction::Add => result.created += 1,
                    DiffAction::Modify => result.updated += 1,
                    DiffAction::Delete => result.deleted += 1,
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
            // would fail identically. Surface it once and stop, keeping the
            // partial successes recorded so far.
            Err(e @ crate::error::Error::GatewayReadOnly(_)) => {
                result.errors.push(e.to_string());
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

/// Refuse to compute prunes from a cached (potentially stale) gateway view.
///
/// During a config-database outage `GET /backup` falls back to the in-memory
/// snapshot and advertises `X-Data-Source: cached`. Resources created since the
/// snapshot are missing from it, so an exclusive-mode diff reads them as
/// "should be deleted". `--allow-large-prune` is the existing "I accept an
/// oversized deletion" opt-in and doubles as the override here.
pub fn stale_view_block(
    served_from_cache: bool,
    delete_count: usize,
    allow_large_prune: bool,
) -> Option<String> {
    if !served_from_cache || delete_count == 0 || allow_large_prune {
        return None;
    }
    Some(format!(
        "Refusing to apply: the gateway served GET /backup from its in-memory cache \
         (X-Data-Source: cached), so the live view may be stale and the {delete_count} computed \
         deletion(s) may target resources that actually exist. Wait for the gateway's config \
         database to recover, or re-run with --allow-large-prune to prune from the stale view \
         anyway."
    ))
}

/// Collect a pure-Add diff into a `POST /batch` payload.
///
/// Returns `Ok(None)` when the gateway answered 501 (standalone MongoDB has no
/// multi-document transaction), signalling the caller to fall back to
/// per-resource creates.
async fn try_batch_create(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    client: &AdminClient,
    namespace: &str,
) -> crate::error::Result<Option<ApplyResult>> {
    let mut batch = BatchCreate::default();
    let mut ops: Vec<AppliedOp> = Vec::new();

    for diff in diffs {
        let matched = match diff.kind.as_str() {
            "Upstream" => {
                match desired
                    .upstreams
                    .iter()
                    .find(|u| u.id == diff.id && u.namespace == diff.namespace)
                {
                    Some(u) => {
                        batch.upstreams.push(u.clone());
                        true
                    }
                    None => false,
                }
            }
            "Consumer" => {
                match desired
                    .consumers
                    .iter()
                    .find(|c| c.id == diff.id && c.namespace == diff.namespace)
                {
                    Some(c) => {
                        batch.consumers.push(c.clone());
                        true
                    }
                    None => false,
                }
            }
            "Proxy" => {
                match desired
                    .proxies
                    .iter()
                    .find(|p| p.id == diff.id && p.namespace == diff.namespace)
                {
                    Some(p) => {
                        batch.proxies.push(p.clone());
                        true
                    }
                    None => false,
                }
            }
            "PluginConfig" => {
                match desired
                    .plugin_configs
                    .iter()
                    .find(|p| p.id == diff.id && p.namespace == diff.namespace)
                {
                    Some(p) => {
                        batch.plugin_configs.push(p.clone());
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if matched {
            ops.push(AppliedOp {
                kind: diff.kind.clone(),
                namespace: diff.namespace.clone(),
                id: diff.id.clone(),
                action: DiffAction::Add,
            });
        }
    }

    if batch.is_empty() {
        return Ok(Some(ApplyResult::default()));
    }

    // `split_batch` packs in dependency order, and `ops` was collected in the
    // same order the batch arrays were filled, so per-chunk slices of `ops`
    // line up with the resources each chunk carries only if `ops` is
    // re-sorted the same way. Rebuild it from the chunk contents instead of
    // assuming.
    let chunks = http_client::split_batch(&batch, BATCH_MAX_BODY_BYTES)?;
    let by_key: BTreeMap<(String, String), AppliedOp> = ops
        .into_iter()
        .map(|op| ((op.kind.clone(), op.id.clone()), op))
        .collect();

    let mut created = 0usize;
    let mut applied: Vec<AppliedOp> = Vec::new();

    for (index, chunk) in chunks.iter().enumerate() {
        match client.post_batch(chunk, namespace).await {
            Ok(Some(_counts)) => {
                // `/batch` is all-or-nothing and never answers 207, so a
                // non-error response means the whole chunk landed.
                created += chunk.len();
                applied.extend(chunk_ops(chunk, &by_key));
            }
            // 501 on the first chunk: nothing landed, so the caller can retry
            // the whole namespace per-resource. On a later chunk the earlier
            // ones are already committed — report progress instead.
            Ok(None) if index == 0 => return Ok(None),
            Ok(None) => {
                return Ok(Some(ApplyResult {
                    created,
                    applied_incremental: applied,
                    errors: vec![format!(
                        "POST /batch stopped after {created} resource(s): gateway returned 501 \
                         mid-run. Re-run apply to create the remaining {} resource(s) via \
                         per-resource calls.",
                        batch.len().saturating_sub(created)
                    )],
                    ..Default::default()
                }));
            }
            Err(e) if index == 0 && matches!(e, crate::error::Error::GatewayReadOnly(_)) => {
                return Err(e)
            }
            Err(e) => {
                return Ok(Some(ApplyResult {
                    created,
                    applied_incremental: applied,
                    errors: vec![format!("POST /batch: {e}")],
                    ..Default::default()
                }));
            }
        }
    }

    Ok(Some(ApplyResult {
        created,
        applied_incremental: applied,
        ..Default::default()
    }))
}

/// Recover the `AppliedOp` records for the resources a chunk actually carries.
fn chunk_ops(
    chunk: &BatchCreate,
    by_key: &BTreeMap<(String, String), AppliedOp>,
) -> Vec<AppliedOp> {
    let keys = chunk
        .upstreams
        .iter()
        .map(|u| ("Upstream".to_string(), u.id.clone()))
        .chain(
            chunk
                .consumers
                .iter()
                .map(|c| ("Consumer".to_string(), c.id.clone())),
        )
        .chain(
            chunk
                .proxies
                .iter()
                .map(|p| ("Proxy".to_string(), p.id.clone())),
        )
        .chain(
            chunk
                .plugin_configs
                .iter()
                .map(|p| ("PluginConfig".to_string(), p.id.clone())),
        );
    keys.filter_map(|key| by_key.get(&key).cloned()).collect()
}
