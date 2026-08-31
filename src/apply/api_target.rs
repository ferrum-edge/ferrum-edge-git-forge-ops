use std::collections::{BTreeMap, HashMap};

use crate::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::config::ApplyStrategy;
use crate::diff::resource_diff::{
    compute_diff_with_options, DiffAction, DiffOptions, DiffResult, OwnershipScope, ResourceDiff,
    SpecOwnedResource,
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
    /// `--allow-large-prune`. Doubles as the explicit acknowledgement that
    /// pruning against a *stale* (`X-Data-Source: cached`) gateway view is
    /// acceptable — both are "I accept that this apply may delete more than it
    /// should" decisions.
    pub allow_large_prune: bool,
    /// `--confirm-api-spec-deletion`. Full replace drops the namespace's
    /// `api_specs` section instead of carrying it through, and an exclusive
    /// incremental apply is allowed to prune live resources tagged with an
    /// `api_spec_id`. Without it, spec-owned resources are reported and
    /// skipped.
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
pub async fn apply_api(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&BTreeMap<String, BackupExtras>>,
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
                let extras = extras_by_namespace.and_then(|extras| extras.get(namespace));
                match apply_full_replace(&desired_namespace, client, namespace, extras, options)
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

/// `prefetched` carries the backup-only sections the caller already pulled with
/// the namespace's live config. Only fetched here when the caller had none —
/// `cmd_apply` reads `/backup` for its preview and large-prune guard anyway, so
/// re-reading it per namespace was a second full download of a document we
/// already had in hand.
async fn apply_full_replace(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespace: &str,
    prefetched: Option<&BackupExtras>,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
    // A bare `GatewayConfig` restore omits `api_specs`, which the gateway
    // reads as "delete every API spec in this namespace" — it answers 409
    // rather than doing it. Read the live sections first and hand them back
    // verbatim so a full replace only replaces what this repo manages.
    let fetched;
    let none = BackupExtras::default();
    let extras = if options.confirm_api_spec_deletion {
        &none
    } else {
        let extras = match prefetched {
            Some(extras) => extras,
            None => {
                fetched = client.get_backup_snapshot(namespace).await?.extras;
                &fetched
            }
        };
        if !extras.is_empty() {
            eprintln!(
                "[{namespace}] carrying {} API spec(s) and {} trust-bundle record(s) through the restore unchanged",
                extras.api_spec_count(),
                extras.trust_bundle_count(),
            );
        }
        extras
    };

    client
        .post_restore(
            desired,
            namespace,
            extras,
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
    let DiffResult {
        diffs,
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
    let diffs = order_diffs(diffs);

    for message in spec_owned_skip_messages(&spec_owned) {
        eprintln!("[{namespace}] {message}");
    }
    let spec_owned_skipped = spec_owned.iter().filter(|s| !s.pruned).count();

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
                Some(p) => client.create_proxy(p, namespace).await.map(applied),
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
                Some(c) => client.create_consumer(c, namespace).await.map(applied),
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
                Some(u) => client.create_upstream(u, namespace).await.map(applied),
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
                Some(p) => client.create_plugin_config(p, namespace).await.map(applied),
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

/// Collect a pure-Add diff into a `POST /batch` payload and send it.
///
/// Returns `Ok(None)` when the gateway answered 501 on the *first* chunk
/// (standalone MongoDB has no multi-document transaction and nothing landed),
/// signalling the caller to fall back to per-resource creates for the whole
/// namespace.
///
/// Any other chunk failure — a 501 partway through, a validation 400, a 409 on
/// one resource — is **not** the end of the run. `/batch` is all-or-nothing per
/// chunk, so a rejected chunk left nothing behind, and the single aggregate
/// `POST /batch: {e}` this used to return told the operator nothing about
/// *which* resource the gateway objected to while silently abandoning every
/// chunk behind it. The failing chunk and all remaining ones are replayed as
/// per-resource creates instead: each failure is then named individually, and
/// the resources the gateway is happy with still land.
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
                return Ok(Some(result));
            }
            Err(e) => {
                eprintln!(
                    "[{namespace}] POST /batch chunk {} failed ({e}); creating the remaining {} \
                     resource(s) individually so each failure is reported on its own.",
                    position + 1,
                    total.saturating_sub(result.created),
                );
                replay_from = Some(position);
                break;
            }
        }
    }

    if let Some(start) = replay_from {
        create_individually(&chunks[start..], client, namespace, &mut result).await;
    }

    Ok(Some(result))
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
/// Stops early on a read-only plane; every other failure is recorded against
/// the individual resource and the walk continues.
async fn create_individually(
    chunks: &[BatchCreate],
    client: &AdminClient,
    namespace: &str,
    result: &mut ApplyResult,
) {
    for chunk in chunks {
        for u in &chunk.upstreams {
            let outcome = client.create_upstream(u, namespace).await;
            record_create(result, outcome, "Upstream", &u.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        for c in &chunk.consumers {
            let outcome = client.create_consumer(c, namespace).await;
            record_create(result, outcome, "Consumer", &c.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        for p in &chunk.proxies {
            let outcome = client.create_proxy(p, namespace).await;
            record_create(result, outcome, "Proxy", &p.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        for pc in &chunk.plugin_configs {
            let outcome = client.create_plugin_config(pc, namespace).await;
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
