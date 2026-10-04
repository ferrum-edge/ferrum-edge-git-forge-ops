use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::config::schema::{
    Consumer, GatewayConfig, PassthroughFields, PluginConfig, PluginScope, Proxy, Upstream,
};
use crate::config::ApplyStrategy;
use crate::diagnostics::{safe, safe_line};
use crate::diff::resource_diff::{
    compare_fields, compute_diff_with_options, normalize_associations_for_comparison, state_key,
    DiffAction, DiffOptions, DiffResult, OwnershipScope, ResourceDiff, SpecOwnedResource,
};
use crate::http_client::conditional::ConsumerEvidence;
use crate::http_client::{
    self, AdminClient, BackupExtras, BatchCreate, ConditionalUpdate, DeleteOutcome,
    BATCH_MAX_BODY_BYTES,
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
    /// Every `namespace:Kind:id` the ownership ledger already lists as managed.
    ///
    /// Read-only here, and used for exactly one decision: a repository-declared
    /// row that is live, identical, and *absent* from this set produced no diff
    /// operation, so nothing would ever have recorded ownership of it. Those
    /// rows are adopted — see [`adoption_candidates`].
    pub managed_ledger: BTreeSet<String>,
    /// `--confirm-api-spec-deletion`. Full replace may proceed against a
    /// namespace with API specs only with this explicit destructive opt-in;
    /// an exclusive incremental apply may prune live resources tagged with an
    /// `api_spec_id`. Without it, spec-owned resources are reported and
    /// skipped, and non-empty spec namespaces reject full replacement.
    pub confirm_api_spec_deletion: bool,
    /// Accept a temporarily unprotected proxy during batch 501/413 fallback.
    pub allow_nontransactional_plugin_attach: bool,
    /// Namespaces the caller's own preflight refused, keyed to the reason.
    ///
    /// `cmd_apply` withholds credential allocation, delivery and create
    /// journaling for these, so their rows may still carry unallocated slots.
    /// The apply refuses them unconditionally rather than re-deriving the
    /// verdict from state the caller has since reconciled.
    pub refused_namespaces: BlockedNamespaces,
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
    /// Planned deletes not attempted because an Add/Modify failed in the same
    /// namespace or a referencing proxy could not be deleted. They never enter
    /// `applied_incremental`, preserving ownership.
    pub deletes_deferred: usize,
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
    /// Repository-declared rows that already matched the live gateway exactly
    /// and were claimed into the ownership ledger by this run.
    ///
    /// Kept separate from `applied_incremental` because they are not changes:
    /// nothing about the gateway's configuration differs afterwards. The caller
    /// records them the same way (`StateFile::record_op`), which is the whole
    /// point — without it a resource that was identical on the first apply
    /// never entered the shared-mode delete fence, and its later removal from
    /// the repository was never pruned.
    pub adopted: Vec<AppliedOp>,
    /// Operator-facing reasons an adoption candidate was *not* claimed: a
    /// cached backup, a failed confirmation read, or a row that changed between
    /// the diff and the ownership assertion.
    pub adoption_skipped: Vec<String>,
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
            "{} created, {} updated, {} deleted, {} deletes deferred",
            self.created, self.updated, self.deleted, self.deletes_deferred
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
/// | 1    | Add/Modify PluginConfig                     |
/// | 2    | Add/Modify Proxy                            |
/// | 3    | Delete Proxy                                |
/// | 4    | Delete PluginConfig                         |
/// | 5    | Delete Upstream, Delete Consumer            |
///
/// Deletes go *after* adds/modifies rather than before: an upstream can only
/// be removed once nothing references it, and the proxy modify that drops the
/// reference has to land first (`DELETE /upstreams/{id}` answers 409 while a
/// proxy still points at it). A rename on a contended unique value (a route,
/// say) conflicts. Any failed Add/Modify defers this namespace's deletes,
/// preserving the incumbent; an unchanged retry still conflicts until the
/// operator resolves the routing conflict. This is not an atomic swap.
/// New proxies and their new scoped configs form a cycle: neither can be
/// created individually first. `apply_incremental` batches those together at
/// rank 2, after independent plugin writes, without stripping associations.
pub fn operation_rank(action: &DiffAction, kind: &str) -> u8 {
    match action {
        DiffAction::Add | DiffAction::Modify => match kind {
            "Upstream" | "Consumer" => 0,
            "PluginConfig" => 1,
            "Proxy" => 2,
            _ => 2,
        },
        DiffAction::Delete => match kind {
            "Proxy" => 3,
            "PluginConfig" => 4,
            "Upstream" | "Consumer" => 5,
            _ => 3,
        },
    }
}

/// Sort a computed diff into admin-API application order.
///
/// Stable, so resources sharing a rank keep `compute_diff`'s
/// `(namespace, kind, id)` ordering. Applied here in the api target rather than
/// in `compute_diff` — the diff is also consumed by `plan`/`diff` output where
/// the grouping by kind is the more readable presentation.
pub fn order_diffs(mut diffs: Vec<ResourceDiff>) -> Vec<ResourceDiff> {
    diffs.sort_by_key(|d| operation_rank(&d.action, &d.kind));
    diffs
}

/// Execution and previews share namespace order and the rank-2 create batch.
/// Cycles precede ordinary proxy writes, after all independent plugin writes.
pub fn order_incremental_diffs(
    diffs: Vec<ResourceDiff>,
    desired: &GatewayConfig,
) -> Vec<ResourceDiff> {
    let mut diffs = order_diffs(diffs);
    let index = DesiredIndex::build(desired);
    let cycles = cyclic_create_diffs(&diffs, &index);
    let keys: BTreeSet<_> = cycles
        .iter()
        .map(|d| state_key(&d.namespace, &d.kind, &d.id))
        .collect();
    diffs.sort_by_key(|d| {
        let cyclic = keys.contains(&state_key(&d.namespace, &d.kind, &d.id));
        (
            d.namespace.clone(),
            if cyclic {
                2
            } else {
                operation_rank(&d.action, &d.kind)
            },
            !cyclic,
        )
    });
    diffs
}

/// The safe default and its explicit availability exception belong in every
/// preview of a create cycle, including plan JSON and the PR comment.
pub fn incremental_plugin_attach_notice(
    strategy: &ApplyStrategy,
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
) -> Option<&'static str> {
    if !matches!(strategy, ApplyStrategy::Incremental) {
        return None;
    }
    let index = DesiredIndex::build(desired);
    (!cyclic_create_diffs(diffs, &index).is_empty()).then_some(
        "New proxies and their new proxy-scoped plugins form a create cycle and require POST /batch. By default, a rejected batch never publishes a proxy without its scoped plugin. On 501/413 only, --allow-nontransactional-plugin-attach (or GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH=true) permits proxy-then-plugin creation: WARNING, the proxy is briefly published without its scoped plugin and remains so if attachment fails. Existing plugin retargets to new proxies must be staged separately.",
    )
}

/// A preview cannot predict write failures, so describe deletes as conditional.
pub fn incremental_prune_notice(
    strategy: &ApplyStrategy,
    diffs: &[ResourceDiff],
) -> Option<&'static str> {
    if matches!(strategy, ApplyStrategy::Incremental)
        && diffs.iter().any(|d| matches!(d.action, DiffAction::Delete))
    {
        Some(
            "Incremental deletes are conditional: any failed Add/Modify defers all deletes in that namespace; a failed proxy deletion also retains its referenced plugins. A same-route rename requires resolving the routing conflict; an unchanged retry cannot complete it.",
        )
    } else {
        None
    }
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
#[derive(Default)]
struct PreparedApply<'a> {
    /// One authoritative live view per namespace. Views the caller supplied
    /// are borrowed, not copied: a caller that already holds every
    /// namespace's backup (as `cmd_apply` does) would otherwise clone the
    /// whole live gateway once for the preflight and again for the apply.
    actuals: BTreeMap<String, Cow<'a, GatewayConfig>>,
    full_replaces: BTreeMap<String, PreparedFullReplace>,
    consumer_evidence: BTreeMap<String, BTreeMap<String, ConsumerEvidence>>,
    /// Namespaces that cannot be reconciled this run, keyed to the reason.
    ///
    /// A repository declaration colliding with an API-spec-owned row is a
    /// property of *that* namespace, not of the gateway or of the run, so it
    /// stops writes to that namespace only. Every other namespace still
    /// reconciles, and the reason lands in `ApplyResult::errors` so the run
    /// exits non-zero with the conflict named.
    blocked: BTreeMap<String, String>,
}

struct PreparedFullReplace {
    config: GatewayConfig,
    extras: BackupExtras,
}

/// Namespaces an apply will refuse to write, keyed to the refusal it will
/// report. See [`preflight_api_apply`].
pub type BlockedNamespaces = BTreeMap<String, String>;

/// Run every deterministic and remote write-capability preflight without
/// mutating the gateway.
///
/// `cmd_apply` calls this before credential allocation. `apply_api` repeats it
/// immediately before writes so a library caller cannot bypass the boundary
/// and a plane that became read-only while credentials were delivered still
/// fails before the first gateway mutation.
///
/// Returns the namespaces the apply will skip with a per-namespace error (a
/// repository/API-spec conflict, or a write that would drop fields this build
/// does not model). They are not a run-wide failure, so the caller gets them
/// back instead of an `Err`, and must not allocate credentials, deliver them,
/// or journal creates for those namespaces: nothing there would be written.
pub async fn preflight_api_apply(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&BTreeMap<String, BackupExtras>>,
    options: &ApplyOptions,
) -> crate::error::Result<BlockedNamespaces> {
    let prepared = prepare_apply(
        desired,
        client,
        namespaces,
        ownership_scope,
        actual_by_namespace,
        extras_by_namespace,
        options,
        true,
    )
    .await?;
    preflight_writes(client).await?;
    if matches!(options.strategy, ApplyStrategy::Incremental) {
        let targets = overwrite_targets(desired, namespaces, ownership_scope, &prepared, options)?;
        if let Some(refusal) = conditional_write_refusal(client, &targets).await {
            return Err(crate::error::Error::ConditionalWriteUnavailable(refusal));
        }
    }
    Ok(prepared.blocked)
}

/// Most rows [`conditional_write_refusal`] reads.
const CONDITIONAL_WRITE_PROBES: usize = 3;

/// Learn, before any write, whether the gateway issues the strong `ETag`
/// every incremental overwrite needs; `Some(refusal)` when it issues none.
///
/// Every overwrite is conditional (see [`Preconditions`]), and a gateway that
/// issues no tag would otherwise be found only at the first overwrite, after
/// earlier creates had landed. One read of a row the run will overwrite settles
/// it. `targets` are `(namespace, kind, id)`;
/// a row gone since the plan, or a read that fails, settles nothing, so the
/// next target is tried, and every write still checks for itself.
async fn conditional_write_refusal(
    client: &AdminClient,
    targets: &[(String, String, String)],
) -> Option<String> {
    for (namespace, kind, id) in targets.iter().take(CONDITIONAL_WRITE_PROBES) {
        match client.get_tagged(kind, id, namespace).await {
            Ok(Some(_)) => return None,
            Err(error @ crate::error::Error::ConditionalWriteUnavailable(_)) => {
                return Some(error.to_string());
            }
            Ok(None) | Err(_) => {}
        }
    }
    None
}

/// Consumer evidence needed before allocation. Nonconsumer work keeps its existing reads.
pub fn consumer_evidence_targets(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    namespace: &str,
    ownership_scope: OwnershipScope<'_>,
    options: &ApplyOptions,
) -> crate::error::Result<BTreeSet<String>> {
    let desired = crate::config::filter_config_by_namespace(desired, namespace);
    let diff = compute_diff_with_options(
        &desired,
        actual,
        ownership_scope,
        DiffOptions {
            prune_spec_owned: options.confirm_api_spec_deletion,
        },
    )?;
    let rewritten = incremental_rewrite_keys(&desired, actual, &diff, ownership_scope, options)?;
    Ok(actual
        .consumers
        .iter()
        .filter(|row| {
            rewritten.contains(&state_key(namespace, "Consumer", &row.id))
                || diff.diffs.iter().any(|diff| {
                    diff.kind == "Consumer"
                        && diff.id == row.id
                        && diff.action == DiffAction::Delete
                })
        })
        .map(|row| row.id.clone())
        .collect())
}

/// The first row each unrefused namespace will overwrite, as
/// `(namespace, kind, id)`: a Modify, Delete or pending-create assertion, or,
/// in shared mode, an adoption claim.
fn overwrite_targets(
    desired: &GatewayConfig,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    prepared: &PreparedApply<'_>,
    options: &ApplyOptions,
) -> crate::error::Result<Vec<(String, String, String)>> {
    let mut targets = Vec::new();
    for namespace in namespaces {
        if prepared.blocked.contains_key(namespace) {
            continue;
        }
        let Some(actual) = prepared.actuals.get(namespace) else {
            continue;
        };
        let desired = crate::config::filter_config_by_namespace(desired, namespace);
        let diff_options = DiffOptions {
            prune_spec_owned: options.confirm_api_spec_deletion,
        };
        let result = compute_diff_with_options(&desired, actual, ownership_scope, diff_options)?;
        let pending = &options.pending_create_assertions;
        let assertions = pending_create_assertion_diffs(&desired, actual, pending, namespace)?;
        let mut overwrite = result
            .diffs
            .iter()
            .chain(&assertions)
            .find(|diff| diff.action != DiffAction::Add)
            .map(|diff| (diff.kind.clone(), diff.id.clone()));
        if overwrite.is_none() && matches!(ownership_scope, OwnershipScope::Shared { .. }) {
            let handled: BTreeSet<String> = result
                .diffs
                .iter()
                .map(|diff| state_key(&diff.namespace, &diff.kind, &diff.id))
                .chain(pending.iter().cloned())
                .collect();
            let candidates =
                adoption_candidates(&desired, actual, &options.managed_ledger, &handled)?;
            overwrite = candidates.into_iter().next().map(|row| (row.kind, row.id));
        }
        if let Some((kind, id)) = overwrite {
            targets.push((namespace.clone(), kind, id));
        }
    }
    Ok(targets)
}

/// The per-namespace refusals an apply with these inputs would report, without
/// the write-capability probe or any mutation.
///
/// This is the same preparation [`apply_api`] runs, so an interactive preview
/// can show the refusal the apply would make. Deterministic run-wide errors
/// (an unsupported restore section, an unprovable spec graph, a cached view)
/// are returned as `Err`, exactly as the apply would return them.
pub async fn apply_blocked_namespaces(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    actual_by_namespace: Option<&BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&BTreeMap<String, BackupExtras>>,
    options: &ApplyOptions,
) -> crate::error::Result<BlockedNamespaces> {
    let prepared = prepare_apply(
        desired,
        client,
        namespaces,
        ownership_scope,
        actual_by_namespace,
        extras_by_namespace,
        options,
        false,
    )
    .await?;
    Ok(prepared.blocked)
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
    let mut prepared = prepare_apply(
        desired,
        client,
        namespaces,
        ownership_scope,
        actual_by_namespace,
        extras_by_namespace,
        options,
        true,
    )
    .await?;
    block_unresolved_placeholders(desired, namespaces, &mut prepared.blocked);
    preflight_writes(client).await?;
    Ok(apply_prepared(
        desired,
        client,
        namespaces,
        ownership_scope,
        &prepared,
        options,
    )
    .await)
}

/// Refuse every namespace whose rows still spell a broker slot as its
/// `${gh-env-secret:...}` placeholder.
///
/// Resolution only writes back values it found, so an unallocated or withheld
/// slot keeps its placeholder text, and a PUT or `/restore` would store that
/// text as the credential. Only the write path runs this: the preflight and
/// the preview see the configuration before allocation, where a slot awaiting
/// its value legitimately still holds a placeholder. Messages name slots,
/// never values.
fn block_unresolved_placeholders(
    desired: &GatewayConfig,
    namespaces: &[String],
    blocked: &mut BTreeMap<String, String>,
) {
    for namespace in namespaces {
        if blocked.contains_key(namespace) {
            continue;
        }
        let desired_namespace = crate::config::filter_config_by_namespace(desired, namespace);
        let reason = match crate::secrets::unresolved_placeholder_slots(&desired_namespace) {
            Ok(slots) if slots.is_empty() => continue,
            Ok(slots) => {
                let slots = slots
                    .iter()
                    .map(|slot| format!("`{slot}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "refusing apply for namespace `{namespace}`: credential slot(s) {slots} still hold an unresolved `${{gh-env-secret:...}}` placeholder, which would be written to the gateway as the credential value. Allocate or seed each slot and re-run. No resource in this namespace was written"
                )
            }
            Err(error) => format!(
                "refusing apply for namespace `{namespace}`: its credential slots could not be checked for unresolved placeholders: {error}. No resource in this namespace was written"
            ),
        };
        blocked.insert(namespace.clone(), reason);
    }
}

// Keep the aggregation boundary private: preparation and write preflight must
// finish before production callers can enter this loop.
async fn apply_prepared(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    prepared: &PreparedApply<'_>,
    options: &ApplyOptions,
) -> ApplyResult {
    let mut aggregate = ApplyResult::default();

    for namespace in namespaces {
        if let Some(reason) = prepared.blocked.get(namespace) {
            eprintln!("[{}] {}", safe(namespace), safe_line(reason));
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
                    aggregate.fatal_error = Some(format!(
                        "internal error: full-replace payload for namespace `{namespace}` was not prebuilt"
                    ));
                    break;
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
                // `prepare_apply` refuses to return without a view for every
                // namespace, so this is an internal invariant, not a fallback.
                let Some(actual) = prepared.actuals.get(namespace) else {
                    aggregate.fatal_error = Some(format!(
                        "internal error: authoritative backup for namespace `{namespace}` was not prepared"
                    ));
                    break;
                };
                match apply_incremental(
                    &desired_namespace,
                    client,
                    namespace,
                    ownership_scope,
                    actual,
                    prepared.consumer_evidence.get(namespace),
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
            eprintln!("Warning: {}", safe_line(warning));
        }

        aggregate.created += namespace_result.created;
        aggregate.updated += namespace_result.updated;
        aggregate.deleted += namespace_result.deleted;
        aggregate.deletes_missing += namespace_result.deletes_missing;
        aggregate.deletes_deferred += namespace_result.deletes_deferred;
        aggregate.unmanaged_skipped += namespace_result.unmanaged_skipped;
        aggregate.spec_owned_skipped += namespace_result.spec_owned_skipped;
        aggregate
            .applied_incremental
            .extend(namespace_result.applied_incremental);
        aggregate.adopted.extend(namespace_result.adopted);
        aggregate
            .adoption_skipped
            .extend(namespace_result.adoption_skipped);
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

    aggregate
}

/// Materialize the complete live view and every full-replace body before a
/// write is possible. This prevents a deterministic error in a later
/// namespace from appearing only after an earlier namespace was restored.
#[allow(clippy::too_many_arguments)]
async fn prepare_apply<'a>(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespaces: &[String],
    ownership_scope: OwnershipScope<'_>,
    actual_by_namespace: Option<&'a BTreeMap<String, GatewayConfig>>,
    extras_by_namespace: Option<&'a BTreeMap<String, BackupExtras>>,
    options: &ApplyOptions,
    require_evidence: bool,
) -> crate::error::Result<PreparedApply<'a>> {
    validate_no_desired_spec_tags(desired)?;
    let mut prepared = PreparedApply::default();
    let mut extras: BTreeMap<String, Cow<'a, BackupExtras>> = BTreeMap::new();

    for namespace in namespaces {
        let supplied_actual = actual_by_namespace.and_then(|items| items.get(namespace));
        let supplied_extras = extras_by_namespace.and_then(|items| items.get(namespace));
        let needs_paired_snapshot = matches!(options.strategy, ApplyStrategy::FullReplace)
            && (supplied_actual.is_none() || supplied_extras.is_none());

        if needs_paired_snapshot || supplied_actual.is_none() {
            let mut snapshot = if require_evidence
                && matches!(options.strategy, ApplyStrategy::FullReplace)
            {
                client.get_conditional_backup(namespace).await?
            } else {
                client.get_backup_snapshot_for_mutation(namespace).await?
            };
            if require_evidence && matches!(options.strategy, ApplyStrategy::Incremental) {
                let selected = consumer_evidence_targets(
                    desired,
                    &snapshot.config,
                    namespace,
                    ownership_scope,
                    options,
                )?;
                client
                    .capture_consumer_evidence(&mut snapshot, namespace, &selected)
                    .await?;
            }
            if snapshot.cached {
                return Err(crate::error::Error::StaleGatewayView(stale_view_message()));
            }
            prepared
                .actuals
                .insert(namespace.clone(), Cow::Owned(snapshot.config));
            extras.insert(namespace.clone(), Cow::Owned(snapshot.extras));
        } else if let Some(actual) = supplied_actual {
            prepared
                .actuals
                .insert(namespace.clone(), Cow::Borrowed(actual));
            if let Some(value) = supplied_extras {
                extras.insert(namespace.clone(), Cow::Borrowed(value));
            }
        }
    }

    for (namespace, value) in &extras {
        prepared
            .consumer_evidence
            .insert(namespace.clone(), value.consumer_evidence.clone());
    }

    // A cached backup deliberately omits API-spec documents and clears
    // `api_spec_id` tags. That makes every derived mutation unsafe, not just
    // deletes. The flag is sticky across namespaces, so fail before any
    // conflict or payload decision can trust that incomplete classification.
    ensure_authoritative_view(client)?;

    for namespace in namespaces {
        if let Some(reason) = options.refused_namespaces.get(namespace) {
            prepared.blocked.insert(namespace.clone(), reason.clone());
            continue;
        }
        let desired_namespace = crate::config::filter_config_by_namespace(desired, namespace);
        let actual = prepared.actuals.get(namespace).ok_or_else(|| {
            crate::error::Error::Config(format!(
                "internal error: authoritative backup for namespace `{namespace}` was not prepared"
            ))
        })?;
        let diff = compute_diff_with_options(
            &desired_namespace,
            actual,
            OwnershipScope::Exclusive,
            DiffOptions::default(),
        )?;
        if let Some(conflict) = spec_owned_conflict_block(&diff, namespace) {
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
            let full_replace = prepare_full_replace(
                &desired_namespace,
                actual,
                live_extras,
                namespace,
                options,
                require_evidence,
            )?;
            // The restore body re-creates every row it carries, including the
            // live spec-owned rows `preserve_spec_owned_graph` copied in. Those
            // are copied verbatim, `extra` included, so only the repository's
            // rows can lose a live-only top-level field.
            let rewritten: BTreeSet<String> = row_identities(&full_replace.config)
                .map(|(kind, namespace, id)| state_key(namespace, kind, id))
                .collect();
            let top_level = undeclared_live_top_level_fields(&desired_namespace, actual);
            if let Some(block) = unmodeled_field_block(
                &live_extras.unmodeled_nested_fields,
                &top_level,
                &rewritten,
                namespace,
            ) {
                prepared.blocked.insert(namespace.clone(), block);
                continue;
            }
            prepared
                .full_replaces
                .insert(namespace.clone(), full_replace);
        } else {
            // A caller-supplied live view without its extras would skip this
            // check silently, so a missing inventory is refused instead.
            let live_extras = extras.get(namespace).ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "backup extras (the unmodeled nested field inventory) for namespace `{namespace}` were not supplied alongside its live view; pass both from the same `/backup` snapshot"
                ))
            })?;
            let rewritten = incremental_rewrite_keys(
                &desired_namespace,
                actual,
                &diff,
                ownership_scope,
                options,
            )?;
            let targets = if require_evidence {
                consumer_evidence_targets(desired, actual, namespace, ownership_scope, options)?
            } else {
                BTreeSet::new()
            };
            for id in &targets {
                let evidence = live_extras.consumer_evidence.get(id).ok_or_else(|| {
                    crate::error::Error::ConditionalWriteUnavailable(
                        "complete consumer evidence must accompany the original plan before allocation"
                            .to_string(),
                    )
                })?;
                if let Some(consumer) = desired_namespace
                    .consumers
                    .iter()
                    .find(|row| &row.id == id)
                {
                    http_client::conditional::require_preserved_credentials(
                        &evidence.row,
                        consumer,
                        false,
                    )?;
                }
            }
            let top_level = undeclared_live_top_level_fields(&desired_namespace, actual);
            if let Some(block) = unmodeled_field_block(
                &live_extras.unmodeled_nested_fields,
                &top_level,
                &rewritten,
                namespace,
            ) {
                prepared.blocked.insert(namespace.clone(), block);
            }
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
fn spec_owned_conflict_block(result: &DiffResult, namespace: &str) -> Option<String> {
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

/// `(kind, namespace, id)` of every row in `config`.
fn row_identities(config: &GatewayConfig) -> impl Iterator<Item = (&'static str, &str, &str)> {
    let proxies = config
        .proxies
        .iter()
        .map(|row| ("Proxy", row.namespace.as_str(), row.id.as_str()));
    let consumers = config
        .consumers
        .iter()
        .map(|row| ("Consumer", row.namespace.as_str(), row.id.as_str()));
    let upstreams = config
        .upstreams
        .iter()
        .map(|row| ("Upstream", row.namespace.as_str(), row.id.as_str()));
    let plugin_configs = config
        .plugin_configs
        .iter()
        .map(|row| ("PluginConfig", row.namespace.as_str(), row.id.as_str()));
    proxies
        .chain(consumers)
        .chain(upstreams)
        .chain(plugin_configs)
}

/// State keys of the live rows an incremental apply will PUT in one namespace.
///
/// Mirrors the writes `apply_incremental` issues against rows that already
/// exist: every Modify, every pending-create ownership assertion, and in
/// shared mode every row [`adoption_candidates`] selects (claimed with an
/// idempotent PUT). Adoption is computed by the same function the apply uses,
/// so a declared row outside the ledger whose live copy differs from the
/// declaration — which is never adopted and so never written — does not
/// count. A declared row that is unchanged and needs no claim — including
/// every such row in exclusive mode, where adoption writes nothing — is left
/// out, so a defaulted field a newer gateway starts serializing does not wedge
/// every apply that merely declares it. Only declared keys are added, and only
/// live rows carry unmodeled fields, so a key naming a row that is not live
/// never matches one.
fn incremental_rewrite_keys(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    diff: &DiffResult,
    ownership_scope: OwnershipScope<'_>,
    options: &ApplyOptions,
) -> crate::error::Result<BTreeSet<String>> {
    let mut rewritten: BTreeSet<String> = diff
        .diffs
        .iter()
        .filter(|d| d.action == DiffAction::Modify)
        .map(|d| state_key(&d.namespace, &d.kind, &d.id))
        .collect();
    rewritten.extend(
        row_identities(desired)
            .map(|(kind, namespace, id)| state_key(namespace, kind, id))
            .filter(|key| options.pending_create_assertions.contains(key)),
    );
    if matches!(ownership_scope, OwnershipScope::Shared { .. }) {
        // `adopt_matching_rows` excludes every key the run already has an
        // operation for; the same exclusions apply here.
        let handled: BTreeSet<String> = diff
            .diffs
            .iter()
            .map(|d| state_key(&d.namespace, &d.kind, &d.id))
            .chain(options.pending_create_assertions.iter().cloned())
            .collect();
        let candidates = adoption_candidates(desired, actual, &options.managed_ledger, &handled)?;
        rewritten.extend(
            candidates
                .iter()
                .map(|row| state_key(&row.namespace, &row.kind, &row.id)),
        );
    }
    Ok(rewritten)
}

/// Unknown top-level fields a declared row's live copy carries and its
/// declaration does not, one entry per field, in the notation of the nested
/// inventory (`.spec.<field>`).
///
/// The live decode keeps every unknown top-level field in the row's flattened
/// `extra` map, whether or not `FERRUM_ALLOW_UNKNOWN_FIELDS` is set; the
/// repository row carries only what the repository declared. A PUT or
/// `/restore` built from the declaration therefore omits each such field and
/// the gateway resets it. A field the declaration does name (possible only
/// under `FERRUM_ALLOW_UNKNOWN_FIELDS=true`) is sent with the declared value
/// and diffed like any other, so it is not listed.
fn undeclared_live_top_level_fields(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
) -> Vec<http_client::UnmodeledNestedField> {
    fn undeclared<T: PassthroughFields>(
        kind: &str,
        key: (&str, &str),
        declared: &T,
        live: Option<&&T>,
        fields: &mut Vec<http_client::UnmodeledNestedField>,
    ) {
        let Some(live) = live else { return };
        let (namespace, id) = key;
        for field in live.passthrough().keys() {
            if !declared.passthrough().contains_key(field) {
                fields.push(http_client::UnmodeledNestedField {
                    kind: kind.to_string(),
                    namespace: namespace.to_string(),
                    id: id.to_string(),
                    path: format!(".spec.{field}"),
                });
            }
        }
    }

    let live = LiveIndex::build(actual);
    let mut fields = Vec::new();
    for row in &desired.proxies {
        let key = (row.namespace.as_str(), row.id.as_str());
        undeclared("Proxy", key, row, live.proxies.get(&key), &mut fields);
    }
    for row in &desired.consumers {
        let key = (row.namespace.as_str(), row.id.as_str());
        undeclared("Consumer", key, row, live.consumers.get(&key), &mut fields);
    }
    for row in &desired.upstreams {
        let key = (row.namespace.as_str(), row.id.as_str());
        undeclared("Upstream", key, row, live.upstreams.get(&key), &mut fields);
    }
    for row in &desired.plugin_configs {
        let key = (row.namespace.as_str(), row.id.as_str());
        let live_row = live.plugin_configs.get(&key);
        undeclared("PluginConfig", key, row, live_row, &mut fields);
    }
    fields
}

/// Refuse to rewrite a live row carrying fields this build does not model and
/// the repository does not declare.
///
/// `nested` is the backup's nested inventory: the typed decode dropped those
/// values. `top_level` comes from [`undeclared_live_top_level_fields`]: the
/// decode kept them, but the repository row the write is built from does not
/// carry them. Either way a PUT or `/restore` built from the repository
/// declaration would omit them and the gateway would reset each one to its
/// default — a silent change nobody declared. `rewritten` holds the state key
/// of every row the namespace's writes will send: see
/// [`incremental_rewrite_keys`] for incremental apply, and every row of the
/// restore body for full replace. Other rows are left alone or deleted,
/// neither of which truncates anything, so they do not block. A nested entry
/// that could not be attributed to a resource blocks unconditionally.
///
/// Namespace-scoped like [`spec_owned_conflict_block`], and deliberately not
/// narrowed to the affected rows: skipping one write would break the
/// dependency order the rest of the namespace relies on. There is no override
/// for nested fields: the repository loader rejects them, so no declaration
/// could carry them. A top-level field can instead be declared on the row
/// under `FERRUM_ALLOW_UNKNOWN_FIELDS=true`, which makes the write send it.
fn unmodeled_field_block(
    nested: &[http_client::UnmodeledNestedField],
    top_level: &[http_client::UnmodeledNestedField],
    rewritten: &BTreeSet<String>,
    namespace: &str,
) -> Option<String> {
    let offenders = nested
        .iter()
        .chain(top_level)
        .filter(|field| match field.kind.as_str() {
            "Proxy" | "Consumer" | "Upstream" | "PluginConfig" => {
                rewritten.contains(&state_key(&field.namespace, &field.kind, &field.id))
            }
            _ => true,
        })
        .collect::<Vec<_>>();
    if offenders.is_empty() {
        return None;
    }
    Some(format!(
        "refusing apply for namespace `{namespace}`: live row(s) this run would rewrite carry field(s) this build of gitforgeops does not model and the repository does not declare, and the write would reset them to their gateway defaults: {}. Upgrade gitforgeops to a version that models them (the intended fix), or remove them on the gateway; a top-level field can also be declared on the resource with FERRUM_ALLOW_UNKNOWN_FIELDS=true. No resource in this namespace was written; other namespaces were reconciled normally",
        http_client::describe_unmodeled_nested_fields(offenders).join("; ")
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
            | crate::error::Error::BackupNamespace(_)
            | crate::error::Error::DuplicateLiveResource(_)
            | crate::error::Error::StaleGatewayView(_)
            | crate::error::Error::RestoreNeedsManualRecovery(_)
            | crate::error::Error::UnsupportedBackupSections(_)
            | crate::error::Error::CommittedNotLive { .. }
            | crate::error::Error::AmbiguousMutation(_)
            | crate::error::Error::ConditionalWriteUnavailable(_)
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
            eprintln!(
                "Warning: admin preflight GET /health failed ({}); continuing.",
                safe_line(&e)
            );
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
///   retaining the existing authoritative-empty-section semantics. The original
///   namespace token also fences a concurrent spec creation. Sending `items: []`
///   is defined as an intentional wipe, so it is omitted.
/// - **`gateway_trust_bundles` is never sent.** The gateway defines an absent
///   section as "leave trust exactly as it is", so omitting it preserves the
///   live roots without the lost-update window that replaying a possibly-stale
///   snapshot would open.
///
/// The original namespace token fences the complete replacement at commit.
fn prepare_full_replace(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    live_extras: &BackupExtras,
    namespace: &str,
    options: &ApplyOptions,
    require_evidence: bool,
) -> crate::error::Result<PreparedFullReplace> {
    let conditional = live_extras.conditional.clone();
    if require_evidence
        && conditional
            .as_ref()
            .is_none_or(|metadata| metadata.namespace != namespace)
    {
        return Err(crate::error::Error::ConditionalWriteUnavailable(
            "full replacement requires the original coherent conditional namespace snapshot"
                .to_string(),
        ));
    }
    for consumer in &desired.consumers {
        if let Some(evidence) = live_extras.consumer_evidence.get(&consumer.id) {
            http_client::conditional::require_preserved_credentials(
                &evidence.row,
                consumer,
                true,
            )?;
        }
    }
    if options.confirm_api_spec_deletion {
        // Deliberate destruction of the spec graph: desired rows only, with
        // `confirm_api_spec_deletion=true` on the query so the gateway's
        // existing-spec guard stands down. Trust bundles still stay absent, so
        // the namespace's roots survive the wipe.
        return Ok(PreparedFullReplace {
            config: desired.clone(),
            extras: BackupExtras {
                conditional,
                ..BackupExtras::default()
            },
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
            conditional,
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
    crate::config::validate_unique_live_resource_keys(actual)?;
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
    actual: &GatewayConfig,
    consumer_evidence: Option<&BTreeMap<String, ConsumerEvidence>>,
    options: &ApplyOptions,
) -> crate::error::Result<ApplyResult> {
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
    )?;
    let assertions = dedupe_pending_assertions(
        &diffs,
        pending_create_assertion_diffs(
            desired,
            actual,
            &options.pending_create_assertions,
            namespace,
        )?,
    );
    for assertion in &assertions {
        eprintln!(
            "[{}] asserting repository ownership of pending {} `{}` with an idempotent update",
            safe(namespace),
            safe(&assertion.kind),
            safe(&assertion.id)
        );
    }
    diffs.extend(assertions);
    let diffs = order_incremental_diffs(diffs, desired);

    for message in spec_owned_skip_messages(&spec_owned) {
        eprintln!("[{}] {}", safe(namespace), safe_line(&message));
    }
    let spec_owned_skipped = spec_owned.iter().filter(|s| !s.pruned).count();

    let mut result = ApplyResult {
        unmanaged_skipped: unmanaged.len(),
        spec_owned_skipped,
        ..Default::default()
    };

    let index = DesiredIndex::build(desired);
    let cyclic_creates = cyclic_create_diffs(&diffs, &index);
    let cyclic_keys: BTreeSet<_> = cyclic_creates
        .iter()
        .map(|d| state_key(&d.namespace, &d.kind, &d.id))
        .collect();

    // Pure-Add namespaces take the transactional bulk path. `POST /batch` is
    // create-only and all-or-nothing (never 207), so any Modify or Delete in
    // the set disqualifies it.
    //
    // The batch path replaces the per-resource loop, not the adoption step
    // below it: a namespace whose *diff* is pure adds can still hold declared
    // rows that already match live and have never been claimed.
    let mut batched_result = None;
    if !diffs.is_empty() && diffs.iter().all(|d| matches!(d.action, DiffAction::Add)) {
        match try_batch_create(&diffs, &index, client, namespace, options).await? {
            Some(batched) => batched_result = Some(batched),
            // 501: standalone-MongoDB gateway with no multi-document
            // transaction. Fall through to per-resource CRUD.
            None => eprintln!(
                "[{}] gateway does not support POST /batch (501); \
                 falling back to per-resource creates.",
                safe(namespace)
            ),
        }
    }

    if let Some(batched) = batched_result {
        result = ApplyResult {
            unmanaged_skipped: result.unmanaged_skipped,
            spec_owned_skipped: result.spec_owned_skipped,
            ..batched
        };
        if result.fatal_error.is_none() {
            let adoption = AdoptionContext {
                desired,
                actual,
                index: &index,
                diffs: &diffs,
                stale_plan: None,
                consumer_evidence,
            };
            adopt_matching_rows(
                &adoption,
                client,
                namespace,
                ownership_scope,
                options,
                &mut result,
            )
            .await;
        }
        return Ok(result);
    }

    // All Add/Modify ranks precede all Delete ranks. Keep collecting write
    // failures, but do not remove incumbents when desired state was not
    // established. This flag belongs to this namespace only; failed deletes
    // do not prevent other deletes from being attempted.
    let mut writes_failed = false;
    let mut cyclic_pending = !cyclic_creates.is_empty();
    let mut failed_plugins = BTreeSet::new();
    let mut failed_proxy_deletions = BTreeSet::new();
    let mut changed_proxy_associations = BTreeSet::new();
    // The plan above came from `actual`, which the caller may have read long
    // before this point (`cmd_apply` reads it before credential allocation and
    // delivery). Every write that overwrites or deletes an existing row is made
    // conditional on a fresh read that still matches the plan; see
    // [`Preconditions`].
    let mut preconditions = Preconditions::new(client, namespace, actual, consumer_evidence)?;
    // The first write refused because its row changed after the plan. The
    // namespace's plan is then known to be stale, so nothing more is sent.
    let mut plan_stale: Option<String> = None;
    for diff in &diffs {
        if diff.namespace != namespace {
            return Err(crate::error::Error::BackupNamespace(format!(
                "diff namespace {:?} does not match apply namespace {namespace:?}",
                diff.namespace
            )));
        }
        let namespace = diff.namespace.as_str();
        if let Some(first) = &plan_stale {
            withhold_after_stale_plan(diff, first, &mut result);
            continue;
        }
        if cyclic_pending
            && (operation_rank(&diff.action, &diff.kind) >= 2
                || cyclic_keys.contains(&state_key(namespace, &diff.kind, &diff.id)))
        {
            cyclic_pending = false;
            // Withhold only the dependency groups whose proxy references a
            // plugin write that already failed; every other group still gets
            // its transactional create.
            let (blocked, attempt) =
                partition_cyclic_creates(&cyclic_creates, &index, &failed_plugins);
            for group in blocked {
                writes_failed = true;
                failed_plugins.extend(group.withheld_plugins);
                result.errors.push(group.message);
            }
            let batched = if attempt.is_empty() {
                Ok(Some(ApplyResult::default()))
            } else {
                try_batch_create(&attempt, &index, client, namespace, options).await
            };
            match batched {
                Ok(Some(batched)) => {
                    writes_failed |= !batched.errors.is_empty();
                    for op in &batched.applied_incremental {
                        if op.kind == "PluginConfig" {
                            preconditions.note_plugin_write(&op.id);
                        }
                    }
                    for pending in &attempt {
                        if pending.kind == "PluginConfig"
                            && !batched
                                .applied_incremental
                                .iter()
                                .any(|op| op.kind == pending.kind && op.id == pending.id)
                        {
                            failed_plugins.insert(pending.id.clone());
                        }
                    }
                    result.created += batched.created;
                    result
                        .applied_incremental
                        .extend(batched.applied_incremental);
                    result.errors.extend(batched.errors);
                    if batched.fatal_error.is_some() {
                        result.fatal_error = batched.fatal_error;
                        return Ok(result);
                    }
                }
                Ok(None) => {
                    writes_failed = true;
                    result.errors.push(
                        "new proxies and scoped plugins require transactional POST /batch support"
                            .to_string(),
                    );
                }
                Err(error) if is_fatal(&error) => {
                    result.fatal_error = Some(error.to_string());
                    return Ok(result);
                }
                Err(error) => {
                    writes_failed = true;
                    result.errors.push(error.to_string());
                }
            }
        }
        if cyclic_keys.contains(&state_key(namespace, &diff.kind, &diff.id)) {
            continue;
        }
        if writes_failed && matches!(diff.action, DiffAction::Delete) {
            result.deletes_deferred += 1;
            eprintln!(
                "[{}] DEFER DELETE {} `{}`: an Add/Modify failed in this namespace; prune not attempted and existing managed ledger entries preserved. Resolve the write failure before retrying.",
                safe(namespace),
                safe(&diff.kind),
                safe(&diff.id)
            );
            continue;
        }
        if diff.action == DiffAction::Delete
            && diff.kind == "PluginConfig"
            && actual.proxies.iter().any(|proxy| {
                failed_proxy_deletions.contains(&proxy.id)
                    && proxy
                        .plugins
                        .iter()
                        .any(|association| association.plugin_config_id == diff.id)
            })
        {
            result.deletes_deferred += 1;
            eprintln!(
                "[{}] DEFER DELETE PluginConfig `{}`: a referencing proxy could not be deleted; managed ledger entry preserved.",
                safe(namespace),
                safe(&diff.id)
            );
            continue;
        }
        let key = (diff.namespace.as_str(), diff.id.as_str());
        // Creates need no precondition: `POST` and `POST /batch` are
        // create-only, so the gateway refuses an id someone else took after
        // the plan. Every Modify, Delete and pending-create assertion goes
        // through `preconditions`, which sends it only with `If-Match` on a
        // fresh read that still matches the plan.
        let outcome = match (&diff.action, diff.kind.as_str()) {
            (DiffAction::Add, "Proxy") => match index.proxies.get(&key) {
                Some(p) if proxy_has_failed_plugin(p, &failed_plugins) => {
                    Err(failed_plugin_dependency(p, &failed_plugins))
                }
                Some(p) => create_with_reconciliation(client, namespace, CreateResource::Proxy(p))
                    .await
                    .map(applied),
                None => continue,
            },
            (DiffAction::Modify, "Proxy") => match index.proxies.get(&key) {
                Some(p) if proxy_has_failed_plugin(p, &failed_plugins) => {
                    Err(failed_plugin_dependency(p, &failed_plugins))
                }
                Some(p) if changed_proxy_associations.contains(&diff.id) => {
                    update_proxy_after_plugins(p, &preconditions, ownership_scope, options).await
                }
                Some(p) => preconditions.update(CreateResource::Proxy(p)).await,
                None => continue,
            },

            (DiffAction::Add, "Consumer") => match index.consumers.get(&key) {
                Some(c) => {
                    create_with_reconciliation(client, namespace, CreateResource::Consumer(c))
                        .await
                        .map(applied)
                }
                None => continue,
            },
            (DiffAction::Modify, "Consumer") => match index.consumers.get(&key) {
                Some(c) => preconditions.update(CreateResource::Consumer(c)).await,
                None => continue,
            },

            (DiffAction::Add, "Upstream") => match index.upstreams.get(&key) {
                Some(u) => {
                    create_with_reconciliation(client, namespace, CreateResource::Upstream(u))
                        .await
                        .map(applied)
                }
                None => continue,
            },
            (DiffAction::Modify, "Upstream") => match index.upstreams.get(&key) {
                Some(u) => preconditions.update(CreateResource::Upstream(u)).await,
                None => continue,
            },

            (DiffAction::Add, "PluginConfig") => match index.plugin_configs.get(&key) {
                Some(p) => {
                    create_with_reconciliation(client, namespace, CreateResource::PluginConfig(p))
                        .await
                        .map(applied)
                }
                None => continue,
            },
            (DiffAction::Modify, "PluginConfig") => match index.plugin_configs.get(&key) {
                Some(p) => preconditions.update(CreateResource::PluginConfig(p)).await,
                None => continue,
            },

            (DiffAction::Delete, "Proxy" | "Consumer" | "Upstream" | "PluginConfig") => {
                preconditions.delete(&diff.kind, &diff.id).await
            }

            _ => continue,
        };

        match outcome {
            Ok(OpOutcome::Unchanged) => {
                eprintln!(
                    "[{}] Proxy `{}` already matches after plugin writes; no proxy update needed",
                    safe(namespace),
                    safe(&diff.id)
                );
                if !options
                    .managed_ledger
                    .contains(&state_key(namespace, "Proxy", &diff.id))
                {
                    result.adopted.push(AppliedOp {
                        kind: diff.kind.clone(),
                        namespace: diff.namespace.clone(),
                        id: diff.id.clone(),
                        action: DiffAction::Modify,
                    });
                }
            }
            Ok(op) => {
                if diff.kind == "PluginConfig" && diff.action != DiffAction::Delete {
                    preconditions.note_plugin_write(&diff.id);
                    for plugin in actual
                        .plugin_configs
                        .iter()
                        .filter(|plugin| plugin.id == diff.id)
                        .chain(index.plugin_configs.get(&key).copied())
                    {
                        if let Some(proxy_id) = &plugin.proxy_id {
                            changed_proxy_associations.insert(proxy_id.clone());
                        }
                    }
                }
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
            Err(e) if is_fatal(&e) => {
                result.fatal_error = Some(e.to_string());
                return Ok(result);
            }
            Err(e) => {
                if matches!(e, crate::error::Error::StalePlan(_)) {
                    plan_stale = Some(format!("{} `{}`", diff.kind, diff.id));
                }
                if matches!(diff.action, DiffAction::Add | DiffAction::Modify) {
                    writes_failed = true;
                    if diff.kind == "PluginConfig" {
                        failed_plugins.insert(diff.id.clone());
                    }
                } else if diff.kind == "Proxy" {
                    failed_proxy_deletions.insert(diff.id.clone());
                }
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

    // Claim declared rows that were already identical. Per-resource failures
    // above do not block this: an adoption candidate is by definition a row no
    // operation touched, so a neighbour's failed update says nothing about it,
    // and leaving it unclaimed is precisely the bug being fixed. A plan proved
    // stale does block it: nothing more is written to this namespace.
    let adoption = AdoptionContext {
        desired,
        actual,
        index: &index,
        diffs: &diffs,
        stale_plan: plan_stale.as_deref(),
        consumer_evidence,
    };
    adopt_matching_rows(
        &adoption,
        client,
        namespace,
        ownership_scope,
        options,
        &mut result,
    )
    .await;

    Ok(result)
}

/// Withhold one write in a namespace whose plan an earlier refusal proved
/// stale. A withheld Add or Modify is an error; a withheld Delete is deferred.
fn withhold_after_stale_plan(diff: &ResourceDiff, first: &str, result: &mut ApplyResult) {
    let reason = format!(
        "{first} changed after this run planned namespace `{}`, so the namespace's remaining writes were withheld. Re-run apply to plan against the current gateway",
        diff.namespace
    );
    if diff.action == DiffAction::Delete {
        result.deletes_deferred += 1;
        eprintln!(
            "[{}] DEFER DELETE {} `{}`: {}",
            safe(&diff.namespace),
            safe(&diff.kind),
            safe(&diff.id),
            safe_line(&reason)
        );
        return;
    }
    let verb = if diff.action == DiffAction::Add {
        "create"
    } else {
        "update"
    };
    let message = format!("{} {} {verb}: not sent: {reason}", diff.kind, diff.id);
    result.errors.push(message);
}

fn proxy_has_failed_plugin(proxy: &Proxy, failed_plugins: &BTreeSet<String>) -> bool {
    proxy
        .plugins
        .iter()
        .any(|association| failed_plugins.contains(&association.plugin_config_id))
}

/// The referenced PluginConfig ids whose write failed, sorted and deduplicated.
fn failed_plugin_references<'a>(
    proxy: &'a Proxy,
    failed_plugins: &BTreeSet<String>,
) -> BTreeSet<&'a str> {
    proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .filter(|id| failed_plugins.contains(*id))
        .collect()
}

fn failed_plugin_dependency(
    proxy: &Proxy,
    failed_plugins: &BTreeSet<String>,
) -> crate::error::Error {
    let failed = failed_plugin_references(proxy, failed_plugins)
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    crate::error::Error::Config(format!(
        "proxy write not attempted because referenced PluginConfig {failed} failed to write"
    ))
}

/// A proxy/scoped-plugin create group withheld from `POST /batch` because a
/// proxy in it references a PluginConfig whose write already failed.
struct BlockedCreateGroup {
    message: String,
    /// The group's new PluginConfig ids. They were never created, so any later
    /// write that depends on them must be gated too.
    withheld_plugins: Vec<String>,
}

/// Split the cyclic creates into their proxy/plugin dependency groups (the
/// same components `split_batch` keeps inside one chunk). A group whose proxy
/// references a failed plugin write is reported by name and withheld; every
/// other group is returned for the transactional create, in diff order.
fn partition_cyclic_creates(
    cyclic_creates: &[ResourceDiff],
    index: &DesiredIndex<'_>,
    failed_plugins: &BTreeSet<String>,
) -> (Vec<BlockedCreateGroup>, Vec<ResourceDiff>) {
    if failed_plugins.is_empty() {
        return (Vec::new(), cyclic_creates.to_vec());
    }
    let mut blocked = Vec::new();
    let mut withheld = BTreeSet::new();
    for group in http_client::batch_dependency_groups(collect_batch(cyclic_creates, index)) {
        let failed: BTreeSet<&str> = group
            .proxies
            .iter()
            .flat_map(|proxy| failed_plugin_references(proxy, failed_plugins))
            .collect();
        if failed.is_empty() {
            continue;
        }
        let proxies = group
            .proxies
            .iter()
            .map(|proxy| proxy.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let failed = failed.into_iter().collect::<Vec<_>>().join(", ");
        let scoped = group
            .plugin_configs
            .iter()
            .map(|plugin| plugin.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        blocked.push(BlockedCreateGroup {
            message: format!(
                "Proxy {proxies} create: not attempted because referenced PluginConfig {failed} failed to write; its new scoped PluginConfig {scoped} was withheld from the same POST /batch transaction and not created"
            ),
            withheld_plugins: group
                .plugin_configs
                .iter()
                .map(|plugin| plugin.id.clone())
                .collect(),
        });
        for proxy in &group.proxies {
            withheld.insert(state_key(&proxy.namespace, "Proxy", &proxy.id));
        }
        for plugin in &group.plugin_configs {
            withheld.insert(state_key(&plugin.namespace, "PluginConfig", &plugin.id));
        }
    }
    let attempt = cyclic_creates
        .iter()
        .filter(|diff| !withheld.contains(&state_key(&diff.namespace, &diff.kind, &diff.id)))
        .cloned()
        .collect();
    (blocked, attempt)
}

/// Update a proxy whose associations this run's own plugin writes rewrote.
///
/// Never infer proxy reconciliation from a plugin response alone: the proxy is
/// read again after Edge's attachment/detachment writes. A shared unowned or
/// pending row still needs its explicit ownership assertion.
///
/// That read is also the proxy's precondition (see [`Preconditions`]): a proxy
/// an API spec claimed since the plan is refused, and so is one that changed in
/// any other way. Only the associations to plugin configs this run wrote are
/// left out of the comparison, because the gateway rewrites those itself. An
/// association to any other plugin that appeared or vanished since the plan is
/// a concurrent change, which the repository's association list must not
/// revert. The update is sent with `If-Match` on that read.
async fn update_proxy_after_plugins(
    proxy: &Proxy,
    preconditions: &Preconditions<'_>,
    ownership_scope: OwnershipScope<'_>,
    options: &ApplyOptions,
) -> crate::error::Result<OpOutcome> {
    let client = preconditions.client;
    let namespace = preconditions.namespace;
    let Some(tagged) = client.get_tagged("Proxy", &proxy.id, namespace).await? else {
        return Err(crate::error::Error::StalePlan(format!(
            "proxy `{}` disappeared after plugin writes; no proxy update was attempted. Re-run apply",
            proxy.id
        )));
    };
    let (live, dropped): (Proxy, _) = decode_live_row("Proxy", &tagged.body)?;
    refuse_dropped_field(dropped)?;
    if let Some(spec_id) = &live.api_spec_id {
        return Err(crate::error::Error::StalePlan(format!(
            "proxy `{}` became owned by API spec `{spec_id}` after plugin writes; no proxy update was attempted. Re-run apply to reassess namespace ownership",
            proxy.id
        )));
    }
    let observed = observed_row("Proxy", None, &live)?;
    preconditions
        .confirm_content("Proxy", &proxy.id, &observed)
        .await?;
    let key = state_key(namespace, "Proxy", &proxy.id);
    let needs_assertion = options.pending_create_assertions.contains(&key)
        || matches!(ownership_scope, OwnershipScope::Shared { .. })
            && !options.managed_ledger.contains(&key);
    if !needs_assertion && compare_fields("Proxy", proxy, &live).is_empty() {
        return Ok(OpOutcome::Unchanged);
    }
    CreateResource::Proxy(proxy)
        .update_if_match(client, namespace, &tagged.etag)
        .await
        .map(applied)
}

/// Why a planned overwrite was withheld because its row changed after the plan.
const STALE_PLAN_CHANGED: &str =
    "not sent: the live row changed after this run planned the write, so sending it would overwrite a concurrent change. Re-run apply to plan against the current gateway";

fn stale_plan_changed() -> crate::error::Error {
    crate::error::Error::StalePlan(STALE_PLAN_CHANGED.to_string())
}

/// Why a planned overwrite was withheld because its row lost or changed its
/// API-spec owner after the plan.
const STALE_PLAN_OWNERSHIP: &str =
    "not sent: the live row's API-spec ownership changed after this run planned the write. Re-run apply to plan against the current gateway";

/// Why a planned update was withheld because its row no longer exists.
const STALE_PLAN_GONE: &str =
    "not sent: the live row no longer exists, so it changed after this run planned the write. Re-run apply to plan against the current gateway";

/// Makes every incremental overwrite conditional on the row the plan judged.
///
/// The plan is computed from a live view the caller may have read long before
/// the first write: `cmd_apply` reads every namespace's `/backup`, then
/// allocates and delivers credentials and journals creates, and only then
/// applies. A concurrent `/api-specs` import or admin edit in that window must
/// not be overwritten (a PUT) or removed (a DELETE) from a stale ownership
/// decision. So every Modify, Delete and pending-create assertion:
///
/// 1. reads the row with `GET /<kind>/{id}`, which Ferrum Edge answers with a
///    strong `ETag` for the stored representation;
/// 2. refuses the write (as [`crate::error::Error::StalePlan`]) when that row
///    gained, lost or changed its `api_spec_id`, or changed in any field other
///    than server timestamps, since the plan (see
///    [`Preconditions::confirm_content`]); and
/// 3. sends the write with `If-Match: <etag>`. Edge compares the tag and
///    commits under one namespace admission lease that every admin writer
///    takes, so a change after the read is refused with `412` (also
///    `StalePlan`) instead of being overwritten.
///
/// A row that is gone needs no write to be deleted, so its DELETE is not sent
/// and is counted as already gone; an update of a row that is gone is
/// refused. A row served from cache, or one without a strong `ETag`, stops the
/// run: no write to it can be made conditional.
///
/// Consumers compare complete verification with the raw evidence captured before
/// allocation, including hidden fields and the original row token. Archival
/// normalization is never substituted for this stored-state precondition.
struct Preconditions<'a> {
    client: &'a AdminClient,
    namespace: &'a str,
    /// Rows as the plan saw them, keyed by `namespace:Kind:id`.
    planned: HashMap<String, ObservedRow>,
    consumer_evidence: BTreeMap<String, ConsumerEvidence>,
    /// PluginConfigs this run created or updated in the namespace. The gateway
    /// rewrites proxy associations to them itself, so a proxy comparison
    /// leaves those associations, and only those, out.
    written_plugins: BTreeSet<String>,
}

impl<'a> Preconditions<'a> {
    fn new(
        client: &'a AdminClient,
        namespace: &'a str,
        planned: &GatewayConfig,
        evidence: Option<&BTreeMap<String, ConsumerEvidence>>,
    ) -> crate::error::Result<Self> {
        Ok(Self {
            client,
            namespace,
            planned: observe_rows(planned)?,
            consumer_evidence: evidence.cloned().unwrap_or_default(),
            written_plugins: BTreeSet::new(),
        })
    }

    /// Record a PluginConfig this run created or updated.
    fn note_plugin_write(&mut self, id: &str) {
        self.written_plugins.insert(id.to_string());
    }

    /// Send the planned update of `resource` conditionally.
    async fn update(&mut self, resource: CreateResource<'_>) -> crate::error::Result<OpOutcome> {
        if let CreateResource::Consumer(consumer) = resource {
            if let Some(evidence) = self.consumer_evidence.get(resource.id()) {
                http_client::conditional::require_preserved_credentials(
                    &evidence.row,
                    consumer,
                    false,
                )?;
            }
        }
        match self.confirm(resource.kind(), resource.id(), true).await? {
            Some(etag) => resource
                .update_if_match(self.client, self.namespace, &etag)
                .await
                .map(applied),
            None => Err(crate::error::Error::StalePlan(STALE_PLAN_GONE.to_string())),
        }
    }

    /// Send the planned delete of `kind`/`id` conditionally.
    async fn delete(&mut self, kind: &str, id: &str) -> crate::error::Result<OpOutcome> {
        match self.confirm(kind, id, false).await? {
            Some(etag) => self
                .client
                .delete_if_match(kind, id, self.namespace, &etag)
                .await
                .map(OpOutcome::from),
            None => Ok(OpOutcome::AlreadyGone),
        }
    }

    /// The tag to write `kind`/`id` with, or `None` when no row holds it.
    ///
    /// An `update` also refuses a row carrying a nested field this client does
    /// not model: the rewrite would reset it, and `prepare_apply` refused every
    /// rewritten row carrying one at plan time, so it is new.
    async fn confirm(
        &mut self,
        kind: &str,
        id: &str,
        update: bool,
    ) -> crate::error::Result<Option<String>> {
        if kind == "Consumer" {
            return self.confirm_consumer(id, update).await;
        }
        let Some(tagged) = self.client.get_tagged(kind, id, self.namespace).await? else {
            return Ok(None);
        };
        let (live, dropped) = observe_body(kind, &tagged.body)?;
        if update {
            refuse_dropped_field(dropped)?;
        }
        self.confirm_content(kind, id, &live).await?;
        Ok(Some(tagged.etag))
    }

    /// Prove that `live`, from a single-resource read, is still the row the
    /// plan judged; otherwise [`crate::error::Error::StalePlan`].
    ///
    /// The owner must match. The content is compared with the read first and,
    /// only when that differs, with one `/backup` taken after the read. The
    /// plan came from `/backup`, which Ferrum Edge normalizes on load, while
    /// the read returns the row as stored, so a row stored before a
    /// normalization rule existed reads differently without having changed.
    /// The later backup shows any change made before it in the plan's own
    /// form, and the `If-Match` write refuses any change made after the read.
    async fn confirm_content(
        &self,
        kind: &str,
        id: &str,
        live: &ObservedRow,
    ) -> crate::error::Result<()> {
        let key = state_key(self.namespace, kind, id);
        let planned = self.planned.get(&key);
        if let Some(reason) = ownership_refusal(planned, live) {
            return Err(crate::error::Error::StalePlan(reason));
        }
        if self.content_matches(kind, planned, live) {
            return Ok(());
        }
        let snapshot = self
            .client
            .get_backup_snapshot_for_mutation(self.namespace)
            .await?;
        ensure_authoritative_view(self.client)?;
        let confirmed = observe_rows(&snapshot.config)?;
        let Some(row) = confirmed.get(&key) else {
            return Err(stale_plan_changed());
        };
        if let Some(reason) = ownership_refusal(planned, row) {
            return Err(crate::error::Error::StalePlan(reason));
        }
        if self.content_matches(kind, planned, row) {
            return Ok(());
        }
        Err(stale_plan_changed())
    }

    /// Content equality apart from server timestamps and, for a proxy, the
    /// associations to plugin configs this run wrote.
    fn content_matches(
        &self,
        kind: &str,
        planned: Option<&ObservedRow>,
        live: &ObservedRow,
    ) -> bool {
        planned.is_some_and(|planned| {
            let written = &self.written_plugins;
            without_written_associations(kind, &planned.value, written)
                == without_written_associations(kind, &live.value, written)
        })
    }

    async fn confirm_consumer(
        &mut self,
        id: &str,
        _update: bool,
    ) -> crate::error::Result<Option<String>> {
        let planned = self.consumer_evidence.get(id).ok_or_else(|| {
            crate::error::Error::ConditionalWriteUnavailable(
                "complete planned consumer evidence was not captured before allocation".to_string(),
            )
        })?;
        let Some(live) = self.client.get_consumer_verification(id, self.namespace).await? else {
            return Ok(None);
        };
        if !planned.same_row(&live) {
            return Err(stale_plan_changed());
        }
        Ok(Some(live.token.as_str().to_string()))
    }
}

/// One row's ownership tag and comparable content.
struct ObservedRow {
    api_spec_id: Option<String>,
    /// [`comparison_value`]: the row without server timestamps, with
    /// association order normalized.
    value: serde_json::Value,
}

/// `Some(reason)` when `live` gained, lost or changed its `api_spec_id`
/// since the plan.
fn ownership_refusal(planned: Option<&ObservedRow>, live: &ObservedRow) -> Option<String> {
    let planned_owner = planned.and_then(|row| row.api_spec_id.as_deref());
    if planned_owner == live.api_spec_id.as_deref() {
        return None;
    }
    Some(match &live.api_spec_id {
        Some(spec) => format!(
            "not sent: the live row became owned by API spec `{spec}` after this run planned the write. Re-run apply to plan against the current gateway"
        ),
        None => STALE_PLAN_OWNERSHIP.to_string(),
    })
}

/// A proxy comparison value without its associations to `written` plugin
/// configs. Any other kind is returned unchanged.
fn without_written_associations(
    kind: &str,
    value: &serde_json::Value,
    written: &BTreeSet<String>,
) -> serde_json::Value {
    let mut value = value.clone();
    if kind != "Proxy" {
        return value;
    }
    if let Some(associations) = value
        .get_mut("plugins")
        .and_then(serde_json::Value::as_array_mut)
    {
        associations.retain(|association| {
            association
                .get("plugin_config_id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|id| !written.contains(id))
        });
    }
    value
}

/// `row` as an [`ObservedRow`].
fn observed_row<T: serde::Serialize>(
    kind: &str,
    api_spec_id: Option<&str>,
    row: &T,
) -> crate::error::Result<ObservedRow> {
    let value = comparison_value(kind, row).ok_or_else(|| {
        crate::error::Error::Config(format!(
            "a {kind} row could not be serialized for comparison"
        ))
    })?;
    Ok(ObservedRow {
        api_spec_id: api_spec_id.map(str::to_string),
        value,
    })
}

/// Every row of one live view as an [`ObservedRow`], keyed by
/// `namespace:Kind:id`. Duplicate identities are refused, as on every other
/// view a mutation is authorized from.
fn observe_rows(config: &GatewayConfig) -> crate::error::Result<HashMap<String, ObservedRow>> {
    crate::config::validate_unique_live_resource_keys(config)?;
    let mut rows = HashMap::new();
    for row in &config.proxies {
        let observed = observed_row("Proxy", row.api_spec_id.as_deref(), row)?;
        rows.insert(state_key(&row.namespace, "Proxy", &row.id), observed);
    }
    for row in &config.consumers {
        let observed = observed_row("Consumer", None, row)?;
        rows.insert(state_key(&row.namespace, "Consumer", &row.id), observed);
    }
    for row in &config.upstreams {
        let observed = observed_row("Upstream", row.api_spec_id.as_deref(), row)?;
        rows.insert(state_key(&row.namespace, "Upstream", &row.id), observed);
    }
    for row in &config.plugin_configs {
        let observed = observed_row("PluginConfig", row.api_spec_id.as_deref(), row)?;
        rows.insert(state_key(&row.namespace, "PluginConfig", &row.id), observed);
    }
    Ok(rows)
}

/// A single-resource read as an [`ObservedRow`], with the first nested field
/// its typed decode dropped (see [`decode_live_row`]).
fn observe_body(
    kind: &str,
    body: &serde_json::Value,
) -> crate::error::Result<(ObservedRow, Option<String>)> {
    let (observed, dropped) = match kind {
        "Proxy" => {
            let (row, dropped): (Proxy, _) = decode_live_row(kind, body)?;
            (
                observed_row(kind, row.api_spec_id.as_deref(), &row)?,
                dropped,
            )
        }
        "Consumer" => {
            let (row, dropped): (Consumer, _) = decode_live_row(kind, body)?;
            (observed_row(kind, None, &row)?, dropped)
        }
        "Upstream" => {
            let (row, dropped): (Upstream, _) = decode_live_row(kind, body)?;
            (
                observed_row(kind, row.api_spec_id.as_deref(), &row)?,
                dropped,
            )
        }
        "PluginConfig" => {
            let (row, dropped): (PluginConfig, _) = decode_live_row(kind, body)?;
            (
                observed_row(kind, row.api_spec_id.as_deref(), &row)?,
                dropped,
            )
        }
        other => {
            return Err(crate::error::Error::Config(format!(
                "no conditional write for resource kind `{other}`"
            )));
        }
    };
    Ok((observed, dropped))
}

/// Decode one single-resource read, with the first nested field the typed
/// mirror dropped. Top-level unknown fields are kept in the row's flattened
/// `extra` map, so the content comparison already sees those.
fn decode_live_row<T: serde::de::DeserializeOwned>(
    kind: &str,
    body: &serde_json::Value,
) -> crate::error::Result<(T, Option<String>)> {
    let mut dropped = None;
    let row = serde_ignored::deserialize(body.clone(), |path| {
        if dropped.is_none() {
            dropped = Some(path.to_string());
        }
    })
    .map_err(|_| {
        crate::error::Error::HttpClient(format!(
            "the gateway returned a {kind} this client cannot read; details withheld"
        ))
    })?;
    Ok((row, dropped))
}

/// Refuse an update whose live row carries a nested field this client does
/// not model: the write is built from the repository row and would reset it.
fn refuse_dropped_field(dropped: Option<String>) -> crate::error::Result<()> {
    match dropped {
        Some(field) => Err(crate::error::Error::StalePlan(format!(
            "not sent: the live row now carries `{field}`, which this build of gitforgeops does not model, so the write would reset it. Re-run apply to plan against the current gateway"
        ))),
        None => Ok(()),
    }
}

/// New scoped configs and their new target proxies need a create transaction,
/// even when other changes make the namespace ineligible for the bulk path.
fn cyclic_create_diffs(diffs: &[ResourceDiff], index: &DesiredIndex<'_>) -> Vec<ResourceDiff> {
    let new_proxies: BTreeSet<_> = diffs
        .iter()
        .filter(|d| d.action == DiffAction::Add && d.kind == "Proxy")
        .map(|d| (d.namespace.as_str(), d.id.as_str()))
        .collect();
    let mut keys = BTreeSet::new();
    for diff in diffs
        .iter()
        .filter(|d| d.action == DiffAction::Add && d.kind == "PluginConfig")
    {
        let key = (diff.namespace.as_str(), diff.id.as_str());
        if let Some(proxy_id) = index
            .plugin_configs
            .get(&key)
            .filter(|plugin| plugin.scope == PluginScope::Proxy)
            .and_then(|plugin| plugin.proxy_id.as_deref())
        {
            if new_proxies.contains(&(diff.namespace.as_str(), proxy_id)) {
                keys.insert(state_key(&diff.namespace, "PluginConfig", &diff.id));
                keys.insert(state_key(&diff.namespace, "Proxy", proxy_id));
            }
        }
    }
    diffs
        .iter()
        .filter(|d| keys.contains(&state_key(&d.namespace, &d.kind, &d.id)))
        .cloned()
        .collect()
}

/// One repository-declared row that is already live, already identical, and
/// absent from the ownership ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionCandidate {
    pub kind: String,
    pub namespace: String,
    pub id: String,
}

/// The rows an apply would adopt: declared by the repository, live and exactly
/// as declared, untouched by any operation this run, and not yet in the
/// ownership ledger.
///
/// This closes the hole that made a documented adoption path silently fail. A
/// declared resource identical to its live row produces no diff entry, so no
/// operation ever recorded ownership of it — in shared mode it then sat outside
/// the delete fence forever, and removing it from the repository pruned
/// nothing. Its namespace could also drop out of `resolved_namespaces` entirely
/// once the repo stopped declaring anything there, because no ledger key named
/// it.
///
/// Two exclusions are load-bearing:
///
/// - **`handled`** — every key this run already has an operation for (including
///   the pending-create ownership assertions). Those are recorded through
///   `applied_incremental` when they succeed and must not be claimed twice, or
///   claimed at all when they failed.
/// - **API-spec-owned live rows.** The `/api-specs` importer owns them in both
///   ownership modes; adopting one would put a row the repo must never delete
///   inside the delete fence.
///
/// Adoption requires strict equality (apart from timestamps and association
/// order). Unlike pending-create recovery, an arbitrary pre-existing row may
/// carry fields the repository does not own, and the ownership PUT must not
/// erase them.
pub fn adoption_candidates(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    managed_ledger: &BTreeSet<String>,
    handled: &BTreeSet<String>,
) -> crate::error::Result<Vec<AdoptionCandidate>> {
    crate::config::validate_unique_live_resource_keys(actual)?;
    let live = LiveIndex::build(actual);
    let mut candidates = Vec::new();
    let mut consider = |resource: CreateResource<'_>, namespace: &str| {
        let kind = resource.kind();
        let id = resource.id();
        let key = state_key(namespace, kind, id);
        if managed_ledger.contains(&key) || handled.contains(&key) {
            return;
        }
        if live.is_spec_owned(kind, namespace, id) {
            return;
        }
        if !resource.safe_to_overwrite(&live) {
            return;
        }
        candidates.push(AdoptionCandidate {
            kind: kind.to_string(),
            namespace: namespace.to_string(),
            id: id.to_string(),
        });
    };

    for resource in &desired.upstreams {
        consider(CreateResource::Upstream(resource), &resource.namespace);
    }
    for resource in &desired.consumers {
        consider(CreateResource::Consumer(resource), &resource.namespace);
    }
    for resource in &desired.proxies {
        consider(CreateResource::Proxy(resource), &resource.namespace);
    }
    for resource in &desired.plugin_configs {
        consider(CreateResource::PluginConfig(resource), &resource.namespace);
    }

    Ok(candidates)
}

/// The one-line apply summary for an adoption pass, or `None` when nothing was
/// adopted (in which case the run says nothing about adoption at all).
pub fn adoption_summary_line(adopted: usize) -> Option<String> {
    (adopted > 0).then(|| format!("Adopted {adopted} already-matching resource(s) into the ledger"))
}

/// Claim already-matching declared rows into the ownership ledger.
///
/// **Shared mode** issues the same idempotent PUT the pending-create recovery
/// uses. Equality is not provenance: a row identical to the repository's
/// declaration may have been created by an administrator, and recording
/// ownership on the strength of equality alone would hand the repo deletion
/// authority over somebody else's resource. The PUT makes the repository the
/// row's last writer, which is a claim the gateway acknowledged.
///
/// Because that PUT overwrites the row, it is conditional: each candidate is
/// read with `GET /<kind>/{id}` and must still be exactly the declared row,
/// unowned by any API spec, and the PUT carries `If-Match` on that read (see
/// [`Preconditions`]). A human edit landing between this run's diff and the
/// assertion would otherwise be silently reverted. A row that moved is skipped
/// with a per-resource message and stays unclaimed; the next run sees it as an
/// ordinary Modify. Consumers use complete verification compared to the original
/// preallocation evidence; their credentials and row tokens are never inferred from
/// an archival backup.
///
/// **Exclusive mode** writes nothing. The repo is already authoritative for the
/// namespace and does not need a claim; the ledger entry is recorded anyway so
/// the fence is correct if the environment is ever switched to `shared`.
///
/// Nothing is adopted from a cached (`X-Data-Source: cached`) view in either
/// mode: that backup clears `api_spec_id` tags, so it cannot prove a row is not
/// spec-owned. Nothing is adopted from a namespace whose plan an earlier
/// refusal proved stale either.
async fn adopt_matching_rows(
    context: &AdoptionContext<'_>,
    client: &AdminClient,
    namespace: &str,
    ownership_scope: OwnershipScope<'_>,
    options: &ApplyOptions,
    result: &mut ApplyResult,
) {
    let handled: BTreeSet<String> = context
        .diffs
        .iter()
        .map(|d| state_key(&d.namespace, &d.kind, &d.id))
        .chain(options.pending_create_assertions.iter().cloned())
        .collect();
    let candidates = adoption_candidates(
        context.desired,
        context.actual,
        &options.managed_ledger,
        &handled,
    );
    let candidates = match candidates {
        Ok(candidates) => candidates,
        Err(error) => {
            result.fatal_error = Some(error.to_string());
            return;
        }
    };
    if candidates.is_empty() {
        return;
    }

    let skip_all = |result: &mut ApplyResult, reason: String| {
        let message = format!(
            "not adopting {} already-matching resource(s): {reason}",
            candidates.len()
        );
        eprintln!("[{}] {}", safe(namespace), safe_line(&message));
        result
            .adoption_skipped
            .push(format!("[{namespace}] {message}"));
    };

    if let Some(first) = context.stale_plan {
        skip_all(
            result,
            format!("{first} changed after this run planned the namespace"),
        );
        return;
    }

    if client.served_from_cache() {
        skip_all(
            result,
            "the gateway served /backup from its in-memory cache (X-Data-Source: cached), which clears API-spec ownership tags".to_string(),
        );
        return;
    }

    let index = context.index;
    let resources: Vec<CreateResource<'_>> = candidates
        .iter()
        .filter_map(|candidate| {
            let key = (candidate.namespace.as_str(), candidate.id.as_str());
            match candidate.kind.as_str() {
                "Proxy" => index.proxies.get(&key).copied().map(CreateResource::Proxy),
                "Consumer" => index
                    .consumers
                    .get(&key)
                    .copied()
                    .map(CreateResource::Consumer),
                "Upstream" => index
                    .upstreams
                    .get(&key)
                    .copied()
                    .map(CreateResource::Upstream),
                "PluginConfig" => index
                    .plugin_configs
                    .get(&key)
                    .copied()
                    .map(CreateResource::PluginConfig),
                _ => None,
            }
        })
        .collect();

    if matches!(ownership_scope, OwnershipScope::Exclusive) {
        // Exclusive mode asserts nothing, so there is nothing to overwrite and
        // no read to make.
        for resource in resources {
            eprintln!(
                "[{}] adopted {} `{}` into the ownership ledger (exclusive ownership needs no assertion)",
                safe(namespace),
                safe(resource.kind()),
                safe(resource.id())
            );
            result.adopted.push(adopted_op(resource));
        }
        return;
    }

    // Complete consumer reads are compared with the original preallocation evidence.
    let mut consumer_reads = HashMap::new();
    for resource in &resources {
        if let CreateResource::Consumer(consumer) = resource {
            let id = consumer.id.as_str();
            consumer_reads.insert(id, client.get_tagged("Consumer", id, namespace).await);
        }
    }
    // The confirmation read's `unmodeled_nested_fields` are not re-checked:
    // each candidate's own read refuses a nested field this client drops.
    let confirmation = match client.get_backup_snapshot_for_mutation(namespace).await {
        Ok(snapshot) if snapshot.cached => {
            skip_all(
                result,
                "the confirmation backup was served from cache (X-Data-Source: cached)".to_string(),
            );
            return;
        }
        Ok(snapshot) => snapshot.config,
        Err(error) if is_fatal(&error) => {
            result.fatal_error = Some(error.to_string());
            return;
        }
        Err(error) => {
            skip_all(
                result,
                format!("the confirmation backup could not be read: {error}"),
            );
            return;
        }
    };
    let confirmation = LiveIndex::build(&confirmation);

    for resource in resources {
        let (kind, id) = (resource.kind(), resource.id());
        let changed = format!(
            "not adopting {kind} `{id}`: the live row changed between this run's diff and the ownership assertion, so the repository is not overwriting it. The next apply reconciles it as an ordinary change."
        );
        if confirmation.is_spec_owned(kind, resource.namespace(), id)
            || !resource.safe_to_overwrite(&confirmation)
        {
            skip_adoption(result, namespace, &changed);
            if kind == "Consumer" {
                refuse_consumer_claim(result, namespace, id);
                return;
            }
            continue;
        }
        let read = match resource {
            CreateResource::Consumer(_) => consumer_reads.remove(id).unwrap_or(Ok(None)),
            _ => client.get_tagged(kind, id, namespace).await,
        };
        let etag = match read {
            Ok(Some(tagged))
                if resource.tagged_row_is(&tagged.body)
                    && (kind != "Consumer"
                        || context
                            .consumer_evidence
                            .and_then(|evidence| evidence.get(id))
                            .is_some_and(|planned| {
                                planned.row == tagged.body
                                    && planned.token.as_str() == tagged.etag
                            })) =>
            {
                tagged.etag
            }
            Ok(_) => {
                skip_adoption(result, namespace, &changed);
                if kind == "Consumer" {
                    refuse_consumer_claim(result, namespace, id);
                    return;
                }
                continue;
            }
            Err(error) if is_fatal(&error) => {
                result.fatal_error = Some(error.to_string());
                return;
            }
            Err(error) => {
                fail_adoption(result, namespace, kind, id, &error);
                continue;
            }
        };
        match resource.update_if_match(client, namespace, &etag).await {
            Ok(()) => {}
            Err(crate::error::Error::StalePlan(_)) => {
                skip_adoption(result, namespace, &changed);
                if kind == "Consumer" {
                    refuse_consumer_claim(result, namespace, id);
                    return;
                }
                continue;
            }
            Err(error) if is_fatal(&error) => {
                result.fatal_error = Some(error.to_string());
                return;
            }
            Err(error) => {
                fail_adoption(result, namespace, kind, id, &error);
                continue;
            }
        }
        eprintln!(
            "[{}] adopted {} `{}` into the ownership ledger with an idempotent update",
            safe(namespace),
            safe(kind),
            safe(id)
        );
        result.adopted.push(adopted_op(resource));
    }
}

/// The rows [`adopt_matching_rows`] chooses its candidates from.
struct AdoptionContext<'a> {
    desired: &'a GatewayConfig,
    actual: &'a GatewayConfig,
    index: &'a DesiredIndex<'a>,
    diffs: &'a [ResourceDiff],
    /// The write whose refusal proved the namespace's plan stale, if any.
    stale_plan: Option<&'a str>,
    consumer_evidence: Option<&'a BTreeMap<String, ConsumerEvidence>>,
}

fn adopted_op(resource: CreateResource<'_>) -> AppliedOp {
    AppliedOp {
        kind: resource.kind().to_string(),
        namespace: resource.namespace().to_string(),
        id: resource.id().to_string(),
        action: DiffAction::Modify,
    }
}

fn skip_adoption(result: &mut ApplyResult, namespace: &str, message: &str) {
    eprintln!("[{}] {}", safe(namespace), safe_line(message));
    result
        .adoption_skipped
        .push(format!("[{namespace}] {message}"));
}

fn refuse_consumer_claim(result: &mut ApplyResult, namespace: &str, id: &str) {
    fail_adoption(
        result,
        namespace,
        "Consumer",
        id,
        &crate::error::Error::StalePlan(
            "consumer evidence changed; remaining namespace claims withheld".to_string(),
        ),
    );
}

fn fail_adoption(
    result: &mut ApplyResult,
    namespace: &str,
    kind: &str,
    id: &str,
    error: &crate::error::Error,
) {
    eprintln!(
        "[{}] failed to adopt {} `{}`: {}",
        safe(namespace),
        safe(kind),
        safe(id),
        safe_line(error)
    );
    result.errors.push(format!("{kind} {id} adopt: {error}"));
}

/// What a single successful admin call actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpOutcome {
    Applied,
    /// Plugin writes already established the desired proxy associations.
    Unchanged,
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

/// `(namespace, id)`-keyed view over one gateway document, per kind.
///
/// The diff and the documents are all O(n); pairing them by scanning the
/// relevant `Vec` per entry made the apply loop, adoption and pending-create
/// recovery O(n²), which shows up as real time on namespaces with a few
/// thousand resources. Built once per document and shared by the per-resource
/// path, the batch collector and every live-row lookup.
///
/// The first row wins for a repeated key, matching the linear `find` it
/// replaces. Live documents are checked for duplicate keys before any decision
/// relies on them, and desired documents cannot contain any.
struct ResourceIndex<'a> {
    proxies: HashMap<(&'a str, &'a str), &'a Proxy>,
    consumers: HashMap<(&'a str, &'a str), &'a Consumer>,
    upstreams: HashMap<(&'a str, &'a str), &'a Upstream>,
    plugin_configs: HashMap<(&'a str, &'a str), &'a PluginConfig>,
}

/// The repository's desired document.
type DesiredIndex<'a> = ResourceIndex<'a>;
/// A live (`GET /backup`) document.
type LiveIndex<'a> = ResourceIndex<'a>;

impl<'a> ResourceIndex<'a> {
    fn build(config: &'a GatewayConfig) -> Self {
        fn index<'a, T>(
            rows: &'a [T],
            key: impl Fn(&'a T) -> (&'a str, &'a str),
        ) -> HashMap<(&'a str, &'a str), &'a T> {
            let mut map = HashMap::with_capacity(rows.len());
            for row in rows {
                map.entry(key(row)).or_insert(row);
            }
            map
        }

        Self {
            proxies: index(&config.proxies, |p| (p.namespace.as_str(), p.id.as_str())),
            consumers: index(&config.consumers, |c| (c.namespace.as_str(), c.id.as_str())),
            upstreams: index(&config.upstreams, |u| (u.namespace.as_str(), u.id.as_str())),
            plugin_configs: index(&config.plugin_configs, |p| {
                (p.namespace.as_str(), p.id.as_str())
            }),
        }
    }

    /// Does the `(namespace, kind, id)` row carry an `api_spec_id`? Consumers
    /// are never spec-provisioned, so they can never answer yes.
    fn is_spec_owned(&self, kind: &str, namespace: &str, id: &str) -> bool {
        let key = (namespace, id);
        match kind {
            "Proxy" => self
                .proxies
                .get(&key)
                .is_some_and(|r| r.api_spec_id.is_some()),
            "Upstream" => self
                .upstreams
                .get(&key)
                .is_some_and(|r| r.api_spec_id.is_some()),
            "PluginConfig" => self
                .plugin_configs
                .get(&key)
                .is_some_and(|r| r.api_spec_id.is_some()),
            _ => false,
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

    fn namespace(self) -> &'a str {
        match self {
            Self::Proxy(resource) => &resource.namespace,
            Self::Consumer(resource) => &resource.namespace,
            Self::Upstream(resource) => &resource.namespace,
            Self::PluginConfig(resource) => &resource.namespace,
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

    /// `PUT` this resource only if its stored row still carries `etag`.
    ///
    /// Every overwrite incremental apply sends goes through here: a planned
    /// update, and the idempotent ownership assertion of a row a pending or
    /// ambiguous create, or adoption, found already live.
    async fn update_if_match(
        self,
        client: &AdminClient,
        namespace: &str,
        etag: &str,
    ) -> crate::error::Result<()> {
        let (kind, id) = (self.kind(), self.id());
        let outcome = match self {
            Self::Proxy(row) => client.update_if_match(kind, id, row, namespace, etag).await,
            Self::Consumer(row) => client.update_if_match(kind, id, row, namespace, etag).await,
            Self::Upstream(row) => client.update_if_match(kind, id, row, namespace, etag).await,
            Self::PluginConfig(row) => client.update_if_match(kind, id, row, namespace, etag).await,
        };
        let refusal = match outcome? {
            ConditionalUpdate::Applied => return Ok(()),
            ConditionalUpdate::Refused(refusal) => refusal,
        };
        if refusal.after_retry && self.wrote_itself(client, namespace).await {
            return Ok(());
        }
        Err(crate::error::Error::StalePlan(refusal.message))
    }

    /// After a `412` that followed a retried attempt: does the row now carry
    /// exactly what this run sent, unowned? A subset match would also accept a
    /// concurrent writer's added optional field and incorrectly permit later
    /// writes and pruning. Only known server normalization is ignored.
    /// Consumers never qualify: Basic transformations cannot prove a plaintext write's
    /// outcome, even from complete stored evidence.
    async fn wrote_itself(self, client: &AdminClient, namespace: &str) -> bool {
        if matches!(self, Self::Consumer(_)) {
            return false;
        }
        match client.get_tagged(self.kind(), self.id(), namespace).await {
            Ok(Some(tagged)) => self.tagged_row_is(&tagged.body),
            _ => false,
        }
    }

    /// Does a single-resource read show this row, unowned by any API spec and
    /// carrying no nested field the typed mirror drops?
    ///
    /// Equality includes every optional field, apart from known server
    /// normalization. Consumer verification includes every stored credential field.
    fn tagged_row_is(self, body: &serde_json::Value) -> bool {
        let Ok((live, None)) = observe_body(self.kind(), body) else {
            return false;
        };
        if live.api_spec_id.is_some() {
            return false;
        }
        let desired = match self {
            Self::Proxy(row) => comparison_value(self.kind(), row),
            Self::Consumer(row) => comparison_value(self.kind(), row),
            Self::Upstream(row) => comparison_value(self.kind(), row),
            Self::PluginConfig(row) => comparison_value(self.kind(), row),
        };
        let Some(desired) = desired else {
            return false;
        };
        let desired = recovery_comparison_value(self.kind(), desired);
        let live = recovery_comparison_value(self.kind(), live.value);
        desired == live
    }

    /// The complete verified row, including gateway-populated optional fields.
    /// An ownership assertion must preserve these instead of rewriting the
    /// desired subset. Refuse a verification that dropped nested fields.
    fn verified_row<'b>(
        self,
        live: &LiveIndex<'b>,
        nested: &[http_client::UnmodeledNestedField],
    ) -> Option<CreateResource<'b>> {
        if live.is_spec_owned(self.kind(), self.namespace(), self.id())
            || nested.iter().any(|field| match field.kind.as_str() {
                "Proxy" | "Consumer" | "Upstream" | "PluginConfig" => {
                    field.kind == self.kind()
                        && field.namespace == self.namespace()
                        && field.id == self.id()
                }
                _ => true,
            })
        {
            return None;
        }
        if matches!(self, Self::Consumer(_)) {
            let row = live.consumers.get(&(self.namespace(), self.id()))?;
            let raw = serde_json::to_value(row).ok()?;
            http_client::conditional::require_publishable_credentials(&raw, false).ok()?;
        }
        let key = (self.namespace(), self.id());
        match self {
            Self::Proxy(_) => live.proxies.get(&key).copied().map(CreateResource::Proxy),
            Self::Consumer(_) => live
                .consumers
                .get(&key)
                .copied()
                .map(CreateResource::Consumer),
            Self::Upstream(_) => live
                .upstreams
                .get(&key)
                .copied()
                .map(CreateResource::Upstream),
            Self::PluginConfig(_) => live
                .plugin_configs
                .get(&key)
                .copied()
                .map(CreateResource::PluginConfig),
        }
    }

    fn exact_desired_is_live(self, live: &LiveIndex<'_>) -> bool {
        matches!(self.live_match(live), LiveMatch::Exact)
    }

    /// Whether an adoption PUT can serialize this desired row without dropping
    /// anything currently present on the gateway.
    fn safe_to_overwrite(self, live: &LiveIndex<'_>) -> bool {
        fn matches<T: serde::Serialize>(kind: &str, live: Option<&&T>, desired: &T) -> bool {
            live.is_some_and(|live| resource_values_equal(kind, desired, *live))
        }

        match self {
            Self::Proxy(desired) => matches(
                self.kind(),
                live.proxies
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
            Self::Consumer(desired) => matches(
                self.kind(),
                live.consumers
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
            Self::Upstream(desired) => matches(
                self.kind(),
                live.upstreams
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
            Self::PluginConfig(desired) => matches(
                self.kind(),
                live.plugin_configs
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
        }
    }

    /// Classify what an authoritative backup says about this resource.
    ///
    /// The three answers are not interchangeable after an ambiguous create:
    /// `Absent` proves the write did not commit, `Different` proves *something*
    /// holds the identity but not what we sent, and `Exact` is the only one
    /// that permits recording the create as landed.
    ///
    /// A row carrying an `api_spec_id` is always `Different`. The subset test
    /// cannot see the tag (the repository never declares one), so without this
    /// a create racing an `/api-specs` import that produced identical content
    /// would "recover" by asserting ownership of the spec's row with a PUT.
    fn live_match(self, live: &LiveIndex<'_>) -> LiveMatch {
        fn classify<T: serde::Serialize>(kind: &str, live: Option<&&T>, desired: &T) -> LiveMatch {
            match live {
                None => LiveMatch::Absent,
                Some(live) if resource_values_match(kind, desired, *live) => LiveMatch::Exact,
                Some(_) => LiveMatch::Different,
            }
        }

        if live.is_spec_owned(self.kind(), self.namespace(), self.id()) {
            return LiveMatch::Different;
        }
        match self {
            Self::Proxy(desired) => classify(
                self.kind(),
                live.proxies
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
            Self::Consumer(desired) => classify(
                self.kind(),
                live.consumers
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
            Self::Upstream(desired) => classify(
                self.kind(),
                live.upstreams
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
                desired,
            ),
            Self::PluginConfig(desired) => classify(
                self.kind(),
                live.plugin_configs
                    .get(&(desired.namespace.as_str(), desired.id.as_str())),
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
            // The tagged read comes first, so the ownership assertion below is
            // conditional on a row the verification backup then confirms. The
            // complete consumer verification retains credentials without redaction.
            let tagged = client
                .get_tagged(resource.kind(), resource.id(), namespace)
                .await;
            // Recovery retains the complete verification row and refuses any
            // nested fields its typed decode dropped before asserting ownership.
            let snapshot = if resource.kind() == "Consumer" {
                client.get_complete_backup(namespace).await
            } else {
                client.get_backup_snapshot_for_mutation(namespace).await
            }
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
            let live = LiveIndex::build(&snapshot.config);
            let nested = &snapshot.unmodeled_nested_fields;
            match resource.live_match(&live) {
                LiveMatch::Exact => {
                    let verified = resource
                        .verified_row(&live, nested)
                        .ok_or_else(|| {
                            crate::error::Error::AmbiguousMutation(format!(
                                "{} `{}` in namespace `{namespace}` returned `{original}`; the verification did not retain a complete unowned row, so no ownership assertion was sent",
                                resource.kind(),
                                resource.id(),
                            ))
                        })?;
                    let etag = match tagged {
                        Ok(Some(tagged))
                            if verified.tagged_row_is(&tagged.body)
                                && complete_consumer_read_matches(resource, &snapshot, &tagged) =>
                        {
                            tagged.etag
                        }
                        Ok(_) => {
                            return Err(crate::error::Error::AmbiguousMutation(format!(
                                "{} `{}` in namespace `{namespace}` returned `{original}`; an authoritative backup found the exact desired row, but the conditional read before it did not show that row, so no ownership assertion was sent. The row remains outside the managed delete fence; re-run diff before retrying.",
                                resource.kind(),
                                resource.id(),
                            )));
                        }
                        Err(read) => {
                            return Err(crate::error::Error::AmbiguousMutation(format!(
                                "{} `{}` in namespace `{namespace}` returned `{original}`; an authoritative backup found the exact desired row, but its conditional read failed: {read}. No ownership assertion was sent; the row remains outside the managed delete fence.",
                                resource.kind(),
                                resource.id(),
                            )));
                        }
                    };
                    verified
                        .update_if_match(client, namespace, &etag)
                        .await
                        .map_err(|assertion| {
                            crate::error::Error::AmbiguousMutation(format!(
                                "{} `{}` in namespace `{namespace}` returned `{original}`; an authoritative backup found the exact desired row, but the idempotent ownership assertion failed: {assertion}. The row remains outside the managed delete fence.",
                                resource.kind(),
                                resource.id(),
                            ))
                        })?;
                    eprintln!(
                        "[{}] {} `{}` returned an ambiguous response; an authoritative backup found the exact desired resource live and an idempotent update asserted repository ownership without replaying the create",
                        safe(namespace),
                        safe(resource.kind()),
                        safe(resource.id()),
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
/// scalars still compare exactly, except Proxy.plugins association order. A
/// differing target list or timeout is a real difference, not a gateway default.
/// Extra keys on the live side are
/// ignored. `created_at` / `updated_at` are dropped outright: the desired side
/// omits them unless the repository declares them, and the gateway always
/// stamps them on the live side, so a comparison that kept them would read
/// every row as a foreign one.
///
/// This is not an ownership proof and is never used as one: the callers follow
/// a positive match with an idempotent PUT that overwrites the row with the
/// desired content before anything enters the managed delete fence.
fn resource_values_match<T: serde::Serialize>(kind: &str, desired: &T, live: &T) -> bool {
    match (
        comparison_value(kind, desired),
        comparison_value(kind, live),
    ) {
        (Some(desired), Some(live)) => json_contains(&desired, &live),
        _ => false,
    }
}

/// Strict equality for adoption, apart from timestamps and association order.
fn resource_values_equal<T: serde::Serialize>(kind: &str, desired: &T, live: &T) -> bool {
    match (
        comparison_value(kind, desired),
        comparison_value(kind, live),
    ) {
        (Some(desired), Some(live)) => desired == live,
        _ => false,
    }
}

fn comparison_value<T: serde::Serialize>(kind: &str, value: &T) -> Option<serde_json::Value> {
    let mut value = serde_json::to_value(value).ok()?;
    if let Some(map) = value.as_object_mut() {
        map.remove("created_at");
        map.remove("updated_at");
    }
    normalize_associations_for_comparison(kind, &mut value);
    Some(value)
}

/// Only canonicalize a documented server default for recovery equality.
/// Typed decoding already fills non-optional defaults; other optional fields
/// must remain visible, even when the sent row omitted them. HTTP-family
/// proxies store an omitted backend scheme as `https` (as in assembly), while
/// stream proxies have no such default. Timestamps and association order were
/// already handled by `comparison_value`.
fn recovery_comparison_value(kind: &str, mut value: serde_json::Value) -> serde_json::Value {
    if kind == "Proxy"
        && value
            .get("listen_port")
            .is_none_or(serde_json::Value::is_null)
        && value
            .get("backend_scheme")
            .is_none_or(serde_json::Value::is_null)
    {
        value["backend_scheme"] = serde_json::json!("https");
    }
    value
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
        // Association sets were normalized at the resource boundary; other
        // arrays (targets, credential entries, opaque config) stay ordered.
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
) -> crate::error::Result<Vec<ResourceDiff>> {
    crate::config::validate_unique_live_resource_keys(actual)?;
    let live = LiveIndex::build(actual);
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
        if pending.contains(&key) && CreateResource::Upstream(resource).exact_desired_is_live(&live)
        {
            add("Upstream", &resource.id);
        }
    }
    for resource in &desired.consumers {
        let key = state_key(&resource.namespace, "Consumer", &resource.id);
        if pending.contains(&key) && CreateResource::Consumer(resource).exact_desired_is_live(&live)
        {
            add("Consumer", &resource.id);
        }
    }
    for resource in &desired.proxies {
        let key = state_key(&resource.namespace, "Proxy", &resource.id);
        if pending.contains(&key) && CreateResource::Proxy(resource).exact_desired_is_live(&live) {
            add("Proxy", &resource.id);
        }
    }
    for resource in &desired.plugin_configs {
        let key = state_key(&resource.namespace, "PluginConfig", &resource.id);
        if pending.contains(&key)
            && CreateResource::PluginConfig(resource).exact_desired_is_live(&live)
        {
            add("PluginConfig", &resource.id);
        }
    }

    Ok(assertions)
}

/// Drop pending-create assertions whose `(namespace, kind, id)` already has a
/// diff entry.
///
/// The assertion is a subset match, so a live row carrying a gateway-populated
/// optional field is both an exact pending row *and* an ordinary Modify. The
/// ordinary Modify's PUT already asserts repository ownership, and its success
/// clears the journal entry through `StateFile::record_op`; keeping both would
/// issue the same PUT twice and list the row twice in every preview. Apply and
/// every preview (interactive, `plan`, `review`) share this filter.
pub fn dedupe_pending_assertions(
    diffs: &[ResourceDiff],
    assertions: Vec<ResourceDiff>,
) -> Vec<ResourceDiff> {
    let existing: BTreeSet<String> = diffs
        .iter()
        .map(|d| state_key(&d.namespace, &d.kind, &d.id))
        .collect();
    assertions
        .into_iter()
        .filter(|d| !existing.contains(&state_key(&d.namespace, &d.kind, &d.id)))
        .collect()
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
/// Returns `Ok(None)` when the gateway answered 501 on the *first* chunk and
/// there are no proxy/scoped-plugin cycles, signalling the caller to fall back
/// to per-resource creates. Cycles remain atomic by default; the explicit
/// nontransactional attachment option applies only after batch 501/413.
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
    options: &ApplyOptions,
) -> crate::error::Result<Option<ApplyResult>> {
    let batch = collect_batch(diffs, index);
    if batch.is_empty() {
        return Ok(Some(ApplyResult::default()));
    }

    let total = batch.len();
    let chunks = http_client::split_batch(batch, BATCH_MAX_BODY_BYTES)?;
    let mut result = ApplyResult::default();
    let mut replay_from: Option<usize> = None;
    let mut allow_nontransactional_attach = false;

    for (position, chunk) in chunks.iter().enumerate() {
        match client.post_batch(chunk, namespace).await {
            Ok(Some(_counts)) => {
                // post_batch verified the status and every per-kind count.
                result.created += chunk.len();
                result
                    .applied_incremental
                    .extend(chunk_ops(chunk, namespace));
            }
            // 501 on the first chunk: nothing landed. Only acyclic graphs can
            // take the whole namespace down the per-resource path.
            Ok(None)
                if position == 0
                    && chunks
                        .iter()
                        .all(|chunk| batch_cycle_proxy_ids(chunk).is_empty()) =>
            {
                return Ok(None);
            }
            Ok(None) => {
                allow_nontransactional_attach = options.allow_nontransactional_plugin_attach;
                eprintln!(
                    "[{}] gateway returned 501 for POST /batch after {} resource(s); \
                     creating the remaining {} resource(s) individually.",
                    safe(namespace),
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
                allow_nontransactional_attach = options.allow_nontransactional_plugin_attach
                    && matches!(e, crate::error::Error::ApiError { status: 413, .. });
                eprintln!(
                    "[{}] POST /batch chunk {} was definitively rejected ({}); creating the remaining {} resource(s) individually so each failure is reported on its own.",
                    safe(namespace),
                    position + 1,
                    safe_line(&e),
                    total.saturating_sub(result.created),
                );
                replay_from = Some(position);
                break;
            }
            Err(e)
                if matches!(e, crate::error::Error::AmbiguousMutation(_))
                    || create_outcome_is_ambiguous(&e) =>
            {
                let original = e.to_string();
                // As in `create_with_reconciliation`, consumers are read before
                // the coherent verification backup. Ownership assertions preserve complete
                // rows and refuse fields its typed decode dropped.
                let mut consumer_reads = HashMap::new();
                for consumer in &chunk.consumers {
                    let id = consumer.id.as_str();
                    consumer_reads.insert(id, client.get_tagged("Consumer", id, namespace).await);
                }
                let verification = if chunk.consumers.is_empty() {
                    client.get_backup_snapshot_for_mutation(namespace).await
                } else {
                    client.get_complete_backup(namespace).await
                };
                let snapshot = match verification {
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
                        assert_batch_ownership(
                            chunk,
                            client,
                            namespace,
                            &snapshot,
                            consumer_reads,
                            &mut result,
                        )
                        .await;
                        if result.fatal_error.is_some() || result.errors.len() > errors_before {
                            note_unattempted_chunks(&chunks, position + 1, namespace, &mut result);
                            return Ok(Some(result));
                        }
                        eprintln!(
                            "[{}] POST /batch chunk {} returned an ambiguous response; an authoritative backup found all {} exact desired resources live and idempotent updates asserted repository ownership without replaying the batch",
                            safe(namespace),
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
        create_individually(
            &chunks[start..],
            client,
            namespace,
            allow_nontransactional_attach,
            &mut result,
        )
        .await;
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
    let live = LiveIndex::build(actual);
    let mut any_exact = false;
    let mut any_absent = false;
    let mut any_different = false;

    let mut record = |outcome: LiveMatch| match outcome {
        LiveMatch::Exact => any_exact = true,
        LiveMatch::Absent => any_absent = true,
        LiveMatch::Different => any_different = true,
    };

    for resource in &batch.proxies {
        record(CreateResource::Proxy(resource).live_match(&live));
    }
    for resource in &batch.consumers {
        record(CreateResource::Consumer(resource).live_match(&live));
    }
    for resource in &batch.upstreams {
        record(CreateResource::Upstream(resource).live_match(&live));
    }
    for resource in &batch.plugin_configs {
        record(CreateResource::PluginConfig(resource).live_match(&live));
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

/// Recovery compares the complete stored row and row token, never a normalized projection.
fn complete_consumer_read_matches(
    resource: CreateResource<'_>,
    snapshot: &http_client::BackupSnapshot,
    tagged: &http_client::TaggedResource,
) -> bool {
    resource.kind() != "Consumer"
        || snapshot
            .extras
            .consumer_evidence
            .get(resource.id())
            .is_some_and(|evidence| {
                evidence.row == tagged.body && evidence.token.as_str() == tagged.etag
            })
}

/// Assert ownership of every row an ambiguous batch was proven to have created,
/// each with a conditional `PUT` on a read that still shows the exact row.
///
/// Consumers were read before the verification backup (`consumer_reads`);
/// every other row is read immediately before its own PUT, because the
/// assertions before it may rewrite it (a plugin PUT touches its proxy's
/// associations). Exact batch readback already proved every dependency
/// committed, so a failed plugin ownership assertion does not stop the proxy's.
/// Compare against, and write, the complete verification row rather than the
/// desired subset: a field added after verification must refuse the PUT, and
/// a gateway-populated optional field already verified must survive it.
async fn assert_batch_ownership(
    batch: &BatchCreate,
    client: &AdminClient,
    namespace: &str,
    snapshot: &http_client::BackupSnapshot,
    mut consumer_reads: HashMap<&str, crate::error::Result<Option<http_client::TaggedResource>>>,
    result: &mut ApplyResult,
) {
    let live = LiveIndex::build(&snapshot.config);
    let nested = &snapshot.unmodeled_nested_fields;
    let resources = batch
        .upstreams
        .iter()
        .map(CreateResource::Upstream)
        .chain(batch.consumers.iter().map(CreateResource::Consumer))
        .chain(
            batch
                .plugin_configs
                .iter()
                .map(CreateResource::PluginConfig),
        )
        .chain(batch.proxies.iter().map(CreateResource::Proxy));
    for resource in resources {
        let (kind, id) = (resource.kind(), resource.id());
        let read = match resource {
            CreateResource::Consumer(_) => consumer_reads.remove(id).unwrap_or(Ok(None)),
            _ => client.get_tagged(kind, id, namespace).await,
        };
        let verified = resource.verified_row(&live, nested);
        let outcome = match (read, verified) {
            (Ok(Some(tagged)), Some(verified))
                if verified.tagged_row_is(&tagged.body)
                    && complete_consumer_read_matches(resource, snapshot, &tagged) =>
            {
                verified
                    .update_if_match(client, namespace, &tagged.etag)
                    .await
            }
            (Ok(_), _) => Err(crate::error::Error::StalePlan(
                "not sent: the conditional read before the ownership assertion did not show the exact row the batch created. Re-run diff before retrying".to_string(),
            )),
            (Err(error), _) => Err(error),
        };
        let stale = matches!(outcome, Err(crate::error::Error::StalePlan(_)));
        record_create(result, outcome, kind, id, namespace);
        if stale || result.fatal_error.is_some() {
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

fn batch_cycle_proxy_ids(batch: &BatchCreate) -> BTreeSet<&str> {
    let proxies: BTreeSet<_> = batch.proxies.iter().map(|p| p.id.as_str()).collect();
    batch
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.scope == PluginScope::Proxy)
        .filter_map(|plugin| plugin.proxy_id.as_deref())
        .filter(|id| proxies.contains(id))
        .collect()
}

/// Replay independent creates in dependency order. A new proxy and its scoped
/// configs require a transaction unless the operator explicitly accepts
/// temporary exposure after 501/413. Preserve all other proxy associations.
///
/// Stops early on a run-wide or ambiguous mutation failure; ordinary
/// per-resource validation failures are recorded and the walk continues.
async fn create_individually(
    chunks: &[BatchCreate],
    client: &AdminClient,
    namespace: &str,
    allow_nontransactional_attach: bool,
    result: &mut ApplyResult,
) {
    let mut failed_plugins = BTreeSet::new();
    for chunk in chunks {
        let cycles = batch_cycle_proxy_ids(chunk);
        for id in &cycles {
            if allow_nontransactional_attach {
                eprintln!(
                    "[{}] WARNING: --allow-nontransactional-plugin-attach permits Proxy `{}` to be briefly published without its scoped plugin. If plugin creation fails, the proxy remains published without that protection; repair the attachment immediately.",
                    safe(namespace),
                    safe(id)
                );
            } else {
                result.errors.push(format!(
                    "Proxy {id} and its new scoped PluginConfig(s) require a successful transactional POST /batch; no individual create was attempted for this cycle. Use a transaction-capable gateway and keep the dependency group below the batch body limit, or explicitly accept temporary exposure on 501/413 with --allow-nontransactional-plugin-attach (GITFORGEOPS_ALLOW_NONTRANSACTIONAL_PLUGIN_ATTACH=true)."
                ));
            }
        }
        let deferred_plugins: BTreeSet<_> = chunk
            .plugin_configs
            .iter()
            .filter(|pc| {
                pc.scope == PluginScope::Proxy
                    && pc.proxy_id.as_deref().is_some_and(|id| cycles.contains(id))
            })
            .map(|pc| pc.id.as_str())
            .collect();
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
        for pc in &chunk.plugin_configs {
            if deferred_plugins.contains(pc.id.as_str()) {
                if !allow_nontransactional_attach {
                    failed_plugins.insert(pc.id.clone());
                }
                continue;
            }
            let outcome =
                create_with_reconciliation(client, namespace, CreateResource::PluginConfig(pc))
                    .await;
            if outcome.is_err() {
                failed_plugins.insert(pc.id.clone());
            }
            record_create(result, outcome, "PluginConfig", &pc.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        let mut failed_proxies = BTreeSet::new();
        for p in &chunk.proxies {
            if cycles.contains(p.id.as_str()) && !allow_nontransactional_attach {
                continue;
            }
            let mut initial_proxy = p.clone();
            if cycles.contains(p.id.as_str()) {
                initial_proxy.plugins.retain(|association| {
                    !deferred_plugins.contains(association.plugin_config_id.as_str())
                });
            }
            let outcome = if proxy_has_failed_plugin(p, &failed_plugins) {
                Err(failed_plugin_dependency(p, &failed_plugins))
            } else {
                create_with_reconciliation(client, namespace, CreateResource::Proxy(&initial_proxy))
                    .await
            };
            if outcome.is_err() {
                failed_proxies.insert(p.id.as_str());
            }
            record_create(result, outcome, "Proxy", &p.id, namespace);
            if result.fatal_error.is_some() {
                return;
            }
        }
        if allow_nontransactional_attach {
            for pc in &chunk.plugin_configs {
                if !deferred_plugins.contains(pc.id.as_str()) {
                    continue;
                }
                let outcome = if pc
                    .proxy_id
                    .as_deref()
                    .is_some_and(|id| failed_proxies.contains(id))
                {
                    Err(crate::error::Error::Config(
                        "scoped plugin create not attempted because its proxy create failed"
                            .to_string(),
                    ))
                } else {
                    create_with_reconciliation(client, namespace, CreateResource::PluginConfig(pc))
                        .await
                };
                if outcome.is_err() {
                    failed_plugins.insert(pc.id.clone());
                }
                record_create(result, outcome, "PluginConfig", &pc.id, namespace);
                if result.fatal_error.is_some() {
                    return;
                }
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
        Err(e) if is_fatal(&e) => result.fatal_error = Some(e.to_string()),
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

#[cfg(test)]
mod prepared_apply_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // This invariant cannot be broken through apply_api today. Exercise its
    // private, real aggregation loop after preparing all namespaces, without
    // adding a production fault-injection option or a public test-only API.
    #[tokio::test]
    async fn missing_prepared_restore_preserves_completed_namespace_and_failed_verdict() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = AdminClient::new_scoped(
            &crate::config::EnvConfig {
                gateway_url: Some(format!("http://{}", listener.local_addr().unwrap())),
                admin_jwt_secret: Some("test-secret-must-be-32-chars-long".into()),
                gateway_max_retries: 0,
                ..Default::default()
            },
            ["alpha", "beta", "gamma"],
        )
        .unwrap();
        let desired: GatewayConfig = serde_json::from_value(serde_json::json!({
            "upstreams": [{"id": "u1", "namespace": "alpha", "targets": []}]
        }))
        .unwrap();
        let namespaces: Vec<String> = ["alpha", "beta", "gamma"].map(String::from).to_vec();
        let actuals = namespaces
            .iter()
            .map(|ns| (ns.clone(), GatewayConfig::default()))
            .collect();
        let extras = namespaces
            .iter()
            .map(|ns| {
                let body = serde_json::json!({
                    "version": "1", "ferrum_version": "fixture", "exported_at": "fixture",
                    "source": "database", "proxies": [], "consumers": [], "upstreams": [],
                    "plugin_configs": [], "api_specs": {"section_version": "2", "items": []},
                    "gateway_trust_bundles": [],
                    "counts": {"proxies": 0, "consumers": 0, "upstreams": 0,
                        "plugin_configs": 0, "api_specs": 0, "gateway_trust_bundles": 0},
                    "conditional": {"namespace_etag": "\"original\"", "row_etags": {
                        "proxies": {}, "consumers": {}, "upstreams": {}, "plugin_configs": {}}}
                });
                let snapshot = crate::http_client::conditional::conditional_backup(
                    &body.to_string(),
                    ns,
                    Some("\"original\""),
                    None,
                    Some("no-store"),
                )
                .unwrap();
                (ns.clone(), snapshot.extras)
            })
            .collect();
        let options = ApplyOptions {
            strategy: ApplyStrategy::FullReplace,
            ..Default::default()
        };
        let mut prepared = prepare_apply(
            &desired,
            &client,
            &namespaces,
            OwnershipScope::Exclusive,
            Some(&actuals),
            Some(&extras),
            &options,
            true,
        )
        .await
        .unwrap();
        assert_eq!(prepared.full_replaces.len(), 3);
        assert!(prepared.full_replaces.remove("beta").is_some());
        let server = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(10), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut byte = [0_u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                let headers = String::from_utf8(request).unwrap();
                assert!(headers.starts_with("POST /restore?confirm=true "));
                assert!(headers.contains("x-ferrum-namespace: alpha\r\n"));
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .map(|value| value.parse().unwrap())
                    })
                    .unwrap();
                stream.read_exact(&mut vec![0_u8; length]).await.unwrap();
                let body = r#"{"restored":{"proxies":0,"consumers":0,"upstreams":1,"plugin_configs":0,"api_specs":0,"gateway_trust_bundles":0}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            })
            .await
            .expect("restore fixture did not receive its complete request");
        });
        let result = apply_prepared(
            &desired,
            &client,
            &namespaces,
            OwnershipScope::Exclusive,
            &prepared,
            &options,
        )
        .await;
        server.await.unwrap();
        assert_eq!(result.created, 1);
        assert_eq!(result.fully_replaced_namespaces, vec!["alpha"]);
        assert!(result.applied_incremental.is_empty());
        assert!(result.errors.is_empty());
        assert!(result
            .fatal_error
            .as_ref()
            .unwrap()
            .contains("`beta` was not prebuilt"));
        // Replay the same ledger boundary cmd_apply uses before returning its
        // deferred failure. The previous fully-applied stamp must survive.
        let mut state = crate::state::StateFile {
            last_applied_commit: Some("previous-complete-commit".into()),
            ..Default::default()
        };
        for namespace in &result.fully_replaced_namespaces {
            state.record_full_replace(namespace, &desired);
        }
        let outcome = result.into_result();
        state.stamp_last_applied_if_clean(outcome.is_ok());
        assert!(outcome.unwrap_err().to_string().contains("Apply stopped"));
        assert!(state
            .resources
            .contains_key(&state_key("alpha", "Upstream", "u1")));
        assert_eq!(state.resources.len(), 1);
        assert_eq!(
            state.last_applied_commit.as_deref(),
            Some("previous-complete-commit")
        );
    }
}

impl std::fmt::Debug for PreparedApply<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedApply(<redacted>)")
    }
}

impl std::fmt::Debug for PreparedFullReplace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedFullReplace(<redacted>)")
    }
}
