use std::collections::HashSet;

use crate::config::schema::GatewayConfig;
use crate::config::ApplyStrategy;
use crate::diff::resource_diff::{compute_diff_with_ownership, DiffAction, DiffResult};
use crate::http_client::AdminClient;

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

/// Apply configuration to the gateway via the admin API.
///
/// Iterates `namespaces` explicitly rather than inferring them from `desired`.
/// This matters for `exclusive` ownership: a namespace the repo manages but no
/// longer declares resources in still needs to be reconciled (to prune the
/// resources that were removed). The caller decides the scope (typically
/// `ownership.namespaces` for exclusive, or the namespaces present in
/// `desired` for shared).
///
/// When `previously_managed` is `Some`, runs in `shared` ownership mode: only
/// resources present in that set can be deleted; admin-added resources are
/// reported in `unmanaged_skipped` but not touched.
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
    strategy: ApplyStrategy,
    namespaces: &[String],
    previously_managed: Option<&HashSet<String>>,
) -> crate::error::Result<ApplyResult> {
    let mut aggregate = ApplyResult::default();

    for namespace in namespaces {
        let desired_namespace = crate::config::filter_config_by_namespace(desired, namespace);
        let namespace_result = match strategy {
            ApplyStrategy::FullReplace => {
                // Record-and-continue on error so a multi-namespace restore
                // reports every failing namespace, not just the first. The
                // gateway's `/restore` is already atomic per-namespace, so
                // a failure here doesn't cascade into the next namespace;
                // the worst case is that namespaces 0..N restored and
                // namespace N failed, which operators see in the aggregate
                // error listing.
                match apply_full_replace(&desired_namespace, client, namespace).await {
                    Ok(r) => r,
                    Err(e) => {
                        aggregate.errors.push(format!("[{namespace}] {e}"));
                        continue;
                    }
                }
            }
            ApplyStrategy::Incremental => {
                match apply_incremental(&desired_namespace, client, namespace, previously_managed)
                    .await
                {
                    Ok(r) => r,
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

async fn apply_full_replace(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespace: &str,
) -> crate::error::Result<ApplyResult> {
    client.post_restore(desired, namespace).await?;
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
    previously_managed: Option<&HashSet<String>>,
) -> crate::error::Result<ApplyResult> {
    let actual = client.get_backup(namespace).await?;
    let DiffResult { diffs, unmanaged } =
        compute_diff_with_ownership(desired, &actual, previously_managed);

    let mut result = ApplyResult {
        unmanaged_skipped: unmanaged.len(),
        ..Default::default()
    };

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
