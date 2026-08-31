//! Which namespaces a single command invocation reconciles, and which
//! resources inside them the repo is allowed to touch.
//!
//! Both answers key off `.state/<env>.json`, so both live here next to the
//! trust boundary they encode. See the "State file trust model" section in
//! `README.md`: the state file is CI-authored (written and pushed by
//! `apply-on-merge.yml` / `rotate.yml`) and PR-authored changes to `.state/`
//! are rejected by `state-guard.yml`. Everything below assumes that fence
//! holds — a state file an attacker can rewrite can already forge managed
//! entries for live resources and get them deleted on the next apply,
//! whatever this module does with namespaces.

use std::collections::{BTreeSet, HashSet};

use crate::config::{collect_namespaces, GatewayConfig, OwnershipMode, ResolvedEnv};
use crate::diff::resource_diff::state_key_namespace;
use crate::state::StateFile;

/// The namespace list every command iterates for diff/plan/review/apply.
pub fn resolved_namespaces(
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
                //
                // The state-derived half of this union expands only the set of
                // namespaces *looked at*, never what may be deleted inside
                // them: `previously_managed` fences every shared-mode delete
                // to keys the state file already lists, so a namespace that
                // arrives here from state can only ever yield deletes of rows
                // that same file claims the repo applied.
                let mut set: BTreeSet<String> = collect_namespaces(desired).into_iter().collect();
                for key in state.resources.keys().chain(state.pending_creates.iter()) {
                    if let Some(ns) = state_key_namespace(key) {
                        set.insert(ns);
                    }
                }
                set.into_iter().collect()
            }
        },
    }
}

/// The delete fence for shared mode: `Some(keys)` restricts deletes to
/// resources this repo previously applied. `None` (exclusive) means the repo
/// is authoritative for its namespaces and unmanaged rows may be pruned.
pub fn previously_managed(resolved: &ResolvedEnv, state: &StateFile) -> Option<HashSet<String>> {
    match resolved.ownership.mode {
        OwnershipMode::Shared => Some(state.previously_managed_keys()),
        OwnershipMode::Exclusive => None,
    }
}
