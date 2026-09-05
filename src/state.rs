use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::GatewayConfig;
use crate::diff::resource_diff::{state_key, state_key_namespace};

pub const STATE_DIR: &str = ".state";
const STATE_VERSION: u32 = 3;
const MIN_SUPPORTED_STATE_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialMetadata {
    pub slot: String,
    pub shard: u32,
    pub last_rotated: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OverrideRecord {
    pub rule_id: String,
    pub commit: String,
    pub approver: String,
    pub recorded_at: String,
}

/// Per-environment state file at `.state/<env>.json`. Written by apply +
/// rotate; read by all commands that need to distinguish managed vs
/// unmanaged gateway resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u32,
    pub environment: String,
    pub last_applied_at: Option<String>,
    pub last_applied_commit: Option<String>,
    pub resources: HashMap<String, String>,
    /// Creates durably announced before their non-idempotent POST, but not yet
    /// proven to have landed. These keys are deliberately *not* part of the
    /// shared-mode delete fence: a crashed request must not grant deletion
    /// authority over a row that an administrator may have created later.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pending_creates: BTreeSet<String>,
    #[serde(default)]
    pub credentials: HashMap<String, CredentialMetadata>,
    #[serde(default = "default_shard_count")]
    pub credential_shard_count: u32,
    #[serde(default)]
    pub overrides: Vec<OverrideRecord>,
}

#[derive(Debug)]
pub struct StateLock {
    path: PathBuf,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn default_shard_count() -> u32 {
    1
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            environment: "default".to_string(),
            last_applied_at: None,
            last_applied_commit: None,
            resources: HashMap::new(),
            pending_creates: BTreeSet::new(),
            credentials: HashMap::new(),
            credential_shard_count: default_shard_count(),
            overrides: Vec::new(),
        }
    }
}

impl StateFile {
    pub fn path_for(environment: &str) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{environment}.json"))
    }

    pub fn lock(environment: &str) -> crate::error::Result<StateLock> {
        std::fs::create_dir_all(STATE_DIR)?;
        let path = Path::new(STATE_DIR).join(format!("{environment}.lock"));
        // This lock is deliberately fail-closed: a crashed process can leave a
        // stale file behind, and operators must remove it after inspecting the
        // recorded PID/time. Automatic stale detection is unreliable across CI
        // runners and could permit overlapping read-modify-write applies.
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(crate::error::Error::Config(format!(
                    "state file for environment '{environment}' is locked by another gitforgeops process; wait for it to finish or remove {} if the prior process crashed",
                    path.display()
                )));
            }
            Err(source) => return Err(crate::error::Error::Io(source)),
        };

        if let Err(source) = writeln!(
            file,
            "pid={}\ncreated_at={}",
            std::process::id(),
            chrono::Utc::now().to_rfc3339()
        ) {
            let _ = std::fs::remove_file(&path);
            return Err(crate::error::Error::Io(source));
        }
        Ok(StateLock { path })
    }

    pub fn load(environment: &str) -> crate::error::Result<Self> {
        let path = Self::path_for(environment);
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    environment: environment.to_string(),
                    ..Self::default()
                });
            }
            Err(source) => return Err(crate::error::Error::FileRead { path, source }),
        };

        let mut state = serde_json::from_str::<Self>(&contents)
            .map_err(|source| crate::error::Error::StateParse { path, source })?;
        if !(MIN_SUPPORTED_STATE_VERSION..=STATE_VERSION).contains(&state.version) {
            return Err(crate::error::Error::Config(format!(
                "state file for environment '{environment}' has unsupported version {}; this build accepts versions {MIN_SUPPORTED_STATE_VERSION} through {STATE_VERSION}",
                state.version
            )));
        }
        // Normalize environment to the requested name so save() always targets
        // the correct `.state/<env>.json` file, regardless of what the on-disk
        // field says.
        state.environment = environment.to_string();
        // State v2 stored unkeyed hashes of complete resources (including
        // resolved Consumer credentials). Reconciliation has always consumed
        // only the map keys, so normalize the unused values in memory and let
        // the next ordinary save remove those offline verification oracles.
        state.version = STATE_VERSION;
        for marker in state.resources.values_mut() {
            *marker = managed_resource_marker();
        }
        state.validate_resource_keys()?;
        Ok(state)
    }

    fn validate_resource_keys(&self) -> crate::error::Result<()> {
        for key in self.resources.keys().chain(self.pending_creates.iter()) {
            if state_key_namespace(key).is_none() {
                return Err(crate::error::Error::Config(format!(
                    "state file contains invalid resource key {key:?}; expected __gitforgeops_state_key_v2:<namespace>:<kind>:<id>"
                )));
            }
        }
        Ok(())
    }

    pub fn save(&self) -> crate::error::Result<()> {
        self.validate_resource_keys()?;
        std::fs::create_dir_all(STATE_DIR)?;
        let path = Self::path_for(&self.environment);
        let tmp_path = path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        // Serialize a sanitized copy even when a library caller constructed a
        // StateFile directly. Loaded v2 files are normalized in load(), but
        // save() is the final boundary that guarantees no legacy resource hash
        // can be committed as public state.
        let mut public_state = self.clone();
        public_state.version = STATE_VERSION;
        for marker in public_state.resources.values_mut() {
            *marker = managed_resource_marker();
        }
        let json = serde_json::to_string_pretty(&public_state)?;

        let write_result = (|| -> crate::error::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp_path, &path)?;
            if let Ok(dir) = std::fs::File::open(STATE_DIR) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();

        if write_result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        write_result
    }

    /// True when this appears to be the first apply for this environment: no
    /// prior state on disk. Used to decide whether `shared` ownership needs
    /// a bootstrap warning.
    pub fn is_first_apply(environment: &str) -> bool {
        !Self::path_for(environment).exists()
    }

    /// Rewrite the `resources` map with a non-secret ownership marker for every resource in
    /// `config`, but only for keys whose namespace falls within
    /// `scope_namespaces`. Entries outside that scope are preserved.
    ///
    /// This matters when a scoped apply (e.g. `FERRUM_NAMESPACE=ferrum` on a
    /// shared-mode env) narrows `config` to just one namespace. Clearing the
    /// whole map would drop managed-resource keys for every OTHER namespace
    /// the repo tracks — the next shared-mode diff would then classify those
    /// resources as unmanaged and stop issuing deletes/drift alerts for
    /// removals, silently breaking ownership tracking after a routine
    /// scoped apply.
    pub fn record(&mut self, config: &GatewayConfig, scope_namespaces: &[String]) {
        use std::collections::HashSet;
        let scope: HashSet<&str> = scope_namespaces.iter().map(String::as_str).collect();

        // Drop only the entries for namespaces we're reconciling right now;
        // everything else stays as the last apply recorded it.
        self.resources.retain(|key, _| {
            state_key_namespace(key)
                .map(|ns| !scope.contains(ns.as_str()))
                .unwrap_or(false)
        });
        self.pending_creates.retain(|key| {
            state_key_namespace(key)
                .map(|ns| !scope.contains(ns.as_str()))
                .unwrap_or(false)
        });

        for proxy in &config.proxies {
            if !scope.contains(proxy.namespace.as_str()) {
                continue;
            }
            let key = state_key(&proxy.namespace, "Proxy", &proxy.id);
            self.resources.insert(key, managed_resource_marker());
        }
        for consumer in &config.consumers {
            if !scope.contains(consumer.namespace.as_str()) {
                continue;
            }
            let key = state_key(&consumer.namespace, "Consumer", &consumer.id);
            self.resources.insert(key, managed_resource_marker());
        }
        for upstream in &config.upstreams {
            if !scope.contains(upstream.namespace.as_str()) {
                continue;
            }
            let key = state_key(&upstream.namespace, "Upstream", &upstream.id);
            self.resources.insert(key, managed_resource_marker());
        }
        for pc in &config.plugin_configs {
            if !scope.contains(pc.namespace.as_str()) {
                continue;
            }
            let key = state_key(&pc.namespace, "PluginConfig", &pc.id);
            self.resources.insert(key, managed_resource_marker());
        }

        self.last_applied_at = Some(chrono::Utc::now().to_rfc3339());
        self.last_applied_commit = git_rev_parse_head();
    }

    /// Apply a single successful per-resource operation to `resources`.
    ///
    /// Use this for partial-failure-safe state updates: cmd_apply iterates
    /// `ApplyResult::applied_incremental` and calls this for each Op,
    /// leaving failed-op entries untouched. Critical for shared mode: a
    /// failed Delete must NOT remove its key from state, or the next run
    /// classifies the still-live resource as unmanaged and stops retrying
    /// deletion. Add/Modify prove the resource still exists in `desired` and
    /// store a non-secret ownership marker; Delete removes the key.
    /// Out-of-scope entries are never touched here.
    pub fn record_op(
        &mut self,
        op: &crate::apply::AppliedOp,
        desired: &GatewayConfig,
    ) -> crate::error::Result<()> {
        use crate::diff::resource_diff::DiffAction;
        let key = state_key(&op.namespace, &op.kind, &op.id);

        match op.action {
            DiffAction::Delete => {
                self.resources.remove(&key);
                self.pending_creates.remove(&key);
            }
            DiffAction::Add | DiffAction::Modify => {
                let exists = match op.kind.as_str() {
                    "Proxy" => desired
                        .proxies
                        .iter()
                        .find(|p| p.namespace == op.namespace && p.id == op.id)
                        .is_some(),
                    "Consumer" => desired
                        .consumers
                        .iter()
                        .find(|c| c.namespace == op.namespace && c.id == op.id)
                        .is_some(),
                    "Upstream" => desired
                        .upstreams
                        .iter()
                        .find(|u| u.namespace == op.namespace && u.id == op.id)
                        .is_some(),
                    "PluginConfig" => desired
                        .plugin_configs
                        .iter()
                        .find(|p| p.namespace == op.namespace && p.id == op.id)
                        .is_some(),
                    _ => false,
                };
                if exists {
                    self.resources
                        .insert(key.clone(), managed_resource_marker());
                    self.pending_creates.remove(&key);
                }
            }
        }
        Ok(())
    }

    /// Durably journal resources this run is about to create.
    ///
    /// The caller saves these reservations immediately before the first API
    /// mutation. A pending key is not ownership: it stays outside `resources`
    /// and therefore outside the shared-mode delete fence. On the next run,
    /// [`Self::reconcile_pending_creates`] keeps it pending until an
    /// idempotent update explicitly asserts repository ownership.
    /// Existing Modify/Delete ownership is already present and is intentionally
    /// left untouched until those operations succeed.
    pub fn reserve_adds(
        &mut self,
        diffs: &[crate::diff::resource_diff::ResourceDiff],
        desired: &GatewayConfig,
    ) -> crate::error::Result<usize> {
        use crate::diff::resource_diff::DiffAction;

        let mut reserved = 0;
        for diff in diffs
            .iter()
            .filter(|diff| matches!(diff.action, DiffAction::Add))
        {
            let key = state_key(&diff.namespace, &diff.kind, &diff.id);
            if !resource_exists(desired, &key) {
                return Err(crate::error::Error::Config(format!(
                    "cannot journal create for {} `{}` in namespace `{}` because it is absent from the desired configuration",
                    diff.kind, diff.id, diff.namespace
                )));
            }
            if !self.resources.contains_key(&key) && self.pending_creates.insert(key) {
                reserved += 1;
            }
        }
        Ok(reserved)
    }

    /// Reconcile write-ahead create records against an authoritative backup.
    ///
    /// Exact current desired/live equality is intentionally *not* enough to
    /// claim ownership: an administrator could have created the same row while
    /// our POST outcome was unknown. The pending key stays journaled so the
    /// apply target can issue an idempotent PUT and record ownership only after
    /// that explicit assertion succeeds. A row absent from both desired and
    /// live can be forgotten.
    ///
    /// The awkward case is a live row whose desired declaration disappeared.
    /// Its provenance is genuinely unknowable, but refusing to reconcile is
    /// the one response that must never be chosen: the journal is written by
    /// CI before the first POST and read by CI on the next run, so a hard
    /// error there wedges the environment until somebody hand-edits
    /// `.state/<env>.json` — which `state-guard.yml` exists to prevent. Every
    /// resolution below therefore drops the key and lets the *ordinary*
    /// ownership rules decide the row's fate:
    ///
    /// - [`PendingCreateScope::Shared`] — the row is not in `resources`, so
    ///   dropping the key leaves it outside the delete fence and it is
    ///   reported as unmanaged. It is never deleted. A warning names it,
    ///   because "gitforgeops may have created this and then forgot" is
    ///   exactly the kind of orphan an operator has to look at.
    /// - [`PendingCreateScope::Exclusive`] — the repo is authoritative for the
    ///   namespace, so the row is an ordinary prune candidate and the
    ///   large-prune guard applies to it like any other.
    /// - [`PendingCreateScope::FullReplace`] — `/restore` replaces the whole
    ///   namespace atomically; the journal has no say in what survives.
    ///
    /// Returns the keys that were forgotten and the warnings to surface.
    pub fn reconcile_pending_creates(
        &mut self,
        desired: &GatewayConfig,
        actual_by_namespace: &BTreeMap<String, GatewayConfig>,
        scope: PendingCreateScope,
    ) -> PendingCreateReconciliation {
        let pending = self.pending_creates.iter().cloned().collect::<Vec<_>>();
        let mut report = PendingCreateReconciliation::default();

        for key in pending {
            if self.resources.contains_key(&key) {
                self.pending_creates.remove(&key);
                report.forgotten += 1;
                continue;
            }

            // `validate_resource_keys()` rejects this shape on load and save,
            // so it should be unreachable. Drop it rather than erroring: a
            // journal entry nothing can parse is not a reason to refuse every
            // future apply.
            let Some(namespace) = state_key_namespace(&key) else {
                self.pending_creates.remove(&key);
                report.forgotten += 1;
                report.warnings.push(format!(
                    "dropped unparseable pending-create key {key:?} from the state journal"
                ));
                continue;
            };
            let Some(actual) = actual_by_namespace.get(&namespace) else {
                // A namespace filter can intentionally leave pending entries
                // outside this invocation's authoritative read scope.
                continue;
            };

            // Full replacement does not consult the journal at all, and the
            // restore is authoritative for every row in the namespace.
            if scope == PendingCreateScope::FullReplace {
                self.pending_creates.remove(&key);
                report.forgotten += 1;
                continue;
            }

            let desired_exists = resource_exists(desired, &key);
            let live_exists = resource_exists(actual, &key);
            match (desired_exists, live_exists) {
                (true, _) => {
                    // Still desired: keep the journal entry. An absent or
                    // different row takes the ordinary Add/Modify path; an
                    // exact row gets a synthetic idempotent Modify assertion.
                    // Either enters the managed fence only after success.
                }
                (false, false) => {
                    self.pending_creates.remove(&key);
                    report.forgotten += 1;
                }
                (false, true) => {
                    self.pending_creates.remove(&key);
                    report.forgotten += 1;
                    report.warnings.push(match scope {
                        PendingCreateScope::Shared => format!(
                            "pending create {key:?} names a row that is live on the gateway but no longer declared in this repository. Its provenance cannot be proven, so it is being forgotten and reported as UNMANAGED — gitforgeops will not delete it. If this repository created it, remove it through the gateway admin API by hand."
                        ),
                        PendingCreateScope::Exclusive => format!(
                            "pending create {key:?} names a row that is live on the gateway but no longer declared in this repository. Forgetting the journal entry; exclusive ownership means the ordinary prune path (and the large-prune guard) now decides its fate."
                        ),
                        // Handled above.
                        PendingCreateScope::FullReplace => format!(
                            "pending create {key:?} was forgotten before a full replacement of namespace `{namespace}`."
                        ),
                    });
                }
            }
        }

        report
    }

    /// Remove managed-ledger entries that an authoritative backup proves are
    /// absent both from the repository and the gateway.
    ///
    /// Without this garbage collection, externally deleted rows remain in the
    /// large-prune denominator forever and can dilute a later destructive
    /// change. Entries outside the current namespace read scope are untouched.
    pub fn reconcile_absent_managed_resources(
        &mut self,
        desired: &GatewayConfig,
        actual_by_namespace: &BTreeMap<String, GatewayConfig>,
    ) -> usize {
        let before = self.resources.len();
        self.resources.retain(|key, _| {
            let Some(namespace) = state_key_namespace(key) else {
                // Loading/saving rejects malformed keys. Retain defensively so
                // this maintenance pass never turns corruption into deletion.
                return true;
            };
            let Some(actual) = actual_by_namespace.get(&namespace) else {
                return true;
            };
            resource_exists(desired, key) || resource_exists(actual, key)
        });
        before.saturating_sub(self.resources.len())
    }

    /// Drop all `resources` entries in `namespace` and rebuild from `desired`.
    /// Use only after a successful `apply_full_replace` for that namespace —
    /// /restore is atomic, so on success the namespace's live state is
    /// authoritative and equals `desired`.
    pub fn record_full_replace(&mut self, namespace: &str, desired: &GatewayConfig) {
        self.resources.retain(|key, _| {
            state_key_namespace(key)
                .map(|ns| ns != namespace)
                .unwrap_or(false)
        });
        self.pending_creates.retain(|key| {
            state_key_namespace(key)
                .map(|ns| ns != namespace)
                .unwrap_or(false)
        });
        for p in desired.proxies.iter().filter(|p| p.namespace == namespace) {
            self.resources.insert(
                state_key(&p.namespace, "Proxy", &p.id),
                managed_resource_marker(),
            );
        }
        for c in desired
            .consumers
            .iter()
            .filter(|c| c.namespace == namespace)
        {
            self.resources.insert(
                state_key(&c.namespace, "Consumer", &c.id),
                managed_resource_marker(),
            );
        }
        for u in desired
            .upstreams
            .iter()
            .filter(|u| u.namespace == namespace)
        {
            self.resources.insert(
                state_key(&u.namespace, "Upstream", &u.id),
                managed_resource_marker(),
            );
        }
        for p in desired
            .plugin_configs
            .iter()
            .filter(|p| p.namespace == namespace)
        {
            self.resources.insert(
                state_key(&p.namespace, "PluginConfig", &p.id),
                managed_resource_marker(),
            );
        }
    }

    /// Stamp last_applied_* metadata. Call after recording per-op or
    /// full-replace results, so the timestamp reflects the latest run
    /// regardless of which code path updated `resources`.
    pub fn stamp_last_applied(&mut self) {
        self.last_applied_at = Some(chrono::Utc::now().to_rfc3339());
        self.last_applied_commit = git_rev_parse_head();
    }

    /// Stamp completion metadata only when the aggregate apply converged
    /// cleanly. Successful per-resource ownership updates are still persisted
    /// after a partial run, but `last_applied_*` must continue to identify the
    /// most recent commit that landed in full.
    pub fn stamp_last_applied_if_clean(&mut self, apply_succeeded: bool) {
        if apply_succeeded {
            self.stamp_last_applied();
        }
    }

    pub fn record_credential(
        &mut self,
        slot: &str,
        shard: u32,
        delivered_to: Option<&str>,
        delivered_run_id: Option<&str>,
    ) {
        self.credentials.insert(
            slot.to_string(),
            CredentialMetadata {
                slot: slot.to_string(),
                shard,
                last_rotated: chrono::Utc::now().to_rfc3339(),
                delivered_to: delivered_to.map(str::to_string),
                delivered_run_id: delivered_run_id.map(str::to_string),
            },
        );
    }

    pub fn record_override(&mut self, rule_id: &str, commit: &str, approver: &str) {
        self.overrides.push(OverrideRecord {
            rule_id: rule_id.to_string(),
            commit: commit.to_string(),
            approver: approver.to_string(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn previously_managed_keys(&self) -> std::collections::HashSet<String> {
        self.resources.keys().cloned().collect()
    }
}

/// Which ownership rules apply to a run reconciling its pending-create journal.
///
/// The journal never decides an outcome on its own; it only says which of the
/// ordinary rules a forgotten row falls back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingCreateScope {
    /// Shared ownership: an undeclared live row is unmanaged and untouchable.
    Shared,
    /// Exclusive ownership: an undeclared live row is an ordinary prune
    /// candidate, subject to the large-prune guard.
    Exclusive,
    /// `full_replace`: `/restore` is authoritative for the whole namespace.
    FullReplace,
}

/// Outcome of [`StateFile::reconcile_pending_creates`].
#[derive(Debug, Default)]
pub struct PendingCreateReconciliation {
    /// Journal entries removed by this pass.
    pub forgotten: usize,
    /// Operator-facing lines about rows whose provenance could not be proven.
    pub warnings: Vec<String>,
}

impl PendingCreateReconciliation {
    pub fn changed(&self) -> bool {
        self.forgotten > 0
    }
}

fn resource_exists(config: &GatewayConfig, key: &str) -> bool {
    config
        .proxies
        .iter()
        .any(|resource| state_key(&resource.namespace, "Proxy", &resource.id) == key)
        || config
            .consumers
            .iter()
            .any(|resource| state_key(&resource.namespace, "Consumer", &resource.id) == key)
        || config
            .upstreams
            .iter()
            .any(|resource| state_key(&resource.namespace, "Upstream", &resource.id) == key)
        || config
            .plugin_configs
            .iter()
            .any(|resource| state_key(&resource.namespace, "PluginConfig", &resource.id) == key)
}

fn managed_resource_marker() -> String {
    // Only the key participates in ownership reconciliation. Retain a stable
    // value for backwards-compatible JSON shape without hashing resource
    // content (which can include resolved credentials).
    "managed:v1".to_string()
}

fn git_rev_parse_head() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
