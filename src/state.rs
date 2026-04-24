use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::GatewayConfig;

pub const STATE_DIR: &str = ".state";
pub const LEGACY_STATE_FILE: &str = ".state/state.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialMetadata {
    pub slot: String,
    pub shard: u32,
    pub last_rotated: String,
    pub sha256_prefix: String,
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

// All fields carry serde defaults so v1 `.state/state.json` files — which
// predate `environment`, `credentials`, `credential_bundle_versions`,
// `credential_shard_count`, and `overrides` — deserialize cleanly into the
// v2 struct during the legacy migration path in `load()`. The caller patches
// `environment` after load, so its default ("") is never observable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub last_applied_at: Option<String>,
    #[serde(default)]
    pub last_applied_commit: Option<String>,
    #[serde(default)]
    pub resources: HashMap<String, String>,
    #[serde(default)]
    pub credentials: HashMap<String, CredentialMetadata>,
    #[serde(default)]
    pub credential_bundle_versions: HashMap<String, String>,
    #[serde(default = "default_shard_count")]
    pub credential_shard_count: u32,
    #[serde(default)]
    pub overrides: Vec<OverrideRecord>,
}

fn default_version() -> u32 {
    2
}

fn default_shard_count() -> u32 {
    1
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: 2,
            environment: "default".to_string(),
            last_applied_at: None,
            last_applied_commit: None,
            resources: HashMap::new(),
            credentials: HashMap::new(),
            credential_bundle_versions: HashMap::new(),
            credential_shard_count: 1,
            overrides: Vec::new(),
        }
    }
}

impl StateFile {
    pub fn path_for(environment: &str) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{environment}.json"))
    }

    pub fn load(environment: &str) -> Self {
        let path = Self::path_for(environment);
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(state) = serde_json::from_str::<Self>(&contents) {
                    return state;
                }
            }
        }

        // Legacy migration: atomically rename `.state/state.json` into this
        // environment's state file so the legacy content is adopted by
        // exactly ONE environment. Without the rename, every env whose
        // specific file didn't yet exist would inherit the same legacy
        // `resources` set — shared-mode diffs would then double-count
        // every resource as "managed by me" and apply could delete
        // resources in the wrong environment on first multi-env rollout.
        //
        // Rename is atomic on POSIX within a filesystem. Whichever env
        // calls load() first wins; concurrent calls see the legacy file
        // already gone and fall through to default state. Operators can
        // inspect the audit log (loud notice below) and, if the wrong env
        // adopted, restore from git history and re-name manually.
        let legacy = Path::new(LEGACY_STATE_FILE);
        if legacy.exists() {
            let _ = std::fs::create_dir_all(STATE_DIR);
            if std::fs::rename(legacy, &path).is_ok() {
                eprintln!(
                    "Notice: migrated legacy .state/state.json -> .state/{environment}.json \
                     (this is a one-time operation). If '{environment}' is not the environment \
                     the legacy state represented, restore from git history and rename manually \
                     before the next apply."
                );
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    if let Ok(mut state) = serde_json::from_str::<Self>(&contents) {
                        state.environment = environment.to_string();
                        state.version = 2;
                        return state;
                    }
                }
            }
            // Rename failed — either legacy is gone (another env won the
            // race) or the target already exists. Either way, fall through
            // and retry reading `path` if it now exists.
            if path.exists() {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    if let Ok(state) = serde_json::from_str::<Self>(&contents) {
                        return state;
                    }
                }
            }
        }

        Self {
            environment: environment.to_string(),
            ..Self::default()
        }
    }

    pub fn save(&self) -> crate::error::Result<()> {
        std::fs::create_dir_all(STATE_DIR)?;
        let path = Self::path_for(&self.environment);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// True when this appears to be the first apply for this environment: no
    /// prior state on disk at all. Used to decide whether `shared` ownership
    /// needs a bootstrap warning.
    pub fn is_first_apply(environment: &str) -> bool {
        let path = Self::path_for(environment);
        !path.exists() && !Path::new(LEGACY_STATE_FILE).exists()
    }

    pub fn record(&mut self, config: &GatewayConfig) {
        self.resources.clear();

        for proxy in &config.proxies {
            let key = format!("{}:Proxy:{}", proxy.namespace, proxy.id);
            self.resources.insert(key, hash_resource(proxy));
        }
        for consumer in &config.consumers {
            let key = format!("{}:Consumer:{}", consumer.namespace, consumer.id);
            self.resources.insert(key, hash_resource(consumer));
        }
        for upstream in &config.upstreams {
            let key = format!("{}:Upstream:{}", upstream.namespace, upstream.id);
            self.resources.insert(key, hash_resource(upstream));
        }
        for pc in &config.plugin_configs {
            let key = format!("{}:PluginConfig:{}", pc.namespace, pc.id);
            self.resources.insert(key, hash_resource(pc));
        }

        self.last_applied_at = Some(chrono::Utc::now().to_rfc3339());
        self.last_applied_commit = git_rev_parse_head();
    }

    pub fn record_credential(
        &mut self,
        slot: &str,
        shard: u32,
        value: &str,
        delivered_to: Option<&str>,
        delivered_run_id: Option<&str>,
    ) {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let full = format!("{:x}", hasher.finalize());
        let prefix = full.chars().take(16).collect();
        self.credentials.insert(
            slot.to_string(),
            CredentialMetadata {
                slot: slot.to_string(),
                shard,
                last_rotated: chrono::Utc::now().to_rfc3339(),
                sha256_prefix: prefix,
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

fn hash_resource<T: serde::Serialize>(resource: &T) -> String {
    // Serialize through `serde_json::Value` first: direct `to_string` on a
    // struct iterates `HashMap` fields (e.g. `Consumer.credentials`,
    // `UpstreamTarget.tags`) in random order, producing different hashes
    // across runs for the same resource. `serde_json::Map` is backed by
    // `BTreeMap` (no `preserve_order` feature), so going through `Value`
    // yields sorted, deterministic output.
    let value = serde_json::to_value(resource).unwrap_or(serde_json::Value::Null);
    let canonical = serde_json::to_string(&value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn git_rev_parse_head() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
