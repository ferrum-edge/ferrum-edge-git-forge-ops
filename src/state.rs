use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::GatewayConfig;

const STATE_DIR: &str = ".state";
const STATE_FILE: &str = ".state/state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFile {
    pub version: u32,
    pub last_applied_at: Option<String>,
    pub last_applied_commit: Option<String>,
    pub resources: HashMap<String, String>,
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: 1,
            last_applied_at: None,
            last_applied_commit: None,
            resources: HashMap::new(),
        }
    }
}

impl StateFile {
    pub fn load() -> Self {
        let path = Path::new(STATE_FILE);
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> crate::error::Result<()> {
        std::fs::create_dir_all(STATE_DIR)?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(STATE_FILE, json)?;
        Ok(())
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
