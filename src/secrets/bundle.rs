use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// The maximum bytes we will pack into a single bundle before splitting to a
/// new shard. GitHub's hard limit is 48 KB; we stay under at 40 KB so reads
/// and writes always have headroom.
pub const BUNDLE_SOFT_LIMIT_BYTES: usize = 40 * 1024;

pub const BUNDLE_SECRET_PREFIX: &str = "FERRUM_CREDS_BUNDLE";

/// A single shard's credential map. Keys are slot paths
/// (`<namespace>/<id>/<cred_key>`), values are plaintext secret material.
pub type CredentialBundle = BTreeMap<String, String>;

/// Parse `FERRUM_CREDS_JSON` (a JSON object of `{ "BUNDLE_0": {...}, "BUNDLE_1": {...} }`)
/// loaded by the workflow into a merged map and a per-shard map.
///
/// Returns `(merged, per_shard)`. The `merged` map is flat (`slot → value`) for
/// resolution. The `per_shard` map keeps the original shard structure for
/// read-modify-write operations during allocation/rotation.
pub fn load_bundles_from_env(
    raw: &str,
) -> crate::error::Result<(CredentialBundle, BTreeMap<u32, CredentialBundle>)> {
    let outer: serde_json::Value = serde_json::from_str(raw)?;
    let obj = outer.as_object().ok_or_else(|| {
        crate::error::Error::Config("FERRUM_CREDS_JSON is not a JSON object".to_string())
    })?;

    let mut per_shard: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
    let mut merged: CredentialBundle = BTreeMap::new();

    for (secret_name, secret_value) in obj {
        let shard_idx = match parse_shard_index(secret_name) {
            Some(n) => n,
            None => continue,
        };
        let inner: CredentialBundle = match secret_value {
            serde_json::Value::String(s) if s.is_empty() => BTreeMap::new(),
            serde_json::Value::String(s) => serde_json::from_str(s).map_err(|e| {
                crate::error::Error::Config(format!(
                    "shard {secret_name}: malformed JSON value: {e}"
                ))
            })?,
            serde_json::Value::Object(_) => serde_json::from_value(secret_value.clone())?,
            _ => {
                return Err(crate::error::Error::Config(format!(
                    "shard {secret_name}: unexpected value type (need object or JSON string)"
                )))
            }
        };

        for (slot, value) in &inner {
            merged.insert(slot.clone(), value.clone());
        }
        per_shard.insert(shard_idx, inner);
    }

    Ok((merged, per_shard))
}

fn parse_shard_index(secret_name: &str) -> Option<u32> {
    if secret_name == BUNDLE_SECRET_PREFIX {
        return Some(0);
    }
    let suffix = secret_name.strip_prefix(&format!("{BUNDLE_SECRET_PREFIX}_"))?;
    suffix.parse().ok()
}

pub fn shard_secret_name(shard: u32) -> String {
    if shard == 0 {
        BUNDLE_SECRET_PREFIX.to_string()
    } else {
        format!("{BUNDLE_SECRET_PREFIX}_{shard}")
    }
}

pub fn merge_bundles(shards: &BTreeMap<u32, CredentialBundle>) -> CredentialBundle {
    let mut merged = BTreeMap::new();
    for bundle in shards.values() {
        for (slot, value) in bundle {
            merged.insert(slot.clone(), value.clone());
        }
    }
    merged
}

pub fn serialize_bundle(bundle: &CredentialBundle) -> crate::error::Result<String> {
    serde_json::to_string(bundle).map_err(crate::error::Error::SerdeJson)
}

pub fn bundle_hash(bundle: &CredentialBundle) -> String {
    let mut hasher = Sha256::new();
    let serialized = serde_json::to_string(bundle).unwrap_or_default();
    hasher.update(serialized.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Pick a shard for a new slot.
///
/// Deterministic within a given shard count: sha256(slot) mod shard_count. If
/// the target shard would exceed `BUNDLE_SOFT_LIMIT_BYTES` after insertion,
/// returns `None` and the caller should increment `shard_count` and retry.
pub fn pick_shard(
    slot: &str,
    value_len: usize,
    shards: &BTreeMap<u32, CredentialBundle>,
    shard_count: u32,
) -> Option<u32> {
    if shard_count == 0 {
        return Some(0);
    }
    let mut hasher = Sha256::new();
    hasher.update(slot.as_bytes());
    let digest = hasher.finalize();
    let first_8 = u64::from_be_bytes(digest[0..8].try_into().unwrap());
    let target = (first_8 % shard_count as u64) as u32;

    let projected_size = projected_shard_size(slot, value_len, shards, target);
    if projected_size > BUNDLE_SOFT_LIMIT_BYTES {
        return None;
    }

    Some(target)
}

fn projected_shard_size(
    slot: &str,
    value_len: usize,
    shards: &BTreeMap<u32, CredentialBundle>,
    target: u32,
) -> usize {
    let existing = shards
        .get(&target)
        .map(|b| serde_json::to_string(b).map(|s| s.len()).unwrap_or(0))
        .unwrap_or(2);
    // Add slot + value + JSON overhead.
    existing + slot.len() + value_len + 8
}
