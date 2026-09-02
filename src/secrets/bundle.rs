use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// The maximum bytes we will pack into a single bundle before splitting to a
/// new shard. GitHub's hard limit is 48 KB; we stay under at 40 KB so reads
/// and writes always have headroom.
pub const BUNDLE_SOFT_LIMIT_BYTES: usize = 40 * 1024;

pub const BUNDLE_SECRET_PREFIX: &str = "FERRUM_CREDS_BUNDLE";

/// How many `FERRUM_CREDS_BUNDLE[_N]` Environment Secrets the credential
/// broker may ever occupy. Valid shard indices are `0..MAX_BUNDLE_SHARDS`,
/// i.e. `FERRUM_CREDS_BUNDLE` through `FERRUM_CREDS_BUNDLE_15`.
///
/// The ceiling exists because the privileged workflows bind every shard secret
/// **by name**. GitHub offers no way to enumerate an environment's secrets
/// without `${{ toJSON(secrets) }}`, which hands the step the admin JWT signing
/// key, the state-writer App private key and the registry token alongside the
/// bundles — and, since GitHub's 2026-07-28 change, makes public-repository
/// runs wait for manual approval. So the list of bundle secrets is finite and
/// this constant is its length: 16 shards x ~440 slots ~= 7,000 credential
/// slots.
///
/// Raising it means changing all of these together, which
/// `.github/scripts/check_supply_chain.py` cross-checks:
///   1. this constant,
///   2. `MAX_BUNDLE_SHARDS` in `.github/scripts/credential_bundles.py`,
///   3. the `FERRUM_CREDS_BUNDLE_<N>` env bindings in the "Load credential
///      bundles" step of `.github/workflows/apply-on-merge.yml`,
///      `drift-check.yml`, `materialize-file.yml` and `rotate.yml`.
///
/// Reading is deliberately unbounded: `load_bundles_from_env` still accepts any
/// shard index so a repository that allocated beyond an older, higher ceiling
/// keeps resolving its existing slots.
pub const MAX_BUNDLE_SHARDS: u32 = 16;

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
    let mut slot_sources: BTreeMap<String, u32> = BTreeMap::new();

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
            if let Some(previous_shard) = slot_sources.insert(slot.clone(), shard_idx) {
                return Err(crate::error::Error::Config(format!(
                    "credential slot '{slot}' appears in multiple bundle shards ({previous_shard} and {shard_idx}); repair FERRUM_CREDS_BUNDLE secrets before continuing"
                )));
            }
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
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Pick a shard for a new slot.
///
/// Deterministic within a given shard count when the hash-target shard has
/// room: `sha256(slot) mod shard_count`. When the hash-target shard would
/// exceed `BUNDLE_SOFT_LIMIT_BYTES`, falls back to scanning the remaining
/// shards for one with capacity. Returns `None` only when EVERY addressable
/// shard is full — at that point the caller should grow `shard_count` to add a
/// new shard. Without the fallback scan, a slot hashing to a full shard would
/// force shard growth even when other existing shards have free space, hitting
/// `MAX_BUNDLE_SHARDS` prematurely.
///
/// `shard_count` is clamped to `MAX_BUNDLE_SHARDS`, so this never returns an
/// index the privileged workflows do not bind. A repository whose state file
/// still records a higher count (allocated under an older ceiling) keeps
/// reading those shards; it simply stops placing *new* slots on them.
///
/// Determinism note: the hash-based placement is preferred for new slots so
/// steady-state distribution stays predictable. The probe is a fallback for
/// the overflow case; once a slot is written, callers locate it via
/// `bundle.contains_key` lookups, so the chosen shard is recorded and
/// subsequent operations always find it (no re-probe needed).
pub fn pick_shard(
    slot: &str,
    value_len: usize,
    shards: &BTreeMap<u32, CredentialBundle>,
    shard_count: u32,
) -> Option<u32> {
    if shard_count == 0 {
        return Some(0);
    }
    let addressable = shard_count.min(MAX_BUNDLE_SHARDS);
    let mut hasher = Sha256::new();
    hasher.update(slot.as_bytes());
    let digest = hasher.finalize();
    let first_8 = u64::from_be_bytes(digest[0..8].try_into().unwrap_or_default());
    let target = (first_8 % addressable as u64) as u32;

    if projected_shard_size(slot, value_len, shards, target) <= BUNDLE_SOFT_LIMIT_BYTES {
        return Some(target);
    }

    // Hash target is full. Probe the remaining shards before signaling
    // overflow — heterogeneous slot/value sizes mean the target can be
    // full while neighbours have room, especially when shard_count is
    // already at MAX_BUNDLE_SHARDS.
    for s in 0..addressable {
        if s == target {
            continue;
        }
        if projected_shard_size(slot, value_len, shards, s) <= BUNDLE_SOFT_LIMIT_BYTES {
            return Some(s);
        }
    }

    None
}

/// Resolve the shard a slot must be written to, growing `shard_count` when the
/// existing shards are full.
///
/// A slot that already lives on a shard stays there. Running `pick_shard`
/// again after `shard_count` grew could pick a different target, leaving a
/// stale copy behind on the old shard; because `merge_bundles` iterates in
/// ascending shard order, whichever copy sits higher wins, which can silently
/// revert a freshly rotated value.
///
/// Refuses to create a shard index at or beyond [`MAX_BUNDLE_SHARDS`]: the
/// workflows bind each shard secret by name, so a `FERRUM_CREDS_BUNDLE_16`
/// would be written to GitHub and then never read back, and the next run would
/// re-allocate every slot it holds.
pub fn reserve_shard(
    slot: &str,
    value_len: usize,
    shards: &BTreeMap<u32, CredentialBundle>,
    shard_count: &mut u32,
    operation: &str,
) -> crate::error::Result<u32> {
    if let Some(existing) = shards
        .iter()
        .find_map(|(index, bundle)| bundle.contains_key(slot).then_some(*index))
    {
        return Ok(existing);
    }
    loop {
        if *shard_count == 0 {
            *shard_count = 1;
        }
        if let Some(index) = pick_shard(slot, value_len, shards, *shard_count) {
            return Ok(index);
        }
        if *shard_count >= MAX_BUNDLE_SHARDS {
            return Err(shard_ceiling_error(slot, operation));
        }
        *shard_count += 1;
    }
}

/// Actionable refusal for a bundle layout that has run out of named shards.
fn shard_ceiling_error(slot: &str, operation: &str) -> crate::error::Error {
    crate::error::Error::Config(format!(
        "credential bundle shards are full: {operation} slot '{slot}' would need a new \
         {next} secret, but MAX_BUNDLE_SHARDS = {MAX_BUNDLE_SHARDS} (src/secrets/bundle.rs) \
         caps the layout at shards 0..={last}. The privileged workflows bind every bundle \
         secret by name rather than dumping the whole secrets context, so capacity is only \
         added deliberately: raise MAX_BUNDLE_SHARDS in src/secrets/bundle.rs and in \
         .github/scripts/credential_bundles.py, then add the matching \
         FERRUM_CREDS_BUNDLE_<N> env bindings to the 'Load credential bundles' step of \
         .github/workflows/apply-on-merge.yml, drift-check.yml, materialize-file.yml and \
         rotate.yml.",
        next = shard_secret_name(MAX_BUNDLE_SHARDS),
        last = MAX_BUNDLE_SHARDS - 1,
    ))
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
