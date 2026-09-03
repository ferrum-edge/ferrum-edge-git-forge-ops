//! Deterministic fake credentials for the validator's input document.
//!
//! `ferrum-edge validate` checks credential *shape*: a `jwt` or `hmac_auth`
//! secret must be at least 32 characters, a `basicauth` entry must carry a
//! `hmac_sha256:<64 hex>` hash in file mode, and so on. A PR-review run has
//! no credential bundle, so what reaches the validator is the placeholder
//! text itself — and `${gh-env-secret:alloc=generate}` is 30 characters, two
//! short of the floor. Every repo that brokers a `jwt` or `hmac_auth` secret
//! therefore failed validation in CI for a reason that has nothing to do with
//! the change under review.
//!
//! So the validator gets stand-ins instead: a deterministic, obviously fake
//! value of adequate shape, derived from the credential's own slot path. They
//! exist for exactly one file — the 0600 temp spec handed to
//! `ferrum-edge validate` — and are never exported, applied, written to state,
//! or delivered. `export --materialize` still refuses to run while any slot is
//! unresolved; `apply` still fails on `alloc=require` with no value.

use sha2::{Digest, Sha256};

use crate::config::GatewayConfig;
use crate::secrets::parse_placeholder;

/// Fixed marker every stand-in starts with. It is deliberately unmistakable:
/// a value carrying this prefix anywhere but a validator temp spec is a bug,
/// and greppable as one.
pub const VALIDATION_STANDIN_PREFIX: &str = "gitforgeops-validation-standin-";

/// Prefix ferrum-edge requires on a `basicauth` password hash, followed by 64
/// lowercase hex characters.
const BASIC_AUTH_HASH_PREFIX: &str = "hmac_sha256:";

/// The credential leaf whose value must be a gateway-computed HMAC digest
/// rather than free-form text.
const PASSWORD_HASH_LEAF: &str = "password_hash";

/// Build the stand-in for one credential leaf.
///
/// Deterministic in `slot`, so re-validating an unchanged repo produces a
/// byte-identical document (a validator that reports a value back does not
/// churn between runs), and distinct per slot, so a uniqueness constraint the
/// gateway enforces across credentials is still exercised.
///
/// Two shapes:
///
/// * `password_hash` → `hmac_sha256:<64 hex>`, the only shape ferrum-edge
///   accepts there. The digest is not a real HMAC under the gateway's secret
///   and could never authenticate anyone; it exists so the *format* check
///   passes.
/// * everything else → [`VALIDATION_STANDIN_PREFIX`] followed by 64 hex
///   characters, 95 in total. Comfortably past the 32-character floor
///   `jwt`/`hmac_auth` impose and well under the 4096-character ceiling.
pub fn validation_standin(slot: &str, leaf: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slot.as_bytes());
    let digest = hex::encode(hasher.finalize());

    if leaf == Some(PASSWORD_HASH_LEAF) {
        return format!("{BASIC_AUTH_HASH_PREFIX}{digest}");
    }
    format!("{VALIDATION_STANDIN_PREFIX}{digest}")
}

/// Return a copy of `config` whose unresolved consumer-credential
/// placeholders have been replaced with [`validation_standin`] values, or
/// `None` when there were none (the overwhelmingly common bundle-loaded case,
/// which then validates the config as-is with no clone).
///
/// Only `Consumer.credentials` is rewritten. Plugin-config placeholders are
/// left alone: ferrum-edge does not impose a length floor on opaque plugin
/// config, so a stand-in would buy nothing there while risking a *new*
/// failure against a plugin that does check its own field shapes.
pub fn with_validation_standins(config: &GatewayConfig) -> Option<GatewayConfig> {
    if !config
        .consumers
        .iter()
        .any(|consumer| consumer.credentials.values().any(has_placeholder))
    {
        return None;
    }

    let mut patched = config.clone();
    for consumer in &mut patched.consumers {
        let namespace = consumer.namespace.clone();
        let consumer_id = consumer.id.clone();
        for (credential_type, value) in consumer.credentials.iter_mut() {
            let mut path = vec![
                namespace.clone(),
                consumer_id.clone(),
                credential_type.clone(),
            ];
            substitute_leaves(value, &mut path, None);
        }
    }
    Some(patched)
}

fn has_placeholder(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => matches!(parse_placeholder(text), Some(Ok(_))),
        serde_json::Value::Object(map) => map.values().any(has_placeholder),
        serde_json::Value::Array(items) => items.iter().any(has_placeholder),
        _ => false,
    }
}

fn substitute_leaves(value: &mut serde_json::Value, path: &mut Vec<String>, leaf: Option<&str>) {
    match value {
        serde_json::Value::String(text) => {
            if matches!(parse_placeholder(text), Some(Ok(_))) {
                *text = validation_standin(&path.join("/"), leaf);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                let leaf = key.clone();
                substitute_leaves(child, path, Some(&leaf));
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                path.push(format!("[{index}]"));
                // An index does not change which field the leaf is, so the
                // enclosing object key carries through.
                let inherited = leaf.map(str::to_string);
                substitute_leaves(child, path, inherited.as_deref());
                path.pop();
            }
        }
        _ => {}
    }
}
