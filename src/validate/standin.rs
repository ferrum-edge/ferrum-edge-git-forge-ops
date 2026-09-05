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
//! Brokered plugin config has the same problem in a different shape. The
//! sensitivity classifier brokers credential-bearing *endpoints* as well as
//! tokens, and the gateway parses those: a brokered `ldap_auth.ldap_url` comes
//! back as "'ldap_url' is not a valid URL: relative URL without a base", which
//! is a verdict on the brokering rather than on the configuration.
//!
//! So the validator gets stand-ins instead: a deterministic, obviously fake
//! value of adequate *shape* — a 64-hex token, an `hmac_sha256:` digest, or a
//! syntactically valid URL on a reserved `.invalid` host, whichever the field
//! calls for — derived from the leaf's own broker slot. They exist for exactly
//! one file — the 0600 temp spec handed to `ferrum-edge validate` — and are
//! never exported, applied, written to state, or delivered.
//! `export --materialize` still refuses to run while any slot is unresolved;
//! `apply` still fails on `alloc=require` with no value.

use sha2::{Digest, Sha256};

use crate::config::GatewayConfig;
use crate::secrets::parse_placeholder;
use crate::secrets::plugin_config::ConfigPathComponent;

/// Fixed marker every opaque stand-in starts with. It is deliberately
/// unmistakable: a value carrying this prefix anywhere but a validator temp
/// spec is a bug, and greppable as one.
pub const VALIDATION_STANDIN_PREFIX: &str = "gitforgeops-validation-standin-";

/// Host every URL-shaped stand-in points at.
///
/// `.invalid` is reserved by RFC 2606 and can never resolve, so a stand-in
/// that somehow escaped into a live configuration fails closed at connect
/// time instead of reaching a real host. Same greppability contract as
/// [`VALIDATION_STANDIN_PREFIX`].
pub const VALIDATION_STANDIN_HOST: &str = "gitforgeops-validation-standin.invalid";

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

/// Build the stand-in for one brokered plugin-config leaf that the gateway
/// parses as a URL.
///
/// `<scheme>://gitforgeops-validation-standin.invalid/<64 hex>`: a
/// syntactically valid absolute URL, on a host RFC 2606 reserves as
/// permanently unresolvable, deterministic in `slot` for the same reasons
/// [`validation_standin`] is. The scheme comes from the field
/// ([`crate::secrets::plugin_config::endpoint_scheme`]) because several
/// plugins check it — `ldap_auth` wants `ldap`/`ldaps`, the Redis-backed
/// plugins want `redis` — and a stand-in that parses but fails the scheme
/// check would swap one spurious CI failure for another.
pub fn validation_url_standin(slot: &str, scheme: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slot.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{scheme}://{VALIDATION_STANDIN_HOST}/{digest}")
}

/// Return a copy of `config` whose unresolved broker placeholders have been
/// replaced with stand-in values, or `None` when there were none (the
/// overwhelmingly common bundle-loaded case, which then validates the config
/// as-is with no clone).
///
/// Two sources, matching the two the resolver walks:
///
/// * **`Consumer.credentials`** — shape-checked by ferrum-edge (the
///   32-character `jwt`/`hmac_auth` floor, the `hmac_sha256:<64 hex>`
///   basicauth hash), so a 30-character placeholder literal fails validation
///   on the brokering rather than on the credential.
/// * **`PluginConfig.config`** — the same problem with a different shape. The
///   sensitivity classifier brokers credential-bearing *endpoints* as well as
///   tokens, and the gateway parses those: `ldap_auth` rejects
///   `${gh-env-secret:alloc=require}` with "not a valid URL". Endpoint-typed
///   leaves therefore get [`validation_url_standin`] with the field's own
///   scheme, and everything else gets the opaque token form. Header maps are
///   rewritten value-side only, so `headers.x-honeycomb-team` keeps its key
///   and a plugin that validates required header *names* still sees them.
///
/// Nothing outside the 0600 temp spec handed to `ferrum-edge validate` ever
/// sees the result: the caller's `config` is untouched, and export, apply,
/// delivery and state all serialize that original.
pub fn with_validation_standins(config: &GatewayConfig) -> Option<GatewayConfig> {
    let credentials_brokered = config
        .consumers
        .iter()
        .any(|consumer| consumer.credentials.values().any(has_placeholder));
    let plugin_config_brokered = config
        .plugin_configs
        .iter()
        .any(|plugin| has_placeholder(&plugin.config));
    if !credentials_brokered && !plugin_config_brokered {
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

    for plugin in &mut patched.plugin_configs {
        // Classified before the walk mutates anything: the rules key on paths,
        // and replacing a string leaf never moves one.
        let endpoints = crate::secrets::plugin_config::endpoint_paths(
            plugin.plugin_name.as_str(),
            &plugin.config,
        );
        let namespace = plugin.namespace.clone();
        let plugin_id = plugin.id.clone();
        let plugin_name = plugin.plugin_name.clone();
        let mut path = Vec::new();
        substitute_plugin_leaves(
            &mut plugin.config,
            &namespace,
            &plugin_id,
            &plugin_name,
            &endpoints,
            &mut path,
        );
    }

    Some(patched)
}

fn substitute_plugin_leaves(
    value: &mut serde_json::Value,
    namespace: &str,
    plugin_id: &str,
    plugin_name: &str,
    endpoints: &std::collections::BTreeSet<Vec<ConfigPathComponent>>,
    path: &mut Vec<ConfigPathComponent>,
) {
    match value {
        serde_json::Value::String(text) => {
            if !matches!(parse_placeholder(text), Some(Ok(_))) {
                return;
            }
            // The canonical broker slot, so a stand-in is distinct per leaf
            // and stable across runs for the same repository.
            let slot = crate::secrets::resolver::plugin_config_slot(namespace, plugin_id, path);
            *text = if endpoints.contains(path) {
                validation_url_standin(
                    &slot,
                    crate::secrets::plugin_config::endpoint_scheme(plugin_name, path),
                )
            } else {
                validation_standin(&slot, None)
            };
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(ConfigPathComponent::Key(key.clone()));
                substitute_plugin_leaves(child, namespace, plugin_id, plugin_name, endpoints, path);
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                substitute_plugin_leaves(child, namespace, plugin_id, plugin_name, endpoints, path);
                path.pop();
            }
        }
        _ => {}
    }
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
