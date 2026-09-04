//! Redaction of live secret material from untrusted child-process output.
//!
//! `ferrum-edge validate` is handed a spec whose credential placeholders have
//! already been replaced with real bundle values, and its diagnostics quote
//! the offending document freely. Discarding the whole stream whenever the
//! input carried credential material is safe but useless: with a bundle
//! loaded *every* credential is a literal, so a plain proxy typo would print
//! nothing but "diagnostics were suppressed".
//!
//! [`SecretScrubber`] detects whether the validator input contains secret
//! material. Callers must withhold the complete untrusted output when it does:
//! exact-string replacement cannot cover escaped, split, normalized, or
//! otherwise transformed representations of a secret.

use std::collections::BTreeSet;

use crate::config::GatewayConfig;

use super::placeholder::parse_placeholder;
use super::plugin_config::{sensitive_string_paths, value_at};
use super::resolver::is_identity_credential_leaf;

/// Secret material detected in a validator input.
///
/// Build one with [`SecretScrubber::from_gateway_config`] *after* credential
/// resolution, so the resolved values are the ones in hand.
#[derive(Debug, Clone, Default)]
pub struct SecretScrubber {
    values: Vec<String>,
}

impl SecretScrubber {
    /// Collect every secret string reachable from `config`.
    ///
    /// Two sources, matching what the broker itself manages:
    ///
    /// * **Consumer credentials** — every string leaf under
    ///   `Consumer.credentials` that is not a well-formed
    ///   `${gh-env-secret:…}` placeholder. Placeholder text is repository
    ///   data and stays visible; a resolved or literal value does not.
    ///   `basicauth[].username` and `mtls_auth[].identity` are identities,
    ///   not secrets ([`is_identity_credential_leaf`]), and are excluded so
    ///   an error naming the consumer stays legible.
    /// * **Plugin config** — the leaves
    ///   [`sensitive_string_paths`] classifies as secret, which is the same
    ///   set `import` moves into the private bundle. A plugin secret such as
    ///   an `otel_tracing` `headers.x-honeycomb-team` value is resolved into
    ///   the validator input exactly like a consumer credential.
    pub fn from_gateway_config(config: &GatewayConfig) -> Self {
        let mut values = BTreeSet::new();
        collect_consumer_secrets(config, &mut values);
        collect_plugin_config_secrets(config, &mut values);
        Self::from_values(values)
    }

    fn from_values(values: BTreeSet<String>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    /// True when the config carried no secret material at all.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

fn collect_consumer_secrets(config: &GatewayConfig, out: &mut BTreeSet<String>) {
    for consumer in &config.consumers {
        for (credential_type, value) in &consumer.credentials {
            collect_credential_leaves(credential_type, value, None, out);
        }
    }
}

fn collect_credential_leaves(
    credential_type: &str,
    value: &serde_json::Value,
    leaf_key: Option<&str>,
    out: &mut BTreeSet<String>,
) {
    match value {
        serde_json::Value::String(text) => {
            if is_identity_credential_leaf(credential_type, leaf_key) {
                return;
            }
            record_secret(text, out);
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                collect_credential_leaves(credential_type, child, Some(key.as_str()), out);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                // An array index does not change which field a leaf is, so
                // the enclosing key (`keyauth` → `key`) carries through.
                collect_credential_leaves(credential_type, child, leaf_key, out);
            }
        }
        _ => {}
    }
}

fn collect_plugin_config_secrets(config: &GatewayConfig, out: &mut BTreeSet<String>) {
    for plugin in &config.plugin_configs {
        for path in sensitive_string_paths(&plugin.plugin_name, &plugin.config) {
            if let Some(serde_json::Value::String(text)) = value_at(&plugin.config, &path) {
                record_secret(text, out);
            }
        }
    }
}

/// Keep a leaf unless it is repository data rather than secret material: a
/// well-formed placeholder (validators quote those back and operators need to
/// read them) or an empty string (scrubbing `""` would redact everything).
fn record_secret(text: &str, out: &mut BTreeSet<String>) {
    if text.is_empty() || matches!(parse_placeholder(text), Some(Ok(_))) {
        return;
    }
    out.insert(text.to_string());
}
