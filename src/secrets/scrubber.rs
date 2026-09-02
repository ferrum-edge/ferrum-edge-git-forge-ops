//! Redaction of live secret material from untrusted child-process output.
//!
//! `ferrum-edge validate` is handed a spec whose credential placeholders have
//! already been replaced with real bundle values, and its diagnostics quote
//! the offending document freely. Discarding the whole stream whenever the
//! input carried credential material is safe but useless: with a bundle
//! loaded *every* credential is a literal, so a plain proxy typo would print
//! nothing but "diagnostics were suppressed".
//!
//! [`SecretScrubber`] takes the other route. It enumerates the exact byte
//! sequences that are secret — every value the resolver substituted from the
//! bundle plus every literal secret leaf committed in the repo — and removes
//! only those from the child's output, leaving every non-credential
//! diagnostic intact.

use std::collections::BTreeSet;

use base64::Engine;

use crate::config::GatewayConfig;

use super::placeholder::parse_placeholder;
use super::plugin_config::{sensitive_string_paths, value_at};
use super::resolver::is_identity_credential_leaf;

/// Text substituted for every secret occurrence.
pub const REDACTION: &str = "[REDACTED]";

/// Shortest secret value that is removed by substring replacement.
///
/// A three-byte credential such as `dev` occurs inside ordinary words, so
/// scrubbing it would replace unrelated text and turn a readable schema error
/// into `pro[REDACTED]uction: unknown field`. Eight bytes is short enough that
/// no real credential is meant to be below it and long enough that a
/// collision with prose is a curiosity rather than the norm.
///
/// Values below the threshold are **not** exempt from protection: they are
/// still checked verbatim by [`SecretScrubber::leaks`], and a hit there makes
/// the caller fall back to suppressing the stream entirely. The threshold only
/// chooses which of the two protections applies, never whether one applies.
pub const MIN_SCRUB_LENGTH: usize = 8;

/// The secret byte sequences to remove from a child process's output.
///
/// Build one with [`SecretScrubber::from_gateway_config`] *after* credential
/// resolution, so the resolved values are the ones in hand.
#[derive(Debug, Clone, Default)]
pub struct SecretScrubber {
    /// Every byte sequence replaced by [`REDACTION`], longest first so a
    /// value nested inside another is not left half-redacted.
    needles: Vec<String>,
    /// The raw secret values, including those below [`MIN_SCRUB_LENGTH`].
    /// Used only by [`SecretScrubber::leaks`].
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
        let mut needles = BTreeSet::new();
        for value in &values {
            if value.len() < MIN_SCRUB_LENGTH {
                continue;
            }
            needles.insert(value.clone());
            // Cheap re-encodings a validator might echo instead of the raw
            // bytes: a value carried through a URL or copied out of a
            // base64-wrapped payload. Anything more exotic (compression,
            // hashing) is out of reach and is covered by `leaks` instead.
            needles.insert(base64::engine::general_purpose::STANDARD.encode(value.as_bytes()));
            needles
                .insert(base64::engine::general_purpose::STANDARD_NO_PAD.encode(value.as_bytes()));
            let encoded = percent_encoded(value);
            if encoded != *value {
                needles.insert(encoded);
            }
        }

        let mut needles: Vec<String> = needles.into_iter().collect();
        // Longest first: replacing a short needle that is a substring of a
        // longer secret would otherwise leave the rest of the longer value in
        // place around a `[REDACTED]` marker.
        needles.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));

        Self {
            needles,
            values: values.into_iter().collect(),
        }
    }

    /// True when the config carried no secret material at all.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Replace every known secret sequence in `text` with [`REDACTION`].
    pub fn scrub(&self, text: &str) -> String {
        let mut scrubbed = text.to_string();
        for needle in &self.needles {
            if scrubbed.contains(needle.as_str()) {
                scrubbed = scrubbed.replace(needle.as_str(), REDACTION);
            }
        }
        scrubbed
    }

    /// True when any secret value is still present verbatim.
    ///
    /// Checked against the raw values including the ones below
    /// [`MIN_SCRUB_LENGTH`], so a credential too short to substring-replace
    /// still forces the caller into last-resort suppression rather than
    /// through an unredacted stream.
    pub fn leaks(&self, text: &str) -> bool {
        self.values
            .iter()
            .any(|value| text.contains(value.as_str()))
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

/// Percent-encode every byte outside RFC 3986's unreserved set.
fn percent_encoded(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}
