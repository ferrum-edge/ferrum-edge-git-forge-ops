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
//!
//! # Where substring replacement stops working
//!
//! Removing exact bytes only protects a value the child echoed *as those
//! bytes*. `ferrum-edge validate` re-serializes the document it was handed, so
//! a value can come back quoted, escaped, or wrapped instead:
//!
//! ```text
//! secret:  -----BEGIN PRIVATE KEY-----\nMIIE…\n-----END PRIVATE KEY-----
//! echoed:  key: |
//!            -----BEGIN PRIVATE KEY-----
//!            MIIE…
//! ```
//!
//! Indentation and re-wrapping mean no needle matches, and a naive scrubber
//! prints the key. So the scrubber does three more things, all of them
//! fail-closed:
//!
//! 1. **Refuse to scrub what cannot be scrubbed.** A value carrying any of the
//!    characters an emitter re-encodes ([`is_reencoding_hazard`]) makes
//!    [`SecretScrubber::scrub_streams`] withhold the entire stream instead of
//!    pretending the substitution was complete.
//! 2. **Match the encodings that stay single-line** — base64, percent-encoding,
//!    JSON escaping, single-quoted YAML — not just the raw bytes.
//! 3. **Check the result.** After scrubbing, any surviving
//!    [`FRAGMENT_SCAN_LENGTH`]-byte run of any secret withholds the stream:
//!    proof that some encoding got past steps 1 and 2.
//!
//! The common case is untouched. An API key, JWT or HMAC secret is a
//! single-line base64/hex string with none of those characters, so its
//! diagnostics stay fully readable — which is the whole point of scrubbing
//! rather than suppressing.

use std::collections::{BTreeSet, HashSet};

use base64::Engine;

use crate::config::GatewayConfig;

use super::placeholder::parse_placeholder;
use super::plugin_config::{sensitive_string_paths, value_at};
use super::resolver::is_identity_credential_leaf;

/// Text substituted for every secret occurrence.
pub const REDACTION: &str = "[REDACTED]";

/// Length of the sliding window used to detect a *partial* secret that
/// survived scrubbing.
///
/// Twelve bytes is long enough that ordinary diagnostic prose does not collide
/// with a credential by accident, and short enough that a value split across a
/// wrapped line or broken up by escaping still leaves a detectable run. The
/// scan runs on the already-scrubbed text, so a hit means an encoding the
/// needle list does not cover reproduced part of a secret verbatim.
pub const FRAGMENT_SCAN_LENGTH: usize = 12;

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
    /// Every [`FRAGMENT_SCAN_LENGTH`]-byte window of every secret value.
    ///
    /// Precomputed because the check runs against the output once per stream:
    /// the secret side is small and bounded by the document, the output side
    /// is whatever the validator decided to print.
    fragments: HashSet<Vec<u8>>,
    /// The scrubbed document, used to tell a leaked fragment apart from a run
    /// the validator would print anyway. See [`SecretScrubber::leaks_fragment`].
    public_text: String,
    /// At least one secret cannot be scrubbed reliably — see
    /// [`is_reencoding_hazard`]. Every stream is withheld while this is set,
    /// because a partial substitution reads exactly like a complete one.
    unsafe_to_scrub: bool,
}

/// Why a validator's output was withheld instead of scrubbed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    /// A secret's own bytes are not reliably matchable in re-encoded output
    /// ([`is_reencoding_hazard`]). Decided before the child even runs.
    NotSafelyScrubbable,
    /// A secret value survived scrubbing verbatim. Only reachable below
    /// [`MIN_SCRUB_LENGTH`], where substring replacement would corrupt the
    /// surrounding diagnostic.
    ResidualValue,
    /// A [`FRAGMENT_SCAN_LENGTH`]-byte run of a secret survived scrubbing, so
    /// the value reached the output in some encoding the needles do not cover.
    ResidualFragment,
}

impl SuppressionReason {
    /// Operator-facing explanation, printed in place of the validator's own
    /// output. Each one names the cause and the way out, because "diagnostics
    /// were suppressed" with no reason is indistinguishable from a bug.
    pub fn notice(self) -> &'static str {
        match self {
            Self::NotSafelyScrubbable => {
                "Validator diagnostics were withheld: a resolved secret is not safely scrubbable. \
                 Its value contains a newline, a quote or backslash, a '#', a ': ' sequence, or \
                 leading/trailing whitespace — characters a validator re-encodes when it quotes \
                 the document back (YAML block scalar, escaped string, wrapped line), so removing \
                 the exact bytes would leave fragments behind. Rotate the value to a single-line \
                 secret without those characters to get diagnostics back.\n"
            }
            Self::ResidualValue => {
                "Validator diagnostics were withheld: a credential value survived redaction, so \
                 the output could not be shown without leaking it. Credentials shorter than 8 \
                 bytes cannot be redacted from a diagnostic without mangling it — lengthen the \
                 credential, or move the literal value into the ${gh-env-secret:...} broker.\n"
            }
            Self::ResidualFragment => {
                "Validator diagnostics were withheld: a 12-byte run of a resolved secret survived \
                 redaction. The validator reproduced part of the value in an encoding this build \
                 does not recognize, so the stream was dropped rather than printed with a fragment \
                 of a live credential in it.\n"
            }
        }
    }
}

/// One validator stream pair, after scrubbing or suppression.
#[derive(Debug, Clone)]
pub struct ScrubbedOutput {
    pub stdout: String,
    pub stderr: String,
    /// `Some` when both streams were replaced by
    /// [`SuppressionReason::notice`] instead of being scrubbed.
    pub suppressed: Option<SuppressionReason>,
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
    /// * **Service discovery** — the modeled secret leaves of
    ///   `Upstream.service_discovery` ([`super::service_discovery`]), today the
    ///   Consul ACL token. The validator is handed the resolved upstream, so
    ///   an error quoting the discovery block quotes the token with it.
    pub fn from_gateway_config(config: &GatewayConfig) -> Self {
        let mut values = BTreeSet::new();
        collect_consumer_secrets(config, &mut values);
        collect_plugin_config_secrets(config, &mut values);
        collect_service_discovery_secrets(config, &mut values);
        let mut scrubber = Self::from_values(values);
        // The document with every secret removed. Serialization failure is not
        // worth failing validation over: an empty `public_text` only makes the
        // fragment scan stricter, never laxer.
        let document = serde_json::to_string(config).unwrap_or_default();
        scrubber.public_text = scrubber.scrub(&document);
        scrubber
    }

    fn from_values(values: BTreeSet<String>) -> Self {
        let mut needles = BTreeSet::new();
        for value in &values {
            if value.len() < MIN_SCRUB_LENGTH {
                continue;
            }
            needles.insert(value.clone());
            // Cheap re-encodings a validator might echo instead of the raw
            // bytes: a value carried through a URL, copied out of a
            // base64-wrapped payload, or re-quoted by the emitter. All of
            // these keep the value on one line, which is what makes them
            // matchable at all; the ones that do not are refused outright by
            // `is_reencoding_hazard`. Anything more exotic (compression,
            // hashing) is out of reach and is covered by the fragment scan.
            needles.insert(base64::engine::general_purpose::STANDARD.encode(value.as_bytes()));
            needles
                .insert(base64::engine::general_purpose::STANDARD_NO_PAD.encode(value.as_bytes()));
            let encoded = percent_encoded(value);
            if encoded != *value {
                needles.insert(encoded);
            }
            if let Some(escaped) = json_escaped(value) {
                needles.insert(escaped);
            }
            let single_quoted = yaml_single_quoted(value);
            if single_quoted != *value {
                needles.insert(single_quoted);
            }
        }

        let mut needles: Vec<String> = needles.into_iter().collect();
        // Longest first: replacing a short needle that is a substring of a
        // longer secret would otherwise leave the rest of the longer value in
        // place around a `[REDACTED]` marker.
        needles.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));

        let unsafe_to_scrub = values.iter().any(|value| is_reencoding_hazard(value));
        let fragments = values
            .iter()
            .flat_map(|value| value.as_bytes().windows(FRAGMENT_SCAN_LENGTH))
            .map(<[u8]>::to_vec)
            .collect();

        Self {
            needles,
            values: values.into_iter().collect(),
            fragments,
            public_text: String::new(),
            unsafe_to_scrub,
        }
    }

    /// True when the config carried no secret material at all.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// True when at least one secret cannot be scrubbed reliably, so every
    /// stream is withheld rather than partially redacted.
    pub fn is_unsafe_to_scrub(&self) -> bool {
        self.unsafe_to_scrub
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

    /// True when any [`FRAGMENT_SCAN_LENGTH`]-byte run of any secret is
    /// present in `text`.
    ///
    /// Run on already-scrubbed output, where every needle has been replaced,
    /// so a hit is evidence that some encoding reproduced part of a secret.
    /// The comparison is byte-oriented on purpose: a wrapped or escaped value
    /// can be split mid-character, and those bytes are just as much of a leak.
    ///
    /// One narrowing, and it is load-bearing rather than a softening: a run
    /// that also occurs in the **scrubbed document** is not evidence. Secrets
    /// routinely share long runs with public text — a header value that
    /// embeds its own header name, a brokered `endpoint` whose host is also a
    /// proxy's `backend_host` — and the validator prints that public text
    /// whether or not a secret exists. Flagging it would withhold every
    /// diagnostic for the lifetime of the configuration while protecting
    /// nothing: the run is readable in the repository. What remains flagged is
    /// exactly what the scan is for — a run of the secret that has no public
    /// explanation, i.e. one that reached the output through the secret
    /// itself.
    pub fn leaks_fragment(&self, text: &str) -> bool {
        if self.fragments.is_empty() {
            return false;
        }
        text.as_bytes()
            .windows(FRAGMENT_SCAN_LENGTH)
            .any(|window| self.fragments.contains(window) && !self.is_public_run(window))
    }

    /// Does this byte run also occur in the scrubbed document?
    fn is_public_run(&self, window: &[u8]) -> bool {
        self.public_text
            .as_bytes()
            .windows(window.len())
            .any(|candidate| candidate == window)
    }

    /// Scrub both validator streams, or withhold them when redaction cannot be
    /// trusted.
    ///
    /// The whole suppression policy lives here rather than at the call site,
    /// so gateway and mesh validation cannot reach different conclusions from
    /// the same evidence. Order matters: the unscrubbable check runs first
    /// because its verdict does not depend on what the child happened to
    /// print, then the exact-value check, then the fragment scan on the
    /// scrubbed result.
    pub fn scrub_streams(&self, stdout: &str, stderr: &str) -> ScrubbedOutput {
        let withheld = |reason: SuppressionReason| ScrubbedOutput {
            stdout: String::new(),
            stderr: reason.notice().to_string(),
            suppressed: Some(reason),
        };

        if self.unsafe_to_scrub {
            return withheld(SuppressionReason::NotSafelyScrubbable);
        }

        let stdout = self.scrub(stdout);
        let stderr = self.scrub(stderr);

        if self.leaks(&stdout) || self.leaks(&stderr) {
            return withheld(SuppressionReason::ResidualValue);
        }
        if self.leaks_fragment(&stdout) || self.leaks_fragment(&stderr) {
            return withheld(SuppressionReason::ResidualFragment);
        }

        ScrubbedOutput {
            stdout,
            stderr,
            suppressed: None,
        }
    }
}

/// Would a validator re-encoding this value produce bytes the needle list
/// cannot match?
///
/// Substring replacement is only sound while the value survives a round trip
/// through the emitter unchanged. These are the characters that break that,
/// and each one is here for a concrete reason:
///
/// * **`\n` / `\r`** — a multi-line value (a PEM key, a JSON blob) is emitted
///   as a YAML block scalar or wrapped across lines, indented per line. No
///   contiguous copy of the original bytes exists in the output.
/// * **`"`, `'`, `\`** — force the emitter into a quoted style and get
///   escaped, in a form that varies by emitter and quoting choice.
/// * **`#`** — a YAML comment introducer, so the value is quoted (and may then
///   be escaped) rather than emitted plain.
/// * **`: `** — the YAML mapping indicator, same consequence.
/// * **leading or trailing whitespace** — invisible in a plain scalar, so
///   emitters quote it, and readers routinely trim it.
///
/// A value carrying any of them makes [`SecretScrubber::scrub_streams`]
/// withhold the stream outright. That is the fail-closed half of the design:
/// the alternative is printing output that *looks* redacted while a
/// re-encoded copy of a private key sits in it.
///
/// Everything outside this set stays on one line through every emitter this
/// code has to deal with, which is why the common single-line API key, JWT or
/// HMAC secret keeps its diagnostics.
pub fn is_reencoding_hazard(value: &str) -> bool {
    value.contains(['\n', '\r', '"', '\'', '\\', '#'])
        || value.contains(": ")
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace)
}

/// The value as JSON would escape it, without the surrounding quotes, or
/// `None` when that is byte-identical to the value itself.
///
/// Covers a validator that reports the offending document as JSON, or as
/// double-quoted YAML: an interior tab becomes `\t`, a control character
/// becomes `\u00NN`.
fn json_escaped(value: &str) -> Option<String> {
    let quoted = serde_json::to_string(value).ok()?;
    let inner = quoted
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))?;
    (inner != value).then(|| inner.to_string())
}

/// The value as single-quoted YAML would write it, without the surrounding
/// quotes: the only escape in that style is a doubled `'`.
fn yaml_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
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

fn collect_service_discovery_secrets(config: &GatewayConfig, out: &mut BTreeSet<String>) {
    for upstream in &config.upstreams {
        for (_field, value) in super::service_discovery::present_secrets(upstream) {
            record_secret(value, out);
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
