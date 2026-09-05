use crate::config::{GatewayConfig, GatewayMode};

use super::bundle::CredentialBundle;
use super::placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};
use super::plugin_config::{classify_plugin_config, render_config_path, ConfigPathComponent};

/// Reserved third slot component for brokered plugin-config strings.
///
/// Consumer slots use their credential type here (`keyauth`, `jwt`, ...), so
/// the marker keeps plugin config in a separate keyspace while preserving the
/// existing `<namespace>/<resource-id>/<kind>/...` bundle shape.
const PLUGIN_CONFIG_SLOT_KIND: &str = "@plugin-config";

/// Credential types whose secret must be at least 32 characters
/// (`jwt.secret`, `hmac_auth.secret`).
pub const MIN32_CREDENTIAL_TYPES: [&str; 2] = ["jwt", "hmac_auth"];

/// Minimum `len=` (entropy bytes) that still yields ≥32 characters once
/// base64url-no-pad encoded: `ceil(24 * 4 / 3) == 32`.
pub const MIN_ENTROPY_BYTES_FOR_32_CHARS: usize = 24;

/// ferrum-edge rejects any credential string longer than 4096 characters.
pub const MAX_CREDENTIAL_VALUE_CHARS: usize = 4096;

/// Sentinel ferrum-edge substitutes for `keyauth.key`, `jwt.secret` and
/// `hmac_auth.secret` on a normal `GET` (only `GET /backup` returns real
/// values). It is reserved: writing it back is rejected by the gateway, so a
/// bundle that contains it was seeded from the wrong endpoint.
pub const REDACTED_SENTINEL: &str = "[REDACTED]";

/// Placeholder emitted for credential values captured by `import`.
/// `require` deliberately refuses to generate a replacement: the operator
/// must seed the exact live value from the private migration bundle.
pub const IMPORT_REQUIRED_PLACEHOLDER: &str = "${gh-env-secret:alloc=require}";

/// What resolution does with a detected credential-array slot remap
/// (see [`check_array_slot_identity`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotRemapPolicy {
    /// Fail resolution. The default, and what every mutating path uses: a
    /// remap silently re-issues a retired credential, and a warning in a CI
    /// log is not a control.
    #[default]
    Refuse,
    /// Record the hazard on [`ResolveReport::slot_remaps`] and continue.
    ///
    /// Two callers want this. `--allow-credential-slot-remap` is the
    /// operator's explicit acknowledgement of the documented
    /// shrink-then-rotate sequence; `plan` and `review` use it because they
    /// render the hazard themselves (and `plan` supplies its own non-zero
    /// exit) instead of aborting with a bare error string.
    Allow,
}

/// Knobs that change resolution's *verdict* without changing what it walks.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolveOptions {
    pub slot_remap: SlotRemapPolicy,
}

impl ResolveOptions {
    /// Report slot remaps instead of failing on them.
    pub fn allowing_slot_remap(allow: bool) -> Self {
        Self {
            slot_remap: if allow {
                SlotRemapPolicy::Allow
            } else {
                SlotRemapPolicy::Refuse
            },
        }
    }
}

/// Whether generation constraints ([`check_generation_constraints`]) abort the
/// walk or are merely reflected in the returned statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstraintMode {
    /// Return `Err` for a placeholder the broker provably cannot satisfy.
    /// Used by `plan`/`diff`/`apply`, where allocation is about to happen.
    Enforce,
    /// Never fail on a generation constraint. Used by the `rotate` preflight,
    /// which walks the whole config to locate one slot and must not be blocked
    /// by an unrelated consumer's unsatisfiable placeholder.
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotStatus {
    /// Placeholder found a matching value in the bundle; resolved in-place.
    Resolved,
    /// Placeholder has no existing value and needs the allocator
    /// (`alloc=generate` or `alloc=rotate`, first apply).
    ///
    /// `alloc=rotate` is treated identically to `alloc=generate` at apply time:
    /// first apply allocates, subsequent applies reuse the stored value.
    /// Rotating an already-allocated slot is an explicit operation via
    /// `gitforgeops rotate` (typically run from the rotate workflow with an
    /// explicit `--recipient`). This avoids redelivering a freshly rotated
    /// credential to whichever user happened to author the most recent
    /// unrelated PR.
    NeedsAllocation,
    /// Placeholder wants `alloc=require` but no value exists — this is an error
    /// at apply time, but we surface it as a report entry first so `plan` can
    /// show it.
    MissingRequired,
}

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub consumer_id: String,
    pub namespace: String,
    pub cred_key: String,
    pub slot: String,
    pub placeholder: SecretPlaceholder,
    pub status: SlotStatus,
}

#[derive(Debug, Clone, Default)]
pub struct ResolveReport {
    pub results: Vec<ResolveResult>,
    /// Non-fatal advisories raised while walking the credential tree.
    ///
    /// These describe the array-slot-identity hazard from [`is_elided`] in the
    /// abstract — entry *position* is the slot identity, so a multi-entry
    /// credential array is order-sensitive — without any evidence that a remap
    /// has actually happened. A steady multi-entry array raises one on every
    /// run, which is exactly why they cannot be fatal. Proven remaps go to
    /// [`Self::slot_remaps`] instead. Each message is echoed to stderr once
    /// per process so it shows up in CI logs even when the caller ignores this
    /// field.
    pub warnings: Vec<String>,
    /// Credential-array shape changes that provably re-own a stored slot.
    ///
    /// Populated when the bundle still holds a value for an entry index the
    /// declared array no longer has: the value has either already been handed
    /// to whichever entry shifted into its index, or is sitting orphaned
    /// waiting for the next grow to resurrect it. Unlike [`Self::warnings`]
    /// this cannot fire in steady state, so it is fatal by default —
    /// resolution returns [`crate::error::Error::CredentialSlotRemap`] unless
    /// the caller passes [`SlotRemapPolicy::Allow`].
    ///
    /// Messages name slots only. A bundle value never appears in one.
    pub slot_remaps: Vec<String>,
    /// `slot → credential type` for every slot in `results`, captured
    /// structurally while walking (the type is the third path component, known
    /// before the slot string is ever joined).
    ///
    /// The allocator consumes this so it does not have to recover the type by
    /// string-splitting the slot back apart; see
    /// [`crate::secrets::allocator::generate_credential_value_typed`].
    pub slot_credential_types: std::collections::BTreeMap<String, String>,
}

impl ResolveReport {
    /// Structurally-captured credential type for `slot`, if this report
    /// produced it.
    pub fn credential_type_for(&self, slot: &str) -> Option<&str> {
        self.slot_credential_types.get(slot).map(String::as_str)
    }

    pub fn needs_allocation(&self) -> Vec<&ResolveResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.status, SlotStatus::NeedsAllocation))
            .collect()
    }

    pub fn missing_required(&self) -> Vec<&ResolveResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.status, SlotStatus::MissingRequired))
            .collect()
    }
}

/// A single slot-path component. `Literal` covers user-controlled names
/// (namespace, consumer id, object keys) and is JSON-Pointer-style escaped
/// so `~`, `/`, and `[` cannot break the encoding. `ArrayIndex` is emitted
/// by the walker for array positions and renders as `[N]` without escape,
/// so it's distinguishable from an object key whose name literally reads
/// `[N]` (the latter becomes `~2N]` once `[` is escaped).
#[derive(Clone, Copy)]
enum SlotComponent<'a> {
    Literal(&'a str),
    ArrayIndex(usize),
}

/// JSON-Pointer-style escape for a single literal slot-path component.
///
/// `~` → `~0`, `/` → `~1`, `[` → `~2`. The `/` escape keeps the component
/// separator unambiguous; `[` escape distinguishes a literal `[0]` object
/// key from the array-index `[0]` emitted by the walker.
///
/// Injective by construction, which keeps distinct credential tree
/// locations mapped to distinct slot strings.
fn escape_slot_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            '[' => out.push_str("~2"),
            _ => out.push(ch),
        }
    }
    out
}

/// Inverse of [`escape_slot_component`]. A trailing lone `~` (impossible in
/// output of the escaper) is passed through verbatim rather than dropped.
fn unescape_slot_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some('2') => out.push('['),
            Some(other) => {
                out.push('~');
                out.push(other);
            }
            None => out.push('~'),
        }
    }
    out
}

/// The credential type (`keyauth`, `basicauth`, …) encoded in a slot string.
///
/// Slot components are `/`-joined with real `/` escaped to `~1`, so a plain
/// `split('/')` is unambiguous: index 0 is the namespace, 1 the consumer id,
/// and 2 the top-level credential key.
pub(crate) fn credential_type_from_slot(slot: &str) -> Option<String> {
    slot.split('/').nth(2).map(unescape_slot_component)
}

fn encode_component(c: &SlotComponent<'_>) -> String {
    match c {
        SlotComponent::Literal(s) => escape_slot_component(s),
        SlotComponent::ArrayIndex(n) => format!("[{n}]"),
    }
}

/// `ArrayIndex(0)` is elided from the canonical slot path.
///
/// ferrum-edge stores every consumer credential as an **array** of entries
/// (`keyauth: [{key: "…"}]`), and `gitforgeops` now normalizes the bare-object
/// form (`keyauth: {key: "…"}`) into that array during assembly. Without this
/// elision the normalization would silently rename every existing slot from
/// `<ns>/<id>/keyauth/key` to `<ns>/<id>/keyauth/[0]/key`, orphaning every
/// value already allocated in `FERRUM_CREDS_BUNDLE*` and re-generating (and
/// re-delivering) credentials that consumers are actively using.
///
/// So index `0` — the only index a normalized single-entry credential can
/// have — renders as the legacy unindexed name, and only index ≥ 1 appends
/// `[N]`:
///
/// ```text
/// keyauth: [{key: K}]            -> <ns>/<id>/keyauth/key
/// keyauth: {key: K}   (legacy)   -> <ns>/<id>/keyauth/key      (same slot)
/// keyauth: [{key: K}, {key: K2}] -> <ns>/<id>/keyauth/key
///                                   <ns>/<id>/keyauth/[1]/key
/// ```
///
/// Injectivity is preserved because index 0 is unique within its parent
/// array, and a literal object key spelled `[0]` escapes its bracket to
/// `~20]`. `detect_slot_collisions` is the backstop if that ever stops
/// holding.
///
/// # Hazard: entry position IS the slot identity
///
/// Nothing about an entry's *content* participates in its slot name — only its
/// index does. So for a multi-entry credential array, deleting or reordering
/// entries silently re-owns stored values:
///
/// ```text
/// before:  keyauth: [{key: A}, {key: B}]
///          A -> <ns>/<id>/keyauth/key        (elided index 0)
///          B -> <ns>/<id>/keyauth/[1]/key
///
/// delete the first entry:
/// after:   keyauth: [{key: B}]
///          B -> <ns>/<id>/keyauth/key        <-- now resolves to A's value
/// ```
///
/// The credential the operator meant to retire is still live, now issued to
/// the surviving entry, and `[1]` is orphaned in the bundle where a later
/// re-grow would resurrect it. A retroactive content-addressed rename is not
/// possible without orphaning every slot already allocated by earlier
/// releases, so the resolver instead *detects* both shapes and reports them
/// through [`ResolveReport::warnings`] (see `check_array_slot_identity`). The
/// safe operation is `gitforgeops rotate --credential …/[N]/…`, which replaces
/// the value in place rather than moving entries around.
fn is_elided(c: &SlotComponent<'_>) -> bool {
    matches!(c, SlotComponent::ArrayIndex(0))
}

fn join_slot_components(components: &[SlotComponent<'_>]) -> String {
    components
        .iter()
        .filter(|c| !is_elided(c))
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

/// Verbatim join that keeps `[0]`. This is the shape emitted by gitforgeops
/// releases between the array-walker landing and index-0 elision; kept as a
/// read-only lookup candidate so those bundles still resolve.
fn join_slot_components_verbatim(components: &[SlotComponent<'_>]) -> String {
    components
        .iter()
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

fn legacy_slot_from_components(
    components: &[SlotComponent<'_>],
    keep_index_zero: bool,
) -> Option<String> {
    if components.len() <= 3 {
        return None;
    }
    let namespace = match components.first() {
        Some(SlotComponent::Literal(s)) => *s,
        _ => return None,
    };
    let consumer_id = match components.get(1) {
        Some(SlotComponent::Literal(s)) => *s,
        _ => return None,
    };
    let top_cred_key = match components.get(2) {
        Some(SlotComponent::Literal(s)) => *s,
        _ => return None,
    };

    let mut path = top_cred_key.to_string();
    for c in components.iter().skip(3) {
        match c {
            SlotComponent::Literal(s) => {
                // Legacy dotted paths are ambiguous once a nested key itself
                // contains a dot or bracket marker.
                if s.contains('.') || s.contains('[') || s.contains(']') {
                    return None;
                }
                path.push('.');
                path.push_str(s);
            }
            SlotComponent::ArrayIndex(0) if !keep_index_zero => {}
            SlotComponent::ArrayIndex(i) => path.push_str(&format!("[{i}]")),
        }
    }
    Some(format!("{namespace}/{consumer_id}/{path}"))
}

/// Read-only lookup order for a credential slot, newest encoding first.
///
/// Only `join_slot_components` (index-0 elided) is ever **written**; the rest
/// exist so a bundle allocated by an older gitforgeops still resolves after
/// an upgrade instead of orphaning and re-allocating.
fn slot_lookup_candidates(components: &[SlotComponent<'_>]) -> Vec<String> {
    let mut candidates = vec![join_slot_components(components)];
    let mut push = |s: String| {
        if !candidates.contains(&s) {
            candidates.push(s);
        }
    };
    push(join_slot_components_verbatim(components));
    if let Some(s) = legacy_slot_from_components(components, false) {
        push(s);
    }
    if let Some(s) = legacy_slot_from_components(components, true) {
        push(s);
    }
    candidates
}

fn lookup_slot_value<'a>(
    components: &[SlotComponent<'_>],
    slot: &str,
    bundle: &'a CredentialBundle,
) -> crate::error::Result<Option<&'a String>> {
    let found = slot_lookup_candidates(components)
        .into_iter()
        .find_map(|candidate| bundle.get(&candidate));

    if let Some(value) = found {
        // `[REDACTED]` is what a plain `GET /consumers/...` returns for
        // `keyauth.key`, `jwt.secret` and `hmac_auth.secret`. If it made it
        // into a bundle, the bundle was seeded from the wrong endpoint (only
        // `GET /backup` returns real values) and pushing it back would be
        // rejected by the gateway — or, worse, quietly install the literal
        // string as the credential.
        if value == REDACTED_SENTINEL {
            return Err(crate::error::Error::Config(format!(
                "credential slot '{slot}' holds the reserved sentinel '{REDACTED_SENTINEL}'. \
                 ferrum-edge redacts keyauth/jwt/hmac_auth secrets on normal GETs; re-seed the \
                 bundle from 'GET /backup' or rotate the slot with 'gitforgeops rotate'."
            )));
        }
        return Ok(Some(value));
    }
    Ok(None)
}

fn lookup_exact_slot_value<'a>(
    slot: &str,
    bundle: &'a CredentialBundle,
) -> crate::error::Result<Option<&'a String>> {
    let found = bundle.get(slot);
    if found.is_some_and(|value| value == REDACTED_SENTINEL) {
        return Err(crate::error::Error::Config(format!(
            "secret slot '{slot}' holds the reserved sentinel '{REDACTED_SENTINEL}'; re-seed the bundle from an unredacted GET /backup source"
        )));
    }
    Ok(found)
}

/// Build a slot path from the CLI `--credential` argument.
///
/// `cred_key` is interpreted as a `/`-separated path matching the walker's
/// emission for ferrum-edge's real credential shapes. Credentials are arrays
/// of entries, and index 0 is elided (see [`is_elided`]), so the first entry
/// of each type is addressed without an index:
///
/// ```text
/// --credential keyauth/key        -> <ns>/<id>/keyauth/key
/// --credential jwt/secret         -> <ns>/<id>/jwt/secret
/// --credential hmac_auth/secret   -> <ns>/<id>/hmac_auth/secret
/// --credential mtls_auth/identity -> <ns>/<id>/mtls_auth/identity
/// --credential basicauth/password -> <ns>/<id>/basicauth/password
/// ```
///
/// A segment spelled exactly `[N]` is an array index, so the second and later
/// entries of a type stay addressable: `--credential keyauth/[1]/key`.
/// `[0]` is accepted and normalizes to the elided form, so
/// `keyauth/[0]/key` and `keyauth/key` name the same slot.
///
/// Limitations, both from `/` being the unescapable separator: a literal `/`
/// inside a single credential key (`foo/bar`, which the walker emits as
/// `<ns>/<id>/foo~1bar`) and a literal object key spelled exactly `[1]` can't
/// be addressed from the CLI. There is no CLI escape syntax because routing a
/// user-typed `~1` through `escape_slot_component` would double-escape the
/// `~` to `~01`. Neither shape occurs in ferrum-edge's credential schema; if
/// you hit it in a custom credential type, rename the key.
pub fn slot_path(namespace: &str, consumer_id: &str, cred_key: &str) -> String {
    let mut components: Vec<SlotComponent<'_>> = vec![
        SlotComponent::Literal(namespace),
        SlotComponent::Literal(consumer_id),
    ];
    for piece in cred_key.split('/') {
        match parse_index_segment(piece) {
            Some(i) => components.push(SlotComponent::ArrayIndex(i)),
            None => components.push(SlotComponent::Literal(piece)),
        }
    }
    join_slot_components(&components)
}

/// Is this credential leaf an *identity* rather than a secret?
///
/// ferrum-edge's credential shapes mix the two in one object:
/// `basicauth: [{username, password}]` and
/// `mtls_auth: [{identity, ...}]`. `username` is the login name the caller
/// presents and `identity` is a certificate CN/SAN/fingerprint — both are
/// public halves of the credential, both have to stay legible in an imported
/// resource file for the config to mean anything, and neither can be
/// generated by the broker. Treating them as secrets would broker values the
/// operator must supply verbatim anyway, and would blank out the one field
/// that tells a reader which credential a diagnostic is about.
///
/// `leaf` is the enclosing object key of the string being classified
/// (`None` when the credential is a bare string with no key). An array index
/// does not change which field a leaf is, so callers carry `leaf` through
/// array recursion unchanged.
///
/// One definition, four callers, deliberately: the resolver (never broker an
/// identity), `import`'s capture walk (never redact one out of the file), the
/// validator-output scrubber (never black out the field that says which
/// credential an error is about) and the pre-resolve security audit
/// ([`crate::diff::security`], never block `apply` on one). Any two of those
/// disagreeing produces a configuration that one command accepts and another
/// refuses.
pub(crate) fn is_identity_credential_leaf(credential_type: &str, leaf: Option<&str>) -> bool {
    matches!(
        (credential_type, leaf),
        ("basicauth", Some("username")) | ("mtls_auth", Some("identity"))
    )
}

/// Capture every string credential leaf under its canonical broker slot and
/// replace it in-place with [`IMPORT_REQUIRED_PLACEHOLDER`].
///
/// Import is the one path where the input contains live backup credentials.
/// Keeping slot derivation beside the ordinary resolver prevents the migration
/// bundle and emitted placeholders from drifting to different encodings.
/// Non-string leaves fail closed because the broker can only store strings.
pub fn capture_and_redact_import_credentials(
    cfg: &mut GatewayConfig,
) -> crate::error::Result<CredentialBundle> {
    let mut captured = CredentialBundle::new();

    for consumer in &mut cfg.consumers {
        let namespace = consumer.namespace.clone();
        let consumer_id = consumer.id.clone();
        for (credential_type, value) in &mut consumer.credentials {
            let mut components = vec![
                SlotComponent::Literal(namespace.as_str()),
                SlotComponent::Literal(consumer_id.as_str()),
                SlotComponent::Literal(credential_type.as_str()),
            ];
            let credential_type = credential_type.clone();
            capture_and_redact_value(
                value,
                &mut components,
                &credential_type,
                None,
                &mut captured,
            )?;
        }
    }

    Ok(captured)
}

/// One non-builtin plugin's config strings that import left in place.
#[derive(Debug, Clone)]
pub struct UnbrokeredPluginConfig {
    pub namespace: String,
    pub plugin_id: String,
    pub plugin_name: String,
    /// Dotted paths, rendered for a human
    /// (`headers.x-vendor-auth`, `servers.[0].upstream_url`).
    pub paths: Vec<String>,
}

/// What [`capture_and_redact_import_plugin_config_secrets`] found.
#[derive(Debug, Clone, Default)]
pub struct PluginConfigCapture {
    /// Slot → live value for every leaf moved into the private bundle.
    pub captured: CredentialBundle,
    /// Per-plugin review lists for non-builtin plugins. Empty when the repo
    /// imported only builtin plugins.
    pub unbrokered: Vec<UnbrokeredPluginConfig>,
}

/// Capture sensitive string leaves from plugin configuration and replace them
/// with broker placeholders before import writes any resource file.
///
/// The gateway's admin backup intentionally returns plugin configs raw. The
/// classifier mirrors its schema-aware projection contract and fails closed
/// for custom plugins, so OIDC/LDAP/Kafka/Redis/collector credentials and
/// arbitrary authorization-header values cannot be committed by import.
pub fn capture_and_redact_import_plugin_config_secrets(
    cfg: &mut GatewayConfig,
) -> crate::error::Result<PluginConfigCapture> {
    let mut capture = PluginConfigCapture::default();
    let captured = &mut capture.captured;

    for plugin in &mut cfg.plugin_configs {
        if plugin.api_spec_id.is_some() {
            continue;
        }
        let classification = classify_plugin_config(&plugin.plugin_name, &plugin.config);
        if !classification.unbrokered.is_empty() {
            capture.unbrokered.push(UnbrokeredPluginConfig {
                namespace: plugin.namespace.clone(),
                plugin_id: plugin.id.clone(),
                plugin_name: plugin.plugin_name.clone(),
                paths: classification
                    .unbrokered
                    .iter()
                    .map(|path| render_config_path(path))
                    .collect(),
            });
        }
        for path in classification.sensitive {
            let slot = plugin_config_slot(&plugin.namespace, &plugin.id, &path);
            let value = plugin_config_value_mut(&mut plugin.config, &path).ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "internal: sensitive plugin config path for slot '{slot}' disappeared during import"
                ))
            })?;
            let serde_json::Value::String(text) = value else {
                continue;
            };
            capture_and_redact_string(text, &slot, captured, "plugin config")?;
        }
    }

    Ok(capture)
}

fn capture_and_redact_value<'a>(
    value: &'a mut serde_json::Value,
    components: &mut Vec<SlotComponent<'a>>,
    credential_type: &str,
    leaf: Option<&str>,
    captured: &mut CredentialBundle,
) -> crate::error::Result<()> {
    // `basicauth[].username` and `mtls_auth[].identity` are the public halves
    // of their credentials (see `is_identity_credential_leaf`). Brokering them
    // would demand a hand-seeded slot for a value that is not secret and blank
    // out the field that says which credential a resource file describes.
    if is_identity_credential_leaf(credential_type, leaf) {
        return Ok(());
    }
    match value {
        serde_json::Value::String(text) => {
            let slot = join_slot_components(components);
            capture_and_redact_string(text, &slot, captured, "credential")?;
        }
        serde_json::Value::Object(fields) => {
            for (key, child) in fields {
                components.push(SlotComponent::Literal(key.as_str()));
                let child_leaf = key.clone();
                capture_and_redact_value(
                    child,
                    components,
                    credential_type,
                    Some(&child_leaf),
                    captured,
                )?;
                components.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                components.push(SlotComponent::ArrayIndex(index));
                // An index does not change which field a leaf is.
                let inherited = leaf.map(str::to_string);
                capture_and_redact_value(
                    child,
                    components,
                    credential_type,
                    inherited.as_deref(),
                    captured,
                )?;
                components.pop();
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            let slot = join_slot_components(components);
            return Err(crate::error::Error::Config(format!(
                "credential slot '{slot}' has a non-string leaf; refusing to import a credential shape that cannot be stored by the broker"
            )));
        }
    }
    Ok(())
}

fn capture_and_redact_string(
    text: &mut String,
    slot: &str,
    captured: &mut CredentialBundle,
    label: &str,
) -> crate::error::Result<()> {
    if text == REDACTED_SENTINEL {
        return Err(crate::error::Error::Config(format!(
            "{label} slot '{slot}' contains the reserved redaction sentinel; import requires an unredacted GET /backup source"
        )));
    }
    if text.starts_with("${gh-env-secret:") {
        // A flat file exported without `--materialize` is already in the safe
        // GitOps representation. Preserve its placeholder; storing the literal
        // placeholder in a bundle would only defer an unresolved-secret bug.
        // Parser details are intentionally suppressed because malformed input
        // can itself contain secret material.
        let parsed = parse_placeholder(text).ok_or_else(|| {
            crate::error::Error::Config(format!(
                "{label} slot '{slot}' contains a malformed gh-env-secret placeholder"
            ))
        })?;
        return parsed.map(|_| ()).map_err(|_| {
            crate::error::Error::Config(format!(
                "{label} slot '{slot}' contains a malformed gh-env-secret placeholder"
            ))
        });
    }
    let original = std::mem::replace(text, IMPORT_REQUIRED_PLACEHOLDER.to_string());
    if captured.insert(slot.to_string(), original).is_some() {
        return Err(crate::error::Error::Config(format!(
            "secret slot '{slot}' is produced by multiple imported leaves"
        )));
    }
    Ok(())
}

fn plugin_config_slot(namespace: &str, plugin_id: &str, path: &[ConfigPathComponent]) -> String {
    let mut pieces = vec![
        escape_slot_component(namespace),
        escape_slot_component(plugin_id),
        escape_slot_component(PLUGIN_CONFIG_SLOT_KIND),
        "config".to_string(),
    ];
    pieces.extend(path.iter().map(|part| match part {
        ConfigPathComponent::Key(key) => escape_slot_component(key),
        ConfigPathComponent::Index(index) => format!("[{index}]"),
    }));
    pieces.join("/")
}

fn plugin_config_cred_key(path: &[ConfigPathComponent]) -> String {
    let mut pieces = vec![PLUGIN_CONFIG_SLOT_KIND.to_string(), "config".to_string()];
    pieces.extend(path.iter().map(|part| match part {
        ConfigPathComponent::Key(key) => escape_slot_component(key),
        ConfigPathComponent::Index(index) => format!("[{index}]"),
    }));
    pieces.join("/")
}

fn plugin_config_value_mut<'a>(
    mut value: &'a mut serde_json::Value,
    path: &[ConfigPathComponent],
) -> Option<&'a mut serde_json::Value> {
    for part in path {
        value = match part {
            ConfigPathComponent::Key(key) => value.as_object_mut()?.get_mut(key)?,
            ConfigPathComponent::Index(index) => value.as_array_mut()?.get_mut(*index)?,
        };
    }
    Some(value)
}

/// `"[12]"` → `Some(12)`; anything else → `None`.
fn parse_index_segment(piece: &str) -> Option<usize> {
    piece
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse::<usize>().ok())
}

/// Gateway mode for the current process, read from `FERRUM_GATEWAY_MODE`.
///
/// The mode-taking `*_with_mode` variants exist so tests (and any caller that
/// already has an `EnvConfig` in hand) don't have to go through the process
/// environment. `main.rs` calls the two-argument forms, whose signatures stay
/// stable.
fn current_gateway_mode() -> crate::error::Result<GatewayMode> {
    Ok(crate::config::load_env_config()?.gateway_mode)
}

/// Walk consumers and produce a [`ResolveReport`] **without mutating** `cfg`.
///
/// Use this in contexts where the caller must preserve placeholder strings in
/// `cfg` (notably file-mode apply, which serializes `cfg` to a YAML that gets
/// committed to the repo). `resolve_secrets` is the right function when the
/// caller wants placeholders replaced with bundle values in-memory.
pub fn report_secrets(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
) -> crate::error::Result<ResolveReport> {
    report_secrets_with_mode(cfg, bundle, current_gateway_mode()?)
}

/// [`report_secrets`] with the slot-remap verdict supplied explicitly.
pub fn report_secrets_with_options(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
    options: ResolveOptions,
) -> crate::error::Result<ResolveReport> {
    report_secrets_with_mode_inner(
        cfg,
        bundle,
        current_gateway_mode()?,
        ConstraintMode::Enforce,
        options,
    )
}

/// [`report_secrets`] that never fails on a *generation constraint*.
///
/// Same signature and return type as [`report_secrets`]; the only difference
/// is that placeholders the broker provably cannot generate
/// ([`check_generation_constraints`]) are reported as ordinary statuses rather
/// than returned as an `Err`.
///
/// This exists for the `rotate` preflight. `rotate` targets one specific slot,
/// but the preflight walks the *whole* assembled config to find it — so an
/// unrelated consumer holding, say, a `len=16` `jwt` generate placeholder
/// would abort a rotation that has nothing to do with it. Structural errors
/// (malformed placeholders, `[REDACTED]` bundle values, slot collisions) are
/// still hard failures in both variants, because those make the report itself
/// untrustworthy.
///
/// `plan`/`diff`/`apply` keep using strict [`report_secrets`]: there the
/// constraint really is fatal, since apply would otherwise write a GitHub
/// Environment Secret holding a value the gateway rejects.
pub fn report_secrets_lenient(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
) -> crate::error::Result<ResolveReport> {
    report_secrets_with_mode_inner(
        cfg,
        bundle,
        current_gateway_mode()?,
        ConstraintMode::ReportOnly,
        ResolveOptions::default(),
    )
}

/// [`report_secrets`] with the gateway mode supplied explicitly.
pub fn report_secrets_with_mode(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
) -> crate::error::Result<ResolveReport> {
    report_secrets_with_mode_and_options(cfg, bundle, mode, ResolveOptions::default())
}

/// [`report_secrets`] with both the gateway mode and the slot-remap verdict
/// supplied explicitly.
pub fn report_secrets_with_mode_and_options(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
    options: ResolveOptions,
) -> crate::error::Result<ResolveReport> {
    report_secrets_with_mode_inner(cfg, bundle, mode, ConstraintMode::Enforce, options)
}

fn report_secrets_with_mode_inner(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
    constraints: ConstraintMode,
    options: ResolveOptions,
) -> crate::error::Result<ResolveReport> {
    let mut report = ResolveReport::default();
    for consumer in &cfg.consumers {
        let namespace = &consumer.namespace;
        let consumer_id = &consumer.id;
        for (cred_key, value) in &consumer.credentials {
            let components = vec![
                SlotComponent::Literal(namespace.as_str()),
                SlotComponent::Literal(consumer_id.as_str()),
                SlotComponent::Literal(cred_key.as_str()),
            ];
            walk_and_report(value, &components, bundle, &mode, constraints, &mut report)?;
        }
    }
    for plugin in &cfg.plugin_configs {
        let mut path = Vec::new();
        walk_plugin_and_report(
            &plugin.config,
            &plugin.namespace,
            &plugin.id,
            &mut path,
            bundle,
            &mut report,
        )?;
    }
    // Defense-in-depth: detect any duplicate slot strings. With the escape
    // function being injective, structurally-distinct tree locations can't
    // produce the same slot — but if a future refactor breaks the
    // invariant, this catches it before we silently collapse two
    // credentials into one GitHub Env Secret entry.
    detect_slot_collisions(&report)?;
    enforce_slot_remap_policy(&report, &options)?;
    Ok(report)
}

/// Walk the consumers in `cfg` and replace `${gh-env-secret:...}` placeholders
/// with values from the merged credential bundle.
///
/// Mutates `cfg` in place:
///   - `alloc=require` with a bundle match: replaced.
///   - `alloc=generate` with a bundle match: replaced (existing value reused).
///   - `alloc=rotate` with a bundle match: replaced. `rotate` is treated
///     identically to `generate` at apply time — once allocated, the value is
///     stable across applies. Re-rotation is explicit via `gitforgeops rotate`
///     (the dedicated workflow with its own `--recipient`); the earlier
///     auto-rotate-on-every-apply behavior meant any merged PR would
///     redeliver every persistent rotate slot to that PR's author, even
///     when the credential belonged to an unrelated consumer.
///   - Missing slot: placeholder stays; the report tells the caller why.
///
/// # Read-modify-write hazard
///
/// ferrum-edge treats an omitted credential type asymmetrically on write:
/// omitting `keyauth`, `jwt`, `hmac_auth` or `mtls_auth` **deletes** the
/// stored entries, while omitting `basicauth` or any unrecognized type
/// **preserves** them. So a repo YAML that drops a `keyauth` block silently
/// revokes those API keys on the next apply, but dropping a `basicauth` block
/// leaves the password in place and gitforgeops will report it as unmanaged
/// drift forever. Removing a credential you actually want gone therefore
/// needs an explicit empty array (`keyauth: []`) for the delete-on-omit
/// types, and a gateway-side removal for `basicauth`.
pub fn resolve_secrets(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
) -> crate::error::Result<ResolveReport> {
    resolve_secrets_with_mode(cfg, bundle, current_gateway_mode()?)
}

/// [`resolve_secrets`] with the slot-remap verdict supplied explicitly.
pub fn resolve_secrets_with_options(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
    options: ResolveOptions,
) -> crate::error::Result<ResolveReport> {
    resolve_secrets_with_mode_and_options(cfg, bundle, current_gateway_mode()?, options)
}

/// [`resolve_secrets`] with the gateway mode supplied explicitly.
pub fn resolve_secrets_with_mode(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
) -> crate::error::Result<ResolveReport> {
    resolve_secrets_with_mode_and_options(cfg, bundle, mode, ResolveOptions::default())
}

/// [`resolve_secrets`] with both the gateway mode and the slot-remap verdict
/// supplied explicitly.
pub fn resolve_secrets_with_mode_and_options(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
    options: ResolveOptions,
) -> crate::error::Result<ResolveReport> {
    let mut report = ResolveReport::default();

    for consumer in cfg.consumers.iter_mut() {
        let namespace = consumer.namespace.clone();
        let consumer_id = consumer.id.clone();
        for (cred_key, value) in consumer.credentials.iter_mut() {
            let mut components = vec![
                SlotComponent::Literal(namespace.as_str()),
                SlotComponent::Literal(consumer_id.as_str()),
                SlotComponent::Literal(cred_key.as_str()),
            ];
            walk_report_and_replace(value, &mut components, bundle, &mode, &mut report)?;
        }
    }

    for plugin in cfg.plugin_configs.iter_mut() {
        let namespace = plugin.namespace.clone();
        let plugin_id = plugin.id.clone();
        let mut path = Vec::new();
        walk_plugin_report_and_replace(
            &mut plugin.config,
            &namespace,
            &plugin_id,
            &mut path,
            bundle,
            &mut report,
        )?;
    }

    detect_slot_collisions(&report)?;
    enforce_slot_remap_policy(&report, &options)?;
    Ok(report)
}

/// Reject `alloc=generate` / `alloc=rotate` placeholders the broker provably
/// cannot satisfy, at resolve time — so `plan`/`diff` surface the problem
/// before `apply` writes a GitHub Environment Secret holding a value the
/// gateway will refuse.
///
/// Only fires for slots that would actually be allocated
/// ([`SlotStatus::NeedsAllocation`]); an already-allocated slot keeps
/// resolving from the bundle whatever its shape.
///
/// Constraints, all from ferrum-edge's `Consumer::validate_fields()`:
///
/// * `basicauth` + **file mode** — a file-mode gateway hard-rejects a
///   plaintext `password`, and only the admin API hashes one on write.
/// * `basicauth/…/password_hash` — the hash is
///   `hmac_sha256:<64 lowercase hex>` computed under the gateway's
///   server-wide `FERRUM_BASIC_AUTH_HMAC_SECRET`, which gitforgeops does not
///   have. Random bytes can never be a valid hash, in either mode.
/// * `jwt` / `hmac_auth` — secrets must be ≥32 characters, so `len=` must be
///   at least [`MIN_ENTROPY_BYTES_FOR_32_CHARS`] entropy bytes.
///
/// `mtls_auth.identity` is *also* not brokerable (it has to match a real
/// certificate's CN/SAN/fingerprint), but it is left as a documented footgun
/// rather than a hard error: unlike basicauth there is no mode in which a
/// generated value is correct, so anyone writing `alloc=generate` there has
/// already gone out of their way, and failing existing configs closed on
/// upgrade would be worse than the gateway's own rejection message.
fn check_generation_constraints(
    components: &[SlotComponent<'_>],
    placeholder: &SecretPlaceholder,
    status: &SlotStatus,
    mode: &GatewayMode,
    constraints: ConstraintMode,
) -> crate::error::Result<()> {
    if matches!(constraints, ConstraintMode::ReportOnly) {
        return Ok(());
    }
    if !matches!(status, SlotStatus::NeedsAllocation) {
        return Ok(());
    }
    let slot = join_slot_components(components);
    let cred_type = match components.get(2) {
        Some(SlotComponent::Literal(s)) => *s,
        _ => return Ok(()),
    };
    let leaf = match components.last() {
        Some(SlotComponent::Literal(s)) => *s,
        _ => "",
    };

    if cred_type == "basicauth" {
        if leaf == "password_hash" {
            return Err(crate::error::Error::Config(format!(
                "credential slot '{slot}': the broker cannot generate a basicauth password_hash. \
                 ferrum-edge expects 'hmac_sha256:<64 lowercase hex>' computed with the gateway's \
                 FERRUM_BASIC_AUTH_HMAC_SECRET, which gitforgeops does not have. Set the hash \
                 manually, or use a plaintext 'password' against an api-mode gateway and let the \
                 gateway hash it."
            )));
        }
        if matches!(mode, GatewayMode::File) {
            return Err(crate::error::Error::Config(format!(
                "credential slot '{slot}': file-mode gateways require password_hash; the broker \
                 cannot compute hmac_sha256 hashes without the gateway's \
                 FERRUM_BASIC_AUTH_HMAC_SECRET — set the hash manually or use api mode \
                 (FERRUM_GATEWAY_MODE=api), where the admin API hashes a plaintext password on \
                 write."
            )));
        }
    }

    check_min_entropy(&slot, cred_type, placeholder.length_bytes)?;

    Ok(())
}

/// The one implementation of ferrum-edge's ≥32-character secret floor for
/// `jwt` / `hmac_auth`.
///
/// Both the plan-time resolver check ([`check_generation_constraints`]) and
/// the generate-time allocator check
/// ([`crate::secrets::allocator::generate_credential_value_typed`]) call this,
/// so the rule and its wording live in exactly one place. Pure: no I/O, no
/// randomness — it only decides whether `length_bytes` entropy bytes can
/// base64url-encode to at least 32 characters for this credential type.
pub(crate) fn check_min_entropy(
    slot: &str,
    cred_type: &str,
    length_bytes: usize,
) -> crate::error::Result<()> {
    if MIN32_CREDENTIAL_TYPES.contains(&cred_type) && length_bytes < MIN_ENTROPY_BYTES_FOR_32_CHARS
    {
        return Err(crate::error::Error::Config(format!(
            "credential slot '{slot}': {cred_type} secrets must be at least 32 characters, but \
             'len={length_bytes}' generates only {} base64url characters. Use \
             'len={MIN_ENTROPY_BYTES_FOR_32_CHARS}' or higher (the default len=32 yields 43 \
             characters).",
            base64_chars(length_bytes),
        )));
    }
    Ok(())
}

/// Does this credential subtree contain at least one `${gh-env-secret:…}`
/// placeholder? Used to decide whether array-slot advisories are relevant —
/// an array of literal credentials has no brokered slots to shift.
///
/// A malformed placeholder counts as present; the walker reports the parse
/// error on its own pass.
fn contains_placeholder(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => parse_placeholder(s).is_some(),
        serde_json::Value::Object(map) => map.values().any(contains_placeholder),
        serde_json::Value::Array(items) => items.iter().any(contains_placeholder),
        _ => false,
    }
}

/// Slot-identity findings for one credential **array** node.
///
/// Slot identity is positional (see [`is_elided`]): entry 0 owns the elided
/// slot, entry 1 owns `[1]`, and so on. Nothing in the entry's own content
/// participates in the slot name, which produces two findings of very
/// different weight.
///
/// * **Order is identity** ([`ResolveReport::warnings`], advisory) — a
///   brokered array with more than one entry is order-sensitive: reordering
///   it, or prepending to it, re-owns stored values. That hazard is real but
///   *undetectable from the document*. A reorder leaves the array length, the
///   bundle keys and every slot status byte-identical to steady state, and a
///   prepend is indistinguishable from an append. Promoting this to an error
///   would therefore mean refusing every multi-entry brokered credential
///   forever, so it stays a warning and the safe operation is named in it.
///
/// * **Orphaned slot** ([`ResolveReport::slot_remaps`], fatal by default) —
///   the bundle still holds a value for an entry index the array no longer
///   has. This *is* evidence: the array shrank. Either the survivor at the
///   vacated index inherited a credential the operator meant to retire, or
///   the value sits unreferenced until a later grow resurrects it for a new
///   entry. It cannot occur in steady state, so it is refused unless the
///   caller passes [`SlotRemapPolicy::Allow`].
///
/// The orphan scan runs regardless of `brokered`, because an array that lost
/// its last placeholder is exactly the shrink case.
fn check_array_slot_identity(
    components: &[SlotComponent<'_>],
    items: &[serde_json::Value],
    bundle: &CredentialBundle,
    report: &mut ResolveReport,
) {
    let prefix = join_slot_components(components);
    let brokered = items.iter().any(contains_placeholder);

    if brokered && items.len() > 1 {
        push_warning(
            report,
            format!(
                "credential array '{prefix}' has {} entries and entry ORDER is the slot identity \
                 (entry 0 uses the unindexed slot, later entries use '[1]', '[2]', …). Removing or \
                 reordering an entry reassigns the retired slot's value to whichever entry shifts \
                 into its index. Rotate with 'gitforgeops rotate --credential' instead of deleting \
                 entries.",
                items.len()
            ),
        );
    }

    let scan_prefix = format!("{prefix}/");
    for slot in bundle.keys() {
        let Some(rest) = slot.strip_prefix(&scan_prefix) else {
            continue;
        };
        let index = entry_index_of_suffix(rest);
        if index >= items.len() {
            push_slot_remap(
                report,
                format!(
                    "credential slot '{slot}' is orphaned: the credential bundle still holds a \
                     value for it, but array '{prefix}' now has {} entr{} (entry index {index} no \
                     longer exists). Slot identity is positional, so the entry that shifted into \
                     a vacated index has inherited a retired credential, and re-growing the array \
                     would resurrect this value for a new entry. Rotate the slot in place first \
                     ('gitforgeops rotate --consumer <id> --credential <type>/[{index}]/<key>'), \
                     then remove the entry — or pass --allow-credential-slot-remap to accept the \
                     reassignment.",
                    items.len(),
                    if items.len() == 1 { "y" } else { "ies" }
                ),
            );
        }
    }
}

/// Turn detected remaps into the resolution verdict.
///
/// Called at the end of every walk so `plan`, `apply`, `review`,
/// `export --materialize` and `rotate` all reach the same conclusion from the
/// same evidence, rather than each entrypoint re-deriving it.
fn enforce_slot_remap_policy(
    report: &ResolveReport,
    options: &ResolveOptions,
) -> crate::error::Result<()> {
    if report.slot_remaps.is_empty() || matches!(options.slot_remap, SlotRemapPolicy::Allow) {
        return Ok(());
    }
    Err(crate::error::Error::CredentialSlotRemap(format!(
        "Refusing to resolve credentials: {} credential slot(s) would be reassigned by a \
         credential-array shape change:\n  {}",
        report.slot_remaps.len(),
        report.slot_remaps.join("\n  ")
    )))
}

/// Entry index a bundle-slot suffix belongs to: `"[2]/key"` → 2, and anything
/// else → 0, since index 0 renders without its bracket (see [`is_elided`]).
fn entry_index_of_suffix(rest: &str) -> usize {
    rest.split('/')
        .next()
        .and_then(parse_index_segment)
        .unwrap_or(0)
}

/// Record a warning once per report and echo it to stderr the first time this
/// process sees that exact text, so a `plan` that resolves the same config
/// several times doesn't repeat itself.
fn push_warning(report: &mut ResolveReport, message: String) {
    if report.warnings.contains(&message) {
        return;
    }
    if warn_once(&message) {
        eprintln!("Warning: {message}");
    }
    report.warnings.push(message);
}

/// [`push_warning`] for a proven remap. Deduplicated and echoed the same way,
/// but recorded where the callers look for something that blocks.
fn push_slot_remap(report: &mut ResolveReport, message: String) {
    if report.slot_remaps.contains(&message) {
        return;
    }
    if warn_once(&message) {
        eprintln!("Credential slot remap: {message}");
    }
    report.slot_remaps.push(message);
}

fn warn_once(message: &str) -> bool {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    match SEEN.get_or_init(|| Mutex::new(HashSet::new())).lock() {
        Ok(mut seen) => seen.insert(message.to_string()),
        // A poisoned mutex only costs us deduplication.
        Err(_) => true,
    }
}

/// Character count of `n` bytes encoded as base64url without padding.
pub(crate) fn base64_chars(n: usize) -> usize {
    n.div_ceil(3) * 4 - (3 - n % 3) % 3
}

/// Detect duplicate slot strings within a single resolve report. Each report
/// entry corresponds to a distinct credential tree location; if two entries
/// share a slot, two distinct credentials would overwrite each other in the
/// same GitHub Env Secret slot and resolve to the same bundle value. Under
/// the current escaped-component scheme this should never fire, but it's
/// cheap defense-in-depth against future refactors that could break the
/// injectivity invariant.
fn detect_slot_collisions(report: &ResolveReport) -> crate::error::Result<()> {
    use std::collections::BTreeMap;
    let mut seen: BTreeMap<&str, Vec<(&str, &str, &str)>> = BTreeMap::new();
    for r in &report.results {
        seen.entry(r.slot.as_str()).or_default().push((
            r.namespace.as_str(),
            r.consumer_id.as_str(),
            r.cred_key.as_str(),
        ));
    }
    for (slot, sources) in seen {
        if sources.len() > 1 {
            let detail = sources
                .iter()
                .map(|(ns, c, k)| format!("{ns}/{c}: {k}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(crate::error::Error::Config(format!(
                "credential slot '{slot}' is produced by {} distinct credential paths ({detail}); two credentials would share one GitHub Env Secret entry",
                sources.len()
            )));
        }
    }
    Ok(())
}

fn walk_and_report(
    value: &serde_json::Value,
    components: &[SlotComponent<'_>],
    bundle: &CredentialBundle,
    mode: &GatewayMode,
    constraints: ConstraintMode,
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(s) {
                let placeholder = res?;
                let slot = join_slot_components(components);
                let existing = lookup_slot_value(components, &slot, bundle)?;
                let status = classify_status(&placeholder, existing);
                check_generation_constraints(components, &placeholder, &status, mode, constraints)?;
                let (namespace, consumer_id, cred_key) = decompose_components(components);
                record_credential_type(report, &slot, components);
                report.results.push(ResolveResult {
                    consumer_id,
                    namespace,
                    cred_key,
                    slot,
                    placeholder,
                    status,
                });
            }
        }
        serde_json::Value::Object(map) => {
            for (child_key, child_val) in map {
                let mut child_components = components.to_vec();
                child_components.push(SlotComponent::Literal(child_key.as_str()));
                walk_and_report(
                    child_val,
                    &child_components,
                    bundle,
                    mode,
                    constraints,
                    report,
                )?;
            }
        }
        serde_json::Value::Array(items) => {
            check_array_slot_identity(components, items, bundle, report);
            for (i, item) in items.iter().enumerate() {
                let mut child_components = components.to_vec();
                child_components.push(SlotComponent::ArrayIndex(i));
                walk_and_report(item, &child_components, bundle, mode, constraints, report)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk_plugin_and_report(
    value: &serde_json::Value,
    namespace: &str,
    plugin_id: &str,
    path: &mut Vec<ConfigPathComponent>,
    bundle: &CredentialBundle,
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(text) => {
            if let Some(parsed) = parse_placeholder(text) {
                let placeholder = parsed?;
                let slot = plugin_config_slot(namespace, plugin_id, path);
                let existing = lookup_exact_slot_value(&slot, bundle)?;
                let status = classify_status(&placeholder, existing);
                report
                    .slot_credential_types
                    .insert(slot.clone(), PLUGIN_CONFIG_SLOT_KIND.to_string());
                report.results.push(ResolveResult {
                    consumer_id: plugin_id.to_string(),
                    namespace: namespace.to_string(),
                    cred_key: plugin_config_cred_key(path),
                    slot,
                    placeholder,
                    status,
                });
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                path.push(ConfigPathComponent::Key(key.clone()));
                walk_plugin_and_report(child, namespace, plugin_id, path, bundle, report)?;
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                walk_plugin_and_report(child, namespace, plugin_id, path, bundle, report)?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

/// Capture the credential type (third slot component) structurally, before it
/// is flattened into the slot string. See
/// [`ResolveReport::slot_credential_types`].
fn record_credential_type(
    report: &mut ResolveReport,
    slot: &str,
    components: &[SlotComponent<'_>],
) {
    if let Some(SlotComponent::Literal(cred_type)) = components.get(2) {
        report
            .slot_credential_types
            .insert(slot.to_string(), (*cred_type).to_string());
    }
}

fn walk_report_and_replace<'a>(
    value: &'a mut serde_json::Value,
    components: &mut Vec<SlotComponent<'a>>,
    bundle: &CredentialBundle,
    mode: &GatewayMode,
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(s) {
                let placeholder = res?;
                let slot = join_slot_components(components);
                let existing = lookup_slot_value(components, &slot, bundle)?;
                let status = classify_status(&placeholder, existing);
                check_generation_constraints(
                    components,
                    &placeholder,
                    &status,
                    mode,
                    ConstraintMode::Enforce,
                )?;
                let (namespace, consumer_id, cred_key) = decompose_components(components);
                let replacement = existing.cloned();
                record_credential_type(report, &slot, components);
                report_push(
                    report,
                    placeholder,
                    status,
                    &slot,
                    namespace,
                    consumer_id,
                    cred_key,
                );
                if let Some(v) = replacement {
                    *s = v;
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (child_key, child_val) in map.iter_mut() {
                components.push(SlotComponent::Literal(child_key.as_str()));
                walk_report_and_replace(child_val, components, bundle, mode, report)?;
                components.pop();
            }
        }
        serde_json::Value::Array(items) => {
            check_array_slot_identity(components, items, bundle, report);
            for (i, item) in items.iter_mut().enumerate() {
                components.push(SlotComponent::ArrayIndex(i));
                walk_report_and_replace(item, components, bundle, mode, report)?;
                components.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk_plugin_report_and_replace(
    value: &mut serde_json::Value,
    namespace: &str,
    plugin_id: &str,
    path: &mut Vec<ConfigPathComponent>,
    bundle: &CredentialBundle,
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(text) => {
            if let Some(parsed) = parse_placeholder(text) {
                let placeholder = parsed?;
                let slot = plugin_config_slot(namespace, plugin_id, path);
                let existing = lookup_exact_slot_value(&slot, bundle)?;
                let status = classify_status(&placeholder, existing);
                report
                    .slot_credential_types
                    .insert(slot.clone(), PLUGIN_CONFIG_SLOT_KIND.to_string());
                report.results.push(ResolveResult {
                    consumer_id: plugin_id.to_string(),
                    namespace: namespace.to_string(),
                    cred_key: plugin_config_cred_key(path),
                    slot,
                    placeholder,
                    status,
                });
                if let Some(replacement) = existing {
                    *text = replacement.clone();
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(ConfigPathComponent::Key(key.clone()));
                walk_plugin_report_and_replace(child, namespace, plugin_id, path, bundle, report)?;
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                walk_plugin_report_and_replace(child, namespace, plugin_id, path, bundle, report)?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

fn report_push(
    report: &mut ResolveReport,
    placeholder: SecretPlaceholder,
    status: SlotStatus,
    slot: &str,
    namespace: String,
    consumer_id: String,
    cred_key: String,
) {
    report.results.push(ResolveResult {
        consumer_id,
        namespace,
        cred_key,
        slot: slot.to_string(),
        placeholder,
        status,
    });
}

/// Split a component slice back into (namespace, consumer_id, joined_cred_key)
/// for the `ResolveResult` record. The first two components are always
/// literal (namespace, consumer_id); the remainder joined by `/` gives a
/// human-readable cred-key path that matches the slot-path encoding for
/// top-level or nested access — including the index-0 elision, so a
/// `keyauth: [{key: …}]` credential reports `cred_key: "keyauth/key"` and can
/// be pasted straight into `gitforgeops rotate --credential`.
fn decompose_components(components: &[SlotComponent<'_>]) -> (String, String, String) {
    let namespace = match components.first() {
        Some(SlotComponent::Literal(s)) => (*s).to_string(),
        _ => String::new(),
    };
    let consumer_id = match components.get(1) {
        Some(SlotComponent::Literal(s)) => (*s).to_string(),
        _ => String::new(),
    };
    let cred_key = join_slot_components(components.get(2..).unwrap_or(&[]));
    (namespace, consumer_id, cred_key)
}

fn classify_status(placeholder: &SecretPlaceholder, existing: Option<&String>) -> SlotStatus {
    // `alloc=rotate` behaves like `alloc=generate` at apply time: allocate if
    // no value, reuse otherwise. Re-rotation is an explicit `gitforgeops
    // rotate` operation; auto-rotate-on-every-apply was removed because it
    // redelivered every persistent rotate slot to the latest merger even when
    // their PR didn't touch the consumer.
    match (placeholder.alloc, existing) {
        (_, Some(_)) => SlotStatus::Resolved,
        (PlaceholderAlloc::Generate | PlaceholderAlloc::Rotate, None) => {
            SlotStatus::NeedsAllocation
        }
        (PlaceholderAlloc::Require, None) => SlotStatus::MissingRequired,
    }
}
