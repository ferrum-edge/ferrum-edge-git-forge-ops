use crate::config::{GatewayConfig, GatewayMode};

use super::bundle::CredentialBundle;
use super::placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};

/// The five credential types ferrum-edge recognizes on a `Consumer`
/// (`ALLOWED_CREDENTIAL_TYPES`). Anything else is stored verbatim and ignored
/// at runtime; the broker still brokers it, it just has no gateway meaning.
pub const KNOWN_CREDENTIAL_TYPES: [&str; 5] =
    ["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"];

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
}

impl ResolveReport {
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
fn current_gateway_mode() -> GatewayMode {
    crate::config::load_env_config().gateway_mode
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
    report_secrets_with_mode(cfg, bundle, current_gateway_mode())
}

/// [`report_secrets`] with the gateway mode supplied explicitly.
pub fn report_secrets_with_mode(
    cfg: &crate::config::GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
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
            walk_and_report(value, &components, bundle, &mode, &mut report)?;
        }
    }
    // Defense-in-depth: detect any duplicate slot strings. With the escape
    // function being injective, structurally-distinct tree locations can't
    // produce the same slot — but if a future refactor breaks the
    // invariant, this catches it before we silently collapse two
    // credentials into one GitHub Env Secret entry.
    detect_slot_collisions(&report)?;
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
    resolve_secrets_with_mode(cfg, bundle, current_gateway_mode())
}

/// [`resolve_secrets`] with the gateway mode supplied explicitly.
pub fn resolve_secrets_with_mode(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
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

    detect_slot_collisions(&report)?;
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
) -> crate::error::Result<()> {
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

    if MIN32_CREDENTIAL_TYPES.contains(&cred_type)
        && placeholder.length_bytes < MIN_ENTROPY_BYTES_FOR_32_CHARS
    {
        return Err(crate::error::Error::Config(format!(
            "credential slot '{slot}': {cred_type} secrets must be at least 32 characters, but \
             'len={}' generates only {} base64url characters. Use 'len={}' or higher (the default \
             len=32 yields 43 characters).",
            placeholder.length_bytes,
            base64_chars(placeholder.length_bytes),
            MIN_ENTROPY_BYTES_FOR_32_CHARS
        )));
    }

    Ok(())
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
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(s) {
                let placeholder = res?;
                let slot = join_slot_components(components);
                let existing = lookup_slot_value(components, &slot, bundle)?;
                let status = classify_status(&placeholder, existing);
                check_generation_constraints(components, &placeholder, &status, mode)?;
                let (namespace, consumer_id, cred_key) = decompose_components(components);
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
                walk_and_report(child_val, &child_components, bundle, mode, report)?;
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let mut child_components = components.to_vec();
                child_components.push(SlotComponent::ArrayIndex(i));
                walk_and_report(item, &child_components, bundle, mode, report)?;
            }
        }
        _ => {}
    }
    Ok(())
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
                check_generation_constraints(components, &placeholder, &status, mode)?;
                let (namespace, consumer_id, cred_key) = decompose_components(components);
                let replacement = existing.cloned();
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
