use std::collections::BTreeMap;

use crate::config::GatewayConfig;

use super::bundle::CredentialBundle;
use super::placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};

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

fn encode_component(c: &SlotComponent<'_>) -> String {
    match c {
        SlotComponent::Literal(s) => escape_slot_component(s),
        SlotComponent::ArrayIndex(n) => format!("[{n}]"),
    }
}

fn join_slot_components(components: &[SlotComponent<'_>]) -> String {
    components
        .iter()
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

/// Build a slot path from the top-level credential key.
///
/// `cred_key` is treated as an opaque literal — exactly how `report_secrets`
/// emits the same component when walking `consumer.credentials`
/// (`BTreeMap<String, String>`, no path semantics). Splitting on `/` here
/// would diverge from the walker: a key like `foo/bar` would round-trip to
/// `<ns>/<id>/foo/bar` instead of the walker's `<ns>/<id>/foo~1bar`, and
/// `gitforgeops rotate` would fail preflight on a slot that exists.
/// Escaping (including `/` → `~1` and `~` → `~0`) is handled by
/// `escape_slot_component` inside `join_slot_components`.
pub fn slot_path(namespace: &str, consumer_id: &str, cred_key: &str) -> String {
    let components = vec![
        SlotComponent::Literal(namespace),
        SlotComponent::Literal(consumer_id),
        SlotComponent::Literal(cred_key),
    ];
    join_slot_components(&components)
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
            walk_and_report(value, &components, bundle, &mut report)?;
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
pub fn resolve_secrets(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
) -> crate::error::Result<ResolveReport> {
    let mut report = ResolveReport::default();

    for consumer in cfg.consumers.iter_mut() {
        let namespace = consumer.namespace.clone();
        let consumer_id = consumer.id.clone();
        let mut replacements: BTreeMap<String, serde_json::Value> = BTreeMap::new();

        for (cred_key, value) in consumer.credentials.iter() {
            let components = vec![
                SlotComponent::Literal(namespace.as_str()),
                SlotComponent::Literal(consumer_id.as_str()),
                SlotComponent::Literal(cred_key.as_str()),
            ];
            walk_and_report(value, &components, bundle, &mut report)?;
        }

        for (cred_key, value) in consumer.credentials.iter() {
            let components = vec![
                SlotComponent::Literal(namespace.as_str()),
                SlotComponent::Literal(consumer_id.as_str()),
                SlotComponent::Literal(cred_key.as_str()),
            ];
            let replaced = walk_and_replace(value.clone(), &components, bundle)?;
            replacements.insert(cred_key.clone(), replaced);
        }

        for (k, v) in replacements {
            consumer.credentials.insert(k, v);
        }
    }

    detect_slot_collisions(&report)?;
    Ok(report)
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
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(s) {
                let placeholder = res?;
                let slot = join_slot_components(components);
                let status = classify_status(&placeholder, bundle.get(&slot));
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
                walk_and_report(child_val, &child_components, bundle, report)?;
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let mut child_components = components.to_vec();
                child_components.push(SlotComponent::ArrayIndex(i));
                walk_and_report(item, &child_components, bundle, report)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk_and_replace(
    value: serde_json::Value,
    components: &[SlotComponent<'_>],
    bundle: &CredentialBundle,
) -> crate::error::Result<serde_json::Value> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(&s) {
                let _placeholder = res?;
                let slot = join_slot_components(components);
                match bundle.get(&slot) {
                    Some(v) => Ok(serde_json::Value::String(v.clone())),
                    None => Ok(serde_json::Value::String(s)),
                }
            } else {
                Ok(serde_json::Value::String(s))
            }
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (child_key, child_val) in map {
                let mut child_components = components.to_vec();
                child_components.push(SlotComponent::Literal(child_key.as_str()));
                out.insert(
                    child_key.clone(),
                    walk_and_replace(child_val, &child_components, bundle)?,
                );
            }
            Ok(serde_json::Value::Object(out))
        }
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                let mut child_components = components.to_vec();
                child_components.push(SlotComponent::ArrayIndex(i));
                out.push(walk_and_replace(item, &child_components, bundle)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        other => Ok(other),
    }
}

/// Split a component slice back into (namespace, consumer_id, joined_cred_key)
/// for the `ResolveResult` record. The first two components are always
/// literal (namespace, consumer_id); the remainder joined by `/` gives a
/// human-readable cred-key path that matches the slot-path encoding for
/// top-level or nested access.
fn decompose_components(components: &[SlotComponent<'_>]) -> (String, String, String) {
    let namespace = match components.first() {
        Some(SlotComponent::Literal(s)) => (*s).to_string(),
        _ => String::new(),
    };
    let consumer_id = match components.get(1) {
        Some(SlotComponent::Literal(s)) => (*s).to_string(),
        _ => String::new(),
    };
    let cred_key = components
        .get(2..)
        .unwrap_or(&[])
        .iter()
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/");
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
