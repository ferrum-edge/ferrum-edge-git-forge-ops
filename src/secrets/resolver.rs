use std::collections::BTreeMap;

use crate::config::GatewayConfig;

use super::bundle::CredentialBundle;
use super::placeholder::{parse_placeholder, PlaceholderAlloc, SecretPlaceholder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotStatus {
    /// Placeholder found a matching value in the bundle; resolved in-place.
    Resolved,
    /// Placeholder wants `alloc=generate` and no existing value — needs allocator.
    NeedsAllocation,
    /// Placeholder wants `alloc=rotate` — will be regenerated on apply.
    NeedsRotation,
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
            .filter(|r| {
                matches!(
                    r.status,
                    SlotStatus::NeedsAllocation | SlotStatus::NeedsRotation
                )
            })
            .collect()
    }

    pub fn missing_required(&self) -> Vec<&ResolveResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.status, SlotStatus::MissingRequired))
            .collect()
    }
}

pub fn slot_path(namespace: &str, consumer_id: &str, cred_key: &str) -> String {
    format!("{namespace}/{consumer_id}/{cred_key}")
}

/// Walk the consumers in `cfg` and replace `${gh-env-secret:...}` placeholders
/// with values from the merged credential bundle.
///
/// Mutates `cfg` in place: for each placeholder, replaces the string with the
/// resolved value (or leaves it alone when the value is missing and alloc is
/// `require`; the caller decides how to react based on the returned report).
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
            walk_and_report(
                value,
                &namespace,
                &consumer_id,
                cred_key,
                bundle,
                &mut report,
            )?;
        }

        for (cred_key, value) in consumer.credentials.iter() {
            let replaced =
                walk_and_replace(value.clone(), &namespace, &consumer_id, cred_key, bundle)?;
            replacements.insert(cred_key.clone(), replaced);
        }

        for (k, v) in replacements {
            consumer.credentials.insert(k, v);
        }
    }

    Ok(report)
}

fn walk_and_report(
    value: &serde_json::Value,
    namespace: &str,
    consumer_id: &str,
    cred_key: &str,
    bundle: &CredentialBundle,
    report: &mut ResolveReport,
) -> crate::error::Result<()> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(s) {
                let placeholder = res?;
                let slot = slot_path(namespace, consumer_id, cred_key);
                let status = classify_status(&placeholder, bundle.get(&slot));
                report.results.push(ResolveResult {
                    consumer_id: consumer_id.to_string(),
                    namespace: namespace.to_string(),
                    cred_key: cred_key.to_string(),
                    slot,
                    placeholder,
                    status,
                });
            }
        }
        serde_json::Value::Object(map) => {
            for (child_key, child_val) in map {
                let child_path = format!("{cred_key}.{child_key}");
                walk_and_report(
                    child_val,
                    namespace,
                    consumer_id,
                    &child_path,
                    bundle,
                    report,
                )?;
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let child_path = format!("{cred_key}[{i}]");
                walk_and_report(item, namespace, consumer_id, &child_path, bundle, report)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn walk_and_replace(
    value: serde_json::Value,
    namespace: &str,
    consumer_id: &str,
    cred_key: &str,
    bundle: &CredentialBundle,
) -> crate::error::Result<serde_json::Value> {
    match value {
        serde_json::Value::String(s) => {
            if let Some(res) = parse_placeholder(&s) {
                let placeholder = res?;
                let slot = slot_path(namespace, consumer_id, cred_key);
                match bundle.get(&slot) {
                    Some(v) => Ok(serde_json::Value::String(v.clone())),
                    None => {
                        // Allocation (generate/rotate) is the allocator's job;
                        // we leave the placeholder in place so the apply path
                        // can act on the report. Require + missing returns the
                        // placeholder too, with a clear error in the report.
                        let _ = placeholder;
                        Ok(serde_json::Value::String(s))
                    }
                }
            } else {
                Ok(serde_json::Value::String(s))
            }
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (child_key, child_val) in map {
                let child_path = format!("{cred_key}.{child_key}");
                out.insert(
                    child_key,
                    walk_and_replace(child_val, namespace, consumer_id, &child_path, bundle)?,
                );
            }
            Ok(serde_json::Value::Object(out))
        }
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                let child_path = format!("{cred_key}[{i}]");
                out.push(walk_and_replace(
                    item,
                    namespace,
                    consumer_id,
                    &child_path,
                    bundle,
                )?);
            }
            Ok(serde_json::Value::Array(out))
        }
        other => Ok(other),
    }
}

fn classify_status(placeholder: &SecretPlaceholder, existing: Option<&String>) -> SlotStatus {
    match (placeholder.alloc, existing) {
        (PlaceholderAlloc::Rotate, _) => SlotStatus::NeedsRotation,
        (_, Some(_)) => SlotStatus::Resolved,
        (PlaceholderAlloc::Generate, None) => SlotStatus::NeedsAllocation,
        (PlaceholderAlloc::Require, None) => SlotStatus::MissingRequired,
    }
}
