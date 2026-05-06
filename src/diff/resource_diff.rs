use std::collections::HashSet;

use crate::config::GatewayConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffAction {
    Add,
    Modify,
    Delete,
}

#[derive(Debug, Clone)]
pub struct FieldChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone)]
pub struct ResourceDiff {
    pub action: DiffAction,
    pub kind: String,
    pub id: String,
    pub namespace: String,
    pub details: Vec<FieldChange>,
}

#[derive(Debug, Clone)]
pub struct UnmanagedResource {
    pub kind: String,
    pub id: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    pub diffs: Vec<ResourceDiff>,
    pub unmanaged: Vec<UnmanagedResource>,
}

#[derive(Debug, Clone, Copy)]
pub enum OwnershipScope<'a> {
    Shared {
        previously_managed: &'a HashSet<String>,
    },
    Exclusive,
}

pub fn compute_diff(desired: &GatewayConfig, actual: &GatewayConfig) -> Vec<ResourceDiff> {
    compute_diff_with_scope(desired, actual, OwnershipScope::Exclusive).diffs
}

/// Compute a diff, honoring ownership constraints.
///
/// When `previously_managed` is `Some`, resources present in `actual` but not in
/// `previously_managed` (and not in `desired`) are classified as *unmanaged*
/// rather than as deletions. This models `shared` ownership: we only touch what
/// this repo has previously applied.
///
/// When `previously_managed` is `None`, all resources in `actual` not in
/// `desired` are emitted as `Delete` actions (the classic `exclusive` mode).
pub fn compute_diff_with_ownership(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    previously_managed: Option<&HashSet<String>>,
) -> DiffResult {
    let scope = match previously_managed {
        Some(previously_managed) => OwnershipScope::Shared { previously_managed },
        None => OwnershipScope::Exclusive,
    };
    compute_diff_with_scope(desired, actual, scope)
}

pub fn compute_diff_with_scope(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    ownership_scope: OwnershipScope<'_>,
) -> DiffResult {
    let mut result = DiffResult::default();

    diff_collection(
        &desired.proxies,
        &actual.proxies,
        "Proxy",
        |p| p.id.clone(),
        |p| p.namespace.clone(),
        ownership_scope,
        &mut result,
    );
    diff_collection(
        &desired.consumers,
        &actual.consumers,
        "Consumer",
        |c| c.id.clone(),
        |c| c.namespace.clone(),
        ownership_scope,
        &mut result,
    );
    diff_collection(
        &desired.upstreams,
        &actual.upstreams,
        "Upstream",
        |u| u.id.clone(),
        |u| u.namespace.clone(),
        ownership_scope,
        &mut result,
    );
    diff_collection(
        &desired.plugin_configs,
        &actual.plugin_configs,
        "PluginConfig",
        |p| p.id.clone(),
        |p| p.namespace.clone(),
        ownership_scope,
        &mut result,
    );

    result
}

pub fn state_key(namespace: &str, kind: &str, id: &str) -> String {
    format!(
        "{}:{}:{kind}:{}",
        STATE_KEY_PREFIX,
        encode_state_key_component(namespace),
        encode_state_key_component(id)
    )
}

pub fn legacy_state_key(namespace: &str, kind: &str, id: &str) -> String {
    format!("{namespace}:{kind}:{id}")
}

pub fn state_key_candidates(namespace: &str, kind: &str, id: &str) -> [String; 2] {
    [
        state_key(namespace, kind, id),
        legacy_state_key(namespace, kind, id),
    ]
}

pub fn state_key_namespace(key: &str) -> Option<String> {
    if let Some((namespace, _kind, _id)) = parse_versioned_state_key(key) {
        return Some(decode_state_key_component(namespace));
    }

    // Legacy keys were stored as raw `<namespace>:<kind>:<id>` strings. Do not
    // percent-decode this branch: a pre-upgrade namespace may legitimately
    // contain literal `%3A` or `%25`, and changing its meaning would mis-scope
    // shared-mode reconciliation.
    let mut parts = key.splitn(3, ':');
    let namespace = parts.next()?;
    let _kind = parts.next()?;
    Some(namespace.to_string())
}

const STATE_KEY_PREFIX: &str = "__gitforgeops_state_key_v2";

fn parse_versioned_state_key(key: &str) -> Option<(&str, &str, &str)> {
    let mut parts = key.splitn(4, ':');
    let prefix = parts.next()?;
    if prefix != STATE_KEY_PREFIX {
        return None;
    }
    let namespace = parts.next()?;
    let kind = parts.next()?;
    let id = parts.next()?;
    if matches!(kind, "Proxy" | "Consumer" | "Upstream" | "PluginConfig") {
        Some((namespace, kind, id))
    } else {
        None
    }
}

fn encode_state_key_component(value: &str) -> String {
    value.replace('%', "%25").replace(':', "%3A")
}

fn decode_state_key_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let first = chars.next();
            let second = chars.next();
            match (first, second) {
                (Some('2'), Some('5')) => out.push('%'),
                (Some('3'), Some('A')) | (Some('3'), Some('a')) => out.push(':'),
                (Some(a), Some(b)) => {
                    out.push('%');
                    out.push(a);
                    out.push(b);
                }
                (Some(a), None) => {
                    out.push('%');
                    out.push(a);
                }
                (None, _) => out.push('%'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn diff_collection<T: serde::Serialize>(
    desired: &[T],
    actual: &[T],
    kind: &str,
    id_fn: impl Fn(&T) -> String,
    ns_fn: impl Fn(&T) -> String,
    ownership_scope: OwnershipScope<'_>,
    result: &mut DiffResult,
) {
    let desired_map: std::collections::HashMap<(String, String), &T> =
        desired.iter().map(|r| ((ns_fn(r), id_fn(r)), r)).collect();
    let actual_map: std::collections::HashMap<(String, String), &T> =
        actual.iter().map(|r| ((ns_fn(r), id_fn(r)), r)).collect();

    for ((namespace, id), desired_res) in &desired_map {
        match actual_map.get(&(namespace.clone(), id.clone())) {
            Some(actual_res) => {
                let details = compare_fields(desired_res, actual_res);
                if !details.is_empty() {
                    result.diffs.push(ResourceDiff {
                        action: DiffAction::Modify,
                        kind: kind.to_string(),
                        id: id.clone(),
                        namespace: namespace.clone(),
                        details,
                    });
                }
            }
            None => {
                result.diffs.push(ResourceDiff {
                    action: DiffAction::Add,
                    kind: kind.to_string(),
                    id: id.clone(),
                    namespace: namespace.clone(),
                    details: Vec::new(),
                });
            }
        }
    }

    for (namespace, id) in actual_map.keys() {
        if desired_map.contains_key(&(namespace.clone(), id.clone())) {
            continue;
        }

        match ownership_scope {
            OwnershipScope::Shared { previously_managed } => {
                let was_managed = state_key_candidates(namespace, kind, id)
                    .iter()
                    .any(|key| previously_managed.contains(key));
                if was_managed {
                    // We previously applied this resource, repo no longer declares
                    // it → delete.
                    result.diffs.push(ResourceDiff {
                        action: DiffAction::Delete,
                        kind: kind.to_string(),
                        id: id.clone(),
                        namespace: namespace.clone(),
                        details: Vec::new(),
                    });
                } else {
                    // Admin-added, never managed by us → leave alone.
                    result.unmanaged.push(UnmanagedResource {
                        kind: kind.to_string(),
                        id: id.clone(),
                        namespace: namespace.clone(),
                    });
                }
            }
            OwnershipScope::Exclusive => {
                // Exclusive mode: everything not in desired gets deleted.
                result.diffs.push(ResourceDiff {
                    action: DiffAction::Delete,
                    kind: kind.to_string(),
                    id: id.clone(),
                    namespace: namespace.clone(),
                    details: Vec::new(),
                });
            }
        }
    }
}

fn compare_fields<T: serde::Serialize>(desired: &T, actual: &T) -> Vec<FieldChange> {
    let desired_val = serde_json::to_value(desired).unwrap_or_default();
    let actual_val = serde_json::to_value(actual).unwrap_or_default();

    let mut changes = Vec::new();
    if desired_val == actual_val {
        return changes;
    }

    if let (serde_json::Value::Object(d_map), serde_json::Value::Object(a_map)) =
        (&desired_val, &actual_val)
    {
        for (key, d_val) in d_map {
            if key == "created_at" || key == "updated_at" {
                continue;
            }
            let a_val = a_map.get(key).unwrap_or(&serde_json::Value::Null);
            if d_val != a_val {
                changes.push(FieldChange {
                    field: key.clone(),
                    old_value: serde_json::to_string(a_val).unwrap_or_default(),
                    new_value: serde_json::to_string(d_val).unwrap_or_default(),
                });
            }
        }

        for (key, a_val) in a_map {
            if key == "created_at" || key == "updated_at" {
                continue;
            }
            if !d_map.contains_key(key) {
                changes.push(FieldChange {
                    field: key.clone(),
                    old_value: serde_json::to_string(a_val).unwrap_or_default(),
                    new_value: "null".to_string(),
                });
            }
        }
    }

    changes
}
