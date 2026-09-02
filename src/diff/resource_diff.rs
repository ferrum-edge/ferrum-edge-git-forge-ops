use std::collections::HashSet;

use crate::config::GatewayConfig;

/// Exclude only unresolved broker-controlled leaves from a live comparison
/// when the caller has no secret bundle and cannot materialize desired slots.
///
/// Matching Consumer credentials and PluginConfig config values are aligned
/// leaf-by-leaf. Literal siblings, extra live entries, shape differences,
/// adds/deletes, and every nonsecret field remain visible, so review loses no
/// actionable drift signal beyond exact values it cannot authoritatively know.
pub fn mask_indeterminate_secret_values(desired: &GatewayConfig, actual: &mut GatewayConfig) {
    for live in &mut actual.consumers {
        if let Some(expected) = desired
            .consumers
            .iter()
            .find(|candidate| candidate.namespace == live.namespace && candidate.id == live.id)
        {
            for (credential_type, desired_value) in &expected.credentials {
                if let Some(live_value) = live.credentials.get_mut(credential_type) {
                    mask_placeholder_leaves(desired_value, live_value);
                }
            }
        }
    }

    for live in &mut actual.plugin_configs {
        if let Some(expected) = desired
            .plugin_configs
            .iter()
            .find(|candidate| candidate.namespace == live.namespace && candidate.id == live.id)
        {
            mask_placeholder_leaves(&expected.config, &mut live.config);
        }
    }
}

fn mask_placeholder_leaves(desired: &serde_json::Value, live: &mut serde_json::Value) {
    match (desired, live) {
        (serde_json::Value::String(expected), serde_json::Value::String(actual))
            if matches!(crate::secrets::parse_placeholder(expected), Some(Ok(_))) =>
        {
            *actual = expected.clone();
        }
        (serde_json::Value::Object(expected), serde_json::Value::Object(actual)) => {
            for (key, expected_child) in expected {
                if let Some(actual_child) = actual.get_mut(key) {
                    mask_placeholder_leaves(expected_child, actual_child);
                }
            }
        }
        (serde_json::Value::Array(expected), serde_json::Value::Array(actual)) => {
            for (expected_child, actual_child) in expected.iter().zip(actual.iter_mut()) {
                mask_placeholder_leaves(expected_child, actual_child);
            }
        }
        _ => {}
    }
}

/// Diff fields whose values must never be rendered verbatim to stdout/logs.
pub fn is_sensitive_diff_field(kind: &str, field: &str) -> bool {
    matches!(
        (kind, field),
        ("Consumer", "credentials") | ("PluginConfig", "config")
    )
}

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

/// A live resource the gateway's OpenAPI-spec ingestion owns (`api_spec_id`
/// is set).
///
/// These have a third owner — neither this repo nor a human admin, but the
/// `/api-specs` importer, which re-provisions them atomically from the spec
/// document. gitforgeops reports them and stays off them: a Modify would be
/// reverted on the next spec import, and a Delete would silently break the
/// spec's contract.
#[derive(Debug, Clone)]
pub struct SpecOwnedResource {
    pub kind: String,
    pub id: String,
    pub namespace: String,
    /// `api_spec_id` as reported by the live resource.
    pub api_spec_id: String,
    /// The repo *also* declares this `(namespace, kind, id)`. Two owners are
    /// writing the same row — the repo is fighting the spec importer, and the
    /// Modify that would normally be emitted is suppressed.
    pub declared_in_repo: bool,
    /// The resource is scheduled for deletion anyway, because the run carries
    /// the explicit `--confirm-api-spec-deletion` opt-in.
    pub pruned: bool,
}

impl SpecOwnedResource {
    /// True when this entry is a repo-vs-spec ownership conflict rather than a
    /// resource we are merely staying off.
    pub fn is_conflict(&self) -> bool {
        self.declared_in_repo
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    pub diffs: Vec<ResourceDiff>,
    pub unmanaged: Vec<UnmanagedResource>,
    /// Live resources tagged with an `api_spec_id`. Reported in their own
    /// bucket rather than folded into `unmanaged`: the classification applies
    /// in *both* ownership modes, and it carries the conflict signal.
    pub spec_owned: Vec<SpecOwnedResource>,
}

impl DiffResult {
    /// Spec-owned resources the repo also declares — the ones an operator has
    /// to resolve by hand (drop the file, or stop managing the spec).
    pub fn spec_conflicts(&self) -> impl Iterator<Item = &SpecOwnedResource> {
        self.spec_owned.iter().filter(|s| s.is_conflict())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OwnershipScope<'a> {
    Shared {
        previously_managed: &'a HashSet<String>,
    },
    Exclusive,
}

/// Knobs that change which diff entries are *materialized* (as opposed to
/// which ownership fence applies).
#[derive(Debug, Clone, Copy, Default)]
pub struct DiffOptions {
    /// Mirrors `apply --confirm-api-spec-deletion`. Off (the default),
    /// spec-owned live resources are never emitted as deletions. On, exclusive
    /// mode prunes them like anything else — the operator has said so
    /// explicitly. Shared mode ignores this: the state file is the fence there
    /// and a spec-owned resource was never in it.
    pub prune_spec_owned: bool,
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
    compute_diff_with_options(desired, actual, ownership_scope, DiffOptions::default())
}

pub fn compute_diff_with_options(
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    ownership_scope: OwnershipScope<'_>,
    options: DiffOptions,
) -> DiffResult {
    let mut result = DiffResult::default();
    let ctx = CollectionContext {
        ownership_scope,
        options,
    };

    diff_collection(
        &desired.proxies,
        &actual.proxies,
        "Proxy",
        |p| p.id.clone(),
        |p| p.namespace.clone(),
        |p| p.api_spec_id.clone(),
        ctx,
        &mut result,
    );
    diff_collection(
        &desired.consumers,
        &actual.consumers,
        "Consumer",
        |c| c.id.clone(),
        |c| c.namespace.clone(),
        // Consumers are never provisioned by spec ingestion — the admin API's
        // `api_spec_id` tag exists on proxies, upstreams and plugin configs only.
        |_| None,
        ctx,
        &mut result,
    );
    diff_collection(
        &desired.upstreams,
        &actual.upstreams,
        "Upstream",
        |u| u.id.clone(),
        |u| u.namespace.clone(),
        |u| u.api_spec_id.clone(),
        ctx,
        &mut result,
    );
    diff_collection(
        &desired.plugin_configs,
        &actual.plugin_configs,
        "PluginConfig",
        |p| p.id.clone(),
        |p| p.namespace.clone(),
        |p| p.api_spec_id.clone(),
        ctx,
        &mut result,
    );

    // `actual` is walked through a HashMap, so the spec-owned bucket comes out
    // in arbitrary order. It is rendered verbatim into PR comments and plan
    // output — sort it so re-runs of an unchanged config produce an unchanged
    // report.
    result
        .spec_owned
        .sort_by(|a, b| (&a.namespace, &a.kind, &a.id).cmp(&(&b.namespace, &b.kind, &b.id)));

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

pub fn state_key_namespace(key: &str) -> Option<String> {
    parse_state_key(key).map(|(namespace, _kind, _id)| decode_state_key_component(namespace))
}

const STATE_KEY_PREFIX: &str = "__gitforgeops_state_key_v2";
const STATE_KEY_KINDS: [&str; 4] = ["Proxy", "Consumer", "Upstream", "PluginConfig"];

fn parse_state_key(key: &str) -> Option<(&str, &str, &str)> {
    let mut parts = key.splitn(4, ':');
    let prefix = parts.next()?;
    if prefix != STATE_KEY_PREFIX {
        return None;
    }
    let namespace = parts.next()?;
    let kind = parts.next()?;
    let id = parts.next()?;
    if !namespace.is_empty() && !id.is_empty() && is_state_key_kind(kind) {
        Some((namespace, kind, id))
    } else {
        None
    }
}

fn is_state_key_kind(value: &str) -> bool {
    STATE_KEY_KINDS.contains(&value)
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

/// The per-run knobs `diff_collection` needs, bundled so the argument list
/// stays readable.
#[derive(Debug, Clone, Copy)]
struct CollectionContext<'a> {
    ownership_scope: OwnershipScope<'a>,
    options: DiffOptions,
}

#[allow(clippy::too_many_arguments)]
fn diff_collection<T: serde::Serialize>(
    desired: &[T],
    actual: &[T],
    kind: &str,
    id_fn: impl Fn(&T) -> String,
    ns_fn: impl Fn(&T) -> String,
    spec_fn: impl Fn(&T) -> Option<String>,
    ctx: CollectionContext<'_>,
    result: &mut DiffResult,
) {
    let desired_map: std::collections::HashMap<(String, String), &T> =
        desired.iter().map(|r| ((ns_fn(r), id_fn(r)), r)).collect();
    let actual_map: std::collections::HashMap<(String, String), &T> =
        actual.iter().map(|r| ((ns_fn(r), id_fn(r)), r)).collect();

    for ((namespace, id), desired_res) in &desired_map {
        match actual_map.get(&(namespace.clone(), id.clone())) {
            Some(actual_res) => {
                // The live row belongs to a spec import. Modifying it would be
                // reverted on the next `PUT /api-specs`, so record the
                // ownership conflict and emit no Modify. Reported even when
                // the fields happen to agree today: two owners writing one row
                // is the finding, not the current field delta.
                if let Some(api_spec_id) = spec_fn(actual_res) {
                    result.spec_owned.push(SpecOwnedResource {
                        kind: kind.to_string(),
                        id: id.clone(),
                        namespace: namespace.clone(),
                        api_spec_id,
                        declared_in_repo: true,
                        pruned: false,
                    });
                    continue;
                }
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

    for ((namespace, id), actual_res) in &actual_map {
        if desired_map.contains_key(&(namespace.clone(), id.clone())) {
            continue;
        }

        // Spec-owned rows are off-limits to the repo's prune in both modes.
        // Exclusive mode can still be told to take them, but only through the
        // explicit `--confirm-api-spec-deletion` opt-in.
        if let Some(api_spec_id) = spec_fn(actual_res) {
            let prune = matches!(ctx.ownership_scope, OwnershipScope::Exclusive)
                && ctx.options.prune_spec_owned;
            result.spec_owned.push(SpecOwnedResource {
                kind: kind.to_string(),
                id: id.clone(),
                namespace: namespace.clone(),
                api_spec_id,
                declared_in_repo: false,
                pruned: prune,
            });
            if !prune {
                continue;
            }
            result.diffs.push(ResourceDiff {
                action: DiffAction::Delete,
                kind: kind.to_string(),
                id: id.clone(),
                namespace: namespace.clone(),
                details: Vec::new(),
            });
            continue;
        }

        match ctx.ownership_scope {
            OwnershipScope::Shared { previously_managed } => {
                let was_managed = previously_managed.contains(&state_key(namespace, kind, id));
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
