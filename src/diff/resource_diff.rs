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

pub fn compute_diff(desired: &GatewayConfig, actual: &GatewayConfig) -> Vec<ResourceDiff> {
    let mut diffs = Vec::new();

    diff_collection(
        &desired.proxies,
        &actual.proxies,
        "Proxy",
        |p| p.id.clone(),
        |p| p.namespace.clone(),
        &mut diffs,
    );
    diff_collection(
        &desired.consumers,
        &actual.consumers,
        "Consumer",
        |c| c.id.clone(),
        |c| c.namespace.clone(),
        &mut diffs,
    );
    diff_collection(
        &desired.upstreams,
        &actual.upstreams,
        "Upstream",
        |u| u.id.clone(),
        |u| u.namespace.clone(),
        &mut diffs,
    );
    diff_collection(
        &desired.plugin_configs,
        &actual.plugin_configs,
        "PluginConfig",
        |p| p.id.clone(),
        |p| p.namespace.clone(),
        &mut diffs,
    );

    diffs
}

fn diff_collection<T: serde::Serialize>(
    desired: &[T],
    actual: &[T],
    kind: &str,
    id_fn: impl Fn(&T) -> String,
    ns_fn: impl Fn(&T) -> String,
    diffs: &mut Vec<ResourceDiff>,
) {
    let desired_map: std::collections::HashMap<String, &T> =
        desired.iter().map(|r| (id_fn(r), r)).collect();
    let actual_map: std::collections::HashMap<String, &T> =
        actual.iter().map(|r| (id_fn(r), r)).collect();

    for (id, desired_res) in &desired_map {
        match actual_map.get(id) {
            Some(actual_res) => {
                let details = compare_fields(desired_res, actual_res);
                if !details.is_empty() {
                    diffs.push(ResourceDiff {
                        action: DiffAction::Modify,
                        kind: kind.to_string(),
                        id: id.clone(),
                        namespace: ns_fn(desired_res),
                        details,
                    });
                }
            }
            None => {
                diffs.push(ResourceDiff {
                    action: DiffAction::Add,
                    kind: kind.to_string(),
                    id: id.clone(),
                    namespace: ns_fn(desired_res),
                    details: Vec::new(),
                });
            }
        }
    }

    for (id, actual_res) in &actual_map {
        if !desired_map.contains_key(id) {
            diffs.push(ResourceDiff {
                action: DiffAction::Delete,
                kind: kind.to_string(),
                id: id.clone(),
                namespace: ns_fn(actual_res),
                details: Vec::new(),
            });
        }
    }
}

fn compare_fields<T: serde::Serialize>(desired: &T, actual: &T) -> Vec<FieldChange> {
    let desired_val = serde_json::to_value(desired).unwrap_or_default();
    let actual_val = serde_json::to_value(actual).unwrap_or_default();

    let mut changes = Vec::new();

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
