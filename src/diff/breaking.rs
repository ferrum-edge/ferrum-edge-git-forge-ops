use crate::config::GatewayConfig;

use super::resource_diff::{DiffAction, ResourceDiff};

#[derive(Debug, Clone)]
pub struct BreakingChange {
    pub kind: String,
    pub id: String,
    pub reason: String,
}

pub fn detect_breaking_changes(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    actual: &GatewayConfig,
) -> Vec<BreakingChange> {
    let mut breaking = Vec::new();

    for diff in diffs {
        match diff.action {
            DiffAction::Delete => {
                if diff.kind == "Proxy" {
                    breaking.push(BreakingChange {
                        kind: diff.kind.clone(),
                        id: diff.id.clone(),
                        reason: "Proxy deleted".to_string(),
                    });
                }
                if diff.kind == "Consumer" {
                    breaking.push(BreakingChange {
                        kind: diff.kind.clone(),
                        id: diff.id.clone(),
                        reason: "Consumer deleted".to_string(),
                    });
                }
                if diff.kind == "PluginConfig" {
                    let is_auth = actual
                        .plugin_configs
                        .iter()
                        .find(|p| p.id == diff.id)
                        .map(|p| p.plugin_name.contains("auth"))
                        .unwrap_or(false);
                    if is_auth {
                        breaking.push(BreakingChange {
                            kind: diff.kind.clone(),
                            id: diff.id.clone(),
                            reason: "Auth plugin deleted".to_string(),
                        });
                    }
                }
            }
            DiffAction::Modify => {
                if diff.kind == "Proxy" {
                    check_proxy_breaking_fields(diff, desired, actual, &mut breaking);
                }
            }
            DiffAction::Add => {}
        }
    }

    breaking
}

fn check_proxy_breaking_fields(
    diff: &ResourceDiff,
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    breaking: &mut Vec<BreakingChange>,
) {
    let desired_proxy = desired.proxies.iter().find(|p| p.id == diff.id);
    let actual_proxy = actual.proxies.iter().find(|p| p.id == diff.id);

    if let (Some(d), Some(a)) = (desired_proxy, actual_proxy) {
        if d.listen_path != a.listen_path {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: "listen_path changed".to_string(),
            });
        }
        if d.hosts != a.hosts {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: "hosts changed".to_string(),
            });
        }
        if d.backend_protocol != a.backend_protocol {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: "backend_protocol changed".to_string(),
            });
        }
    }
}
