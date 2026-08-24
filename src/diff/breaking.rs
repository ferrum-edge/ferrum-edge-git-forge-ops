use crate::config::GatewayConfig;
use crate::plugin_catalog::effective_scheme;
use crate::policy::config::is_default_auth_plugin_name;

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
                        .find(|p| p.id == diff.id && p.namespace == diff.namespace)
                        .map(|p| is_default_auth_plugin_name(&p.plugin_name))
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
    let desired_proxy = desired
        .proxies
        .iter()
        .find(|p| p.id == diff.id && p.namespace == diff.namespace);
    let actual_proxy = actual
        .proxies
        .iter()
        .find(|p| p.id == diff.id && p.namespace == diff.namespace);

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
        // Compare the *effective* schemes, not the raw `Option`s. A DB-backed
        // gateway always reports a resolved scheme (it canonicalizes `None` to
        // `https` for non-stream proxies on write), so a repo proxy that omits
        // the field would otherwise read as `None != Some(https)` — a breaking
        // change on every PR touching that proxy, for an edit that changes
        // nothing on the wire. Assembly normalizes the desired side for the
        // same reason; this keeps the comparison correct for configs that did
        // not come through the assembler.
        if effective_scheme(d) != effective_scheme(a) {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: "backend_scheme changed".to_string(),
            });
        }
        if d.upstream_subset != a.upstream_subset {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: "upstream_subset changed — traffic is rerouted to a different \
                         set of upstream targets"
                    .to_string(),
            });
        }
        if d.listen_port != a.listen_port {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: "listen_port changed — the old listener is torn down and \
                         existing connections are dropped"
                    .to_string(),
            });
        }
        if d.frontend_tls != a.frontend_tls {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: format!(
                    "frontend_tls changed ({} -> {}) — clients must switch between \
                     plaintext and TLS on this listener",
                    a.frontend_tls, d.frontend_tls
                ),
            });
        }
        if d.passthrough != a.passthrough {
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: diff.id.clone(),
                reason: format!(
                    "passthrough changed ({} -> {}) — TLS termination moves between \
                     the gateway and the backend, and plugins stop or start seeing traffic",
                    a.passthrough, d.passthrough
                ),
            });
        }
    }
}
