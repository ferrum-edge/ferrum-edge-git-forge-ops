use crate::config::schema::PluginConfig;
use crate::config::GatewayConfig;
use crate::plugin_catalog::effective_scheme;
use crate::policy::config::effective_auth_plugin_names;
use crate::policy::PolicyConfig;

use super::resource_diff::{DiffAction, ResourceDiff};

#[derive(Debug, Clone)]
pub struct BreakingChange {
    pub kind: String,
    pub id: String,
    pub reason: String,
}

/// Detect breaking changes with the built-in notion of what counts as an
/// authentication plugin.
pub fn detect_breaking_changes(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    actual: &GatewayConfig,
) -> Vec<BreakingChange> {
    detect_breaking_changes_with_policy(diffs, desired, actual, None)
}

/// Detect breaking changes against a resolved policy configuration.
///
/// A plugin config counts as authentication when its `plugin_name` is on the
/// same allowlist `require_auth_plugin` and the security audit use (see
/// [`effective_auth_plugin_names`]), so a configured custom authenticator is
/// reported exactly like a built-in one. Without a policy the built-in
/// defaults apply.
pub fn detect_breaking_changes_with_policy(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    policy: Option<&PolicyConfig>,
) -> Vec<BreakingChange> {
    let auth_names = effective_auth_plugin_names(policy);
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
                    let deleted_auth = find_plugin_config(actual, diff)
                        .is_some_and(|p| is_auth_plugin(&auth_names, &p.plugin_name));
                    if deleted_auth {
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
                if diff.kind == "PluginConfig" {
                    check_auth_plugin_modify(diff, desired, actual, &auth_names, &mut breaking);
                }
            }
            DiffAction::Add => {}
        }
    }

    breaking
}

fn find_plugin_config<'a>(
    config: &'a GatewayConfig,
    diff: &ResourceDiff,
) -> Option<&'a PluginConfig> {
    config
        .plugin_configs
        .iter()
        .find(|p| p.id == diff.id && p.namespace == diff.namespace)
}

fn is_auth_plugin(auth_names: &[String], plugin_name: &str) -> bool {
    auth_names.contains(&plugin_name.to_ascii_lowercase())
}

/// A live, enabled authenticator that stops authenticating strands every
/// client that relies on it: disabling it leaves its proxies without that
/// check, and renaming it to a different plugin kind orphans the credentials
/// consumers hold for the old one. Any other edit (config values, priority,
/// labels) is not reported.
fn check_auth_plugin_modify(
    diff: &ResourceDiff,
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    auth_names: &[String],
    breaking: &mut Vec<BreakingChange>,
) {
    let desired_plugin = find_plugin_config(desired, diff);
    let actual_plugin = find_plugin_config(actual, diff);
    let (Some(d), Some(a)) = (desired_plugin, actual_plugin) else {
        return;
    };
    if !a.enabled || !is_auth_plugin(auth_names, &a.plugin_name) {
        return;
    }

    if d.plugin_name != a.plugin_name {
        breaking.push(BreakingChange {
            kind: "PluginConfig".to_string(),
            id: diff.id.clone(),
            reason: format!(
                "Auth plugin plugin_name changed ({} -> {}) — consumer credentials for \
                 the previous authenticator no longer apply",
                a.plugin_name, d.plugin_name
            ),
        });
    }
    if !d.enabled {
        breaking.push(BreakingChange {
            kind: "PluginConfig".to_string(),
            id: diff.id.clone(),
            reason: "Auth plugin disabled (enabled: true -> false) — proxies it guarded \
                     stop authenticating with it"
                .to_string(),
        });
    }
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
