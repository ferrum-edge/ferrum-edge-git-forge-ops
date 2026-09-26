use std::collections::{BTreeSet, HashSet};

use crate::config::schema::PluginConfig;
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    auth_coverage, effective_scheme, protocol_list, AuthAllowlist, AuthCoverage,
};
use crate::policy::config::effective_auth_allowlist;
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
/// [`effective_auth_allowlist`]), so a configured custom authenticator is
/// reported exactly like a built-in one. Without a policy the built-in
/// defaults apply.
pub fn detect_breaking_changes_with_policy(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    policy: Option<&PolicyConfig>,
) -> Vec<BreakingChange> {
    let auth = effective_auth_allowlist(policy);
    let mut breaking = Vec::new();
    // Auth plugin configs a PluginConfig-level finding already explains
    // (deleted, disabled, renamed). The per-proxy check below does not repeat
    // them for every proxy the same instance guarded.
    let mut reported_auth_plugins: HashSet<(String, String)> = HashSet::new();

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
                        .is_some_and(|p| auth.contains(&p.plugin_name));
                    if deleted_auth {
                        reported_auth_plugins.insert((diff.namespace.clone(), diff.id.clone()));
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
                if diff.kind == "PluginConfig"
                    && check_auth_plugin_modify(diff, desired, actual, &auth, &mut breaking)
                {
                    reported_auth_plugins.insert((diff.namespace.clone(), diff.id.clone()));
                }
            }
            DiffAction::Add => {}
        }
    }

    check_proxy_auth_coverage(
        diffs,
        desired,
        actual,
        &auth,
        &reported_auth_plugins,
        &mut breaking,
    );

    breaking
}

fn diff_action<'a>(
    diffs: &'a [ResourceDiff],
    kind: &str,
    namespace: &str,
    id: &str,
) -> Option<&'a DiffAction> {
    diffs
        .iter()
        .find(|d| d.kind == kind && d.namespace == namespace && d.id == id)
        .map(|d| &d.action)
}

/// The plugin configs the gateway holds once `diffs` are applied.
///
/// This is deliberately not `desired`: in shared mode a live plugin the repo
/// never declared is unmanaged and survives the apply, and a spec-owned row is
/// never modified. Only an Add/Modify replaces the live row and only a Delete
/// removes it.
fn projected_plugin_configs(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    actual: &GatewayConfig,
) -> Vec<PluginConfig> {
    let mut projected = Vec::new();
    for plugin in &desired.plugin_configs {
        let live = actual
            .plugin_configs
            .iter()
            .find(|p| p.namespace == plugin.namespace && p.id == plugin.id);
        match (
            diff_action(diffs, "PluginConfig", &plugin.namespace, &plugin.id),
            live,
        ) {
            (Some(DiffAction::Add | DiffAction::Modify), _) | (None, None) => {
                projected.push(plugin.clone())
            }
            (None, Some(live)) => projected.push(live.clone()),
            (Some(DiffAction::Delete), _) => {}
        }
    }
    for live in &actual.plugin_configs {
        let declared = desired
            .plugin_configs
            .iter()
            .any(|p| p.namespace == live.namespace && p.id == live.id);
        let deleted = matches!(
            diff_action(diffs, "PluginConfig", &live.namespace, &live.id),
            Some(DiffAction::Delete)
        );
        if !declared && !deleted {
            projected.push(live.clone());
        }
    }
    projected
}

/// Enabled authenticators the gateway runs on a proxy, by `plugin_name`, with
/// the ids of the instances providing each one. Only an authenticator that
/// runs on one of the listener's request protocols counts ([`auth_coverage`],
/// the classification `require_auth_plugin` and the security audit use), so
/// dropping a `key_auth` that a TCP listener never runs is not an
/// authentication loss.
fn running_authenticators(coverage: &AuthCoverage<'_>) -> Vec<(String, Vec<String>)> {
    let mut by_name: Vec<(String, Vec<String>)> = Vec::new();
    for plugin in &coverage.applicable {
        match by_name
            .iter_mut()
            .find(|(name, _)| *name == plugin.plugin_name)
        {
            Some((_, ids)) => ids.push(plugin.id.clone()),
            None => by_name.push((plugin.plugin_name.clone(), vec![plugin.id.clone()])),
        }
    }
    by_name
}

/// A proxy that keeps existing but stops running an authenticator it runs
/// today strands every client holding credentials for it. That happens
/// without any auth PluginConfig being deleted, disabled or renamed: a
/// `proxy_group` association is dropped, a proxy-scoped instance is retargeted
/// to another proxy, or a global instance is narrowed to a different proxy.
///
/// Evaluates every live proxy that survives the apply, whether or not the
/// repository declares it: in shared mode an unmanaged proxy is retained, yet
/// a managed global authenticator still decides its effective plugin list.
/// Only a proxy the diff deletes is skipped (its deletion is reported on its
/// own), and a proxy takes its desired shape only when the diff modifies it.
///
/// Compares the effective authenticators live vs after the apply, per request
/// protocol ([`running_authenticators`]). Keyed on `plugin_name`, so swapping
/// one instance for another of the same authenticator is not reported. A loss
/// whose providing instances were all already reported at the PluginConfig
/// level is not repeated per proxy.
fn check_proxy_auth_coverage(
    diffs: &[ResourceDiff],
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    auth: &AuthAllowlist,
    reported_auth_plugins: &HashSet<(String, String)>,
    breaking: &mut Vec<BreakingChange>,
) {
    let projected = GatewayConfig {
        plugin_configs: projected_plugin_configs(diffs, desired, actual),
        ..GatewayConfig::default()
    };

    for live_proxy in &actual.proxies {
        let after_proxy = match diff_action(diffs, "Proxy", &live_proxy.namespace, &live_proxy.id) {
            Some(DiffAction::Delete) => continue,
            Some(DiffAction::Modify) => desired
                .proxies
                .iter()
                .find(|p| p.namespace == live_proxy.namespace && p.id == live_proxy.id)
                .unwrap_or(live_proxy),
            _ => live_proxy,
        };

        let before_coverage = auth_coverage(actual, live_proxy, auth);
        let after_coverage = auth_coverage(&projected, after_proxy, auth);
        let after: BTreeSet<String> = running_authenticators(&after_coverage)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let consequence = if after_coverage.applicable.is_empty() {
            ", which is left with no enabled authenticator".to_string()
        } else {
            let newly_uncovered: Vec<_> = after_coverage
                .uncovered
                .iter()
                .copied()
                .filter(|protocol| !before_coverage.uncovered.contains(protocol))
                .collect();
            if newly_uncovered.is_empty() {
                String::new()
            } else {
                format!(
                    ", which leaves its {} requests unauthenticated",
                    protocol_list(&newly_uncovered)
                )
            }
        };

        for (name, ids) in running_authenticators(&before_coverage) {
            if after.contains(&name) {
                continue;
            }
            let explained = ids.iter().all(|id| {
                reported_auth_plugins.contains(&(live_proxy.namespace.clone(), id.clone()))
            });
            if explained {
                continue;
            }
            breaking.push(BreakingChange {
                kind: "Proxy".to_string(),
                id: live_proxy.id.clone(),
                reason: format!(
                    "proxy {}/{} loses authenticator {} — consumer credentials for it no \
                     longer apply on this proxy{}",
                    live_proxy.namespace,
                    live_proxy.id,
                    name,
                    consequence
                ),
            });
        }
    }
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

/// A live, enabled authenticator that stops authenticating strands every
/// client that relies on it: disabling it leaves its proxies without that
/// check, and renaming it to a different plugin kind orphans the credentials
/// consumers hold for the old one. Any other edit (config values, priority,
/// labels) is not reported. Returns whether a finding was emitted.
fn check_auth_plugin_modify(
    diff: &ResourceDiff,
    desired: &GatewayConfig,
    actual: &GatewayConfig,
    auth: &AuthAllowlist,
    breaking: &mut Vec<BreakingChange>,
) -> bool {
    let desired_plugin = find_plugin_config(desired, diff);
    let actual_plugin = find_plugin_config(actual, diff);
    let (Some(d), Some(a)) = (desired_plugin, actual_plugin) else {
        return false;
    };
    if !a.enabled || !auth.contains(&a.plugin_name) {
        return false;
    }
    let before = breaking.len();

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
    breaking.len() > before
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
