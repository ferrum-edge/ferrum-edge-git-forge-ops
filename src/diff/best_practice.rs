use std::collections::BTreeMap;

use crate::config::schema::{BackendScheme, PluginConfig, Proxy, SdStalePolicy, Upstream};
use crate::config::GatewayConfig;
use crate::diff::security::{effective_scheme, scheme_is_http_family};
use crate::plugin_catalog::{
    effective_plugins, is_ai_plugin, is_observability_plugin, over_attached_chargeback,
    AI_GUARDRAIL_PLUGIN_NAMES, OBSERVABILITY_PLUGIN_NAMES, RATE_LIMIT_PLUGIN_NAMES,
};

#[derive(Debug, Clone)]
pub struct BestPractice {
    /// `warning` for a gap that has a concrete failure mode, `info` for a
    /// recommendation. Recommendations never block an apply; the severity only
    /// orders the reviewer's attention.
    pub severity: String,
    pub kind: String,
    pub id: String,
    pub namespace: String,
    pub message: String,
}

impl BestPractice {
    fn warning(kind: &str, id: &str, namespace: &str, message: String) -> Self {
        Self {
            severity: "warning".to_string(),
            kind: kind.to_string(),
            id: id.to_string(),
            namespace: namespace.to_string(),
            message,
        }
    }

    fn info(kind: &str, id: &str, namespace: &str, message: String) -> Self {
        Self {
            severity: "info".to_string(),
            kind: kind.to_string(),
            id: id.to_string(),
            namespace: namespace.to_string(),
            message,
        }
    }
}

pub fn check_best_practices(config: &GatewayConfig) -> Vec<BestPractice> {
    let mut findings = Vec::new();

    for proxy in &config.proxies {
        check_proxy(config, proxy, &mut findings);
    }

    for upstream in &config.upstreams {
        check_upstream(upstream, &mut findings);
    }

    findings
}

/// Which plugin actually rate-limits this proxy depends on its wire protocol:
/// `rate_limiting` never sees a UDP datagram or a raw TCP connection, so
/// recommending it on a stream proxy is advice the operator cannot follow.
///
/// Returns `(accepted plugin names, the name to recommend)`.
fn rate_limit_expectation(
    config: &GatewayConfig,
    proxy: &Proxy,
) -> (Vec<&'static str>, &'static str) {
    match effective_scheme(proxy) {
        BackendScheme::Udp | BackendScheme::Dtls => {
            (vec!["udp_rate_limiting"], "udp_rate_limiting")
        }
        BackendScheme::Tcp | BackendScheme::Tcps => {
            (vec!["tcp_connection_throttle"], "tcp_connection_throttle")
        }
        BackendScheme::Http | BackendScheme::Https => {
            let recommended = if effective_plugins(config, proxy)
                .iter()
                .any(|plugin| is_ai_plugin(&plugin.plugin_name))
            {
                "ai_rate_limiter"
            } else if !proxy.allowed_ws_origins.is_empty()
                || proxy.websocket_idle_timeout_seconds.is_some()
            {
                "ws_rate_limiting"
            } else {
                "rate_limiting"
            };
            (RATE_LIMIT_PLUGIN_NAMES.to_vec(), recommended)
        }
    }
}

fn check_proxy(config: &GatewayConfig, proxy: &Proxy, findings: &mut Vec<BestPractice>) {
    let effective = effective_plugins(config, proxy);
    let has = |name: &str| effective.iter().any(|plugin| plugin.plugin_name == name);
    let id = proxy.id.as_str();
    let ns = proxy.namespace.as_str();
    let scheme = effective_scheme(proxy);

    let (accepted, recommended) = rate_limit_expectation(config, proxy);
    if !effective
        .iter()
        .any(|plugin| accepted.contains(&plugin.plugin_name.as_str()))
    {
        findings.push(BestPractice::warning(
            "Proxy",
            id,
            ns,
            format!(
                "No rate-limit plugin attached to proxy {id} in namespace {ns} (scheme {}) — a single client can saturate the backend; attach {recommended}",
                scheme.as_str()
            ),
        ));
    }

    if !effective
        .iter()
        .any(|plugin| is_observability_plugin(&plugin.plugin_name))
    {
        findings.push(BestPractice::warning(
            "Proxy",
            id,
            ns,
            format!(
                "No observability plugin attached to proxy {id} in namespace {ns} — requests through it leave no trace to debug from; attach one of: {}",
                OBSERVABILITY_PLUGIN_NAMES.join(", ")
            ),
        ));
    }

    if proxy.backend_read_timeout_ms > 60_000 {
        findings.push(BestPractice::warning(
            "Proxy",
            id,
            ns,
            format!(
                "proxy {id} in namespace {ns} has backend_read_timeout_ms {} (over 60s) — a stalled backend holds the connection and its pool slot for that long; lower it to the backend's real worst case",
                proxy.backend_read_timeout_ms
            ),
        ));
    }

    // AI routes carry a per-token cost and an untrusted prompt surface that
    // ordinary HTTP checks do not model.
    if effective
        .iter()
        .any(|plugin| is_ai_plugin(&plugin.plugin_name))
    {
        if !has("ai_token_metrics") {
            findings.push(BestPractice::info(
                "Proxy",
                id,
                ns,
                format!(
                    "proxy {id} in namespace {ns} routes AI traffic without ai_token_metrics — token spend through it is unattributed; attach ai_token_metrics"
                ),
            ));
        }
        if !has("ai_rate_limiter") {
            findings.push(BestPractice::info(
                "Proxy",
                id,
                ns,
                format!(
                    "proxy {id} in namespace {ns} routes AI traffic without ai_rate_limiter — a request-count limit does not bound token cost; attach ai_rate_limiter with a token_limit"
                ),
            ));
        }
        if !AI_GUARDRAIL_PLUGIN_NAMES.iter().any(|name| has(name)) {
            findings.push(BestPractice::warning(
                "Proxy",
                id,
                ns,
                format!(
                    "proxy {id} in namespace {ns} routes AI traffic with no prompt guardrail — attach {}",
                    AI_GUARDRAIL_PLUGIN_NAMES.join(" or ")
                ),
            ));
        }
    }

    if scheme_is_http_family(scheme) && !has("compression") {
        findings.push(BestPractice::info(
            "Proxy",
            id,
            ns,
            format!(
                "proxy {id} in namespace {ns} serves {} without a compression plugin — responses cross the wire uncompressed; attach compression",
                scheme.as_str()
            ),
        ));
    }

    if scheme == BackendScheme::Https && !has("security_headers") {
        findings.push(BestPractice::info(
            "Proxy",
            id,
            ns,
            format!(
                "proxy {id} in namespace {ns} serves https without a security_headers plugin — no HSTS, frame or content-type protections are emitted; attach security_headers"
            ),
        ));
    }

    // Two instances of one plugin with no explicit priority land on the same
    // effective priority, so which one runs first is whatever order the cache
    // happened to build — and for transformers that changes the result.
    let mut implicit_order: BTreeMap<&str, Vec<&PluginConfig>> = BTreeMap::new();
    for plugin in &effective {
        if plugin.priority_override.is_none() {
            implicit_order
                .entry(plugin.plugin_name.as_str())
                .or_default()
                .push(plugin);
        }
    }
    for (name, instances) in implicit_order {
        if instances.len() < 2 {
            continue;
        }
        let ids: Vec<&str> = instances.iter().map(|plugin| plugin.id.as_str()).collect();
        findings.push(BestPractice::warning(
            "Proxy",
            id,
            ns,
            format!(
                "proxy {id} in namespace {ns} has {} effective {name} instances ({}) and none sets priority_override — their relative order is unspecified; set priority_override on each",
                instances.len(),
                ids.join(", ")
            ),
        ));
    }

    // The `/charges` registry is a process-global singleton with no instance
    // dimension, so two retained chargeback hooks double-count one client
    // transaction. The gateway rejects this at admission and reload.
    let chargeback_instances = over_attached_chargeback(config, proxy);
    if chargeback_instances > 1 {
        findings.push(BestPractice::warning(
            "Proxy",
            id,
            ns,
            format!(
                "proxy {id} in namespace {ns} has {chargeback_instances} effective api_chargeback instances — the gateway allows at most one per proxy and rejects the rest at admission; keep a single global, proxy- or proxy-group-scoped instance"
            ),
        ));
    }
}

fn check_upstream(upstream: &Upstream, findings: &mut Vec<BestPractice>) {
    let id = upstream.id.as_str();
    let ns = upstream.namespace.as_str();

    if upstream.targets.len() <= 1 {
        findings.push(BestPractice::warning(
            "Upstream",
            id,
            ns,
            format!(
                "upstream {id} in namespace {ns} has {} target(s) — there is nothing to fail over to; add a second target or attach service discovery",
                upstream.targets.len()
            ),
        ));
    }

    match &upstream.health_checks {
        None => findings.push(BestPractice::warning(
            "Upstream",
            id,
            ns,
            format!(
                "upstream {id} in namespace {ns} has no health_checks configured — a dead target keeps receiving its share of traffic; add an active or passive check"
            ),
        )),
        Some(checks) => {
            if let Some(passive) = &checks.passive {
                if passive.max_ejection_percent.is_none() {
                    findings.push(BestPractice::warning(
                        "Upstream",
                        id,
                        ns,
                        format!(
                            "upstream {id} in namespace {ns} has passive health checks with max_ejection_percent unset — a correlated backend failure can eject every target at once; cap it (for example 50)"
                        ),
                    ));
                }
            }
        }
    }

    if let Some(sd) = &upstream.service_discovery {
        if sd.stale_policy == Some(SdStalePolicy::Retain) {
            findings.push(BestPractice::warning(
                "Upstream",
                id,
                ns,
                format!(
                    "upstream {id} in namespace {ns} uses service discovery with stale_policy: retain — targets that vanished from the registry keep receiving traffic; prefer withdraw or fail_readiness"
                ),
            ));
        }
        if sd.max_stale_seconds == Some(0) {
            findings.push(BestPractice::warning(
                "Upstream",
                id,
                ns,
                format!(
                    "upstream {id} in namespace {ns} sets max_stale_seconds: 0, which means unbounded staleness — a discovery outage freezes the target set indefinitely; set a bound in 5..=86400"
                ),
            ));
        }
    }
}
