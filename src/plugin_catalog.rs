//! The Ferrum Edge built-in plugin catalog and the scope-merge algorithm.
//!
//! Mirrors `ferrum_edge::plugins::BUILTIN_PLUGIN_REGISTRATIONS` (82 accepted
//! `plugin_name` strings) plus the `priorities` constant block. Anything not
//! listed here falls through to the gateway's custom-plugin registry, which
//! logs `Unknown plugin: {name}` and runs at [`DEFAULT_PRIORITY`].
//!
//! Two names are *retired and reserved*: the gateway refuses to load a config
//! that mentions them at all. Both were fail-closed plugins, so a config that
//! still references one is not merely stale — it is a config whose security
//! posture silently disappeared.
//!
//! This module is the single source of truth for "which plugins are effective
//! on this proxy": [`effective_plugins`] implements the documented scope-merge
//! (`docs/plugins.md`, "Plugin Scope Merging"), which the analysis passes and
//! policy rules all share.

use crate::config::schema::{BackendScheme, PluginConfig, PluginScope, Proxy};
use crate::config::GatewayConfig;

/// Priority assigned to a plugin the gateway does not recognize. Matches
/// `ferrum_edge::plugins::priorities::DEFAULT`.
pub const DEFAULT_PRIORITY: u16 = 5000;

/// Inclusive upper bound the gateway enforces on `priority_override`.
/// gitforgeops models the field as `u16`, so values above this parse locally
/// and are rejected at apply.
pub const MAX_PRIORITY_OVERRIDE: u16 = 10_000;

/// Broad functional grouping, used to phrase findings and to drive the
/// category-based checks (AI routes, observability coverage, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCategory {
    /// Establishes a caller principal.
    Authentication,
    /// Authorizes an already-established principal.
    Authorization,
    /// Rate, size, concurrency and overload control.
    Traffic,
    /// Request filtering, validation and response hardening.
    Security,
    /// LLM / agent traffic mediation.
    Ai,
    /// Protocol translation, routing and body/header rewriting.
    Transform,
    /// Logging, tracing, metrics and billing.
    Observability,
}

/// One built-in plugin registration.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinPlugin {
    pub name: &'static str,
    /// Built-in execution priority, overridable per instance with
    /// `priority_override`. Lower runs earlier.
    pub priority: u16,
    pub category: PluginCategory,
}

const fn p(name: &'static str, priority: u16, category: PluginCategory) -> BuiltinPlugin {
    BuiltinPlugin {
        name,
        priority,
        category,
    }
}

use PluginCategory::{
    Ai, Authentication, Authorization, Observability, Security, Traffic, Transform,
};

/// The 82 `plugin_name` values the gateway accepts as built-ins.
pub const BUILTIN_PLUGINS: &[BuiltinPlugin] = &[
    // --- Early band (0-949) ---
    p("otel_tracing", 25, Observability),
    p("correlation_id", 50, Observability),
    p("cors", 100, Security),
    p("request_termination", 125, Traffic),
    p("mesh_outbound_registry", 130, Security),
    p("ip_restriction", 150, Security),
    p("geo_restriction", 175, Security),
    p("bot_detection", 200, Security),
    p("spec_expose", 210, Transform),
    p("sse", 250, Transform),
    p("grpc_web", 260, Transform),
    p("grpc_method_router", 275, Transform),
    // --- Authentication band (950-1999) ---
    p("spiffe_identity", 940, Authentication),
    p("mtls_auth", 950, Authentication),
    p("jwks_auth", 1000, Authentication),
    p("oauth2_introspection", 1050, Authentication),
    p("oidc_relying_party", 1075, Authentication),
    p("jwt_auth", 1100, Authentication),
    p("key_auth", 1200, Authentication),
    p("ldap_auth", 1250, Authentication),
    p("basic_auth", 1300, Authentication),
    p("hmac_auth", 1400, Authentication),
    p("soap_ws_security", 1500, Authentication),
    // --- Admission band (2000-2999) ---
    p("access_control", 2000, Authorization),
    p("tcp_connection_throttle", 2050, Traffic),
    p("mesh_authz", 2075, Authorization),
    p("opa", 2080, Authorization),
    p("adaptive_concurrency", 2090, Traffic),
    p("ai_transcript_audit", 2740, Ai),
    p("request_size_limiting", 2800, Traffic),
    p("ws_message_size_limiting", 2810, Traffic),
    p("graphql", 2850, Transform),
    p("rate_limiting", 2900, Traffic),
    p("ws_rate_limiting", 2910, Traffic),
    p("udp_rate_limiting", 2915, Traffic),
    p("ai_prompt_shield", 2925, Ai),
    p("waf", 2930, Security),
    p("fault_injection", 2940, Transform),
    p("body_validator", 2950, Security),
    p("openapi_validator", 2960, Security),
    p("ai_semantic_firewall", 2968, Ai),
    p("ai_request_guard", 2975, Ai),
    p("ai_tool_governor", 2978, Ai),
    p("ai_stream_router", 2984, Ai),
    p("mcp_gateway", 2992, Ai),
    p("a2a_gateway", 2993, Ai),
    p("mesh_route_dispatch", 2995, Transform),
    // --- Transform band (3000-3999) ---
    p("request_transformer", 3000, Transform),
    p("request_deduplication", 3010, Traffic),
    p("serverless_function", 3025, Transform),
    p("response_mock", 3030, Transform),
    p("grpc_deadline", 3050, Transform),
    p("load_testing", 3070, Transform),
    p("request_mirror", 3075, Transform),
    p("response_size_limiting", 3490, Traffic),
    p("response_caching", 3500, Transform),
    // --- Response band (4000-4999) ---
    p("response_transformer", 4000, Transform),
    p("compression", 4050, Transform),
    p("ai_prompt_compressor", 4055, Ai),
    p("ai_semantic_cache", 4057, Ai),
    p("ai_federation", 4060, Ai),
    p("ai_response_guard", 4075, Ai),
    p("security_headers", 4080, Security),
    p("ai_token_metrics", 4100, Ai),
    p("ai_rate_limiter", 4200, Ai),
    // --- Logging band (9000-9999) ---
    p("stdout_logging", 9000, Observability),
    p("ws_frame_logging", 9050, Observability),
    p("statsd_logging", 9075, Observability),
    p("http_logging", 9100, Observability),
    p("tcp_logging", 9125, Observability),
    p("kafka_logging", 9150, Observability),
    p("loki_logging", 9155, Observability),
    p("udp_logging", 9160, Observability),
    p("ws_logging", 9175, Observability),
    p("transaction_debugger", 9200, Observability),
    p("proxy_alerts", 9250, Observability),
    p("prometheus_metrics", 9300, Observability),
    p("api_chargeback", 9350, Observability),
    p("api_chargeback_sink", 9351, Observability),
    p("workload_metrics", 9360, Observability),
    p("__mesh_bpf_metrics", 9365, Observability),
    p("transaction_log_schema", 9999, Observability),
];

/// Names the gateway retired. Both were fail-closed; the gateway raises a
/// fatal load error when a config still references one, so gitforgeops must
/// hard-reject them rather than pass them through as "custom" plugins.
pub const RETIRED_PLUGIN_NAMES: &[&str] = &["oauth2_auth", "semantic_ai_firewall"];

/// What to do about a retired plugin name — the *fact*, not the sentence.
///
/// The security audit and the `plugin_name_is_known` policy rule both tell the
/// operator how to fix a retired name, in their own voice (lowercase clause
/// versus imperative remediation line). Only the mapping from retired name to
/// successor is shared knowledge, so that is what lives here; each consumer
/// still phrases its own finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetiredRemediation {
    /// The plugin's job moved to one of these successors.
    ReplaceWith(&'static [&'static str]),
    /// Same plugin, new `plugin_name` spelling.
    RenamedTo(&'static str),
    /// No successor — the config entry should go.
    Remove,
}

/// Successor for a retired `plugin_name`. Returns
/// [`RetiredRemediation::Remove`] for anything without a known successor, so
/// callers always have something actionable to say.
pub fn retired_replacement(plugin_name: &str) -> RetiredRemediation {
    match plugin_name {
        "oauth2_auth" => {
            RetiredRemediation::ReplaceWith(&["oauth2_introspection", "oidc_relying_party"])
        }
        "semantic_ai_firewall" => RetiredRemediation::RenamedTo("ai_semantic_firewall"),
        _ => RetiredRemediation::Remove,
    }
}

/// Names the mesh data plane auto-injects. Operators must never configure
/// them by hand — a hand-written instance collides with the injected one.
pub const RESERVED_PLUGIN_NAMES: &[&str] = &["__mesh_bpf_metrics"];

/// Built-in plugins that establish a caller principal, in priority order.
pub const AUTH_PLUGIN_NAMES: &[&str] = &[
    "spiffe_identity",
    "mtls_auth",
    "jwks_auth",
    "oauth2_introspection",
    "oidc_relying_party",
    "jwt_auth",
    "key_auth",
    "ldap_auth",
    "basic_auth",
    "hmac_auth",
    "soap_ws_security",
];

/// Plugins that enforce a request/token budget. `graphql` belongs here
/// because its query-cost limiter is the rate control for GraphQL routes, and
/// the websocket / UDP / AI variants are the per-protocol equivalents of
/// `rate_limiting` — an exact-match check on `rate_limiting` alone misses all
/// four.
pub const RATE_LIMIT_PLUGIN_NAMES: &[&str] = &[
    "rate_limiting",
    "ws_rate_limiting",
    "udp_rate_limiting",
    "ai_rate_limiter",
    "graphql",
];

/// Plugins that emit per-request telemetry. Deliberately explicit rather than
/// a `contains("logging")` substring test: that substring misses
/// `otel_tracing` / `prometheus_metrics` / `transaction_debugger` and would
/// match an unrelated custom plugin whose name happens to contain "logging".
pub const OBSERVABILITY_PLUGIN_NAMES: &[&str] = &[
    "stdout_logging",
    "ws_frame_logging",
    "statsd_logging",
    "http_logging",
    "tcp_logging",
    "kafka_logging",
    "loki_logging",
    "udp_logging",
    "ws_logging",
    "otel_tracing",
    "prometheus_metrics",
    "transaction_debugger",
];

/// Guardrails that inspect prompt content and can refuse a request.
pub const AI_GUARDRAIL_PLUGIN_NAMES: &[&str] = &["ai_prompt_shield", "ai_semantic_firewall"];

/// Size-limit plugins are conjunctive: a scoped instance never replaces the
/// same-name global, they all stay effective and compose to the strictest
/// configured limit.
pub const SIZE_LIMIT_PLUGIN_NAMES: &[&str] = &["request_size_limiting", "response_size_limiting"];

/// Look up a built-in registration by exact `plugin_name`.
pub fn builtin(plugin_name: &str) -> Option<&'static BuiltinPlugin> {
    BUILTIN_PLUGINS.iter().find(|b| b.name == plugin_name)
}

/// Is this one of the 82 names the gateway ships?
pub fn is_builtin(plugin_name: &str) -> bool {
    builtin(plugin_name).is_some()
}

/// Was this name retired (and is therefore a fatal gateway load error)?
pub fn is_retired(plugin_name: &str) -> bool {
    RETIRED_PLUGIN_NAMES.contains(&plugin_name)
}

/// Is this name reserved for mesh auto-injection?
pub fn is_reserved(plugin_name: &str) -> bool {
    RESERVED_PLUGIN_NAMES.contains(&plugin_name)
}

/// Functional category, or `None` for a custom plugin.
pub fn category(plugin_name: &str) -> Option<PluginCategory> {
    builtin(plugin_name).map(|b| b.category)
}

/// Does this name establish a caller principal?
pub fn is_auth_plugin(plugin_name: &str) -> bool {
    AUTH_PLUGIN_NAMES.contains(&plugin_name)
}

/// Does this plugin mediate AI / agent traffic? Covers every `ai_*` built-in
/// plus the two agent-protocol gateways, which carry LLM traffic without the
/// `ai_` prefix.
pub fn is_ai_plugin(plugin_name: &str) -> bool {
    category(plugin_name) == Some(Ai)
}

/// Does this plugin emit per-request telemetry?
pub fn is_observability_plugin(plugin_name: &str) -> bool {
    OBSERVABILITY_PLUGIN_NAMES.contains(&plugin_name)
}

/// The priority this instance actually runs at: its `priority_override` when
/// set, otherwise the built-in default, otherwise the custom-plugin default.
pub fn effective_priority(plugin: &PluginConfig) -> u16 {
    plugin.priority_override.unwrap_or_else(|| {
        builtin(&plugin.plugin_name)
            .map(|b| b.priority)
            .unwrap_or(DEFAULT_PRIORITY)
    })
}

/// Is this plugin instance attached to `proxy` by a non-global scope?
///
/// `proxy`-scoped instances must both name the proxy *and* be listed in the
/// proxy's `plugins:` association list; `proxy_group`-scoped instances are
/// attached purely by association.
fn is_scoped_to(plugin: &PluginConfig, proxy: &Proxy) -> bool {
    match plugin.scope {
        PluginScope::Global => false,
        PluginScope::Proxy => {
            plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
                && proxy
                    .plugins
                    .iter()
                    .any(|assoc| assoc.plugin_config_id == plugin.id)
        }
        PluginScope::ProxyGroup => proxy
            .plugins
            .iter()
            .any(|assoc| assoc.plugin_config_id == plugin.id),
    }
}

/// Build the effective plugin list for one proxy, following the gateway's
/// documented scope merge:
///
/// 1. start with every **enabled global** plugin in the proxy's namespace;
/// 2. every attached proxy- or proxy-group-scoped instance **removes** the
///    global with the same `plugin_name` (the scoped instance replaces it);
/// 3. multiple scoped instances of the same name all coexist — only the
///    global is displaced;
/// 4. sort by effective priority.
///
/// Exceptions, both from `docs/plugins.md`:
///
/// * `request_size_limiting` / `response_size_limiting` are conjunctive
///   security boundaries. A looser scoped instance must not be able to relax a
///   stricter global one, so their globals survive step 2 and every instance
///   stays effective.
/// * `api_chargeback` merges normally but the gateway then requires **at most
///   one** effective instance per proxy (the `/charges` registry is a process
///   singleton, so two retained hooks double-count). That is a violation to
///   report, not a merge step — see [`over_attached_chargeback`].
///
/// Disabled instances never appear: the gateway skips them on every request,
/// so treating one as present is how a `enabled: false` auth plugin sneaks a
/// proxy past an auth check.
pub fn effective_plugins<'a>(config: &'a GatewayConfig, proxy: &Proxy) -> Vec<&'a PluginConfig> {
    let enabled_in_ns: Vec<&PluginConfig> = config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.enabled && plugin.namespace == proxy.namespace)
        .collect();

    let scoped: Vec<&PluginConfig> = enabled_in_ns
        .iter()
        .copied()
        .filter(|plugin| is_scoped_to(plugin, proxy))
        .collect();

    // Names a scoped instance displaces the global for. Size-limit plugins are
    // exempt — see the doc comment.
    let replaced: Vec<&str> = scoped
        .iter()
        .map(|plugin| plugin.plugin_name.as_str())
        .filter(|name| !SIZE_LIMIT_PLUGIN_NAMES.contains(name))
        .collect();

    let mut effective: Vec<&PluginConfig> = enabled_in_ns
        .iter()
        .copied()
        .filter(|plugin| {
            matches!(plugin.scope, PluginScope::Global)
                && !replaced.contains(&plugin.plugin_name.as_str())
        })
        .collect();
    effective.extend(scoped);
    effective.sort_by_key(|plugin| effective_priority(plugin));
    effective
}

// --- Backend scheme ---

/// Is this a stream (L4) proxy? The gateway's discriminator is the presence of
/// `listen_port`: a stream proxy binds its own listener, an HTTP-family proxy
/// is routed by host/path on the shared HTTP listener.
pub fn is_stream_proxy(proxy: &Proxy) -> bool {
    proxy.listen_port.is_some()
}

/// The scheme the gateway will actually dial.
///
/// Mirrors `Proxy::effective_scheme()` in ferrum-edge (`src/config/types.rs`):
/// an absent `backend_scheme` means `https` on the HTTP family, so `None` must
/// never be read as "plaintext". On a *stream* proxy an absent scheme is not a
/// default at all — the gateway rejects it in validation — and the upstream
/// sentinel is `tcp`.
///
/// The gateway also writes this resolution back into the stored proxy
/// (`resolve_dispatch_kind_fields` normalizes `None` → `Some(https)` for
/// non-stream proxies), which is why
/// `config::assembler::normalize_proxy_backend_schemes` applies the same rule
/// to the desired config: otherwise every schemeless proxy diffs forever
/// against the value the gateway resolved for it.
pub fn effective_scheme(proxy: &Proxy) -> BackendScheme {
    proxy.backend_scheme.unwrap_or({
        if is_stream_proxy(proxy) {
            BackendScheme::Tcp
        } else {
            BackendScheme::Https
        }
    })
}

/// Does this scheme negotiate TLS on the backend connection? Only these carry
/// a server certificate, so only these give
/// `backend_tls_verify_server_cert: false` any meaning — the gateway rejects
/// the field outright on the plaintext schemes.
pub fn scheme_is_tls(scheme: BackendScheme) -> bool {
    matches!(
        scheme,
        BackendScheme::Https | BackendScheme::Tcps | BackendScheme::Dtls
    )
}

/// Is this an HTTP-family scheme (as opposed to a raw L4 stream)?
pub fn scheme_is_http_family(scheme: BackendScheme) -> bool {
    matches!(scheme, BackendScheme::Http | BackendScheme::Https)
}

// --- Shared plugin-configuration predicates ---
//
// These read the untyped `PluginConfig.config` and answer a question about the
// gateway's *behavior*. The security audit, the best-practice audit and the
// policy rules all need the same answers; only the wording and severity of the
// resulting finding differ, so the predicates live here and the phrasing stays
// with each consumer.

/// WAF rule actions that actually reject a matched request. The gateway spells
/// the enforcing action `enforce`; `block` / `reject` are accepted so a config
/// using the response-oriented wording is not misread as monitor-only.
pub const WAF_ENFORCING_ACTIONS: &[&str] = &["enforce", "block", "reject"];

/// Effective `waf.mode`, lowercased. Absent means `enforce` (the gateway's
/// default).
pub fn waf_mode(config: &serde_json::Value) -> String {
    cfg_str(config, &["mode"]).unwrap_or_else(|| "enforce".to_string())
}

/// Is this WAF mode one that never rejects (`monitor` / `disabled`)?
pub fn waf_mode_is_passive(mode: &str) -> bool {
    matches!(mode, "monitor" | "disabled")
}

/// Does any rule-level setting promote at least one WAF rule to enforcement?
///
/// The built-in rule pack ships every rule at `monitor`, so `mode: enforce` on
/// its own blocks nothing. Enforcement arrives through the bulk
/// `default_rule_action` switch, a per-rule `rule_modes` entry, a
/// `rule_overrides.<id>.action`, or a `custom_rules[].action`.
pub fn waf_has_enforcing_rule(config: &serde_json::Value) -> bool {
    let enforcing = |value: Option<String>| {
        value.is_some_and(|action| WAF_ENFORCING_ACTIONS.contains(&action.as_str()))
    };

    if enforcing(cfg_str(config, &["default_rule_action"])) {
        return true;
    }
    if let Some(modes) = cfg_at(config, &["rule_modes"]).and_then(|v| v.as_object()) {
        if modes
            .values()
            .any(|v| enforcing(v.as_str().map(|s| s.to_ascii_lowercase())))
        {
            return true;
        }
    }
    if let Some(overrides) = cfg_at(config, &["rule_overrides"]).and_then(|v| v.as_object()) {
        if overrides
            .values()
            .any(|v| enforcing(cfg_str(v, &["action"])))
        {
            return true;
        }
    }
    if let Some(custom) = cfg_array(config, &["custom_rules"]) {
        if custom.iter().any(|v| enforcing(cfg_str(v, &["action"]))) {
            return true;
        }
    }
    false
}

/// Does this WAF instance wave through bodies it could not scan?
/// `on_body_too_large` defaults to `fail_closed`; `skip` forwards a body the
/// scanner never looked at.
pub fn waf_skips_oversized_body(config: &serde_json::Value) -> bool {
    cfg_str(config, &["on_body_too_large"]).as_deref() == Some("skip")
}

/// Fail-open escape hatch: on a Redis outage the plugin falls back to a
/// per-replica budget instead of failing closed, silently multiplying the
/// shared limit by the replica count.
pub fn has_local_redis_fallback(config: &serde_json::Value) -> bool {
    cfg_str(config, &["redis_failure_policy"]).as_deref() == Some("local_fallback")
}

/// Fail-open escape hatch: a body the plugin cannot parse is forwarded
/// unchecked rather than rejected.
pub fn allows_uninspectable_body(config: &serde_json::Value) -> bool {
    cfg_bool(config, &["fail_on_uninspectable_body"]) == Some(false)
}

// --- Untyped plugin-config accessors ---
//
// `PluginConfig.config` is deliberately untyped: the gateway owns the per-plugin
// schema and gitforgeops must round-trip fields it does not understand. The
// analysis passes therefore read individual keys defensively — a wrong type or
// a missing key means "not configured", never a panic.

/// Follow a dotted path through nested objects.
pub fn cfg_at<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    Some(current)
}

/// Read a string at `path`, lowercased for case-insensitive comparison.
pub fn cfg_str(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    cfg_at(value, path)
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase())
}

/// Read a bool at `path`.
pub fn cfg_bool(value: &serde_json::Value, path: &[&str]) -> Option<bool> {
    cfg_at(value, path).and_then(|v| v.as_bool())
}

/// Read an unsigned integer at `path`.
pub fn cfg_u64(value: &serde_json::Value, path: &[&str]) -> Option<u64> {
    cfg_at(value, path).and_then(|v| v.as_u64())
}

/// Read an array at `path`.
pub fn cfg_array<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a Vec<serde_json::Value>> {
    cfg_at(value, path).and_then(|v| v.as_array())
}

/// Number of effective `api_chargeback` instances on this proxy. More than one
/// is rejected by the gateway at admission and reload.
pub fn over_attached_chargeback(config: &GatewayConfig, proxy: &Proxy) -> usize {
    effective_plugins(config, proxy)
        .into_iter()
        .filter(|plugin| plugin.plugin_name == "api_chargeback")
        .count()
}
