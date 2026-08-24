use crate::config::schema::{BackendScheme, PluginConfig, Proxy};
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    cfg_array, cfg_at, cfg_bool, cfg_str, effective_plugins, is_auth_plugin, is_builtin,
    is_retired, RETIRED_PLUGIN_NAMES,
};
use crate::policy::config::default_auth_plugin_names;
use crate::policy::PolicyConfig;

#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub severity: String,
    pub kind: String,
    pub id: String,
    pub namespace: String,
    pub message: String,
}

impl SecurityFinding {
    fn error(kind: &str, id: &str, namespace: &str, message: String) -> Self {
        Self {
            severity: "error".to_string(),
            kind: kind.to_string(),
            id: id.to_string(),
            namespace: namespace.to_string(),
            message,
        }
    }

    fn warning(kind: &str, id: &str, namespace: &str, message: String) -> Self {
        Self {
            severity: "warning".to_string(),
            kind: kind.to_string(),
            id: id.to_string(),
            namespace: namespace.to_string(),
            message,
        }
    }
}

/// The scheme the gateway will actually dial. An absent `backend_scheme` on an
/// HTTP-family proxy defaults to `https` (`effective_scheme()` upstream), so
/// `None` must never be read as "plaintext".
pub fn effective_scheme(proxy: &Proxy) -> BackendScheme {
    proxy.backend_scheme.unwrap_or(BackendScheme::Https)
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

/// Audit with the repository's default notion of what counts as authentication.
pub fn audit_security(config: &GatewayConfig) -> Vec<SecurityFinding> {
    audit_security_with_policy(config, None)
}

/// Audit against a resolved policy configuration.
///
/// The auth-plugin allowlist is the operator's statement of what counts as
/// authentication in this repo, so when a policy config is available it wins
/// over the built-in defaults; without one the eleven built-in auth plugins
/// (plus tolerated legacy spellings) are used.
///
/// Must run **before** `secrets::resolve_secrets`: the literal-credential
/// check treats any string that is not a `${...}` placeholder as a committed
/// secret, so auditing a resolved config flags every allocated credential.
pub fn audit_security_with_policy(
    config: &GatewayConfig,
    policy: Option<&PolicyConfig>,
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    let auth_names: Vec<String> = match policy {
        Some(cfg) => cfg
            .policies
            .require_auth_plugin
            .auth_plugin_names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect(),
        None => default_auth_plugin_names()
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect(),
    };

    for consumer in &config.consumers {
        for (cred_type, cred_value) in &consumer.credentials {
            check_literal_credentials(
                &consumer.id,
                &consumer.namespace,
                cred_type,
                cred_value,
                &mut findings,
            );
        }
    }

    for proxy in &config.proxies {
        check_proxy(config, proxy, &auth_names, &mut findings);
    }

    // An Upstream carries the same TLS-verification flag as a Proxy, and a
    // proxy that delegates to an upstream dials through the upstream's
    // settings — scanning proxies alone leaves that bypass unreported.
    for upstream in &config.upstreams {
        if !upstream.backend_tls_verify_server_cert {
            findings.push(SecurityFinding::warning(
                "Upstream",
                &upstream.id,
                &upstream.namespace,
                format!(
                    "upstream {} in namespace {} sets backend_tls_verify_server_cert: false — backend certificates are accepted unvalidated; trust the backend CA via backend_tls_server_ca_cert_path instead",
                    upstream.id, upstream.namespace
                ),
            ));
        }
    }

    for plugin in &config.plugin_configs {
        check_plugin(plugin, &mut findings);
    }

    findings
}

fn check_proxy(
    config: &GatewayConfig,
    proxy: &Proxy,
    auth_names: &[String],
    findings: &mut Vec<SecurityFinding>,
) {
    let effective = effective_plugins(config, proxy);

    let auth_plugins: Vec<&&PluginConfig> = effective
        .iter()
        .filter(|plugin| auth_names.contains(&plugin.plugin_name.to_ascii_lowercase()))
        .collect();

    if auth_plugins.is_empty() {
        findings.push(SecurityFinding::warning(
            "Proxy",
            &proxy.id,
            &proxy.namespace,
            format!(
                "No auth plugin attached to proxy {} in namespace {} — its effective plugin list contains no enabled authenticator; attach one of: {}",
                proxy.id,
                proxy.namespace,
                auth_names.join(", ")
            ),
        ));
    }

    // A conditional auth plugin only runs when its trigger matches, so every
    // request the predicate misses reaches the backend unauthenticated. That is
    // a legitimate pattern (public health endpoints) but never an accident
    // worth leaving unreviewed.
    for plugin in &auth_plugins {
        if plugin.trigger.is_some() {
            findings.push(SecurityFinding::warning(
                "Proxy",
                &proxy.id,
                &proxy.namespace,
                format!(
                    "proxy {} in namespace {} is authenticated by {} plugin {}, which carries a trigger — requests the trigger does not match are served unauthenticated; drop the trigger to authenticate every request",
                    proxy.id, proxy.namespace, plugin.plugin_name, plugin.id
                ),
            ));
        }
    }

    let scheme = effective_scheme(proxy);
    if scheme_is_tls(scheme) && !proxy.backend_tls_verify_server_cert {
        findings.push(SecurityFinding::warning(
            "Proxy",
            &proxy.id,
            &proxy.namespace,
            format!(
                "proxy {} in namespace {} dials {} with backend_tls_verify_server_cert: false — backend certificates are accepted unvalidated; trust the backend CA via backend_tls_server_ca_cert_path instead",
                proxy.id,
                proxy.namespace,
                scheme.as_str()
            ),
        ));
    }

    if proxy.stream_proxy_protocol == Some(true) {
        findings.push(SecurityFinding::warning(
            "Proxy",
            &proxy.id,
            &proxy.namespace,
            format!(
                "proxy {} in namespace {} sets stream_proxy_protocol: true — the client IP is taken from an inbound PROXY header, which any direct connection can forge; keep it only behind a trusted L4 hop listed in FERRUM_TRUSTED_PROXIES",
                proxy.id, proxy.namespace
            ),
        ));
    }

    if proxy.passthrough {
        findings.push(SecurityFinding::warning(
            "Proxy",
            &proxy.id,
            &proxy.namespace,
            format!(
                "proxy {} in namespace {} sets passthrough: true — TLS is forwarded untouched, so no request is inspected and every attached plugin (auth included) is inert; unset passthrough to terminate TLS at the gateway",
                proxy.id, proxy.namespace
            ),
        ));
    }
}

/// Rule actions that actually reject a matched request.
const WAF_ENFORCING_ACTIONS: &[&str] = &["enforce", "block", "reject"];

fn waf_has_enforcing_rule(config: &serde_json::Value) -> bool {
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

/// Is this `allowed_origins` entry the any-origin wildcard? CORS origins are
/// either bare strings or match objects, so `"*"` and `{exact: "*"}` are the
/// same policy written two ways.
fn is_wildcard_origin(entry: &serde_json::Value) -> bool {
    if entry.as_str() == Some("*") {
        return true;
    }
    match entry.get("exact") {
        Some(serde_json::Value::String(s)) => s == "*",
        Some(serde_json::Value::Array(values)) => values.iter().any(|v| v.as_str() == Some("*")),
        _ => false,
    }
}

fn check_plugin(plugin: &PluginConfig, findings: &mut Vec<SecurityFinding>) {
    let id = plugin.id.as_str();
    let ns = plugin.namespace.as_str();
    let name = plugin.plugin_name.as_str();

    // Name checks apply regardless of `enabled`: a retired name is a fatal
    // gateway load error for the whole config, not a skipped plugin.
    if is_retired(name) {
        findings.push(SecurityFinding::error(
            "PluginConfig",
            id,
            ns,
            format!(
                "plugin {id} in namespace {ns} uses the retired plugin_name: {name} — the gateway refuses to load any config mentioning {}; {}",
                RETIRED_PLUGIN_NAMES.join(" or "),
                match name {
                    "oauth2_auth" => "replace it with oauth2_introspection or oidc_relying_party",
                    "semantic_ai_firewall" => "rename it to ai_semantic_firewall",
                    _ => "remove this plugin config",
                }
            ),
        ));
        return;
    }

    if !is_builtin(name) {
        findings.push(SecurityFinding::warning(
            "PluginConfig",
            id,
            ns,
            format!(
                "plugin {id} in namespace {ns} uses plugin_name: {name}, which is not a built-in plugin — the gateway logs it as unknown and applies no policy from it; fix the spelling or confirm the custom plugin is compiled into your gateway build"
            ),
        ));
        return;
    }

    // Everything below reads the instance's own configuration, which the
    // gateway only consults for enabled instances.
    if !plugin.enabled {
        return;
    }

    let cfg = &plugin.config;

    match name {
        "waf" => {
            let mode = cfg_str(cfg, &["mode"]).unwrap_or_else(|| "enforce".to_string());
            if mode == "monitor" || mode == "disabled" {
                findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                        "waf plugin {id} in namespace {ns} has mode: {mode} — matched requests are recorded but never rejected; set config.mode: enforce"
                    ),
                ));
            } else if !waf_has_enforcing_rule(cfg) {
                findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                        "waf plugin {id} in namespace {ns} has mode: enforce but every built-in rule is monitor-only — no default_rule_action, rule_modes, rule_overrides or custom_rules entry promotes a rule to enforcement; set config.default_rule_action: enforce"
                    ),
                ));
            }
            if cfg_str(cfg, &["on_body_too_large"]).as_deref() == Some("skip") {
                findings.push(SecurityFinding::warning(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                        "waf plugin {id} in namespace {ns} has on_body_too_large: skip — bodies over max_scan_bytes bypass inspection; remove the key to keep the fail_closed default"
                    ),
                ));
            }
        }
        "openapi_validator" => {
            if let Some(mode) = cfg_str(cfg, &["enforcement_mode"]) {
                if mode == "log_only" || mode == "disabled" {
                    findings.push(SecurityFinding::error(
                        "PluginConfig",
                        id,
                        ns,
                        format!(
                            "openapi_validator plugin {id} in namespace {ns} has enforcement_mode: {mode} — schema violations are logged and forwarded to the backend; set config.enforcement_mode: block (the default)"
                        ),
                    ));
                }
            }
        }
        "ai_semantic_firewall" | "ai_tool_governor"
            if cfg_str(cfg, &["mode"]).as_deref() == Some("dry_run") =>
        {
            findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                    "{name} plugin {id} in namespace {ns} has mode: dry_run — violations are recorded but the request proceeds; set config.mode: enforce (the default)"
                ),
            ));
        }
        "cors" => {
            let wildcard = cfg_array(cfg, &["allowed_origins"])
                .is_some_and(|origins| origins.iter().any(is_wildcard_origin));
            if wildcard {
                findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                        "cors plugin {id} in namespace {ns} has allowed_origins containing \"*\" — any site may read responses from this proxy; list the origins that need access"
                    ),
                ));
                if cfg_bool(cfg, &["allow_credentials"]) == Some(true) {
                    findings.push(SecurityFinding::warning(
                        "PluginConfig",
                        id,
                        ns,
                        format!(
                            "cors plugin {id} in namespace {ns} combines allow_credentials: true with a \"*\" origin — the gateway silently drops the credentials grant rather than echoing it, so browsers will not send cookies; replace the wildcard with explicit origins"
                        ),
                    ));
                }
            }
        }
        "ldap_auth" if cfg_bool(cfg, &["allow_plaintext"]) == Some(true) => {
            findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                    "ldap_auth plugin {id} in namespace {ns} has allow_plaintext: true — bind credentials cross the network unencrypted; use ldaps:// or enable starttls"
                ),
            ));
        }
        "oidc_relying_party" if cfg_bool(cfg, &["session", "secure"]) == Some(false) => {
            findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                    "oidc_relying_party plugin {id} in namespace {ns} has session.secure: false — the session cookie is sent over plaintext HTTP; remove the key to keep the secure default"
                ),
            ));
        }
        "hmac_auth" if cfg_bool(cfg, &["allow_unsafe_replayable_v1"]) == Some(true) => {
            findings.push(SecurityFinding::error(
                    "PluginConfig",
                    id,
                    ns,
                    format!(
                    "hmac_auth plugin {id} in namespace {ns} has allow_unsafe_replayable_v1: true — signatures from the v1 profile can be captured and replayed; migrate clients and remove the key"
                ),
            ));
        }
        _ => {}
    }

    // Fail-open escape hatches shared across several plugins.
    if cfg_str(cfg, &["redis_failure_policy"]).as_deref() == Some("local_fallback") {
        findings.push(SecurityFinding::warning(
            "PluginConfig",
            id,
            ns,
            format!(
                "{name} plugin {id} in namespace {ns} has redis_failure_policy: local_fallback — a Redis outage silently degrades the shared budget into a per-replica one; use the fail-closed policy instead"
            ),
        ));
    }
    if cfg_bool(cfg, &["fail_on_uninspectable_body"]) == Some(false) {
        findings.push(SecurityFinding::warning(
            "PluginConfig",
            id,
            ns,
            format!(
                "{name} plugin {id} in namespace {ns} has fail_on_uninspectable_body: false — a body the plugin cannot parse is forwarded unchecked; remove the key to keep the fail-closed default"
            ),
        ));
    }

    // A trigger on an auth plugin decides whether a route is authenticated at
    // all. Flagged here as well as per-proxy so an unattached-but-committed
    // instance is still surfaced.
    if is_auth_plugin(name) && plugin.trigger.is_some() {
        findings.push(SecurityFinding::warning(
            "PluginConfig",
            id,
            ns,
            format!(
                "{name} plugin {id} in namespace {ns} carries a trigger — authentication only runs when the predicate matches, leaving the remaining requests public; drop the trigger unless the exemption is intended"
            ),
        ));
    }
}

fn check_literal_credentials(
    consumer_id: &str,
    namespace: &str,
    cred_type: &str,
    value: &serde_json::Value,
    findings: &mut Vec<SecurityFinding>,
) {
    match value {
        serde_json::Value::String(s) if !s.starts_with("${") => {
            findings.push(SecurityFinding::error(
                "Consumer",
                consumer_id,
                namespace,
                format!(
                    "Literal credential in '{cred_type}' on consumer {consumer_id} in namespace {namespace} (use ${{gh-env-secret:...}} for secrets)"
                ),
            ));
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let nested_path = format!("{cred_type}.{k}");
                check_literal_credentials(consumer_id, namespace, &nested_path, v, findings);
            }
        }
        serde_json::Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                let nested_path = format!("{cred_type}[{idx}]");
                check_literal_credentials(consumer_id, namespace, &nested_path, item, findings);
            }
        }
        _ => {}
    }
}
