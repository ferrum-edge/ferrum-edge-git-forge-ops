use crate::config::schema::{PluginConfig, Proxy};
use crate::config::GatewayConfig;
use crate::plugin_catalog::{
    allows_uninspectable_body, cfg_array, cfg_bool, cfg_str, effective_plugins, effective_scheme,
    has_local_redis_fallback, is_auth_plugin, is_builtin, is_retired, retired_replacement,
    scheme_is_tls, waf_has_enforcing_rule, waf_mode, waf_mode_is_passive, waf_skips_oversized_body,
    RetiredRemediation, RETIRED_PLUGIN_NAMES,
};
use crate::policy::config::default_auth_plugin_names;
use crate::policy::PolicyConfig;
use crate::secrets::resolver::is_identity_credential_leaf;

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

/// Severity string that blocks `apply`. Matches
/// [`crate::policy::Severity::blocks_apply`] so the two gates share one notion
/// of "this must not reach a gateway".
pub const BLOCKING_SEVERITY: &str = "error";

/// The findings that must stop an `apply`.
///
/// Pure and total so the gate itself is testable without a gateway, a repo
/// checkout, or a process: `apply` refuses when this is non-empty (absent an
/// override), and `plan` exits non-zero on exactly the same set, so a preview
/// and the post-merge apply never disagree.
///
/// The load-bearing member is `check_literal_credentials`: a consumer
/// credential *secret* string that is not a `${gh-env-secret:…}` placeholder
/// is a secret committed to the repository, and applying it publishes it to
/// the gateway. That is only true of the **pre-resolve** config — see
/// [`audit_security_with_policy`]. Credential *identities*
/// (`basicauth[].username`, `mtls_auth[].identity`) are excluded: they are
/// public halves the broker cannot generate, so blocking on them refused
/// configurations this repo's own `import` produces.
pub fn security_blockers(findings: &[SecurityFinding]) -> Vec<&SecurityFinding> {
    findings
        .iter()
        .filter(|finding| finding.severity == BLOCKING_SEVERITY)
        .collect()
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
/// check treats any secret string that is not a `${...}` placeholder as a
/// committed secret, so auditing a resolved config flags every allocated
/// credential.
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
                cred_type,
                None,
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
                match retired_replacement(name) {
                    RetiredRemediation::ReplaceWith(successors) =>
                        format!("replace it with {}", successors.join(" or ")),
                    RetiredRemediation::RenamedTo(successor) =>
                        format!("rename it to {successor}"),
                    RetiredRemediation::Remove => "remove this plugin config".to_string(),
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
            let mode = waf_mode(cfg);
            if waf_mode_is_passive(&mode) {
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
            if waf_skips_oversized_body(cfg) {
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
    if has_local_redis_fallback(cfg) {
        findings.push(SecurityFinding::warning(
            "PluginConfig",
            id,
            ns,
            format!(
                "{name} plugin {id} in namespace {ns} has redis_failure_policy: local_fallback — a Redis outage silently degrades the shared budget into a per-replica one; use the fail-closed policy instead"
            ),
        ));
    }
    if allows_uninspectable_body(cfg) {
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

/// Flag every literal (non-placeholder) secret string under one consumer
/// credential type.
///
/// Two positions are tracked separately as the walk descends, and the
/// distinction is the whole point of the function:
///
/// * `credential_type` is the **structural** top-level key of the credential
///   map (`basicauth`, `mtls_auth`, `keyauth`, or a custom type). It never
///   changes.
/// * `leaf` is the enclosing object key of the string being classified
///   (`None` for a bare string). An array index does not change which field a
///   leaf is, so it carries through array recursion unchanged — the same rule
///   [`crate::secrets::scrubber`] and the import capture walk follow.
/// * `path` is the human-readable location for the diagnostic
///   (`mtls_auth[0].identity`) and is not consulted for any decision.
///
/// Only `(credential_type, leaf)` decides the identity exemption, so
/// `basicauth[0].username` is exempt while a custom credential type's
/// `username` — which the broker would happily manage and the gateway has no
/// public-half contract for — still blocks.
fn check_literal_credentials(
    consumer_id: &str,
    namespace: &str,
    credential_type: &str,
    path: &str,
    leaf: Option<&str>,
    value: &serde_json::Value,
    findings: &mut Vec<SecurityFinding>,
) {
    match value {
        serde_json::Value::String(s) if !s.starts_with("${") => {
            // `basicauth[].username` and `mtls_auth[].identity` are the public
            // halves of their credentials: `import` deliberately preserves
            // them verbatim, the broker refuses to generate them, and the
            // scrubber leaves them readable so a diagnostic can still say
            // which credential it is about. Calling them committed secrets
            // blocked `apply` on the output of this repo's own importer.
            // One classifier for all four call sites — see
            // [`is_identity_credential_leaf`].
            if is_identity_credential_leaf(credential_type, leaf) {
                return;
            }
            findings.push(SecurityFinding::error(
                "Consumer",
                consumer_id,
                namespace,
                format!(
                    "Literal credential in '{path}' on consumer {consumer_id} in namespace {namespace} (use ${{gh-env-secret:...}} for secrets)"
                ),
            ));
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let nested_path = format!("{path}.{k}");
                check_literal_credentials(
                    consumer_id,
                    namespace,
                    credential_type,
                    &nested_path,
                    Some(k.as_str()),
                    v,
                    findings,
                );
            }
        }
        serde_json::Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                let nested_path = format!("{path}[{idx}]");
                check_literal_credentials(
                    consumer_id,
                    namespace,
                    credential_type,
                    &nested_path,
                    leaf,
                    item,
                    findings,
                );
            }
        }
        _ => {}
    }
}
