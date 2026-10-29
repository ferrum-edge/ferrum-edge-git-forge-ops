//! Sensitive-string classification for opaque plugin configuration.
//!
//! Ferrum Edge deliberately returns raw plugin config from the admin-only
//! backup endpoint. Import therefore has to identify credential-bearing
//! strings before it writes resource YAML. These rules mirror the gateway's
//! schema-aware `plugin_config_projection` contract: explicit per-plugin
//! paths cover arbitrary header maps and credential-bearing endpoint URLs,
//! while conservative key and URL heuristics protect custom/future fields.

use std::collections::BTreeSet;

use serde_json::Value;

use super::MIN_SCRUB_LENGTH;
use crate::plugin_catalog::is_builtin;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConfigPathComponent {
    Key(String),
    Index(usize),
}

#[derive(Clone, Copy)]
enum RuleKind {
    Secret,
    Endpoint,
    /// A value the gateway writes or matches on a request (a rule's header
    /// value, a match condition). Edge redacts it because an operator may put
    /// a credential there, so a string of at least [`MIN_SCRUB_LENGTH`] bytes
    /// is brokered, masked, scrubbed and gated like a secret. Such values are
    /// just as often ordinary settings (`value: "1"`), so a shorter one, which
    /// could neither be brokered nor scrubbed, stays literal, and none is
    /// rule-declared for display admission. Whatever its length or JSON type,
    /// the matched value is a site `/config/export` fingerprints
    /// ([`export_redacted_paths`]).
    Value,
    KafkaProperties,
}

#[derive(Clone, Copy)]
struct Rule {
    path: &'static [&'static str],
    kind: RuleKind,
}

const fn secret(path: &'static [&'static str]) -> Rule {
    Rule {
        path,
        kind: RuleKind::Secret,
    }
}

const fn endpoint(path: &'static [&'static str]) -> Rule {
    Rule {
        path,
        kind: RuleKind::Endpoint,
    }
}

const fn operator_value(path: &'static [&'static str]) -> Rule {
    Rule {
        path,
        kind: RuleKind::Value,
    }
}

const REDIS_URL: &[Rule] = &[endpoint(&["redis_url"])];

const KAFKA_SAFE_PROPERTIES: &[&str] = &[
    "acks",
    "batch.num.messages",
    "batch.size",
    "client.id",
    "compression.codec",
    "compression.level",
    "compression.type",
    "delivery.timeout.ms",
    "enable.idempotence",
    "linger.ms",
    "max.in.flight",
    "max.in.flight.requests.per.connection",
    "message.max.bytes",
    "message.send.max.retries",
    "message.timeout.ms",
    "metadata.max.age.ms",
    "partitioner",
    "queue.buffering.max.kbytes",
    "queue.buffering.max.messages",
    "queue.buffering.max.ms",
    "reconnect.backoff.max.ms",
    "reconnect.backoff.ms",
    "request.required.acks",
    "request.timeout.ms",
    "retries",
    "retry.backoff.max.ms",
    "retry.backoff.ms",
    "socket.keepalive.enable",
    "socket.nagle.disable",
    "socket.timeout.ms",
    "sticky.partitioning.linger.ms",
    "topic.metadata.refresh.interval.ms",
];

fn rules_for(plugin_name: &str) -> Vec<Rule> {
    match plugin_name {
        "otel_tracing" => vec![
            endpoint(&["endpoint"]),
            secret(&["authorization"]),
            secret(&["headers", "*"]),
        ],
        "spec_expose" => vec![endpoint(&["spec_url"])],
        "grpc_method_router"
        | "request_deduplication"
        | "graphql"
        | "rate_limiting"
        | "ws_rate_limiting"
        | "udp_rate_limiting"
        | "ai_rate_limiter" => REDIS_URL.to_vec(),
        "jwks_auth" => vec![
            endpoint(&["providers", "*", "discovery_url"]),
            endpoint(&["providers", "*", "jwks_uri"]),
            endpoint(&["discovery_url"]),
            endpoint(&["jwks_uri"]),
        ],
        "oauth2_introspection" => vec![
            secret(&["providers", "*", "client_auth", "client_secret"]),
            secret(&["providers", "*", "client_auth", "private_key_pem"]),
            endpoint(&["providers", "*", "discovery_url"]),
            endpoint(&["providers", "*", "introspection_endpoint"]),
            endpoint(&["discovery_url"]),
            endpoint(&["introspection_endpoint"]),
        ],
        "oidc_relying_party" => vec![
            secret(&["providers", "*", "client_auth", "client_secret"]),
            secret(&["providers", "*", "client_auth", "private_key_pem"]),
            secret(&["session", "encryption_secret"]),
            secret(&["session", "encryption_secret_previous"]),
            endpoint(&["providers", "*", "discovery_url"]),
            endpoint(&["providers", "*", "jwks_uri"]),
            endpoint(&["providers", "*", "token_endpoint"]),
            endpoint(&["providers", "*", "authorization_endpoint"]),
            endpoint(&["providers", "*", "userinfo_endpoint"]),
            endpoint(&["providers", "*", "end_session_endpoint"]),
            endpoint(&["discovery_url"]),
            endpoint(&["jwks_uri"]),
            endpoint(&["token_endpoint"]),
            endpoint(&["authorization_endpoint"]),
            endpoint(&["userinfo_endpoint"]),
            endpoint(&["end_session_endpoint"]),
        ],
        "ldap_auth" => vec![
            endpoint(&["ldap_url"]),
            endpoint(&["failover_ldap_urls"]),
            secret(&["service_account_password"]),
        ],
        "soap_ws_security" => vec![
            endpoint(&["redis_url"]),
            secret(&["redis_password"]),
            secret(&["username_token", "credentials", "*", "password"]),
        ],
        "opa" => vec![secret(&["headers", "*"])],
        "ai_transcript_audit" => vec![
            endpoint(&["sink", "endpoint_url"]),
            secret(&["sink", "custom_headers", "*"]),
            endpoint(&["endpoint_url"]),
            secret(&["headers", "*"]),
            secret(&["custom_headers", "*"]),
        ],
        "ai_semantic_firewall" => vec![endpoint(&["provider", "endpoint"])],
        "ai_tool_governor" => vec![
            endpoint(&["endpoint_url"]),
            endpoint(&["approval", "endpoint_url"]),
        ],
        "ai_stream_router" => vec![endpoint(&["providers", "*", "endpoint"])],
        "mcp_gateway" => vec![
            endpoint(&["servers", "*", "upstream_url"]),
            endpoint(&["upstream_url"]),
        ],
        "ai_semantic_cache" => vec![
            endpoint(&["redis_url"]),
            endpoint(&["semantic_embedding_endpoint"]),
            secret(&["semantic_embedding_auth_header"]),
        ],
        "serverless_function" => vec![
            endpoint(&["function_url"]),
            endpoint(&["aws_endpoint_url"]),
            secret(&["azure_function_key"]),
        ],
        "ai_federation" => vec![
            endpoint(&["base_url"]),
            endpoint(&["providers", "*", "base_url"]),
        ],
        "http_logging" => vec![
            endpoint(&["endpoint_url"]),
            secret(&["custom_headers", "*"]),
        ],
        "kafka_logging" => vec![Rule {
            path: &["producer_config"],
            kind: RuleKind::KafkaProperties,
        }],
        "loki_logging" => vec![
            endpoint(&["endpoint_url"]),
            secret(&["authorization_header"]),
            secret(&["custom_headers", "*"]),
        ],
        // Ferrum Edge v0.9.19 redacts these, so `/config/export` fingerprints
        // them. `header_present` values are shared secrets (Edge requires at
        // least 16 characters); the rest are operator-chosen values with no
        // gateway minimum.
        "ws_logging" => vec![
            endpoint(&["endpoint_url"]),
            operator_value(&["custom_headers", "*"]),
        ],
        "waf" => vec![secret(&["global_exemptions", "header_present", "*"])],
        "request_transformer" => vec![operator_value(&["rules", "*", "value"])],
        "mesh_route_dispatch" => vec![operator_value(&[
            "rules",
            "*",
            "request_transform",
            "*",
            "value",
        ])],
        "fault_injection" => vec![operator_value(&["match", "headers", "*"])],
        "response_mock" => vec![
            operator_value(&["rules", "*", "match", "headers", "*"]),
            operator_value(&["rules", "*", "match", "query_params", "*"]),
        ],
        "proxy_alerts" => vec![
            endpoint(&["channels", "*", "webhook_url"]),
            endpoint(&["channels", "*", "url"]),
            secret(&["channels", "*", "headers", "*"]),
            secret(&["channels", "*", "body_template"]),
        ],
        "api_chargeback_sink" => vec![
            endpoint(&["clickhouse", "url"]),
            secret(&["clickhouse", "insert_query_params", "*"]),
        ],
        "workload_metrics" => vec![
            endpoint(&["tracing_provider", "config", "url"]),
            endpoint(&["tracing_provider", "config", "agent_url"]),
            endpoint(&["tracing_provider", "config", "collector_url"]),
            endpoint(&["tracing_provider", "config", "endpoint"]),
            endpoint(&["tracing_providers", "*", "config", "url"]),
            endpoint(&["tracing_providers", "*", "config", "agent_url"]),
            endpoint(&["tracing_providers", "*", "config", "collector_url"]),
            endpoint(&["tracing_providers", "*", "config", "endpoint"]),
        ],
        _ => Vec::new(),
    }
}

/// What a plugin config's string leaves were classified as.
#[derive(Debug, Default, Clone)]
pub(crate) struct PluginConfigClassification {
    /// Leaves import must move into the private broker bundle.
    pub sensitive: Vec<Vec<ConfigPathComponent>>,
    /// Leaves requiring explicit plaintext allowance: heuristic matches outside
    /// the builtin's schema rules, or unflagged strings in a non-builtin plugin.
    /// Import must refuse before publication unless the operator accepts them.
    pub unbrokered: Vec<Vec<ConfigPathComponent>>,
}

/// Classify a plugin config's string leaves.
///
/// Three cases:
///
/// * **A config that is not an object** (a bare string, a list). There is no
///   key to judge anything by, so every string is brokered and nothing is
///   reported for review — fail closed, exactly as before.
/// * **A builtin plugin.** Its schema-declared rules ([`rules_for`]) select
///   brokered leaves. Secret-looking key/URL heuristic matches outside those
///   rules require explicit plaintext allowance; other leaves stay literal.
/// * **A non-builtin (custom, future, or renamed) plugin.** Only the
///   heuristics apply. Brokering *every* string leaf, which is what this used
///   to do, means a plugin whose config is `{"mode": "strict"}` has `strict`
///   captured into a GitHub Environment Secret and replaced with
///   `${gh-env-secret:alloc=require}` — the imported repo then cannot be
///   applied until someone hand-seeds a slot for the word "strict", and the
///   resource file no longer says what the plugin does. The unflagged leaves
///   are returned in `unbrokered` so the operator reviews them instead.
pub(crate) fn classify_plugin_config(
    plugin_name: &str,
    config: &Value,
) -> PluginConfigClassification {
    let mut sensitive = BTreeSet::new();
    let root = Vec::new();

    if !config.is_null() && !config.is_object() {
        collect_string_paths(config, &root, &mut sensitive);
        return PluginConfigClassification {
            sensitive: sensitive.into_iter().collect(),
            unbrokered: Vec::new(),
        };
    }

    if !is_builtin(plugin_name) {
        collect_heuristic_paths(config, &root, &mut sensitive, false);
        let mut all = BTreeSet::new();
        collect_string_paths(config, &root, &mut all);
        let unbrokered = all.difference(&sensitive).cloned().collect();
        return PluginConfigClassification {
            sensitive: sensitive.into_iter().collect(),
            unbrokered,
        };
    }

    // Operator values too short to broker or scrub are ordinary settings: the
    // schema rule, not the key-name heuristic, decides them.
    let mut ordinary = BTreeSet::new();
    for rule in rules_for(plugin_name) {
        if matches!(rule.kind, RuleKind::Value) {
            let mut values = BTreeSet::new();
            apply_rule(config, rule.path, rule.kind, &root, &mut values);
            for path in values {
                match value_at(config, &path) {
                    Some(Value::String(text)) if text.len() < MIN_SCRUB_LENGTH => {
                        ordinary.insert(path);
                    }
                    _ => {
                        sensitive.insert(path);
                    }
                }
            }
        } else {
            apply_rule(config, rule.path, rule.kind, &root, &mut sensitive);
        }
    }
    let mut heuristic = BTreeSet::new();
    collect_heuristic_paths(config, &root, &mut heuristic, true);
    let unbrokered = heuristic
        .into_iter()
        .filter(|path| !sensitive.contains(path) && !ordinary.contains(path))
        .collect();
    PluginConfigClassification {
        sensitive: sensitive.into_iter().collect(),
        unbrokered,
    }
}

/// Return every sensitive string for redaction and security checks, including
/// builtin heuristic matches that import gates instead of automatically brokering.
pub(crate) fn sensitive_string_paths(
    plugin_name: &str,
    config: &Value,
) -> Vec<Vec<ConfigPathComponent>> {
    let classification = classify_plugin_config(plugin_name, config);
    let mut sensitive: BTreeSet<_> = classification.sensitive.into_iter().collect();
    if is_builtin(plugin_name) {
        sensitive.extend(classification.unbrokered);
    }
    sensitive.into_iter().collect()
}

/// Every location `/config/export` fingerprints that the repository can
/// put its declared value back at: [`sensitive_string_paths`], plus the node
/// each secret, endpoint or [`RuleKind::Value`] rule matches, as a whole.
/// Edge fingerprints the whole non-null value at a secret site, and at an
/// endpoint site that is not a string, whatever its length or JSON type (a
/// `request_transformer` body rule's `value` may be `true`, a number or an
/// object; `failover_ldap_urls` is an array). Matching the site itself keeps
/// such a value comparable against a baseline instead of reading as drift
/// or as a masked ancestor.
pub(crate) fn export_redacted_paths(
    plugin_name: &str,
    config: &Value,
) -> BTreeSet<Vec<ConfigPathComponent>> {
    let mut found: BTreeSet<_> = sensitive_string_paths(plugin_name, config)
        .into_iter()
        .collect();
    if !config.is_object() || !is_builtin(plugin_name) {
        return found;
    }
    for rule in rules_for(plugin_name) {
        if matches!(rule.kind, RuleKind::KafkaProperties) {
            continue;
        }
        walk_rule(config, rule.path, &[], &mut |node, path, complete| {
            if complete && !node.is_null() {
                found.insert(path.to_vec());
            }
        });
    }
    found
}

/// The LDAP scheme an `ldap_auth` config already commits to, if any.
///
/// Edge refuses an `ldap_url` and `failover_ldap_urls` that mix `ldap` and
/// `ldaps`, so a validator stand-in for an unresolved endpoint must use the
/// scheme of a literal or resolved one (the primary first) rather than the
/// `ldaps` default of [`endpoint_scheme`].
pub(crate) fn declared_ldap_scheme(plugin_name: &str, config: &Value) -> Option<&'static str> {
    if plugin_name != "ldap_auth" {
        return None;
    }
    let endpoints = endpoint_paths(plugin_name, config);
    let is_primary = |path: &[ConfigPathComponent]| matches!(path.first(), Some(ConfigPathComponent::Key(key)) if normalize_key(key) == "ldapurl");
    endpoints
        .iter()
        .filter(|path| is_primary(path))
        .chain(endpoints.iter().filter(|path| !is_primary(path)))
        .find_map(|path| {
            let text = value_at(config, path)?
                .as_str()?
                .trim()
                .to_ascii_lowercase();
            if text.starts_with("ldaps://") {
                Some("ldaps")
            } else if text.starts_with("ldap://") {
                Some("ldap")
            } else {
                None
            }
        })
}

/// The leaves this plugin's schema rules classify as **endpoints** — a URL,
/// URI or DSN the gateway parses — as opposed to opaque secret material.
///
/// Brokering an endpoint is right (a URL routinely carries userinfo, a query
/// token, or an internal hostname), but it changes what the field *looks*
/// like: `ferrum-edge validate` parses `ldap_auth.ldap_url` and grades
/// `${gh-env-secret:alloc=require}` as a malformed URL, so a secretless PR run
/// fails on the brokering rather than on the configuration. The validator
/// stand-in generator ([`crate::validate::standin`]) uses this to fabricate a
/// syntactically valid URL for the temp spec instead of an opaque token.
///
/// Only the rule-declared endpoints are returned. The key/URL heuristics stay
/// out: they fire on names like `api_key`, and a leaf they flagged for
/// containing userinfo is a URL whose scheme we can no longer read off the
/// document (it is a placeholder by then), so guessing one buys nothing that
/// the opaque stand-in does not already give.
pub(crate) fn endpoint_paths(
    plugin_name: &str,
    config: &Value,
) -> BTreeSet<Vec<ConfigPathComponent>> {
    let mut found = BTreeSet::new();
    if config.is_null() || !config.is_object() {
        return found;
    }
    for rule in rules_for(plugin_name) {
        if matches!(rule.kind, RuleKind::Endpoint) {
            apply_rule(config, rule.path, rule.kind, &[], &mut found);
        }
    }
    found
}

/// The leaves a builtin plugin's schema rules name explicitly: its declared
/// secrets and endpoints, and the Kafka producer properties named like a
/// credential (`sasl.password`). The rest of the Kafka properties are left
/// out (that rule keeps every property not on a safe list, such as
/// `security.protocol: SSL`), as are [`RuleKind::Value`] leaves, the key/URL
/// heuristics and every leaf of a custom plugin or of a config that is not an
/// object.
///
/// Display admission refuses the run for a declared leaf too short to
/// protect, while a short leaf only the heuristics flag (a header name under
/// a `key` field, say) is not registered.
pub(crate) fn rule_declared_paths(
    plugin_name: &str,
    config: &Value,
) -> BTreeSet<Vec<ConfigPathComponent>> {
    let mut found = BTreeSet::new();
    if !config.is_object() || !is_builtin(plugin_name) {
        return found;
    }
    for rule in rules_for(plugin_name) {
        match rule.kind {
            RuleKind::Secret | RuleKind::Endpoint => {
                apply_rule(config, rule.path, rule.kind, &[], &mut found);
            }
            RuleKind::Value => {}
            RuleKind::KafkaProperties => {
                let mut properties = BTreeSet::new();
                apply_rule(config, rule.path, rule.kind, &[], &mut properties);
                found.extend(properties.into_iter().filter(|path| match path.last() {
                    Some(ConfigPathComponent::Key(key)) => is_sensitive_key(key),
                    _ => false,
                }));
            }
        }
    }
    found
}

/// URL scheme a stand-in for this endpoint field must carry.
///
/// ferrum-edge does not merely check that an endpoint parses; several plugins
/// require a specific scheme (`ldap_auth` accepts `ldap`/`ldaps`, the Redis
/// clients want a `redis` URL). The rule table keys endpoints by field name,
/// so the field name is what decides here too, with the plugin name as the
/// tiebreaker for a generically named field on a protocol-specific plugin.
/// `https` is the fallback: every remaining builtin endpoint is an HTTP
/// collector, webhook, or discovery document.
pub(crate) fn endpoint_scheme(plugin_name: &str, path: &[ConfigPathComponent]) -> &'static str {
    let leaf = path
        .iter()
        .rev()
        .find_map(|part| match part {
            ConfigPathComponent::Key(key) => Some(normalize_key(key)),
            ConfigPathComponent::Index(_) => None,
        })
        .unwrap_or_default();
    let plugin = normalize_key(plugin_name);
    let says = |needle: &str| leaf.contains(needle) || plugin.contains(needle);

    if says("ldap") {
        "ldaps"
    } else if says("redis") {
        "redis"
    } else if says("kafka") || leaf.contains("broker") {
        "kafka"
    } else {
        "https"
    }
}

/// Render a classified path the way an operator reads it: `headers.x-api-key`,
/// `servers.[0].upstream_url`.
pub(crate) fn render_config_path(path: &[ConfigPathComponent]) -> String {
    if path.is_empty() {
        return "<root>".to_string();
    }
    path.iter()
        .map(|part| match part {
            ConfigPathComponent::Key(key) => key.clone(),
            ConfigPathComponent::Index(index) => format!("[{index}]"),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Resolve a classified path against a plugin config document.
///
/// The read-only twin of the resolver's `plugin_config_value_mut`: both the
/// import capture and the validator-output scrubber need to fetch the leaf a
/// [`sensitive_string_paths`] entry points at, and a path that no longer
/// resolves (a concurrent edit, a future classifier bug) must be `None`
/// rather than a panic.
pub(crate) fn value_at<'a>(
    mut value: &'a Value,
    path: &[ConfigPathComponent],
) -> Option<&'a Value> {
    for part in path {
        value = match part {
            ConfigPathComponent::Key(key) => value.as_object()?.get(key)?,
            ConfigPathComponent::Index(index) => value.as_array()?.get(*index)?,
        };
    }
    Some(value)
}

fn apply_rule(
    value: &Value,
    path: &[&str],
    kind: RuleKind,
    current: &[ConfigPathComponent],
    found: &mut BTreeSet<Vec<ConfigPathComponent>>,
) {
    walk_rule(value, path, current, &mut |node, at, complete| match kind {
        RuleKind::KafkaProperties if complete => collect_kafka_properties(node, at, found),
        _ => collect_string_paths(node, at, found),
    });
}

/// Walk a rule path, calling `visit` with each node it reaches and whether
/// the whole path matched (`false` for a scalar met part-way, which
/// [`apply_rule`] still collects so a mis-shaped config fails closed).
fn walk_rule(
    value: &Value,
    path: &[&str],
    current: &[ConfigPathComponent],
    visit: &mut dyn FnMut(&Value, &[ConfigPathComponent], bool),
) {
    let Some((head, rest)) = path.split_first() else {
        visit(value, current, true);
        return;
    };

    match value {
        Value::Object(map) => {
            if *head == "*" {
                for (key, child) in map {
                    let mut next = current.to_vec();
                    next.push(ConfigPathComponent::Key(key.clone()));
                    walk_rule(child, rest, &next, visit);
                }
            } else {
                let wanted = normalize_key(head);
                for (key, child) in map {
                    if normalize_key(key) == wanted {
                        let mut next = current.to_vec();
                        next.push(ConfigPathComponent::Key(key.clone()));
                        walk_rule(child, rest, &next, visit);
                    }
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Index(index));
                walk_rule(child, if *head == "*" { rest } else { path }, &next, visit);
            }
        }
        _ => visit(value, current, false),
    }
}

fn collect_kafka_properties(
    value: &Value,
    current: &[ConfigPathComponent],
    found: &mut BTreeSet<Vec<ConfigPathComponent>>,
) {
    let Some(properties) = value.as_object() else {
        collect_string_paths(value, current, found);
        return;
    };
    for (key, child) in properties {
        if KAFKA_SAFE_PROPERTIES
            .iter()
            .any(|safe| key.trim().eq_ignore_ascii_case(safe))
        {
            continue;
        }
        let mut next = current.to_vec();
        next.push(ConfigPathComponent::Key(key.clone()));
        collect_string_paths(child, &next, found);
    }
}

fn collect_heuristic_paths(
    value: &Value,
    current: &[ConfigPathComponent],
    found: &mut BTreeSet<Vec<ConfigPathComponent>>,
    builtin: bool,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Key(key.clone()));
                // Keep custom-plugin brokering stable; broaden only the builtin
                // review safety net for compound keys and header-map aliases.
                let builtin_match = builtin
                    && (normalize_key(key).ends_with("key")
                        || matches!(
                            normalize_key(key).as_str(),
                            "extraheaders" | "outboundheaders" | "additionalheaders"
                        ));
                if is_sensitive_key(key) || is_header_container(key) || builtin_match {
                    collect_string_paths(child, &next, found);
                } else {
                    collect_heuristic_paths(child, &next, found, builtin);
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Index(index));
                collect_heuristic_paths(child, &next, found, builtin);
            }
        }
        Value::String(text) if url_has_userinfo(text) => {
            found.insert(current.to_vec());
        }
        _ => {}
    }
}

fn collect_string_paths(
    value: &Value,
    current: &[ConfigPathComponent],
    found: &mut BTreeSet<Vec<ConfigPathComponent>>,
) {
    match value {
        Value::String(_) => {
            found.insert(current.to_vec());
        }
        Value::Object(map) => {
            for (key, child) in map {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Key(key.clone()));
                collect_string_paths(child, &next, found);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Index(index));
                collect_string_paths(child, &next, found);
            }
        }
        _ => {}
    }
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|character| !matches!(character, '-' | '.' | '_'))
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    normalized == "key"
        || normalized.ends_with("token")
        || normalized.contains("authorization")
        || normalized.contains("cookie")
        || normalized.contains("bearer")
        || normalized.contains("password")
        || normalized.contains("passphrase")
        || normalized.contains("passwd")
        || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.contains("privatekey")
        || normalized.contains("serviceaccountjson")
        || normalized.contains("integritykey")
        || normalized.contains("apikey")
        || normalized.contains("accesskey")
        || normalized.contains("functionkey")
        || normalized.contains("webhook")
}

fn is_header_container(key: &str) -> bool {
    matches!(
        normalize_key(key).as_str(),
        "headers" | "customheaders" | "staticheaders" | "requestheaders"
    )
}

fn url_has_userinfo(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    remainder
        .split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dotted(paths: Vec<Vec<ConfigPathComponent>>) -> Vec<String> {
        paths
            .into_iter()
            .map(|path| {
                path.into_iter()
                    .map(|part| match part {
                        ConfigPathComponent::Key(key) => key,
                        ConfigPathComponent::Index(index) => format!("[{index}]"),
                    })
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect()
    }

    #[test]
    fn schema_and_heuristics_cover_opaque_plugin_secrets() {
        let paths = dotted(sensitive_string_paths(
            "otel_tracing",
            &serde_json::json!({
                "endpoint": "https://collector.example/v1/traces?token=abc",
                "headers": {"x-honeycomb-team": "team-secret"},
                "nested": {"clientSecret": "client-secret"},
                "safe": "visible"
            }),
        ));
        assert!(paths.contains(&"endpoint".to_string()));
        assert!(paths.contains(&"headers.x-honeycomb-team".to_string()));
        assert!(paths.contains(&"nested.clientSecret".to_string()));
        assert!(!paths.contains(&"safe".to_string()));
    }

    #[test]
    fn passphrase_and_passwd_spellings_are_sensitive() {
        let paths = dotted(sensitive_string_paths(
            "custom_enterprise_plugin",
            &serde_json::json!({
                "tls_passphrase": "open-sesame",
                "dbPasswd": "hunter2",
                "signing_pass_phrase": "correct horse",
                "passage": "a safe word that merely starts alike"
            }),
        ));
        assert!(paths.contains(&"tls_passphrase".to_string()));
        assert!(paths.contains(&"dbPasswd".to_string()));
        assert!(paths.contains(&"signing_pass_phrase".to_string()));
        assert!(!paths.contains(&"passage".to_string()));
    }

    #[test]
    fn kafka_properties_are_fail_closed_except_for_reviewed_tuning_keys() {
        let paths = dotted(sensitive_string_paths(
            "kafka_logging",
            &serde_json::json!({
                "producer_config": {
                    "acks": "all",
                    "sasl.password": "secret",
                    "future.vendor.property": "unknown"
                }
            }),
        ));
        assert!(!paths.contains(&"producer_config.acks".to_string()));
        assert!(paths.contains(&"producer_config.sasl.password".to_string()));
        assert!(paths.contains(&"producer_config.future.vendor.property".to_string()));
    }

    /// A non-builtin plugin brokers only what the sensitivity heuristics
    /// flag. Everything else stays in the committed file and is reported for
    /// review, because gitforgeops has no schema to judge it by and capturing
    /// `mode: strict` into a GitHub Environment Secret helps nobody.
    #[test]
    fn custom_plugins_broker_only_heuristic_matches_and_report_the_rest() {
        let classification = classify_plugin_config(
            "custom_enterprise_plugin",
            &serde_json::json!({
                "mode": "strict",
                "nested": ["value"],
                "api_key": "live-key",
                "headers": {"x-vendor-auth": "live-header"},
                "callback": "https://user:pw@vendor.example/hook"
            }),
        );

        assert_eq!(
            dotted(classification.sensitive),
            vec!["api_key", "callback", "headers.x-vendor-auth"]
        );
        assert_eq!(
            dotted(classification.unbrokered),
            vec!["mode", "nested.[0]"]
        );
    }

    /// A config that is not an object has no keys to judge, so it still fails
    /// closed with nothing left for review.
    #[test]
    fn non_object_custom_plugin_config_still_fails_closed() {
        let classification =
            classify_plugin_config("custom_enterprise_plugin", &serde_json::json!(["opaque"]));

        assert_eq!(dotted(classification.sensitive), vec!["[0]"]);
        assert!(classification.unbrokered.is_empty());
    }

    /// Schema-covered secrets and ordinary settings need no plaintext allowance.
    #[test]
    fn builtin_plugins_report_nothing_for_review() {
        let classification = classify_plugin_config(
            "otel_tracing",
            &serde_json::json!({"endpoint": "https://collector.example", "safe": "visible"}),
        );

        assert!(classification.unbrokered.is_empty());
    }

    /// Operator-chosen values Edge v0.9.19 redacts are brokered when long
    /// enough to protect and otherwise stay ordinary settings, but every one
    /// is an export site, and none is rule-declared for display admission.
    #[test]
    fn operator_values_are_sensitive_when_protectable_and_always_export_sites() {
        let transform = serde_json::json!({"rules": [
            {"operation": "add", "target": "header", "value": "Bearer long-upstream-value"},
            {"operation": "add", "target": "header", "value": "1"},
            {"operation": "add", "target": "body", "value": true},
            {"operation": "add", "target": "body", "value": {"enabled": "yes"}}
        ]});
        let classification = classify_plugin_config("request_transformer", &transform);
        assert_eq!(dotted(classification.sensitive), vec!["rules.[0].value"]);
        assert!(classification.unbrokered.is_empty());
        assert_eq!(
            dotted(sensitive_string_paths("request_transformer", &transform)),
            vec!["rules.[0].value"]
        );
        assert_eq!(
            dotted(
                export_redacted_paths("request_transformer", &transform)
                    .into_iter()
                    .collect()
            ),
            vec![
                "rules.[0].value",
                "rules.[1].value",
                "rules.[2].value",
                "rules.[3].value"
            ]
        );
        assert!(rule_declared_paths("request_transformer", &transform).is_empty());

        // A short header-map condition the key-name heuristic would flag is
        // decided by the schema rule: an ordinary setting, not a review item.
        for (plugin, config, site) in [
            (
                "mesh_route_dispatch",
                serde_json::json!({"rules": [{"request_transform": [{"value": "on"}]}]}),
                "rules.[0].request_transform.[0].value",
            ),
            (
                "fault_injection",
                serde_json::json!({"match": {"headers": {"x-chaos": "on"}}}),
                "match.headers.x-chaos",
            ),
            (
                "response_mock",
                serde_json::json!({"rules": [{"match": {"query_params": {"page": "2"}}}]}),
                "rules.[0].match.query_params.page",
            ),
            (
                "ws_logging",
                serde_json::json!({"custom_headers": {"x-env": "prod"}}),
                "custom_headers.x-env",
            ),
        ] {
            let classification = classify_plugin_config(plugin, &config);
            assert!(classification.sensitive.is_empty(), "{plugin}");
            assert!(classification.unbrokered.is_empty(), "{plugin}");
            assert!(
                sensitive_string_paths(plugin, &config).is_empty(),
                "{plugin}"
            );
            assert_eq!(
                dotted(export_redacted_paths(plugin, &config).into_iter().collect()),
                vec![site],
                "{plugin}"
            );
            assert!(rule_declared_paths(plugin, &config).is_empty(), "{plugin}");
        }

        let ws =
            serde_json::json!({"custom_headers": {"authorization": "Bearer long-token-value"}});
        assert_eq!(
            dotted(sensitive_string_paths("ws_logging", &ws)),
            vec!["custom_headers.authorization"]
        );
        assert!(rule_declared_paths("ws_logging", &ws).is_empty());

        let waf = serde_json::json!({"global_exemptions": {"header_present": {"x-hop": "s"}}});
        assert_eq!(
            dotted(rule_declared_paths("waf", &waf).into_iter().collect()),
            vec!["global_exemptions.header_present.x-hop"]
        );
    }

    #[test]
    fn rule_matched_nodes_are_export_sites() {
        let ldap = serde_json::json!({
            "ldap_url": "ldaps://ldap1.example:636",
            "failover_ldap_urls": ["ldaps://ldap2.example:636"]
        });
        assert_eq!(
            dotted(
                export_redacted_paths("ldap_auth", &ldap)
                    .into_iter()
                    .collect()
            ),
            vec!["failover_ldap_urls", "failover_ldap_urls.[0]", "ldap_url"]
        );
    }

    #[test]
    fn ldap_schemes_follow_the_committed_endpoints() {
        assert_eq!(
            declared_ldap_scheme(
                "ldap_auth",
                &serde_json::json!({
                    "ldap_url": "${gh-env-secret:alloc=require}",
                    "failover_ldap_urls": ["LDAP://failover.example:389"]
                })
            ),
            Some("ldap")
        );
        assert_eq!(
            declared_ldap_scheme(
                "ldap_auth",
                &serde_json::json!({
                    "ldap_url": "ldaps://primary.example:636",
                    "failover_ldap_urls": ["ldap://failover.example:389"]
                })
            ),
            Some("ldaps")
        );
        assert_eq!(
            declared_ldap_scheme(
                "ldap_auth",
                &serde_json::json!({"ldap_url": "${gh-env-secret:alloc=require}"})
            ),
            None
        );
        assert_eq!(
            declared_ldap_scheme(
                "otel_tracing",
                &serde_json::json!({"endpoint": "ldap://x.example"})
            ),
            None
        );
    }

    #[test]
    fn ldap_failover_urls_are_endpoints() {
        let config = serde_json::json!({
            "ldap_url": "ldaps://ldap1.example:636",
            "failover_ldap_urls": ["ldaps://ldap2.example:636", "ldap://ldap3.example:389"]
        });
        let endpoints: Vec<Vec<ConfigPathComponent>> =
            endpoint_paths("ldap_auth", &config).into_iter().collect();
        assert_eq!(
            dotted(endpoints.clone()),
            vec![
                "failover_ldap_urls.[0]",
                "failover_ldap_urls.[1]",
                "ldap_url"
            ]
        );
        assert_eq!(endpoint_scheme("ldap_auth", &endpoints[0]), "ldaps");
    }

    #[test]
    fn config_paths_render_for_operators() {
        assert_eq!(
            render_config_path(&[
                ConfigPathComponent::Key("servers".to_string()),
                ConfigPathComponent::Index(0),
                ConfigPathComponent::Key("upstream_url".to_string()),
            ]),
            "servers.[0].upstream_url"
        );
        assert_eq!(render_config_path(&[]), "<root>");
    }
}
