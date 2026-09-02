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
            endpoint(&["providers", "*", "discovery_url"]),
            endpoint(&["providers", "*", "introspection_endpoint"]),
            endpoint(&["discovery_url"]),
            endpoint(&["introspection_endpoint"]),
        ],
        "oidc_relying_party" => vec![
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
        "ldap_auth" => vec![endpoint(&["ldap_url"])],
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
        "ws_logging" => vec![endpoint(&["endpoint_url"])],
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

/// Return every string leaf that import must move into the private broker
/// bundle. Unknown/custom plugins fail closed by classifying every string.
pub(crate) fn sensitive_string_paths(
    plugin_name: &str,
    config: &Value,
) -> Vec<Vec<ConfigPathComponent>> {
    let mut paths = BTreeSet::new();
    let root = Vec::new();

    if (!config.is_null() && !config.is_object()) || !is_builtin(plugin_name) {
        collect_string_paths(config, &root, &mut paths);
    } else {
        for rule in rules_for(plugin_name) {
            apply_rule(config, rule.path, rule.kind, &root, &mut paths);
        }
        collect_heuristic_paths(config, &root, &mut paths);
    }

    paths.into_iter().collect()
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
    let Some((head, rest)) = path.split_first() else {
        match kind {
            RuleKind::Secret | RuleKind::Endpoint => collect_string_paths(value, current, found),
            RuleKind::KafkaProperties => collect_kafka_properties(value, current, found),
        }
        return;
    };

    match value {
        Value::Object(map) => {
            if *head == "*" {
                for (key, child) in map {
                    let mut next = current.to_vec();
                    next.push(ConfigPathComponent::Key(key.clone()));
                    apply_rule(child, rest, kind, &next, found);
                }
            } else {
                let wanted = normalize_key(head);
                for (key, child) in map {
                    if normalize_key(key) == wanted {
                        let mut next = current.to_vec();
                        next.push(ConfigPathComponent::Key(key.clone()));
                        apply_rule(child, rest, kind, &next, found);
                    }
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Index(index));
                apply_rule(
                    child,
                    if *head == "*" { rest } else { path },
                    kind,
                    &next,
                    found,
                );
            }
        }
        _ => collect_string_paths(value, current, found),
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
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Key(key.clone()));
                if is_sensitive_key(key) || is_header_container(key) {
                    collect_string_paths(child, &next, found);
                } else {
                    collect_heuristic_paths(child, &next, found);
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Index(index));
                collect_heuristic_paths(child, &next, found);
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

    #[test]
    fn custom_plugins_broker_every_string_leaf() {
        let paths = dotted(sensitive_string_paths(
            "custom_enterprise_plugin",
            &serde_json::json!({"mode": "strict", "nested": ["value"]}),
        ));
        assert_eq!(paths, vec!["mode", "nested.[0]"]);
    }
}
