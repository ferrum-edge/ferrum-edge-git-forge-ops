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

/// Redis sync fields of a plugin that reads them through Edge's shared
/// `RedisConfig::from_plugin_config` beside its own credential settings.
/// `redis_password` is declared outright so import brokers it instead of
/// asking for a plaintext allowance on the key-name heuristic.
const REDIS_URL_AND_PASSWORD: &[Rule] = &[endpoint(&["redis_url"]), secret(&["redis_password"])];

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
        // Arbitrary header maps (here and in `opa`, `ai_transcript_audit`,
        // `http_logging`, `loki_logging`, `proxy_alerts`, `ws_logging`,
        // `ai_tool_governor`, `mcp_gateway`) are operator values, not
        // secrets: a vendor credential usually rides there, but so do
        // ordinary short headers (`X-Scope-OrgID: "12345"`,
        // `x-api-version: "2"`) and Edge sets no minimum. A declared secret
        // shorter than 8 bytes would refuse every live `/backup` read, so a
        // value long enough to protect is brokered, masked and gated while a
        // shorter one stays an ordinary setting (with a warning when its
        // header name looks like a credential). Fields that only ever hold a
        // credential (`authorization`, `authorization_header`) stay secrets.
        "otel_tracing" => vec![
            endpoint(&["endpoint"]),
            secret(&["authorization"]),
            operator_value(&["headers", "*"]),
        ],
        "spec_expose" => vec![endpoint(&["spec_url"])],
        "grpc_method_router"
        | "request_deduplication"
        | "graphql"
        | "rate_limiting"
        | "ws_rate_limiting"
        | "udp_rate_limiting"
        | "ai_rate_limiter" => REDIS_URL.to_vec(),
        // DPoP replay protection (`jwks_auth`) and `replay_scope: "shared"`
        // nonce tracking (`hmac_auth`) read the root Redis fields through
        // Edge's shared `RedisConfig::from_plugin_config`, exactly like the
        // rate limiters. Edge v0.9.20 projects `redis_url` on any plugin by
        // name (later Edge also declares it for both plugins), fingerprinting
        // it in `/config/export` whenever projection changes it (userinfo,
        // query or fragment), so it is an export site here as it is for
        // `rate_limiting`.
        "jwks_auth" => {
            let mut rules = vec![
                endpoint(&["providers", "*", "discovery_url"]),
                endpoint(&["providers", "*", "jwks_uri"]),
                endpoint(&["discovery_url"]),
                endpoint(&["jwks_uri"]),
            ];
            rules.extend_from_slice(REDIS_URL_AND_PASSWORD);
            rules
        }
        "hmac_auth" => REDIS_URL_AND_PASSWORD.to_vec(),
        "oauth2_introspection" => vec![
            secret(&["providers", "*", "client_auth", "client_secret"]),
            secret(CLIENT_ASSERTION_KEY),
            endpoint(&["providers", "*", "discovery_url"]),
            endpoint(&["providers", "*", "introspection_endpoint"]),
            endpoint(&["discovery_url"]),
            endpoint(&["introspection_endpoint"]),
        ],
        "oidc_relying_party" => vec![
            secret(&["providers", "*", "client_auth", "client_secret"]),
            secret(CLIENT_ASSERTION_KEY),
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
        "soap_ws_security" => {
            let mut rules = REDIS_URL_AND_PASSWORD.to_vec();
            rules.push(secret(&["username_token", "credentials", "*", "password"]));
            rules
        }
        "opa" => vec![operator_value(&["headers", "*"])],
        "ai_transcript_audit" => vec![
            endpoint(&["sink", "endpoint_url"]),
            operator_value(&["sink", "custom_headers", "*"]),
            endpoint(&["endpoint_url"]),
            operator_value(&["headers", "*"]),
            operator_value(&["custom_headers", "*"]),
        ],
        // `privacy.snippet_hash_salt` keys the hashes of logged snippets; a
        // reader holding it can confirm guessed snippets against them.
        // Ferrum Edge v0.9.20 accepts it unredacted; later Edge redacts it
        // (ferrum-edge#7054).
        "ai_semantic_firewall" => vec![
            endpoint(&["provider", "endpoint"]),
            secret(&["privacy", "snippet_hash_salt"]),
        ],
        // Edge after v0.9.20 redacts the approval webhook's static headers
        // and each MCP server's upstream request headers: the approval
        // service's or hosted MCP server's credential usually rides there
        // under a vendor name. The same maps carry ordinary short settings
        // (`x-api-version: "2"`) and Edge sets no minimum, so they are
        // operator values like `ws_logging` `custom_headers`: a credential
        // long enough to protect is brokered and gated, while a short value
        // stays literal instead of refusing live admission (a declared
        // secret shorter than 8 bytes refuses every `/backup` read).
        "ai_tool_governor" => vec![
            endpoint(&["endpoint_url"]),
            endpoint(&["approval", "endpoint_url"]),
            operator_value(&["approval", "headers", "*"]),
        ],
        "ai_stream_router" => vec![endpoint(&["providers", "*", "endpoint"])],
        "mcp_gateway" => vec![
            endpoint(&["servers", "*", "upstream_url"]),
            endpoint(&["upstream_url"]),
            operator_value(&["servers", "*", "headers", "*"]),
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
            operator_value(&["custom_headers", "*"]),
        ],
        "kafka_logging" => vec![Rule {
            path: &["producer_config"],
            kind: RuleKind::KafkaProperties,
        }],
        "loki_logging" => vec![
            endpoint(&["endpoint_url"]),
            secret(&["authorization_header"]),
            operator_value(&["custom_headers", "*"]),
        ],
        // Ferrum Edge v0.9.19 redacts these, so `/config/export` fingerprints
        // them. `header_present` values are shared secrets (Edge requires at
        // least 16 characters); the rest are operator-chosen values with no
        // gateway minimum.
        "ws_logging" => vec![
            endpoint(&["endpoint_url"]),
            operator_value(&["custom_headers", "*"]),
        ],
        // `conditions.headers` values scope a custom rule or override to
        // requests carrying a header value. Edge after v0.9.20 redacts them
        // because an operator may target with a shared secret, as for
        // `fault_injection`; a `null` (presence-only) condition stays `null`.
        "waf" => vec![
            secret(&["global_exemptions", "header_present", "*"]),
            operator_value(&["custom_rules", "*", "conditions", "headers", "*"]),
            operator_value(&["rule_overrides", "*", "conditions", "headers", "*"]),
        ],
        // Since Edge v0.9.19 every `bypass.header_present` value is a shared
        // secret (16 to 4096 visible ASCII characters) whose exact presence
        // skips OpenAPI request validation, the same kind of value as the
        // `waf` exemption above (GHSA-5p93-qfr5-m7m9). Edge v0.9.20 does not
        // yet redact it; later Edge does (ferrum-edge#7054).
        "openapi_validator" => vec![secret(&["bypass", "header_present", "*"])],
        "request_transformer" => vec![operator_value(&["rules", "*", "value"])],
        // Match operands (Edge after v0.9.20) select a route by a value the
        // client presents, which may be a shared secret. Each is a bare
        // string or a one-key `{exact|prefix|regex: ...}` object: the
        // trailing `*` matches the bare string (a scalar where a container is
        // expected) and the object form's inner value.
        "mesh_route_dispatch" => vec![
            operator_value(&["rules", "*", "request_transform", "*", "value"]),
            operator_value(&["rules", "*", "match", "headers", "*", "*"]),
            operator_value(&["rules", "*", "match", "without_headers", "*", "*"]),
            operator_value(&["rules", "*", "match", "query_params", "*", "*"]),
        ],
        // Operator-chosen selector tokens Edge after v0.9.20 redacts: the
        // header value a request must carry to be terminated or captured.
        // Neither has a gateway minimum, so short ones stay literal.
        "request_termination" => vec![operator_value(&["trigger", "header_value"])],
        "transaction_debugger" => vec![operator_value(&["capture_request_header_value"])],
        "fault_injection" => vec![operator_value(&["match", "headers", "*"])],
        "response_mock" => vec![
            operator_value(&["rules", "*", "match", "headers", "*"]),
            operator_value(&["rules", "*", "match", "query_params", "*"]),
        ],
        "proxy_alerts" => vec![
            endpoint(&["channels", "*", "webhook_url"]),
            endpoint(&["channels", "*", "url"]),
            operator_value(&["channels", "*", "headers", "*"]),
            secret(&["channels", "*", "body_template"]),
        ],
        // `clickhouse.insert_query_params` is an export-only site (see
        // `export_only_rules_for`): Edge rejects credential-named keys.
        "api_chargeback_sink" => vec![endpoint(&["clickhouse", "url"])],
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

/// Sites the Ferrum Edge `plugin_config_projection` on `main` (after the pinned
/// v0.9.20) withholds from `/config/export` that [`rules_for`] does not
/// declare. They only extend [`export_redacted_paths`], so a fingerprint at one
/// of them is substituted and counted as uncompared instead of reading as
/// permanent drift once the pin moves; a gateway that does not fingerprint
/// them (v0.9.20) still compares them as ordinary values. Import brokering,
/// redaction, scrubbing and display admission are unchanged for them, with
/// one exception: a credential-named key of a
/// [`credential_named_parameter_maps`] map (`api_chargeback_sink`
/// `clickhouse.insert_query_params`) joins the builtin heuristic matches, so
/// it needs an import plaintext allowance, is literal-gated and is scrubbed.
///
/// Three kinds of site belong here:
///
/// * Values Edge merely withholds: endpoint URLs and paths (`opa`
///   `opa_host`, a `mesh_route_dispatch` rewrite, a mirror path, the
///   `mesh_authz` slice's collector, JWKS and federation URLs) and TLS
///   certificate and key sources. The TLS-source and endpoint rules withhold
///   only some values (inline key material, a non-trivial path, a
///   credential-bearing URL); listing the site is harmless for the rest,
///   because only a live fingerprint is substituted.
/// * The `mesh_authz` policy operands and slice payloads Edge classifies as
///   `secret` (`to.*.headers.*`, `when.*.values` / `not_values`, the
///   external-authorization header values and `path_prefix`, ProxyConfig
///   `environment`, extension `value`). Brokering them is deliberately
///   deferred: Edge withholds every `when` value because a path rule cannot
///   read the sibling `key`, so most are principals, namespaces, IPs and
///   claims rather than credentials, and brokering them would move routine
///   authorization identities into the secret broker. A `to.*.headers.*`
///   value is still caught by the header-map heuristic (an import plaintext
///   allowance and the literal-secret gate).
/// * `api_chargeback_sink` `clickhouse.insert_query_params.*`. Edge v0.9.20
///   and later redact every value, but their own validation refuses a
///   credential-named key (`password`, `user`, `access_token`, `session_id`,
///   anything containing `apikey`, `api_key`, `credential`, `passwd`,
///   `secret` or `token`) and the reserved `database` / `query`, so an
///   accepted key is a ClickHouse setting (`async_insert`,
///   `session_timezone`). Its value stays literal; brokering
///   `date_time_input_format: best_effort` would demand a hand-seeded slot
///   for a tuning knob. A credential-named key that reaches the repository
///   anyway (import reads a backup file without Edge's validation) is still
///   flagged by [`credential_named_parameter_maps`], which runs the key-name
///   heuristics plus Edge's own refused names on these keys: an import
///   plaintext allowance and the literal-secret gate.
///
/// Every other credential or operator-chosen token Edge redacts is a
/// [`rules_for`] rule instead (brokered, literal-gated and masked), whether
/// or not the pinned gateway redacts it yet.
fn export_only_rules_for(plugin_name: &str) -> &'static [&'static [&'static str]] {
    match plugin_name {
        "mtls_auth" => &[&["allowed_issuers", "*", "ca_certificate_pem"]],
        "soap_ws_security" => &[
            &["x509_signature", "trusted_certs", "*"],
            &["saml", "trusted_signing_certs", "*"],
        ],
        "mesh_authz" => &[
            &[
                "mesh_policies",
                "*",
                "rules",
                "*",
                "to",
                "*",
                "headers",
                "*",
            ],
            &[
                "mesh_policies",
                "*",
                "rules",
                "*",
                "when",
                "*",
                "values",
                "*",
            ],
            &[
                "mesh_policies",
                "*",
                "rules",
                "*",
                "when",
                "*",
                "not_values",
                "*",
            ],
            &[
                "mesh_slice",
                "mesh_policies",
                "*",
                "rules",
                "*",
                "to",
                "*",
                "headers",
                "*",
            ],
            &[
                "mesh_slice",
                "mesh_policies",
                "*",
                "rules",
                "*",
                "when",
                "*",
                "values",
                "*",
            ],
            &[
                "mesh_slice",
                "mesh_policies",
                "*",
                "rules",
                "*",
                "when",
                "*",
                "not_values",
                "*",
            ],
            &[
                "mesh_slice",
                "node_waypoint_capture_mesh_policies",
                "*",
                "rules",
                "*",
                "to",
                "*",
                "headers",
                "*",
            ],
            &[
                "mesh_slice",
                "node_waypoint_capture_mesh_policies",
                "*",
                "rules",
                "*",
                "when",
                "*",
                "values",
                "*",
            ],
            &[
                "mesh_slice",
                "node_waypoint_capture_mesh_policies",
                "*",
                "rules",
                "*",
                "when",
                "*",
                "not_values",
                "*",
            ],
            &[
                "mesh_slice",
                "ext_authz_providers",
                "*",
                "include_additional_headers_in_check",
                "*",
                "value",
            ],
            &["mesh_slice", "ext_authz_providers", "*", "path_prefix"],
            &["mesh_slice", "proxy_configs", "*", "environment", "*"],
            &["mesh_slice", "extension_configs", "*", "value"],
            &[
                "mesh_slice",
                "telemetry_resources",
                "*",
                "config",
                "tracing",
                "providers",
                "*",
                "config",
                "url",
            ],
            &[
                "mesh_slice",
                "telemetry_resources",
                "*",
                "config",
                "tracing",
                "providers",
                "*",
                "config",
                "agent_url",
            ],
            &[
                "mesh_slice",
                "telemetry_resources",
                "*",
                "config",
                "tracing",
                "providers",
                "*",
                "config",
                "collector_url",
            ],
            &[
                "mesh_slice",
                "telemetry_resources",
                "*",
                "config",
                "tracing",
                "providers",
                "*",
                "config",
                "endpoint",
            ],
            &[
                "mesh_slice",
                "request_authentications",
                "*",
                "jwt_rules",
                "*",
                "jwks_uri",
            ],
            &["mesh_slice", "multi_cluster", "federation_endpoint"],
            &[
                "mesh_slice",
                "multi_cluster",
                "remote_clusters",
                "*",
                "control_plane_url",
            ],
            &[
                "mesh_slice",
                "multi_cluster",
                "remote_clusters",
                "*",
                "federation_endpoint",
            ],
        ],
        // Edge projects the OPA server URL structurally like any endpoint
        // (it may carry a base path); it names a server, not a credential,
        // and URL userinfo is caught by the import heuristics.
        "opa" => &[&["opa_host"]],
        // A backend path rewrite is projected like an endpoint path.
        "mesh_route_dispatch" => &[&["rules", "*", "rewrite", "uri"]],
        "api_chargeback_sink" => &[CHARGEBACK_INSERT_QUERY_PARAMS],
        "request_mirror" => &[&["mirror_path"]],
        "udp_logging" => &[
            &["dtls_key_path"],
            &["dtls_cert_path"],
            &["dtls_ca_cert_path"],
        ],
        _ => &[],
    }
}

/// `api_chargeback_sink` `clickhouse.insert_query_params`: an export-only site
/// whose keys are also judged by [`credential_named_parameter_maps`].
const CHARGEBACK_INSERT_QUERY_PARAMS: &[&str] = &["clickhouse", "insert_query_params", "*"];

/// Literal parameter maps (keyed by parameter name, not brokered) whose keys
/// are judged by [`parameter_name_looks_like_credential`]: a string under a
/// credential-named key joins the builtin heuristic matches, so import needs
/// a plaintext allowance for it and `apply` refuses it as a literal secret.
/// Every other value in the map stays an ordinary setting.
/// Every entry must also be an [`export_only_rules_for`] entry (a test pins
/// it), so moving the map in one place cannot silently drop the gate.
fn credential_named_parameter_maps(plugin_name: &str) -> &'static [&'static [&'static str]] {
    match plugin_name {
        "api_chargeback_sink" => &[CHARGEBACK_INSERT_QUERY_PARAMS],
        _ => &[],
    }
}

/// Parameter names (normalized, see [`normalize_key`]) Ferrum Edge's
/// `api_chargeback_sink` validation refuses outright
/// (`CREDENTIAL_QUERY_PARAM_NAMES`), plus short credential spellings no
/// ClickHouse setting uses (`pwd`, `pass`, `auth`, `sig`, `signature`).
const CREDENTIAL_PARAMETER_NAMES: &[&str] = &[
    "accesstoken",
    "password",
    "sessionid",
    "user",
    "pwd",
    "pass",
    "auth",
    "sig",
    "signature",
];

/// Substrings (normalized) that make Edge refuse a parameter name
/// (`CREDENTIAL_QUERY_PARAM_MARKERS`; `api_key` normalizes to `apikey`).
const CREDENTIAL_PARAMETER_MARKERS: &[&str] =
    &["apikey", "credential", "passwd", "secret", "token"];

/// Whether a literal parameter's name looks like a credential: the key-name
/// heuristics ([`name_looks_like_credential`]), plus every name Edge's
/// validation would refuse, in case a repository or backup file holds one.
fn parameter_name_looks_like_credential(name: &str) -> bool {
    let normalized = normalize_key(name);
    name_looks_like_credential(name)
        || CREDENTIAL_PARAMETER_NAMES.contains(&normalized.as_str())
        || CREDENTIAL_PARAMETER_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
}

/// String leaves under a credential-named key of a
/// [`credential_named_parameter_maps`] map.
fn collect_credential_named_parameters(
    plugin_name: &str,
    config: &Value,
    found: &mut BTreeSet<Vec<ConfigPathComponent>>,
) {
    for path in credential_named_parameter_maps(plugin_name) {
        walk_rule(config, path, &[], &mut |node, at, complete| {
            let named = matches!(
                at.last(),
                Some(ConfigPathComponent::Key(name)) if parameter_name_looks_like_credential(name)
            );
            if complete && named {
                collect_string_paths(node, at, found);
            }
        });
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
    /// Non-empty [`RuleKind::Value`] leaves too short to broker (so ordinary
    /// settings) whose entry name looks like a credential (`authorization`,
    /// `x-functions-key`, `token`). They are committed and applied literally
    /// and cannot be scrubbed, so import and the security audit warn about
    /// each one instead of staying silent.
    pub short_credential_named: Vec<Vec<ConfigPathComponent>>,
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
            short_credential_named: Vec::new(),
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
            short_credential_named: Vec::new(),
        };
    }

    // Operator values too short to broker or scrub are ordinary settings: the
    // schema rule, not the key-name heuristic, decides them.
    let mut ordinary = BTreeSet::new();
    let mut short_credential_named = BTreeSet::new();
    for rule in rules_for(plugin_name) {
        if matches!(rule.kind, RuleKind::Value) {
            let mut values = BTreeSet::new();
            apply_rule(config, rule.path, rule.kind, &root, &mut values);
            for path in values {
                match value_at(config, &path) {
                    Some(Value::String(text)) if text.len() < MIN_SCRUB_LENGTH => {
                        if !text.is_empty() && value_name_looks_like_credential(config, &path) {
                            short_credential_named.insert(path.clone());
                        }
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
    collect_credential_named_parameters(plugin_name, config, &mut heuristic);
    let unbrokered = heuristic
        .into_iter()
        .filter(|path| !sensitive.contains(path) && !ordinary.contains(path))
        .collect();
    PluginConfigClassification {
        sensitive: sensitive.into_iter().collect(),
        unbrokered,
        short_credential_named: short_credential_named.into_iter().collect(),
    }
}

/// Match-kind keys of an operand object (`{exact: ...}`); the entry they
/// belong to is named one level up.
const OPERAND_KINDS: &[&str] = &["exact", "prefix", "suffix", "regex", "contains"];

/// Value fields whose header or field name sits in a sibling field, with the
/// sibling keys that may carry it (`request_transformer` and
/// `mesh_route_dispatch` request-transform `{operation, target, key, value}`,
/// `request_termination` `{header, header_value}`, `transaction_debugger`
/// `{capture_request_header, capture_request_header_value}`).
const SIBLING_NAMED_VALUES: &[(&str, &[&str])] = &[
    ("value", &["key"]),
    ("headervalue", &["header"]),
    ("capturerequestheadervalue", &["capturerequestheader"]),
];

/// Whether a name looks like a credential: the key-name heuristics, plus any
/// name ending in `key` (`x-functions-key`, `Ocp-Apim-Subscription-Key`).
fn name_looks_like_credential(name: &str) -> bool {
    is_sensitive_key(name) || normalize_key(name).ends_with("key")
}

/// Whether the header, parameter or field a matched leaf sets is named like
/// a credential. The name is the map entry the leaf belongs to (skipping an
/// operand's match-kind key), or, for a value field whose name sits beside
/// it ([`SIBLING_NAMED_VALUES`]), that sibling string. A leaf ending in an
/// array index (an element inside a structured value, such as a
/// `request_transformer` body rule's `{"authorization": ["..."]}`) has no
/// sibling name and is judged by its nearest enclosing key.
fn value_name_looks_like_credential(config: &Value, path: &[ConfigPathComponent]) -> bool {
    if sibling_name_looks_like_credential(config, path) {
        return true;
    }
    let mut keys = path.iter().rev().filter_map(|part| match part {
        ConfigPathComponent::Key(key) => Some(key.as_str()),
        ConfigPathComponent::Index(_) => None,
    });
    let Some(mut name) = keys.next() else {
        return false;
    };
    if OPERAND_KINDS.contains(&normalize_key(name).as_str()) {
        let Some(entry) = keys.next() else {
            return false;
        };
        name = entry;
    }
    name_looks_like_credential(name)
}

/// Whether a leaf ending in a [`SIBLING_NAMED_VALUES`] field sits beside a
/// sibling name field whose string looks like a credential.
fn sibling_name_looks_like_credential(config: &Value, path: &[ConfigPathComponent]) -> bool {
    let Some((ConfigPathComponent::Key(leaf), parent)) = path.split_last() else {
        return false;
    };
    let leaf = normalize_key(leaf);
    let Some(siblings) = SIBLING_NAMED_VALUES
        .iter()
        .find(|(name, _)| *name == leaf)
        .map(|(_, siblings)| *siblings)
    else {
        return false;
    };
    value_at(config, parent)
        .and_then(Value::as_object)
        .is_some_and(|object| {
            object
                .iter()
                .filter(|(key, _)| siblings.contains(&normalize_key(key).as_str()))
                .filter_map(|(_, value)| value.as_str())
                .any(name_looks_like_credential)
        })
}

/// Short, credential-named operator values (see
/// [`PluginConfigClassification::short_credential_named`]).
pub(crate) fn short_credential_named_paths(
    plugin_name: &str,
    config: &Value,
) -> Vec<Vec<ConfigPathComponent>> {
    classify_plugin_config(plugin_name, config).short_credential_named
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
/// each secret, endpoint or [`RuleKind::Value`] rule (and each
/// [`export_only_rules_for`] rule) matches, as a whole. Edge fingerprints the
/// whole non-null value at a secret site, and at an endpoint site that is not
/// a string, whatever its length or JSON type (a `request_transformer` body
/// rule's `value` may be `true`, a number or an object; `failover_ldap_urls`
/// is an array). A non-null scalar met where a rule expects a container is
/// fingerprinted too (Edge fails closed on it). Matching the site itself keeps
/// such a value comparable against a baseline instead of reading as drift or
/// as a masked ancestor.
///
/// A custom (non-built-in) plugin has no schema, so Edge after v0.9.20
/// fingerprints every scalar leaf (string, number, boolean) of its object
/// config; each one is a site.
pub(crate) fn export_redacted_paths(
    plugin_name: &str,
    config: &Value,
) -> BTreeSet<Vec<ConfigPathComponent>> {
    let mut found: BTreeSet<_> = sensitive_string_paths(plugin_name, config)
        .into_iter()
        .collect();
    if !config.is_object() {
        return found;
    }
    if !is_builtin(plugin_name) {
        collect_scalar_leaf_paths(config, &[], &mut found);
        return found;
    }
    let mut site = |node: &Value, path: &[ConfigPathComponent], _complete: bool| {
        if !node.is_null() {
            found.insert(path.to_vec());
        }
    };
    for rule in rules_for(plugin_name) {
        if matches!(rule.kind, RuleKind::KafkaProperties) {
            continue;
        }
        walk_rule(config, rule.path, &[], &mut site);
    }
    for path in export_only_rules_for(plugin_name) {
        walk_rule(config, path, &[], &mut site);
    }
    found
}

/// Every non-null scalar leaf under `value`.
fn collect_scalar_leaf_paths(
    value: &Value,
    current: &[ConfigPathComponent],
    found: &mut BTreeSet<Vec<ConfigPathComponent>>,
) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Key(key.clone()));
                collect_scalar_leaf_paths(child, &next, found);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut next = current.to_vec();
                next.push(ConfigPathComponent::Index(index));
                collect_scalar_leaf_paths(child, &next, found);
            }
        }
        Value::Null => {}
        _ => {
            found.insert(current.to_vec());
        }
    }
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
/// clients want `redis`/`rediss`, `ws_logging` wants `ws`/`wss`). The rule
/// table keys endpoints by field name, so the field name is what decides here
/// too, with the plugin name as the tiebreaker for a generically named field
/// on a protocol-specific plugin. `https` is the fallback: every remaining
/// builtin endpoint is an HTTP collector, webhook, provider, or discovery
/// document.
pub(crate) fn endpoint_scheme(plugin_name: &str, path: &[ConfigPathComponent]) -> &'static str {
    let leaf = endpoint_leaf(path);
    let plugin = normalize_key(plugin_name);
    let says = |needle: &str| leaf.contains(needle) || plugin.contains(needle);

    if says("ldap") {
        "ldaps"
    } else if says("redis") {
        "redis"
    } else if plugin == "wslogging" {
        // The only `ws_logging` endpoint is the collector's WebSocket URL.
        "wss"
    } else {
        "https"
    }
}

/// How much of a URL stand-in beyond its scheme an endpoint field constrains.
///
/// Most builtin endpoints accept any path, so their stand-in carries the
/// slot digest there. A few validate the path itself, and a stand-in that
/// parses but fails that check would swap one spurious CI failure for
/// another; for those the digest moves into a host label on the reserved
/// `.invalid` host instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointForm {
    /// Any path: `<scheme>://<host>/<digest>`.
    DigestPath,
    /// A Redis URL, whose path Edge's `validate_redis_database_selector`
    /// admits only when empty, `/`, or a canonical database number.
    RedisDatabase,
    /// An origin with no path, query or fragment (`serverless_function`
    /// `aws_endpoint_url`, which Edge refuses with any path but `/`).
    Origin,
    /// An `ai_stream_router` provider endpoint. A `google_gemini` provider
    /// routes the model only through the URL, so Edge refuses its endpoint
    /// unless the path carries the `{model}` placeholder (or names the single
    /// exact model the provider admits); every provider type accepts it.
    ModelTemplate,
}

/// The [`EndpointForm`] a stand-in for this endpoint field must take.
pub(crate) fn endpoint_form(plugin_name: &str, path: &[ConfigPathComponent]) -> EndpointForm {
    let leaf = endpoint_leaf(path);
    match normalize_key(plugin_name).as_str() {
        _ if endpoint_scheme(plugin_name, path) == "redis" => EndpointForm::RedisDatabase,
        "serverlessfunction" if leaf == "awsendpointurl" => EndpointForm::Origin,
        "aistreamrouter" if leaf == "endpoint" => EndpointForm::ModelTemplate,
        _ => EndpointForm::DigestPath,
    }
}

/// The nearest object key of a classified endpoint path, normalized.
fn endpoint_leaf(path: &[ConfigPathComponent]) -> String {
    path.iter()
        .rev()
        .find_map(|part| match part {
            ConfigPathComponent::Key(key) => Some(normalize_key(key)),
            ConfigPathComponent::Index(_) => None,
        })
        .unwrap_or_default()
}

/// `private_key_jwt` client-assertion keys: an inline PEM the gateway parses
/// for the sibling `private_key_jwt_alg` and signs a throwaway assertion with
/// at admission (`oauth2_introspection`, `oidc_relying_party`).
const CLIENT_ASSERTION_KEY: &[&str] = &["providers", "*", "client_auth", "private_key_pem"];

/// The sibling of a [`client_assertion_key_paths`] leaf that selects its
/// signing algorithm.
pub(crate) const CLIENT_ASSERTION_ALG_FIELD: &str = "private_key_jwt_alg";

/// Rule-declared secret leaves that hold a `private_key_jwt` signing key,
/// which the validator stand-in generator ([`crate::validate::standin`])
/// replaces with a throwaway key of the selected algorithm's family rather
/// than an opaque token Edge would refuse as malformed PEM.
pub(crate) fn client_assertion_key_paths(
    plugin_name: &str,
    config: &Value,
) -> BTreeSet<Vec<ConfigPathComponent>> {
    let mut found = BTreeSet::new();
    if matches!(plugin_name, "oauth2_introspection" | "oidc_relying_party") && config.is_object() {
        apply_rule(
            config,
            CLIENT_ASSERTION_KEY,
            RuleKind::Secret,
            &[],
            &mut found,
        );
    }
    found
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

    /// `openapi_validator` `bypass.header_present` values and the `waf`
    /// exemption values are the same kind of shared secret, so a header map
    /// is classified identically under both (GHSA-5p93-qfr5-m7m9).
    #[test]
    fn openapi_validator_bypass_secrets_match_the_waf_exemption() {
        let headers = serde_json::json!({
            "x-internal-scan": "synthetic-bypass-value-1",
            "x-second-scan": "synthetic-bypass-value-2"
        });
        let waf = serde_json::json!({"global_exemptions": {"header_present": headers.clone()}});
        let openapi = serde_json::json!({
            "bypass": {"header_present": headers, "paths": ["/health"]}
        });
        let relative = |paths: Vec<Vec<ConfigPathComponent>>, prefix: usize| {
            paths
                .into_iter()
                .map(|path| render_config_path(&path[prefix..]))
                .collect::<Vec<_>>()
        };

        let waf_classified = classify_plugin_config("waf", &waf);
        let openapi_classified = classify_plugin_config("openapi_validator", &openapi);
        assert_eq!(
            relative(openapi_classified.sensitive.clone(), 2),
            relative(waf_classified.sensitive, 2)
        );
        assert_eq!(
            dotted(openapi_classified.sensitive),
            vec![
                "bypass.header_present.x-internal-scan",
                "bypass.header_present.x-second-scan"
            ]
        );
        assert!(openapi_classified.unbrokered.is_empty());
        assert_eq!(
            dotted(sensitive_string_paths("openapi_validator", &openapi)),
            vec![
                "bypass.header_present.x-internal-scan",
                "bypass.header_present.x-second-scan"
            ]
        );
        assert_eq!(
            dotted(
                rule_declared_paths("openapi_validator", &openapi)
                    .into_iter()
                    .collect()
            ),
            vec![
                "bypass.header_present.x-internal-scan",
                "bypass.header_present.x-second-scan"
            ]
        );
    }

    #[test]
    fn ai_semantic_firewall_snippet_hash_salt_is_a_secret() {
        let config = serde_json::json!({
            "privacy": {"include_snippet_hash": true, "snippet_hash_salt": "synthetic-salt-value"}
        });
        let classified = classify_plugin_config("ai_semantic_firewall", &config);
        assert_eq!(
            dotted(classified.sensitive),
            vec!["privacy.snippet_hash_salt"]
        );
        assert!(classified.unbrokered.is_empty());
        assert_eq!(
            dotted(
                rule_declared_paths("ai_semantic_firewall", &config)
                    .into_iter()
                    .collect()
            ),
            vec!["privacy.snippet_hash_salt"]
        );
    }

    /// Edge after v0.9.20 fingerprints every scalar leaf of a custom plugin's
    /// config. Each is an export site, while import still brokers only the
    /// heuristic matches and reports the rest for review.
    #[test]
    fn custom_plugin_scalar_leaves_are_export_sites() {
        let config = serde_json::json!({
            "mode": "strict",
            "retries": 3,
            "enabled": true,
            "unset": null,
            "nested": {"labels": ["a", {"weight": 2.5}]},
            "api_key": "live-key-value"
        });
        assert_eq!(
            dotted(
                export_redacted_paths("custom_enterprise_plugin", &config)
                    .into_iter()
                    .collect()
            ),
            vec![
                "api_key",
                "enabled",
                "mode",
                "nested.labels.[0]",
                "nested.labels.[1].weight",
                "retries"
            ]
        );
        let classification = classify_plugin_config("custom_enterprise_plugin", &config);
        assert_eq!(dotted(classification.sensitive), vec!["api_key"]);
    }

    /// Built-in sites Edge's projection on `main` merely withholds (endpoint
    /// URLs and paths, TLS sources) are export sites only: nothing about
    /// import brokering, redaction or display admission changes for them.
    #[test]
    fn post_v0_9_20_withheld_builtin_sites_are_export_only() {
        for (plugin, config, sites) in [
            (
                "request_mirror",
                serde_json::json!({"mirror_host": "shadow.internal", "mirror_path": "/ingest/t0k"}),
                vec!["mirror_path"],
            ),
            (
                "opa",
                serde_json::json!({"opa_host": "http://opa.internal:8181/v1/base", "policy_path": "authz/allow"}),
                vec!["opa_host"],
            ),
            (
                "mesh_route_dispatch",
                serde_json::json!({"rules": [{"rewrite": {"uri": "/internal/backend-path"}}]}),
                vec!["rules.[0].rewrite.uri"],
            ),
            (
                "udp_logging",
                serde_json::json!({"dtls_key_path": "/etc/ferrum/dtls.key", "dtls_cert_path": "/etc/ferrum/dtls.crt"}),
                vec!["dtls_cert_path", "dtls_key_path"],
            ),
        ] {
            assert_eq!(
                dotted(export_redacted_paths(plugin, &config).into_iter().collect()),
                sites,
                "{plugin}"
            );
            let classification = classify_plugin_config(plugin, &config);
            assert!(classification.sensitive.is_empty(), "{plugin}");
            assert!(rule_declared_paths(plugin, &config).is_empty(), "{plugin}");
        }
    }

    /// The credential header maps Edge after v0.9.20 redacts are operator
    /// values: a credential long enough to protect is brokered, a short
    /// ordinary header (`x-api-version: "2"`) stays literal and is not
    /// rule-declared, so it never refuses live display admission, and every
    /// value is an export site.
    #[test]
    fn post_v0_9_20_credential_header_maps_are_operator_values() {
        for (plugin, config, brokered, declared, sites) in [
            (
                "ai_tool_governor",
                serde_json::json!({"approval": {
                    "endpoint_url": "https://approvals.example/hook",
                    "headers": {"x-approval-auth": "synthetic-approval-token", "x-short": "s"}
                }}),
                vec!["approval.endpoint_url", "approval.headers.x-approval-auth"],
                vec!["approval.endpoint_url"],
                vec![
                    "approval.endpoint_url",
                    "approval.headers.x-approval-auth",
                    "approval.headers.x-short",
                ],
            ),
            (
                "mcp_gateway",
                serde_json::json!({"servers": {"docs": {
                    "upstream_url": "https://mcp.example/docs",
                    "headers": {"Ocp-Apim-Subscription-Key": "synthetic-mcp-key", "x-api-version": "2"}
                }}}),
                vec![
                    "servers.docs.headers.Ocp-Apim-Subscription-Key",
                    "servers.docs.upstream_url",
                ],
                vec!["servers.docs.upstream_url"],
                vec![
                    "servers.docs.headers.Ocp-Apim-Subscription-Key",
                    "servers.docs.headers.x-api-version",
                    "servers.docs.upstream_url",
                ],
            ),
        ] {
            let classification = classify_plugin_config(plugin, &config);
            assert_eq!(dotted(classification.sensitive), brokered, "{plugin}");
            assert!(classification.unbrokered.is_empty(), "{plugin}");
            assert_eq!(
                dotted(sensitive_string_paths(plugin, &config)),
                brokered,
                "{plugin}"
            );
            assert_eq!(
                dotted(rule_declared_paths(plugin, &config).into_iter().collect()),
                declared,
                "{plugin}"
            );
            assert_eq!(
                dotted(export_redacted_paths(plugin, &config).into_iter().collect()),
                sites,
                "{plugin}"
            );
        }
    }

    /// Every arbitrary header map is an operator value: a long value is
    /// brokered, a short ordinary header (`X-Scope-OrgID: "12345"`) stays
    /// literal, and none is rule-declared, so no short live header refuses
    /// display admission. Fields that only ever hold a credential stay
    /// declared secrets.
    #[test]
    fn arbitrary_header_maps_are_operator_values() {
        for (plugin, config, brokered, sites) in [
            (
                "otel_tracing",
                serde_json::json!({"headers": {"x-honeycomb-team": "synthetic-team-key", "x-env": "prod"}}),
                vec!["headers.x-honeycomb-team"],
                vec!["headers.x-env", "headers.x-honeycomb-team"],
            ),
            (
                "opa",
                serde_json::json!({"headers": {"x-bundle-token": "synthetic-opa-token", "x-tier": "a"}}),
                vec!["headers.x-bundle-token"],
                vec!["headers.x-bundle-token", "headers.x-tier"],
            ),
            (
                "ai_transcript_audit",
                serde_json::json!({
                    "sink": {"custom_headers": {"x-ingest": "synthetic-ingest-key", "x-v": "2"}},
                    "headers": {"x-flat": "1"},
                    "custom_headers": {"x-legacy": "synthetic-legacy-key"}
                }),
                vec!["custom_headers.x-legacy", "sink.custom_headers.x-ingest"],
                vec![
                    "custom_headers.x-legacy",
                    "headers.x-flat",
                    "sink.custom_headers.x-ingest",
                    "sink.custom_headers.x-v",
                ],
            ),
            (
                "http_logging",
                serde_json::json!({"custom_headers": {"x-collector": "synthetic-collector", "x-dc": "eu1"}}),
                vec!["custom_headers.x-collector"],
                vec!["custom_headers.x-collector", "custom_headers.x-dc"],
            ),
            (
                "loki_logging",
                serde_json::json!({"custom_headers": {"X-Scope-OrgID": "12345"}}),
                vec![],
                vec!["custom_headers.X-Scope-OrgID"],
            ),
            (
                "proxy_alerts",
                serde_json::json!({"channels": [{"headers": {"x-route": "ops", "x-hook": "synthetic-hook-key"}}]}),
                vec!["channels.[0].headers.x-hook"],
                vec![
                    "channels.[0].headers.x-hook",
                    "channels.[0].headers.x-route",
                ],
            ),
        ] {
            let classification = classify_plugin_config(plugin, &config);
            assert_eq!(dotted(classification.sensitive), brokered, "{plugin}");
            assert!(classification.unbrokered.is_empty(), "{plugin}");
            assert!(classification.short_credential_named.is_empty(), "{plugin}");
            assert!(rule_declared_paths(plugin, &config).is_empty(), "{plugin}");
            assert_eq!(
                dotted(export_redacted_paths(plugin, &config).into_iter().collect()),
                sites,
                "{plugin}"
            );
        }

        for (plugin, config, declared) in [
            (
                "otel_tracing",
                serde_json::json!({"authorization": "s"}),
                "authorization",
            ),
            (
                "loki_logging",
                serde_json::json!({"authorization_header": "s"}),
                "authorization_header",
            ),
        ] {
            assert_eq!(
                dotted(rule_declared_paths(plugin, &config).into_iter().collect()),
                vec![declared],
                "{plugin}"
            );
        }
    }

    /// A short operator value is an ordinary setting, but one whose entry
    /// name looks like a credential (skipping an operand's match-kind key)
    /// is reported so import and the security audit can warn about it.
    #[test]
    fn short_credential_named_operator_values_are_reported() {
        let config = serde_json::json!({"custom_headers": {
            "authorization": "x",
            "x-functions-key": "abc",
            "X-Scope-OrgID": "12345",
            "x-empty-token": "",
            "x-long-token": "synthetic-long-token"
        }});
        let classification = classify_plugin_config("http_logging", &config);
        assert_eq!(
            dotted(classification.short_credential_named),
            vec![
                "custom_headers.authorization",
                "custom_headers.x-functions-key"
            ]
        );
        assert_eq!(
            dotted(classification.sensitive),
            vec!["custom_headers.x-long-token"]
        );
        assert!(classification.unbrokered.is_empty());
        assert_eq!(
            dotted(sensitive_string_paths("http_logging", &config)),
            vec!["custom_headers.x-long-token"]
        );

        let dispatch = serde_json::json!({"rules": [{"match": {"query_params": {
            "token": {"exact": "t1"},
            "page": {"exact": "2"}
        }}}]});
        assert_eq!(
            dotted(short_credential_named_paths(
                "mesh_route_dispatch",
                &dispatch
            )),
            vec!["rules.[0].match.query_params.token.exact"]
        );

        // A value whose name sits in a sibling field is judged by that name.
        let transform = serde_json::json!({"rules": [
            {"key": "X-Api-Key", "value": "k1"},
            {"key": "Authorization", "value": "abc"},
            {"key": "X-Env", "value": "1"}
        ]});
        assert_eq!(
            dotted(short_credential_named_paths(
                "request_transformer",
                &transform
            )),
            vec!["rules.[0].value", "rules.[1].value"]
        );
        // A `mesh_route_dispatch` request transform names its header in
        // `key` (Edge's `RawRouteHeaderTransformRule`); `name` is not a
        // field there, so it names nothing.
        let dispatch_transform = serde_json::json!({"rules": [{"request_transform": [
            {"operation": "add", "target": "header", "key": "X-Api-Key", "value": "k1"},
            {"operation": "add", "target": "header", "key": "x-tier", "value": "gold"},
            {"operation": "add", "target": "header", "key": "x-env", "name": "x-route-token", "value": "t1"}
        ]}]});
        assert_eq!(
            dotted(short_credential_named_paths(
                "mesh_route_dispatch",
                &dispatch_transform
            )),
            vec!["rules.[0].request_transform.[0].value"]
        );
        for (plugin, config, path) in [
            (
                "request_termination",
                serde_json::json!({"trigger": {"header": "x-api-key", "header_value": "k1"}}),
                "trigger.header_value",
            ),
            (
                "transaction_debugger",
                serde_json::json!({"capture_request_header": "authorization", "capture_request_header_value": "abc"}),
                "capture_request_header_value",
            ),
        ] {
            assert_eq!(
                dotted(short_credential_named_paths(plugin, &config)),
                vec![path],
                "{plugin}"
            );
        }
        let ordinary = serde_json::json!({"trigger": {"header": "x-kill", "header_value": "on"}});
        assert!(short_credential_named_paths("request_termination", &ordinary).is_empty());
    }

    /// A short leaf ending in an array index (an element inside a structured
    /// `request_transformer` body value) has no sibling name field, so it is
    /// judged by its nearest enclosing key, as before sibling lookup existed.
    #[test]
    fn short_leaves_ending_in_an_array_index_keep_the_name_fallback() {
        let config = serde_json::json!({"rules": [
            {"operation": "add", "target": "body", "key": "payload",
                "value": {"authorization": ["q7z"], "tags": ["a1"]}},
            {"operation": "add", "target": "body", "key": "list",
                "value": [{"x-api-key": "k2"}, "v3"]}
        ]});
        let classification = classify_plugin_config("request_transformer", &config);
        assert!(classification.sensitive.is_empty());
        assert_eq!(
            dotted(classification.short_credential_named),
            vec![
                "rules.[0].value.authorization.[0]",
                "rules.[1].value.[0].x-api-key",
            ]
        );
    }

    /// Edge redacts every `api_chargeback_sink` insert query parameter but
    /// refuses credential-named keys, so an accepted one is a ClickHouse
    /// setting: an export site whose value stays literal, long or short. A
    /// credential-named key (by the key-name heuristics or a name Edge
    /// refuses) still needs an import allowance and is literal-gated.
    #[test]
    fn chargeback_insert_query_params_are_export_only() {
        let tuning = serde_json::json!({"clickhouse": {
            "url": "https://clickhouse.example:8443",
            "insert_query_params": {
                "async_insert": "1",
                "date_time_input_format": "best_effort",
                "session_timezone": "Europe/Berlin"
            }
        }});
        let classification = classify_plugin_config("api_chargeback_sink", &tuning);
        assert_eq!(dotted(classification.sensitive), vec!["clickhouse.url"]);
        assert!(classification.unbrokered.is_empty());
        assert!(classification.short_credential_named.is_empty());
        assert_eq!(
            dotted(
                rule_declared_paths("api_chargeback_sink", &tuning)
                    .into_iter()
                    .collect()
            ),
            vec!["clickhouse.url"]
        );
        assert_eq!(
            dotted(
                export_redacted_paths("api_chargeback_sink", &tuning)
                    .into_iter()
                    .collect()
            ),
            vec![
                "clickhouse.insert_query_params.async_insert",
                "clickhouse.insert_query_params.date_time_input_format",
                "clickhouse.insert_query_params.session_timezone",
                "clickhouse.url",
            ]
        );

        // Every name Edge refuses (exact names and markers anywhere in the
        // name), the key-name heuristics and short credential spellings are
        // flagged, long or short, so import needs an allowance and `apply`
        // refuses the literal; the ordinary settings beside them are not.
        let named = serde_json::json!({"clickhouse": {"insert_query_params": {
            "async_insert": "1",
            "date_time_input_format": "best_effort",
            "password": "synthetic-clickhouse-password",
            "token_value": "z9n4-clickhouse-opaque-material",
            "User": "default",
            "session_id": "s1",
            "access_token": "t",
            "x_api_key_v": "synthetic-api-material",
            "my-credential-ref": "c",
            "PASSWD2": "p",
            "client_secret_id": "s",
            "pwd": "hunter2-hunter2",
            "pass": "p",
            "auth": "a",
            "sig": "s",
            "signature": "synthetic-signature",
            "authorization": "Bearer x",
            "x-functions-key": "k"
        }}});
        let classification = classify_plugin_config("api_chargeback_sink", &named);
        assert!(classification.sensitive.is_empty());
        assert!(classification.short_credential_named.is_empty());
        let flagged = [
            "clickhouse.insert_query_params.PASSWD2",
            "clickhouse.insert_query_params.User",
            "clickhouse.insert_query_params.access_token",
            "clickhouse.insert_query_params.auth",
            "clickhouse.insert_query_params.authorization",
            "clickhouse.insert_query_params.client_secret_id",
            "clickhouse.insert_query_params.my-credential-ref",
            "clickhouse.insert_query_params.pass",
            "clickhouse.insert_query_params.password",
            "clickhouse.insert_query_params.pwd",
            "clickhouse.insert_query_params.session_id",
            "clickhouse.insert_query_params.sig",
            "clickhouse.insert_query_params.signature",
            "clickhouse.insert_query_params.token_value",
            "clickhouse.insert_query_params.x-functions-key",
            "clickhouse.insert_query_params.x_api_key_v",
        ];
        assert_eq!(dotted(classification.unbrokered), flagged);
        assert_eq!(
            dotted(sensitive_string_paths("api_chargeback_sink", &named)),
            flagged
        );
        assert!(rule_declared_paths("api_chargeback_sink", &named).is_empty());

        // The extra names apply to this map only: elsewhere in the same
        // config (and in other plugins) `user` is an ordinary setting.
        let elsewhere = serde_json::json!({"clickhouse": {"user": "default", "insert_query_params": {"async_insert": "1"}}});
        assert!(classify_plugin_config("api_chargeback_sink", &elsewhere)
            .unbrokered
            .is_empty());
        assert!(
            classify_plugin_config("http_logging", &serde_json::json!({"session_id": "s1"}))
                .unbrokered
                .is_empty()
        );
    }

    /// A credential-named parameter map is gated only where it is also an
    /// export-only site, so the two tables cannot drift apart silently.
    #[test]
    fn credential_named_parameter_maps_are_export_only_sites() {
        let mut checked = 0;
        for plugin in crate::plugin_catalog::BUILTIN_PLUGINS
            .iter()
            .map(|plugin| plugin.name)
        {
            for map in credential_named_parameter_maps(plugin) {
                assert!(
                    export_only_rules_for(plugin).contains(map),
                    "{plugin}: {map:?}"
                );
                assert!(
                    rules_for(plugin).iter().all(|rule| rule.path != *map),
                    "{plugin}: {map:?}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 1);
    }

    /// Edge classifies the `mesh_authz` policy operands as `secret`, but
    /// brokering them is deferred (see [`export_only_rules_for`]): they are
    /// export sites only. A `to.*.headers.*` value is still caught by the
    /// header-map heuristic (import plaintext allowance, literal-secret
    /// gate), while `when` values (principals, IPs, claims) stay literal.
    #[test]
    fn mesh_authz_policy_operands_are_deferred_export_sites() {
        let config = serde_json::json!({"mesh_policies": [{"rules": [{
            "to": [{"headers": {"authorization": "Bearer synthetic-mesh-token"}}],
            "when": [{"key": "source.principal", "values": ["spiffe://cluster.local/ns/a/sa/b"]}]
        }]}]});
        let classification = classify_plugin_config("mesh_authz", &config);
        assert!(classification.sensitive.is_empty());
        assert_eq!(
            dotted(classification.unbrokered),
            vec![
                "mesh_policies.[0].rules.[0].to.[0].headers.authorization",
                "mesh_policies.[0].rules.[0].when.[0].key",
            ]
        );
        assert_eq!(
            dotted(sensitive_string_paths("mesh_authz", &config)),
            vec![
                "mesh_policies.[0].rules.[0].to.[0].headers.authorization",
                "mesh_policies.[0].rules.[0].when.[0].key",
            ]
        );
        assert!(rule_declared_paths("mesh_authz", &config).is_empty());
        assert_eq!(
            dotted(
                export_redacted_paths("mesh_authz", &config)
                    .into_iter()
                    .collect()
            ),
            vec![
                "mesh_policies.[0].rules.[0].to.[0].headers.authorization",
                "mesh_policies.[0].rules.[0].when.[0].key",
                "mesh_policies.[0].rules.[0].when.[0].values.[0]",
            ]
        );
    }

    /// Operator-chosen tokens and match operands Edge after v0.9.20 redacts
    /// are [`RuleKind::Value`] rules: brokered when long enough to protect,
    /// ordinary settings when shorter, never rule-declared, and an export
    /// site whatever their length.
    #[test]
    fn post_v0_9_20_operator_tokens_are_operator_values() {
        for (plugin, config, brokered, sites) in [
            (
                "request_termination",
                serde_json::json!({"status_code": 403, "trigger": {"header": "x-kill", "header_value": "kill-switch-token"}}),
                vec!["trigger.header_value"],
                vec!["trigger.header_value"],
            ),
            (
                "request_termination",
                serde_json::json!({"trigger": {"header": "x-kill", "header_value": "on"}}),
                vec![],
                vec!["trigger.header_value"],
            ),
            (
                "transaction_debugger",
                serde_json::json!({"capture_request_header": "x-debug", "capture_request_header_value": "debug-session-42"}),
                vec!["capture_request_header_value"],
                vec!["capture_request_header_value"],
            ),
            (
                "transaction_debugger",
                serde_json::json!({"capture_request_header": "x-debug", "capture_request_header_value": "1"}),
                vec![],
                vec!["capture_request_header_value"],
            ),
            (
                "waf",
                serde_json::json!({
                    "custom_rules": [{"conditions": {"headers": {"x-tenant": "tenant-alpha-key", "x-env": "t1", "x-any": null}}}],
                    "rule_overrides": {"FE-XSS-001": {"conditions": {"headers": {"x-scan": "scanner-shared-value"}}}}
                }),
                vec![
                    "custom_rules.[0].conditions.headers.x-tenant",
                    "rule_overrides.FE-XSS-001.conditions.headers.x-scan",
                ],
                vec![
                    "custom_rules.[0].conditions.headers.x-env",
                    "custom_rules.[0].conditions.headers.x-tenant",
                    "rule_overrides.FE-XSS-001.conditions.headers.x-scan",
                ],
            ),
            (
                // A bare operand is matched whole (a scalar where Edge
                // expects a container); the object form keeps its match kind.
                "mesh_route_dispatch",
                serde_json::json!({"rules": [{"match": {
                    "headers": {"x-a": "v", "x-b": {"exact": "route-shared-secret"}},
                    "without_headers": {"x-c": {"prefix": "internal-only-"}},
                    "query_params": {"token": "query-shared-secret", "page": "2"}
                }}]}),
                vec![
                    "rules.[0].match.headers.x-b.exact",
                    "rules.[0].match.query_params.token",
                    "rules.[0].match.without_headers.x-c.prefix",
                ],
                vec![
                    "rules.[0].match.headers.x-a",
                    "rules.[0].match.headers.x-b.exact",
                    "rules.[0].match.query_params.page",
                    "rules.[0].match.query_params.token",
                    "rules.[0].match.without_headers.x-c.prefix",
                ],
            ),
        ] {
            let classification = classify_plugin_config(plugin, &config);
            assert_eq!(dotted(classification.sensitive), brokered, "{plugin}");
            assert!(
                classification.unbrokered.is_empty(),
                "{plugin}: {:?}",
                dotted(classification.unbrokered)
            );
            assert_eq!(
                dotted(sensitive_string_paths(plugin, &config)),
                brokered,
                "{plugin}"
            );
            assert!(rule_declared_paths(plugin, &config).is_empty(), "{plugin}");
            assert_eq!(
                dotted(export_redacted_paths(plugin, &config).into_iter().collect()),
                sites,
                "{plugin}"
            );
        }
    }

    /// Edge fails closed on a non-null scalar where a rule expects a
    /// container; a number there is an export site too, not only a string.
    #[test]
    fn a_scalar_where_a_rule_expects_a_container_is_an_export_site() {
        let config = serde_json::json!({"headers": 42});
        assert_eq!(
            dotted(
                export_redacted_paths("otel_tracing", &config)
                    .into_iter()
                    .collect()
            ),
            vec!["headers"]
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

    /// `jwks_auth` and `hmac_auth` read the root Redis fields through Edge's
    /// shared `RedisConfig::from_plugin_config`, like the rate limiters
    /// (#744), so their `redis_url` is an endpoint everywhere
    /// `rate_limiting.redis_url` is, and `redis_password` a declared secret.
    #[test]
    fn redis_backed_auth_plugins_classify_redis_fields_like_the_rate_limiters() {
        let config = serde_json::json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.example:6379/0",
            "redis_password": "synthetic-redis-password"
        });
        for plugin in [
            "jwks_auth",
            "hmac_auth",
            "rate_limiting",
            "soap_ws_security",
        ] {
            assert_eq!(
                dotted(endpoint_paths(plugin, &config).into_iter().collect()),
                vec!["redis_url"],
                "{plugin}"
            );
            let url = [ConfigPathComponent::Key("redis_url".to_string())];
            assert_eq!(endpoint_scheme(plugin, &url), "redis", "{plugin}");
            assert_eq!(
                endpoint_form(plugin, &url),
                EndpointForm::RedisDatabase,
                "{plugin}"
            );
            let export = export_redacted_paths(plugin, &config);
            for field in ["redis_url", "redis_password"] {
                assert!(
                    export.contains(&vec![ConfigPathComponent::Key(field.to_string())]),
                    "{plugin} {field}"
                );
            }
        }
        for plugin in ["jwks_auth", "hmac_auth", "soap_ws_security"] {
            assert_eq!(
                dotted(rule_declared_paths(plugin, &config).into_iter().collect()),
                vec!["redis_password", "redis_url"],
                "{plugin}"
            );
            let classification = classify_plugin_config(plugin, &config);
            assert_eq!(
                dotted(classification.sensitive),
                vec!["redis_password", "redis_url"],
                "{plugin}"
            );
            assert!(classification.unbrokered.is_empty(), "{plugin}");
        }
        // The identity endpoints are unchanged beside them.
        let jwks = serde_json::json!({
            "providers": [{"jwks_uri": "https://idp.example/jwks"}],
            "redis_url": "redis://cache.example:6379"
        });
        assert_eq!(
            dotted(endpoint_paths("jwks_auth", &jwks).into_iter().collect()),
            vec!["providers.[0].jwks_uri", "redis_url"]
        );
    }

    /// The stand-in shape follows each endpoint's own Edge validation (#745).
    #[test]
    fn endpoint_stand_in_shapes_follow_the_gateway_checks() {
        let key = |name: &str| vec![ConfigPathComponent::Key(name.to_string())];
        let provider_endpoint = vec![
            ConfigPathComponent::Key("providers".to_string()),
            ConfigPathComponent::Index(0),
            ConfigPathComponent::Key("endpoint".to_string()),
        ];
        for (plugin, path, scheme, form) in [
            (
                "ws_logging",
                key("endpoint_url"),
                "wss",
                EndpointForm::DigestPath,
            ),
            (
                "http_logging",
                key("endpoint_url"),
                "https",
                EndpointForm::DigestPath,
            ),
            (
                "serverless_function",
                key("aws_endpoint_url"),
                "https",
                EndpointForm::Origin,
            ),
            (
                "serverless_function",
                key("function_url"),
                "https",
                EndpointForm::DigestPath,
            ),
            (
                "ai_stream_router",
                provider_endpoint.clone(),
                "https",
                EndpointForm::ModelTemplate,
            ),
            (
                "ai_semantic_cache",
                key("redis_url"),
                "redis",
                EndpointForm::RedisDatabase,
            ),
            (
                "ai_semantic_cache",
                key("semantic_embedding_endpoint"),
                "https",
                EndpointForm::DigestPath,
            ),
            (
                "ldap_auth",
                key("ldap_url"),
                "ldaps",
                EndpointForm::DigestPath,
            ),
            (
                "otel_tracing",
                key("endpoint"),
                "https",
                EndpointForm::DigestPath,
            ),
        ] {
            assert_eq!(endpoint_scheme(plugin, &path), scheme, "{plugin}");
            assert_eq!(endpoint_form(plugin, &path), form, "{plugin}");
        }
    }

    #[test]
    fn client_assertion_keys_are_the_declared_private_key_pem_secrets() {
        let config = serde_json::json!({"providers": [
            {"client_auth": {"method": "private_key_jwt", "private_key_pem": "x", "private_key_jwt_alg": "ES256"}},
            {"client_auth": {"method": "client_secret_basic", "client_secret": "y"}}
        ]});
        for plugin in ["oauth2_introspection", "oidc_relying_party"] {
            let keys = client_assertion_key_paths(plugin, &config);
            assert_eq!(
                dotted(keys.iter().cloned().collect()),
                vec!["providers.[0].client_auth.private_key_pem"],
                "{plugin}"
            );
            let declared = rule_declared_paths(plugin, &config);
            assert!(keys.is_subset(&declared), "{plugin}");
        }
        assert!(client_assertion_key_paths("jwks_auth", &config).is_empty());
        assert!(
            client_assertion_key_paths("oidc_relying_party", &serde_json::json!(null)).is_empty()
        );
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
