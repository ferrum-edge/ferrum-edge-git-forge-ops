use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

fn default_namespace() -> String {
    "ferrum".to_string()
}

fn default_config_version() -> String {
    "1".to_string()
}

fn default_true() -> bool {
    true
}

fn default_weight() -> u32 {
    1
}

fn default_connect_timeout() -> u64 {
    5000
}

fn default_read_timeout() -> u64 {
    30000
}

fn default_write_timeout() -> u64 {
    30000
}

fn default_udp_idle_timeout() -> u64 {
    60
}

// --- Enums ---

/// Backend wire scheme, mirroring `ferrum_edge::config::types::BackendScheme`.
///
/// The gateway cut this enum from eleven variants down to six: WebSocket and
/// gRPC are now detected per request rather than declared, and HTTP/3 is
/// negotiated per backend. Since users' git trees still hold YAML written
/// against the old `backend_protocol` field and its wider variant set, this
/// mirror deserializes the legacy wire values and folds them onto the six
/// canonical ones:
///
/// | legacy value | canonical scheme |
/// |---|---|
/// | `ws`       | `http`  |
/// | `wss`      | `https` |
/// | `grpc`     | `http`  |
/// | `grpcs`    | `https` |
/// | `h3`       | `https` |
/// | `tcp_tls`  | `tcps`  |
///
/// Serialization **always** emits a canonical value, so a load/export cycle
/// upgrades a legacy tree in place. The legacy field name `backend_protocol`
/// is likewise accepted (via `#[serde(alias)]` on `Proxy::backend_scheme`) but
/// never emitted.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BackendScheme {
    Http,
    Https,
    Tcp,
    Tcps,
    Udp,
    Dtls,
}

impl BackendScheme {
    /// Canonical wire name — matches what `Serialize` emits.
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendScheme::Http => "http",
            BackendScheme::Https => "https",
            BackendScheme::Tcp => "tcp",
            BackendScheme::Tcps => "tcps",
            BackendScheme::Udp => "udp",
            BackendScheme::Dtls => "dtls",
        }
    }

    /// Accepts both canonical and legacy wire values. Returns `None` for
    /// anything else.
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "http" => Some(BackendScheme::Http),
            "https" => Some(BackendScheme::Https),
            "tcp" => Some(BackendScheme::Tcp),
            "tcps" => Some(BackendScheme::Tcps),
            "udp" => Some(BackendScheme::Udp),
            "dtls" => Some(BackendScheme::Dtls),
            // Legacy `backend_protocol` values, folded onto the canonical set.
            "ws" => Some(BackendScheme::Http),
            "wss" => Some(BackendScheme::Https),
            "grpc" => Some(BackendScheme::Http),
            "grpcs" => Some(BackendScheme::Https),
            "h3" => Some(BackendScheme::Https),
            "tcp_tls" => Some(BackendScheme::Tcps),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for BackendScheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        BackendScheme::from_wire(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown backend scheme `{raw}`, expected one of: http, https, tcp, tcps, udp, dtls \
                 (legacy: ws, wss, grpc, grpcs, h3, tcp_tls)"
            ))
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerAlgorithm {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    LeastLatency,
    ConsistentHashing,
    Random,
    Passthrough,
}

/// Outbound PROXY-protocol mode for stream backend connects.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendProxyProtocol {
    V2,
}

/// Destination mesh topology for mesh service discovery.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeshSdTopology {
    #[default]
    Ambient,
    Sidecar,
}

impl MeshSdTopology {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// What the gateway does with a discovered target set that has gone stale.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SdStalePolicy {
    Retain,
    #[default]
    Withdraw,
    FailReadiness,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthProbeType {
    #[default]
    Http,
    Tcp,
    Udp,
    Grpc,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SdProvider {
    DnsSd,
    Kubernetes,
    Consul,
    Mesh,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Single,
    Multi,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseBodyMode {
    #[default]
    Stream,
    Buffer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginScope {
    Global,
    Proxy,
    ProxyGroup,
}

// --- Sub-structs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAssociation {
    pub plugin_config_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    /// Istio-style `region/zone/subzone` locality for this target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// A named subset of upstream targets identified by label selectors.
///
/// `traffic_policy` is deliberately not mirrored: ferrum-edge rejects it as
/// operator input (it is projected from mesh DestinationRules).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsetDefinition {
    pub name: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHealthCheck {
    #[serde(default = "default_health_path")]
    pub http_path: String,
    #[serde(default = "default_health_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_health_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_healthy_status_codes")]
    pub healthy_status_codes: Vec<u16>,
    #[serde(default)]
    pub use_tls: bool,
    #[serde(default)]
    pub probe_type: HealthProbeType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_probe_payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_service_name: Option<String>,
}

fn default_health_path() -> String {
    "/health".to_string()
}
fn default_health_interval() -> u64 {
    10
}
fn default_health_timeout() -> u64 {
    5000
}
fn default_health_threshold() -> u32 {
    3
}
fn default_healthy_status_codes() -> Vec<u16> {
    vec![200, 302]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveHealthCheck {
    #[serde(default = "default_passive_unhealthy_codes")]
    pub unhealthy_status_codes: Vec<u16>,
    #[serde(default = "default_health_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_passive_window")]
    pub unhealthy_window_seconds: u64,
    #[serde(default = "default_passive_window")]
    pub healthy_after_seconds: u64,
    /// Cap (0-100) on the share of targets that may be ejected at once.
    /// `None` means no cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ejection_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_error_codes: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_external_local_origin_errors: Option<bool>,
}

fn default_passive_unhealthy_codes() -> Vec<u16> {
    vec![500, 502, 503, 504]
}
fn default_passive_window() -> u64 {
    30
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<ActiveHealthCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive: Option<PassiveHealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashOnCookieConfig {
    #[serde(default = "default_cookie_path")]
    pub path: String,
    #[serde(default = "default_cookie_ttl")]
    pub ttl_seconds: u64,
    /// Emit the hash cookie as a session cookie (no `Max-Age`/`Expires`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub session_cookie: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default = "default_true")]
    pub http_only: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

fn default_cookie_path() -> String {
    "/".to_string()
}
fn default_cookie_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSdConfig {
    pub service_name: String,
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

fn default_sd_poll_interval() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
    pub service_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_selector: Option<String>,
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

fn default_k8s_namespace() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    pub address: String,
    pub service_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datacenter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default = "default_true")]
    pub healthy_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Ferrum mesh service discovery. Required when `provider = mesh`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSdConfig {
    pub service_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default, skip_serializing_if = "MeshSdTopology::is_default")]
    pub topology: MeshSdTopology,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    pub provider: SdProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_sd: Option<DnsSdConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consul: Option<ConsulConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<MeshSdConfig>,
    /// Maximum tolerated discovery staleness in seconds (5..=86400; `0` means
    /// unbounded and is env-gated by the gateway).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stale_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_policy: Option<SdStalePolicy>,
    #[serde(default = "default_weight")]
    pub default_weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    Fixed { delay_ms: u64 },
    Exponential { base_ms: u64, max_ms: u64 },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self::Fixed { delay_ms: 100 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    #[serde(default = "default_circuit_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_failure_status_codes")]
    pub failure_status_codes: Vec<u16>,
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
    #[serde(default = "default_true")]
    pub trip_on_connection_errors: bool,
}

fn default_failure_threshold() -> u32 {
    5
}
fn default_success_threshold() -> u32 {
    3
}
fn default_circuit_timeout() -> u64 {
    30
}
fn default_failure_status_codes() -> Vec<u16> {
    vec![500, 502, 503, 504]
}
fn default_half_open_max() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default)]
    pub retryable_status_codes: Vec<u16>,
    #[serde(default = "default_retryable_methods")]
    pub retryable_methods: Vec<String>,
    #[serde(default)]
    pub backoff: BackoffStrategy,
    #[serde(default = "default_true")]
    pub retry_on_connect_failure: bool,
}

fn default_max_retries() -> u32 {
    3
}
fn default_retryable_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "HEAD".to_string(),
        "OPTIONS".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ]
}

// --- Stream (L4) match predicates ---

/// VirtualService-style L4 match predicates for a stream proxy. Arms are OR'd;
/// predicates within an arm are AND'd. Rejected by the gateway on udp/dtls
/// proxies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamMatchCriteria {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arms: Vec<StreamMatchArm>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamMatchArm {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_subnets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_subnets: Vec<String>,
    /// `mesh` or `namespace/name` gateway selectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<String>,
}

// --- Plugin trigger predicates ---

/// Conditional-execution predicate tree for a plugin instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTrigger {
    pub when: PluginTriggerNode,
}

/// One node of the predicate tree. Exactly one field is expected to be set;
/// the gateway is the authority on that constraint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginTriggerNode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<PluginTriggerNode>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<PluginTriggerNode>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<PluginTriggerNode>>,
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_: Option<PluginTriggerMatch>,
}

/// A leaf predicate. Exactly one field is expected to be set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginTriggerMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PluginTriggerStringMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<PluginTriggerStringMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<PluginTriggerStringMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<PluginTriggerFieldMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<PluginTriggerFieldMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<PluginTriggerFieldMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Vec<PluginTriggerProtocol>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cidr: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<Vec<u16>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer: Option<PluginTriggerIdentityMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<PluginTriggerIdentityMatch>,
}

/// String comparison. Exactly one of `exact` / `prefix` / `regex` is expected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginTriggerStringMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub case_insensitive: bool,
}

/// Header / query / cookie predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTriggerFieldMatch {
    pub name: String,
    #[serde(default)]
    pub presence: PluginTriggerPresence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<PluginTriggerStringMatch>,
    #[serde(default)]
    pub multi_value: PluginTriggerMultiValue,
}

/// Authenticated-identity predicate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginTriggerIdentityMatch {
    #[serde(default)]
    pub presence: PluginTriggerPresence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<PluginTriggerStringMatch>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginTriggerPresence {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginTriggerMultiValue {
    #[default]
    Any,
    All,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginTriggerProtocol {
    Http1,
    Http2,
    Http3,
    Grpc,
    GrpcWeb,
    Websocket,
    Tcp,
    Udp,
    Dtls,
}

// --- Top-level resources ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_path: Option<String>,
    /// Backend wire scheme. Optional on HTTP-family proxies (the gateway
    /// defaults it to `https`), required on stream proxies. Accepts the legacy
    /// field name `backend_protocol` on read; always emits `backend_scheme`.
    #[serde(default, alias = "backend_protocol")]
    pub backend_scheme: Option<BackendScheme>,
    /// Optional (empty) when `upstream_id` supplies the dial address.
    #[serde(default)]
    pub backend_host: String,
    /// Optional (0) when `upstream_id` supplies the dial address.
    #[serde(default)]
    pub backend_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_path: Option<String>,
    #[serde(default = "default_true")]
    pub strip_listen_path: bool,
    #[serde(default)]
    pub preserve_host_header: bool,
    #[serde(default = "default_connect_timeout")]
    pub backend_connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub backend_read_timeout_ms: u64,
    #[serde(default = "default_write_timeout")]
    pub backend_write_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_client_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_client_key_path: Option<String>,
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_server_ca_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_override: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_cache_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub plugins: Vec<PluginAssociation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_idle_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_enable_http_keep_alive: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_enable_http2: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_tcp_keepalive_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_keep_alive_interval_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_keep_alive_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_initial_stream_window_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_initial_connection_window_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_adaptive_window: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_max_frame_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http2_max_concurrent_streams: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_http3_connections_per_backend: Option<usize>,
    /// Deprecated upstream carrier, still persisted — mirrored for fidelity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_max_requests_per_connection: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
    /// Names a subset declared in the referenced upstream's `subsets`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_subset: Option<String>,
    /// Admin-only ownership tag set by the spec-import API. Never hand-authored,
    /// but must round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_spec_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,
    #[serde(default)]
    pub response_body_mode: ResponseBodyMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub frontend_tls: bool,
    #[serde(default)]
    pub passthrough: bool,
    #[serde(default = "default_udp_idle_timeout")]
    pub udp_idle_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_max_response_amplification_factor: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_idle_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_idle_timeout_seconds: Option<u64>,
    /// Trust an inbound PROXY-protocol header on this stream listener. Only
    /// safe behind a trusted L4 hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_proxy_protocol: Option<bool>,
    /// Emit an outbound PROXY-protocol header on stream backend connects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_proxy_protocol: Option<BackendProxyProtocol>,
    /// L4 match predicates evaluated before this stream route is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_match: Option<StreamMatchCriteria>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_methods: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_ws_origins: Vec<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consumer {
    #[serde(default)]
    pub id: String,
    pub username: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_id: Option<String>,
    #[serde(default)]
    pub credentials: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub acl_groups: Vec<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub targets: Vec<UpstreamTarget>,
    #[serde(default)]
    pub algorithm: LoadBalancerAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_on_cookie_config: Option<HashOnCookieConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_checks: Option<HealthCheckConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_discovery: Option<ServiceDiscoveryConfig>,
    /// Named subsets of targets, selected by `Proxy.upstream_subset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsets: Option<Vec<SubsetDefinition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_client_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_client_key_path: Option<String>,
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_server_ca_cert_path: Option<String>,
    /// Backend TLS SNI override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_sni: Option<String>,
    /// Backend certificate SAN allow-list (cert pinning by SAN).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backend_tls_san_allow_list: Vec<String>,
    /// Admin-only ownership tag set by the spec-import API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_spec_id: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default)]
    pub id: String,
    pub plugin_name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub scope: PluginScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_override: Option<u16>,
    /// Conditional-execution predicate tree for this plugin instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<PluginTrigger>,
    /// Admin-only ownership tag set by the spec-import API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_spec_id: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

// --- Root config ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_config_version")]
    pub version: String,
    #[serde(default)]
    pub proxies: Vec<Proxy>,
    #[serde(default)]
    pub consumers: Vec<Consumer>,
    #[serde(default)]
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            version: default_config_version(),
            proxies: Vec::new(),
            consumers: Vec::new(),
            plugin_configs: Vec::new(),
            upstreams: Vec::new(),
        }
    }
}

// --- Mesh configuration ---

/// Permissive mirror of the **user-authored** fields of ferrum-edge's
/// `modes::mesh::config::MeshConfig`.
///
/// # Why this is not a deep mirror
///
/// ferrum-edge's `MeshConfig` is *not* `deny_unknown_fields`, and
/// `ferrum-edge validate -m mesh` is the authoritative validator for its
/// contents (gitforgeops shells out to it for every mesh document it
/// produces). Mirroring the ~40 nested Istio-shaped types would buy nothing
/// but a second, always-stale schema — so the top level is typed (one field
/// per mesh collection, which is what fragment merging and overlay identity
/// need) and every per-item shape stays a `serde_json::Value` that
/// round-trips verbatim.
///
/// # What is deliberately absent
///
/// The runtime-derived `#[serde(skip)]` fields on ferrum-edge's `MeshConfig`
/// (`node_waypoint_assertors`, `local_inbound_services`,
/// `local_ingress_listeners`, `declared_ingress_http_ports`,
/// `local_workload_addresses`, the node-waypoint capture inventories, the
/// sidecar-ingress projections and the UDP egress tables) are never
/// operator-settable and never on the wire. They are not mirrored: authoring
/// them is meaningless and emitting them would be rejected noise.
///
/// # Namespaces
///
/// A mesh document has **no** top-level namespace. Its constituent resources
/// (workloads, services, peer authentications, ...) carry their own
/// `namespace` fields inside their `Value` payloads. The directory a fragment
/// is loaded from (`resources/<ns>/mesh/`) is bookkeeping for
/// `FERRUM_NAMESPACE` filtering and overlay matching only — it never rewrites
/// anything inside the mesh document.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MeshConfigSpec {
    /// Istio root namespace for mesh-wide policy resources. `None` leaves
    /// ferrum-edge's own default (`istio-system`) in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub istio_root_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_policies: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ext_authz_providers: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_authentications: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_entries: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_authentications: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telemetry_resources: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_rules: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub virtual_service_cors_policies: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_configs: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waypoint_bindings: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_cluster: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_traffic_policy: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_configs: Vec<serde_json::Value>,
}

impl MeshConfigSpec {
    /// True when the fragment declares nothing at all. Used to decide whether
    /// a mesh document is worth emitting or validating.
    pub fn is_empty(&self) -> bool {
        *self == MeshConfigSpec::default()
    }

    /// Non-empty collection counts, in declaration order, as
    /// `"3 workloads, 1 service"`. Empty string when nothing is declared.
    /// Drives the lightweight `plan` summary — mesh resources have no live
    /// admin API to diff against, so counts are all a preview can honestly
    /// report.
    pub fn summary(&self) -> String {
        let counts: [(&str, usize); 14] = [
            ("workload", self.workloads.len()),
            ("service", self.services.len()),
            ("mesh policy", self.mesh_policies.len()),
            ("ext authz provider", self.ext_authz_providers.len()),
            ("peer authentication", self.peer_authentications.len()),
            ("service entry", self.service_entries.len()),
            ("request authentication", self.request_authentications.len()),
            ("telemetry resource", self.telemetry_resources.len()),
            ("destination rule", self.destination_rules.len()),
            ("CORS policy", self.virtual_service_cors_policies.len()),
            ("proxy config", self.proxy_configs.len()),
            ("sidecar", self.sidecars.len()),
            ("waypoint binding", self.waypoint_bindings.len()),
            ("extension config", self.extension_configs.len()),
        ];

        let mut parts: Vec<String> = counts
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(label, n)| {
                if *n == 1 {
                    format!("1 {label}")
                } else {
                    format!("{n} {label}s")
                }
            })
            .collect();

        for (label, present) in [
            ("trust bundles", self.trust_bundles.is_some()),
            ("multi-cluster", self.multi_cluster.is_some()),
            (
                "outbound traffic policy",
                self.outbound_traffic_policy.is_some(),
            ),
        ] {
            if present {
                parts.push(label.to_string());
            }
        }

        parts.join(", ")
    }
}

// --- Resource file wrapper ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Resource {
    Proxy {
        spec: Proxy,
    },
    Consumer {
        spec: Consumer,
    },
    Upstream {
        spec: Upstream,
    },
    PluginConfig {
        spec: PluginConfig,
    },
    /// A mesh-configuration **fragment**. Unlike the gateway kinds, several
    /// fragments merge into a single document rather than each becoming one
    /// addressable gateway resource.
    ///
    /// `id` is a gitforgeops-side fragment name, not part of the mesh schema:
    /// mesh documents have no resource ids, so overlays need *something* to
    /// match on. The loader defaults it to the file stem, and it is never
    /// serialized into the emitted mesh document (which carries only
    /// `version` and `mesh`).
    MeshConfig {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        spec: MeshConfigSpec,
    },
}
