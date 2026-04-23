use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendProtocol {
    Http,
    Https,
    Ws,
    Wss,
    Grpc,
    Grpcs,
    H3,
    Tcp,
    TcpTls,
    Udp,
    Dtls,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    pub provider: SdProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_sd: Option<DnsSdConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consul: Option<ConsulConfig>,
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
    pub backend_protocol: BackendProtocol,
    pub backend_host: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_client_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_client_key_path: Option<String>,
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_server_ca_cert_path: Option<String>,
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

// --- Resource file wrapper ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Resource {
    Proxy { spec: Proxy },
    Consumer { spec: Consumer },
    Upstream { spec: Upstream },
    PluginConfig { spec: PluginConfig },
}
