//! Namespace-scope and delete-fence behavior for a single invocation.
//!
//! `resolved_namespaces` decides which namespaces diff/plan/review/apply
//! iterate. The shared-mode union with state-derived namespaces is the piece
//! that keeps orphan cleanup working — see the "State file trust model"
//! section in README.md for why the state file is trusted to widen that set.

use std::collections::HashSet;

use gitforgeops::config::repo_config::{OwnershipConfig, OwnershipMode};
use gitforgeops::config::schema::{BackendScheme, GatewayConfig, Proxy};
use gitforgeops::config::{ApplyStrategy, ResolvedEnv};
use gitforgeops::diff::state_key;
use gitforgeops::reconcile::{previously_managed, resolved_namespaces};
use gitforgeops::state::StateFile;

fn proxy(id: &str, namespace: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        name: None,
        namespace: namespace.to_string(),
        hosts: vec![],
        listen_path: Some(format!("/{id}")),
        backend_scheme: Some(BackendScheme::Https),
        backend_host: "backend.example".to_string(),
        backend_port: 443,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: Default::default(),
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 30,
        udp_max_response_amplification_factor: None,
        tcp_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        pool_max_requests_per_connection: None,
        upstream_subset: None,
        api_spec_id: None,
        websocket_idle_timeout_seconds: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn env(mode: OwnershipMode, namespaces: Option<Vec<String>>) -> ResolvedEnv {
    ResolvedEnv {
        name: "production".to_string(),
        overlay: None,
        namespace_filter: None,
        apply_strategy: ApplyStrategy::Incremental,
        ownership: OwnershipConfig {
            mode,
            namespaces,
            ..Default::default()
        },
    }
}

fn state_with(namespaces: &[&str]) -> StateFile {
    let mut state = StateFile::default();
    for (i, ns) in namespaces.iter().enumerate() {
        state.resources.insert(
            state_key(ns, "Proxy", &format!("p{i}")),
            format!("hash-{i}"),
        );
    }
    state
}

fn desired_with(namespaces: &[&str]) -> GatewayConfig {
    let mut cfg = GatewayConfig::default();
    for (i, ns) in namespaces.iter().enumerate() {
        cfg.proxies.push(proxy(&format!("p{i}"), ns));
    }
    cfg
}

/// The orphan-cleanup guarantee: a PR that removes the last resource from a
/// namespace must not stop that namespace from being reconciled, or the
/// gateway keeps the orphaned resource forever.
#[test]
fn shared_mode_keeps_reconciling_a_namespace_the_repo_no_longer_declares() {
    let resolved = env(OwnershipMode::Shared, None);
    // Repo declares only `platform`; state remembers a resource in `foo`.
    let desired = desired_with(&["platform"]);
    let state = state_with(&["foo"]);

    let namespaces = resolved_namespaces(&resolved, &desired, &state);

    assert_eq!(namespaces, vec!["foo".to_string(), "platform".to_string()]);
}

#[test]
fn shared_mode_unions_declared_and_previously_managed_without_duplicates() {
    let resolved = env(OwnershipMode::Shared, None);
    let desired = desired_with(&["platform", "ferrum"]);
    let state = state_with(&["ferrum", "foo"]);

    let namespaces = resolved_namespaces(&resolved, &desired, &state);

    // Sorted (BTreeSet) and deduplicated.
    assert_eq!(
        namespaces,
        vec![
            "ferrum".to_string(),
            "foo".to_string(),
            "platform".to_string()
        ]
    );
}

#[test]
fn shared_mode_namespace_filter_overrides_both_sources() {
    let mut resolved = env(OwnershipMode::Shared, None);
    resolved.namespace_filter = Some("ferrum".to_string());
    let desired = desired_with(&["platform"]);
    let state = state_with(&["foo"]);

    assert_eq!(
        resolved_namespaces(&resolved, &desired, &state),
        vec!["ferrum".to_string()]
    );
}

/// Exclusive mode never consults state: the declared `ownership.namespaces`
/// list is the whole scope.
#[test]
fn exclusive_mode_ignores_state_derived_namespaces() {
    let resolved = env(
        OwnershipMode::Exclusive,
        Some(vec!["platform".to_string(), "ferrum".to_string()]),
    );
    let desired = desired_with(&["platform"]);
    let state = state_with(&["foo"]);

    assert_eq!(
        resolved_namespaces(&resolved, &desired, &state),
        vec!["platform".to_string(), "ferrum".to_string()]
    );
}

#[test]
fn exclusive_mode_namespace_filter_narrows_to_one_namespace() {
    let mut resolved = env(
        OwnershipMode::Exclusive,
        Some(vec!["platform".to_string(), "ferrum".to_string()]),
    );
    resolved.namespace_filter = Some("ferrum".to_string());

    assert_eq!(
        resolved_namespaces(&resolved, &GatewayConfig::default(), &StateFile::default()),
        vec!["ferrum".to_string()]
    );
}

/// The delete fence, and the reason a state-derived namespace can't be used
/// to prune arbitrary live resources: shared mode restricts deletes to keys
/// the state file already lists.
#[test]
fn shared_mode_fences_deletes_to_previously_managed_keys() {
    let resolved = env(OwnershipMode::Shared, None);
    let state = state_with(&["foo"]);

    let managed = previously_managed(&resolved, &state).expect("shared mode is fenced");
    let expected: HashSet<String> = state.resources.keys().cloned().collect();

    assert_eq!(managed, expected);
    assert!(managed.contains(&state_key("foo", "Proxy", "p0")));
}

#[test]
fn exclusive_mode_has_no_delete_fence() {
    let resolved = env(OwnershipMode::Exclusive, Some(vec!["platform".to_string()]));
    assert!(previously_managed(&resolved, &state_with(&["foo"])).is_none());
}
