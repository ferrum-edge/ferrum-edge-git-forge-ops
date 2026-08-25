use gitforgeops::apply::{apply_file, spec_owned_skip_messages, ApplyResult};
use gitforgeops::config::schema::{GatewayConfig, Proxy};
use gitforgeops::diff::SpecOwnedResource;

#[test]
fn apply_result_into_result_rejects_partial_failure() {
    let result = ApplyResult {
        created: 1,
        updated: 2,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Proxy proxy-a update: 500".to_string()],
        ..Default::default()
    };

    let error = result.into_result().unwrap_err();
    let msg = error.to_string();
    assert!(msg.contains("Apply failed after partial success"));
    assert!(msg.contains("Proxy proxy-a update: 500"));
    // The successful-counts portion of the message is what cmd_apply
    // surfaces via the deferred-propagation path: state.record/save
    // runs first, then this error propagates to the CLI. The counts
    // tell operators exactly which portion landed in state.
    assert!(msg.contains("1 created"), "expected created count: {msg}");
    assert!(msg.contains("2 updated"), "expected updated count: {msg}");
    assert!(msg.contains("1 failed"), "expected failed count: {msg}");
}

#[test]
fn apply_result_into_result_propagates_via_err_for_deferred_pattern() {
    // cmd_apply now uses `raw.into_result().err()` to capture the
    // partial-failure error AFTER state.record/state.save runs. This
    // documents that pattern: into_result returns Err on partial
    // failure (even when created+updated > 0), and `.err()` yields
    // Some(error) for deferred propagation.
    let partial = ApplyResult {
        created: 3,
        updated: 0,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec!["Consumer alice create: 500".to_string()],
        ..Default::default()
    };
    assert!(
        partial.into_result().err().is_some(),
        "partial failure must yield Some(err) so deferred propagation triggers"
    );

    // Pure success path: into_result returns Ok, .err() yields None →
    // deferred-propagation block is a no-op.
    let success = ApplyResult {
        created: 5,
        updated: 0,
        deleted: 0,
        unmanaged_skipped: 0,
        errors: vec![],
        ..Default::default()
    };
    assert!(
        success.into_result().err().is_none(),
        "clean apply must yield None — deferred propagation must not fire"
    );
}

#[test]
fn apply_file_creates_parent_dirs_and_writes_yaml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nested/resources.yaml");
    let config = GatewayConfig {
        proxies: vec![Proxy {
            id: "p1".to_string(),
            name: None,
            namespace: "ferrum".to_string(),
            hosts: vec![],
            listen_path: Some("/p1".to_string()),
            backend_scheme: Some(gitforgeops::config::schema::BackendScheme::Http),
            backend_host: "localhost".to_string(),
            backend_port: 8080,
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
            udp_idle_timeout_seconds: 60,
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
        }],
        ..GatewayConfig::default()
    };

    apply_file(&config, path.to_str().unwrap()).unwrap();

    let written = std::fs::read_to_string(path).unwrap();
    assert!(written.contains("p1"));
    assert!(written.contains("proxies:"));
}

// --- Apply ordering ----------------------------------------------------------

use gitforgeops::apply::{operation_rank, order_diffs, stale_view_block};
use gitforgeops::diff::resource_diff::{DiffAction, ResourceDiff};

fn diff(action: DiffAction, kind: &str, id: &str) -> ResourceDiff {
    ResourceDiff {
        action,
        kind: kind.to_string(),
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        details: Vec::new(),
    }
}

fn issued(diffs: Vec<ResourceDiff>) -> Vec<String> {
    order_diffs(diffs)
        .into_iter()
        .map(|d| format!("{:?} {} {}", d.action, d.kind, d.id))
        .collect()
}

#[test]
fn adds_follow_the_dependency_graph() {
    // The old kind-major order issued the Proxy add before the Upstream add,
    // and the gateway rejected it: "upstream_id '…' does not exist in
    // namespace '…'".
    let order = issued(vec![
        diff(DiffAction::Add, "Proxy", "p1"),
        diff(DiffAction::Add, "PluginConfig", "pc1"),
        diff(DiffAction::Add, "Upstream", "u1"),
        diff(DiffAction::Add, "Consumer", "c1"),
    ]);

    assert_eq!(
        order,
        vec![
            "Add Upstream u1",
            "Add Consumer c1",
            "Add Proxy p1",
            "Add PluginConfig pc1",
        ]
    );
}

#[test]
fn deletes_run_in_reverse_dependency_order() {
    let order = issued(vec![
        diff(DiffAction::Delete, "Upstream", "u1"),
        diff(DiffAction::Delete, "Proxy", "p1"),
        diff(DiffAction::Delete, "PluginConfig", "pc1"),
        diff(DiffAction::Delete, "Consumer", "c1"),
    ]);

    assert_eq!(
        order,
        vec![
            "Delete PluginConfig pc1",
            "Delete Proxy p1",
            "Delete Upstream u1",
            "Delete Consumer c1",
        ]
    );
}

#[test]
fn a_mixed_diff_applies_writes_before_deletes() {
    // Deleting an upstream only succeeds once nothing references it, so the
    // proxy modify that drops the reference has to land first.
    let order = issued(vec![
        diff(DiffAction::Delete, "Upstream", "old-upstream"),
        diff(DiffAction::Add, "Proxy", "new-proxy"),
        diff(DiffAction::Modify, "Proxy", "moved-proxy"),
        diff(DiffAction::Add, "Upstream", "new-upstream"),
        diff(DiffAction::Delete, "PluginConfig", "stale-pc"),
        diff(DiffAction::Modify, "PluginConfig", "kept-pc"),
    ]);

    assert_eq!(
        order,
        vec![
            "Add Upstream new-upstream",
            "Add Proxy new-proxy",
            "Modify Proxy moved-proxy",
            "Modify PluginConfig kept-pc",
            "Delete PluginConfig stale-pc",
            "Delete Upstream old-upstream",
        ]
    );
}

#[test]
fn ordering_is_stable_within_a_rank() {
    // Same rank ⇒ original (deterministic) diff order is preserved, so
    // repeated runs issue identical request sequences.
    let order = issued(vec![
        diff(DiffAction::Add, "Upstream", "u-b"),
        diff(DiffAction::Add, "Consumer", "c-a"),
        diff(DiffAction::Add, "Upstream", "u-a"),
    ]);
    assert_eq!(
        order,
        vec!["Add Upstream u-b", "Add Consumer c-a", "Add Upstream u-a"]
    );
}

#[test]
fn every_write_rank_precedes_every_delete_rank() {
    for kind in ["Upstream", "Consumer", "Proxy", "PluginConfig"] {
        let write = operation_rank(&DiffAction::Add, kind);
        let modify = operation_rank(&DiffAction::Modify, kind);
        assert_eq!(write, modify, "Add and Modify share a rank for {kind}");
        for other in ["Upstream", "Consumer", "Proxy", "PluginConfig"] {
            assert!(
                write < operation_rank(&DiffAction::Delete, other),
                "{kind} write must precede {other} delete"
            );
        }
    }
}

#[test]
fn unknown_kinds_get_a_defined_rank() {
    // Forward compatibility: a resource kind this build doesn't know about
    // must still sort deterministically rather than panicking or vanishing.
    let order = issued(vec![
        diff(DiffAction::Add, "FutureKind", "x"),
        diff(DiffAction::Add, "Upstream", "u1"),
    ]);
    assert_eq!(order, vec!["Add Upstream u1", "Add FutureKind x"]);
}

// --- Stale gateway view ------------------------------------------------------

#[test]
fn stale_view_blocks_prunes_from_a_cached_backup() {
    // During a config-database outage /backup falls back to the in-memory
    // snapshot; resources created since then read as "should be deleted".
    let block = stale_view_block(true, 3, false).expect("should block");
    assert!(block.contains("X-Data-Source: cached"), "{block}");
    assert!(block.contains("3 computed deletion"), "{block}");
    assert!(block.contains("--allow-large-prune"), "{block}");
}

#[test]
fn stale_view_allows_a_pure_write_apply() {
    // No deletes means nothing can be wrongly pruned, so a cached view is
    // merely a warning.
    assert!(stale_view_block(true, 0, false).is_none());
}

#[test]
fn stale_view_is_overridable_and_inert_on_a_fresh_view() {
    assert!(stale_view_block(true, 5, true).is_none());
    assert!(stale_view_block(false, 5, false).is_none());
}

// --- Spec-owned skip messages ------------------------------------------------

fn spec_owned(id: &str, declared_in_repo: bool, pruned: bool) -> SpecOwnedResource {
    SpecOwnedResource {
        kind: "Proxy".to_string(),
        id: id.to_string(),
        namespace: "ferrum".to_string(),
        api_spec_id: "spec-7".to_string(),
        declared_in_repo,
        pruned,
    }
}

#[test]
fn spec_owned_skip_message_names_the_owning_spec() {
    let messages = spec_owned_skip_messages(&[spec_owned("from-spec", false, false)]);

    assert_eq!(messages.len(), 1);
    assert!(
        messages[0].contains("skipping Proxy `from-spec`"),
        "{}",
        messages[0]
    );
    assert!(messages[0].contains("spec-7"), "{}", messages[0]);
    assert!(
        messages[0].contains("--confirm-api-spec-deletion"),
        "the skip message must say how to override it: {}",
        messages[0]
    );
}

#[test]
fn spec_owned_skip_message_flags_repo_conflict() {
    let messages = spec_owned_skip_messages(&[spec_owned("shared-id", true, false)]);

    assert!(messages[0].starts_with("conflict:"), "{}", messages[0]);
    assert!(
        messages[0].contains("this repo also declares it"),
        "{}",
        messages[0]
    );
    assert!(
        !messages[0].contains("--confirm-api-spec-deletion"),
        "a conflict is not fixed by the deletion flag: {}",
        messages[0]
    );
}

#[test]
fn spec_owned_skip_message_announces_confirmed_deletion() {
    let messages = spec_owned_skip_messages(&[spec_owned("from-spec", false, true)]);

    assert!(
        messages[0].contains("deleting Proxy `from-spec`"),
        "{}",
        messages[0]
    );
    assert!(
        messages[0].contains("--confirm-api-spec-deletion"),
        "{}",
        messages[0]
    );
}

#[test]
fn spec_owned_skip_messages_is_empty_without_spec_owned_resources() {
    assert!(spec_owned_skip_messages(&[]).is_empty());
}

#[test]
fn apply_result_reports_spec_owned_skips() {
    let result = ApplyResult {
        created: 1,
        spec_owned_skipped: 2,
        ..Default::default()
    };
    let ok = result.into_result().expect("no errors means Ok");
    assert_eq!(ok.spec_owned_skipped, 2);
}

// --- Fatal stops -------------------------------------------------------------

#[test]
fn a_fatal_stop_still_yields_an_error_with_the_partial_counts() {
    // The fatal error rides on the result instead of being returned as Err, so
    // cmd_apply can persist state for the ops that landed first. into_result
    // is what turns it back into a non-zero exit.
    let result = ApplyResult {
        created: 4,
        updated: 1,
        fatal_error: Some(
            "[team-b] gateway admin API is read-only, refusing to apply: ...".to_string(),
        ),
        ..Default::default()
    };

    let msg = result.into_result().unwrap_err().to_string();
    assert!(msg.contains("Apply stopped"), "{msg}");
    assert!(msg.contains("read-only"), "{msg}");
    assert!(
        msg.contains("4 created"),
        "the operator must see what landed before the stop: {msg}"
    );
}

#[test]
fn a_fatal_stop_alongside_per_resource_failures_reports_both() {
    let result = ApplyResult {
        created: 2,
        errors: vec!["Proxy p9 create: 409 duplicate".to_string()],
        fatal_error: Some("[team-b] gateway admin API is read-only".to_string()),
        ..Default::default()
    };

    let msg = result.into_result().unwrap_err().to_string();
    assert!(msg.contains("Apply stopped"), "{msg}");
    assert!(msg.contains("Proxy p9 create"), "{msg}");
    assert!(msg.contains("1 failed"), "{msg}");
}

#[test]
fn a_clean_result_has_no_fatal_error() {
    let result = ApplyResult {
        created: 3,
        ..Default::default()
    };
    assert!(result.fatal_error.is_none());
    assert!(result.into_result().is_ok());
}

// --- All-404 delete warning --------------------------------------------------

#[test]
fn every_delete_404ing_is_called_out() {
    let warning = all_deletes_missing_warning("team-alpha", 3, 3).expect("should warn");
    assert!(warning.contains("[team-alpha]"), "{warning}");
    assert!(
        warning.contains("all 3 delete(s) returned 404"),
        "{warning}"
    );
    assert!(warning.contains("FERRUM_GATEWAY_URL"), "{warning}");
    assert!(
        warning.contains("state entries were still removed"),
        "the operator has to know the next run will not retry them: {warning}"
    );
}

#[test]
fn a_single_tolerated_404_stays_silent() {
    // The gateway cascades deletes server-side, so one follow-up delete
    // finding nothing is routine and must not become noise.
    assert!(all_deletes_missing_warning("team-alpha", 3, 1).is_none());
    assert!(all_deletes_missing_warning("team-alpha", 2, 0).is_none());
    // Nothing was deleted at all — there is no signal here either way.
    assert!(all_deletes_missing_warning("team-alpha", 0, 0).is_none());
}

// --- apply_api against a stub gateway ----------------------------------------

use gitforgeops::apply::{all_deletes_missing_warning, apply_api, ApplyOptions};
use gitforgeops::config::env::{EnvConfig, GatewayMode};
use gitforgeops::config::schema::Upstream;
use gitforgeops::diff::OwnershipScope;
use gitforgeops::http_client::AdminClient;
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;

/// Canned-response gateway on a loopback socket, matched by the first route
/// whose needle appears anywhere in the request (line, headers, or body).
///
/// Reads the full request including its body, so routes can key on a payload —
/// which is how "fail this one resource, accept the others" is expressed.
fn spawn_stub_gateway(routes: Vec<(&'static str, u16, &'static str)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = routes.clone();
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                let (status, body) = routes
                    .iter()
                    .find(|(needle, _, _)| request.contains(needle))
                    .map(|(_, status, body)| (*status, *body))
                    .unwrap_or((200, "{}"));
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    format!("http://{addr}")
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let mut buf = [0_u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw).to_string();
        let Some(header_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let content_length = text
            .to_ascii_lowercase()
            .split("\r\n")
            .find_map(|line| {
                line.strip_prefix("content-length:")
                    .map(str::trim)
                    .map(String::from)
            })
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if raw.len() >= header_end + 4 + content_length {
            return Some(text);
        }
    }
}

fn stub_client(url: String) -> AdminClient {
    let env = EnvConfig {
        gateway_url: Some(url),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        gateway_mode: GatewayMode::Api,
        // No backoff sleeps in the failure paths.
        gateway_max_retries: 0,
        ..EnvConfig::default()
    };
    AdminClient::new(&env).unwrap()
}

fn upstream(id: &str, namespace: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream fixture")
}

const HEALTHY: &str = r#"{"status":"ok","mode":"database","admin_writes_enabled":true}"#;

fn empty_actuals(namespaces: &[&str]) -> BTreeMap<String, GatewayConfig> {
    namespaces
        .iter()
        .map(|ns| (ns.to_string(), GatewayConfig::default()))
        .collect()
}

#[tokio::test]
async fn a_rejected_batch_chunk_falls_back_to_named_per_resource_creates() {
    // The old behaviour returned one opaque "POST /batch: {e}" and abandoned
    // every remaining resource. `/batch` is all-or-nothing per chunk, so
    // nothing landed — replaying the chunk per resource names the resource the
    // gateway actually objected to and still creates the rest.
    let url = spawn_stub_gateway(vec![
        ("GET /health", 200, HEALTHY),
        ("POST /batch", 400, r#"{"error":"batch rejected"}"#),
        (r#""id":"u2""#, 409, r#"{"error":"duplicate id"}"#),
        ("POST /upstreams", 201, "{}"),
    ]);
    let client = stub_client(url);

    let desired = GatewayConfig {
        upstreams: vec![
            upstream("u1", "team-alpha"),
            upstream("u2", "team-alpha"),
            upstream("u3", "team-alpha"),
        ],
        ..Default::default()
    };

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a per-resource failure is not fatal");

    assert_eq!(result.created, 2, "the healthy resources still land");
    assert_eq!(result.errors.len(), 1, "got {:?}", result.errors);
    assert!(
        result.errors[0].contains("Upstream u2 create"),
        "the failing resource must be named: {:?}",
        result.errors
    );
    // Order follows the diff, which is not id-sorted; the *set* is what
    // matters for the state update.
    let mut created: Vec<&str> = result
        .applied_incremental
        .iter()
        .map(|op| op.id.as_str())
        .collect();
    created.sort_unstable();
    assert_eq!(created, vec!["u1", "u3"]);
    assert!(result.fatal_error.is_none());
}

#[tokio::test]
async fn a_read_only_plane_stops_the_run_but_keeps_earlier_namespaces_recorded() {
    // The whole point of F1/F2: namespace ferrum applied cleanly, team-b hit a
    // read-only admin plane. Returning Err here threw away ferrum's applied
    // ops, so cmd_apply persisted nothing and the next run re-derived those
    // resources as unmanaged. The ops survive; the error rides on the result.
    let url = spawn_stub_gateway(vec![
        ("GET /health", 200, HEALTHY),
        // Force the per-resource path so the read-only 403 comes from a
        // single-resource create, the way it does mid-namespace.
        ("POST /batch", 501, "{}"),
        (
            "x-ferrum-namespace: team-b",
            403,
            r#"{"error":"Admin API is in read-only mode"}"#,
        ),
        ("POST /upstreams", 201, "{}"),
    ]);
    let client = stub_client(url);

    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "ferrum"), upstream("u2", "team-b")],
        ..Default::default()
    };

    let result = apply_api(
        &desired,
        &client,
        &["ferrum".to_string(), "team-b".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum", "team-b"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("a fatal stop is reported on the result, not as Err");

    assert_eq!(result.created, 1);
    assert_eq!(
        result
            .applied_incremental
            .iter()
            .map(|op| op.id.as_str())
            .collect::<Vec<_>>(),
        vec!["u1"],
        "the namespace that succeeded must still be recordable in state"
    );
    let fatal = result.fatal_error.clone().expect("read-only is fatal");
    assert!(fatal.contains("[team-b]"), "{fatal}");
    assert!(fatal.contains("read-only"), "{fatal}");

    // ...and it is still a failed run.
    assert!(result.into_result().is_err());
}

#[tokio::test]
async fn a_read_only_plane_at_the_first_namespace_stops_immediately() {
    // Nothing landed, but the run must still stop rather than collecting the
    // same 403 once per remaining namespace.
    let url = spawn_stub_gateway(vec![
        ("GET /health", 200, HEALTHY),
        ("POST /batch", 501, "{}"),
        (
            "POST /upstreams",
            403,
            r#"{"error":"Admin API is in read-only mode"}"#,
        ),
    ]);
    let client = stub_client(url);

    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "ferrum"), upstream("u2", "team-b")],
        ..Default::default()
    };

    let result = apply_api(
        &desired,
        &client,
        &["ferrum".to_string(), "team-b".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum", "team-b"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("reported on the result");

    assert_eq!(result.created, 0);
    let fatal = result.fatal_error.expect("read-only is fatal");
    assert!(fatal.contains("[ferrum]"), "stopped at the first: {fatal}");
}

#[tokio::test]
async fn a_read_only_preflight_fails_before_any_mutation() {
    // Unchanged behaviour: the up-front GET /health verdict is a hard Err,
    // because nothing has been applied and there is no partial state to save.
    let url = spawn_stub_gateway(vec![(
        "GET /health",
        200,
        r#"{"status":"degraded","mode":"database","admin_writes_enabled":false}"#,
    )]);
    let client = stub_client(url);

    let err = apply_api(
        &GatewayConfig::default(),
        &client,
        &["ferrum".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["ferrum"])),
        None,
        &ApplyOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, gitforgeops::error::Error::GatewayReadOnly(_)));
}
