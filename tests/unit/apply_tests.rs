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

use gitforgeops::apply::{
    exclusive_prune_denominator, format_prune_percentage, large_prune_exceeds_threshold,
    operation_rank, order_diffs, pending_create_assertion_diffs, preserve_spec_owned_graph,
    stale_view_block, validate_no_desired_spec_tags,
};
use gitforgeops::diff::resource_diff::{state_key, DiffAction, ResourceDiff};

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
fn stale_view_blocks_every_mutation_from_a_cached_backup() {
    // Cached fallback also strips API-spec ownership tags, so even a pure
    // add/modify can collide with a row that only appears hand-owned.
    let block = stale_view_block(true).expect("should block");
    assert!(block.contains("X-Data-Source: cached"), "{block}");
    assert!(block.contains("API-spec ownership metadata"), "{block}");
    assert!(block.contains("--allow-large-prune"), "{block}");
    assert!(block.contains("does not bypass"), "{block}");
}

#[test]
fn fresh_view_is_not_blocked() {
    assert!(stale_view_block(false).is_none());
}

#[test]
fn large_prune_threshold_uses_an_exact_ratio() {
    assert!(large_prune_exceeds_threshold(1, 200, 0));
    assert!(large_prune_exceeds_threshold(26, 101, 25));
    assert!(!large_prune_exceeds_threshold(25, 100, 25));
    assert!(!large_prune_exceeds_threshold(0, 0, 0));
    assert!(!large_prune_exceeds_threshold(0, usize::MAX, 0));

    // The comparison widens before multiplication, so large platform values
    // cannot overflow and silently weaken the guard.
    assert!(!large_prune_exceeds_threshold(usize::MAX, usize::MAX, 100));
    assert!(large_prune_exceeds_threshold(usize::MAX, usize::MAX, 99));
    assert_eq!(format_prune_percentage(26, 101), "25.74");
    assert_eq!(format_prune_percentage(0, 0), "0.00");
}

#[test]
fn large_prune_decision_matches_rational_reference_across_small_domain() {
    for denominator in 0_usize..=250 {
        for deletes in 0_usize..=denominator {
            for threshold in 0_u8..=100 {
                let reference = denominator > 0
                    && (deletes as u128) * 100 > (threshold as u128) * (denominator as u128);
                assert_eq!(
                    large_prune_exceeds_threshold(deletes, denominator, threshold),
                    reference,
                    "deletes={deletes}, denominator={denominator}, threshold={threshold}"
                );
            }
        }
    }
}

// --- Full-replace API-spec graph preservation -------------------------------

fn proxy(id: &str, namespace: &str, api_spec_id: Option<&str>) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "backend_host": "127.0.0.1",
        "backend_port": 8080,
        "api_spec_id": api_spec_id,
    }))
    .expect("proxy fixture")
}

fn plugin_config(
    id: &str,
    namespace: &str,
    proxy_id: &str,
    api_spec_id: Option<&str>,
) -> gitforgeops::config::schema::PluginConfig {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": namespace,
        "plugin_name": "cors",
        "config": {},
        "scope": "proxy",
        "proxy_id": proxy_id,
        "api_spec_id": api_spec_id,
    }))
    .expect("plugin fixture")
}

fn spec_extras(ids: &[&str]) -> gitforgeops::http_client::BackupExtras {
    gitforgeops::http_client::BackupExtras {
        api_specs: Some(serde_json::json!({
            "section_version": "2",
            "items": ids.iter().map(|id| serde_json::json!({
                "id": id,
                "namespace": "team-alpha",
                "proxy_id": "spec-proxy"
            })).collect::<Vec<_>>(),
        })),
        gateway_trust_bundles: Some(serde_json::json!([{"revision": 7}])),
        unsupported_sections: Vec::new(),
    }
}

/// Repo-owned desired rows plus the live spec-owned graph they must be
/// restored alongside: one API spec `spec-a` owning proxy `spec-proxy`,
/// upstream `spec-upstream` and plugin config `spec-plugin`.
fn spec_owned_graph() -> (GatewayConfig, GatewayConfig) {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let mut spec_upstream = upstream("spec-upstream", "team-alpha");
    spec_upstream.api_spec_id = Some("spec-a".to_string());
    let mut spec_proxy = proxy("spec-proxy", "team-alpha", Some("spec-a"));
    spec_proxy
        .plugins
        .push(gitforgeops::config::schema::PluginAssociation {
            plugin_config_id: "spec-plugin".to_string(),
        });
    let actual = GatewayConfig {
        proxies: vec![spec_proxy],
        upstreams: vec![spec_upstream],
        plugin_configs: vec![plugin_config(
            "spec-plugin",
            "team-alpha",
            "spec-proxy",
            Some("spec-a"),
        )],
        ..Default::default()
    };
    (desired, actual)
}

#[test]
fn merging_the_spec_owned_graph_keeps_repo_rows_authoritative() {
    let (desired, actual) = spec_owned_graph();

    let merged =
        preserve_spec_owned_graph(&desired, &actual, &spec_extras(&["spec-a"]), "team-alpha")
            .expect("complete graph should merge");

    assert_eq!(merged.proxies.len(), 1);
    assert_eq!(merged.plugin_configs.len(), 1);
    assert_eq!(merged.upstreams.len(), 2);
    assert_eq!(merged.upstreams[0].id, "repo-upstream");
    assert_eq!(merged.upstreams[1].id, "spec-upstream");
    assert_eq!(merged.upstreams[1].api_spec_id.as_deref(), Some("spec-a"));
}

#[test]
fn full_replace_rejects_repo_collision_with_spec_owned_row() {
    let desired = GatewayConfig {
        proxies: vec![proxy("shared-id", "team-alpha", None)],
        ..Default::default()
    };
    let actual = GatewayConfig {
        proxies: vec![proxy("shared-id", "team-alpha", Some("spec-a"))],
        ..Default::default()
    };

    let error =
        preserve_spec_owned_graph(&desired, &actual, &spec_extras(&["spec-a"]), "team-alpha")
            .unwrap_err()
            .to_string();
    assert!(error.contains("conflicts"), "{error}");
    assert!(error.contains("shared-id"), "{error}");
    assert!(error.contains("spec-a"), "{error}");
}

#[test]
fn every_api_strategy_rejects_repository_authored_spec_ownership_tags() {
    let desired = GatewayConfig {
        proxies: vec![proxy("forged-owner", "team-alpha", Some("spec-a"))],
        ..Default::default()
    };

    let error = validate_no_desired_spec_tags(&desired)
        .unwrap_err()
        .to_string();
    assert!(error.contains("forged-owner"), "{error}");
    assert!(error.contains("admin-generated"), "{error}");
}

#[test]
fn interactive_preview_includes_pending_create_ownership_assertions() {
    let desired_upstream = upstream("pending-upstream", "team-alpha");
    let desired = GatewayConfig {
        upstreams: vec![desired_upstream.clone()],
        ..Default::default()
    };
    let actual = GatewayConfig {
        upstreams: vec![desired_upstream],
        ..Default::default()
    };
    let pending =
        std::collections::BTreeSet::from([state_key("team-alpha", "Upstream", "pending-upstream")]);

    let assertions = pending_create_assertion_diffs(&desired, &actual, &pending, "team-alpha");

    assert_eq!(assertions.len(), 1);
    assert!(matches!(assertions[0].action, DiffAction::Modify));
    assert_eq!(assertions[0].kind, "Upstream");
    assert_eq!(assertions[0].id, "pending-upstream");
}

#[test]
fn full_replace_rejects_incomplete_spec_ownership_graph() {
    let desired = GatewayConfig::default();
    let actual = GatewayConfig::default();
    let error =
        preserve_spec_owned_graph(&desired, &actual, &spec_extras(&["spec-a"]), "team-alpha")
            .unwrap_err()
            .to_string();
    assert!(
        error.contains("no tagged") || error.contains("owning proxy"),
        "{error}"
    );
    assert!(error.contains("spec-a"), "{error}");
}

#[test]
fn full_replace_rejects_a_tagged_proxy_that_is_not_the_declared_owner() {
    let actual = GatewayConfig {
        proxies: vec![proxy("wrong-proxy", "team-alpha", Some("spec-a"))],
        ..Default::default()
    };

    let error = preserve_spec_owned_graph(
        &GatewayConfig::default(),
        &actual,
        &spec_extras(&["spec-a"]),
        "team-alpha",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("spec-proxy"), "{error}");
    assert!(error.contains("exactly one"), "{error}");
}

#[test]
fn full_replace_rejects_spec_owned_rows_from_another_namespace() {
    let actual = GatewayConfig {
        proxies: vec![proxy("spec-proxy", "foreign", Some("spec-a"))],
        ..Default::default()
    };

    let error = preserve_spec_owned_graph(
        &GatewayConfig::default(),
        &actual,
        &spec_extras(&["spec-a"]),
        "team-alpha",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("foreign"), "{error}");
    assert!(error.contains("team-alpha"), "{error}");
}

#[test]
fn exclusive_prune_denominator_excludes_unconfirmed_spec_owned_rows() {
    let actual = GatewayConfig {
        proxies: vec![
            proxy("manual-proxy", "team-alpha", None),
            proxy("spec-proxy", "team-alpha", Some("spec-a")),
        ],
        upstreams: vec![upstream("manual-upstream", "team-alpha"), {
            let mut value = upstream("spec-upstream", "team-alpha");
            value.api_spec_id = Some("spec-a".to_string());
            value
        }],
        plugin_configs: vec![
            plugin_config("manual-plugin", "team-alpha", "manual-proxy", None),
            plugin_config("spec-plugin", "team-alpha", "spec-proxy", Some("spec-a")),
        ],
        ..Default::default()
    };

    assert_eq!(exclusive_prune_denominator(&actual, false), 3);
    assert_eq!(exclusive_prune_denominator(&actual, true), 6);
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
use std::sync::{Arc, Mutex};

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

/// Owned-response variant that records every request and can attach response
/// headers (notably `X-Data-Source: cached`).
type RecordingRoute = (String, u16, String, Vec<(String, String)>);

fn spawn_recording_gateway(routes: Vec<RecordingRoute>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = routes.clone();
            let requests = Arc::clone(&thread_requests);
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                requests.lock().unwrap().push(request.clone());
                let (status, body, headers) = routes
                    .iter()
                    .find(|(needle, _, _, _)| request.contains(needle))
                    .map(|(_, status, body, headers)| (*status, body.as_str(), headers.as_slice()))
                    .unwrap_or((200, "{}", &[]));
                let headers = headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>();
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\n{headers}content-length: {}\r\n\r\n{}",
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
    (format!("http://{addr}"), requests)
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

/// Namespace scope every test client is built with.
///
/// `AdminClient::new_scoped` is the only public constructor, so tests declare
/// a scope like production call sites do. The stub gateways ignore the token,
/// but this keeps the tests honest about the constructor's contract.
const TEST_NAMESPACES: [&str; 5] = ["team-alpha", "team-a", "team-b", "ferrum", "alpha"];

fn stub_client(url: String) -> AdminClient {
    stub_client_with_retries(url, 0)
}

fn stub_client_with_retries(url: String, gateway_max_retries: u32) -> AdminClient {
    let env = EnvConfig {
        gateway_url: Some(url),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        gateway_mode: GatewayMode::Api,
        gateway_max_retries,
        ..EnvConfig::default()
    };
    AdminClient::new_scoped(&env, TEST_NAMESPACES).unwrap()
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
async fn full_replace_rejects_unknown_backup_sections_before_preflight_or_mutation() {
    let client = stub_client("http://127.0.0.1:9".to_string());
    let namespaces = ["team-alpha".to_string()];
    let actuals = empty_actuals(&["team-alpha"]);
    let extras = BTreeMap::from([(
        "team-alpha".to_string(),
        gitforgeops::http_client::BackupExtras {
            unsupported_sections: vec!["future_security_policy".to_string()],
            ..Default::default()
        },
    )]);
    let options = ApplyOptions {
        strategy: gitforgeops::config::ApplyStrategy::FullReplace,
        ..Default::default()
    };

    let error = apply_api(
        &GatewayConfig::default(),
        &client,
        &namespaces,
        OwnershipScope::Exclusive,
        Some(&actuals),
        Some(&extras),
        &options,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        gitforgeops::error::Error::UnsupportedBackupSections(_)
    ));
    assert!(error.to_string().contains("future_security_policy"));
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
    let client = stub_client_with_retries(url, 3);

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
async fn ambiguous_batch_is_not_replayed_and_is_recovered_from_authoritative_backup() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let backup = serde_json::to_string(&desired).unwrap();
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /batch".into(),
            503,
            r#"{"error":"upstream response lost"}"#.into(),
            vec![],
        ),
        ("GET /backup".into(), 200, backup, vec![]),
    ]);
    let client = stub_client_with_retries(url, 3);

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
    .expect("reconciliation should prove the committed chunk");

    assert_eq!(result.created, 1);
    assert_eq!(result.applied_incremental.len(), 1);
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.fatal_error.is_none(), "{:?}", result.fatal_error);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("POST /batch"))
            .count(),
        1,
        "the ambiguous POST must never be retried"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("POST /upstreams"))
            .count(),
        0,
        "an ambiguous batch must not fall back to individual creates"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("PUT /upstreams/u1"))
            .count(),
        1,
        "exact readback still needs an idempotent ownership assertion"
    );
}

#[tokio::test]
async fn ambiguous_create_is_sent_once_and_recovered_from_authoritative_backup() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let backup = serde_json::to_string(&desired).unwrap();
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("POST /batch".into(), 501, "{}".into(), vec![]),
        (
            "POST /upstreams".into(),
            502,
            r#"{"error":"response lost after commit"}"#.into(),
            vec![],
        ),
        ("GET /backup".into(), 200, backup, vec![]),
    ]);
    let client = stub_client_with_retries(url, 3);

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
    .expect("reconciliation should prove the committed create");

    assert_eq!(result.created, 1);
    assert_eq!(result.applied_incremental.len(), 1);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("POST /upstreams"))
            .count(),
        1,
        "the ambiguous create must never be retried"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.contains("PUT /upstreams/u1"))
            .count(),
        1,
        "exact readback still needs an idempotent ownership assertion"
    );
}

#[tokio::test]
async fn pending_exact_row_gets_an_idempotent_ownership_assertion() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("PUT /upstreams/u1".into(), 200, "{}".into(), vec![]),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            desired.clone(),
        )])),
        None,
        &ApplyOptions {
            pending_create_assertions: std::collections::BTreeSet::from([state_key(
                "team-alpha",
                "Upstream",
                "u1",
            )]),
            ..Default::default()
        },
    )
    .await
    .expect("ownership assertion should succeed");

    assert_eq!(result.updated, 1);
    assert_eq!(result.applied_incremental.len(), 1);
    assert!(matches!(
        result.applied_incremental[0].action,
        DiffAction::Modify
    ));
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("PUT /upstreams/u1"))
            .count(),
        1
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("POST /upstreams")),
        "the uncertain create must not be replayed"
    );
}

#[tokio::test]
async fn committed_but_not_live_create_is_failed_without_reconciliation_success() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("POST /batch".into(), 501, "{}".into(), vec![]),
        (
            "POST /upstreams".into(),
            503,
            r#"{"error":"reload timed out","applied":false,"reason":"reload_timeout"}"#.into(),
            vec![],
        ),
    ]);
    let client = stub_client_with_retries(url, 3);

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
    .expect("run-stopping failure is returned in the aggregate");

    assert_eq!(result.created, 0);
    assert!(
        result
            .fatal_error
            .as_deref()
            .is_some_and(|error| error.contains("write committed, awaiting reload")),
        "{:?}",
        result.fatal_error
    );
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("POST /upstreams"))
            .count(),
        1
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("GET /backup")),
        "applied:false is a known failure, not proof that the desired resource is live"
    );
}

#[tokio::test]
async fn cached_backup_blocks_all_apply_mutations_before_the_first_write() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "GET /backup".into(),
            200,
            serde_json::to_string(&GatewayConfig::default()).unwrap(),
            vec![("X-Data-Source".into(), "cached".into())],
        ),
    ]);
    let client = stub_client(url);
    let snapshot = client
        .get_backup_snapshot("team-alpha")
        .await
        .expect("cached backup itself remains readable");
    assert!(snapshot.cached);

    let error = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            snapshot.config,
        )])),
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            snapshot.extras,
        )])),
        &ApplyOptions::default(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, gitforgeops::error::Error::StaleGatewayView(_)),
        "{error:?}"
    );
    // The wording is the operator's only clue about why an apply that looks
    // routine refused, so assert it where it is actually produced.
    let message = error.to_string();
    assert!(message.contains("X-Data-Source: cached"), "{message}");
    assert!(message.contains("API-spec ownership metadata"), "{message}");
    assert!(
        message.contains("--allow-large-prune") && message.contains("does not bypass"),
        "the one override an operator would reach for must be ruled out: {message}"
    );
    let requests = requests.lock().unwrap();
    assert!(
        requests.iter().all(|request| {
            !request.contains("POST ") && !request.contains("PUT ") && !request.contains("DELETE ")
        }),
        "no mutation may be sent from cached ownership data: {requests:?}"
    );
}

#[tokio::test]
async fn full_replace_preserves_the_complete_spec_owned_resource_graph() {
    // Issue #71. `/restore` validates the ownership graph as one unit: an
    // `api_specs` document whose owning proxy is missing, or a tagged row
    // whose spec is missing, is a 400 before anything is deleted. So the body
    // has to carry the repo's desired rows AND the live spec-owned rows AND
    // the live `api_specs` section. Restore never re-extracts resources from
    // the documents, so nothing is duplicated by carrying both.
    let (desired, actual) = spec_owned_graph();
    let extras = spec_extras(&["spec-a"]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([("team-alpha".to_string(), actual)])),
        Some(&BTreeMap::from([("team-alpha".to_string(), extras)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("a namespace with API specs must be restorable");

    assert_eq!(
        result.created, 1,
        "only the repo-owned row counts as applied; preserved spec rows are not this repo's"
    );
    assert_eq!(result.fully_replaced_namespaces, vec!["team-alpha"]);

    let restore = requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| request.contains("POST /restore?confirm=true"))
        .cloned()
        .expect("restore request");
    let body: serde_json::Value =
        serde_json::from_str(restore.split_once("\r\n\r\n").expect("request body").1)
            .expect("restore body is JSON");

    assert!(
        !restore.contains("confirm_api_spec_deletion"),
        "preservation must not use the destructive opt-in: {restore}"
    );

    let ids = |section: &str| {
        body[section]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|value| value["id"].as_str().map(str::to_string))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids("upstreams"), vec!["repo-upstream", "spec-upstream"]);
    assert_eq!(ids("proxies"), vec!["spec-proxy"]);
    assert_eq!(ids("plugin_configs"), vec!["spec-plugin"]);

    // Every tagged row names a spec that is present in `api_specs.items`, and
    // that spec's owning proxy is present and carries the tag — the exact two
    // directions ferrum-edge's restore validator checks.
    assert_eq!(body["api_specs"]["items"][0]["id"], "spec-a");
    assert_eq!(body["api_specs"]["items"][0]["proxy_id"], "spec-proxy");
    for section in ["proxies", "upstreams", "plugin_configs"] {
        for row in body[section].as_array().into_iter().flatten() {
            if let Some(tag) = row["api_spec_id"].as_str() {
                assert_eq!(tag, "spec-a", "{section}: {row}");
            }
        }
    }

    assert!(
        !restore.contains("gateway_trust_bundles"),
        "an absent trust section preserves the live roots: {restore}"
    );
}

#[tokio::test]
async fn full_replace_refuses_an_incomplete_spec_owned_graph_before_mutating() {
    // The preservation path is only safe while the graph can be proven whole.
    // A spec document whose tagged rows are missing from the same
    // authoritative backup means the view is incomplete, not that the rows
    // should be deleted.
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let error = apply_api(
        &GatewayConfig::default(),
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&empty_actuals(&["team-alpha"])),
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            spec_extras(&["spec-a"]),
        )])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("spec-a"), "{error}");
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("POST /restore")),
        "an unprovable graph must never reach /restore"
    );
}

#[tokio::test]
async fn confirmed_spec_deletion_leaves_live_trust_bundles_untouched() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let extras = spec_extras(&["spec-a"]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true&confirm_api_spec_deletion=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            GatewayConfig::default(),
        )])),
        Some(&BTreeMap::from([("team-alpha".to_string(), extras)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            confirm_api_spec_deletion: true,
            ..Default::default()
        },
    )
    .await
    .expect("confirmed full replace should succeed");

    assert_eq!(result.created, 1);
    let restore = requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| {
            request.contains("POST /restore?confirm=true&confirm_api_spec_deletion=true")
        })
        .cloned()
        .expect("confirmed restore request");
    assert!(restore.contains("repo-upstream"), "{restore}");
    assert!(!restore.contains("gateway_trust_bundles"), "{restore}");
    assert!(!restore.contains("api_specs"), "{restore}");
    assert!(!restore.contains("spec-proxy"), "{restore}");
}

#[tokio::test]
async fn empty_spec_snapshot_omits_api_specs_and_trust_to_close_lost_update_races() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("repo-upstream", "team-alpha")],
        ..Default::default()
    };
    let extras = gitforgeops::http_client::BackupExtras {
        api_specs: Some(serde_json::json!({"section_version": "2", "items": []})),
        gateway_trust_bundles: Some(serde_json::json!([{"revision": 7}])),
        unsupported_sections: Vec::new(),
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /restore?confirm=true".into(),
            200,
            "{}".into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["team-alpha".to_string()],
        OwnershipScope::Exclusive,
        Some(&BTreeMap::from([(
            "team-alpha".to_string(),
            GatewayConfig::default(),
        )])),
        Some(&BTreeMap::from([("team-alpha".to_string(), extras)])),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .expect("empty spec snapshot is safe to restore");

    assert_eq!(result.created, 1);
    let restore = requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| request.contains("POST /restore?confirm=true"))
        .cloned()
        .expect("restore request");
    assert!(restore.contains("repo-upstream"), "{restore}");
    assert!(!restore.contains("api_specs"), "{restore}");
    assert!(!restore.contains("gateway_trust_bundles"), "{restore}");
}

#[tokio::test]
async fn later_namespace_restore_validation_fails_before_any_namespace_is_mutated() {
    let (url, requests) = spawn_recording_gateway(vec![]);
    let client = stub_client(url);
    let namespaces = vec!["alpha".to_string(), "beta".to_string()];
    let actuals = empty_actuals(&["alpha", "beta"]);
    let extras = BTreeMap::from([
        (
            "alpha".to_string(),
            gitforgeops::http_client::BackupExtras {
                api_specs: Some(serde_json::json!({
                    "section_version": "2",
                    "items": []
                })),
                ..Default::default()
            },
        ),
        (
            "beta".to_string(),
            gitforgeops::http_client::BackupExtras {
                api_specs: Some(serde_json::json!({"section_version": "2"})),
                ..Default::default()
            },
        ),
    ]);

    let error = apply_api(
        &GatewayConfig::default(),
        &client,
        &namespaces,
        OwnershipScope::Exclusive,
        Some(&actuals),
        Some(&extras),
        &ApplyOptions {
            strategy: gitforgeops::config::ApplyStrategy::FullReplace,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("items"), "{error}");
    assert!(
        requests.lock().unwrap().is_empty(),
        "alpha must not restore before beta's deterministic error"
    );
}

#[tokio::test]
async fn a_spec_owned_conflict_blocks_only_the_conflicting_namespace() {
    // Two owners writing one row is a correctness problem in *that* namespace.
    // Stopping every other namespace turned one team's mis-declared proxy into
    // an outage for everybody sharing the environment, so the block is scoped
    // and reported as a per-namespace error — the run still exits non-zero.
    let desired_proxy = proxy("shared", "alpha", None);
    let mut spec_proxy = desired_proxy.clone();
    spec_proxy.api_spec_id = Some("spec-a".to_string());
    let desired = GatewayConfig {
        proxies: vec![desired_proxy],
        upstreams: vec![upstream("unrelated", "beta")],
        ..Default::default()
    };
    let actuals = BTreeMap::from([
        (
            "alpha".to_string(),
            GatewayConfig {
                proxies: vec![spec_proxy],
                ..Default::default()
            },
        ),
        ("beta".to_string(), GatewayConfig::default()),
    ]);
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        (
            "POST /batch".into(),
            200,
            r#"{"created":{"upstreams":1}}"#.into(),
            vec![],
        ),
    ]);
    let client = stub_client(url);

    let result = apply_api(
        &desired,
        &client,
        &["alpha".to_string(), "beta".to_string()],
        OwnershipScope::Exclusive,
        Some(&actuals),
        None,
        &ApplyOptions::default(),
    )
    .await
    .expect("the conflict rides on the result as a per-namespace error");

    assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    assert!(
        result.errors[0].starts_with("[alpha]"),
        "{:?}",
        result.errors
    );
    assert!(
        result.errors[0].contains("API-spec-owned"),
        "{:?}",
        result.errors
    );
    assert!(result.fatal_error.is_none(), "{:?}", result.fatal_error);

    assert_eq!(result.created, 1, "beta still reconciles");
    assert_eq!(
        result
            .applied_incremental
            .iter()
            .map(|op| op.namespace.as_str())
            .collect::<Vec<_>>(),
        vec!["beta"],
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| !request.contains("x-ferrum-namespace: alpha")),
        "nothing may be written to the conflicting namespace"
    );

    // ...and the run is still a failure.
    assert!(result.into_result().is_err());
}

#[tokio::test]
async fn three_xx_batch_response_never_records_an_applied_operation() {
    let desired = GatewayConfig {
        upstreams: vec![upstream("u1", "team-alpha")],
        ..Default::default()
    };
    let (url, requests) = spawn_recording_gateway(vec![
        ("GET /health".into(), 200, HEALTHY.into(), vec![]),
        ("POST /batch".into(), 304, "{}".into(), vec![]),
    ]);
    let client = stub_client(url);

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
    .expect("nonfatal namespace error is aggregated");

    assert_eq!(result.created, 0);
    assert!(result.applied_incremental.is_empty());
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(
        result
            .fatal_error
            .as_deref()
            .is_some_and(|error| error.contains("304")),
        "{:?}",
        result.fatal_error
    );
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.contains("POST /batch"))
            .count(),
        1
    );
}

#[tokio::test]
async fn bare_restore_403_is_refined_to_a_run_stopping_read_only_error() {
    let read_only_health = r#"{"status":"ok","mode":"file","admin_writes_enabled":false}"#;
    let (url, requests) = spawn_recording_gateway(vec![
        (
            "POST /restore?confirm=true".into(),
            403,
            r#"{"error":"forbidden"}"#.into(),
            vec![],
        ),
        ("GET /health".into(), 200, read_only_health.into(), vec![]),
    ]);
    let client = stub_client(url);

    let error = client
        .post_restore(
            &GatewayConfig::default(),
            "team-a",
            &Default::default(),
            false,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(error, gitforgeops::error::Error::GatewayReadOnly(_)),
        "{error:?}"
    );
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("POST /restore"))
            .count(),
        1,
        "restore must not be replayed"
    );
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
