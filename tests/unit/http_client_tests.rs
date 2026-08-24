use gitforgeops::config::env::{ApplyStrategy, EnvConfig, GatewayMode};
use gitforgeops::config::schema::{GatewayConfig, Proxy, Upstream};
use gitforgeops::http_client::{
    build_restore_body, classify_retry, delete_succeeded, map_api_error, merge_pages,
    next_page_offset, split_batch, write_block_reason, AdminClient, ApiErrorBody, BackupExtras,
    BackupSnapshot, BatchCreate, HealthStatus, RequestKind, RetryDecision, BATCH_MAX_BODY_BYTES,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

fn base_env() -> EnvConfig {
    EnvConfig {
        gateway_url: Some("https://gateway.example:9000".to_string()),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        gateway_mode: GatewayMode::Api,
        apply_strategy: ApplyStrategy::Incremental,
        ..EnvConfig::default()
    }
}

#[test]
fn admin_client_rejects_client_cert_without_key() {
    let mut env = base_env();
    env.client_cert = Some("dummy".to_string());
    env.client_key = None;

    let err = match AdminClient::new(&env) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err.contains("FERRUM_GATEWAY_CLIENT_KEY"),
        "expected missing-key error, got: {err}"
    );
}

#[test]
fn admin_client_rejects_client_key_without_cert() {
    let mut env = base_env();
    env.client_cert = None;
    env.client_key = Some("dummy".to_string());

    let err = match AdminClient::new(&env) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err.contains("FERRUM_GATEWAY_CLIENT_CERT"),
        "expected missing-cert error, got: {err}"
    );
}

#[test]
fn admin_client_rejects_short_jwt_secret() {
    let mut env = base_env();
    env.admin_jwt_secret = Some("too-short".to_string());

    let err = match AdminClient::new(&env) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error"),
    };
    assert!(
        err.contains("at least 32 characters"),
        "expected short-secret error, got: {err}"
    );
}

#[test]
fn admin_client_builds_without_mtls() {
    let env = base_env();
    AdminClient::new(&env).expect("client should build without mTLS");
}

#[test]
fn admin_client_honors_custom_timeouts() {
    let mut env = base_env();
    env.gateway_connect_timeout_secs = 3;
    env.gateway_request_timeout_secs = 15;
    AdminClient::new(&env).expect("client should build with custom timeouts");
}

#[tokio::test]
async fn admin_client_get_backup_sends_namespace_and_bearer_token() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        tx.send(request).unwrap();
        let body =
            r#"{"version":"1","proxies":[],"consumers":[],"plugin_configs":[],"upstreams":[]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    let mut env = base_env();
    env.gateway_url = Some(format!("http://{addr}"));
    let client = AdminClient::new(&env).unwrap();

    let backup = client.get_backup("team-alpha").await.unwrap();
    assert!(backup.proxies.is_empty());

    let request = rx.recv().unwrap();
    assert!(request.starts_with("GET /backup HTTP/1.1"));
    assert!(request.contains("authorization: Bearer "));
    assert!(request.contains("x-ferrum-namespace: team-alpha"));
}

#[tokio::test]
async fn admin_client_rejects_unsafe_resource_ids_in_paths() {
    let env = base_env();
    let client = AdminClient::new(&env).unwrap();

    let err = client
        .delete_proxy("../consumers/victim?confirm=true", "team-alpha")
        .await;
    assert!(err.is_err(), "expected unsafe id to be rejected");
    let msg = err.err().unwrap().to_string();
    assert!(
        msg.contains("unsafe characters"),
        "unexpected error message: {msg}"
    );
}

#[tokio::test]
async fn admin_client_accepts_safe_resource_id_in_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        tx.send(request).unwrap();
        write!(
            stream,
            "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n"
        )
        .unwrap();
    });

    let mut env = base_env();
    env.gateway_url = Some(format!("http://{addr}"));
    let client = AdminClient::new(&env).unwrap();

    client
        .delete_proxy("proxy-01._A", "team-alpha")
        .await
        .unwrap();

    let request = rx.recv().unwrap();
    // `cleanup_orphaned_upstream=false` opts out of the server-side cascade
    // that would silently delete the proxy's last-referenced upstream and make
    // the diff's own upstream delete 404.
    assert!(
        request.starts_with("DELETE /proxies/proxy-01._A?cleanup_orphaned_upstream=false HTTP/1.1"),
        "unexpected request line: {request}"
    );
}

// --- Resource-id grammar -----------------------------------------------------

#[tokio::test]
async fn admin_client_rejects_ids_outside_the_server_grammar() {
    let env = base_env();
    let client = AdminClient::new(&env).unwrap();

    // Aligned exactly with the gateway's `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`:
    // `~` is URL-safe but not in the server's alphabet, and a leading `-`
    // or `.` is rejected too.
    for id in ["proxy~01", "-leading-dash", ".leading-dot", "_leading"] {
        let err = client.delete_proxy(id, "team-alpha").await;
        assert!(err.is_err(), "expected {id:?} to be rejected");
        assert!(
            err.err().unwrap().to_string().contains("unsafe characters"),
            "expected grammar rejection for {id:?}"
        );
    }
}

#[tokio::test]
async fn admin_client_rejects_ids_over_the_length_limit() {
    let env = base_env();
    let client = AdminClient::new(&env).unwrap();

    let too_long = "a".repeat(255);
    let err = client.delete_proxy(&too_long, "team-alpha").await;
    assert!(
        err.err().unwrap().to_string().contains("254"),
        "expected the 254-character limit to be named"
    );
}

// --- Pagination --------------------------------------------------------------

#[test]
fn next_page_offset_advances_until_the_total_is_covered() {
    // 250 namespaces, page size 100: offsets 0 → 100 → 200 → done.
    assert_eq!(next_page_offset(0, 100, Some(250), 100), Some(100));
    assert_eq!(next_page_offset(100, 100, Some(250), 200), Some(200));
    assert_eq!(next_page_offset(200, 50, Some(250), 250), None);
}

#[test]
fn next_page_offset_stops_on_an_empty_page() {
    // Guards against a server that ignores `offset` and would otherwise loop
    // forever returning the same (or no) rows.
    assert_eq!(next_page_offset(0, 0, Some(500), 0), None);
}

#[test]
fn next_page_offset_stops_without_a_pagination_envelope() {
    // No `pagination` key at all (an older gateway, or a proxy that rewrote
    // the body) — take the single page rather than guessing.
    assert_eq!(next_page_offset(0, 12, None, 12), None);
}

#[test]
fn next_page_offset_stops_when_accumulated_exceeds_total() {
    assert_eq!(next_page_offset(0, 100, Some(80), 100), None);
}

#[test]
fn merge_pages_flattens_and_dedups_preserving_order() {
    let merged = merge_pages(vec![
        vec!["ferrum".to_string(), "team-a".to_string()],
        // `team-a` can legitimately reappear across a page boundary: the
        // listing is a union of registry rows and derived namespaces and can
        // shift mid-walk.
        vec!["team-a".to_string(), "team-b".to_string()],
    ]);
    assert_eq!(merged, vec!["ferrum", "team-a", "team-b"]);
}

#[test]
fn merge_pages_on_no_pages_is_empty() {
    assert!(merge_pages(Vec::new()).is_empty());
}

// --- Retry classification ----------------------------------------------------

fn body(json: &str) -> ApiErrorBody {
    ApiErrorBody::parse(json)
}

#[test]
fn retry_classification_table() {
    let empty = ApiErrorBody::default();
    let cases: &[(u16, RetryDecision)] = &[
        (408, RetryDecision::Retry),
        (429, RetryDecision::Retry),
        (500, RetryDecision::Retry),
        (502, RetryDecision::Retry),
        (503, RetryDecision::Retry),
        (504, RetryDecision::Retry),
        // 501 is permanent: a standalone-MongoDB gateway has no multi-document
        // transaction and will answer it forever.
        (501, RetryDecision::NoRetry),
        (400, RetryDecision::NoRetry),
        (401, RetryDecision::NoRetry),
        (403, RetryDecision::NoRetry),
        (404, RetryDecision::NoRetry),
        (409, RetryDecision::NoRetry),
        (413, RetryDecision::NoRetry),
    ];
    for (status, expected) in cases {
        assert_eq!(
            classify_retry(*status, &empty, RequestKind::Mutation),
            *expected,
            "status {status} classified wrong"
        );
    }
}

#[test]
fn applied_false_is_never_retried() {
    // Durable but not live: the write is committed, so a retry re-applies it
    // (and a create answers 409 the second time round).
    let b = body(r#"{"error":"reload timed out","applied":false,"reason":"reload_timeout"}"#);
    assert_eq!(b.applied, Some(false));
    assert_eq!(b.reason.as_deref(), Some("reload_timeout"));
    assert_eq!(
        classify_retry(503, &b, RequestKind::Mutation),
        RetryDecision::NoRetry
    );
}

#[test]
fn restore_500_with_dirty_rollback_is_never_retried() {
    for rollback in ["incomplete", "unknown_outcome"] {
        let b = body(&format!(
            r#"{{"error":"restore failed","rollback":"{rollback}","failure_class":"data_integrity"}}"#
        ));
        assert_eq!(
            classify_retry(500, &b, RequestKind::Restore),
            RetryDecision::NoRetry,
            "rollback={rollback} must not be retried — a retry re-runs a destructive replace"
        );
    }

    // A clean rollback means nothing was left behind; the generic 500 rule
    // applies again.
    let clean = body(r#"{"error":"restore failed","rollback":"completed"}"#);
    assert_eq!(
        classify_retry(500, &clean, RequestKind::Restore),
        RetryDecision::Retry
    );
}

#[test]
fn restore_503_connectivity_is_retryable() {
    let b = body(r#"{"error":"datastore unavailable","failure_class":"connectivity"}"#);
    assert_eq!(
        classify_retry(503, &b, RequestKind::Restore),
        RetryDecision::Retry
    );
}

#[test]
fn api_error_body_tolerates_non_json_bodies() {
    // Load balancers and proxies emit HTML error pages; the classifier must
    // degrade to the status-only decision rather than blowing up.
    let b = ApiErrorBody::parse("<html>502 Bad Gateway</html>");
    assert!(b.error.is_none());
    assert_eq!(
        classify_retry(502, &b, RequestKind::Mutation),
        RetryDecision::Retry
    );
}

// --- Delete tolerance --------------------------------------------------------

#[test]
fn delete_treats_404_as_success() {
    // Proxy deletes cascade server-side to scoped plugin configs, so the
    // diff's own follow-up delete legitimately finds nothing. Recording that
    // as an error left the state entry behind and wedged every later run.
    assert!(delete_succeeded(200));
    assert!(delete_succeeded(204));
    assert!(delete_succeeded(404));

    assert!(!delete_succeeded(403));
    assert!(!delete_succeeded(409));
    assert!(!delete_succeeded(500));
}

// --- Error mapping -----------------------------------------------------------

#[test]
fn read_only_403_maps_to_a_dedicated_error() {
    let err = map_api_error(
        403,
        r#"{"error":"Admin API is in read-only mode"}"#,
        RequestKind::Mutation,
    );
    assert!(
        matches!(err, gitforgeops::error::Error::GatewayReadOnly(_)),
        "expected GatewayReadOnly, got: {err:?}"
    );
    assert!(err.to_string().contains("read-only"));
}

#[test]
fn other_403s_stay_generic_api_errors() {
    // Role/namespace-claim rejections are also 403 but are a different
    // problem, and must not short-circuit the apply as read-only.
    let err = map_api_error(
        403,
        r#"{"error":"Namespace claim does not cover team-alpha"}"#,
        RequestKind::Mutation,
    );
    assert!(matches!(
        err,
        gitforgeops::error::Error::ApiError { status: 403, .. }
    ));
}

#[test]
fn api_specs_409_is_actionable() {
    let err = map_api_error(
        409,
        r#"{"error":"restore would delete API specs","api_specs_at_risk":["spec-a","spec-b"],"confirmation_required":"confirm_api_spec_deletion=true"}"#,
        RequestKind::Restore,
    );
    assert!(matches!(err, gitforgeops::error::Error::ApiSpecsAtRisk(_)));
    let msg = err.to_string();
    assert!(msg.contains("2 spec(s)"), "should count the specs: {msg}");
    assert!(
        msg.contains("--confirm-api-spec-deletion"),
        "should name the opt-in flag: {msg}"
    );
}

#[test]
fn restore_rollback_failure_demands_manual_recovery() {
    let err = map_api_error(
        500,
        r#"{"error":"import failed","rollback":"incomplete","restore_errors":["proxy-a"]}"#,
        RequestKind::Restore,
    );
    assert!(matches!(
        err,
        gitforgeops::error::Error::RestoreNeedsManualRecovery(_)
    ));
    let msg = err.to_string();
    assert!(msg.contains("Do NOT re-run apply"), "got: {msg}");
    assert!(
        msg.contains("proxy-a"),
        "should surface restore_errors: {msg}"
    );
}

#[test]
fn applied_false_maps_to_committed_not_live() {
    let err = map_api_error(
        503,
        r#"{"error":"reload timed out","applied":false,"reason":"reload_timeout"}"#,
        RequestKind::Mutation,
    );
    match err {
        gitforgeops::error::Error::CommittedNotLive { reason, .. } => {
            assert_eq!(reason, "reload_timeout");
        }
        other => panic!("expected CommittedNotLive, got {other:?}"),
    }
}

#[test]
fn payload_too_large_names_the_limit_knob() {
    let err = map_api_error(413, r#"{"error":"body too large"}"#, RequestKind::Restore);
    assert!(err
        .to_string()
        .contains("FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB"));
}

// --- Restore body ------------------------------------------------------------

fn backup_extras() -> BackupExtras {
    BackupExtras {
        api_specs: Some(serde_json::json!({
            "section_version": "2",
            "items": [{"id": "spec-a"}, {"id": "spec-b"}],
        })),
        gateway_trust_bundles: Some(serde_json::json!([{ "revision": 7 }])),
    }
}

#[test]
fn restore_body_carries_opaque_api_specs_and_trust_bundles() {
    let extras = backup_extras();
    let body = build_restore_body(&GatewayConfig::default(), &extras, false).unwrap();

    // Carried through byte-for-byte: gitforgeops does not model (or version)
    // these sections, it just refuses to destroy them.
    assert_eq!(body["api_specs"], extras.api_specs.clone().unwrap());
    assert_eq!(
        body["gateway_trust_bundles"],
        extras.gateway_trust_bundles.clone().unwrap()
    );
    // The managed sections are still present alongside them.
    assert_eq!(body["version"], "1");
    assert!(body.get("proxies").is_some());
}

#[test]
fn restore_body_drops_api_specs_on_explicit_confirmation() {
    let body = build_restore_body(&GatewayConfig::default(), &backup_extras(), true).unwrap();
    assert!(
        body.get("api_specs").is_none(),
        "the destructive opt-in must omit the section so /restore deletes it"
    );
    assert!(body.get("gateway_trust_bundles").is_none());
}

#[test]
fn restore_body_omits_absent_sections_entirely() {
    // Three-valued trust-bundle contract: absent = no-op, present-empty =
    // revoke. A backup that omitted the section must restore as a no-op, so we
    // must not synthesize an empty array.
    let body =
        build_restore_body(&GatewayConfig::default(), &BackupExtras::default(), false).unwrap();
    assert!(body.get("api_specs").is_none());
    assert!(body.get("gateway_trust_bundles").is_none());
}

#[test]
fn backup_extras_counts_report_what_was_carried() {
    let extras = backup_extras();
    assert_eq!(extras.api_spec_count(), 2);
    assert_eq!(extras.trust_bundle_count(), 1);
    assert!(!extras.is_empty());

    let none = BackupExtras::default();
    assert_eq!(none.api_spec_count(), 0);
    assert_eq!(none.trust_bundle_count(), 0);
    assert!(none.is_empty());
}

#[test]
fn backup_snapshot_parses_the_full_envelope() {
    let snapshot = BackupSnapshot::from_body(
        r#"{
            "version": "1",
            "ferrum_version": "2.4.0",
            "exported_at": "2026-08-24T00:00:00Z",
            "source": "database",
            "counts": {"proxies": 0},
            "proxies": [], "consumers": [], "plugin_configs": [], "upstreams": [],
            "api_specs": {"section_version": "2", "items": [{"id": "spec-a"}]},
            "gateway_trust_bundles": []
        }"#,
    )
    .unwrap();

    assert_eq!(snapshot.ferrum_version.as_deref(), Some("2.4.0"));
    assert_eq!(snapshot.source.as_deref(), Some("database"));
    assert_eq!(snapshot.extras.api_spec_count(), 1);
    // Present-but-empty is distinct from absent and must survive the round trip.
    assert_eq!(
        snapshot.extras.gateway_trust_bundles,
        Some(serde_json::json!([]))
    );
    assert!(snapshot.config.proxies.is_empty());
}

// --- Batch -------------------------------------------------------------------

/// Build resources through serde so these tests stay decoupled from the
/// (permissive, frequently extended) schema struct's field list.
fn upstream(id: &str) -> Upstream {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": "team-alpha",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream fixture")
}

fn proxy(id: &str) -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": "team-alpha",
        "listen_path": format!("/{id}"),
        "backend_host": "localhost",
        "backend_port": 8080,
    }))
    .expect("proxy fixture")
}

#[test]
fn split_batch_keeps_one_chunk_when_it_fits() {
    let batch = BatchCreate {
        upstreams: vec![upstream("u1")],
        proxies: vec![proxy("p1")],
        ..BatchCreate::default()
    };
    let chunks = split_batch(&batch, BATCH_MAX_BODY_BYTES).unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), 2);
}

#[test]
fn split_batch_preserves_dependency_order_across_chunks() {
    // A tiny budget forces one resource per chunk. Upstreams must all land
    // before the proxies that reference them, or the gateway rejects the
    // proxy with "upstream_id '…' does not exist".
    let batch = BatchCreate {
        upstreams: vec![upstream("u1"), upstream("u2")],
        proxies: vec![proxy("p1"), proxy("p2")],
        ..BatchCreate::default()
    };
    let chunks = split_batch(&batch, 600).unwrap();
    assert!(chunks.len() > 1, "expected the budget to force chunking");

    let order: Vec<&str> = chunks
        .iter()
        .flat_map(|c| {
            c.upstreams
                .iter()
                .map(|_| "upstream")
                .chain(c.proxies.iter().map(|_| "proxy"))
        })
        .collect();
    let first_proxy = order.iter().position(|k| *k == "proxy").unwrap();
    let last_upstream = order.iter().rposition(|k| *k == "upstream").unwrap();
    assert!(
        last_upstream < first_proxy,
        "upstreams must precede proxies across chunk boundaries: {order:?}"
    );
    assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), 4);
}

#[test]
fn split_batch_on_empty_input_produces_no_requests() {
    assert!(split_batch(&BatchCreate::default(), BATCH_MAX_BODY_BYTES)
        .unwrap()
        .is_empty());
}

#[test]
fn batch_counts_mirror_the_payload() {
    let batch = BatchCreate {
        upstreams: vec![upstream("u1"), upstream("u2")],
        proxies: vec![proxy("p1")],
        ..BatchCreate::default()
    };
    let counts = batch.counts();
    assert_eq!(counts.upstreams, 2);
    assert_eq!(counts.proxies, 1);
    assert_eq!(counts.total(), 3);
}

#[test]
fn batch_payload_omits_empty_sections() {
    // `BatchCreateRequest` is `additionalProperties: false` and create-only;
    // sending `version` or empty arrays is needless surface.
    let batch = BatchCreate {
        upstreams: vec![upstream("u1")],
        ..BatchCreate::default()
    };
    let json = serde_json::to_value(&batch).unwrap();
    assert!(json.get("upstreams").is_some());
    assert!(json.get("proxies").is_none());
    assert!(json.get("version").is_none());
}

// --- Health preflight --------------------------------------------------------

#[test]
fn write_block_reason_passes_a_writable_gateway() {
    let health = serde_json::from_str::<HealthStatus>(
        r#"{"status":"ok","ready":true,"mode":"database","admin_writes_enabled":true}"#,
    )
    .unwrap();
    assert!(write_block_reason(&health).is_none());
}

#[test]
fn write_block_reason_flags_read_only_mode() {
    let health = serde_json::from_str::<HealthStatus>(
        r#"{"status":"degraded","ready":true,"mode":"database","admin_writes_enabled":false}"#,
    )
    .unwrap();
    let reason = write_block_reason(&health).expect("should block");
    assert!(reason.contains("admin_writes_enabled=false"), "{reason}");
}

#[test]
fn write_block_reason_flags_modes_that_never_accept_writes() {
    for mode in ["file", "dp", "mesh", "node_agent", "FILE"] {
        let health = serde_json::from_str::<HealthStatus>(&format!(
            r#"{{"status":"ok","ready":true,"mode":"{mode}"}}"#
        ))
        .unwrap();
        assert!(
            write_block_reason(&health).is_some(),
            "{mode} mode is read-only unconditionally"
        );
    }
}

#[test]
fn write_block_reason_tolerates_a_sparse_health_body() {
    // Older builds (or an unauthenticated projection) report only status/ready.
    // Absence of the flag is not evidence of read-only mode.
    let health = serde_json::from_str::<HealthStatus>(r#"{"status":"ok","ready":true}"#).unwrap();
    assert!(write_block_reason(&health).is_none());
}
