//! Incremental apply confirms every row it overwrites against a backup read
//! after the plan (GHSA-fh5w-5x4f-86gh).
//!
//! `cmd_apply` plans from a `/backup` it read before credential allocation,
//! delivery and create journaling. An `/api-specs` import or admin edit that
//! lands in that window must not be overwritten or deleted from the stale
//! plan. Each test hands `apply_api` the plan's view and serves a different
//! confirmation `/backup`, the way a concurrent writer would leave it.

use gitforgeops::apply::{apply_api, ApplyOptions, ApplyResult};
use gitforgeops::config::env::{EnvConfig, GatewayMode};
use gitforgeops::config::schema::GatewayConfig;
use gitforgeops::diff::resource_diff::state_key;
use gitforgeops::diff::OwnershipScope;
use gitforgeops::http_client::{AdminClient, BackupExtras};
use std::collections::{BTreeMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

const NS: &str = "team-alpha";
const SPEC: &str = "concurrent-spec";
const HEALTHY: &str = r#"{"status":"ok","mode":"database","admin_writes_enabled":true}"#;
const CHANGED: &str = "changed after this run planned the write";
const SPEC_KINDS: [Kind; 3] = [Kind::Proxy, Kind::Upstream, Kind::PluginConfig];

/// `(needle, status, body, headers)`. The first route whose needle appears
/// anywhere in a request answers it; any other request gets `200 {}`.
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

fn client(url: String) -> AdminClient {
    let env = EnvConfig {
        gateway_url: Some(url),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        gateway_mode: GatewayMode::Api,
        gateway_max_retries: 0,
        ..EnvConfig::default()
    };
    AdminClient::new_scoped(&env, [NS]).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Proxy,
    Upstream,
    PluginConfig,
    Consumer,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Proxy => "Proxy",
            Kind::Upstream => "Upstream",
            Kind::PluginConfig => "PluginConfig",
            Kind::Consumer => "Consumer",
        }
    }

    fn section(self) -> &'static str {
        match self {
            Kind::Proxy => "proxies",
            Kind::Upstream => "upstreams",
            Kind::PluginConfig => "plugin_configs",
            Kind::Consumer => "consumers",
        }
    }
}

/// A one-row document. `version` sets one ordinary field, so two versions of
/// the same row differ only in content; `owner` is its `api_spec_id`.
fn document(kind: Kind, id: &str, owner: Option<&str>, version: u16) -> GatewayConfig {
    let row = match kind {
        Kind::Proxy => serde_json::json!({
            "id": id,
            "namespace": NS,
            "backend_host": "127.0.0.1",
            "backend_port": version,
            "api_spec_id": owner,
        }),
        Kind::Upstream => serde_json::json!({
            "id": id,
            "namespace": NS,
            "targets": [{"host": "10.0.0.1", "port": version}],
            "api_spec_id": owner,
        }),
        Kind::PluginConfig => serde_json::json!({
            "id": id,
            "namespace": NS,
            "plugin_name": "cors",
            "config": {"max_age": version},
            "scope": "global",
            "api_spec_id": owner,
        }),
        Kind::Consumer => serde_json::json!({
            "id": id,
            "namespace": NS,
            "username": format!("user-{version}"),
        }),
    };
    let mut document = serde_json::Map::new();
    document.insert(kind.section().to_string(), serde_json::json!([row]));
    serde_json::from_value(serde_json::Value::Object(document)).unwrap()
}

/// Proxy `p1` on `port`. With `with_plugin`, its scoped plugin `pc1` exists
/// and is attached.
fn scoped_pair(port: u16, with_plugin: bool) -> GatewayConfig {
    let (associations, plugin_configs) = if with_plugin {
        (
            serde_json::json!([{"plugin_config_id": "pc1"}]),
            serde_json::json!([{
                "id": "pc1",
                "namespace": NS,
                "plugin_name": "cors",
                "config": {},
                "scope": "proxy",
                "proxy_id": "p1",
            }]),
        )
    } else {
        (serde_json::json!([]), serde_json::json!([]))
    };
    serde_json::from_value(serde_json::json!({
        "proxies": [{
            "id": "p1",
            "namespace": NS,
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "plugins": associations,
        }],
        "plugin_configs": plugin_configs,
    }))
    .unwrap()
}

fn health() -> RecordingRoute {
    ("GET /health".into(), 200, HEALTHY.into(), vec![])
}

/// Serve `config` as every `GET /backup`: the confirmation read.
fn backup(config: &GatewayConfig) -> RecordingRoute {
    let body = serde_json::to_string(config).unwrap();
    ("GET /backup".into(), 200, body, vec![])
}

struct Run {
    result: ApplyResult,
    requests: Vec<String>,
}

impl Run {
    /// The request line of every non-GET request, in order.
    fn mutations(&self) -> Vec<String> {
        self.requests
            .iter()
            .filter(|request| !request.starts_with("GET "))
            .filter_map(|request| request.lines().next())
            .map(str::to_string)
            .collect()
    }

    fn backup_reads(&self) -> usize {
        self.requests
            .iter()
            .filter(|request| request.starts_with("GET /backup "))
            .count()
    }
}

/// Apply `desired` to one namespace planned from `planned`, against a gateway
/// answering `routes`. Shared mode fences exactly `options.managed_ledger`.
async fn apply(
    desired: &GatewayConfig,
    planned: GatewayConfig,
    routes: Vec<RecordingRoute>,
    shared: bool,
    options: ApplyOptions,
) -> Run {
    let (url, requests) = spawn_recording_gateway(routes);
    let managed: HashSet<String> = options.managed_ledger.iter().cloned().collect();
    let scope = if shared {
        OwnershipScope::Shared {
            previously_managed: &managed,
        }
    } else {
        OwnershipScope::Exclusive
    };
    let result = apply_api(
        desired,
        &client(url),
        &[NS.to_string()],
        scope,
        Some(&BTreeMap::from([(NS.to_string(), planned)])),
        Some(&BTreeMap::from([(NS.to_string(), BackupExtras::default())])),
        &options,
    )
    .await
    .expect("per-resource refusals ride on the result");
    let requests = requests.lock().unwrap().clone();
    Run { result, requests }
}

/// The run sent no write, reported exactly one refusal naming `reason`, and
/// recorded nothing for the ledger.
fn assert_refused(run: &Run, reason: &str, context: &str) {
    assert_eq!(run.mutations(), Vec::<String>::new(), "{context}");
    let errors = &run.result.errors;
    assert_eq!(errors.len(), 1, "{context}: {errors:?}");
    assert!(errors[0].contains(reason), "{context}: {errors:?}");
    assert!(run.result.applied_incremental.is_empty(), "{context}");
    assert!(run.result.fatal_error.is_none(), "{context}");
}

#[tokio::test]
async fn a_row_an_api_spec_claimed_after_the_plan_is_never_overwritten() {
    let claimed_by = format!("became owned by API spec `{SPEC}`");
    for kind in SPEC_KINDS {
        for action in ["modify", "delete", "pending-create assertion"] {
            for shared in [false, true] {
                let context = format!("{kind:?} {action} shared={shared}");
                let planned = document(kind, "r1", None, 1);
                let key = state_key(NS, kind.name(), "r1");
                let mut options = ApplyOptions::default();
                if shared {
                    options.managed_ledger.insert(key.clone());
                }
                let desired = match action {
                    "modify" => document(kind, "r1", None, 2),
                    "delete" => GatewayConfig::default(),
                    _ => {
                        options.pending_create_assertions.insert(key);
                        planned.clone()
                    }
                };
                // Same content, now tagged by a spec import.
                let claimed = document(kind, "r1", Some(SPEC), 1);
                let routes = vec![health(), backup(&claimed)];

                let run = apply(&desired, planned, routes, shared, options).await;

                assert_refused(&run, &claimed_by, &context);
                assert_eq!(run.backup_reads(), 1, "{context}");
            }
        }
    }
}

#[tokio::test]
async fn a_row_edited_after_the_plan_is_not_overwritten() {
    for kind in [
        Kind::Proxy,
        Kind::Upstream,
        Kind::PluginConfig,
        Kind::Consumer,
    ] {
        for action in ["modify", "delete"] {
            let context = format!("{kind:?} {action}");
            let planned = document(kind, "r1", None, 1);
            let desired = if action == "modify" {
                document(kind, "r1", None, 2)
            } else {
                GatewayConfig::default()
            };
            let edited = document(kind, "r1", None, 3);
            let routes = vec![health(), backup(&edited)];

            let run = apply(&desired, planned, routes, false, Default::default()).await;

            assert_refused(&run, CHANGED, &context);
        }
    }
}

#[tokio::test]
async fn a_refused_update_defers_the_namespace_deletes() {
    let mut planned = document(Kind::Upstream, "edited", None, 1);
    planned
        .upstreams
        .extend(document(Kind::Upstream, "pruned", None, 1).upstreams);
    let desired = document(Kind::Upstream, "edited", None, 2);
    let mut concurrent = document(Kind::Upstream, "edited", None, 3);
    concurrent
        .upstreams
        .extend(document(Kind::Upstream, "pruned", None, 1).upstreams);
    let routes = vec![health(), backup(&concurrent)];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_refused(&run, CHANGED, "refused update");
    assert!(run.result.errors[0].contains("Upstream edited update"));
    assert_eq!(run.result.deletes_deferred, 1);
}

#[tokio::test]
async fn an_unchanged_confirmation_lets_every_planned_write_through() {
    let mut planned = document(Kind::Proxy, "p1", None, 1);
    planned.upstreams = document(Kind::Upstream, "stale-upstream", None, 1).upstreams;
    let desired = document(Kind::Proxy, "p1", None, 2);
    let routes = vec![health(), backup(&planned)];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
    assert_eq!(
        run.mutations(),
        [
            "PUT /proxies/p1 HTTP/1.1",
            "DELETE /upstreams/stale-upstream HTTP/1.1",
        ]
    );
    assert_eq!(run.result.updated, 1);
    assert_eq!(run.result.deleted, 1);
    // One confirmation read serves every overwrite in the namespace.
    assert_eq!(run.backup_reads(), 1);
}

#[tokio::test]
async fn a_row_already_gone_is_left_to_the_gateway() {
    // Nothing holds the id any more, so nothing can be overwritten: the DELETE
    // goes out and the gateway's 404 (here a 200) answers for itself.
    let planned = document(Kind::Upstream, "u1", None, 1);
    let routes = vec![health(), backup(&GatewayConfig::default())];

    let run = apply(
        &GatewayConfig::default(),
        planned,
        routes,
        false,
        Default::default(),
    )
    .await;

    assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
    assert_eq!(run.mutations(), ["DELETE /upstreams/u1 HTTP/1.1"]);
}

#[tokio::test]
async fn a_cached_confirmation_stops_the_run_before_any_overwrite() {
    let planned = document(Kind::Upstream, "u1", None, 1);
    let desired = document(Kind::Upstream, "u1", None, 2);
    let body = serde_json::to_string(&planned).unwrap();
    let cached: RecordingRoute = (
        "GET /backup".into(),
        200,
        body,
        vec![("X-Data-Source".into(), "cached".into())],
    );

    let routes = vec![health(), cached];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_eq!(run.mutations(), Vec::<String>::new());
    let fatal = run.result.fatal_error.expect("cached view is fatal");
    assert!(fatal.contains("X-Data-Source: cached"), "{fatal}");
}

#[tokio::test]
async fn a_failed_confirmation_read_refuses_the_overwrite_and_defers_deletes() {
    let mut planned = document(Kind::Upstream, "u1", None, 1);
    planned
        .upstreams
        .extend(document(Kind::Upstream, "u2", None, 1).upstreams);
    let desired = document(Kind::Upstream, "u1", None, 2);
    let failed: RecordingRoute = (
        "GET /backup".into(),
        500,
        r#"{"error":"boom"}"#.into(),
        vec![],
    );
    let routes = vec![health(), failed];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_refused(&run, "confirmation read", "failed read");
    assert!(run.result.errors[0].contains("Upstream u1 update"));
    assert_eq!(run.result.deletes_deferred, 1);
}

#[tokio::test]
async fn a_pure_add_namespace_needs_no_confirmation_read() {
    // `POST /batch` is create-only: an id taken since the plan is refused by
    // the gateway itself, so there is nothing to confirm.
    let desired = document(Kind::Upstream, "u1", None, 1);
    let ack = r#"{"created":{"proxies":0,"consumers":0,"plugin_configs":0,"upstreams":1}}"#;
    let batch: RecordingRoute = ("POST /batch".into(), 200, ack.into(), vec![]);
    let routes = vec![health(), batch];

    let run = apply(
        &desired,
        GatewayConfig::default(),
        routes,
        false,
        Default::default(),
    )
    .await;

    assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
    assert_eq!(run.mutations(), ["POST /batch HTTP/1.1"]);
    assert_eq!(run.backup_reads(), 0);
}

#[tokio::test]
async fn an_ambiguous_create_never_claims_a_row_an_api_spec_now_owns() {
    // The readback finds the declared content, but under a spec's tag. Before
    // the fix the subset match called that our row and PUT over it.
    let desired = document(Kind::Upstream, "u1", None, 1);
    let spec_row = document(Kind::Upstream, "u1", Some(SPEC), 1);
    for per_resource in [false, true] {
        let mut routes = vec![health(), backup(&spec_row)];
        let mut expected = vec!["POST /batch HTTP/1.1"];
        if per_resource {
            routes.push(("POST /batch".into(), 501, "{}".into(), vec![]));
            routes.push(("POST /upstreams".into(), 502, "{}".into(), vec![]));
            expected.push("POST /upstreams HTTP/1.1");
        } else {
            routes.push(("POST /batch".into(), 503, "{}".into(), vec![]));
        }

        let run = apply(
            &desired,
            GatewayConfig::default(),
            routes,
            false,
            Default::default(),
        )
        .await;

        assert_eq!(run.mutations(), expected, "per_resource={per_resource}");
        assert!(run.result.applied_incremental.is_empty());
        assert!(run.result.fatal_error.is_some(), "{:?}", run.result);
    }
}

#[tokio::test]
async fn a_post_plugin_proxy_update_is_confirmed_outside_its_associations() {
    // Creating `pc1` makes the gateway attach it to `p1`, so the post-plugin
    // snapshot's associations legitimately differ from the plan. Any other
    // field that moved was somebody else's edit.
    for (live_port, concurrent) in [(1, false), (7, true)] {
        let desired = scoped_pair(2, true);
        let routes = vec![health(), backup(&scoped_pair(live_port, true))];

        let run = apply(
            &desired,
            scoped_pair(1, false),
            routes,
            false,
            Default::default(),
        )
        .await;

        let mut expected = vec!["POST /plugins/config HTTP/1.1"];
        if concurrent {
            let errors = &run.result.errors;
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert!(errors[0].contains("Proxy p1 update"), "{errors:?}");
            assert!(errors[0].contains(CHANGED), "{errors:?}");
        } else {
            expected.push("PUT /proxies/p1 HTTP/1.1");
            assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
        }
        assert_eq!(run.mutations(), expected, "concurrent={concurrent}");
        assert_eq!(run.backup_reads(), 1, "concurrent={concurrent}");
    }
}

#[tokio::test]
async fn a_confirmed_spec_deletion_still_requires_the_same_owner() {
    let planned = document(Kind::Upstream, "u1", Some("spec-a"), 1);
    for (owner, deleted) in [("spec-a", true), ("spec-b", false)] {
        let live = document(Kind::Upstream, "u1", Some(owner), 1);
        let options = ApplyOptions {
            confirm_api_spec_deletion: true,
            ..Default::default()
        };

        let run = apply(
            &GatewayConfig::default(),
            planned.clone(),
            vec![health(), backup(&live)],
            false,
            options,
        )
        .await;

        if deleted {
            assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
            assert_eq!(run.mutations(), ["DELETE /upstreams/u1 HTTP/1.1"]);
        } else {
            assert_refused(&run, "became owned by API spec `spec-b`", owner);
        }
    }
}
