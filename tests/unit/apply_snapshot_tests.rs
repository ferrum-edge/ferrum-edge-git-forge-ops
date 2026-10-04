//! Incremental apply sends every overwrite conditionally on the row the plan
//! judged (GHSA-fh5w-5x4f-86gh).
//!
//! `cmd_apply` plans from a `/backup` it read before credential allocation,
//! delivery and create journaling. An `/api-specs` import or admin edit that
//! lands in that window must not be overwritten or deleted from the stale
//! plan. Each test hands `apply_api` the plan's view and serves the rows the
//! way a concurrent writer would leave them: on `GET /<kind>/{id}` with an
//! `ETag`; consumers use complete `/consumers/{id}/verification` evidence.

use gitforgeops::apply::{apply_api, ApplyOptions, ApplyResult};
use gitforgeops::config::env::{EnvConfig, GatewayMode};
use gitforgeops::config::schema::{BackendScheme, GatewayConfig};
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
const WITHHELD: &str = "so the namespace's remaining writes were withheld";
const TAG: &str = "\"planned-tag\"";
const SPEC_KINDS: [Kind; 3] = [Kind::Proxy, Kind::Upstream, Kind::PluginConfig];
const ALL_KINDS: [Kind; 4] = [
    Kind::Proxy,
    Kind::Upstream,
    Kind::PluginConfig,
    Kind::Consumer,
];

/// `(needle, status, body, headers)`. The first route whose needle appears
/// anywhere in a request answers it; any other request gets `200 {}`. A needle
/// starting with [`ONCE`] answers only the first request it matches, so a
/// later route with the same needle answers the rest.
type RecordingRoute = (String, u16, String, Vec<(String, String)>);

/// Prefix for a route that answers one request only.
const ONCE: &str = "once:";

fn spawn_recording_gateway(routes: Vec<RecordingRoute>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    let spent = Arc::new(Mutex::new(HashSet::new()));
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = routes.clone();
            let requests = Arc::clone(&thread_requests);
            let spent = Arc::clone(&spent);
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                requests.lock().unwrap().push(request.clone());
                let route = route_for(&routes, &mut spent.lock().unwrap(), &request);
                let (status, body, headers) = route
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

/// The route that answers `request`. See [`RecordingRoute`].
fn route_for<'r>(
    routes: &'r [RecordingRoute],
    spent: &mut HashSet<usize>,
    request: &str,
) -> Option<&'r RecordingRoute> {
    for (index, route) in routes.iter().enumerate() {
        let (needle, once) = match route.0.strip_prefix(ONCE) {
            Some(needle) => (needle, true),
            None => (route.0.as_str(), false),
        };
        if !request.contains(needle) || (once && spent.contains(&index)) {
            continue;
        }
        if once {
            spent.insert(index);
        }
        return Some(route);
    }
    None
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
    client_with_retries(url, 0)
}

fn client_with_retries(url: String, gateway_max_retries: u32) -> AdminClient {
    let env = EnvConfig {
        gateway_url: Some(url),
        admin_jwt_secret: Some("test-secret-must-be-32-chars-long".to_string()),
        gateway_mode: GatewayMode::Api,
        gateway_max_retries,
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

    fn path(self) -> &'static str {
        match self {
            Kind::Proxy => "/proxies",
            Kind::Upstream => "/upstreams",
            Kind::PluginConfig => "/plugins/config",
            Kind::Consumer => "/consumers",
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

/// Add a typed optional field the desired row omitted.
fn with_optional_addition(kind: Kind, config: &GatewayConfig) -> GatewayConfig {
    let mut config = config.clone();
    match kind {
        Kind::Proxy => config.proxies[0].dns_override = Some("10.0.0.42".to_string()),
        Kind::Upstream => {
            config.upstreams[0].backend_tls_sni = Some("concurrent.example".to_string());
        }
        Kind::PluginConfig => config.plugin_configs[0].priority_override = Some(17),
        Kind::Consumer => config.consumers[0].custom_id = Some("external-id".to_string()),
    }
    config
}

/// One upstream per `(id, version)`, as [`document`] builds it.
fn upstreams(rows: &[(&str, u16)]) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    for (id, version) in rows {
        config
            .upstreams
            .extend(document(Kind::Upstream, id, None, *version).upstreams);
    }
    config
}

/// Consumer `c1`, whose keyauth key is `key`.
fn keyed_consumer(username: &str, key: &str) -> GatewayConfig {
    serde_json::from_value(serde_json::json!({
        "consumers": [{
            "id": "c1",
            "namespace": NS,
            "username": username,
            "credentials": {"keyauth": [{"key": key}]},
        }]
    }))
    .unwrap()
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

/// Serve `config` as every `GET /backup`.
fn backup(config: &GatewayConfig) -> RecordingRoute {
    let body = serde_json::to_string(config).unwrap();
    ("GET /backup".into(), 200, body, vec![])
}

/// The row `id` of `config` as JSON.
fn row(kind: Kind, id: &str, config: &GatewayConfig) -> serde_json::Value {
    let document = serde_json::to_value(config).unwrap();
    document[kind.section()]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap()
        .clone()
}

/// Serve `body` on `GET /<kind>/{id}` with the given response headers.
fn read_route(kind: Kind, id: &str, body: String, headers: &[(&str, &str)]) -> RecordingRoute {
    let headers = headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let suffix = if matches!(kind, Kind::Consumer) {
        "/verification"
    } else {
        ""
    };
    let mut headers: Vec<(String, String)> = headers;
    if matches!(kind, Kind::Consumer) {
        headers.push(("Cache-Control".to_string(), "no-store".to_string()));
    }
    (format!("GET {}/{id}{suffix} ", kind.path()), 200, body, headers)
}

/// Serve the row `id` of `config` on `GET /<kind>/{id}` with `etag`, the way
/// Ferrum Edge answers a single-resource read from its database.
fn tagged(kind: Kind, id: &str, config: &GatewayConfig, etag: &str) -> RecordingRoute {
    let body = row(kind, id, config).to_string();
    read_route(kind, id, body, &[("ETag", etag)])
}

/// `GET /<kind>/{id}` answering 404.
fn missing(kind: Kind, id: &str) -> RecordingRoute {
    let body = r#"{"error":"not found"}"#.to_string();
    let suffix = if matches!(kind, Kind::Consumer) {
        "/verification"
    } else {
        ""
    };
    (format!("GET {}/{id}{suffix} ", kind.path()), 404, body, vec![])
}

/// Every route that lets `id`'s row read as `config`: consumers also need the
/// backup that carries their credentials.
fn live(kind: Kind, id: &str, config: &GatewayConfig, etag: &str) -> Vec<RecordingRoute> {
    let mut routes = vec![tagged(kind, id, config, etag)];
    if matches!(kind, Kind::Consumer) {
        routes.push(backup(config));
    }
    routes
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

    /// The first request whose line starts with `prefix`.
    fn request(&self, prefix: &str) -> &str {
        self.requests
            .iter()
            .find(|request| request.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` request"))
    }

    fn position(&self, prefix: &str) -> usize {
        self.requests
            .iter()
            .position(|request| request.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` request"))
    }

    fn count(&self, prefix: &str) -> usize {
        self.requests
            .iter()
            .filter(|request| request.starts_with(prefix))
            .count()
    }

    fn backup_reads(&self) -> usize {
        self.count("GET /backup ")
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
    let (url, requests) = spawn_recording_gateway(routes.clone());
    let managed: HashSet<String> = options.managed_ledger.iter().cloned().collect();
    let scope = if shared {
        OwnershipScope::Shared {
            previously_managed: &managed,
        }
    } else {
        OwnershipScope::Exclusive
    };
    let mut extras =
        super::conditional_fixtures::planned_extras(&planned, NS, BackupExtras::default());
    for evidence in extras.consumer_evidence.values_mut() {
        let id = evidence.row["id"].as_str().unwrap();
        let route = format!("GET /consumers/{id}/verification ");
        let tag = routes
            .iter()
            .find(|(needle, _, _, _)| needle.ends_with(&route))
            .and_then(|(_, _, _, headers)| {
                headers.iter().find(|(key, _)| key.eq_ignore_ascii_case("etag"))
            })
            .map(|(_, tag)| tag.as_str())
            .filter(|tag| tag.starts_with('"'))
            .unwrap_or(TAG);
        *evidence = gitforgeops::http_client::conditional::ConsumerEvidence::from_response(
            &evidence.row.to_string(),
            NS,
            id,
            Some(tag),
            None,
            Some("no-store"),
        )
        .unwrap();
    }
    let result = apply_api(
        desired,
        &client(url),
        &[NS.to_string()],
        scope,
        Some(&BTreeMap::from([(NS.to_string(), planned)])),
        Some(&BTreeMap::from([(NS.to_string(), extras)])),
        &options,
    )
    .await
    .expect("per-resource refusals ride on the result");
    let requests = requests.lock().unwrap().clone();
    Run { result, requests }
}

/// [`apply`] in exclusive mode with default options.
async fn apply_exclusive(
    desired: &GatewayConfig,
    planned: GatewayConfig,
    routes: Vec<RecordingRoute>,
) -> Run {
    apply(desired, planned, routes, false, Default::default()).await
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

/// `errors[index]` names `what` (`<Kind> <id> <verb>`) for this test's
/// namespace, with the `[<namespace>] ` prefix `apply_api` adds.
fn assert_starts(errors: &[String], index: usize, what: &str) {
    let expected = format!("[{NS}] {what}");
    assert!(errors[index].starts_with(&expected), "{errors:?}");
}

/// `(desired, options)` for one overwrite of `planned`'s row `r1`.
fn overwrite(kind: Kind, action: &str, planned: &GatewayConfig) -> (GatewayConfig, ApplyOptions) {
    let mut options = ApplyOptions::default();
    let desired = match action {
        "modify" => document(kind, "r1", None, 2),
        "delete" => GatewayConfig::default(),
        _ => {
            let key = state_key(NS, kind.name(), "r1");
            options.pending_create_assertions.insert(key);
            planned.clone()
        }
    };
    (desired, options)
}

#[tokio::test]
async fn a_row_an_api_spec_claimed_after_the_plan_is_never_overwritten() {
    let claimed_by = format!("became owned by API spec `{SPEC}`");
    for kind in SPEC_KINDS {
        for action in ["modify", "delete", "pending-create assertion"] {
            for shared in [false, true] {
                let context = format!("{kind:?} {action} shared={shared}");
                let planned = document(kind, "r1", None, 1);
                let (desired, mut options) = overwrite(kind, action, &planned);
                if shared {
                    let key = state_key(NS, kind.name(), "r1");
                    options.managed_ledger.insert(key);
                }
                // Same content, now tagged by a spec import.
                let claimed = document(kind, "r1", Some(SPEC), 1);
                let routes = vec![health(), tagged(kind, "r1", &claimed, TAG)];

                let run = apply(&desired, planned, routes, shared, options).await;

                assert_refused(&run, &claimed_by, &context);
                let read = format!("GET {}/r1 ", kind.path());
                assert_eq!(run.count(&read), 1, "{context}");
                assert_eq!(run.backup_reads(), 0, "{context}");
            }
        }
    }
}

#[tokio::test]
async fn a_row_edited_after_the_plan_is_not_overwritten() {
    for kind in ALL_KINDS {
        for action in ["modify", "delete", "pending-create assertion"] {
            let context = format!("{kind:?} {action}");
            let planned = document(kind, "r1", None, 1);
            let (desired, options) = overwrite(kind, action, &planned);
            let edited = document(kind, "r1", None, 3);
            let mut routes = vec![health()];
            routes.extend(live(kind, "r1", &edited, TAG));

            let run = apply(&desired, planned, routes, false, options).await;

            assert_refused(&run, CHANGED, &context);
        }
    }
}

#[tokio::test]
async fn every_overwrite_is_sent_with_the_etag_its_read_returned() {
    for kind in ALL_KINDS {
        for action in ["modify", "delete", "pending-create assertion"] {
            let context = format!("{kind:?} {action}");
            let planned = document(kind, "r1", None, 1);
            let (desired, options) = overwrite(kind, action, &planned);
            let etag = format!("\"{}-r1-v1\"", kind.name());
            let mut routes = vec![health()];
            routes.extend(live(kind, "r1", &planned, &etag));

            let run = apply(&desired, planned, routes, false, options).await;

            assert!(run.result.errors.is_empty(), "{context}: {:?}", run.result);
            assert!(run.result.fatal_error.is_none(), "{context}");
            let method = if action == "delete" { "DELETE" } else { "PUT" };
            let mutations = run.mutations();
            assert_eq!(mutations.len(), 1, "{context}: {mutations:?}");
            let write = format!("{method} {}/r1", kind.path());
            assert!(mutations[0].starts_with(&write), "{mutations:?}");
            let sent = run.request(&write);
            assert!(
                sent.contains(&format!("if-match: {etag}\r\n")),
                "{context}: {sent}"
            );
            assert_eq!(run.result.applied_incremental.len(), 1, "{context}");
            assert_eq!(run.backup_reads(), 0, "{context}");
        }
    }
}

#[tokio::test]
async fn a_412_refuses_the_write_and_withholds_the_rest_of_the_namespace() {
    // u1 and u2 are updated, u9 created and u3 pruned. The gateway refuses the
    // first conditional write because the row changed after it was read: the
    // plan is stale, so nothing else in the namespace is sent.
    let planned = upstreams(&[("u1", 1), ("u2", 1), ("u3", 1)]);
    let desired = upstreams(&[("u1", 2), ("u2", 2), ("u9", 1)]);
    let refused: RecordingRoute = (
        "PUT /upstreams/u1".into(),
        412,
        r#"{"error":"Upstream 'u1' has changed since its If-Match tag was issued"}"#.into(),
        vec![],
    );
    let routes = vec![
        health(),
        tagged(Kind::Upstream, "u1", &planned, TAG),
        refused,
    ];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_eq!(run.mutations(), ["PUT /upstreams/u1 HTTP/1.1"]);
    let sent = run.request("PUT /upstreams/u1");
    assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
    // Nothing after the refusal was even read.
    assert_eq!(run.count("GET /upstreams/u2 "), 0);
    assert_eq!(run.count("GET /upstreams/u3 "), 0);
    let errors = &run.result.errors;
    assert_eq!(errors.len(), 3, "{errors:?}");
    assert_starts(errors, 0, "Upstream u1 update");
    assert!(errors[0].contains("412 Precondition Failed"), "{errors:?}");
    assert_starts(errors, 1, "Upstream u2 update");
    assert_starts(errors, 2, "Upstream u9 create");
    for withheld in &errors[1..] {
        assert!(withheld.contains("Upstream `u1`"), "{errors:?}");
        assert!(withheld.contains(WITHHELD), "{errors:?}");
    }
    assert_eq!(run.result.deletes_deferred, 1);
    assert!(run.result.applied_incremental.is_empty());
    assert!(run.result.fatal_error.is_none());
}

#[tokio::test]
async fn a_412_on_a_delete_defers_the_namespace_remaining_deletes() {
    let planned = upstreams(&[("u1", 1), ("u2", 1)]);
    let refused: RecordingRoute = ("DELETE /upstreams/u1".into(), 412, "{}".into(), vec![]);
    let routes = vec![
        health(),
        tagged(Kind::Upstream, "u1", &planned, TAG),
        refused,
    ];

    let run = apply(
        &GatewayConfig::default(),
        planned,
        routes,
        false,
        Default::default(),
    )
    .await;

    assert_eq!(run.mutations(), ["DELETE /upstreams/u1 HTTP/1.1"]);
    assert_eq!(run.count("GET /upstreams/u2 "), 0);
    let errors = &run.result.errors;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_starts(errors, 0, "Upstream u1 delete");
    assert!(errors[0].contains("412 Precondition Failed"), "{errors:?}");
    assert_eq!(run.result.deleted, 0);
    assert_eq!(run.result.deletes_deferred, 1);
}

#[tokio::test]
async fn a_stale_read_withholds_the_rest_of_the_namespace() {
    // The refusal does not need the gateway's 412: a read that disagrees with
    // the plan proves it stale just the same.
    let planned = upstreams(&[("edited", 1), ("next", 1), ("pruned", 1)]);
    let desired = upstreams(&[("edited", 2), ("next", 2)]);
    let live = upstreams(&[("edited", 3)]);
    let routes = vec![health(), tagged(Kind::Upstream, "edited", &live, TAG)];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_eq!(run.mutations(), Vec::<String>::new());
    assert_eq!(run.count("GET /upstreams/next "), 0);
    let errors = &run.result.errors;
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_starts(errors, 0, "Upstream edited");
    assert!(errors[0].contains(CHANGED), "{errors:?}");
    assert_starts(errors, 1, "Upstream next update");
    assert!(errors[1].contains(WITHHELD), "{errors:?}");
    assert_eq!(run.result.deletes_deferred, 1);
}

#[tokio::test]
async fn a_consumer_whose_credentials_changed_after_the_plan_is_not_overwritten() {
    // Complete verification sees the rotated key directly, without an archival backup.
    let planned = keyed_consumer("user-1", "planned-key-value");
    let desired = keyed_consumer("user-2", "planned-key-value");
    for (backup_key, refused) in [("rotated-key-value", true), ("planned-key-value", false)] {
        let routes = vec![
            health(),
            tagged(Kind::Consumer, "c1", &keyed_consumer("user-1", backup_key), TAG),
        ];

        let run = apply_exclusive(&desired, planned.clone(), routes).await;

        assert_eq!(run.count("GET /consumers/c1/verification "), 1);
        assert_eq!(run.backup_reads(), 0);
        if refused {
            assert_refused(&run, CHANGED, "rotated credential");
        } else {
            assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
            assert_eq!(run.mutations(), ["PUT /consumers/c1 HTTP/1.1"]);
            let sent = run.request("PUT /consumers/c1");
            assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
        }
    }
}

#[tokio::test]
async fn a_row_already_gone_is_neither_deleted_again_nor_recreated() {
    let planned = document(Kind::Upstream, "u1", None, 1);
    for (desired, gone_is_fine) in [
        (GatewayConfig::default(), true),
        (document(Kind::Upstream, "u1", None, 2), false),
    ] {
        let routes = vec![health(), missing(Kind::Upstream, "u1")];

        let run = apply_exclusive(&desired, planned.clone(), routes).await;

        assert_eq!(run.mutations(), Vec::<String>::new());
        if gone_is_fine {
            // A DELETE now could only remove a row someone recreated since.
            assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
            assert_eq!(run.result.deleted, 1);
            assert_eq!(run.result.deletes_missing, 1);
        } else {
            // A PUT now would recreate a row someone deleted.
            assert_refused(&run, "no longer exists", "gone before its update");
        }
    }
}

#[tokio::test]
async fn a_cached_read_stops_the_run_before_any_overwrite() {
    let planned = document(Kind::Upstream, "u1", None, 1);
    let desired = document(Kind::Upstream, "u1", None, 2);
    let body = row(Kind::Upstream, "u1", &planned).to_string();
    let cached = read_route(
        Kind::Upstream,
        "u1",
        body,
        &[("X-Data-Source", "cached"), ("ETag", TAG)],
    );

    let run = apply(
        &desired,
        planned,
        vec![health(), cached],
        false,
        Default::default(),
    )
    .await;

    assert_eq!(run.mutations(), Vec::<String>::new());
    let fatal = run.result.fatal_error.expect("cached view is fatal");
    assert!(fatal.contains("X-Data-Source: cached"), "{fatal}");

    // Credential-complete verification must never accept a cached response.
    let planned = document(Kind::Consumer, "c1", None, 1);
    let desired = document(Kind::Consumer, "c1", None, 2);
    let cached = read_route(
        Kind::Consumer,
        "c1",
        row(Kind::Consumer, "c1", &planned).to_string(),
        &[("X-Data-Source", "cached"), ("ETag", TAG)],
    );
    let routes = vec![health(), cached];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_eq!(run.mutations(), Vec::<String>::new());
    let fatal = run.result.fatal_error.expect("cached backup is fatal");
    assert!(fatal.contains("X-Data-Source: cached"), "{fatal}");
}

#[tokio::test]
async fn a_read_without_a_strong_etag_stops_the_run() {
    // An older gateway issues no tag and would ignore `If-Match`, so nothing
    // may be written on the strength of its read.
    let planned = document(Kind::Upstream, "u1", None, 1);
    let desired = document(Kind::Upstream, "u1", None, 2);
    for etag in [None, Some("W/\"weak\""), Some("unquoted")] {
        let body = row(Kind::Upstream, "u1", &planned).to_string();
        let headers: Vec<(&str, &str)> = etag.map(|etag| ("ETag", etag)).into_iter().collect();
        let routes = vec![health(), read_route(Kind::Upstream, "u1", body, &headers)];

        let run = apply_exclusive(&desired, planned.clone(), routes).await;

        assert_eq!(run.mutations(), Vec::<String>::new(), "{etag:?}");
        let fatal = run.result.fatal_error.expect("no conditional write");
        assert!(fatal.contains("no strong ETag"), "{etag:?}: {fatal}");
    }
}

#[tokio::test]
async fn a_failed_read_refuses_the_overwrite_and_defers_deletes() {
    let planned = upstreams(&[("u1", 1), ("u2", 1)]);
    let desired = upstreams(&[("u1", 2)]);
    let failed: RecordingRoute = (
        "GET /upstreams/u1 ".into(),
        500,
        r#"{"error":"boom"}"#.into(),
        vec![],
    );
    let routes = vec![health(), failed];

    let run = apply(&desired, planned, routes, false, Default::default()).await;

    assert_refused(&run, "boom", "failed read");
    assert_starts(&run.result.errors, 0, "Upstream u1 update");
    assert_eq!(run.count("GET /upstreams/u2 "), 0);
    assert_eq!(run.result.deletes_deferred, 1);

    // Audit-admission or verification failure must stop the conditional operation.
    let planned = document(Kind::Consumer, "c1", None, 1);
    let desired = document(Kind::Consumer, "c1", None, 2);
    let failed: RecordingRoute = (
        "GET /consumers/c1/verification ".into(),
        503,
        r#"{"error":"private diagnostic withheld"}"#.into(),
        vec![],
    );
    let run = apply(&desired, planned, vec![health(), failed], false, Default::default()).await;
    assert!(run.result.fatal_error.is_some());
    assert!(run.mutations().is_empty());
}

#[tokio::test]
async fn an_update_never_resets_a_nested_field_the_plan_did_not_see() {
    let planned = document(Kind::Upstream, "u1", None, 1);
    let mut body = row(Kind::Upstream, "u1", &planned);
    body["targets"][0]["future_target_option"] = serde_json::json!(true);
    for (desired, refused) in [
        (document(Kind::Upstream, "u1", None, 2), true),
        // A delete rewrites nothing, so the field does not matter.
        (GatewayConfig::default(), false),
    ] {
        let read = read_route(Kind::Upstream, "u1", body.to_string(), &[("ETag", TAG)]);

        let run = apply(
            &desired,
            planned.clone(),
            vec![health(), read],
            false,
            Default::default(),
        )
        .await;

        if refused {
            assert_refused(&run, "future_target_option", "nested field");
        } else {
            assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
            assert_eq!(run.mutations(), ["DELETE /upstreams/u1 HTTP/1.1"]);
        }
    }
}

#[tokio::test]
async fn a_pure_add_namespace_needs_no_read() {
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
    assert_eq!(run.count("GET /upstreams/"), 0);
}

#[tokio::test]
async fn an_ambiguous_create_never_claims_a_row_an_api_spec_now_owns() {
    // The readback finds the declared content, but under a spec's tag. Before
    // the fix the subset match called that our row and PUT over it.
    let desired = document(Kind::Upstream, "u1", None, 1);
    let spec_row = document(Kind::Upstream, "u1", Some(SPEC), 1);
    for per_resource in [false, true] {
        let mut routes = vec![
            health(),
            backup(&spec_row),
            tagged(Kind::Upstream, "u1", &spec_row, TAG),
        ];
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
async fn an_ambiguous_create_claims_its_row_only_with_if_match_on_a_matching_read() {
    let desired = document(Kind::Upstream, "u1", None, 1);
    for (read_port, claimed) in [(1, true), (9, false)] {
        let read = document(Kind::Upstream, "u1", None, read_port);
        let routes = vec![
            health(),
            ("POST /batch".into(), 501, "{}".into(), vec![]),
            ("POST /upstreams".into(), 502, "{}".into(), vec![]),
            tagged(Kind::Upstream, "u1", &read, TAG),
            backup(&desired),
        ];

        let run = apply(
            &desired,
            GatewayConfig::default(),
            routes,
            false,
            Default::default(),
        )
        .await;

        let context = format!("read_port={read_port}");
        // The tagged read precedes the backup that proves the row exact.
        assert!(
            run.position("GET /upstreams/u1 ") < run.position("GET /backup "),
            "{context}"
        );
        if claimed {
            assert!(run.result.fatal_error.is_none(), "{context}");
            let mutations = run.mutations();
            assert_eq!(mutations.last().unwrap(), "PUT /upstreams/u1 HTTP/1.1");
            let sent = run.request("PUT /upstreams/u1");
            assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
            assert_eq!(run.result.created, 1, "{context}");
        } else {
            assert_eq!(run.count("PUT /upstreams/u1"), 0, "{context}");
            let fatal = run
                .result
                .fatal_error
                .expect("an unproven claim stops the run");
            assert!(fatal.contains("did not show that row"), "{fatal}");
        }
    }
}

#[tokio::test]
async fn ambiguous_batch_recovery_refuses_optional_fields_added_after_verification() {
    for (kind, nested) in [
        (Kind::Proxy, false),
        (Kind::Upstream, false),
        (Kind::PluginConfig, false),
        (Kind::PluginConfig, true),
    ] {
        let desired = document(kind, "r1", None, 1);
        let edited = if nested {
            let mut edited = desired.clone();
            edited.plugin_configs[0].config["allow_credentials"] = serde_json::json!(true);
            edited
        } else {
            with_optional_addition(kind, &desired)
        };
        let routes = vec![
            health(),
            ("POST /batch".into(), 503, "{}".into(), vec![]),
            backup(&desired),
            tagged(kind, "r1", &edited, "\"concurrent-tag\""),
        ];

        let run = apply_exclusive(&desired, GatewayConfig::default(), routes).await;

        let context = format!("{kind:?} nested={nested}");
        assert_eq!(run.mutations(), ["POST /batch HTTP/1.1"], "{context}");
        let read = format!("GET {}/r1 ", kind.path());
        assert!(
            run.position("GET /backup ") < run.position(&read),
            "{context}"
        );
        assert_eq!(run.result.created, 0, "{context}");
        assert!(run.result.applied_incremental.is_empty(), "{context}");
        assert_eq!(run.result.errors.len(), 1, "{context}: {:?}", run.result);
        assert!(
            run.result.errors[0].contains("did not show the exact row"),
            "{context}: {:?}",
            run.result
        );
    }
}

#[tokio::test]
async fn ambiguous_create_recovery_preserves_the_complete_verified_row() {
    for kind in ALL_KINDS {
        for per_resource in [false, true] {
            let mut desired = document(kind, "r1", None, 1);
            if matches!(kind, Kind::Consumer) {
                desired.consumers[0].credentials.insert(
                    "keyauth".to_string(),
                    serde_json::json!([{"key": "ambiguous-test-key"}]),
                );
            }
            let mut verified = with_optional_addition(kind, &desired);
            if matches!(kind, Kind::Proxy) {
                // This is the gateway's documented default for an omitted
                // HTTP backend scheme, not a field to erase during recovery.
                verified.proxies[0].backend_scheme = Some(BackendScheme::Https);
            }
            let mut read = row(kind, "r1", &verified);
            if matches!(kind, Kind::Proxy) {
                // A legacy stored row may omit the scheme that backup
                // normalizes. Only this documented default may compare equal.
                read.as_object_mut().unwrap().remove("backend_scheme");
            }
            if matches!(kind, Kind::Consumer) {
                read["credentials"] = serde_json::json!({"keyauth": [{"key": "***"}]});
            }
            let mut routes = vec![
                health(),
                backup(&verified),
                read_route(kind, "r1", read.to_string(), &[("ETag", TAG)]),
            ];
            if per_resource {
                routes.push(("POST /batch".into(), 501, "{}".into(), vec![]));
                let post = format!("POST {} ", kind.path());
                routes.push((post, 502, "{}".into(), vec![]));
            } else {
                routes.push(("POST /batch".into(), 503, "{}".into(), vec![]));
            }

            let run = apply_exclusive(&desired, GatewayConfig::default(), routes).await;

            let context = format!("{kind:?} per_resource={per_resource}");
            assert!(run.result.errors.is_empty(), "{context}: {:?}", run.result);
            assert!(
                run.result.fatal_error.is_none(),
                "{context}: {:?}",
                run.result
            );
            assert_eq!(run.result.created, 1, "{context}");
            assert_eq!(run.result.applied_incremental.len(), 1, "{context}");
            assert_eq!(run.count("POST /batch "), 1, "{context}");
            let put = format!("PUT {}/r1", kind.path());
            assert_eq!(run.count(&put), 1, "{context}");
            let sent = run.request(&put);
            assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
            let payload: serde_json::Value =
                serde_json::from_str(sent.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(payload, row(kind, "r1", &verified), "{context}");
        }
    }
}

#[tokio::test]
async fn ambiguous_recovery_refuses_a_verification_that_dropped_nested_fields() {
    let desired = document(Kind::Upstream, "u1", None, 1);
    let mut incomplete = serde_json::to_value(&desired).unwrap();
    incomplete["upstreams"][0]["targets"][0]["future_option"] = serde_json::json!(true);
    for per_resource in [false, true] {
        // The single-row response has no dropped field, but the verification
        // backup does. Its typed row cannot be a complete ownership payload.
        let mut routes = vec![
            health(),
            ("GET /backup".into(), 200, incomplete.to_string(), vec![]),
            tagged(Kind::Upstream, "u1", &desired, TAG),
        ];
        if per_resource {
            routes.push(("POST /batch".into(), 501, "{}".into(), vec![]));
            routes.push(("POST /upstreams".into(), 502, "{}".into(), vec![]));
        } else {
            routes.push(("POST /batch".into(), 503, "{}".into(), vec![]));
        }

        let run = apply_exclusive(&desired, GatewayConfig::default(), routes).await;

        assert_eq!(
            run.count("PUT /upstreams/u1"),
            0,
            "per_resource={per_resource}"
        );
        assert_eq!(run.result.created, 0, "per_resource={per_resource}");
        assert!(run.result.applied_incremental.is_empty());
        assert!(!run.result.errors.is_empty() || run.result.fatal_error.is_some());
    }
}

#[tokio::test]
async fn an_added_optional_field_during_batch_recovery_defers_pruning() {
    // A mixed namespace needs a batch for the new scoped-plugin cycle, then
    // intends to prune `old`. The proxy is edited after batch verification.
    let planned = document(Kind::Upstream, "old", None, 1);
    let desired = scoped_pair(1, true);
    let edited = with_optional_addition(Kind::Proxy, &desired);
    let mut verified = desired.clone();
    verified.upstreams.extend(planned.upstreams.clone());
    let routes = vec![
        health(),
        ("POST /batch".into(), 503, "{}".into(), vec![]),
        backup(&verified),
        tagged(Kind::PluginConfig, "pc1", &verified, TAG),
        tagged(Kind::Proxy, "p1", &edited, "\"concurrent-tag\""),
        tagged(Kind::Upstream, "old", &planned, TAG),
    ];

    let run = apply_exclusive(&desired, planned, routes).await;

    assert_eq!(
        run.mutations(),
        ["POST /batch HTTP/1.1", "PUT /plugins/config/pc1 HTTP/1.1"]
    );
    assert_eq!(run.count("GET /upstreams/old "), 0);
    assert_eq!(run.result.deleted, 0);
    assert_eq!(run.result.deletes_deferred, 1);
    assert_eq!(run.result.created, 1);
    assert_eq!(run.result.applied_incremental.len(), 1);
    assert_eq!(run.result.applied_incremental[0].kind, "PluginConfig");
    assert!(
        run.result
            .errors
            .iter()
            .any(|error| error.contains("did not show the exact row")),
        "{:?}",
        run.result
    );
}

#[tokio::test]
async fn adoption_claims_a_row_only_with_if_match_on_a_matching_read() {
    // Shared mode: a declared row identical to live and not in the ledger is
    // claimed with an ownership PUT, which must not revert a concurrent edit.
    let planned = document(Kind::Upstream, "u1", None, 1);
    for (read_version, adopted) in [(1, true), (3, false)] {
        let read = document(Kind::Upstream, "u1", None, read_version);
        let routes = vec![
            health(),
            tagged(Kind::Upstream, "u1", &read, TAG),
            backup(&planned),
        ];

        let run = apply(&planned, planned.clone(), routes, true, Default::default()).await;

        let context = format!("read_version={read_version}");
        assert!(run.result.errors.is_empty(), "{context}: {:?}", run.result);
        if adopted {
            assert_eq!(run.mutations(), ["PUT /upstreams/u1 HTTP/1.1"]);
            let sent = run.request("PUT /upstreams/u1");
            assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
            assert_eq!(run.result.adopted.len(), 1, "{context}");
        } else {
            assert_eq!(run.mutations(), Vec::<String>::new(), "{context}");
            assert!(run.result.adopted.is_empty(), "{context}");
            assert_eq!(run.result.adoption_skipped.len(), 1, "{context}");
        }
    }
}

#[tokio::test]
async fn a_post_plugin_proxy_update_is_confirmed_outside_its_associations() {
    // Creating `pc1` makes the gateway attach it to `p1`, so the proxy's read
    // after the plugin write legitimately shows associations the plan did
    // not. Any other field that moved was somebody else's edit.
    for (live_port, concurrent) in [(1, false), (7, true)] {
        let desired = scoped_pair(2, true);
        let after_plugins = scoped_pair(live_port, true);
        let routes = vec![health(), tagged(Kind::Proxy, "p1", &after_plugins, TAG)];

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
            let sent = run.request("PUT /proxies/p1");
            assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
        }
        assert_eq!(run.mutations(), expected, "concurrent={concurrent}");
        // One read, after the plugin write, and no backup.
        assert_eq!(run.count("GET /proxies/p1 "), 1, "concurrent={concurrent}");
        let plugin_write = run.position("POST /plugins/config");
        assert!(plugin_write < run.position("GET /proxies/p1 "));
        // A read that disagrees with the plan is settled by one backup read.
        let backups = usize::from(concurrent);
        assert_eq!(run.backup_reads(), backups, "concurrent={concurrent}");
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
            vec![health(), tagged(Kind::Upstream, "u1", &live, TAG)],
            false,
            options,
        )
        .await;

        if deleted {
            assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
            assert_eq!(run.mutations(), ["DELETE /upstreams/u1 HTTP/1.1"]);
            let sent = run.request("DELETE /upstreams/u1");
            assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
        } else {
            assert_refused(&run, "became owned by API spec `spec-b`", owner);
        }
    }
}

#[test]
fn only_one_strong_entity_tag_can_make_a_write_conditional() {
    use gitforgeops::http_client::strong_entity_tag;

    assert_eq!(
        strong_entity_tag(Some(" \"abc\" ")).as_deref(),
        Some("\"abc\"")
    );
    for raw in [
        None,
        Some(""),
        Some("\"\""),
        Some("W/\"abc\""),
        Some("abc"),
        Some("\"a\", \"b\""),
        Some("\"a b\""),
    ] {
        assert_eq!(strong_entity_tag(raw), None, "{raw:?}");
    }
}

/// Proxies `id → associated plugin ids`, plus proxy-scoped plugins
/// `id → proxy`, as one document.
fn graph(proxies: &[(&str, &[&str])], plugins: &[(&str, &str)]) -> GatewayConfig {
    let proxies: Vec<serde_json::Value> = proxies
        .iter()
        .map(|(id, associated)| {
            let plugins: Vec<serde_json::Value> = associated
                .iter()
                .map(|plugin| serde_json::json!({"plugin_config_id": plugin}))
                .collect();
            serde_json::json!({
                "id": id,
                "namespace": NS,
                "backend_host": "127.0.0.1",
                "backend_port": 1,
                "listen_path": format!("/{id}"),
                "plugins": plugins,
            })
        })
        .collect();
    let plugin_configs: Vec<serde_json::Value> = plugins
        .iter()
        .map(|(id, proxy)| {
            serde_json::json!({
                "id": id,
                "namespace": NS,
                "plugin_name": "cors",
                "config": {},
                "scope": "proxy",
                "proxy_id": proxy,
            })
        })
        .collect();
    let document = serde_json::json!({"proxies": proxies, "plugin_configs": plugin_configs});
    serde_json::from_value(document).unwrap()
}

#[tokio::test]
async fn a_post_plugin_proxy_update_does_not_detach_a_concurrently_attached_plugin() {
    // `pc1` is this run's; `audit` was attached by someone else after the
    // plan. Only the association this run wrote may differ from the plan.
    let planned = graph(&[("p1", &[]), ("p2", &[])], &[("audit", "p2")]);
    let desired = graph(
        &[("p1", &["pc1"]), ("p2", &[])],
        &[("audit", "p2"), ("pc1", "p1")],
    );
    let live = graph(&[("p1", &["pc1", "audit"]), ("p2", &[])], &[]);
    let routes = vec![
        health(),
        tagged(Kind::Proxy, "p1", &live, TAG),
        backup(&live),
    ];

    let run = apply_exclusive(&desired, planned, routes).await;

    assert_eq!(run.mutations(), ["POST /plugins/config HTTP/1.1"]);
    let errors = &run.result.errors;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_starts(errors, 0, "Proxy p1 update");
    assert!(errors[0].contains(CHANGED), "{errors:?}");
}

#[tokio::test]
async fn moving_a_scoped_plugin_off_a_proxy_and_deleting_that_proxy_is_one_apply() {
    // `move` goes from `old` to `new`, and `old` is deleted, in one commit. The
    // gateway detaches `move` from `old` when the plugin is retargeted, so the
    // delete's read no longer shows that association: this run wrote it.
    let planned = graph(&[("new", &[]), ("old", &["move"])], &[("move", "old")]);
    let desired = graph(&[("new", &["move"])], &[("move", "new")]);
    let after = graph(&[("new", &["move"]), ("old", &[])], &[("move", "new")]);
    let routes = vec![
        health(),
        tagged(Kind::PluginConfig, "move", &planned, "\"move-tag\""),
        tagged(Kind::Proxy, "new", &after, "\"new-tag\""),
        tagged(Kind::Proxy, "old", &after, "\"old-tag\""),
    ];

    let run = apply_exclusive(&desired, planned, routes).await;

    assert!(run.result.errors.is_empty(), "{:?}", run.result.errors);
    assert_eq!(
        run.mutations(),
        [
            "PUT /plugins/config/move HTTP/1.1",
            "DELETE /proxies/old?cleanup_orphaned_upstream=false HTTP/1.1",
        ]
    );
    let sent = run.request("DELETE /proxies/old");
    assert!(sent.contains("if-match: \"old-tag\"\r\n"), "{sent}");
    assert_eq!(run.backup_reads(), 0);
}

#[tokio::test]
async fn a_row_stored_unnormalized_is_written_once_a_backup_confirms_the_plan() {
    // The plan comes from `/backup`, which Ferrum Edge normalizes on load; the
    // single-row read returns the row as stored. A difference the backup does
    // not show is representation, not a concurrent change.
    for kind in [Kind::Upstream, Kind::PluginConfig, Kind::Proxy] {
        for (backup_version, written) in [(1, true), (3, false)] {
            let context = format!("{kind:?} backup_version={backup_version}");
            let planned = document(kind, "r1", None, 1);
            let stored = document(kind, "r1", None, 9);
            let routes = vec![
                health(),
                tagged(kind, "r1", &stored, TAG),
                backup(&document(kind, "r1", None, backup_version)),
            ];

            let run = apply_exclusive(&document(kind, "r1", None, 2), planned, routes).await;

            let read = format!("GET {}/r1 ", kind.path());
            let backup_read = run.position("GET /backup ");
            assert!(run.position(&read) < backup_read, "{context}");
            if written {
                assert!(run.result.errors.is_empty(), "{context}: {:?}", run.result);
                let write = format!("PUT {}/r1", kind.path());
                let sent = run.request(&write);
                assert!(sent.contains(&format!("if-match: {TAG}\r\n")), "{sent}");
            } else {
                assert_refused(&run, CHANGED, &context);
            }
        }
    }
}

#[tokio::test]
async fn a_412_after_a_retried_put_that_landed_counts_as_applied() {
    // The first attempt reached the gateway and committed; its response was
    // lost to a 503, and the replay's If-Match no longer matches. The row now
    // carrying exactly what this run sent proves the write landed.
    let planned = document(Kind::Upstream, "u1", None, 1);
    let desired = document(Kind::Upstream, "u1", None, 2);
    for (reread_version, applied) in [(2, true), (3, false)] {
        let context = format!("reread_version={reread_version}");
        let reread = document(Kind::Upstream, "u1", None, reread_version);
        let mut routes = vec![health()];
        let first_read = tagged(Kind::Upstream, "u1", &planned, TAG);
        routes.push((
            format!("{ONCE}{}", first_read.0),
            200,
            first_read.2,
            first_read.3,
        ));
        routes.push(tagged(Kind::Upstream, "u1", &reread, "\"after\""));
        let lost = format!("{ONCE}PUT /upstreams/u1");
        routes.push((lost, 503, "{}".into(), vec![]));
        routes.push(("PUT /upstreams/u1".into(), 412, "{}".into(), vec![]));
        let (url, requests) = spawn_recording_gateway(routes);

        let result = apply_api(
            &desired,
            &client_with_retries(url, 1),
            &[NS.to_string()],
            OwnershipScope::Exclusive,
            Some(&BTreeMap::from([(NS.to_string(), planned.clone())])),
            Some(&BTreeMap::from([(NS.to_string(), BackupExtras::default())])),
            &ApplyOptions::default(),
        )
        .await
        .unwrap();

        let puts = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.starts_with("PUT /upstreams/u1"))
            .count();
        assert_eq!(puts, 2, "{context}");
        if applied {
            assert!(result.errors.is_empty(), "{context}: {:?}", result.errors);
            assert_eq!(result.updated, 1, "{context}");
        } else {
            assert_eq!(result.updated, 0, "{context}");
            let errors = &result.errors;
            assert_eq!(errors.len(), 1, "{context}: {errors:?}");
            assert!(errors[0].contains("412 Precondition Failed"), "{errors:?}");
            assert!(errors[0].contains("itself have committed"), "{errors:?}");
        }
    }
}

#[tokio::test]
async fn a_retried_put_does_not_claim_an_optional_addition_as_its_own_write_or_prune() {
    for kind in SPEC_KINDS {
        let mut planned = document(kind, "r1", None, 1);
        let desired = document(kind, "r1", None, 2);
        let edited = with_optional_addition(kind, &desired);
        let old = document(Kind::Upstream, "old", None, 1);
        planned.upstreams.extend(old.upstreams.clone());
        let first_read = tagged(kind, "r1", &planned, TAG);
        let put = format!("PUT {}/r1", kind.path());
        let routes = vec![
            health(),
            (
                format!("{ONCE}{}", first_read.0),
                200,
                first_read.2,
                first_read.3,
            ),
            tagged(kind, "r1", &edited, "\"concurrent-tag\""),
            (format!("{ONCE}{put}"), 503, "{}".into(), vec![]),
            (put.clone(), 412, "{}".into(), vec![]),
            tagged(Kind::Upstream, "old", &old, TAG),
        ];
        let (url, requests) = spawn_recording_gateway(routes);

        let result = apply_api(
            &desired,
            &client_with_retries(url, 1),
            &[NS.to_string()],
            OwnershipScope::Exclusive,
            Some(&BTreeMap::from([(NS.to_string(), planned)])),
            Some(&BTreeMap::from([(NS.to_string(), BackupExtras::default())])),
            &ApplyOptions::default(),
        )
        .await
        .unwrap();
        let requests = requests.lock().unwrap().clone();
        let run = Run { result, requests };

        let context = format!("{kind:?}");
        assert_eq!(run.count(&put), 2, "{context}");
        assert_eq!(run.mutations().len(), 2, "{context}");
        assert!(
            run.requests
                .iter()
                .filter(|request| request.starts_with(&put))
                .all(|request| request.contains(&format!("if-match: {TAG}\r\n"))),
            "{context}"
        );
        assert_eq!(run.count("GET /upstreams/old "), 0, "{context}");
        assert_eq!(run.result.updated, 0, "{context}");
        assert_eq!(run.result.deleted, 0, "{context}");
        assert_eq!(run.result.deletes_deferred, 1, "{context}");
        assert!(run.result.applied_incremental.is_empty(), "{context}");
        assert_eq!(run.result.errors.len(), 1, "{context}: {:?}", run.result);
        assert!(
            run.result.errors[0].contains("412 Precondition Failed"),
            "{context}: {:?}",
            run.result
        );
    }
}

#[tokio::test]
async fn a_retried_proxy_put_recovers_only_its_exact_normalized_result() {
    // The server defaults a missing HTTP backend scheme to https. That known
    // normalization can prove our write landed; it cannot excuse a concurrent
    // dns_override addition or invent a default for a stream proxy.
    for (stream, added, applied) in [
        (false, false, true),
        (false, true, false),
        (true, false, false),
    ] {
        let mut planned = document(Kind::Proxy, "p1", None, 1);
        let mut desired = document(Kind::Proxy, "p1", None, 2);
        if stream {
            planned.proxies[0].listen_port = Some(9000);
            desired.proxies[0].listen_port = Some(9000);
        }
        let mut reread = desired.clone();
        reread.proxies[0].backend_scheme = Some(BackendScheme::Https);
        if added {
            reread = with_optional_addition(Kind::Proxy, &reread);
        }
        let old = document(Kind::Upstream, "old", None, 1);
        planned.upstreams.extend(old.upstreams.clone());
        let first_read = tagged(Kind::Proxy, "p1", &planned, TAG);
        let routes = vec![
            health(),
            (
                format!("{ONCE}{}", first_read.0),
                200,
                first_read.2,
                first_read.3,
            ),
            tagged(Kind::Proxy, "p1", &reread, "\"after\""),
            (format!("{ONCE}PUT /proxies/p1"), 503, "{}".into(), vec![]),
            ("PUT /proxies/p1".into(), 412, "{}".into(), vec![]),
            tagged(Kind::Upstream, "old", &old, "\"old-tag\""),
        ];
        let (url, requests) = spawn_recording_gateway(routes);

        let result = apply_api(
            &desired,
            &client_with_retries(url, 1),
            &[NS.to_string()],
            OwnershipScope::Exclusive,
            Some(&BTreeMap::from([(NS.to_string(), planned)])),
            Some(&BTreeMap::from([(NS.to_string(), BackupExtras::default())])),
            &ApplyOptions::default(),
        )
        .await
        .unwrap();
        let requests = requests.lock().unwrap().clone();
        let run = Run { result, requests };

        let context = format!("stream={stream} added={added}");
        assert_eq!(run.count("PUT /proxies/p1"), 2, "{context}");
        if applied {
            assert!(run.result.errors.is_empty(), "{context}: {:?}", run.result);
            assert_eq!(run.result.updated, 1, "{context}");
            assert_eq!(run.result.deleted, 1, "{context}");
            assert_eq!(run.result.deletes_deferred, 0, "{context}");
            let sent = run.request("DELETE /upstreams/old");
            assert!(sent.contains("if-match: \"old-tag\"\r\n"), "{sent}");
        } else {
            assert_eq!(run.mutations().len(), 2, "{context}");
            assert_eq!(run.result.updated, 0, "{context}");
            assert_eq!(run.result.deleted, 0, "{context}");
            assert_eq!(run.result.deletes_deferred, 1, "{context}");
            assert!(run.result.applied_incremental.is_empty(), "{context}");
            assert!(
                run.result.errors[0].contains("412 Precondition Failed"),
                "{context}: {:?}",
                run.result
            );
        }
    }
}

#[tokio::test]
async fn the_apply_preflight_refuses_a_gateway_without_entity_tags_before_any_write() {
    use gitforgeops::apply::preflight_api_apply;

    // `u0` is a create and `u1` an update: without the preflight the create
    // would land before the update found the gateway cannot fence it.
    let planned = document(Kind::Upstream, "u1", None, 1);
    let mut desired = document(Kind::Upstream, "u1", None, 2);
    desired
        .upstreams
        .extend(document(Kind::Upstream, "u0", None, 1).upstreams);
    let untagged = row(Kind::Upstream, "u1", &planned).to_string();
    for (etag, refused) in [(None, true), (Some(TAG), false)] {
        let headers: Vec<(&str, &str)> = etag.map(|etag| ("ETag", etag)).into_iter().collect();
        let read = read_route(Kind::Upstream, "u1", untagged.clone(), &headers);
        let (url, requests) = spawn_recording_gateway(vec![health(), read]);

        let preflight = preflight_api_apply(
            &desired,
            &client(url),
            &[NS.to_string()],
            OwnershipScope::Exclusive,
            Some(&BTreeMap::from([(NS.to_string(), planned.clone())])),
            Some(&BTreeMap::from([(NS.to_string(), BackupExtras::default())])),
            &ApplyOptions::default(),
        )
        .await;

        let requests = requests.lock().unwrap();
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
        if refused {
            let error = preflight.expect_err("no entity-tag, no apply").to_string();
            assert!(error.contains("no strong ETag"), "{error}");
        } else {
            assert!(preflight.unwrap().is_empty());
        }
    }

    // A namespace that only creates never reads a row for the probe.
    let (url, requests) = spawn_recording_gateway(vec![health()]);
    let empty = BTreeMap::from([(NS.to_string(), GatewayConfig::default())]);
    let created = preflight_api_apply(
        &document(Kind::Upstream, "u0", None, 1),
        &client(url),
        &[NS.to_string()],
        OwnershipScope::Exclusive,
        Some(&empty),
        Some(&BTreeMap::from([(NS.to_string(), BackupExtras::default())])),
        &ApplyOptions::default(),
    )
    .await;
    assert!(created.unwrap().is_empty());
    let requests = requests.lock().unwrap();
    let only_health = requests
        .iter()
        .all(|request| request.starts_with("GET /health"));
    assert!(only_health);
}
