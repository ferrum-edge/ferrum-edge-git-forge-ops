use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use gitforgeops::apply::{apply_api, ApplyOptions};
use gitforgeops::config::schema::Consumer;
use gitforgeops::config::{ApplyStrategy, EnvConfig, GatewayConfig};
use gitforgeops::diff::resource_diff::state_key;
use gitforgeops::diff::OwnershipScope;
use gitforgeops::http_client::conditional::{
    conditional_backup, require_preserved_credentials, require_publishable_credentials,
    ConsumerEvidence, PreparedConsumerRotation,
};
use gitforgeops::http_client::{AdminClient, BackupExtras, BackupSnapshot};
use serde_json::{json, Value};

use super::conditional_fixtures::{envelope, planned_extras, restore_seal, snapshot};

const NS: &str = "team-alpha";
const ROW_TAG: &str = "\"consumers-c1\"";
const NS_TAG: &str = "\"namespace-original\"";
const SECRET: &str = "fixture-secret-aaaaaaaaaaaaaaaaaaaaaaaa";

fn consumer() -> Consumer {
    serde_json::from_value(json!({
        "id": "c1", "namespace": NS, "username": "client",
        "credentials": {"keyauth": [{"key": SECRET}]}
    }))
    .unwrap()
}

fn config() -> GatewayConfig {
    GatewayConfig {
        consumers: vec![consumer()],
        ..Default::default()
    }
}

fn evidence(row: &Value, tag: &str) -> ConsumerEvidence {
    ConsumerEvidence::from_response(
        &row.to_string(),
        NS,
        "c1",
        Some(tag),
        None,
        Some("no-store"),
    )
    .unwrap()
}

fn basic() -> Value {
    json!([{"password_hash": format!("hmac_sha256:{}", "a".repeat(64))}])
}

#[test]
fn verification_keeps_complete_basic_custom_and_legacy_fields_without_debug_leaks() {
    let mut row = serde_json::to_value(consumer()).unwrap();
    row["credentials"]["basicauth"] = basic();
    row["credentials"]["custom"] = json!([{"private": {"url": "https://secret.example/private"}}]);
    row["credentials"]["jwt"] = json!({"secret": SECRET, "legacy": "opaque"});
    let exact = evidence(&row, ROW_TAG);
    assert_eq!(exact.row, row);
    let debug = format!("{exact:?} {:?}", exact.token);
    for private in [SECRET, ROW_TAG, "secret.example", "hmac_sha256"] {
        assert!(!debug.contains(private));
    }
    assert!(require_publishable_credentials(&row, false).is_err());
    assert!(require_publishable_credentials(&row, true).is_err());
}

#[test]
fn preserving_opaque_known_credentials_refuses_server_canonicalization_even_when_declared() {
    for entry in [
        json!({"secret": SECRET, "legacy": "retained"}),
        json!([{ "secret": SECRET, "legacy": "retained" }]),
    ] {
        let mut desired = consumer();
        desired.credentials.insert("jwt".to_string(), entry);
        let raw = serde_json::to_value(&desired).unwrap();
        for replacement in [false, true] {
            let error = require_preserved_credentials(&raw, &desired, replacement).unwrap_err();
            assert!(!format!("{error:?} {error}").contains(SECRET));
        }
    }
    let desired = consumer();
    let mut raw = serde_json::to_value(&desired).unwrap();
    raw["credentials"]["basicauth"] = basic();
    raw["credentials"]["custom"] = json!({"legacy": "opaque"});
    assert!(require_preserved_credentials(&raw, &desired, false).is_ok());
    assert!(require_preserved_credentials(&raw, &desired, true).is_err());
}

#[test]
fn verification_refuses_wrong_identity_cache_weak_or_missing_tags_and_duplicate_keys() {
    let row = serde_json::to_value(consumer()).unwrap();
    for (namespace, id, tag, source, cache) in [
        ("foreign", "c1", Some(ROW_TAG), None, Some("no-store")),
        (NS, "foreign", Some(ROW_TAG), None, Some("no-store")),
        (NS, "c1", None, None, Some("no-store")),
        (NS, "c1", Some("W/\"weak\""), None, Some("no-store")),
        (NS, "c1", Some("\"a\", \"b\""), None, Some("no-store")),
        (NS, "c1", Some(ROW_TAG), Some("cached"), Some("no-store")),
        (NS, "c1", Some(ROW_TAG), Some("replica"), Some("no-store")),
        (NS, "c1", Some(ROW_TAG), None, None),
    ] {
        let error =
            ConsumerEvidence::from_response(&row.to_string(), namespace, id, tag, source, cache)
                .unwrap_err();
        assert!(!format!("{error:?} {error}").contains(SECRET));
    }
    for body in [
        format!(r#"{{"id":"c1","id":"c1","credentials":{{"keyauth":[{{"key":"{SECRET}"}}]}}}}"#),
        format!(r#"{{"username": "{SECRET}", "credentials": "{SECRET}"}}"#),
        format!(r#"{{"{SECRET}": "{SECRET}""#),
    ] {
        let error =
            ConsumerEvidence::from_response(&body, NS, "c1", Some(ROW_TAG), None, Some("no-store"))
                .unwrap_err();
        assert!(!format!("{error:?} {error}").contains(SECRET));
    }
}

#[test]
fn empty_snapshot_still_validates_namespace_and_strong_namespace_token() {
    let raw = envelope(&GatewayConfig::default(), &BackupExtras::default(), NS_TAG).to_string();
    for (namespace, tag) in [
        ("", Some(NS_TAG)),
        ("foreign\nnamespace", Some(NS_TAG)),
        (NS, None),
        (NS, Some("W/\"weak\"")),
        (NS, Some(" \"namespace-original\"")),
    ] {
        assert!(conditional_backup(&raw, namespace, tag, None, Some("no-store")).is_err());
    }
}

#[test]
fn coherent_snapshot_requires_all_maps_exact_coverage_seals_and_header_agreement() {
    let good = envelope(&config(), &BackupExtras::default(), NS_TAG);
    let mut mutations = Vec::new();
    let mut changed = good.clone();
    changed["conditional"]["namespace_etag"] = json!("\"another\"");
    mutations.push(changed);
    for section in ["proxies", "consumers", "upstreams", "plugin_configs"] {
        let mut changed = good.clone();
        changed["conditional"]["row_etags"]
            .as_object_mut()
            .unwrap()
            .remove(section);
        mutations.push(changed);
        let mut changed = good.clone();
        changed["conditional"]["row_etags"][section]["foreign"] = json!(ROW_TAG);
        mutations.push(changed);
    }
    let mut changed = good.clone();
    changed["conditional"]["row_etags"]["consumers"] = json!({});
    mutations.push(changed);
    let mut changed = good.clone();
    changed["consumers"]
        .as_array_mut()
        .unwrap()
        .push(good["consumers"][0].clone());
    mutations.push(changed);
    for field in ["id", "namespace"] {
        let mut changed = good.clone();
        changed["consumers"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        mutations.push(changed);
    }
    for (field, value) in [
        ("source", json!("cached")),
        ("counts", json!({})),
        ("conditional", Value::Null),
    ] {
        let mut changed = good.clone();
        changed[field] = value;
        mutations.push(changed);
    }
    for section in ["api_specs", "gateway_trust_bundles"] {
        let mut changed = good.clone();
        let rows = json!([{"id": "extra", "namespace": "foreign"}]);
        if section == "api_specs" {
            changed[section]["items"] = rows;
        } else {
            changed[section] = rows;
        }
        changed["counts"][section] = json!(1);
        mutations.push(changed);
    }
    for changed in mutations {
        let error = conditional_backup(
            &changed.to_string(),
            NS,
            Some(NS_TAG),
            None,
            Some("no-store"),
        )
        .unwrap_err();
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains(SECRET));
        assert!(!diagnostic.contains(NS_TAG));
    }
    let snapshot = snapshot(&config(), NS, &BackupExtras::default());
    assert_eq!(
        snapshot.extras.consumer_evidence["c1"].row["credentials"]["keyauth"][0]["key"],
        SECRET
    );
    let debug = format!("{snapshot:?} {:?}", snapshot.extras);
    assert!(!debug.contains(SECRET));
    assert!(!debug.contains(NS_TAG));
}

type Reply = (u16, String, Vec<(String, String)>);
type Requests = Arc<Mutex<Vec<String>>>;

fn gateway_env(
    reply: impl Fn(&str, usize) -> Reply + Send + Sync + 'static,
) -> (EnvConfig, Requests) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let reply = Arc::new(reply);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    break;
                }
                bytes.push(byte[0]);
                if bytes.ends_with(b"\r\n\r\n") {
                    let headers = String::from_utf8(bytes.clone()).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|length| length.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    bytes.extend(body);
                    break;
                }
            }
            let request = String::from_utf8(bytes).unwrap();
            let mut seen = recorded.lock().unwrap();
            let position = seen.len();
            seen.push(request.clone());
            drop(seen);
            let (status, body, headers) = reply(&request, position);
            let headers = headers
                .iter()
                .map(|(key, value)| format!("{key}: {value}\r\n"))
                .collect::<String>();
            write!(
                stream,
                "HTTP/1.1 {status} fixture\r\nconnection: close\r\n{headers}content-length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let env = EnvConfig {
        gateway_url: Some(url),
        admin_jwt_secret: Some("fixture-admin-key-aaaaaaaaaaaaaaaa".to_string()),
        gateway_max_retries: 1,
        namespace_filter: Some(NS.to_string()),
        ..Default::default()
    };
    (env, requests)
}

fn gateway(
    reply: impl Fn(&str, usize) -> Reply + Send + Sync + 'static,
) -> (AdminClient, Requests) {
    let (env, requests) = gateway_env(reply);
    (AdminClient::new_scoped(&env, [NS]).unwrap(), requests)
}

fn healthy() -> Reply {
    (
        200,
        json!({"status": "ok", "mode": "database", "admin_writes_enabled": true}).to_string(),
        vec![],
    )
}

fn verified(row: &Value, tag: &str) -> Reply {
    (
        200,
        row.to_string(),
        vec![
            ("ETag".to_string(), tag.to_string()),
            ("Cache-Control".to_string(), "no-store".to_string()),
        ],
    )
}

#[tokio::test]
async fn malformed_create_and_conditional_put_acknowledgements_are_redacted_and_never_replayed() {
    for status in [200, 503] {
        for body in [
            format!(r#"{{"applied":false,"applied":false,"error":"{SECRET}"}}"#),
            format!(r#"{{"applied":false,"applied":true,"error":"{SECRET}"}}"#),
            json!({"applied": false, "reason": {"private": SECRET}}).to_string(),
            json!({"applied": null, "error": SECRET}).to_string(),
            json!({"applied": SECRET}).to_string(),
            json!({"error": {"private": SECRET}}).to_string(),
            format!(r#"{{"{SECRET}":"unfinished""#),
            format!("<html>{SECRET}</html>"),
            "[]".to_string(),
            String::new(),
        ] {
            for create in [true, false] {
                let response = body.clone();
                let (client, requests) = gateway(move |_, _| (status, response.clone(), vec![]));
                let current = consumer();
                let error = if create {
                    client.create_consumer(&current, NS).await.unwrap_err()
                } else {
                    client
                        .update_if_match("Consumer", "c1", &current, NS, ROW_TAG)
                        .await
                        .unwrap_err()
                };
                assert!(matches!(
                    error,
                    gitforgeops::error::Error::AmbiguousMutation(_)
                ));
                assert!(!format!("{error:?} {error}").contains(SECRET));
                assert!(!format!("{error:?} {error}").contains(ROW_TAG));
                let seen = requests.lock().unwrap();
                assert_eq!(seen.len(), 1);
                if create {
                    assert!(seen[0].starts_with("POST /consumers "));
                } else {
                    assert!(seen[0].starts_with("PUT /consumers/c1 "));
                    assert!(seen[0].contains(&format!("if-match: {ROW_TAG}\r\n")));
                }
            }
        }
    }
}

#[tokio::test]
async fn valid_resource_acknowledgements_and_empty_204_deletes_remain_accepted() {
    for (status, body) in [
        (201, serde_json::to_value(consumer()).unwrap().to_string()),
        (200, "{}".to_string()),
        (200, json!({"applied": true}).to_string()),
        (204, String::new()),
    ] {
        let (client, requests) = gateway(move |_, _| (status, body.clone(), vec![]));
        let current = consumer();
        client.create_consumer(&current, NS).await.unwrap();
        assert!(matches!(
            client
                .update_if_match("Consumer", "c1", &current, NS, ROW_TAG)
                .await
                .unwrap(),
            gitforgeops::http_client::ConditionalUpdate::Applied
        ));
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
    for (status, body, accepted) in [
        (204, String::new(), true),
        (
            200,
            json!({"applied": false, "reason": {"private": SECRET}}).to_string(),
            false,
        ),
        (
            200,
            json!({"applied": false, "reason": "reload_timeout", "error": SECRET}).to_string(),
            false,
        ),
    ] {
        let (client, requests) = gateway(move |_, _| (status, body.clone(), vec![]));
        let result = client.delete_if_match("Consumer", "c1", NS, ROW_TAG).await;
        assert_eq!(result.is_ok(), accepted);
        if let Err(error) = result {
            assert!(!format!("{error:?} {error}").contains(SECRET));
        }
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn delete_404_acknowledgements_are_kind_specific_and_never_replayed() {
    use gitforgeops::error::Error;
    use gitforgeops::http_client::DeleteOutcome;

    for kind in ["Proxy", "Consumer", "Upstream", "PluginConfig"] {
        let owner_message = match kind {
            "PluginConfig" => "Plugin config not found".to_string(),
            _ => format!("{kind} not found"),
        };
        let cases = [
            (String::new(), true, false),
            (json!({"error": "not found"}).to_string(), true, false),
            (json!({"error": owner_message}).to_string(), true, false),
            (
                format!(r#"{{"applied":false,"applied":false,"error":"{SECRET}"}}"#),
                false,
                false,
            ),
            (
                format!(r#"{{"applied":false,"applied":true,"error":"{SECRET}"}}"#),
                false,
                false,
            ),
            (
                format!(r#"{{"applied":true,"applied":false,"error":"{SECRET}"}}"#),
                false,
                false,
            ),
            (
                format!(r#"{{"error":"not found","error":"{SECRET}"}}"#),
                false,
                false,
            ),
            (
                json!({"error": "not found", "reason": {"private": SECRET}}).to_string(),
                false,
                false,
            ),
            (
                json!({"applied": null, "error": SECRET}).to_string(),
                false,
                false,
            ),
            (json!({"applied": SECRET}).to_string(), false, false),
            (
                json!({"error": {"private": SECRET}}).to_string(),
                false,
                false,
            ),
            (format!(r#"{{"error":"{SECRET}""#), false, false),
            (format!("<html>{SECRET}</html>"), false, false),
            ("[]".to_string(), false, false),
            (" ".to_string(), false, false),
            (
                json!({"applied": false, "reason": SECRET, "error": SECRET}).to_string(),
                false,
                true,
            ),
        ];
        for (case, (body, accepted, committed_not_live)) in cases.into_iter().enumerate() {
            let accepted =
                accepted && (kind != "Consumer" || body == r#"{"error":"Consumer not found"}"#);
            let response = body.clone();
            let (client, requests) = gateway(move |_, _| (404, response.clone(), vec![]));
            let result = client.delete_if_match(kind, "c1", NS, ROW_TAG).await;
            let context = format!("{kind} case={case}");
            if accepted {
                assert_eq!(result.unwrap(), DeleteOutcome::NotFound, "{context}");
            } else {
                let error = result.unwrap_err();
                if kind == "Consumer" {
                    assert!(
                        matches!(error, Error::ConditionalWriteUnavailable(_)),
                        "{context}"
                    );
                } else if committed_not_live {
                    assert!(matches!(error, Error::CommittedNotLive { .. }), "{context}");
                } else {
                    assert!(matches!(error, Error::AmbiguousMutation(_)), "{context}");
                }
                let diagnostic = format!("{error:?} {error}");
                assert!(!diagnostic.contains(SECRET), "{context}");
                assert!(!diagnostic.contains(ROW_TAG), "{context}");
            }
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 1, "{context}");
            assert!(seen[0].starts_with("DELETE "), "{context}");
            assert!(seen[0].contains(&format!("x-ferrum-namespace: {NS}\r\n")));
            assert!(seen[0].contains(&format!("if-match: {ROW_TAG}\r\n")));
        }
    }
}

#[tokio::test]
async fn malformed_consumer_writes_never_prune_or_update_the_managed_ledger() {
    use gitforgeops::apply::AppliedOp;
    use gitforgeops::diff::resource_diff::{state_key, DiffAction};
    use gitforgeops::state::{ResourceKeys, StateFile};

    for create in [true, false] {
        let mut old = consumer();
        old.id = "old".to_string();
        let mut actual = GatewayConfig {
            consumers: vec![old],
            ..Default::default()
        };
        let mut desired = config();
        if !create {
            actual.consumers.push(consumer());
            desired.consumers[0].username = "updated".to_string();
        }
        let extras = planned_extras(&actual, NS, BackupExtras::default());
        let mut state = StateFile::default();
        let actual_keys = ResourceKeys::from_config(&actual);
        for row in &actual.consumers {
            state
                .record_op(
                    &AppliedOp {
                        kind: "Consumer".to_string(),
                        namespace: NS.to_string(),
                        id: row.id.clone(),
                        action: DiffAction::Add,
                    },
                    &actual_keys,
                )
                .unwrap();
        }
        let original_ledger = serde_json::to_value(&state.resources).unwrap();
        let managed = state.resources.keys().cloned().collect::<HashSet<_>>();
        let raw = serde_json::to_value(consumer()).unwrap();
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if request.starts_with("GET /consumers/c1/verification ") && !create {
                verified(&raw, ROW_TAG)
            } else if request.starts_with("POST /consumers ") && create {
                (
                    201,
                    format!(r#"{{"applied":false,"applied":false,"error":"{SECRET}"}}"#),
                    vec![],
                )
            } else if request.starts_with("PUT /consumers/c1 ") && !create {
                (
                    200,
                    json!({"applied": false, "reason": {"private": SECRET}}).to_string(),
                    vec![],
                )
            } else {
                panic!("an ambiguous write must not authorize pruning or another mutation")
            }
        });
        let result = apply_api(
            &desired,
            &client,
            &[NS.to_string()],
            OwnershipScope::Shared {
                previously_managed: &managed,
            },
            Some(&BTreeMap::from([(NS.to_string(), actual)])),
            Some(&BTreeMap::from([(NS.to_string(), extras)])),
            &ApplyOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!((result.created, result.updated, result.deleted), (0, 0, 0));
        assert!(result.fatal_error.is_some());
        assert!(result.applied_incremental.is_empty());
        assert!(result.adopted.is_empty());
        let desired_keys = ResourceKeys::from_config(&desired);
        for op in result.applied_incremental.iter().chain(&result.adopted) {
            state.record_op(op, &desired_keys).unwrap();
        }
        state.stamp_last_applied_if_clean(result.fatal_error.is_none() && result.errors.is_empty());
        assert_eq!(
            serde_json::to_value(&state.resources).unwrap(),
            original_ledger
        );
        assert!(state
            .resources
            .contains_key(&state_key(NS, "Consumer", "old")));
        assert!(state.last_applied_at.is_none());
        assert!(!format!("{:?} {:?}", result.errors, result.fatal_error).contains(SECRET));
        assert!(!requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request.starts_with("DELETE ")));
        assert!(result.into_result().is_err());
    }
}

#[tokio::test]
async fn router_404_during_consumer_delete_preserves_the_managed_ledger() {
    use gitforgeops::apply::AppliedOp;
    use gitforgeops::diff::resource_diff::{state_key, DiffAction};
    use gitforgeops::state::{ResourceKeys, StateFile};

    let actual = config();
    let extras = planned_extras(&actual, NS, BackupExtras::default());
    let key = state_key(NS, "Consumer", "c1");
    let mut state = StateFile::default();
    state
        .record_op(
            &AppliedOp {
                kind: "Consumer".to_string(),
                namespace: NS.to_string(),
                id: "c1".to_string(),
                action: DiffAction::Add,
            },
            &ResourceKeys::from_config(&actual),
        )
        .unwrap();
    let original_ledger = serde_json::to_value(&state.resources).unwrap();
    let managed = HashSet::from([key.clone()]);
    let raw = serde_json::to_value(consumer()).unwrap();
    let (client, requests) = gateway(move |request, _| {
        if request.starts_with("GET /health") {
            healthy()
        } else if request.starts_with("GET /consumers/c1/verification ") {
            verified(&raw, ROW_TAG)
        } else if request.starts_with("DELETE /consumers/c1 ") {
            (404, r#"{"error":"Not Found"}"#.to_string(), vec![])
        } else {
            panic!("an unexpected request must not authorize deletion")
        }
    });
    let result = apply_api(
        &GatewayConfig::default(),
        &client,
        &[NS.to_string()],
        OwnershipScope::Shared {
            previously_managed: &managed,
        },
        Some(&BTreeMap::from([(NS.to_string(), actual)])),
        Some(&BTreeMap::from([(NS.to_string(), extras)])),
        &ApplyOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(result.deleted, 0);
    assert_eq!(result.deletes_missing, 0);
    assert!(result.applied_incremental.is_empty());
    assert!(result.errors.is_empty());
    assert!(result
        .fatal_error
        .as_deref()
        .unwrap_or_default()
        .contains("authoritative conditional evidence unavailable"));
    let desired_keys = ResourceKeys::from_config(&GatewayConfig::default());
    for op in result.applied_incremental.iter().chain(&result.adopted) {
        state.record_op(op, &desired_keys).unwrap();
    }
    assert_eq!(
        serde_json::to_value(&state.resources).unwrap(),
        original_ledger
    );
    assert!(state.resources.contains_key(&key));
    let seen = requests.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].starts_with("GET /health "));
    assert!(seen[1].starts_with("GET /consumers/c1/verification "));
    assert!(seen[2].starts_with("DELETE /consumers/c1 "));
}

#[tokio::test]
async fn preallocation_capture_checks_archival_projection_but_retains_exact_hidden_fields() {
    let mut archival = config();
    archival.consumers[0]
        .credentials
        .insert("jwt".to_string(), json!([{"secret": SECRET}]));
    let mut raw = serde_json::to_value(&archival.consumers[0]).unwrap();
    raw["credentials"]["jwt"] = json!({"secret": SECRET, "legacy": "hidden"});
    let complete = evidence(&raw, ROW_TAG);
    assert!(complete.matches_archival(&archival.consumers[0]).unwrap());
    let mut changed = archival.consumers[0].clone();
    changed.username = "concurrent".to_string();
    assert!(!complete.matches_archival(&changed).unwrap());
    for conflict in [false, true] {
        let mut served = raw.clone();
        if conflict {
            served["username"] = json!("concurrent");
        }
        let (client, requests) = gateway(move |_, _| verified(&served, ROW_TAG));
        let mut planned =
            BackupSnapshot::from_value(serde_json::to_value(&archival).unwrap()).unwrap();
        let result = client
            .capture_consumer_evidence(&mut planned, NS, &BTreeSet::from(["c1".to_string()]))
            .await;
        assert_eq!(result.is_err(), conflict);
        if !conflict {
            assert_eq!(planned.extras.consumer_evidence["c1"].row, raw);
        }
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn sensitive_http_reads_refuse_duplicate_headers_and_cached_evidence_stays_sticky() {
    let raw = serde_json::to_value(consumer()).unwrap();
    let (client, _) = gateway(move |_, _| {
        let (status, body, mut headers) = verified(&raw, ROW_TAG);
        headers.push(("ETag".to_string(), ROW_TAG.to_string()));
        (status, body, headers)
    });
    let error = client
        .get_consumer_verification("c1", NS)
        .await
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains(ROW_TAG));
    let mut raw = envelope(&config(), &BackupExtras::default(), NS_TAG);
    raw["source"] = json!("cached");
    let (client, _) = gateway(move |_, _| verified(&raw, NS_TAG));
    assert!(client.get_conditional_backup(NS).await.is_err());
    assert!(client.served_from_cache());
}

#[tokio::test]
async fn verification_404_requires_the_exact_consumer_not_found_body() {
    for (body, is_gone) in [
        (r#"{"error":"Consumer not found"}"#, true),
        (r#"{"error":"Not Found"}"#, false),
        (
            r#"{"error":"Consumer not found","detail":"route missing"}"#,
            false,
        ),
        (
            r#"{"error":"Consumer not found","error":"Not Found"}"#,
            false,
        ),
        ("not json", false),
    ] {
        let response = body.to_string();
        let (client, requests) = gateway(move |_, _| (404, response.clone(), vec![]));
        let result = client.get_consumer_verification("c1", NS).await;
        if is_gone {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(
                result.unwrap_err(),
                gitforgeops::error::Error::ConditionalWriteUnavailable(_)
            ));
        }
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn hidden_only_consumer_conflicts_refuse_modify_delete_and_pending_claim() {
    for action in ["modify", "delete", "pending"] {
        let mut actual = config();
        let entries = actual.consumers[0].credentials.get_mut("keyauth").unwrap();
        entries[0]["hidden"] = json!("original");
        let extras = planned_extras(&actual, NS, BackupExtras::default());
        let mut changed = serde_json::to_value(&actual.consumers[0]).unwrap();
        changed["credentials"]["keyauth"][0]["hidden"] = json!("concurrent");
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if request.starts_with("GET /consumers/c1/verification ") {
                verified(&changed, "\"changed-row\"")
            } else {
                panic!("unexpected request; body withheld")
            }
        });
        let mut desired = actual.clone();
        let mut options = ApplyOptions::default();
        match action {
            "modify" => desired.consumers[0].username = "new-name".to_string(),
            "delete" => desired.consumers.clear(),
            _ => {
                options
                    .pending_create_assertions
                    .insert(state_key(NS, "Consumer", "c1"));
            }
        }
        let result = apply_api(
            &desired,
            &client,
            &[NS.to_string()],
            OwnershipScope::Exclusive,
            Some(&BTreeMap::from([(NS.to_string(), actual)])),
            Some(&BTreeMap::from([(NS.to_string(), extras)])),
            &options,
        )
        .await
        .unwrap();
        assert!(!result.errors.is_empty());
        assert!(result.applied_incremental.is_empty());
        assert!(requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET ")));
    }
}

#[tokio::test]
async fn shared_consumer_claim_conflict_withholds_later_claims_and_delete_authority() {
    let mut actual = config();
    let mut second = consumer();
    second.id = "c2".to_string();
    actual.consumers.push(second.clone());
    let extras = planned_extras(&actual, NS, BackupExtras::default());
    let ordinary = serde_json::to_string(&actual).unwrap();
    let mut changed = serde_json::to_value(consumer()).unwrap();
    changed["credentials"]["custom"] = json!([{"hidden": SECRET}]);
    let (client, requests) = gateway(move |request, _| {
        if request.starts_with("GET /health") {
            healthy()
        } else if request.starts_with("GET /consumers/c1/verification ") {
            verified(&changed, "\"changed-row\"")
        } else if request.starts_with("GET /consumers/c2/verification ") {
            verified(&serde_json::to_value(&second).unwrap(), "\"consumers-c2\"")
        } else if request.starts_with("GET /backup ") {
            (200, ordinary.clone(), vec![])
        } else {
            panic!("a stale claim must not authorize another write")
        }
    });
    let result = apply_api(
        &actual,
        &client,
        &[NS.to_string()],
        OwnershipScope::Shared {
            previously_managed: &HashSet::new(),
        },
        Some(&BTreeMap::from([(NS.to_string(), actual.clone())])),
        Some(&BTreeMap::from([(NS.to_string(), extras)])),
        &ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert!(result.adopted.is_empty());
    assert!(!result.errors.is_empty());
    assert!(!result.errors.join(" ").contains(SECRET));
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn ambiguous_consumer_create_and_batch_preserve_complete_rows_and_refuse_basic_inference() {
    for batch in [false, true] {
        for profile in ["exact", "hidden-conflict", "token-conflict", "basic"] {
            let mut desired = config();
            let mut stored = serde_json::to_value(consumer()).unwrap();
            if profile == "basic" {
                desired.consumers[0].credentials =
                    BTreeMap::from([("basicauth".to_string(), json!([{"password": SECRET}]))]);
                stored["credentials"] = json!({"basicauth": basic()});
            } else {
                stored["credentials"]["custom"] = json!([{"hidden": "retained"}]);
            }
            let mut complete =
                envelope(&GatewayConfig::default(), &BackupExtras::default(), NS_TAG);
            complete["consumers"] = json!([stored.clone()]);
            complete["counts"]["consumers"] = json!(1);
            complete["conditional"]["row_etags"]["consumers"] = json!({"c1": ROW_TAG});
            let mut initial = stored;
            if profile == "hidden-conflict" {
                initial["credentials"]["custom"][0]["hidden"] = json!("before-change");
            }
            let (client, requests) = gateway(move |request, _| {
                if request.starts_with("GET /health") {
                    healthy()
                } else if request.starts_with("POST /batch") && !batch {
                    (501, "{}".to_string(), vec![])
                } else if request.starts_with("POST /batch")
                    || request.starts_with("POST /consumers ")
                {
                    (503, json!({"error": SECRET}).to_string(), vec![])
                } else if request.starts_with("GET /consumers/c1/verification ") {
                    let tag = if profile == "token-conflict" {
                        "\"previous-row\""
                    } else {
                        ROW_TAG
                    };
                    verified(&initial, tag)
                } else if request.starts_with("GET /backup?conditional=true") {
                    verified(&complete, NS_TAG)
                } else if request.starts_with("PUT /consumers/c1 ") && profile == "exact" {
                    (200, "{}".to_string(), vec![])
                } else {
                    panic!("unexpected replay or unsupported ownership assertion")
                }
            });
            let empty = GatewayConfig::default();
            let extras = planned_extras(&empty, NS, BackupExtras::default());
            let result = apply_api(
                &desired,
                &client,
                &[NS.to_string()],
                OwnershipScope::Exclusive,
                Some(&BTreeMap::from([(NS.to_string(), empty)])),
                Some(&BTreeMap::from([(NS.to_string(), extras)])),
                &ApplyOptions::default(),
            )
            .await
            .unwrap();
            assert_eq!(result.created, usize::from(profile == "exact"));
            assert_eq!(
                result.fatal_error.is_some() || !result.errors.is_empty(),
                profile != "exact"
            );
            let diagnostics = format!("{:?} {:?}", result.errors, result.fatal_error);
            assert!(!diagnostics.contains(SECRET));
            let seen = requests.lock().unwrap();
            let writes = seen
                .iter()
                .filter(|request| request.starts_with("PUT "))
                .collect::<Vec<_>>();
            assert_eq!(writes.len(), usize::from(profile == "exact"));
            if let Some(write) = writes.first() {
                let body: Value =
                    serde_json::from_str(write.split_once("\r\n\r\n").unwrap().1).unwrap();
                assert_eq!(
                    body["credentials"]["custom"],
                    json!([{"hidden": "retained"}])
                );
                assert!(write.contains(&format!("if-match: {ROW_TAG}\r\n")));
            }
            assert_eq!(
                seen.iter()
                    .filter(|request| request.starts_with("POST /batch"))
                    .count(),
                1
            );
        }
    }
}

#[tokio::test]
async fn rotation_establishes_health_and_exact_fields_before_delivery_and_fences_after_delivery() {
    let current = consumer();
    let mut raw = serde_json::to_value(&current).unwrap();
    raw["credentials"]["custom"] = json!([{"hidden": "preserved"}]);
    raw["credentials"]["basicauth"] = basic();
    for conflict in [false, true] {
        let served = raw.clone();
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if request.starts_with("GET /consumers/c1/verification ") {
                verified(&served, ROW_TAG)
            } else if request.starts_with("PUT /consumers/c1 ") {
                (if conflict { 412 } else { 200 }, "{}".to_string(), vec![])
            } else {
                panic!("unexpected request; body withheld")
            }
        });
        let prepared =
            PreparedConsumerRotation::prepare(&client, &current, "keyauth/key", Some(SECRET))
                .await
                .unwrap();
        // Broker publication occurs here, after every preparatory GET.
        assert!(requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET ")));
        let result = prepared
            .publish(&client, "new-delivered-fixture-value")
            .await;
        assert_eq!(result.is_err(), conflict);
        let seen = requests.lock().unwrap();
        let write = seen
            .iter()
            .find(|request| request.starts_with("PUT "))
            .unwrap();
        assert!(write.contains(&format!("if-match: {ROW_TAG}\r\n")));
        let body: Value = serde_json::from_str(write.split_once("\r\n\r\n").unwrap().1).unwrap();
        let mut expected = raw.clone();
        expected["credentials"]["keyauth"][0]["key"] = json!("new-delivered-fixture-value");
        assert_eq!(body, expected);
    }
    for profile in ["audit", "target", "identity", "legacy", "invalid-basic"] {
        let mut served = raw.clone();
        match profile {
            "target" => served["credentials"]["keyauth"][0]["key"] = json!("changed"),
            "identity" => served["custom_id"] = json!("other-owner"),
            "legacy" => served["credentials"]["jwt"] = json!({"secret": SECRET}),
            "invalid-basic" => {
                served["credentials"]["basicauth"] = json!([{ "password_hash": SECRET }]);
            }
            _ => {}
        }
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if profile == "audit" {
                (
                    503,
                    json!({"error": SECRET}).to_string(),
                    vec![("Retry-After".to_string(), "0".to_string())],
                )
            } else {
                verified(&served, ROW_TAG)
            }
        });
        let error =
            PreparedConsumerRotation::prepare(&client, &current, "keyauth/key", Some(SECRET))
                .await
                .unwrap_err();
        assert!(!format!("{error:?} {error}").contains(SECRET));
        assert!(requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET ")));
    }
}

/// The `ns` claim of the admin token a recorded request carried.
fn ns_claim(request: &str) -> Value {
    use base64::Engine as _;
    let token = request
        .lines()
        .find_map(|line| line.strip_prefix("authorization: Bearer "))
        .expect("authorization header");
    let payload = token.split('.').nth(1).expect("JWT payload");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    let claims: Value = serde_json::from_slice(&decoded).expect("JSON claims");
    claims["ns"].clone()
}

#[tokio::test]
async fn rotation_reads_the_write_state_from_the_detailed_or_tenant_health_tier() {
    // A rotation client's token carries an `ns` claim. Ferrum Edge v0.9.15
    // serves it the detailed `/health` tier; v0.9.16 serves it the tenant
    // tier (`mode`, `admin_writes_enabled`, `namespace`, nothing fleet-wide).
    // Either reports the write state, and every namespace-scoped request stays
    // inside the claim, as v0.9.16 requires.
    let current = consumer();
    let raw = serde_json::to_value(&current).unwrap();
    let tenant = json!({
        "status": "ok", "ready": true, "mode": "database", "admin_writes_enabled": true,
        "namespace": {
            "active": NS, "serving_scope": "single_namespace_data_plane",
            "data_plane_single_namespace": true
        }
    });
    let detailed = json!({
        "status": "ok", "ready": true, "mode": "database", "admin_writes_enabled": true,
        "database": {"status": "connected", "type": "postgres"},
        "cached_config": {"available": false}
    });
    for health in [tenant, detailed] {
        let served = raw.clone();
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                (200, health.to_string(), vec![])
            } else if request.starts_with("GET /consumers/c1/verification ") {
                verified(&served, ROW_TAG)
            } else if request.starts_with("PUT /consumers/c1 ") {
                (200, "{}".to_string(), vec![])
            } else {
                panic!("rotation reaches only health and its consumer routes")
            }
        });
        assert!(client.is_namespace_bounded());
        let key = "keyauth/key";
        let prepared = PreparedConsumerRotation::prepare(&client, &current, key, Some(SECRET))
            .await
            .unwrap();
        prepared
            .publish(&client, "tenant-tier-rotation-fixture")
            .await
            .unwrap();
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 3);
        for request in seen.iter() {
            assert_eq!(ns_claim(request), json!([NS]));
            if !request.starts_with("GET /health") {
                let header = format!("x-ferrum-namespace: {NS}\r\n");
                assert!(request.contains(&header));
            }
        }
    }
}

#[tokio::test]
async fn rotation_refuses_a_minimal_health_tier_before_any_other_request() {
    // A gateway that serves the namespace-scoped token only `status` and
    // `ready` leaves the write state unknown. Rotation publishes the new
    // secret before its gateway write, so it stops at the health read.
    let current = consumer();
    let minimal = json!({"status": "ok", "ready": true}).to_string();
    let (client, requests) = gateway(move |request, _| {
        if request.starts_with("GET /health") {
            (200, minimal.clone(), vec![])
        } else {
            panic!("an unknown write state must stop rotation at its health read")
        }
    });
    let key = "keyauth/key";
    let error = PreparedConsumerRotation::prepare(&client, &current, key, Some(SECRET))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            gitforgeops::error::Error::GatewayWriteStateUnknown(_)
        ),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("admin_writes_enabled"), "{message}");
    assert!(message.contains("`ns` claim"), "{message}");
    assert!(message.contains("tenant tier"), "{message}");
    assert!(!message.contains(SECRET));
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn basic_rotation_keeps_hmac_opaque_and_committed_not_live_never_records_completion() {
    let mut current = consumer();
    current
        .credentials
        .insert("basicauth".to_string(), json!([{ "password": SECRET }]));
    let mut raw = serde_json::to_value(&current).unwrap();
    raw["credentials"]["basicauth"] = basic();
    for applied in [true, false] {
        let served = raw.clone();
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if request.starts_with("GET /consumers/c1/verification ") {
                verified(&served, ROW_TAG)
            } else if request.starts_with("PUT /consumers/c1 ") {
                (
                    200,
                    json!({"applied": applied, "error": SECRET}).to_string(),
                    vec![],
                )
            } else {
                panic!("rotation must preserve its preparation boundary")
            }
        });
        let prepared = PreparedConsumerRotation::prepare(
            &client,
            &current,
            "basicauth/password",
            Some(SECRET),
        )
        .await
        .unwrap();
        let result = prepared.publish(&client, "delivered-basic-password").await;
        assert_eq!(result.is_ok(), applied);
        let seen = requests.lock().unwrap();
        let writes = seen
            .iter()
            .filter(|request| request.starts_with("PUT "))
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        let body: Value =
            serde_json::from_str(writes[0].split_once("\r\n\r\n").unwrap().1).unwrap();
        let mut expected = raw.clone();
        expected["credentials"]["basicauth"] = json!([{ "password": "delivered-basic-password" }]);
        assert_eq!(body, expected);
        if let Err(error) = result {
            assert!(matches!(
                error,
                gitforgeops::error::Error::CommittedNotLive { .. }
            ));
            assert!(!format!("{error:?} {error}").contains(SECRET));
        }
    }
}

#[tokio::test]
async fn malformed_rotation_acknowledgements_refuse_completion_without_replay() {
    for status in [200, 503] {
        let current = consumer();
        let raw = serde_json::to_value(&current).unwrap();
        let served = raw.clone();
        let (client, requests) = gateway(move |request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if request.starts_with("GET /consumers/c1/verification ") {
                verified(&served, ROW_TAG)
            } else if request.starts_with("PUT /consumers/c1 ") {
                (
                    status,
                    json!({"applied": false, "reason": {"private": SECRET}}).to_string(),
                    vec![("Retry-After".to_string(), "0".to_string())],
                )
            } else {
                panic!("rotation must retain its original evidence and refuse replay")
            }
        });
        let prepared =
            PreparedConsumerRotation::prepare(&client, &current, "keyauth/key", Some(SECRET))
                .await
                .unwrap();
        // Delivery has completed. Only confirmed live publication permits the
        // CLI's successful completion arm to record rotation metadata.
        let error = prepared
            .publish(&client, "delivered-rotation-fixture")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            gitforgeops::error::Error::AmbiguousMutation(_)
        ));
        assert!(!format!("{error:?} {error}").contains(SECRET));
        assert!(!format!("{error:?} {error}").contains(ROW_TAG));
        let seen = requests.lock().unwrap();
        let writes = seen
            .iter()
            .filter(|request| request.starts_with("PUT "))
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].contains(&format!("if-match: {ROW_TAG}\r\n")));
        let body: Value =
            serde_json::from_str(writes[0].split_once("\r\n\r\n").unwrap().1).unwrap();
        let mut expected = raw;
        expected["credentials"]["keyauth"][0]["key"] = json!("delivered-rotation-fixture");
        assert_eq!(body, expected);
        assert_eq!(seen.len(), 3);
    }
}

#[tokio::test]
async fn malformed_batch_envelopes_never_authorize_success_fallback_or_replay() {
    let counts = json!({"proxies": 0, "consumers": 1, "plugin_configs": 0, "upstreams": 0});
    for status in [201, 503, 501] {
        for body in [
            format!(r#"{{"created":{counts},"applied":false,"applied":false,"error":"{SECRET}"}}"#),
            json!({"created": counts, "applied": false, "reason": {"private": SECRET}}).to_string(),
            json!({"created": counts, "applied": null, "error": SECRET}).to_string(),
        ] {
            let (client, requests) = gateway(move |_, _| (status, body.clone(), vec![]));
            let batch = gitforgeops::http_client::BatchCreate {
                consumers: vec![consumer()],
                ..Default::default()
            };
            let error = client.post_batch(&batch, NS).await.unwrap_err();
            assert!(matches!(
                error,
                gitforgeops::error::Error::AmbiguousMutation(_)
            ));
            assert!(!format!("{error:?} {error}").contains(SECRET));
            assert_eq!(requests.lock().unwrap().len(), 1);
        }
    }
    for status in [200, 201] {
        let body = json!({"created": counts}).to_string();
        let (client, requests) = gateway(move |_, _| (status, body.clone(), vec![]));
        let batch = gitforgeops::http_client::BatchCreate {
            consumers: vec![consumer()],
            ..Default::default()
        };
        let created = client.post_batch(&batch, NS).await.unwrap().unwrap();
        assert_eq!(created.consumers, 1);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn restore_retries_only_proven_precommit_failure_with_the_exact_original_body_and_token() {
    for refusal in [412, 501, 503, 200] {
        let (client, requests) = gateway(move |request, position| {
            if position == 0 {
                (
                    503,
                    json!({"failure_class": "connectivity"}).to_string(),
                    vec![("Retry-After".to_string(), "0".to_string())],
                )
            } else if refusal == 200 {
                (200, restore_seal(request), vec![])
            } else {
                (refusal, json!({"error": SECRET}).to_string(), vec![])
            }
        });
        let extras = planned_extras(&GatewayConfig::default(), NS, BackupExtras::default());
        let result = client
            .post_restore(&GatewayConfig::default(), NS, &extras, true)
            .await;
        assert_eq!(result.is_ok(), refusal == 200);
        let seen = requests.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].split_once("\r\n\r\n").unwrap().1,
            seen[1].split_once("\r\n\r\n").unwrap().1,
        );
        assert!(seen
            .iter()
            .all(|request| request.contains(&format!("if-match: {NS_TAG}\r\n"))));
        assert!(seen
            .iter()
            .all(|request| request.starts_with("POST /restore")));
        if let Err(error) = result {
            assert!(!format!("{error:?} {error}").contains(SECRET));
        }
    }
}

#[tokio::test]
async fn restore_uncertain_admission_fence_and_bad_seal_responses_are_never_replayed() {
    for (status, body) in [
        (
            503,
            json!({"failure_class": "connectivity", "rollback": "incomplete"}).to_string(),
        ),
        (
            503,
            json!({"failure_class": "audit_admission", "error": SECRET}).to_string(),
        ),
        (
            503,
            json!({"failure_class": "connectivity", "reason": "fence_release_failed"}).to_string(),
        ),
        (
            503,
            json!({"failure_class": "connectivity", "applied": true}).to_string(),
        ),
        (
            500,
            json!({"rollback": "unknown_outcome", "error": SECRET}).to_string(),
        ),
        (
            200,
            json!({"applied": false, "reason": "reload_timeout", "error": SECRET}).to_string(),
        ),
        (200, json!({"restored": {"consumers": 0}}).to_string()),
        (
            200,
            json!({"restored": {"proxies": 0, "consumers": 0, "upstreams": 0,
                "plugin_configs": 0, "api_specs": 0, "gateway_trust_bundles": 0},
                "reason": "fence_release_failed"})
            .to_string(),
        ),
        (
            503,
            r#"{"failure_class":"audit_admission","failure_class":"connectivity"}"#.to_string(),
        ),
        (
            503,
            json!({"failure_class": "connectivity", "applied": false,
                "reason": {"private": SECRET}})
            .to_string(),
        ),
        (
            503,
            json!({"failure_class": "connectivity", "applied": null, "error": SECRET}).to_string(),
        ),
        (
            200,
            json!({"applied": false, "reason": {"private": SECRET},
                "restored": {"proxies": 0, "consumers": 0, "upstreams": 0,
                    "plugin_configs": 0, "api_specs": 0, "gateway_trust_bundles": 0}})
            .to_string(),
        ),
    ] {
        let (client, requests) = gateway(move |_, _| (status, body.clone(), vec![]));
        let extras = planned_extras(&GatewayConfig::default(), NS, BackupExtras::default());
        let error = client
            .post_restore(&GatewayConfig::default(), NS, &extras, false)
            .await
            .unwrap_err();
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert!(!format!("{error:?} {error}").contains(SECRET));
    }
}

#[tokio::test]
async fn contradictory_batch_unsupported_responses_never_authorize_fallback() {
    for body in [
        json!({"applied": false, "reason": "reload_timeout", "error": SECRET}).to_string(),
        json!({"applied": true, "error": SECRET}).to_string(),
        r#"{"applied":false,"applied":true}"#.to_string(),
    ] {
        let (client, requests) = gateway(move |_, _| (501, body.clone(), vec![]));
        let batch = gitforgeops::http_client::BatchCreate {
            consumers: vec![consumer()],
            ..Default::default()
        };
        let error = client.post_batch(&batch, NS).await.unwrap_err();
        assert_eq!(requests.lock().unwrap().len(), 1);
        assert!(!format!("{error:?} {error}").contains(SECRET));
    }
}

#[tokio::test]
async fn coherent_full_replace_empty_and_confirmed_deletion_keep_the_original_token() {
    for confirm in [false, true] {
        let actual = GatewayConfig::default();
        let extras = planned_extras(&actual, NS, BackupExtras::default());
        let (client, requests) = gateway(|request, _| {
            if request.starts_with("GET /health") {
                healthy()
            } else if request.starts_with("POST /restore") {
                (412, "{}".to_string(), vec![])
            } else {
                panic!("no snapshot reread or retagging is permitted")
            }
        });
        let result = apply_api(
            &actual,
            &client,
            &[NS.to_string()],
            OwnershipScope::Exclusive,
            Some(&BTreeMap::from([(NS.to_string(), actual.clone())])),
            Some(&BTreeMap::from([(NS.to_string(), extras)])),
            &ApplyOptions {
                strategy: ApplyStrategy::FullReplace,
                confirm_api_spec_deletion: confirm,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(result.fully_replaced_namespaces.is_empty());
        assert!(!result.errors.is_empty());
        let seen = requests.lock().unwrap();
        assert_eq!(
            seen.iter()
                .filter(|request| request.starts_with("POST /restore"))
                .count(),
            1
        );
        assert!(seen
            .iter()
            .any(|request| request.contains(&format!("if-match: {NS_TAG}\r\n"))));
    }
}

#[tokio::test]
async fn missing_original_evidence_refuses_before_health_or_mutation_and_preview_stays_ordinary() {
    let (client, requests) = gateway(|_, _| panic!("no remote dependency was authorized"));
    let actual = config();
    let mut desired = actual.clone();
    desired.consumers[0].username = "changed".to_string();
    let actuals = BTreeMap::from([(NS.to_string(), actual)]);
    let extras = BTreeMap::from([(NS.to_string(), BackupExtras::default())]);
    let error = apply_api(
        &desired,
        &client,
        &[NS.to_string()],
        OwnershipScope::Exclusive,
        Some(&actuals),
        Some(&extras),
        &ApplyOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("complete consumer evidence"));
    let preview = gitforgeops::apply::apply_blocked_namespaces(
        &desired,
        &client,
        &[NS.to_string()],
        OwnershipScope::Exclusive,
        Some(&actuals),
        Some(&extras),
        &ApplyOptions::default(),
    )
    .await
    .unwrap();
    assert!(preview.is_empty());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn doctor_is_get_only_and_reports_missing_consumer_capability_as_unknown() {
    use gitforgeops::doctor::Status;
    let empty = envelope(&GatewayConfig::default(), &BackupExtras::default(), NS_TAG);
    let (env, requests) = gateway_env(move |request, _| {
        if request.starts_with("GET /health") {
            healthy()
        } else if request.starts_with("GET /cluster") {
            (200, "{}".to_string(), vec![])
        } else if request.starts_with("GET /namespaces") {
            (200, json!({"data": []}).to_string(), vec![])
        } else if request.starts_with("GET /backup?conditional=true") {
            verified(&empty, NS_TAG)
        } else {
            panic!("doctor must only use bounded capability reads")
        }
    });
    let checks = gitforgeops::doctor::gateway::run("fixture", &env).await;
    assert!(checks.iter().any(|check| {
        check.id == "gateway-conditional-snapshot" && check.status == Status::Pass
    }));
    assert!(checks.iter().any(|check| {
        check.id == "gateway-consumer-verification" && check.status == Status::Unknown
    }));
    assert!(requests
        .lock()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn exact_import_refuses_unsupported_credentials_before_tree_or_bundle_publication() {
    let mut raw = envelope(&config(), &BackupExtras::default(), NS_TAG);
    raw["consumers"][0]["credentials"]["custom"] = json!([{"hidden": SECRET}]);
    let (client, _) = gateway(move |_, _| verified(&raw, NS_TAG));
    let output = tempfile::tempdir().unwrap();
    let private = tempfile::tempdir().unwrap();
    let bundle = private.path().join("credentials.json");
    let error = gitforgeops::import::from_api::import_from_api(
        &client,
        output.path(),
        Some(NS),
        Some(&bundle),
        &gitforgeops::import::ImportPassthroughPolicy::default(),
        &[],
    )
    .await
    .unwrap_err();
    assert!(!error.to_string().contains(SECRET));
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);
    assert!(!bundle.exists());
}

#[tokio::test]
async fn exact_api_import_records_provenance_and_conditional_file_import_refuses_headers_absent() {
    let raw = envelope(&config(), &BackupExtras::default(), NS_TAG);
    let served = raw.clone();
    let (client, _) = gateway(move |_, _| verified(&served, NS_TAG));
    let output = tempfile::tempdir().unwrap();
    let private = tempfile::tempdir().unwrap();
    let bundle = private.path().join("credentials.json");
    let imported = gitforgeops::import::from_api::import_from_api(
        &client,
        output.path(),
        Some(NS),
        Some(&bundle),
        &gitforgeops::import::ImportPassthroughPolicy::default(),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        imported.sources[0].credential_representation,
        "exact-stored"
    );
    assert!(bundle.exists());
    let source = private.path().join("conditional.json");
    std::fs::write(&source, raw.to_string()).unwrap();
    let output = tempfile::tempdir().unwrap();
    let refused_bundle = private.path().join("refused.json");
    let error = gitforgeops::import::from_file::import_from_file(
        &source,
        output.path(),
        Some(&refused_bundle),
        &gitforgeops::import::ImportPassthroughPolicy::default(),
        &[],
    )
    .unwrap_err();
    assert!(!format!("{error:?} {error}").contains(SECRET));
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);
    assert!(!refused_bundle.exists());
}

#[test]
fn consumer_target_selection_does_not_add_endpoint_dependencies_to_nonconsumer_work() {
    let actual = config();
    let options = ApplyOptions {
        managed_ledger: BTreeSet::from([state_key(NS, "Consumer", "c1")]),
        ..Default::default()
    };
    let targets = gitforgeops::apply::api_target::consumer_evidence_targets(
        &actual,
        &actual,
        NS,
        OwnershipScope::Shared {
            previously_managed: &HashSet::from([state_key(NS, "Consumer", "c1")]),
        },
        &options,
    )
    .unwrap();
    assert!(targets.is_empty());
}
