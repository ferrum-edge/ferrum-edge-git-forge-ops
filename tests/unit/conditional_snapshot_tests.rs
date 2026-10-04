use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use gitforgeops::apply::{apply_api, ApplyOptions};
use gitforgeops::config::{ApplyStrategy, Consumer, EnvConfig, GatewayConfig};
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
                    .insert(format!("{NS}:Consumer:c1"));
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
        managed_ledger: BTreeSet::from([format!("{NS}:Consumer:c1")]),
        ..Default::default()
    };
    let targets = gitforgeops::apply::api_target::consumer_evidence_targets(
        &actual,
        &actual,
        NS,
        OwnershipScope::Shared {
            previously_managed: &HashSet::from([format!("{NS}:Consumer:c1")]),
        },
        &options,
    )
    .unwrap();
    assert!(targets.is_empty());
}
