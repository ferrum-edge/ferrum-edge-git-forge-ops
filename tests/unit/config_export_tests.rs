//! Drift detection through `GET /config/export` with a mocked export.
//!
//! Covers parsing, the fingerprint substitution that keeps an incomparable
//! secret from reading as drift, the baseline comparison between two exports,
//! cached-export staleness and the viewer credential.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use gitforgeops::config::env::EnvConfig;
use gitforgeops::config::GatewayConfig;
use gitforgeops::config_export::{
    enclosing_git_worktree, is_fingerprint, project_consumer_for_export,
    project_desired_for_export, ConfigExport, FingerprintBaseline, NamespaceSecretComparison,
    SecretChange, SecretChangeKind, SecretFingerprintSummary, BASELINE_FORMAT, VIEWER_ROLE,
};
use gitforgeops::diff::{compute_diff, DiffAction};
use gitforgeops::error::Error;
use gitforgeops::http_client::{
    check_viewer_secret, explain_config_export_refusal, AdminClient, ExportEndpoint,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};

const KEY_ID: &str = "0123456789abcdef";
const ROTATED_KEY_ID: &str = "fedcba9876543210";
const PLACEHOLDER: &str = "${gh-env-secret:alloc=require}";
const ADMIN_SECRET: &str = "config-export-test-admin-secret-32-chars";
const VIEWER_SECRET: &str = "config-export-test-viewer-secret-32-chars";

/// A syntactically valid fingerprint made of one repeated hex digit.
fn fp(digit: char) -> String {
    format!("hmac-sha256:{}", digit.to_string().repeat(64))
}

fn document(namespace: &str, key_id: &str, consumers: Value, plugins: Value) -> Value {
    let consumer_count = consumers.as_array().map_or(0, Vec::len);
    let plugin_count = plugins.as_array().map_or(0, Vec::len);
    json!({
        "version": "1",
        "ferrum_version": "0.9.9",
        "source": "database",
        "namespace": namespace,
        "redaction": {
            "fingerprint_algorithm": "hmac-sha256",
            "fingerprint_prefix": "hmac-sha256:",
            "fingerprint_key_id": key_id,
        },
        "counts": {
            "proxies": 0,
            "consumers": consumer_count,
            "plugin_configs": plugin_count,
            "upstreams": 0,
        },
        "proxies": [],
        "consumers": consumers,
        "plugin_configs": plugins,
        "upstreams": [],
    })
}

fn live_consumer(keys: &[String], hidden: &str) -> Value {
    let entries: Vec<Value> = keys.iter().map(|key| json!({ "key": key })).collect();
    json!({
        "id": "app",
        "namespace": "ferrum",
        "username": "app",
        "credentials": { "keyauth": entries },
        "hidden_credentials_fingerprint": hidden,
    })
}

fn live_plugin(authorization: &str, protocol: &str) -> Value {
    json!({
        "id": "otel",
        "namespace": "ferrum",
        "plugin_name": "otel_tracing",
        "scope": "global",
        "config": { "authorization": authorization, "protocol": protocol },
    })
}

fn export_with(key: char, hidden: char, key_id: &str) -> ConfigExport {
    let consumers = json!([live_consumer(&[fp(key)], &fp(hidden))]);
    let plugins = json!([live_plugin(&fp('e'), "grpc")]);
    let body = document("ferrum", key_id, consumers, plugins).to_string();
    ConfigExport::from_response(&body, "ferrum", false).unwrap()
}

/// `(compared, not_in_baseline, changes)` of a comparison that had a usable
/// baseline entry.
fn compared_of(comparison: NamespaceSecretComparison) -> (usize, usize, Vec<SecretChange>) {
    match comparison {
        NamespaceSecretComparison::Compared {
            compared,
            not_in_baseline,
            changes,
        } => (compared, not_in_baseline, changes),
        other => panic!("expected a comparison, got {other:?}"),
    }
}

/// The repository: a brokered keyauth key and basicauth password, and a
/// plugin with a brokered bearer token.
fn desired() -> GatewayConfig {
    serde_json::from_value(json!({
        "consumers": [{
            "id": "app",
            "namespace": "ferrum",
            "username": "app",
            "credentials": {
                "keyauth": [{ "key": PLACEHOLDER }],
                "basicauth": [{ "username": "alice", "password_hash": PLACEHOLDER }],
            },
        }],
        "plugin_configs": [{
            "id": "otel",
            "namespace": "ferrum",
            "plugin_name": "otel_tracing",
            "scope": "global",
            "config": { "authorization": PLACEHOLDER, "protocol": "grpc" },
        }],
    }))
    .unwrap()
}

#[test]
fn fingerprints_are_recognized_only_in_the_documented_shape() {
    assert!(is_fingerprint(&fp('a')));
    assert!(!is_fingerprint("hmac-sha256:ABC"));
    assert!(!is_fingerprint(&fp('A')));
    assert!(!is_fingerprint(&format!("hmac_sha256:{}", "a".repeat(64))));
    assert!(!is_fingerprint("[REDACTED]"));
}

#[test]
fn a_cached_export_is_marked_stale_from_the_header_or_the_body() {
    let fresh = document("ferrum", KEY_ID, json!([]), json!([]));
    let parsed = ConfigExport::from_response(&fresh.to_string(), "ferrum", false).unwrap();
    assert!(!parsed.cached);
    assert_eq!(parsed.fingerprint_key_id, KEY_ID);
    assert!(parsed.count_seal_notice.is_none());

    let from_header = ConfigExport::from_response(&fresh.to_string(), "ferrum", true).unwrap();
    assert!(from_header.cached);

    let mut cached = fresh;
    cached["source"] = json!("cached");
    let from_body = ConfigExport::from_response(&cached.to_string(), "ferrum", false).unwrap();
    assert!(from_body.cached);
}

#[test]
fn an_export_for_another_namespace_or_with_a_foreign_row_is_refused() {
    let other = document("team-b", KEY_ID, json!([]), json!([]));
    let error = ConfigExport::from_response(&other.to_string(), "ferrum", false).unwrap_err();
    assert!(matches!(error, Error::BackupNamespace(_)), "{error}");

    let mut foreign = live_consumer(&[fp('a')], &fp('b'));
    foreign["namespace"] = json!("team-b");
    let body = document("ferrum", KEY_ID, json!([foreign]), json!([]));
    let error = ConfigExport::from_response(&body.to_string(), "ferrum", false).unwrap_err();
    assert!(matches!(error, Error::BackupNamespace(_)), "{error}");
}

#[test]
fn an_unknown_fingerprint_scheme_or_key_id_is_refused() {
    let mut algorithm = document("ferrum", KEY_ID, json!([]), json!([]));
    algorithm["redaction"]["fingerprint_algorithm"] = json!("hmac-sha512");
    let error = ConfigExport::from_response(&algorithm.to_string(), "ferrum", false).unwrap_err();
    assert!(error.to_string().contains("hmac-sha512"), "{error}");

    let key_id = document("ferrum", "not-hex", json!([]), json!([]));
    let error = ConfigExport::from_response(&key_id.to_string(), "ferrum", false).unwrap_err();
    assert!(error.to_string().contains("fingerprint_key_id"), "{error}");

    let mut missing = document("ferrum", KEY_ID, json!([]), json!([]));
    missing.as_object_mut().unwrap().remove("upstreams");
    let error = ConfigExport::from_response(&missing.to_string(), "ferrum", false).unwrap_err();
    assert!(error.to_string().contains("upstreams"), "{error}");
}

#[test]
fn a_count_seal_that_disagrees_is_advisory() {
    let mut body = document("ferrum", KEY_ID, json!([]), json!([]));
    body["counts"]["consumers"] = json!(3);
    let parsed = ConfigExport::from_response(&body.to_string(), "ferrum", false).unwrap();
    let notice = parsed.count_seal_notice.expect("seal mismatch is reported");
    assert!(notice.contains("consumers"), "{notice}");
}

#[test]
fn declared_secrets_are_not_reported_as_drift_and_are_listed_as_uncompared() {
    let desired = desired();
    let export = export_with('a', 'b', KEY_ID);
    let view = export.live_view(&desired).unwrap();

    let consumer = &view.actual.consumers[0];
    let keyauth = &consumer.credentials["keyauth"];
    assert_eq!(keyauth, &json!([{ "key": PLACEHOLDER }]));
    assert!(consumer.extra.is_empty());
    let plugin = &view.actual.plugin_configs[0];
    assert_eq!(plugin.config["authorization"], PLACEHOLDER);

    let pointers: Vec<(&str, &str)> = view
        .uncompared
        .iter()
        .map(|site| (site.kind.as_str(), site.pointer.as_str()))
        .collect();
    assert_eq!(
        pointers,
        vec![
            ("Consumer", "/credentials/keyauth/0/key"),
            ("Consumer", "/hidden_credentials_fingerprint"),
            ("PluginConfig", "/config/authorization"),
        ]
    );

    let diffs = compute_diff(&project_desired_for_export(&desired), &view.actual).unwrap();
    assert!(diffs.is_empty(), "{diffs:?}");
}

#[test]
fn a_fingerprint_the_repository_does_not_declare_is_still_drift() {
    let desired = desired();
    let consumers = json!([live_consumer(&[fp('a'), fp('c')], &fp('b'))]);
    let plugins = json!([live_plugin(&fp('e'), "http")]);
    let body = document("ferrum", KEY_ID, consumers, plugins).to_string();
    let export = ConfigExport::from_response(&body, "ferrum", false).unwrap();
    let view = export.live_view(&desired).unwrap();

    let consumer = &view.actual.consumers[0];
    assert_eq!(consumer.credentials["keyauth"][1]["key"], json!(fp('c')));

    let diffs = compute_diff(&project_desired_for_export(&desired), &view.actual).unwrap();
    assert_eq!(diffs.len(), 2, "{diffs:?}");
    assert_eq!(diffs[0].kind, "Consumer");
    assert_eq!(diffs[0].action, DiffAction::Modify);
    assert_eq!(diffs[0].details[0].field, "credentials");
    assert_eq!(diffs[1].kind, "PluginConfig");
    assert_eq!(diffs[1].action, DiffAction::Modify);
    assert_eq!(diffs[1].details[0].field, "config");
}

#[test]
fn a_fingerprint_shaped_value_in_a_non_secret_field_is_compared() {
    // Edge publishes no list of the pointers it redacted, so a fingerprint
    // shape alone must not hide drift in an ordinary field.
    let desired = desired();
    let consumers = json!([live_consumer(&[fp('a')], &fp('b'))]);
    let plugins = json!([live_plugin(&fp('e'), &fp('9'))]);
    let body = document("ferrum", KEY_ID, consumers, plugins).to_string();
    let export = ConfigExport::from_response(&body, "ferrum", false).unwrap();
    let view = export.live_view(&desired).unwrap();

    let plugin = &view.actual.plugin_configs[0];
    assert_eq!(plugin.config["protocol"], json!(fp('9')));
    assert_eq!(plugin.config["authorization"], PLACEHOLDER);
    // The key, the hidden credentials and the bearer token; not the protocol.
    assert_eq!(view.uncompared.len(), 3);

    let diffs = compute_diff(&project_desired_for_export(&desired), &view.actual).unwrap();
    assert_eq!(diffs.len(), 1, "{diffs:?}");
    assert_eq!(diffs[0].kind, "PluginConfig");
    assert_eq!(diffs[0].action, DiffAction::Modify);
}

#[test]
fn a_resolved_secret_at_a_modeled_path_is_still_uncompared() {
    // With a bundle loaded the repository value is the real secret, not a
    // placeholder; the Consumer key path alone marks it secret-bearing.
    let mut desired = desired();
    let consumer = &mut desired.consumers[0];
    let key = json!([{ "key": "resolved-key-value-0001" }]);
    consumer.credentials.insert("keyauth".to_string(), key);
    let view = export_with('a', 'b', KEY_ID).live_view(&desired).unwrap();
    let keyauth = &view.actual.consumers[0].credentials["keyauth"];
    assert_eq!(keyauth, &json!([{ "key": "resolved-key-value-0001" }]));
}

#[test]
fn every_declared_consumer_leaves_its_hidden_credentials_uncompared() {
    // A credential-less consumer can still gain a basicauth credential out of
    // band; only the hidden-credentials fingerprint would show it.
    let desired: GatewayConfig = serde_json::from_value(json!({
        "consumers": [{ "id": "app", "namespace": "ferrum", "username": "app" }],
    }))
    .unwrap();
    let mut consumer = live_consumer(&[], &fp('b'));
    consumer["credentials"] = json!({});
    let body = document("ferrum", KEY_ID, json!([consumer]), json!([])).to_string();
    let export = ConfigExport::from_response(&body, "ferrum", false).unwrap();
    let view = export.live_view(&desired).unwrap();

    assert_eq!(view.uncompared.len(), 1);
    let site = &view.uncompared[0];
    assert_eq!(site.pointer, "/hidden_credentials_fingerprint");
    let diffs = compute_diff(&project_desired_for_export(&desired), &view.actual).unwrap();
    assert!(diffs.is_empty(), "{diffs:?}");

    let exports = [export];
    let unverified = SecretFingerprintSummary::evaluate(&exports, 1, None, &desired);
    assert!(!unverified.verified());

    let mut baseline = FingerprintBaseline::default();
    baseline.record(&exports[0]);
    let proven = SecretFingerprintSummary::evaluate(&exports, 1, Some(&baseline), &desired);
    assert!(proven.verified());
}

#[test]
fn a_consumer_exported_without_its_hidden_fingerprint_is_never_verified() {
    // A non-conforming gateway that omits the field must not let a baseline
    // vouch for credentials nobody could see.
    let desired = desired();
    let mut consumer = live_consumer(&[fp('a')], &fp('b'));
    let object = consumer.as_object_mut().unwrap();
    object.remove("hidden_credentials_fingerprint");
    let plugins = json!([live_plugin(&fp('e'), "grpc")]);
    let body = document("ferrum", KEY_ID, json!([consumer]), plugins).to_string();
    let export = ConfigExport::from_response(&body, "ferrum", false).unwrap();
    let view = export.live_view(&desired).unwrap();
    // The key, the hidden credentials (recorded although absent) and the token.
    assert_eq!(view.uncompared.len(), 3);
    let site = &view.uncompared[1];
    assert_eq!(site.pointer, "/hidden_credentials_fingerprint");

    let uncompared = view.uncompared.len();
    let exports = [export];
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&exports[0]);
    let summary =
        SecretFingerprintSummary::evaluate(&exports, uncompared, Some(&baseline), &desired);
    assert!(!summary.verified());
    assert!(summary.notes[0].contains("hidden_credentials_fingerprint"));
}

#[test]
fn a_placeholder_stays_secret_bearing_after_the_bundle_resolves_it() {
    // An unclassified plugin field is secret-bearing only because the
    // repository brokers it; resolution must not erase that.
    let unresolved: GatewayConfig = serde_json::from_value(json!({
        "plugin_configs": [{
            "id": "otel",
            "namespace": "ferrum",
            "plugin_name": "otel_tracing",
            "scope": "global",
            "config": { "service_label": PLACEHOLDER, "protocol": "grpc" },
        }],
    }))
    .unwrap();
    let mut resolved = unresolved.clone();
    resolved.plugin_configs[0].config["service_label"] = json!("resolved-label-0001");
    let mut plugin = live_plugin(&fp('e'), "grpc");
    plugin["config"] = json!({ "service_label": fp('e'), "protocol": "grpc" });
    let body = document("ferrum", KEY_ID, json!([]), json!([plugin])).to_string();
    let export = ConfigExport::from_response(&body, "ferrum", false).unwrap();

    let without_source = export.live_view(&resolved).unwrap();
    assert!(without_source.uncompared.is_empty());

    let view = export.live_view_with(&resolved, &unresolved).unwrap();
    assert_eq!(view.uncompared.len(), 1);
    let label = &view.actual.plugin_configs[0].config["service_label"];
    assert_eq!(label, &json!("resolved-label-0001"));
    let diffs = compute_diff(&resolved, &view.actual).unwrap();
    assert!(diffs.is_empty(), "{diffs:?}");
}

#[test]
fn a_whole_value_fingerprinted_around_a_secret_is_never_authoritative() {
    let desired: GatewayConfig = serde_json::from_value(json!({
        "plugin_configs": [{
            "id": "otel",
            "namespace": "ferrum",
            "plugin_name": "otel_tracing",
            "scope": "global",
            "config": { "headers": { "x-api-key": PLACEHOLDER, "x-trace": "on" } },
        }],
    }))
    .unwrap();
    let mut plugin = live_plugin(&fp('e'), "grpc");
    plugin["config"] = json!({ "headers": fp('c') });
    let body = document("ferrum", KEY_ID, json!([]), json!([plugin])).to_string();
    let export = ConfigExport::from_response(&body, "ferrum", false).unwrap();
    let view = export.live_view(&desired).unwrap();

    assert_eq!(view.masked_ancestors.len(), 1);
    assert_eq!(view.masked_ancestors[0].pointer, "/config/headers");
    assert_eq!(view.uncompared.len(), 1);

    let exports = [export];
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&exports[0]);
    let summary = SecretFingerprintSummary::evaluate(&exports, 1, Some(&baseline), &desired)
        .with_masked_ancestors(view.masked_ancestors.len());
    // The baseline proves the fingerprint unchanged, not its hidden contents.
    assert!(summary.verified());
    assert!(!summary.authoritative());
}

#[test]
fn a_baseline_inside_a_git_worktree_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let nested = dir.path().join("state").join("fingerprints.json");
    let found = enclosing_git_worktree(&nested);
    assert_eq!(found.as_deref(), Some(dir.path()));
}

#[test]
fn the_desired_consumer_is_projected_like_the_export() {
    let desired = desired();
    let consumer: gitforgeops::config::schema::Consumer = serde_json::from_value(json!({
        "id": "app",
        "username": "app",
        "credentials": {
            "keyauth": [{ "key": "k", "legacy": "x" }],
            "jwt": { "secret": "s" },
            "basicauth": [{ "username": "alice", "password": "p" }],
            "mtls_auth": [{ "identity": "CN=app" }, { "identity": " " }],
        },
    }))
    .unwrap();
    let projected = project_consumer_for_export(&consumer);
    assert_eq!(
        serde_json::to_value(&projected.credentials).unwrap(),
        json!({
            "jwt": [{ "secret": "s" }],
            "keyauth": [{ "key": "k" }],
            "mtls_auth": [{ "identity": "CN=app" }],
        })
    );
    let whole = project_desired_for_export(&desired);
    assert!(!whole.consumers[0].credentials.contains_key("basicauth"));
}

#[test]
fn a_baseline_detects_a_secret_that_changed_between_two_exports() {
    let desired = desired();
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&export_with('a', 'b', KEY_ID));

    let unchanged = baseline.compare(&export_with('a', 'b', KEY_ID), &desired);
    assert_eq!(compared_of(unchanged), (2, 0, Vec::new()));

    let changed = baseline.compare(&export_with('c', 'd', KEY_ID), &desired);
    let (_, _, changes) = compared_of(changed);
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].pointer, "/credentials/keyauth/0/key");
    assert_eq!(changes[1].pointer, "/hidden_credentials_fingerprint");
    for change in &changes {
        assert_eq!(change.kind, "Consumer");
        assert_eq!(change.id, "app");
        assert_eq!(change.change, SecretChangeKind::Changed);
    }
}

#[test]
fn a_rotated_gateway_key_or_a_missing_entry_is_not_comparable() {
    let desired = desired();
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&export_with('a', 'b', KEY_ID));

    let rotated = baseline.compare(&export_with('a', 'b', ROTATED_KEY_ID), &desired);
    assert_eq!(rotated, NamespaceSecretComparison::KeyChanged);

    let empty = FingerprintBaseline::default();
    let missing = empty.compare(&export_with('a', 'b', KEY_ID), &desired);
    assert_eq!(missing, NamespaceSecretComparison::NoBaseline);
}

#[test]
fn added_removed_and_unbaselined_secrets_are_reported_separately() {
    let desired = desired();
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&export_with('a', 'b', KEY_ID));
    baseline
        .namespaces
        .get_mut("ferrum")
        .unwrap()
        .resources
        .remove("PluginConfig");

    let consumers = json!([live_consumer(&[fp('a'), fp('c')], &fp('b'))]);
    let plugins = json!([live_plugin(&fp('e'), "grpc")]);
    let body = document("ferrum", KEY_ID, consumers, plugins).to_string();
    let grown = ConfigExport::from_response(&body, "ferrum", false).unwrap();
    let (compared, not_in_baseline, changes) = compared_of(baseline.compare(&grown, &desired));
    assert_eq!((compared, not_in_baseline), (1, 1));
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].pointer, "/credentials/keyauth/1/key");
    assert_eq!(changes[0].change, SecretChangeKind::Added);

    let shrunk = baseline.compare(&export_with('a', 'b', KEY_ID), &desired);
    assert_eq!(compared_of(shrunk), (1, 1, Vec::new()));

    let mut wider = FingerprintBaseline::default();
    wider.record(&grown);
    let removed = wider.compare(&export_with('a', 'b', KEY_ID), &desired);
    let (_, _, changes) = compared_of(removed);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].pointer, "/credentials/keyauth/1/key");
    assert_eq!(changes[0].change, SecretChangeKind::Removed);
}

#[test]
fn undeclared_resources_are_left_to_the_ordinary_diff() {
    let empty = GatewayConfig::default();
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&export_with('a', 'b', KEY_ID));
    let comparison = baseline.compare(&export_with('c', 'd', KEY_ID), &empty);
    assert_eq!(compared_of(comparison), (0, 0, Vec::new()));
}

#[test]
fn a_baseline_round_trips_through_a_file_and_rejects_malformed_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fingerprints.json");
    assert_eq!(FingerprintBaseline::load(&path).unwrap(), None);

    let mut baseline = FingerprintBaseline::default();
    baseline.record(&export_with('a', 'b', KEY_ID));
    baseline.write(&path).unwrap();
    let loaded = FingerprintBaseline::load(&path).unwrap().unwrap();
    assert_eq!(loaded, baseline);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(BASELINE_FORMAT));
    assert!(!text.contains(PLACEHOLDER));

    let mut wrong_format = serde_json::to_value(&baseline).unwrap();
    wrong_format["format"] = json!("something-else/v9");
    let error = FingerprintBaseline::from_json(&wrong_format.to_string()).unwrap_err();
    assert!(error.to_string().contains("something-else/v9"), "{error}");

    let mut bad_value = serde_json::to_value(&baseline).unwrap();
    bad_value["namespaces"]["ferrum"]["resources"]["Consumer"]["app"]["/x"] = json!("plain");
    assert!(FingerprintBaseline::from_json(&bad_value.to_string()).is_err());

    let mut bad_kind = serde_json::to_value(&baseline).unwrap();
    bad_kind["namespaces"]["ferrum"]["resources"]["Gadget"] = json!({});
    assert!(FingerprintBaseline::from_json(&bad_kind.to_string()).is_err());

    let mut unknown_field = serde_json::to_value(&baseline).unwrap();
    unknown_field["extra"] = json!(true);
    assert!(FingerprintBaseline::from_json(&unknown_field.to_string()).is_err());
}

#[test]
fn the_summary_is_unverified_without_a_complete_baseline() {
    let desired = desired();
    let export = export_with('a', 'b', KEY_ID);
    let uncompared = export.live_view(&desired).unwrap().uncompared.len();
    let exports = [export];

    let none = SecretFingerprintSummary::evaluate(&exports, uncompared, None, &desired);
    assert!(!none.verified());
    assert!(none.changes.is_empty());

    let mut baseline = FingerprintBaseline::default();
    baseline.record(&exports[0]);
    let complete =
        SecretFingerprintSummary::evaluate(&exports, uncompared, Some(&baseline), &desired);
    assert!(complete.verified());
    assert!(complete.notes.is_empty());

    let rotated = [export_with('a', 'b', ROTATED_KEY_ID)];
    let key_changed =
        SecretFingerprintSummary::evaluate(&rotated, uncompared, Some(&baseline), &desired);
    assert!(!key_changed.verified());
    assert!(key_changed.key_changed);
    assert!(key_changed.notes[0].contains("fingerprint key changed"));

    // A key change is never verified, even with nothing to compare.
    let empty = GatewayConfig::default();
    let rekeyed = SecretFingerprintSummary::evaluate(&rotated, 0, Some(&baseline), &empty);
    assert!(!rekeyed.verified());

    let nothing_fingerprinted = SecretFingerprintSummary::evaluate(&exports, 0, None, &desired);
    assert!(nothing_fingerprinted.verified());
}

#[test]
fn a_cached_export_is_never_compared_with_the_baseline() {
    let desired = desired();
    let mut baseline = FingerprintBaseline::default();
    baseline.record(&export_with('a', 'b', KEY_ID));

    let consumers = json!([live_consumer(&[fp('c')], &fp('d'))]);
    let mut body = document("ferrum", KEY_ID, consumers, json!([]));
    body["source"] = json!("cached");
    let cached = ConfigExport::from_response(&body.to_string(), "ferrum", false).unwrap();
    let summary = SecretFingerprintSummary::evaluate(&[cached], 2, Some(&baseline), &desired);
    assert!(summary.changes.is_empty());
    assert!(!summary.baseline_complete);
    assert!(!summary.verified());
}

// --- Viewer credential --------------------------------------------------------

fn viewer_env(url: &str) -> EnvConfig {
    EnvConfig {
        gateway_url: Some(url.to_string()),
        admin_jwt_viewer_secret: Some(VIEWER_SECRET.to_string()),
        allow_insecure_http: true,
        gateway_max_retries: 0,
        ..EnvConfig::default()
    }
}

#[test]
fn the_viewer_secret_is_checked_without_echoing_either_value() {
    let mut env = viewer_env("https://gateway.example:9000");
    assert_eq!(check_viewer_secret(&env).unwrap(), VIEWER_SECRET);

    env.admin_jwt_viewer_secret = None;
    let missing = check_viewer_secret(&env).unwrap_err().to_string();
    assert!(missing.contains("FERRUM_ADMIN_JWT_VIEWER_SECRET"));

    env.admin_jwt_viewer_secret = Some("short-viewer-secret".to_string());
    let short = check_viewer_secret(&env).unwrap_err().to_string();
    assert!(short.contains("at least 32"), "{short}");
    assert!(!short.contains("short-viewer-secret"), "{short}");

    env.admin_jwt_viewer_secret = Some(ADMIN_SECRET.to_string());
    env.admin_jwt_secret = Some(ADMIN_SECRET.to_string());
    let same = check_viewer_secret(&env).unwrap_err().to_string();
    assert!(same.contains("must differ"), "{same}");
    assert!(!same.contains(ADMIN_SECRET), "{same}");
}

#[test]
fn a_viewer_client_needs_no_admin_secret() {
    let env = viewer_env("https://gateway.example:9000");
    assert!(env.admin_jwt_secret.is_none());
    assert!(AdminClient::new_viewer_scoped(&env, ["ferrum"]).is_ok());
    assert!(AdminClient::new_scoped(&env, ["ferrum"]).is_err());
}

#[test]
fn export_refusals_name_what_to_check() {
    let api_error = |status| Error::ApiError {
        status,
        message: "refused".to_string(),
    };
    let missing = explain_config_export_refusal(404, "ferrum", api_error(404)).to_string();
    assert!(missing.contains("v0.9.9"), "{missing}");
    let unauthorized = explain_config_export_refusal(401, "ferrum", api_error(401)).to_string();
    assert!(unauthorized.contains("FERRUM_ADMIN_JWT_VIEWER_SECRET"));
    let forbidden = explain_config_export_refusal(403, "ferrum", api_error(403)).to_string();
    assert!(forbidden.contains("FERRUM_ADMIN_JWT_VIEWER_NAMESPACES"));
    let other = explain_config_export_refusal(500, "ferrum", api_error(500));
    assert!(matches!(other, Error::ApiError { status: 500, .. }));
}

/// Serve one canned export to every request and record the request heads.
fn spawn_export_stub(body: String, cached: bool, requests: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0_u8; 8192];
            let mut n = 0;
            while !buf[..n].windows(4).any(|bytes| bytes == b"\r\n\r\n") && n < buf.len() {
                match stream.read(&mut buf[n..]) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => n += read,
                }
            }
            requests
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).to_string());
            let provenance = if cached {
                "x-data-source: cached\r\n"
            } else {
                "x-data-source: database\r\n"
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\n{provenance}content-type: application/json\r\n\
                 connection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    format!("http://{addr}")
}

fn bearer_token(request: &str) -> String {
    request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().trim_start_matches("Bearer ").to_string())
        })
        .expect("authorization header")
}

fn verifies_under(token: &str, secret: &str) -> Option<Value> {
    let validation = Validation::new(Algorithm::HS256);
    let key = DecodingKey::from_secret(secret.as_bytes());
    decode::<Value>(token, &key, &validation)
        .ok()
        .map(|data| data.claims)
}

#[tokio::test]
async fn the_export_is_read_with_a_viewer_token_and_cached_data_is_flagged() {
    let consumers = json!([live_consumer(&[fp('a')], &fp('b'))]);
    let body = document("ferrum", KEY_ID, consumers, json!([])).to_string();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let url = spawn_export_stub(body, true, Arc::clone(&requests));
    let mut env = viewer_env(&url);
    env.admin_jwt_secret = Some(ADMIN_SECRET.to_string());
    let client = AdminClient::new_viewer_scoped(&env, ["ferrum"]).unwrap();

    let endpoint = ExportEndpoint::from_env(&env).unwrap();
    assert_eq!(endpoint.as_str(), format!("{url}/config/export"));
    let export = client.get_config_export(&endpoint, "ferrum").await.unwrap();
    assert!(export.cached);
    assert!(client.served_from_cache());
    assert_eq!(export.fingerprints().resources["Consumer"]["app"].len(), 2);

    let request = requests.lock().unwrap()[0].clone();
    assert!(request.starts_with("GET /config/export "), "{request}");
    let lowered = request.to_ascii_lowercase();
    assert!(lowered.contains("x-ferrum-namespace: ferrum"));
    let token = bearer_token(&request);
    let claims = verifies_under(&token, VIEWER_SECRET).expect("signed with the viewer secret");
    assert_eq!(claims["role"], VIEWER_ROLE);
    assert_eq!(claims["ns"], json!(["ferrum"]));
    assert!(verifies_under(&token, ADMIN_SECRET).is_none());
}

#[test]
fn the_viewer_token_is_sent_only_over_https_or_to_a_loopback_ip() {
    for accepted in [
        "https://gateway.example:9000",
        "https://gateway.example:9000/admin/",
        "http://127.0.0.1:9000",
        "http://127.8.9.10:9000",
        "http://[::1]:9000",
    ] {
        let endpoint = ExportEndpoint::from_gateway_url(accepted).unwrap();
        assert!(endpoint.as_str().ends_with("/config/export"), "{accepted}");
        assert!(!endpoint.as_str().contains("//config"), "{accepted}");
    }
    for refused in [
        "http://gateway.example:9000",
        "http://localhost:9000",
        "http://10.0.0.1:9000",
        "ftp://127.0.0.1:9000",
        "https://user:pass@gateway.example:9000",
        "not a url",
    ] {
        let result = ExportEndpoint::from_gateway_url(refused);
        assert!(result.is_err(), "{refused}");
    }
    let error = ExportEndpoint::from_gateway_url("http://localhost:9000").unwrap_err();
    assert!(error.to_string().contains("literal loopback IP"), "{error}");
}
