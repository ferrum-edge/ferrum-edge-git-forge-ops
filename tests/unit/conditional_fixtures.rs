use gitforgeops::config::GatewayConfig;
use gitforgeops::http_client::conditional::conditional_backup;
use gitforgeops::http_client::{BackupExtras, BackupSnapshot};
use serde_json::{json, Value};

const SECTIONS: [&str; 6] = [
    "proxies",
    "consumers",
    "upstreams",
    "plugin_configs",
    "api_specs",
    "gateway_trust_bundles",
];

pub fn envelope(config: &GatewayConfig, extras: &BackupExtras, namespace_tag: &str) -> Value {
    let mut value = serde_json::to_value(config).unwrap();
    let mut maps = serde_json::Map::new();
    let mut counts = serde_json::Map::new();
    for section in SECTIONS.iter().take(4) {
        let rows = value[*section].as_array().unwrap();
        let tags = rows
            .iter()
            .map(|row| {
                let id = row["id"].as_str().unwrap();
                (id.to_string(), json!(format!("\"{section}-{id}\"")))
            })
            .collect::<serde_json::Map<_, _>>();
        maps.insert(section.to_string(), Value::Object(tags));
        counts.insert(section.to_string(), json!(rows.len()));
    }
    let specs = extras
        .api_specs
        .clone()
        .unwrap_or(json!({"section_version": "2", "items": []}));
    let trust = extras.gateway_trust_bundles.clone().unwrap_or(json!([]));
    counts.insert(
        "api_specs".to_string(),
        json!(specs["items"].as_array().unwrap().len()),
    );
    counts.insert(
        "gateway_trust_bundles".to_string(),
        json!(trust.as_array().unwrap().len()),
    );
    value["api_specs"] = specs;
    value["gateway_trust_bundles"] = trust;
    value["ferrum_version"] = json!("owner-contract-fixture");
    value["exported_at"] = json!("2026-10-04T00:00:00Z");
    value["source"] = json!("database");
    value["counts"] = Value::Object(counts);
    value["conditional"] = json!({"namespace_etag": namespace_tag, "row_etags": maps});
    value
}

pub fn snapshot(config: &GatewayConfig, namespace: &str, extras: &BackupExtras) -> BackupSnapshot {
    conditional_backup(
        &envelope(config, extras, "\"namespace-original\"").to_string(),
        namespace,
        Some("\"namespace-original\""),
        None,
        Some("no-store"),
    )
    .unwrap()
}

pub fn planned_extras(
    config: &GatewayConfig,
    namespace: &str,
    mut extras: BackupExtras,
) -> BackupExtras {
    let evidence = snapshot(config, namespace, &BackupExtras::default()).extras;
    extras.conditional = evidence.conditional;
    extras.consumer_evidence = evidence.consumer_evidence;
    extras
}

pub fn restore_seal(request: &str) -> String {
    let body: Value = serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
    let mut counts = serde_json::Map::new();
    for section in SECTIONS {
        let rows = if section == "api_specs" {
            &body[section]["items"]
        } else {
            &body[section]
        };
        counts.insert(
            section.to_string(),
            json!(rows.as_array().map_or(0, Vec::len)),
        );
    }
    json!({"restored": counts}).to_string()
}

/// Build owner-contract HTTP fixtures without erasing deliberately unmodeled nested fields.
pub fn wire_envelope(raw: &Value, namespace_tag: &str) -> Value {
    let mut value = envelope(
        &GatewayConfig::default(),
        &BackupExtras::default(),
        namespace_tag,
    );
    for section in SECTIONS.iter().take(4) {
        let rows = raw.get(*section).cloned().unwrap_or(json!([]));
        value["counts"][*section] = json!(rows.as_array().unwrap().len());
        let tags = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let id = row["id"].as_str().unwrap();
                (id.to_string(), json!(format!("\"{section}-{id}\"")))
            })
            .collect::<serde_json::Map<_, _>>();
        value[*section] = rows;
        value["conditional"]["row_etags"][*section] = Value::Object(tags);
    }
    for section in ["api_specs", "gateway_trust_bundles"] {
        if let Some(rows) = raw.get(section) {
            value[section] = rows.clone();
            let rows = if section == "api_specs" {
                &rows["items"]
            } else {
                rows
            };
            value["counts"][section] = json!(rows.as_array().unwrap().len());
        }
    }
    value
}
