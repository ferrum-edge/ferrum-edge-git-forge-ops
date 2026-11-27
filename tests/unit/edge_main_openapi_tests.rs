//! Ferrum Edge `main`'s `openapi.yaml` against what GitForgeOps emits.
//!
//! Run by the Edge Main Drift workflow (`.github/workflows/edge-main-drift.yml`)
//! with `EDGE_MAIN_OPENAPI` naming the `openapi.yaml` of the Edge `main` commit
//! under test, and by the lifecycle workflow with the pinned release's; without
//! it the tests have nothing to compare and return early. They fail when:
//!
//! * the top-level writable or read-only `Proxy` / `Upstream` properties differ
//!   from `tests/fixtures/edge-openapi/resource-fields.json` (the pinned
//!   release's lists), so a field Edge `main` adds or removes is visible before
//!   it is released; or
//! * any key GitForgeOps emits for the companion every-field `Proxy`,
//!   `Upstream` and `PluginConfig` resources (the fixtures that exercise every
//!   mirrored field) is not declared by Edge `main`'s schema at its nested
//!   position. Edge refuses unknown keys in every nested proxy and upstream
//!   object, so such a key would be refused by the next Edge release; or
//! * GitForgeOps' copy of an Edge envelope no longer matches the spec: the
//!   `GET /backup` sections both backup decodes accept, the `POST /restore`
//!   body, success seal, response fields and `rollback` / `failure_class`
//!   values, and the `GET /config/export` envelope with its closed Consumer
//!   credential projection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use gitforgeops::config::load_resources;
use gitforgeops::config::schema::{Proxy, Resource};
use serde_json::{Map, Value};

/// Printed once the comparison ran, so the workflow can tell a real pass from
/// a test filter that matched nothing.
const COMPARED_MARKER: &str = "edge-main-openapi: compared";

fn edge_main_openapi() -> Option<Value> {
    let Some(path) = std::env::var_os("EDGE_MAIN_OPENAPI") else {
        eprintln!("skipping the Edge main openapi.yaml comparison: EDGE_MAIN_OPENAPI is unset");
        return None;
    };
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read EDGE_MAIN_OPENAPI {path:?}: {error}"));
    Some(serde_yaml::from_str(&text).expect("EDGE_MAIN_OPENAPI is YAML"))
}

/// Follow `$ref` chains into `components.schemas`.
fn resolve<'a>(schemas: &'a Map<String, Value>, mut schema: &'a Value) -> &'a Value {
    for _ in 0..64 {
        let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
            return schema;
        };
        let name = reference.rsplit('/').next().unwrap_or_default();
        schema = schemas
            .get(name)
            .unwrap_or_else(|| panic!("openapi.yaml has no schema {name}"));
    }
    panic!("openapi.yaml has a $ref cycle");
}

/// What a schema declares: its own properties first, then those of its
/// `allOf` / `oneOf` / `anyOf` members (the first declaration of a name wins,
/// so an `if` / `then` branch that only constrains a property does not
/// replace its declaration), plus `additionalProperties` and `items`.
#[derive(Default)]
struct Shape<'a> {
    properties: BTreeMap<String, &'a Value>,
    additional: Option<&'a Value>,
    items: Option<&'a Value>,
}

fn shape<'a>(schemas: &'a Map<String, Value>, schema: &'a Value, depth: usize) -> Shape<'a> {
    let schema = resolve(schemas, schema);
    let mut out = Shape::default();
    if depth > 32 {
        return out;
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            out.properties.entry(name.clone()).or_insert(property);
        }
    }
    out.additional = schema.get("additionalProperties");
    out.items = schema.get("items");
    for key in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let inner = shape(schemas, member, depth + 1);
            for (name, property) in inner.properties {
                out.properties.entry(name).or_insert(property);
            }
            if out.additional.is_none() {
                out.additional = inner.additional;
            }
            if out.items.is_none() {
                out.items = inner.items;
            }
        }
    }
    out
}

/// Record every key of `value` that `schema` does not declare at its position.
fn undeclared(
    schemas: &Map<String, Value>,
    value: &Value,
    schema: &Value,
    path: &str,
    found: &mut Vec<String>,
) {
    let declared = shape(schemas, schema, 0);
    match value {
        Value::Object(map) => {
            // An object the schema says nothing about (no properties, no
            // additionalProperties) is free-form, like plugin `config`.
            if declared.properties.is_empty() && declared.additional.is_none() {
                return;
            }
            for (key, child) in map {
                if let Some(property) = declared.properties.get(key) {
                    undeclared(schemas, child, property, &format!("{path}.{key}"), found);
                    continue;
                }
                match declared.additional {
                    Some(Value::Bool(true)) => {}
                    Some(additional) if additional.is_object() => undeclared(
                        schemas,
                        child,
                        additional,
                        &format!("{path}.<{key}>"),
                        found,
                    ),
                    _ => found.push(format!("{path}.{key}")),
                }
            }
        }
        Value::Array(items) => {
            if let Some(item_schema) = declared.items {
                for (index, item) in items.iter().enumerate() {
                    undeclared(
                        schemas,
                        item,
                        item_schema,
                        &format!("{path}[{index}]"),
                        found,
                    );
                }
            }
        }
        _ => {}
    }
}

/// Wire shapes the companion Proxy does not take on its own: an enum the
/// mirror serializes as one of several variants is compared in every variant.
/// The fixture sets the exponential retry backoff; a `retry` block that omits
/// `backoff` takes the default fixed backoff, which serializes as
/// `fixed.delay_ms`.
fn proxy_variant_shapes(emitted: &Value) -> Vec<(String, Value)> {
    let mut default_backoff = emitted.clone();
    let retry = default_backoff
        .get_mut("retry")
        .and_then(Value::as_object_mut)
        .expect("the companion Proxy sets a retry block");
    assert!(
        retry.remove("backoff").is_some(),
        "the companion Proxy sets a non-default retry backoff"
    );
    let proxy: Proxy =
        serde_json::from_value(default_backoff).expect("the variant is a valid Proxy");
    let reemitted = serde_json::to_value(proxy).expect("serialize the variant");
    assert!(
        reemitted["retry"]["backoff"].get("fixed").is_some(),
        "the default retry backoff is the fixed variant: {}",
        reemitted["retry"]["backoff"]
    );
    vec![("Proxy(default retry backoff)".to_string(), reemitted)]
}

fn names(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("field list is an array")
        .iter()
        .map(|name| name.as_str().expect("field name").to_string())
        .collect()
}

#[test]
fn edge_main_openapi_declares_every_field_gitforgeops_emits() {
    let Some(spec) = edge_main_openapi() else {
        return;
    };
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("openapi.yaml has components.schemas");
    let mut problems = Vec::new();

    // Top-level fields, both directions, against the pinned release's lists.
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/edge-openapi/resource-fields.json"),
        )
        .expect("read resource-fields.json"),
    )
    .expect("resource-fields.json is JSON");
    for kind in ["Proxy", "Upstream"] {
        let schema = schemas
            .get(kind)
            .unwrap_or_else(|| panic!("openapi.yaml has no {kind} schema"));
        let declared = shape(schemas, schema, 0);
        let (mut writable, mut read_only) = (BTreeSet::new(), BTreeSet::new());
        for (name, property) in &declared.properties {
            let property = resolve(schemas, property);
            if property.get("readOnly") == Some(&Value::Bool(true)) {
                read_only.insert(name.clone());
            } else {
                writable.insert(name.clone());
            }
        }
        let pinned_writable = names(&fixture["schemas"][kind]["properties"]);
        let pinned_read_only = names(&fixture["schemas"][kind]["read_only"]);
        for (label, main, pinned) in [
            ("writable", &writable, &pinned_writable),
            ("read-only", &read_only, &pinned_read_only),
        ] {
            for added in main.difference(pinned) {
                problems.push(format!("{kind}: Edge main adds {label} field `{added}`"));
            }
            for removed in pinned.difference(main) {
                problems.push(format!("{kind}: Edge main drops {label} field `{removed}`"));
            }
        }
    }

    // Every key GitForgeOps emits, at its nested position.
    let companion =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/companion-schema");
    let resources = load_resources(&companion).expect("companion-schema fixtures load");
    let mut checked = BTreeSet::new();
    for (_, resource) in resources {
        let (kind, emitted) = match resource {
            Resource::Proxy { spec } => ("Proxy", serde_json::to_value(spec)),
            Resource::Upstream { spec } => ("Upstream", serde_json::to_value(spec)),
            Resource::PluginConfig { spec } => ("PluginConfig", serde_json::to_value(spec)),
            _ => continue,
        };
        let emitted = emitted.expect("serialize the emitted resource");
        let schema = schemas
            .get(kind)
            .unwrap_or_else(|| panic!("openapi.yaml has no {kind} schema"));
        let mut shapes = vec![(kind.to_string(), emitted.clone())];
        if kind == "Proxy" {
            shapes.extend(proxy_variant_shapes(&emitted));
        }
        for (label, shape) in shapes {
            let mut found = Vec::new();
            undeclared(schemas, &shape, schema, &label, &mut found);
            for path in found {
                problems.push(format!(
                    "{path}: emitted by GitForgeOps, not declared by Edge main"
                ));
            }
        }
        checked.insert(kind);
    }
    assert_eq!(
        checked,
        BTreeSet::from(["PluginConfig", "Proxy", "Upstream"]),
        "the companion fixtures must cover every compared kind"
    );

    println!("{COMPARED_MARKER} ({} difference(s))", problems.len());
    assert!(
        problems.is_empty(),
        "Ferrum Edge main's openapi.yaml differs from what GitForgeOps models:\n{}",
        problems.join("\n")
    );
}

// --- Backup, restore and export envelopes -----------------------------------
//
// GitForgeOps carries its own copies of these Edge contracts, used against a
// live gateway by `apply`, `import` and `diff`. The test below compares each
// copy with the spec under test (Edge `main` in the Edge Main Drift workflow,
// the pinned release in the lifecycle workflow). The lifecycle scenario
// `edge-contract-copies` exercises the same copies against the running
// gateway.

/// The `/restore` response fields this build has reviewed, per status, as
/// `http_client::ApiErrorBody`, `classify_retry` and the restore error mapping
/// use them. Every status and field Edge documents must be listed: a new one
/// may change what a refused or failed restore means, which decides whether
/// apply retries, reports an ambiguous mutation or asks for manual recovery.
///
/// Reviewed against Edge v0.9.21 and Edge `main` at
/// `27fbab8a2906801ebc3f8155ce850e37f8427e60` (1.0.0): the 400 `validation_errors`,
/// the 501 `detail` / `rollback` and the 503 `applied` / `reason` / `rollback`
/// that `main` adds keep a refused restore refused (no retry; a 503 carrying
/// anything beside `failure_class: connectivity` is never replayed).
const RESTORE_RESPONSE_FIELDS: &[(&str, &[&str])] = &[
    ("200", &["restored"]),
    ("202", &[]),
    (
        "400",
        &[
            "applied",
            "audit_unavailable_reason",
            "error",
            "reason",
            "validation_errors",
        ],
    ),
    (
        "401",
        &["applied", "audit_unavailable_reason", "error", "reason"],
    ),
    (
        "403",
        &["applied", "audit_unavailable_reason", "error", "reason"],
    ),
    (
        "408",
        &["applied", "audit_unavailable_reason", "error", "reason"],
    ),
    (
        "409",
        &["api_specs_at_risk", "confirmation_required", "error"],
    ),
    (
        "412",
        &["applied", "audit_unavailable_reason", "error", "reason"],
    ),
    (
        "413",
        &["applied", "audit_unavailable_reason", "error", "reason"],
    ),
    (
        "500",
        &[
            "api_specs_not_restored",
            "api_specs_note",
            "error",
            "failure_class",
            "restore_errors",
            "rollback",
            "rollback_errors",
        ],
    ),
    (
        "501",
        &[
            "applied",
            "audit_unavailable_reason",
            "detail",
            "error",
            "reason",
            "rollback",
        ],
    ),
    (
        "503",
        &[
            "applied",
            "audit_unavailable_reason",
            "error",
            "failure_class",
            "reason",
            "restore_errors",
            "rollback",
        ],
    ),
    (
        "507",
        &[
            "applied",
            "audit_unavailable_reason",
            "durable",
            "error",
            "id",
            "live",
            "profile",
            "reason",
            "recovery_cleanup_authorized",
        ],
    ),
];

/// `/restore` response fields GitForgeOps decides on; each must stay
/// documented at its status.
const RESTORE_RESPONSE_FIELDS_RELIED_ON: &[(&str, &str)] = &[
    ("409", "api_specs_at_risk"),
    ("500", "rollback"),
    ("503", "failure_class"),
];

/// Values of `rollback` (`classify_retry`, `rollback_needs_manual_recovery`,
/// `rollback_left_prior_state` and the restore error mapping) and of
/// `failure_class` this build handles.
const RESTORE_ROLLBACK_VALUES: &[&str] = &[
    "completed",
    "incomplete",
    "not_needed",
    "not_needed_after_intervening_write",
    "skipped_after_intervening_write",
    "unknown_clear_outcome",
    "unknown_outcome",
];
const RESTORE_FAILURE_CLASSES: &[&str] = &["connectivity", "data_integrity"];

/// `POST /restore` body fields GitForgeOps deliberately never sends:
/// `gateway_trust_bundles` (an absent section preserves live trust, which has
/// its own revisioned API) and the backup metadata Edge accepts and ignores.
/// Everything else in `RestoreRequest` must be something `build_restore_body`
/// sends: the serialized `GatewayConfig` plus `api_specs`.
const RESTORE_FIELDS_NEVER_SENT: &[&str] = &[
    "conditional",
    "counts",
    "exported_at",
    "ferrum_version",
    "gateway_trust_bundles",
    "source",
];

/// `GET /config/export` top-level fields `ConfigExport::from_response` reads
/// besides the resource sections (`config_export::SECTIONS`), and those it
/// ignores.
const EXPORT_FIELDS_READ: &[&str] = &["counts", "namespace", "redaction", "source", "version"];
const EXPORT_FIELDS_IGNORED: &[&str] = &["ferrum_version"];
const EXPORT_REDACTION_FIELDS: &[&str] = &[
    "fingerprint_algorithm",
    "fingerprint_key_id",
    "fingerprint_prefix",
];

/// Follow `$ref` chains anywhere in the document (responses, parameters).
fn resolve_local<'a>(spec: &'a Value, mut value: &'a Value) -> &'a Value {
    for _ in 0..64 {
        let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
            return value;
        };
        let pointer = reference
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("openapi.yaml has a non-local $ref {reference}"));
        value = spec
            .pointer(pointer)
            .unwrap_or_else(|| panic!("openapi.yaml has no {reference}"));
    }
    panic!("openapi.yaml has a $ref cycle");
}

fn declared_names(schemas: &Map<String, Value>, schema: &Value) -> BTreeSet<String> {
    shape(schemas, schema, 0).properties.into_keys().collect()
}

fn named<'a>(schemas: &'a Map<String, Value>, name: &str) -> &'a Value {
    schemas
        .get(name)
        .unwrap_or_else(|| panic!("openapi.yaml has no {name} schema"))
}

fn strings(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// Report every name on only one side.
fn compare_sets(
    problems: &mut Vec<String>,
    what: &str,
    documented: &BTreeSet<String>,
    modeled: &BTreeSet<String>,
) {
    for name in documented.difference(modeled) {
        problems.push(format!(
            "{what}: Edge documents `{name}`, GitForgeOps does not handle it"
        ));
    }
    for name in modeled.difference(documented) {
        problems.push(format!(
            "{what}: GitForgeOps handles `{name}`, Edge no longer documents it"
        ));
    }
}

/// `enum` / `const` values of a string property, if it restricts them.
fn enum_values(schemas: &Map<String, Value>, property: &Value) -> BTreeSet<String> {
    let property = resolve(schemas, property);
    let mut values = BTreeSet::new();
    if let Some(constant) = property.get("const").and_then(Value::as_str) {
        values.insert(constant.to_string());
    }
    for value in property
        .get("enum")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(value) = value.as_str() {
            values.insert(value.to_string());
        }
    }
    values
}

/// The credential projection of `project_consumer_for_export`, read off the
/// function itself: every credential type and entry field it keeps when given
/// every known type (and one unknown one), each entry carrying an extra field.
fn gitforgeops_export_projection() -> BTreeMap<String, BTreeSet<String>> {
    use gitforgeops::config::schema::{Consumer, KNOWN_CREDENTIAL_TYPES};
    let mut credentials = Map::new();
    for credential_type in KNOWN_CREDENTIAL_TYPES
        .iter()
        .copied()
        .chain(["custom_type"])
    {
        credentials.insert(
            credential_type.to_string(),
            serde_json::json!([{
                "key": "k", "secret": "s", "password": "p", "identity": "CN=client",
                "legacy_extra": "x"
            }]),
        );
    }
    let consumer: Consumer = serde_json::from_value(serde_json::json!({
        "id": "projection", "username": "projection", "credentials": credentials,
    }))
    .expect("a Consumer with every credential type");
    let projected = gitforgeops::config_export::project_consumer_for_export(&consumer);
    projected
        .credentials
        .iter()
        .map(|(credential_type, entries)| {
            let fields = entries
                .as_array()
                .expect("projected credentials are arrays")
                .iter()
                .flat_map(|entry| entry.as_object().expect("entry object").keys().cloned())
                .collect();
            (credential_type.clone(), fields)
        })
        .collect()
}

#[test]
fn edge_main_openapi_matches_the_backup_restore_and_export_copies() {
    use gitforgeops::config::schema::{GatewayConfig, KNOWN_CREDENTIAL_TYPES};
    use gitforgeops::config_export::{
        FINGERPRINTED_CREDENTIAL_FIELDS, FINGERPRINT_ALGORITHM, FINGERPRINT_PREFIX,
        HIDDEN_CREDENTIALS_FIELD, SECTIONS,
    };
    use gitforgeops::http_client::conditional::{CONDITIONAL_BACKUP_FIELDS, RESTORE_SEAL_SECTIONS};
    use gitforgeops::http_client::BACKUP_TOP_LEVEL_FIELDS;

    let Some(spec) = edge_main_openapi() else {
        return;
    };
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("openapi.yaml has components.schemas");
    let mut problems = Vec::new();

    // `GET /backup`: the plain decode's allow-list (without GitForgeOps' own
    // `resource_counts`, plus the `conditional` metadata it lifts out first)
    // and the conditional decode's allow-list.
    let backup = declared_names(schemas, named(schemas, "BackupResponse"));
    let mut plain: BTreeSet<String> = strings(BACKUP_TOP_LEVEL_FIELDS);
    plain.remove("resource_counts");
    plain.insert("conditional".to_string());
    compare_sets(
        &mut problems,
        "BackupResponse (GET /backup decode)",
        &backup,
        &plain,
    );
    compare_sets(
        &mut problems,
        "BackupResponse (GET /backup?conditional=true decode)",
        &backup,
        &strings(CONDITIONAL_BACKUP_FIELDS),
    );
    let api_specs = named(schemas, "ApiSpecsBackupSection");
    compare_sets(
        &mut problems,
        "ApiSpecsBackupSection",
        &declared_names(schemas, api_specs),
        &strings(&["items", "section_version"]),
    );
    if let Some(version) = shape(schemas, api_specs, 0)
        .properties
        .get("section_version")
    {
        for value in enum_values(schemas, version) {
            if value != "2" {
                problems.push(format!(
                    "ApiSpecsBackupSection.section_version: Edge allows {value:?}; the \
                     conditional decode accepts only \"2\""
                ));
            }
        }
    }
    compare_sets(
        &mut problems,
        "ConditionalBackupMetadata",
        &declared_names(schemas, named(schemas, "ConditionalBackupMetadata")),
        &strings(&["namespace_etag", "row_etags"]),
    );

    // `POST /restore`: what `build_restore_body` sends plus what it never sends.
    let restore = declared_names(schemas, named(schemas, "RestoreRequest"));
    let sent = serde_json::to_value(GatewayConfig::default()).expect("serialize GatewayConfig");
    let mut handled: BTreeSet<String> = sent
        .as_object()
        .expect("GatewayConfig serializes as an object")
        .keys()
        .cloned()
        .collect();
    handled.insert("api_specs".to_string());
    handled.extend(strings(RESTORE_FIELDS_NEVER_SENT));
    compare_sets(&mut problems, "RestoreRequest", &restore, &handled);

    // The success response's count seal (`conditional::RESTORE_SEAL_SECTIONS`).
    let restore_response = shape(schemas, named(schemas, "RestoreResponse"), 0);
    match restore_response.properties.get("restored") {
        Some(seal) => compare_sets(
            &mut problems,
            "RestoreResponse.restored (count seal)",
            &declared_names(schemas, seal),
            &strings(RESTORE_SEAL_SECTIONS),
        ),
        None => problems.push("RestoreResponse: Edge no longer documents `restored`".to_string()),
    }

    // `/restore` responses, status by status.
    let reviewed: BTreeMap<&str, BTreeSet<String>> = RESTORE_RESPONSE_FIELDS
        .iter()
        .map(|(status, fields)| (*status, strings(fields)))
        .collect();
    let responses = spec["paths"]["/restore"]["post"]["responses"]
        .as_object()
        .expect("openapi.yaml documents POST /restore responses");
    let mut documented_fields: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (status, response) in responses {
        let response = resolve_local(&spec, response);
        let fields = response
            .pointer("/content/application~1json/schema")
            .map(|schema| {
                let declared = shape(schemas, schema, 0);
                for (name, property) in &declared.properties {
                    let allowed: &[&str] = match name.as_str() {
                        "rollback" => RESTORE_ROLLBACK_VALUES,
                        "failure_class" => RESTORE_FAILURE_CLASSES,
                        _ => continue,
                    };
                    // A decision marker must stay a closed set: an unbounded
                    // string could carry a value GitForgeOps never classified.
                    let values = enum_values(schemas, property);
                    if values.is_empty() {
                        problems.push(format!(
                            "POST /restore {status}: `{name}` is no longer a closed set of \
                             values, so GitForgeOps cannot have classified every one"
                        ));
                    }
                    for value in values {
                        if !allowed.contains(&value.as_str()) {
                            problems.push(format!(
                                "POST /restore {status}: Edge documents `{name}: {value}`, which \
                                 GitForgeOps does not handle"
                            ));
                        }
                    }
                }
                declared.properties.into_keys().collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        match reviewed.get(status.as_str()) {
            None => problems.push(format!(
                "POST /restore: Edge documents status {status}, which GitForgeOps has not reviewed"
            )),
            Some(known) => {
                for field in fields.difference(known) {
                    problems.push(format!(
                        "POST /restore {status}: Edge documents `{field}`, which GitForgeOps has \
                         not reviewed"
                    ));
                }
            }
        }
        documented_fields.insert(status.clone(), fields);
    }
    for (status, field) in RESTORE_RESPONSE_FIELDS_RELIED_ON {
        if !documented_fields
            .get(*status)
            .is_some_and(|fields| fields.contains(*field))
        {
            problems.push(format!(
                "POST /restore {status}: GitForgeOps decides on `{field}`, which Edge no longer \
                 documents"
            ));
        }
    }

    // `GET /config/export` and its closed Consumer projection.
    let export_schema = named(schemas, "ConfigExportResponse");
    let mut export_fields = strings(EXPORT_FIELDS_READ);
    export_fields.extend(strings(EXPORT_FIELDS_IGNORED));
    export_fields.extend(SECTIONS.iter().map(|(section, _)| section.to_string()));
    let export = shape(schemas, export_schema, 0);
    compare_sets(
        &mut problems,
        "ConfigExportResponse",
        &export.properties.keys().cloned().collect(),
        &export_fields,
    );
    if let Some(redaction) = export.properties.get("redaction") {
        let redaction = shape(schemas, redaction, 0);
        compare_sets(
            &mut problems,
            "ConfigExportResponse.redaction",
            &redaction.properties.keys().cloned().collect(),
            &strings(EXPORT_REDACTION_FIELDS),
        );
        for (field, expected) in [
            ("fingerprint_algorithm", FINGERPRINT_ALGORITHM),
            ("fingerprint_prefix", FINGERPRINT_PREFIX),
        ] {
            if let Some(property) = redaction.properties.get(field) {
                let values = enum_values(schemas, property);
                if values != BTreeSet::from([expected.to_string()]) {
                    problems.push(format!(
                        "ConfigExportResponse.redaction.{field}: Edge documents {values:?}, \
                         GitForgeOps understands only {expected:?}"
                    ));
                }
            }
        }
    }
    if let Some(counts) = export.properties.get("counts") {
        compare_sets(
            &mut problems,
            "ConfigExportResponse.counts",
            &declared_names(schemas, counts),
            &SECTIONS
                .iter()
                .map(|(section, _)| section.to_string())
                .collect(),
        );
    }
    let consumer_export = declared_names(schemas, named(schemas, "ConsumerExport"));
    for field in [HIDDEN_CREDENTIALS_FIELD, "credentials"] {
        if !consumer_export.contains(field) {
            problems.push(format!(
                "ConsumerExport: GitForgeOps reads `{field}`, which Edge no longer documents"
            ));
        }
    }
    let fingerprinted = shape(
        schemas,
        named(schemas, "ConsumerCredentialsFingerprinted"),
        0,
    );
    if fingerprinted.additional != Some(&Value::Bool(false)) {
        problems.push(
            "ConsumerCredentialsFingerprinted: Edge no longer omits unknown credential types; \
             project_consumer_for_export drops them"
                .to_string(),
        );
    }
    let mut edge_projection: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut edge_fingerprinted: BTreeSet<(String, String)> = BTreeSet::new();
    for (credential_type, property) in &fingerprinted.properties {
        if **property == Value::Bool(false) {
            continue;
        }
        let Some(items) = shape(schemas, property, 0).items else {
            problems.push(format!(
                "ConsumerCredentialsFingerprinted.{credential_type}: not an array of entries"
            ));
            continue;
        };
        let entry = shape(schemas, items, 0);
        if entry.additional != Some(&Value::Bool(false)) {
            problems.push(format!(
                "ConsumerCredentialsFingerprinted.{credential_type}: entries are no longer closed"
            ));
        }
        for (field, field_schema) in &entry.properties {
            let reference = field_schema.get("$ref").and_then(Value::as_str);
            if reference.is_some_and(|reference| reference.ends_with("/CredentialFingerprint")) {
                edge_fingerprinted.insert((credential_type.clone(), field.clone()));
            }
        }
        edge_projection.insert(
            credential_type.clone(),
            entry.properties.into_keys().collect(),
        );
    }
    let projection = gitforgeops_export_projection();
    if edge_projection != projection {
        problems.push(format!(
            "ConsumerCredentialsFingerprinted: Edge's export keeps {edge_projection:?}; \
             project_consumer_for_export keeps {projection:?}"
        ));
    }
    let fingerprint_fields: BTreeSet<(String, String)> = FINGERPRINTED_CREDENTIAL_FIELDS
        .iter()
        .map(|(credential_type, field)| (credential_type.to_string(), field.to_string()))
        .collect();
    if edge_fingerprinted != fingerprint_fields {
        problems.push(format!(
            "ConsumerCredentialsFingerprinted: Edge fingerprints {edge_fingerprinted:?}; \
             FINGERPRINTED_CREDENTIAL_FIELDS lists {fingerprint_fields:?}"
        ));
    }
    compare_sets(
        &mut problems,
        "ConsumerCredentialsInput (credential types)",
        &declared_names(schemas, named(schemas, "ConsumerCredentialsInput")),
        &strings(&KNOWN_CREDENTIAL_TYPES),
    );

    println!(
        "{COMPARED_MARKER} envelopes ({} difference(s))",
        problems.len()
    );
    assert!(
        problems.is_empty(),
        "Ferrum Edge's openapi.yaml differs from GitForgeOps' backup, restore and export \
         copies:\n{}",
        problems.join("\n")
    );
}
