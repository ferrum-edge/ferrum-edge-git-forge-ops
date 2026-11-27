//! Ferrum Edge `main`'s `openapi.yaml` against what GitForgeOps emits.
//!
//! Run by the Edge Main Drift workflow (`.github/workflows/edge-main-drift.yml`)
//! with `EDGE_MAIN_OPENAPI` naming the `openapi.yaml` of the Edge `main` commit
//! under test; without it the test has nothing to compare and returns early.
//! It fails when:
//!
//! * the top-level writable or read-only `Proxy` / `Upstream` properties differ
//!   from `tests/fixtures/edge-openapi/resource-fields.json` (the pinned
//!   release's lists), so a field Edge `main` adds or removes is visible before
//!   it is released; or
//! * any key GitForgeOps emits for the companion every-field `Proxy`,
//!   `Upstream` and `PluginConfig` resources (the fixtures that exercise every
//!   mirrored field) is not declared by Edge `main`'s schema at its nested
//!   position. Edge refuses unknown keys in every nested proxy and upstream
//!   object, so such a key would be refused by the next Edge release.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use gitforgeops::config::load_resources;
use gitforgeops::config::schema::Resource;
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
        let mut found = Vec::new();
        undeclared(schemas, &emitted, schema, kind, &mut found);
        for path in found {
            problems.push(format!(
                "{path}: emitted by GitForgeOps, not declared by Edge main"
            ));
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
