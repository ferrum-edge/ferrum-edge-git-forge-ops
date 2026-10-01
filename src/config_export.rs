//! Read-only drift detection through Ferrum Edge's `GET /config/export`.
//!
//! `GET /backup` is `admin`-only because it releases raw credentials. Ferrum
//! Edge v0.9.9 added `GET /config/export`: the same authoritative, namespace
//! scoped load, readable by `viewer` (including tokens signed with the
//! gateway's `FERRUM_ADMIN_JWT_VIEWER_SECRET`, which the gateway caps at
//! `viewer` whatever the token claims). When `FERRUM_ADMIN_JWT_VIEWER_SECRET`
//! is configured, `diff` reads live state from the export with that
//! credential instead of `/backup` with the admin one.
//!
//! # What the export can and cannot prove
//!
//! Every value the gateway's viewer projection withholds — Consumer `keyauth`
//! keys and `jwt` / `hmac_auth` secrets, plugin-config secrets and
//! credential-bearing URLs, URL userinfo in a Proxy or Upstream, the Consul
//! token — arrives as `hmac-sha256:<64 hex>`. The MAC key is derived from the
//! gateway's *primary* admin secret, never from the viewer secret, so a
//! viewer-credential reader **cannot compute the fingerprint of the
//! repository's value**. Edge documents this as intentional, and this module
//! does not try to reproduce the computation. Consequences:
//!
//! - A fingerprinted field cannot be compared with the repository. Where the
//!   repository declares a value at the same location, [`ConfigExport::live_view`]
//!   substitutes the declared value into the live view (so the field is not
//!   reported as drift it cannot be) and records the site in
//!   [`ExportLiveView::uncompared`]. Where the repository declares nothing
//!   there, the fingerprint stays and the structural difference is reported.
//! - Fingerprint equality only shows that a stored value is **unchanged
//!   between two exports** under one gateway key. [`FingerprintBaseline`]
//!   records an export's fingerprints; a later run compares against it and
//!   reports each declared resource's secret that changed, appeared or
//!   disappeared since. It cannot say whether the value matches the
//!   repository, and a baseline taken from a gateway that had already
//!   drifted carries that drift forward.
//! - `redaction.fingerprint_key_id` changes when the gateway's
//!   `FERRUM_ADMIN_JWT_SECRET` rotates (and on every restart of a gateway
//!   without one). Fingerprints under different key ids are not comparable;
//!   [`FingerprintBaseline::compare`] says so instead of reporting drift.
//! - Consumer `basicauth` (and any custom credential type) is omitted from the
//!   export. Each consumer instead carries one
//!   `hidden_credentials_fingerprint` over all of them, which only a baseline
//!   can use.
//! - The export strips `api_spec_id`, so spec-owned rows cannot be told apart
//!   from other live rows on this path.
//!
//! `X-Data-Source: cached` (or `source: cached` in the body) marks the export
//! as possibly stale; callers must not report "no drift" from it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::schema::Consumer;
use crate::config::GatewayConfig;
use crate::error::Error;
use crate::http_client::{BackupSnapshot, SealStrictness};

/// Admin API path of the read-only export.
pub const CONFIG_EXPORT_PATH: &str = "/config/export";

/// `redaction.fingerprint_algorithm` this build understands.
pub const FINGERPRINT_ALGORITHM: &str = "hmac-sha256";

/// Prefix of every fingerprint string in an export.
pub const FINGERPRINT_PREFIX: &str = "hmac-sha256:";

/// Field Edge adds to each exported Consumer: one fingerprint over the
/// credential types the export omits (`basicauth`, custom types).
pub const HIDDEN_CREDENTIALS_FIELD: &str = "hidden_credentials_fingerprint";

/// `role` claim minted into viewer-credential tokens. The gateway caps a
/// viewer-secret token at `viewer` regardless; claiming more would only be
/// misleading in its logs.
pub const VIEWER_ROLE: &str = "viewer";

/// `format` value of a fingerprint baseline file.
pub const BASELINE_FORMAT: &str = "gitforgeops/config-export-fingerprints/v1";

/// Export section name and the repository kind it holds.
const SECTIONS: [(&str, &str); 4] = [
    ("proxies", "Proxy"),
    ("consumers", "Consumer"),
    ("plugin_configs", "PluginConfig"),
    ("upstreams", "Upstream"),
];

/// Credential types whose secret field the export fingerprints, one entry per
/// stored credential, mirroring Edge's closed Consumer projection.
const FINGERPRINTED_CREDENTIAL_FIELDS: [(&str, &str); 3] = [
    ("keyauth", "key"),
    ("jwt", "secret"),
    ("hmac_auth", "secret"),
];

/// Fingerprint per JSON pointer for one resource.
pub type ResourceFingerprints = BTreeMap<String, String>;

/// [`ResourceFingerprints`] per resource id, for one kind.
pub type KindFingerprints = BTreeMap<String, ResourceFingerprints>;

/// True for an `hmac-sha256:<64 lowercase hex>` fingerprint.
pub fn is_fingerprint(value: &str) -> bool {
    value
        .strip_prefix(FINGERPRINT_PREFIX)
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

/// True for a 16-hex-digit `redaction.fingerprint_key_id`.
pub fn is_fingerprint_key_id(value: &str) -> bool {
    is_lower_hex(value, 16)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    value.len() == len && value.bytes().all(lower_hex)
}

/// One resource row of an export, still in its wire form.
#[derive(Debug, Clone)]
struct ExportRow {
    section: &'static str,
    kind: &'static str,
    id: String,
    body: Value,
}

/// One namespace's `GET /config/export` document.
#[derive(Debug, Clone)]
pub struct ConfigExport {
    pub namespace: String,
    /// `X-Data-Source: cached` or `source: cached`: the gateway served its
    /// in-memory snapshot, which may be older than the database. Edge also
    /// serves it when another export already holds the database load.
    pub cached: bool,
    /// Keyed label of the gateway's fingerprint key.
    pub fingerprint_key_id: String,
    pub ferrum_version: Option<String>,
    /// Set when `counts` disagrees with the document. Advisory, as for a
    /// read-only `/backup` comparison.
    pub count_seal_notice: Option<String>,
    version: String,
    rows: Vec<ExportRow>,
}

impl ConfigExport {
    /// Parse and check one export body.
    ///
    /// Refuses a document for another namespace, a resource with a missing
    /// or foreign namespace, a missing section, and a fingerprint scheme this
    /// build does not understand. `header_cached` is the response's
    /// `X-Data-Source: cached`; the body's `source` is honored too, so either
    /// marks the export stale.
    pub fn from_response(
        body: &str,
        namespace: &str,
        header_cached: bool,
    ) -> crate::error::Result<Self> {
        let value: Value = serde_json::from_str(body)
            .map_err(|e| Error::HttpClient(format!("GET {CONFIG_EXPORT_PATH}: {e}")))?;
        let Value::Object(mut document) = value else {
            return Err(Error::Config(format!(
                "GET {CONFIG_EXPORT_PATH} did not return a JSON object"
            )));
        };

        let exported_namespace = document.get("namespace").and_then(Value::as_str);
        if exported_namespace != Some(namespace) {
            return Err(Error::BackupNamespace(format!(
                "configuration export for namespace {namespace:?} reported namespace {:?}; \
                 refusing the snapshot",
                exported_namespace.unwrap_or("<missing>")
            )));
        }

        let redaction = document.get("redaction");
        let redaction_field = |field: &str| {
            redaction
                .and_then(|r| r.get(field))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        let algorithm = redaction_field("fingerprint_algorithm");
        let prefix = redaction_field("fingerprint_prefix");
        if algorithm.as_deref() != Some(FINGERPRINT_ALGORITHM)
            || prefix.as_deref() != Some(FINGERPRINT_PREFIX)
        {
            return Err(Error::Config(format!(
                "GET {CONFIG_EXPORT_PATH} for namespace {namespace:?} uses fingerprint algorithm \
                 {:?} with prefix {:?}; this build understands only {FINGERPRINT_ALGORITHM:?} \
                 with prefix {FINGERPRINT_PREFIX:?}",
                algorithm.as_deref().unwrap_or("<missing>"),
                prefix.as_deref().unwrap_or("<missing>")
            )));
        }
        let fingerprint_key_id = redaction_field("fingerprint_key_id").unwrap_or_default();
        if !is_fingerprint_key_id(&fingerprint_key_id) {
            return Err(Error::Config(format!(
                "GET {CONFIG_EXPORT_PATH} for namespace {namespace:?} has no valid \
                 redaction.fingerprint_key_id (expected 16 lowercase hex digits)"
            )));
        }

        let body_cached = document
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|source| source.eq_ignore_ascii_case("cached"));
        let ferrum_version = document
            .get("ferrum_version")
            .and_then(Value::as_str)
            .map(str::to_string);
        let version = document
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("1")
            .to_string();

        let mut rows = Vec::new();
        for (section, kind) in SECTIONS {
            let entries = match document.remove(section) {
                Some(Value::Array(entries)) => entries,
                Some(_) => {
                    return Err(Error::Config(format!(
                        "GET {CONFIG_EXPORT_PATH}: `{section}` is not an array"
                    )))
                }
                None => {
                    return Err(Error::Config(format!(
                        "GET {CONFIG_EXPORT_PATH}: required section `{section}` is missing"
                    )))
                }
            };
            for entry in entries {
                let row_namespace = entry.get("namespace").and_then(Value::as_str);
                let row_id = entry.get("id").and_then(Value::as_str);
                let id = match (row_namespace, row_id) {
                    (Some(row_namespace), Some(id)) if row_namespace == namespace => id.to_string(),
                    (_, id) => {
                        return Err(Error::BackupNamespace(format!(
                            "configuration export for namespace {namespace:?} returned {section} \
                             {:?} with a missing or foreign namespace or id; refusing the snapshot",
                            id.unwrap_or("?")
                        )))
                    }
                };
                rows.push(ExportRow {
                    section,
                    kind,
                    id,
                    body: entry,
                });
            }
        }
        let seal_notice = count_seal_notice(document.get("counts"), &rows);

        Ok(Self {
            namespace: namespace.to_string(),
            cached: header_cached || body_cached,
            fingerprint_key_id,
            ferrum_version,
            count_seal_notice: seal_notice,
            version,
            rows,
        })
    }

    /// Every fingerprint in this export, by kind, id and JSON pointer (its
    /// location inside the exported resource). Every exported resource has an
    /// entry, even one with no fingerprint, so a baseline can tell "no secret"
    /// from "resource not seen".
    pub fn fingerprints(&self) -> NamespaceFingerprints {
        let mut resources: BTreeMap<String, KindFingerprints> = BTreeMap::new();
        for row in &self.rows {
            let mut sites = ResourceFingerprints::new();
            collect_fingerprints(&row.body, &mut String::new(), &mut sites);
            resources
                .entry(row.kind.to_string())
                .or_default()
                .insert(row.id.clone(), sites);
        }
        NamespaceFingerprints {
            fingerprint_key_id: self.fingerprint_key_id.clone(),
            resources,
        }
    }

    /// The live configuration for comparison with `desired`.
    ///
    /// Each fingerprint at a location where the repository (after
    /// [`project_consumer_for_export`]) declares a value is replaced by that
    /// value and listed in [`ExportLiveView::uncompared`]: the field cannot be
    /// compared, and reporting it as drift would be false. Fingerprints the
    /// repository has no value for stay, so the difference is reported. The
    /// consumers' [`HIDDEN_CREDENTIALS_FIELD`] is removed; it is listed as
    /// uncompared when the repository declares `basicauth` for that consumer.
    pub fn live_view(&self, desired: &GatewayConfig) -> crate::error::Result<ExportLiveView> {
        let desired_rows = desired_comparison_rows(desired, &self.namespace)?;
        let declares_hidden: BTreeSet<&str> = desired
            .consumers
            .iter()
            .filter(|consumer| consumer.namespace == self.namespace)
            .filter(|consumer| {
                consumer
                    .credentials
                    .keys()
                    .any(|credential_type| !exports_credential_type(credential_type))
            })
            .map(|consumer| consumer.id.as_str())
            .collect();

        let mut sections: BTreeMap<&'static str, Vec<Value>> = BTreeMap::new();
        let mut uncompared = Vec::new();
        for row in &self.rows {
            let mut body = row.body.clone();
            if row.kind == "Consumer" {
                let removed = body
                    .as_object_mut()
                    .and_then(|object| object.remove(HIDDEN_CREDENTIALS_FIELD))
                    .is_some();
                if removed && declares_hidden.contains(row.id.as_str()) {
                    uncompared.push(self.site(row, &format!("/{HIDDEN_CREDENTIALS_FIELD}")));
                }
            }
            if let Some(expected) = desired_rows.get(&(row.kind, row.id.clone())) {
                let mut substituted = Vec::new();
                substitute_fingerprints(&mut body, expected, &mut String::new(), &mut substituted);
                uncompared.extend(substituted.iter().map(|pointer| self.site(row, pointer)));
            }
            sections.entry(row.section).or_default().push(body);
        }

        let mut document = serde_json::Map::new();
        document.insert("version".to_string(), Value::String(self.version.clone()));
        for (section, _) in SECTIONS {
            let rows = sections.remove(section).unwrap_or_default();
            document.insert(section.to_string(), Value::Array(rows));
        }
        let snapshot = BackupSnapshot::from_value_with_strictness(
            Value::Object(document),
            SealStrictness::Advisory,
        )?;
        uncompared.sort();
        Ok(ExportLiveView {
            actual: snapshot.config,
            uncompared,
        })
    }

    fn site(&self, row: &ExportRow, pointer: &str) -> FingerprintSite {
        FingerprintSite {
            kind: row.kind.to_string(),
            namespace: self.namespace.clone(),
            id: row.id.clone(),
            pointer: pointer.to_string(),
        }
    }
}

/// A live view built from an export, plus what it could not compare.
#[derive(Debug, Clone)]
pub struct ExportLiveView {
    pub actual: GatewayConfig,
    /// Fingerprinted fields on declared resources whose live value could not
    /// be compared with the repository's value.
    pub uncompared: Vec<FingerprintSite>,
}

/// One fingerprinted field. Every member comes from the gateway; sanitize
/// before printing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FingerprintSite {
    pub kind: String,
    pub namespace: String,
    pub id: String,
    /// JSON pointer of the field inside the exported resource.
    pub pointer: String,
}

/// The repository Consumer as the export projects a live one: only
/// `keyauth[].key`, `jwt[].secret`, `hmac_auth[].secret` and
/// `mtls_auth[].identity` survive; `basicauth` and every other field of a
/// credential entry are dropped. Comparing an unprojected Consumer would
/// report every omitted field as drift.
pub fn project_consumer_for_export(consumer: &Consumer) -> Consumer {
    let mut projected = consumer.clone();
    projected.credentials.clear();
    for (credential_type, field) in FINGERPRINTED_CREDENTIAL_FIELDS {
        let Some(value) = consumer.credentials.get(credential_type) else {
            continue;
        };
        let entries: Vec<Value> = credential_entries(value)
            .into_iter()
            .map(|entry| {
                let mut projected_entry = serde_json::Map::new();
                projected_entry.insert(
                    field.to_string(),
                    entry.get(field).cloned().unwrap_or(Value::Null),
                );
                Value::Object(projected_entry)
            })
            .collect();
        if !entries.is_empty() {
            projected
                .credentials
                .insert(credential_type.to_string(), Value::Array(entries));
        }
    }
    if let Some(value) = consumer.credentials.get("mtls_auth") {
        let entries: Vec<Value> = credential_entries(value)
            .into_iter()
            .filter_map(|entry| entry.get("identity").and_then(Value::as_str))
            .filter(|identity| !identity.trim().is_empty())
            .map(|identity| serde_json::json!({ "identity": identity }))
            .collect();
        if !entries.is_empty() {
            projected
                .credentials
                .insert("mtls_auth".to_string(), Value::Array(entries));
        }
    }
    projected
}

/// `desired` with every Consumer projected by [`project_consumer_for_export`],
/// for comparison with an [`ExportLiveView`].
pub fn project_desired_for_export(desired: &GatewayConfig) -> GatewayConfig {
    let mut projected = desired.clone();
    for consumer in &mut projected.consumers {
        *consumer = project_consumer_for_export(consumer);
    }
    projected
}

fn exports_credential_type(credential_type: &str) -> bool {
    let fingerprinted = FINGERPRINTED_CREDENTIAL_FIELDS.map(|(exported, _)| exported);
    credential_type == "mtls_auth" || fingerprinted.contains(&credential_type)
}

/// Object entries of one credential value: an array's objects, or a legacy
/// single object (Edge emits it at index 0).
fn credential_entries(value: &Value) -> Vec<&serde_json::Map<String, Value>> {
    match value {
        Value::Array(entries) => entries.iter().filter_map(Value::as_object).collect(),
        Value::Object(entry) => vec![entry],
        _ => Vec::new(),
    }
}

/// Desired resources of one namespace, serialized for pointer lookups.
fn desired_comparison_rows(
    desired: &GatewayConfig,
    namespace: &str,
) -> crate::error::Result<HashMap<(&'static str, String), Value>> {
    let desired = crate::config::filter_config_by_namespace(desired, namespace);
    let mut rows = HashMap::new();
    for proxy in &desired.proxies {
        rows.insert(("Proxy", proxy.id.clone()), serde_json::to_value(proxy)?);
    }
    for consumer in &desired.consumers {
        let projected = project_consumer_for_export(consumer);
        rows.insert(
            ("Consumer", consumer.id.clone()),
            serde_json::to_value(&projected)?,
        );
    }
    for plugin in &desired.plugin_configs {
        rows.insert(
            ("PluginConfig", plugin.id.clone()),
            serde_json::to_value(plugin)?,
        );
    }
    for upstream in &desired.upstreams {
        rows.insert(
            ("Upstream", upstream.id.clone()),
            serde_json::to_value(upstream)?,
        );
    }
    Ok(rows)
}

/// Append one RFC 6901 reference token.
fn push_pointer_segment(pointer: &mut String, segment: &str) {
    pointer.push('/');
    for ch in segment.chars() {
        match ch {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            other => pointer.push(other),
        }
    }
}

fn collect_fingerprints(value: &Value, pointer: &mut String, out: &mut ResourceFingerprints) {
    match value {
        Value::String(text) if is_fingerprint(text) => {
            out.insert(pointer.clone(), text.clone());
        }
        Value::Object(map) => {
            for (key, child) in map {
                let len = pointer.len();
                push_pointer_segment(pointer, key);
                collect_fingerprints(child, pointer, out);
                pointer.truncate(len);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let len = pointer.len();
                push_pointer_segment(pointer, &index.to_string());
                collect_fingerprints(child, pointer, out);
                pointer.truncate(len);
            }
        }
        _ => {}
    }
}

/// Replace each fingerprint in `live` that has a counterpart in `desired` with
/// that counterpart, recording the pointer.
fn substitute_fingerprints(
    live: &mut Value,
    desired: &Value,
    pointer: &mut String,
    substituted: &mut Vec<String>,
) {
    if live.as_str().is_some_and(is_fingerprint) {
        if let Some(expected) = desired.pointer(pointer) {
            *live = expected.clone();
            substituted.push(pointer.clone());
        }
        return;
    }
    match live {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let len = pointer.len();
                push_pointer_segment(pointer, key);
                substitute_fingerprints(child, desired, pointer, substituted);
                pointer.truncate(len);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                let len = pointer.len();
                push_pointer_segment(pointer, &index.to_string());
                substitute_fingerprints(child, desired, pointer, substituted);
                pointer.truncate(len);
            }
        }
        _ => {}
    }
}

fn count_seal_notice(counts: Option<&Value>, rows: &[ExportRow]) -> Option<String> {
    let counts = counts?;
    let mut mismatches = Vec::new();
    for (section, kind) in SECTIONS {
        let Some(sealed) = counts.get(section).and_then(Value::as_u64) else {
            continue;
        };
        let actual = rows.iter().filter(|row| row.kind == kind).count() as u64;
        if sealed != actual {
            mismatches.push(format!("{section}: sealed {sealed}, received {actual}"));
        }
    }
    (!mismatches.is_empty()).then(|| mismatches.join("; "))
}

/// Fingerprints of one namespace's export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFingerprints {
    pub fingerprint_key_id: String,
    /// Kind → id → JSON pointer → fingerprint.
    pub resources: BTreeMap<String, KindFingerprints>,
}

/// Fingerprints recorded from earlier exports, for detecting secret changes
/// between two exports. Holds keyed fingerprints only, never a value. Keep it
/// outside the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintBaseline {
    pub format: String,
    pub namespaces: BTreeMap<String, NamespaceFingerprints>,
}

impl Default for FingerprintBaseline {
    fn default() -> Self {
        Self {
            format: BASELINE_FORMAT.to_string(),
            namespaces: BTreeMap::new(),
        }
    }
}

impl FingerprintBaseline {
    /// Parse and check a baseline document.
    pub fn from_json(text: &str) -> crate::error::Result<Self> {
        let baseline: Self = serde_json::from_str(text)
            .map_err(|e| Error::Config(format!("fingerprint baseline is not valid: {e}")))?;
        if baseline.format != BASELINE_FORMAT {
            return Err(Error::Config(format!(
                "fingerprint baseline format {:?} is not supported; expected {BASELINE_FORMAT:?}",
                baseline.format
            )));
        }
        for (namespace, entry) in &baseline.namespaces {
            if !is_fingerprint_key_id(&entry.fingerprint_key_id) {
                return Err(Error::Config(format!(
                    "fingerprint baseline namespace {namespace:?}: invalid fingerprint_key_id"
                )));
            }
            for (kind, resources) in &entry.resources {
                if !SECTIONS.iter().any(|(_, known)| *known == kind.as_str()) {
                    return Err(Error::Config(format!(
                        "fingerprint baseline namespace {namespace:?} names unknown kind {kind:?}"
                    )));
                }
                let malformed = resources
                    .values()
                    .flat_map(|sites| sites.values())
                    .any(|fingerprint| !is_fingerprint(fingerprint));
                if malformed {
                    return Err(Error::Config(format!(
                        "fingerprint baseline namespace {namespace:?} holds a {kind} value that is \
                         not an {FINGERPRINT_ALGORITHM} fingerprint"
                    )));
                }
            }
        }
        Ok(baseline)
    }

    /// Read a baseline file. `Ok(None)` when it does not exist yet.
    pub fn load(path: &Path) -> crate::error::Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text).map(Some),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(Error::FileRead {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Replace the namespace's entry with this export's fingerprints.
    pub fn record(&mut self, export: &ConfigExport) {
        let namespace = export.namespace.clone();
        self.namespaces.insert(namespace, export.fingerprints());
    }

    /// Write the baseline atomically (temporary file, then rename).
    pub fn write(&self, path: &Path) -> crate::error::Result<()> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        let directory = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let mut temp = tempfile::NamedTempFile::new_in(directory)?;
        temp.write_all(text.as_bytes())?;
        temp.as_file().sync_all()?;
        temp.persist(path).map_err(|e| Error::Io(e.error))?;
        Ok(())
    }

    /// Compare one export with this baseline, for the resources `desired`
    /// declares in that namespace. Live-only resources are the ordinary diff's
    /// business; resources absent from the baseline are counted, not judged.
    pub fn compare(
        &self,
        export: &ConfigExport,
        desired: &GatewayConfig,
    ) -> NamespaceSecretComparison {
        let Some(baseline) = self.namespaces.get(&export.namespace) else {
            return NamespaceSecretComparison::NoBaseline;
        };
        if baseline.fingerprint_key_id != export.fingerprint_key_id {
            return NamespaceSecretComparison::KeyChanged;
        }
        let current = export.fingerprints();
        let mut compared = 0;
        let mut not_in_baseline = 0;
        let mut changes = Vec::new();
        for (kind, id) in declared_resources(desired, &export.namespace) {
            let Some(live) = current.resources.get(kind).and_then(|rows| rows.get(&id)) else {
                continue;
            };
            let Some(before) = baseline.resources.get(kind).and_then(|rows| rows.get(&id)) else {
                not_in_baseline += 1;
                continue;
            };
            compared += 1;
            let change = |pointer: &str, change: SecretChangeKind| SecretChange {
                kind: kind.to_string(),
                namespace: export.namespace.clone(),
                id: id.clone(),
                pointer: pointer.to_string(),
                change,
            };
            for (pointer, fingerprint) in live {
                match before.get(pointer) {
                    Some(previous) if previous == fingerprint => {}
                    Some(_) => changes.push(change(pointer, SecretChangeKind::Changed)),
                    None => changes.push(change(pointer, SecretChangeKind::Added)),
                }
            }
            for pointer in before.keys().filter(|pointer| !live.contains_key(*pointer)) {
                changes.push(change(pointer, SecretChangeKind::Removed));
            }
        }
        NamespaceSecretComparison::Compared {
            compared,
            not_in_baseline,
            changes,
        }
    }
}

/// `(kind, id)` of every resource `desired` declares in `namespace`, sorted.
fn declared_resources(
    desired: &GatewayConfig,
    namespace: &str,
) -> BTreeSet<(&'static str, String)> {
    let desired = crate::config::filter_config_by_namespace(desired, namespace);
    let mut declared = BTreeSet::new();
    for proxy in &desired.proxies {
        declared.insert(("Proxy", proxy.id.clone()));
    }
    for consumer in &desired.consumers {
        declared.insert(("Consumer", consumer.id.clone()));
    }
    for plugin in &desired.plugin_configs {
        declared.insert(("PluginConfig", plugin.id.clone()));
    }
    for upstream in &desired.upstreams {
        declared.insert(("Upstream", upstream.id.clone()));
    }
    declared
}

/// Result of comparing one namespace's export with a baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceSecretComparison {
    /// The baseline has no entry for the namespace.
    NoBaseline,
    /// The gateway's fingerprint key changed since the baseline (its
    /// `FERRUM_ADMIN_JWT_SECRET` rotated, or it restarted with a random key),
    /// so no fingerprint is comparable.
    KeyChanged,
    Compared {
        /// Declared resources found in both the export and the baseline.
        compared: usize,
        /// Declared, live resources the baseline has never seen.
        not_in_baseline: usize,
        changes: Vec<SecretChange>,
    },
}

/// How a fingerprinted field changed between the baseline and this export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretChangeKind {
    Changed,
    Added,
    Removed,
}

impl SecretChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            SecretChangeKind::Changed => "CHANGED",
            SecretChangeKind::Added => "ADDED",
            SecretChangeKind::Removed => "REMOVED",
        }
    }
}

/// One fingerprinted field of a declared resource that differs from the
/// baseline. Carries no value. Every member comes from the gateway or the
/// baseline file; sanitize before printing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretChange {
    pub kind: String,
    pub namespace: String,
    pub id: String,
    pub pointer: String,
    pub change: SecretChangeKind,
}

/// What one `diff` run established about fingerprinted secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFingerprintSummary {
    /// Fingerprinted fields on declared resources that could not be compared
    /// with the repository's value.
    pub uncompared: usize,
    /// Changes on declared resources since the baseline.
    pub changes: Vec<SecretChange>,
    /// Every namespace was compared with a baseline under the same key, and
    /// every declared live resource was in it.
    pub baseline_complete: bool,
    /// Why parts of the comparison were not possible. Unsanitized: gateway
    /// and baseline text; print through `diagnostics`.
    pub notes: Vec<String>,
}

impl SecretFingerprintSummary {
    /// Compare each export with `baseline` (when there is one) for the
    /// resources `desired` declares. Cached exports are not compared: they
    /// may predate the database, and the caller already refuses to call the
    /// run authoritative.
    pub fn evaluate(
        exports: &[ConfigExport],
        uncompared: usize,
        baseline: Option<&FingerprintBaseline>,
        desired: &GatewayConfig,
    ) -> Self {
        let mut summary = Self {
            uncompared,
            changes: Vec::new(),
            baseline_complete: baseline.is_some(),
            notes: Vec::new(),
        };
        let Some(baseline) = baseline else {
            return summary;
        };
        for export in exports {
            if export.cached {
                summary.baseline_complete = false;
                continue;
            }
            let namespace = &export.namespace;
            match baseline.compare(export, desired) {
                NamespaceSecretComparison::NoBaseline => {
                    summary.baseline_complete = false;
                    summary.notes.push(format!(
                        "namespace '{namespace}' has no entry in the fingerprint baseline"
                    ));
                }
                NamespaceSecretComparison::KeyChanged => {
                    summary.baseline_complete = false;
                    summary.notes.push(format!(
                        "namespace '{namespace}': the gateway's fingerprint key changed since the \
                         baseline (its FERRUM_ADMIN_JWT_SECRET rotated, or a gateway without one \
                         restarted), so no fingerprint is comparable; record a new baseline"
                    ));
                }
                NamespaceSecretComparison::Compared {
                    not_in_baseline,
                    changes,
                    ..
                } => {
                    if not_in_baseline > 0 {
                        summary.baseline_complete = false;
                        summary.notes.push(format!(
                            "namespace '{namespace}': {not_in_baseline} declared resource(s) are \
                             not in the fingerprint baseline yet"
                        ));
                    }
                    summary.changes.extend(changes);
                }
            }
        }
        summary
    }

    /// True when no declared secret is left unverified: either nothing was
    /// fingerprinted, or a complete baseline shows each one unchanged (or
    /// lists it in [`Self::changes`]).
    pub fn verified(&self) -> bool {
        self.uncompared == 0 || self.baseline_complete
    }
}
