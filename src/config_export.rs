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
//!   repository declares a **secret-bearing** value at the same location (a
//!   brokered placeholder, a modeled secret leaf, or a URL with userinfo),
//!   [`ConfigExport::live_view`] substitutes the declared value into the live
//!   view (so the field is not reported as drift it cannot be) and records the
//!   site in [`ExportLiveView::uncompared`]. Edge v0.9.9 publishes no list of
//!   the pointers it redacted, so a fingerprint-shaped string anywhere else is
//!   compared as an ordinary value and reported when it differs. Where the
//!   repository declares nothing there, the fingerprint stays and the
//!   structural difference is reported.
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
//!   export. Each consumer instead carries one `hidden_credentials_fingerprint`
//!   over the omitted types, which only a baseline can use; it is therefore
//!   uncompared on every declared consumer, and a declared consumer whose
//!   export lacks the field can never be verified. `mtls_auth` falls under the
//!   hidden fingerprint only when none of its identities is valid to Edge;
//!   when at least one is valid, the export shows the valid ones and its
//!   invalid entries are neither shown nor fingerprinted.
//! - Edge may fingerprint a whole value (an ancestor of a secret leaf) when
//!   the value fails closed. Replacing it with the declared value also hides
//!   the value's non-secret contents, so such replacements are counted
//!   separately ([`ExportLiveView::masked_ancestors`]) and keep a run
//!   non-authoritative whatever else is accepted.
//! - The export strips `api_spec_id`, so spec-owned rows cannot be told apart
//!   from other live rows on this path.
//!
//! `X-Data-Source: cached` (or `source: cached` in the body) marks the export
//! as possibly stale; callers must not report "no drift" from it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::schema::Consumer;
use crate::config::GatewayConfig;
use crate::error::Error;
use crate::http_client::{BackupSnapshot, SealStrictness};
use crate::secrets::plugin_config::{sensitive_string_paths, ConfigPathComponent};

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
    /// [`project_consumer_for_export`]) declares a secret-bearing value is
    /// replaced by that value and listed in [`ExportLiveView::uncompared`]:
    /// the field cannot be compared, and reporting it as drift would be
    /// false. A location is secret-bearing when the declared value is a
    /// brokered placeholder or a URL with userinfo, or the location is (or
    /// contains) a modeled secret leaf: a Consumer key or secret, a plugin
    /// config path the secret classifier flags, or the Consul token. Every
    /// other fingerprint-shaped value stays and is compared as written.
    ///
    /// The consumers' [`HIDDEN_CREDENTIALS_FIELD`] is removed and, for every
    /// declared consumer, listed as uncompared whether or not the export
    /// carries it: it covers credentials the export never shows (`basicauth`,
    /// custom types, an `mtls_auth` type with no valid identity), so only a
    /// baseline can say they did not change.
    ///
    /// Equivalent to [`Self::live_view_with`] with `desired` as its own
    /// secret source.
    pub fn live_view(&self, desired: &GatewayConfig) -> crate::error::Result<ExportLiveView> {
        self.live_view_with(desired, desired)
    }

    /// [`Self::live_view`] for a `desired` whose placeholders were already
    /// resolved from a credential bundle. Secret-bearing locations are taken
    /// from both `desired` and `unresolved` (the same configuration before
    /// resolution), so a brokered value stays secret-bearing once the bundle
    /// has replaced its placeholder.
    pub fn live_view_with(
        &self,
        desired: &GatewayConfig,
        unresolved: &GatewayConfig,
    ) -> crate::error::Result<ExportLiveView> {
        let mut desired_rows = desired_comparison_rows(desired, &self.namespace)?;
        let unresolved_rows = desired_comparison_rows(unresolved, &self.namespace)?;
        for (key, row) in &mut desired_rows {
            if let Some(source) = unresolved_rows.get(key) {
                let extra = source.secret_pointers.iter().cloned();
                row.secret_pointers.extend(extra);
            }
        }
        let mut sections: BTreeMap<&'static str, Vec<Value>> = BTreeMap::new();
        let mut uncompared = Vec::new();
        let mut masked_ancestors = Vec::new();
        for row in &self.rows {
            let mut body = row.body.clone();
            let expected = desired_rows.get(&(row.kind, row.id.clone()));
            if row.kind == "Consumer" {
                if let Some(object) = body.as_object_mut() {
                    object.remove(HIDDEN_CREDENTIALS_FIELD);
                }
                if expected.is_some() {
                    uncompared.push(self.site(row, &format!("/{HIDDEN_CREDENTIALS_FIELD}")));
                }
            }
            if let Some(expected) = expected {
                let mut substituted = Vec::new();
                substitute_fingerprints(&mut body, expected, &mut String::new(), &mut substituted);
                for (pointer, ancestor) in &substituted {
                    uncompared.push(self.site(row, pointer));
                    if *ancestor {
                        masked_ancestors.push(self.site(row, pointer));
                    }
                }
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
        masked_ancestors.sort();
        Ok(ExportLiveView {
            actual: snapshot.config,
            uncompared,
            masked_ancestors,
        })
    }

    /// Ids of exported consumers that lack [`HIDDEN_CREDENTIALS_FIELD`]. Edge
    /// always sends it, so its absence means a non-conforming gateway, and no
    /// baseline can then vouch for the hidden credentials.
    pub fn consumers_missing_hidden_fingerprint(&self) -> BTreeSet<&str> {
        self.rows
            .iter()
            .filter(|row| row.kind == "Consumer")
            .filter(|row| row.body.get(HIDDEN_CREDENTIALS_FIELD).is_none())
            .map(|row| row.id.as_str())
            .collect()
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
    /// The subset of [`Self::uncompared`] where Edge fingerprinted a whole
    /// value that only *contains* a secret. Its non-secret contents were not
    /// compared either, so a run with any of these is never authoritative.
    pub masked_ancestors: Vec<FingerprintSite>,
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

/// Object entries of one credential value: an array's objects, or a legacy
/// single object (Edge emits it at index 0).
fn credential_entries(value: &Value) -> Vec<&serde_json::Map<String, Value>> {
    match value {
        Value::Array(entries) => entries.iter().filter_map(Value::as_object).collect(),
        Value::Object(entry) => vec![entry],
        _ => Vec::new(),
    }
}

/// One declared resource, serialized for pointer lookups, with the JSON
/// pointers of its secret-bearing values.
struct DesiredRow {
    value: Value,
    secret_pointers: BTreeSet<String>,
}

impl DesiredRow {
    fn new(value: Value, mut secret_pointers: BTreeSet<String>) -> Self {
        collect_secret_values(&value, &mut String::new(), &mut secret_pointers);
        Self {
            value,
            secret_pointers,
        }
    }

    /// How `pointer` relates to the secret-bearing locations: `Some(false)`
    /// for one of them, `Some(true)` for an ancestor of one (Edge may
    /// fingerprint a whole value that fails closed), `None` otherwise.
    fn secret_bearing(&self, pointer: &str) -> Option<bool> {
        if self.secret_pointers.contains(pointer) {
            return Some(false);
        }
        let below = format!("{pointer}/");
        let ancestor = self
            .secret_pointers
            .iter()
            .any(|secret| secret.starts_with(&below));
        ancestor.then_some(true)
    }
}

/// Declared resources of one namespace, keyed by `(kind, id)`.
fn desired_comparison_rows(
    desired: &GatewayConfig,
    namespace: &str,
) -> crate::error::Result<HashMap<(&'static str, String), DesiredRow>> {
    let desired = crate::config::filter_config_by_namespace(desired, namespace);
    let mut rows = HashMap::new();
    for proxy in &desired.proxies {
        let value = serde_json::to_value(proxy)?;
        rows.insert(
            ("Proxy", proxy.id.clone()),
            DesiredRow::new(value, BTreeSet::new()),
        );
    }
    for consumer in &desired.consumers {
        let projected = project_consumer_for_export(consumer);
        let value = serde_json::to_value(&projected)?;
        let secrets = consumer_secret_pointers(&projected);
        rows.insert(
            ("Consumer", consumer.id.clone()),
            DesiredRow::new(value, secrets),
        );
    }
    for plugin in &desired.plugin_configs {
        let value = serde_json::to_value(plugin)?;
        let mut secrets = BTreeSet::new();
        for path in sensitive_string_paths(&plugin.plugin_name, &plugin.config) {
            let mut pointer = String::from("/config");
            for component in &path {
                let segment = match component {
                    ConfigPathComponent::Key(key) => key.clone(),
                    ConfigPathComponent::Index(index) => index.to_string(),
                };
                push_pointer_segment(&mut pointer, &segment);
            }
            secrets.insert(pointer);
        }
        rows.insert(
            ("PluginConfig", plugin.id.clone()),
            DesiredRow::new(value, secrets),
        );
    }
    for upstream in &desired.upstreams {
        let value = serde_json::to_value(upstream)?;
        let mut secrets = BTreeSet::new();
        for field in crate::secrets::service_discovery::SD_SECRET_FIELDS {
            let mut pointer = String::from("/service_discovery");
            for segment in field.path {
                push_pointer_segment(&mut pointer, segment);
            }
            secrets.insert(pointer);
        }
        rows.insert(
            ("Upstream", upstream.id.clone()),
            DesiredRow::new(value, secrets),
        );
    }
    Ok(rows)
}

/// Pointers of the secret leaves the export fingerprints on a projected
/// Consumer: each `keyauth[].key`, `jwt[].secret` and `hmac_auth[].secret`.
fn consumer_secret_pointers(projected: &Consumer) -> BTreeSet<String> {
    let mut pointers = BTreeSet::new();
    for (credential_type, field) in FINGERPRINTED_CREDENTIAL_FIELDS {
        let Some(Value::Array(entries)) = projected.credentials.get(credential_type) else {
            continue;
        };
        for index in 0..entries.len() {
            let mut pointer = String::from("/credentials");
            push_pointer_segment(&mut pointer, credential_type);
            push_pointer_segment(&mut pointer, &index.to_string());
            push_pointer_segment(&mut pointer, field);
            pointers.insert(pointer);
        }
    }
    pointers
}

/// Add the pointer of every string that is a brokered placeholder or a URL
/// carrying userinfo.
fn collect_secret_values(value: &Value, pointer: &mut String, out: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            if crate::secrets::parse_placeholder(text).is_some() || has_url_userinfo(text) {
                out.insert(pointer.clone());
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                let len = pointer.len();
                push_pointer_segment(pointer, key);
                collect_secret_values(child, pointer, out);
                pointer.truncate(len);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let len = pointer.len();
                push_pointer_segment(pointer, &index.to_string());
                collect_secret_values(child, pointer, out);
                pointer.truncate(len);
            }
        }
        _ => {}
    }
}

/// True for `scheme://user[:password]@host…`.
fn has_url_userinfo(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains('@')
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

/// Replace each fingerprint in `live` at a secret-bearing location the
/// repository declares with the declared value, recording the pointer and
/// whether it was an ancestor of the secret rather than the secret itself.
fn substitute_fingerprints(
    live: &mut Value,
    desired: &DesiredRow,
    pointer: &mut String,
    substituted: &mut Vec<(String, bool)>,
) {
    if live.as_str().is_some_and(is_fingerprint) {
        let expected = desired.value.pointer(pointer);
        if let (Some(expected), Some(ancestor)) = (expected, desired.secret_bearing(pointer)) {
            *live = expected.clone();
            substituted.push((pointer.clone(), ancestor));
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

/// The git worktree containing `path`, if any: the nearest ancestor of its
/// absolute form that holds a `.git` entry. A fingerprint baseline belongs
/// outside the repository, so callers warn when this is `Some`.
pub fn enclosing_git_worktree(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    absolute
        .ancestors()
        .skip(1)
        .find(|ancestor| ancestor.join(".git").exists())
        .map(Path::to_path_buf)
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
    /// A namespace's baseline was recorded under a different gateway key, so
    /// none of its fingerprints could be compared.
    pub key_changed: bool,
    /// A namespace recorded in the baseline could not be compared completely: a
    /// declared Consumer came without `hidden_credentials_fingerprint`. Unlike
    /// a namespace absent from the baseline or a resource not yet recorded —
    /// incremental gaps — this is a failure of the verification control an
    /// operator set up with `--fingerprint-baseline`.
    pub recorded_namespace_incomplete: bool,
    /// Whole values Edge fingerprinted around a secret (see
    /// [`ExportLiveView::masked_ancestors`]). Never authoritative: neither a
    /// baseline nor `--accept-unverified-secrets` covers their non-secret
    /// contents.
    pub masked_ancestors: usize,
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
            key_changed: false,
            recorded_namespace_incomplete: false,
            masked_ancestors: 0,
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
            let declared = declared_resources(desired, namespace);
            let missing = export
                .consumers_missing_hidden_fingerprint()
                .into_iter()
                .filter(|id| declared.contains(&("Consumer", (*id).to_string())))
                .count();
            if missing > 0 {
                summary.baseline_complete = false;
                if baseline.namespaces.contains_key(namespace) {
                    summary.recorded_namespace_incomplete = true;
                }
                summary.notes.push(format!(
                    "namespace '{namespace}': {missing} declared consumer(s) came without \
                     {HIDDEN_CREDENTIALS_FIELD}, so their hidden credentials cannot be verified"
                ));
            }
            match baseline.compare(export, desired) {
                NamespaceSecretComparison::NoBaseline => {
                    summary.baseline_complete = false;
                    summary.notes.push(format!(
                        "namespace '{namespace}' has no entry in the fingerprint baseline"
                    ));
                }
                NamespaceSecretComparison::KeyChanged => {
                    summary.baseline_complete = false;
                    summary.key_changed = true;
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
    /// lists it in [`Self::changes`]). A gateway key change is never
    /// verified: the baseline it invalidated proves nothing.
    pub fn verified(&self) -> bool {
        !self.key_changed && (self.uncompared == 0 || self.baseline_complete)
    }

    /// True when a supplied baseline could not verify secrets for a namespace
    /// it covers, rather than merely lacking an incremental entry (a namespace
    /// or resource not yet recorded). `diff --exit-on-drift` treats this as a
    /// failed check (`1`), not the non-blocking unverified code (`6`): the
    /// verification control the operator set up was invalidated.
    pub fn baseline_invalidated(&self) -> bool {
        self.key_changed || self.recorded_namespace_incomplete
    }

    /// Record how many whole values were fingerprinted around a secret.
    pub fn with_masked_ancestors(mut self, masked_ancestors: usize) -> Self {
        self.masked_ancestors = masked_ancestors;
        self
    }

    /// False when any whole value was fingerprinted around a secret: no flag
    /// or baseline makes such a run authoritative.
    pub fn authoritative(&self) -> bool {
        self.masked_ancestors == 0
    }
}
