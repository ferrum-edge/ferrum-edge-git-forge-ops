//! Sensitive authoritative evidence. Tokens never describe a comparison projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::{strong_entity_tag, BackupSnapshot, SealStrictness};
use crate::error::{Error, Result};

#[derive(Clone, PartialEq, Eq)]
pub struct RowToken(String);

#[derive(Clone, PartialEq, Eq)]
pub struct NamespaceToken(String);

macro_rules! token {
    ($name:ident) => {
        impl $name {
            fn parse(value: Option<&str>) -> Result<Self> {
                let value = value.ok_or_else(invalid)?;
                let tag = strong_entity_tag(Some(value)).ok_or_else(invalid)?;
                if tag != value {
                    return Err(invalid());
                }
                Ok(Self(tag))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

token!(RowToken);
token!(NamespaceToken);

#[derive(Clone)]
pub struct ConsumerEvidence {
    pub row: Value,
    pub token: RowToken,
}

impl fmt::Debug for ConsumerEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsumerEvidence(<redacted>)")
    }
}

impl ConsumerEvidence {
    pub fn from_response(
        body: &str,
        namespace: &str,
        id: &str,
        etag: Option<&str>,
        source: Option<&str>,
        cache_control: Option<&str>,
    ) -> Result<Self> {
        require_authoritative(source, cache_control)?;
        let row = parse_sensitive(body)?;
        validate_consumer(&row, namespace, id)?;
        Ok(Self {
            row,
            token: RowToken::parse(etag)?,
        })
    }

    /// Compare only against the canonical archival projection used by ordinary `/backup`.
    /// The stored row and its token remain untouched and are used for every later precondition.
    pub fn matches_archival(&self, planned: &crate::config::schema::Consumer) -> Result<bool> {
        let mut canonical: crate::config::schema::Consumer =
            serde_json::from_value(self.row.clone()).map_err(|_| invalid())?;
        for (kind, entries) in &mut canonical.credentials {
            if entries.is_object() {
                *entries = Value::Array(vec![entries.clone()]);
            }
            let field = match kind.as_str() {
                "jwt" | "hmac_auth" => "secret",
                "mtls_auth" => "identity",
                _ => continue,
            };
            if let Some(entries) = entries.as_array_mut() {
                for entry in entries {
                    if let Some(value) = entry.get(field).and_then(Value::as_str) {
                        *entry = serde_json::json!({(field): value});
                    }
                }
            }
        }
        let canonical = serde_json::to_value(canonical).map_err(|_| invalid())?;
        let planned = serde_json::to_value(planned).map_err(|_| invalid())?;
        Ok(canonical == planned)
    }

    /// Exact stored evidence, including hidden credentials and legacy fields.
    pub fn same_row(&self, other: &Self) -> bool {
        self.row == other.row && self.token == other.token
    }
}

/// Preserve fields that a declared entry cannot express. Hidden omitted types survive PUT,
/// but restore is a replacement and must carry them explicitly or refuse.
pub fn require_preserved_credentials(
    raw: &Value,
    desired: &crate::config::schema::Consumer,
    replacement: bool,
) -> Result<()> {
    let credentials = raw
        .get("credentials")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    for (kind, live) in credentials {
        let Some(declared) = desired.credentials.get(kind) else {
            if replacement
                && (!crate::config::schema::KNOWN_CREDENTIAL_TYPES.contains(&kind.as_str())
                    || kind == "basicauth")
            {
                return Err(unrepresentable());
            }
            continue;
        };
        let retained = serde_json::json!({"credentials": {(kind): live}});
        require_publishable_credentials(&retained, false)?;
        let live = live.as_array().ok_or_else(unrepresentable)?;
        let declared = declared.as_array().ok_or_else(unrepresentable)?;
        for (live, declared) in live.iter().zip(declared) {
            let live = live.as_object().ok_or_else(unrepresentable)?;
            let declared = declared.as_object().ok_or_else(unrepresentable)?;
            if live.keys().any(|key| {
                !declared.contains_key(key)
                    && !(kind == "basicauth"
                        && key == "password_hash"
                        && declared.contains_key("password"))
            }) {
                return Err(unrepresentable());
            }
        }
    }
    Ok(())
}

/// Exact export is not necessarily an accepted input. Never canonicalize away live fields.
pub fn require_publishable_credentials(row: &Value, importing: bool) -> Result<()> {
    let credentials = row
        .get("credentials")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    for (kind, entries) in credentials {
        if kind.is_empty()
            || kind.len() > 64
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || importing && !crate::config::schema::KNOWN_CREDENTIAL_TYPES.contains(&kind.as_str())
        {
            return Err(unrepresentable());
        }
        let entries = entries
            .as_array()
            .filter(|entries| !entries.is_empty())
            .ok_or_else(unrepresentable)?;
        for entry in entries {
            let object = entry.as_object().ok_or_else(unrepresentable)?;
            let field = match kind.as_str() {
                "jwt" | "hmac_auth" => Some("secret"),
                "mtls_auth" => Some("identity"),
                "basicauth" => Some("password_hash"),
                "keyauth" => Some("key"),
                _ => None,
            };
            if let Some(field) = field {
                if object.get(field).and_then(Value::as_str).is_none()
                    || kind != "keyauth" && object.len() != 1
                {
                    return Err(unrepresentable());
                }
                if kind == "basicauth" {
                    let valid = object[field]
                        .as_str()
                        .and_then(|hash| hash.strip_prefix("hmac_sha256:"))
                        .is_some_and(|hash| {
                            hash.len() == 64
                                && hash.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        });
                    if !valid {
                        return Err(unrepresentable());
                    }
                }
            }
        }
    }
    Ok(())
}

fn unrepresentable() -> Error {
    Error::StalePlan(
        "complete stored consumer credentials cannot be published without losing opaque or \
         legacy fields. Repair the stored representation explicitly before retrying; no secret \
         or gateway write was authorized"
            .to_string(),
    )
}

#[derive(Debug)]
pub struct PreparedConsumerRotation {
    evidence: ConsumerEvidence,
    kind: String,
    index: usize,
    field: String,
}

impl PreparedConsumerRotation {
    /// All remote and field safety checks precede broker publication.
    pub async fn prepare(
        client: &super::AdminClient,
        current: &crate::config::schema::Consumer,
        credential: &str,
        expected_target: Option<&str>,
    ) -> Result<Self> {
        let health = client.get_health().await?;
        if let Some(reason) = super::write_block_reason(&health) {
            return Err(Error::GatewayReadOnly(reason));
        }
        if health.admin_writes_enabled != Some(true) {
            return Err(invalid());
        }
        let evidence = client
            .get_consumer_verification(&current.id, &current.namespace)
            .await?
            .ok_or_else(unrepresentable)?;
        require_publishable_credentials(&evidence.row, false)?;
        let parts = credential.split('/').collect::<Vec<_>>();
        let (kind, index, field) = match parts.as_slice() {
            [kind, field] => (*kind, 0, *field),
            [kind, index, field] => {
                let index = index
                    .strip_prefix('[')
                    .and_then(|index| index.strip_suffix(']'))
                    .and_then(|index| index.parse::<usize>().ok())
                    .ok_or_else(unrepresentable)?;
                (*kind, index, *field)
            }
            _ => return Err(unrepresentable()),
        };
        if !matches!(
            (kind, field),
            ("keyauth", "key") | ("jwt" | "hmac_auth", "secret") | ("basicauth", "password")
        ) {
            return Err(unrepresentable());
        }
        let stored = evidence.row["credentials"][kind]
            .get(index)
            .ok_or_else(unrepresentable)?;
        current
            .credentials
            .get(kind)
            .and_then(|entries| entries.get(index))
            .and_then(|entry| entry.get(field))
            .and_then(Value::as_str)
            .ok_or_else(unrepresentable)?;
        // Basic's gateway-keyed HMAC is opaque; never hash plaintext with an admin key.
        // An absent old bundle value cannot establish equality. The complete stored
        // evidence still authorizes only this leaf, and its token fences publication.
        if kind != "basicauth"
            && expected_target
                .is_some_and(|expected| stored.get(field).and_then(Value::as_str) != Some(expected))
        {
            return Err(Error::StalePlan(
                "rotation target differs from the current bundle; reconcile before rotation"
                    .to_string(),
            ));
        }
        let live: crate::config::schema::Consumer =
            serde_json::from_value(evidence.row.clone()).map_err(|_| invalid())?;
        if live.username != current.username || live.custom_id != current.custom_id {
            return Err(Error::StalePlan(
                "consumer identity changed; reconcile before rotation".to_string(),
            ));
        }
        Ok(Self {
            evidence,
            kind: kind.to_string(),
            index,
            field: field.to_string(),
        })
    }

    pub async fn publish(self, client: &super::AdminClient, value: &str) -> Result<()> {
        let namespace = self.evidence.row["namespace"]
            .as_str()
            .ok_or_else(invalid)?
            .to_string();
        let id = self.evidence.row["id"]
            .as_str()
            .ok_or_else(invalid)?
            .to_string();
        let mut row = self.evidence.row;
        let entry = row["credentials"][&self.kind]
            .get_mut(self.index)
            .and_then(Value::as_object_mut)
            .ok_or_else(unrepresentable)?;
        if self.kind == "basicauth" {
            entry.remove("password_hash");
        }
        entry.insert(self.field, Value::String(value.to_string()));
        match client
            .update_if_match(
                "Consumer",
                &id,
                &row,
                &namespace,
                self.evidence.token.as_str(),
            )
            .await?
        {
            super::ConditionalUpdate::Applied => Ok(()),
            super::ConditionalUpdate::Refused(_) => Err(Error::StalePlan(
                "conditional rotation publication refused after delivery; broker and gateway \
                 may diverge. Reconcile the delivered credential with a fresh apply; rotation \
                 completion was not recorded"
                    .to_string(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct ConditionalMetadata {
    pub namespace: String,
    pub namespace_token: NamespaceToken,
    pub row_tokens: BTreeMap<String, BTreeMap<String, RowToken>>,
    pub raw_rows: BTreeMap<String, BTreeMap<String, Value>>,
}

impl fmt::Debug for ConditionalMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConditionalMetadata(<redacted>)")
    }
}

pub fn conditional_backup(
    body: &str,
    namespace: &str,
    etag: Option<&str>,
    source: Option<&str>,
    cache_control: Option<&str>,
) -> Result<BackupSnapshot> {
    validate_namespace(namespace)?;
    require_authoritative(source, cache_control)?;
    let mut value = parse_sensitive(body)?;
    let root = value.as_object_mut().ok_or_else(invalid)?;
    if root.get("source").and_then(Value::as_str) == Some("cached") {
        return Err(Error::StaleGatewayView(
            "cached namespace evidence cannot authorize a conditional operation".to_string(),
        ));
    }
    const FIELDS: &[&str] = &[
        "version",
        "ferrum_version",
        "exported_at",
        "source",
        "counts",
        "proxies",
        "consumers",
        "upstreams",
        "plugin_configs",
        "api_specs",
        "gateway_trust_bundles",
        "conditional",
    ];
    if root.keys().any(|key| !FIELDS.contains(&key.as_str()))
        || root.get("version").and_then(Value::as_str) != Some("1")
        || root.get("source").and_then(Value::as_str) != Some("database")
        || ["version", "ferrum_version", "exported_at"]
            .iter()
            .any(|key| root.get(*key).and_then(Value::as_str).is_none())
    {
        return Err(invalid());
    }
    let metadata = root.remove("conditional").ok_or_else(invalid)?;
    let metadata = metadata.as_object().ok_or_else(invalid)?;
    if metadata.len() != 2 {
        return Err(invalid());
    }
    let namespace_token = NamespaceToken::parse(etag)?;
    if NamespaceToken::parse(metadata.get("namespace_etag").and_then(Value::as_str))?
        != namespace_token
    {
        return Err(invalid());
    }
    let maps = metadata
        .get("row_etags")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let counts = root
        .get("counts")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if maps.len() != 4 || counts.len() != 6 {
        return Err(invalid());
    }
    let mut row_tokens = BTreeMap::new();
    let mut raw_rows = BTreeMap::new();
    let mut consumers = BTreeMap::new();
    for section in ["proxies", "consumers", "upstreams", "plugin_configs"] {
        let rows = root
            .get(section)
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        let tags = maps
            .get(section)
            .and_then(Value::as_object)
            .ok_or_else(invalid)?;
        let mut ids = BTreeSet::new();
        let mut tokens = BTreeMap::new();
        let mut raw = BTreeMap::new();
        for row in rows {
            let id = row.get("id").and_then(Value::as_str).ok_or_else(invalid)?;
            validate_identity(row, namespace, id)?;
            if !ids.insert(id) {
                return Err(invalid());
            }
            let token = RowToken::parse(tags.get(id).and_then(Value::as_str))?;
            if section == "consumers" {
                validate_consumer(row, namespace, id)?;
                consumers.insert(
                    id.to_string(),
                    ConsumerEvidence {
                        row: row.clone(),
                        token: token.clone(),
                    },
                );
            }
            raw.insert(id.to_string(), row.clone());
            tokens.insert(id.to_string(), token);
        }
        if tags.len() != ids.len() || tags.keys().any(|id| !ids.contains(id.as_str())) {
            return Err(invalid());
        }
        raw_rows.insert(section.to_string(), raw);
        row_tokens.insert(section.to_string(), tokens);
    }
    let specs = root
        .get("api_specs")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if specs.len() != 2 || specs.get("section_version").and_then(Value::as_str) != Some("2") {
        return Err(invalid());
    }
    let specs = specs
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let trust = root
        .get("gateway_trust_bundles")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if trust.len() > 1 {
        return Err(invalid());
    }
    for (section, rows) in [("api_specs", specs), ("gateway_trust_bundles", trust)] {
        if counts.get(section).and_then(Value::as_u64) != Some(rows.len() as u64) {
            return Err(invalid());
        }
        let mut ids = BTreeSet::new();
        for row in rows {
            let id = row.get("id").and_then(Value::as_str).ok_or_else(invalid)?;
            validate_identity(row, namespace, id)?;
            if !ids.insert(id) {
                return Err(invalid());
            }
        }
    }
    let mut snapshot = BackupSnapshot::from_value_with_strictness(value, SealStrictness::Strict)
        .map_err(|_| invalid())?;
    snapshot.extras.consumer_evidence = consumers;
    snapshot.extras.conditional = Some(ConditionalMetadata {
        namespace: namespace.to_string(),
        namespace_token,
        row_tokens,
        raw_rows,
    });
    Ok(snapshot)
}

fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty()
        || namespace.len() > 254
        || !namespace.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_identity(row: &Value, namespace: &str, id: &str) -> Result<()> {
    validate_namespace(namespace)?;
    if id.len() > 254
        || super::validate_resource_id_for_path(id).is_err()
        || row.get("id").and_then(Value::as_str) != Some(id)
        || row.get("namespace").and_then(Value::as_str) != Some(namespace)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_consumer(row: &Value, namespace: &str, id: &str) -> Result<()> {
    validate_identity(row, namespace, id)?;
    let object = row.as_object().ok_or_else(invalid)?;
    const FIELDS: &[&str] = &[
        "id",
        "namespace",
        "username",
        "custom_id",
        "credentials",
        "acl_groups",
        "labels",
        "created_at",
        "updated_at",
    ];
    if object.keys().any(|key| !FIELDS.contains(&key.as_str()))
        || object.get("username").and_then(Value::as_str).is_none()
        || object
            .get("credentials")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(invalid());
    }
    // Credentials are deliberately opaque. The desired schema remains closed.
    serde_json::from_value::<crate::config::schema::Consumer>(row.clone())
        .map_err(|_| invalid())?;
    Ok(())
}

fn require_authoritative(source: Option<&str>, cache_control: Option<&str>) -> Result<()> {
    if source == Some("cached") {
        return Err(Error::StaleGatewayView(
            "X-Data-Source: cached cannot authorize a conditional operation".to_string(),
        ));
    }
    if source.is_some_and(|source| source != "database") || cache_control != Some("no-store") {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn invalid() -> Error {
    Error::ConditionalWriteUnavailable(
        "authoritative conditional evidence unavailable or invalid (no strong ETag or complete \
         contract); no write was authorized. \
         Require credential-complete consumer verification and coherent conditional namespace \
         snapshots from the qualified gateway build; response details withheld"
            .to_string(),
    )
}

/// Reject duplicate JSON keys recursively; serde_json::Value alone keeps only the last one.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a unique-key JSON value")
            }

            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }

            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> std::result::Result<Self::Value, S::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }

            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_string())))
            }

            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }

            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_f64<E: serde::de::Error>(
                self,
                value: f64,
            ) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| UniqueValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("invalid number"))
            }

            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub(super) fn parse_sensitive(body: &str) -> Result<Value> {
    serde_json::from_str::<UniqueValue>(body)
        .map(|value| value.0)
        .map_err(|_| invalid())
}

/// Preserve error categories and no-replay boundaries while withholding sensitive server text.
pub(super) fn withhold_error(error: Error) -> Error {
    let message = "conditional operation refused or failed; response details withheld. \
                   Inspect current gateway state before retrying"
        .to_string();
    match error {
        Error::ConditionalWriteUnavailable(_) => Error::ConditionalWriteUnavailable(
            "conditional operation refused or failed; authoritative conditional evidence \
             unavailable; response details withheld. Inspect current gateway state before retrying"
                .to_string(),
        ),
        Error::ApiError { status, .. } => Error::ApiError { status, message },
        Error::HttpClient(_) => Error::HttpClient(message),
        Error::GatewayReadOnly(_) => Error::GatewayReadOnly(message),
        Error::ApiSpecsAtRisk(_) => Error::ApiSpecsAtRisk(message),
        Error::RestoreNeedsManualRecovery(_) => Error::RestoreNeedsManualRecovery(message),
        Error::AmbiguousMutation(_) => Error::AmbiguousMutation(message),
        Error::CommittedNotLive { .. } => Error::CommittedNotLive {
            reason: "withheld".to_string(),
            message,
        },
        _ => Error::AmbiguousMutation(message),
    }
}

pub(super) fn require_restore_seal(response: &str, request: &Value) -> Result<()> {
    let response = parse_sensitive(response).map_err(|_| {
        Error::AmbiguousMutation(
            "conditional restore success response is invalid; do not replay".to_string(),
        )
    })?;
    let seal = response.get("restored").and_then(Value::as_object);
    let valid = response.as_object().is_some_and(|root| root.len() == 1)
        && seal.is_some_and(|seal| {
            seal.len() == 6
                && [
                    "proxies",
                    "consumers",
                    "upstreams",
                    "plugin_configs",
                    "api_specs",
                    "gateway_trust_bundles",
                ]
                .iter()
                .all(|section| {
                    let rows = if *section == "api_specs" {
                        &request[*section]["items"]
                    } else {
                        &request[*section]
                    };
                    seal.get(*section).and_then(Value::as_u64)
                        == Some(rows.as_array().map_or(0, Vec::len) as u64)
                })
        });
    if !valid {
        return Err(Error::AmbiguousMutation(
            "conditional restore response lacks a matching complete count seal; do not replay"
                .to_string(),
        ));
    }
    Ok(())
}
