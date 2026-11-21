//! TLS private-key material inside gateway documents.
//!
//! Ferrum Edge's TLS source fields accept inline PEM as well as references: a
//! value that starts with `-----BEGIN ` is the material itself, a known URI
//! scheme (`vault://`, `k8s://`, `managed://`, `pkcs11://`, `system://`) names
//! a provider, and anything else is a filesystem path. So
//! `Proxy.backend_tls_client_key_path`, `Upstream.backend_tls_client_key_path`,
//! `udp_logging` `dtls_key_path` and the other private-key slots can hold the
//! private key verbatim, and a certificate or CA field can hold a
//! certificate-plus-key bundle.
//!
//! This module is the one detector for that material. Import, the
//! literal-secret gate, the validator scrubber and display sink, diff and
//! review redaction, plugin-config classification and the `/config/export`
//! site prediction all ask it, so a string cannot be a private key on one
//! path and an ordinary setting on another. It mirrors Edge (`main`, after
//! v0.9.20):
//!
//! * [`contains_inline_private_key`] is Edge's
//!   `kafka_logging::contains_inline_private_key`: a PEM opening line whose
//!   label names a private key (`PRIVATE KEY`, `RSA PRIVATE KEY`,
//!   `ENCRYPTED PRIVATE KEY`, ...), anywhere in the value, case-insensitive,
//!   with the label read up to the next `-----` even across line breaks.
//! * [`tls_material_field`] is Edge's `plugin_config_projection::tls_material_field`,
//!   matched by field name wherever it occurs.
//! * [`is_private_key_material`] is Edge's `tls_material_withheld` without
//!   its echo-detection case for the exact `[REDACTED]` placeholder: a
//!   private-key block anywhere, or, under a private-key field, any PEM armour
//!   or control character (never part of a path or typed URI).
//!
//! A path such as `/etc/ferrum/tls/client.key`, a provider URI and a broker
//! placeholder are references, not material: they stay literal and reviewable
//! everywhere.

use serde_json::Value;

use super::plugin_config::ConfigPathComponent;

/// How a field name classifies the TLS material source it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsMaterialField {
    /// Names a private key: material unless it is plainly a reference.
    PrivateKey,
    /// Names a certificate or CA bundle: public unless it carries a PEM
    /// private-key block.
    Public,
}

/// The TLS material slot a field name denotes (Edge's `tls_material_field`).
pub(crate) fn tls_material_field(name: &str) -> Option<TlsMaterialField> {
    match name {
        "backend_tls_client_key_path" | "client_key_path" | "private_key" => {
            Some(TlsMaterialField::PrivateKey)
        }
        "backend_tls_client_cert_path"
        | "backend_tls_server_ca_cert_path"
        | "client_cert_path"
        | "server_ca_cert_path"
        | "client_certificate"
        | "ca_certificates" => Some(TlsMaterialField::Public),
        _ => None,
    }
}

/// A PEM block whose label names a private key, anywhere in `value`
/// (Edge's `contains_inline_private_key`).
pub(crate) fn contains_inline_private_key(value: &str) -> bool {
    const BANNER: &str = "-----BEGIN";
    let normalized = value.to_ascii_uppercase();
    normalized.match_indices(BANNER).any(|(start, _)| {
        let after = &normalized[start + BANNER.len()..];
        let label = after.find("-----").map_or(after, |end| &after[..end]);
        label.contains("PRIVATE KEY")
    })
}

/// Whether a string at a field classified as `field` is TLS private-key
/// material: a private-key PEM block anywhere, or, at a private-key field,
/// any PEM armour or control character.
pub(crate) fn is_private_key_material(value: &str, field: Option<TlsMaterialField>) -> bool {
    if contains_inline_private_key(value) {
        return true;
    }
    field == Some(TlsMaterialField::PrivateKey)
        && (value.to_ascii_uppercase().contains("-----BEGIN")
            || value.chars().any(char::is_control))
}

/// Plugin-config paths that hold a private-key *source*, by plugin, located
/// by schema rather than by field name alone, so a header or map entry that
/// happens to be named `private_key` keeps its ordinary behaviour. Inline
/// material here is brokered, the broker refuses to generate a value, and a
/// bundle-less validation gets a PEM-shaped stand-in. Paths use `*` for one
/// map key or array entry; array indices are otherwise transparent.
///
/// * `udp_logging` `dtls_key_path`: Edge after v0.9.20 declares it a
///   private-key source (`plugin_config_projection`), so it gets the
///   private-key field rule even though [`tls_material_field`] does not name
///   it.
/// * `mesh_route_dispatch` `rules[].destination.backend_tls.client_key_path`:
///   a `BackendTlsConfig` key source.
const PLUGIN_KEY_SOURCES: &[(&str, &[&str])] = &[
    ("udp_logging", &["dtls_key_path"]),
    (
        "mesh_route_dispatch",
        &[
            "rules",
            "*",
            "destination",
            "backend_tls",
            "client_key_path",
        ],
    ),
];

/// Plugin-config certificate and CA sources Edge declares by schema
/// (`certificate_source`) beyond the names [`tls_material_field`] knows.
const PLUGIN_CERTIFICATE_SOURCES: &[(&str, &[&str])] = &[
    ("udp_logging", &["dtls_cert_path"]),
    ("udp_logging", &["dtls_ca_cert_path"]),
];

/// Whether `path` matches a schema `pattern` (see [`PLUGIN_KEY_SOURCES`]).
fn schema_path_matches(pattern: &[&str], path: &[ConfigPathComponent]) -> bool {
    match (pattern.split_first(), path.split_first()) {
        (None, None) => true,
        // An array at the field: its entries inherit the field.
        (None, Some((ConfigPathComponent::Index(_), rest))) => schema_path_matches(pattern, rest),
        (None, Some(_)) | (Some(_), None) => false,
        (Some((&"*", pattern_rest)), Some((_, rest))) => schema_path_matches(pattern_rest, rest),
        (Some((head, pattern_rest)), Some((ConfigPathComponent::Key(key), rest))) => {
            key == head && schema_path_matches(pattern_rest, rest)
        }
        (Some(_), Some((ConfigPathComponent::Index(_), rest))) => {
            schema_path_matches(pattern, rest)
        }
    }
}

/// Whether `path` in a `plugin_name` config is a schema private-key source
/// ([`PLUGIN_KEY_SOURCES`]).
pub(crate) fn is_plugin_key_source(plugin_name: &str, path: &[ConfigPathComponent]) -> bool {
    PLUGIN_KEY_SOURCES
        .iter()
        .any(|(name, pattern)| *name == plugin_name && schema_path_matches(pattern, path))
}

fn is_plugin_certificate_source(plugin_name: &str, path: &[ConfigPathComponent]) -> bool {
    PLUGIN_CERTIFICATE_SOURCES
        .iter()
        .any(|(name, pattern)| *name == plugin_name && schema_path_matches(pattern, path))
}

/// Where a private-key site sits, which decides whether it may be brokered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyPlacement {
    /// A private-key source field: brokered.
    KeySource,
    /// A certificate or CA field: never brokered, because the field also
    /// carries a public certificate that must stay reviewable and that no
    /// secretless validator stand-in can reproduce.
    Certificate,
    /// Any other string. Brokered unless it also carries a certificate
    /// ([`contains_public_pem_block`]).
    Other,
}

/// One string that holds TLS private-key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivateKeySite {
    /// Location below the swept value.
    pub path: Vec<ConfigPathComponent>,
    /// What the field is, by name ([`tls_material_field`]) or, in a plugin
    /// config, by schema.
    pub placement: KeyPlacement,
}

fn placement_by_name(field: Option<TlsMaterialField>) -> KeyPlacement {
    match field {
        Some(TlsMaterialField::PrivateKey) => KeyPlacement::KeySource,
        Some(TlsMaterialField::Public) => KeyPlacement::Certificate,
        None => KeyPlacement::Other,
    }
}

/// Every string under `value` that is TLS private-key material, the way Edge
/// sweeps a whole Proxy or Upstream body: each object key classifies its
/// value with [`tls_material_field`], and array entries inherit their field's
/// classification. The placement is by field name. `/config/export` site
/// prediction uses this sweep for plugin configs too, as Edge does.
pub(crate) fn private_key_sites(value: &Value) -> Vec<PrivateKeySite> {
    let mut out = Vec::new();
    sweep(value, &mut Vec::new(), None, &mut out);
    out
}

/// [`private_key_sites`] for the value of the field named `name` (a diff
/// entry's top-level field), so the field's own classification applies.
pub(crate) fn private_key_sites_in_field(name: &str, value: &Value) -> Vec<PrivateKeySite> {
    let mut out = Vec::new();
    sweep(value, &mut Vec::new(), tls_material_field(name), &mut out);
    out
}

/// TLS private-key material in one plugin config: the name-based sweep plus
/// the private-key field rule at schema key sources
/// ([`PLUGIN_KEY_SOURCES`]). Placement comes from the schema: a schema key
/// source is [`KeyPlacement::KeySource`], a schema certificate source or a
/// certificate-named field is [`KeyPlacement::Certificate`], and everything
/// else, including a map entry merely named like a key field, is
/// [`KeyPlacement::Other`].
pub(crate) fn plugin_private_key_sites(plugin_name: &str, config: &Value) -> Vec<PrivateKeySite> {
    let mut found = std::collections::BTreeSet::new();
    for site in private_key_sites(config) {
        found.insert(site.path);
    }
    collect_schema_key_sources(plugin_name, config, &mut Vec::new(), &mut found);
    found
        .into_iter()
        .map(|path| {
            let placement = if is_plugin_key_source(plugin_name, &path) {
                KeyPlacement::KeySource
            } else if is_plugin_certificate_source(plugin_name, &path)
                || placement_by_name(nearest_field(&path)) == KeyPlacement::Certificate
            {
                KeyPlacement::Certificate
            } else {
                KeyPlacement::Other
            };
            PrivateKeySite { path, placement }
        })
        .collect()
}

/// [`tls_material_field`] of the nearest object key on `path`.
fn nearest_field(path: &[ConfigPathComponent]) -> Option<TlsMaterialField> {
    path.iter()
        .rev()
        .find_map(|part| match part {
            ConfigPathComponent::Key(key) => Some(key.as_str()),
            ConfigPathComponent::Index(_) => None,
        })
        .and_then(tls_material_field)
}

fn collect_schema_key_sources(
    plugin_name: &str,
    value: &Value,
    path: &mut Vec<ConfigPathComponent>,
    found: &mut std::collections::BTreeSet<Vec<ConfigPathComponent>>,
) {
    match value {
        Value::String(text) => {
            if is_plugin_key_source(plugin_name, path)
                && is_private_key_material(text, Some(TlsMaterialField::PrivateKey))
            {
                found.insert(path.clone());
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                path.push(ConfigPathComponent::Key(key.clone()));
                collect_schema_key_sources(plugin_name, child, path, found);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                collect_schema_key_sources(plugin_name, child, path, found);
                path.pop();
            }
        }
        _ => {}
    }
}

fn sweep(
    value: &Value,
    path: &mut Vec<ConfigPathComponent>,
    field: Option<TlsMaterialField>,
    out: &mut Vec<PrivateKeySite>,
) {
    match value {
        Value::String(text) => {
            if is_private_key_material(text, field) {
                out.push(PrivateKeySite {
                    path: path.clone(),
                    placement: placement_by_name(field),
                });
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                path.push(ConfigPathComponent::Key(key.clone()));
                sweep(child, path, tls_material_field(key), out);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                sweep(child, path, field, out);
                path.pop();
            }
        }
        _ => {}
    }
}

/// TLS material fields under `value` that hold exactly `sentinel` (the
/// `[REDACTED]` placeholder Edge substitutes for withheld material on a
/// non-admin read): a certificate- or key-named field anywhere, and, in a
/// plugin config (`plugin_name`), the schema key and certificate sources. A
/// backup carrying one was read through a redacting endpoint, so the value
/// cannot be imported.
pub(crate) fn redacted_material_sites(
    plugin_name: Option<&str>,
    value: &Value,
    sentinel: &str,
) -> Vec<Vec<ConfigPathComponent>> {
    fn walk(
        plugin_name: Option<&str>,
        value: &Value,
        sentinel: &str,
        path: &mut Vec<ConfigPathComponent>,
        out: &mut Vec<Vec<ConfigPathComponent>>,
    ) {
        match value {
            Value::String(text) if text == sentinel => {
                let schema = plugin_name.is_some_and(|name| {
                    is_plugin_key_source(name, path) || is_plugin_certificate_source(name, path)
                });
                if schema || nearest_field(path).is_some() {
                    out.push(path.clone());
                }
            }
            Value::Object(map) => {
                for (key, child) in map {
                    path.push(ConfigPathComponent::Key(key.clone()));
                    walk(plugin_name, child, sentinel, path, out);
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    path.push(ConfigPathComponent::Index(index));
                    walk(plugin_name, child, sentinel, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(plugin_name, value, sentinel, &mut Vec::new(), &mut out);
    out
}

/// The label of the PEM opening line at `start` (just after `-----BEGIN`),
/// read up to the next `-----` like Edge's detector, and where it ends.
fn banner_label(upper: &str, start: usize) -> (&str, usize) {
    const BANNER: &str = "-----BEGIN";
    let after = start + BANNER.len();
    match upper[after..].find("-----") {
        Some(end) => (&upper[after..after + end], after + end),
        None => (&upper[after..], upper.len()),
    }
}

/// Whether `value` also carries a PEM block that is not a private key (a
/// certificate, a CA bundle): a certificate-plus-key bundle.
pub(crate) fn contains_public_pem_block(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper
        .match_indices("-----BEGIN")
        .any(|(start, _)| !banner_label(&upper, start).0.contains("PRIVATE KEY"))
}

/// Each private-key PEM block in `value`, armour included, in one forward
/// pass over non-overlapping blocks, so the work is linear in the value: a
/// block ends at the close of its `-----END ...-----` line, and an
/// unterminated block runs to the end of the value once, after which the
/// scan stops.
fn private_key_block_slices(value: &str) -> Vec<&str> {
    const BANNER: &str = "-----BEGIN";
    const END: &str = "-----END";
    let upper = value.to_ascii_uppercase();
    let mut blocks = Vec::new();
    let mut cursor = 0;
    while let Some(found) = upper[cursor..].find(BANNER) {
        let start = cursor + found;
        let (label, label_end) = banner_label(&upper, start);
        if !label.contains("PRIVATE KEY") {
            cursor = start + BANNER.len();
            continue;
        }
        let stop = upper[label_end..]
            .find(END)
            .map(|end| label_end + end + END.len())
            .and_then(|end| upper[end..].find("-----").map(|close| end + close + 5))
            .unwrap_or(value.len());
        blocks.push(&value[start..stop]);
        if stop >= value.len() {
            break;
        }
        cursor = stop;
    }
    blocks
}

/// Each private-key PEM block inside `value` (armour included), when the
/// value holds more than that block alone: a certificate-plus-key bundle, or
/// a key with surrounding text. A consumer that echoes only the key block, or
/// one block of several, is then matched too. Linear in the value
/// ([`private_key_block_slices`]).
pub(crate) fn embedded_private_key_blocks(value: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    private_key_block_slices(value)
        .into_iter()
        .filter(|block| *block != value && seen.insert(*block))
        .map(str::to_string)
        .collect()
}

/// The encoded body lines of every private-key block in `value` (of the
/// whole value when it holds none, as material at a private-key field may)
/// that are at least `min_len` bytes: the parts of a key that survive any re-wrapping,
/// re-indentation or escaping of its line breaks (including a key embedded
/// with `\n` escapes in a JSON string, such as a service-account document).
/// Each is a single-line base64 run, so it can be matched on its own.
pub(crate) fn private_key_body_lines(value: &str, min_len: usize) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut lines = Vec::new();
    let mut blocks = private_key_block_slices(value);
    if blocks.is_empty() {
        // Material only by the private-key field rule (other armour, or a
        // control character): the whole value is the key.
        blocks.push(value);
    }
    for block in blocks {
        for line in block
            .split(['\n', '\r'])
            .flat_map(|line| line.split("\\n"))
            .flat_map(|line| line.split("\\r"))
        {
            let line = line.trim();
            if line.len() >= min_len && !line.starts_with("-----") && seen.insert(line) {
                lines.push(line.to_string());
            }
        }
    }
    lines
}

/// The spellings of one private-key value a consumer may echo besides the
/// stored bytes: line endings normalized to LF and to CRLF. A PEM block is
/// multi-line, so an emitter, a terminal or a Git checkout that rewrites line
/// endings would otherwise produce a copy no needle matches. Only the forms
/// that differ from `value` are returned.
pub(crate) fn line_ending_variants(value: &str) -> Vec<String> {
    let lf = value.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    let mut variants = Vec::new();
    for variant in [lf, crlf] {
        if variant != value && !variants.contains(&variant) {
            variants.push(variant);
        }
    }
    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header-detector inputs. The bodies are synthetic text, not key
    /// material: the detector reads armour, never the encoded key.
    #[test]
    fn detector_matches_edge_private_key_banners() {
        for (value, expected) in [
            (
                "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
                true,
            ),
            ("-----BEGIN RSA PRIVATE KEY-----\nsynthetic", true),
            ("-----BEGIN EC PRIVATE KEY-----", true),
            ("-----BEGIN ENCRYPTED PRIVATE KEY-----", true),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", true),
            ("-----begin private key-----", true),
            // Edge reads the label up to the next `-----`, across lines.
            ("-----BEGIN\nPRIVATE KEY-----", true),
            (
                "-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n\
                 -----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
                true,
            ),
            ("-----BEGIN CERTIFICATE-----\nsynthetic", false),
            ("-----BEGIN PUBLIC KEY-----", false),
            ("/etc/ferrum/tls/client.key", false),
            ("vault://secret/tls#key", false),
            ("${gh-env-secret:alloc=require}", false),
        ] {
            assert_eq!(contains_inline_private_key(value), expected, "{value:?}");
        }
    }

    #[test]
    fn key_fields_fail_closed_but_paths_stay_references() {
        let key = Some(TlsMaterialField::PrivateKey);
        let cert = Some(TlsMaterialField::Public);
        assert!(is_private_key_material("-----BEGIN CERTIFICATE-----", key));
        assert!(is_private_key_material("line\nbreak", key));
        assert!(!is_private_key_material(
            "-----BEGIN CERTIFICATE-----",
            cert
        ));
        assert!(!is_private_key_material("line\nbreak", cert));
        for reference in [
            "/etc/ferrum/tls/client.key",
            "C:\\ferrum\\client.key",
            "k8s://ns/secret#tls.key",
            "${gh-env-secret:alloc=require}",
        ] {
            assert!(!is_private_key_material(reference, key), "{reference}");
        }
    }

    #[test]
    fn sweep_classifies_by_field_and_inherits_through_arrays() {
        let value = serde_json::json!({
            "backend_tls_client_key_path": "-----BEGIN PRIVATE KEY-----\nx",
            "backend_tls_client_cert_path": "/etc/ferrum/tls/client.crt",
            "ca_certificates": ["-----BEGIN CERTIFICATE-----\nx", "-----BEGIN EC PRIVATE KEY-----\nx"],
            "nested": {"private_key": ["-----BEGIN CERTIFICATE-----"]},
            "dtls_key_path": "-----BEGIN PRIVATE KEY-----"
        });
        let rendered: Vec<(String, KeyPlacement)> = private_key_sites(&value)
            .iter()
            .map(|site| {
                (
                    super::super::plugin_config::render_config_path(&site.path),
                    site.placement,
                )
            })
            .collect();
        assert_eq!(
            rendered,
            [
                (
                    "backend_tls_client_key_path".to_string(),
                    KeyPlacement::KeySource
                ),
                ("ca_certificates.[1]".to_string(), KeyPlacement::Certificate),
                ("dtls_key_path".to_string(), KeyPlacement::Other),
                (
                    "nested.private_key.[0]".to_string(),
                    KeyPlacement::KeySource
                ),
            ]
        );
    }

    #[test]
    fn plugin_placement_follows_the_schema_not_the_leaf_name() {
        let render = |plugin: &str, config: serde_json::Value| -> Vec<(String, KeyPlacement)> {
            plugin_private_key_sites(plugin, &config)
                .iter()
                .map(|site| {
                    (
                        super::super::plugin_config::render_config_path(&site.path),
                        site.placement,
                    )
                })
                .collect()
        };
        // `dtls_key_path` fails closed on any armour or control character.
        assert_eq!(
            render(
                "udp_logging",
                serde_json::json!({
                    "dtls_key_path": "-----BEGIN EC PARAMETERS-----\nx",
                    "dtls_cert_path": "-----BEGIN CERTIFICATE-----\nc\n-----BEGIN PRIVATE KEY-----\nk"
                })
            ),
            [
                ("dtls_cert_path".to_string(), KeyPlacement::Certificate),
                ("dtls_key_path".to_string(), KeyPlacement::KeySource),
            ]
        );
        assert!(render(
            "udp_logging",
            serde_json::json!({"dtls_key_path": "line\nbreak"})
        )
        .iter()
        .any(|(path, _)| path == "dtls_key_path"));
        assert!(render(
            "udp_logging",
            serde_json::json!({"dtls_key_path": "/etc/dtls.key"})
        )
        .is_empty());
        assert_eq!(
            render(
                "mesh_route_dispatch",
                serde_json::json!({"rules": [{"destination": {"backend_tls": {
                    "client_key_path": "-----BEGIN PRIVATE KEY-----"
                }}}]})
            ),
            [(
                "rules.[0].destination.backend_tls.client_key_path".to_string(),
                KeyPlacement::KeySource
            )]
        );
        // A header named like a key field is not a key source.
        assert_eq!(
            render(
                "http_logging",
                serde_json::json!({"custom_headers": {"private_key": "-----BEGIN PRIVATE KEY-----"}})
            ),
            [(
                "custom_headers.private_key".to_string(),
                KeyPlacement::Other
            )]
        );
        assert!(!is_plugin_key_source(
            "http_logging",
            &[
                ConfigPathComponent::Key("custom_headers".into()),
                ConfigPathComponent::Key("private_key".into())
            ]
        ));
    }

    #[test]
    fn bundles_are_told_apart_from_bare_keys() {
        assert!(contains_public_pem_block(
            "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----"
        ));
        assert!(!contains_public_pem_block(
            "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n"
        ));
    }

    #[test]
    fn body_lines_survive_escaped_line_breaks() {
        let pem =
            "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktM\nTU5P\n-----END PRIVATE KEY-----\n";
        assert_eq!(private_key_body_lines(pem, 8), ["QUJDREVGR0hJSktM"]);
        let escaped = format!("{{\"private_key\": {pem:?}}}");
        assert_eq!(private_key_body_lines(&escaped, 8), ["QUJDREVGR0hJSktM"]);
        let bundle = format!(
            "-----BEGIN CERTIFICATE-----\nQ0VSVElGSUNBVEU=\n-----END CERTIFICATE-----\n{pem}"
        );
        assert_eq!(private_key_body_lines(&bundle, 8), ["QUJDREVGR0hJSktM"]);
    }

    #[test]
    fn block_extraction_is_linear_on_repeated_unterminated_banners() {
        let hostile = "-----BEGIN PRIVATE KEY ".repeat(20_000);
        let blocks = embedded_private_key_blocks(&hostile);
        // One unterminated block from the first banner; the copy is bounded
        // by the value.
        assert!(blocks.iter().map(String::len).sum::<usize>() <= hostile.len());
        assert!(blocks.len() <= 1, "{}", blocks.len());
    }

    #[test]
    fn embedded_blocks_isolate_each_key_of_a_bundle() {
        let cert = "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN EC PRIVATE KEY-----\nk\n-----END EC PRIVATE KEY-----";
        assert_eq!(
            embedded_private_key_blocks(&format!("{cert}{key}\n")),
            [key]
        );
        assert!(embedded_private_key_blocks(key).is_empty());
        assert_eq!(
            embedded_private_key_blocks("x -----BEGIN PRIVATE KEY-----\nunterminated"),
            ["-----BEGIN PRIVATE KEY-----\nunterminated"]
        );
    }

    #[test]
    fn line_ending_variants_cover_both_conventions() {
        assert_eq!(line_ending_variants("a\nb"), ["a\r\nb"]);
        assert_eq!(line_ending_variants("a\r\nb"), ["a\nb"]);
        assert!(line_ending_variants("single-line").is_empty());
    }
}
