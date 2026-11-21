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

/// Field names whose value is a private-key *source* the broker may hold:
/// Edge's private-key slots plus `udp_logging`'s `dtls_key_path`, which Edge
/// classifies by content only. Inline material at one of these is brokered
/// (`${gh-env-secret:alloc=require}`); material anywhere else, such as a
/// certificate-plus-key bundle in a certificate field, is refused instead,
/// because the field also carries public material that must stay reviewable
/// and that a secretless validator stand-in could not reproduce.
pub(crate) fn is_key_source_field(name: &str) -> bool {
    tls_material_field(name) == Some(TlsMaterialField::PrivateKey) || name == "dtls_key_path"
}

/// Whether the nearest object key on `path` (array indices skipped) is a
/// [`is_key_source_field`].
pub(crate) fn is_key_source_path(path: &[ConfigPathComponent]) -> bool {
    path.iter()
        .rev()
        .find_map(|part| match part {
            ConfigPathComponent::Key(key) => Some(key.as_str()),
            ConfigPathComponent::Index(_) => None,
        })
        .is_some_and(is_key_source_field)
}

/// One string that holds TLS private-key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivateKeySite {
    /// Location below the swept value.
    pub path: Vec<ConfigPathComponent>,
    /// The field is a private-key source ([`is_key_source_field`]), so the
    /// string may be brokered there.
    pub key_source: bool,
}

/// Every string under `value` that is TLS private-key material, the way Edge
/// sweeps a whole Proxy or Upstream body or a plugin config: each object key
/// classifies its value with [`tls_material_field`], and array entries inherit
/// their field's classification.
pub(crate) fn private_key_sites(value: &Value) -> Vec<PrivateKeySite> {
    let mut out = Vec::new();
    sweep(value, &mut Vec::new(), None, false, &mut out);
    out
}

/// [`private_key_sites`] for the value of the field named `name` (a diff
/// entry's top-level field), so the field's own classification applies.
pub(crate) fn private_key_sites_in_field(name: &str, value: &Value) -> Vec<PrivateKeySite> {
    let mut out = Vec::new();
    sweep(
        value,
        &mut Vec::new(),
        tls_material_field(name),
        is_key_source_field(name),
        &mut out,
    );
    out
}

fn sweep(
    value: &Value,
    path: &mut Vec<ConfigPathComponent>,
    field: Option<TlsMaterialField>,
    key_source: bool,
    out: &mut Vec<PrivateKeySite>,
) {
    match value {
        Value::String(text) => {
            if is_private_key_material(text, field) {
                out.push(PrivateKeySite {
                    path: path.clone(),
                    key_source,
                });
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                path.push(ConfigPathComponent::Key(key.clone()));
                sweep(
                    child,
                    path,
                    tls_material_field(key),
                    is_key_source_field(key),
                    out,
                );
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                sweep(child, path, field, key_source, out);
                path.pop();
            }
        }
        _ => {}
    }
}

/// Each private-key PEM block inside `value` (armour included), when the
/// value holds more than that block alone: a certificate-plus-key bundle, or
/// a key with surrounding text. A consumer that echoes only the key block, or
/// one block of several, is then matched too. A block with no closing
/// armour runs to the end of the value.
pub(crate) fn embedded_private_key_blocks(value: &str) -> Vec<String> {
    const BANNER: &str = "-----BEGIN";
    const END: &str = "-----END";
    let upper = value.to_ascii_uppercase();
    let mut blocks = Vec::new();
    for (start, _) in upper.match_indices(BANNER) {
        let after = &upper[start + BANNER.len()..];
        let label = after.find("-----").map_or(after, |end| &after[..end]);
        if !label.contains("PRIVATE KEY") {
            continue;
        }
        let stop = upper[start..]
            .find(END)
            .map(|end| start + end + END.len())
            .and_then(|end| upper[end..].find("-----").map(|close| end + close + 5))
            .unwrap_or(value.len());
        let block = &value[start..stop];
        if block != value && !blocks.iter().any(|known| known == block) {
            blocks.push(block.to_string());
        }
    }
    blocks
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
        let sites = private_key_sites(&value);
        let rendered: Vec<(String, bool)> = sites
            .iter()
            .map(|site| {
                (
                    super::super::plugin_config::render_config_path(&site.path),
                    site.key_source,
                )
            })
            .collect();
        assert_eq!(
            rendered,
            [
                ("backend_tls_client_key_path".to_string(), true),
                ("ca_certificates.[1]".to_string(), false),
                ("dtls_key_path".to_string(), true),
                ("nested.private_key.[0]".to_string(), true),
            ]
        );
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
