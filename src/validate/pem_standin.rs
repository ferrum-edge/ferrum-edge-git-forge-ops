//! PEM-shaped validator stand-ins for brokered TLS private keys.
//!
//! Kept apart from [`super::standin`] so it can be unified with any other PEM
//! stand-in generator without touching the slot plumbing.
//!
//! # What Ferrum Edge checks
//!
//! `ferrum-edge validate -m file` (v0.9.20 and `main`) loads every Proxy and
//! Upstream `backend_tls_client_key_path` through `validate_pem_key_file`: a
//! value starting with `-----BEGIN ` is inline material, and
//! `parse_pem_private_key` requires exactly one PEM record with a private-key
//! label and well-formed base64. It does not decode the key or check it
//! against `backend_tls_client_cert_path` (only the DTLS identity of
//! `udp_logging` is paired with its certificate, in the plugin file-dependency
//! phase). The placeholder text itself would be read as a filesystem path and
//! fail to load, so a bundle-less run needs a stand-in of PEM shape.
//!
//! The stand-in is a `PRIVATE KEY` record whose body is the ASCII marker
//! [`PEM_STANDIN_MARKER`] followed by the SHA-256 of the slot: deterministic
//! per slot like the other stand-ins, obviously not key material, and not a
//! key any TLS stack could use. It exists only in the 0600 temp spec handed to
//! the validator.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Bytes every PEM stand-in body starts with, before base64.
pub const PEM_STANDIN_MARKER: &str = "gitforgeops-validation-standin";

/// The PEM stand-in for one brokered private-key slot.
pub fn validation_private_key_standin(slot: &str) -> String {
    let mut body = PEM_STANDIN_MARKER.as_bytes().to_vec();
    body.extend_from_slice(&Sha256::digest(slot.as_bytes()));
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}
