//! Throwaway `private_key_jwt` signing keys for the validator's input document.
//!
//! `oauth2_introspection` and `oidc_relying_party` do not merely check that a
//! `providers[*].client_auth.private_key_pem` is present: Edge parses it as a
//! key of the family the sibling `private_key_jwt_alg` selects and signs one
//! throwaway client assertion with it at admission. An opaque token stand-in
//! is therefore refused as malformed PEM, so a brokered key would fail every
//! secretless PR validation on the brokering rather than on the configuration.
//!
//! The stand-in is a real key, generated in-process with AWS-LC (the provider
//! `jsonwebtoken` already signs admin tokens with) and cached once per key
//! family for the life of the process. Nothing about it is secret: it is never
//! written anywhere but the 0600 temp spec handed to `ferrum-edge validate`,
//! never committed, exported, applied or delivered, and it signs nothing but
//! Edge's own admission probe. It is also not a scrubber value, like every
//! other stand-in: the scrubber is built from the placeholder document, and a
//! multi-line PEM registered there would withhold every validator diagnostic
//! (see [`crate::secrets::is_reencoding_hazard`]). Edge's key diagnostics never
//! quote the key, but a wrapper around the validator could echo its input, so
//! [`mask_generated_keys`] masks every generated key body in the captured
//! output separately, without withholding anything.
//!
//! Unlike the other stand-ins it is not deterministic across runs: AWS-LC
//! cannot derive an RSA key from a seed, and Edge never reports a key back, so
//! a byte-identical document buys nothing here.

use std::sync::OnceLock;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};
use base64::Engine;

/// The key family a `private_key_jwt_alg` needs Edge's admission probe to
/// accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientKeyFamily {
    /// `RS256` / `RS384` / `RS512` (and `PS*`, which Edge does not accept).
    /// 2048 bits is the signing backend's minimum modulus.
    Rsa2048,
    /// `ES256`.
    P256,
    /// `ES384`.
    P384,
    /// `EdDSA`.
    Ed25519,
}

impl ClientKeyFamily {
    /// The family for the sibling `private_key_jwt_alg` value.
    ///
    /// Spelled exactly as Edge matches them (v0.9.20 and later accept
    /// `RS256`, `RS384`, `RS512`, `ES256`, `ES384` and `EdDSA`). Anything else
    /// gets an RSA key: absent or `null` selects Edge's `RS256` default, and
    /// Edge refuses an unsupported or non-string algorithm before it reads the
    /// key, so the validator reports the algorithm itself, which is the
    /// verdict the configuration deserves. Failing here instead would hide
    /// that diagnostic behind a GitForgeOps error.
    pub(crate) fn for_alg(alg: Option<&str>) -> Self {
        match alg {
            Some("ES256") => Self::P256,
            Some("ES384") => Self::P384,
            Some("EdDSA") => Self::Ed25519,
            _ => Self::Rsa2048,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Rsa2048 => 0,
            Self::P256 => 1,
            Self::P384 => 2,
            Self::Ed25519 => 3,
        }
    }
}

/// A PKCS#8 `PRIVATE KEY` PEM of `family`, generated once per process.
///
/// `None` only if AWS-LC cannot generate a key (an exhausted or broken
/// entropy source); the caller then falls back to the opaque token stand-in,
/// which Edge reports as malformed PEM, exactly as before keys were generated.
pub(crate) fn client_assertion_key_pem(family: ClientKeyFamily) -> Option<&'static str> {
    KEYS[family.index()]
        .get_or_init(|| generate_pkcs8(family).map(|der| pem_private_key(&der)))
        .as_deref()
}

/// One generated key per [`ClientKeyFamily`], in [`ClientKeyFamily::index`]
/// order.
static KEYS: [OnceLock<Option<String>>; 4] = [
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
    OnceLock::new(),
];

/// Text that replaces a generated key's body in captured validator output.
pub(crate) const GENERATED_KEY_MASK: &str = "[VALIDATION-STANDIN-KEY]";

/// Shortest PEM body line masked on its own. A key's last base64 line can be
/// a few characters long (`AA==`), short enough to occur in ordinary text;
/// every other line is the full 64 characters.
const MIN_MASKED_LINE: usize = 16;

/// `text` with the body of every key this process generated masked.
///
/// The temp spec renders a key as one quoted YAML line with `\n` escapes; a
/// wrapper echoing that line, the PEM itself, a block scalar or JSON keeps the
/// same 64-character base64 lines. So the contiguous body (a re-encoding that
/// dropped the line breaks) is masked first, then each body line. Families
/// never generated cost nothing.
pub(crate) fn mask_generated_keys(text: &str) -> String {
    let mut masked = text.to_string();
    for pem in KEYS.iter().filter_map(|key| key.get()?.as_deref()) {
        let lines: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let needles = std::iter::once(lines.concat()).chain(
            lines
                .iter()
                .filter(|line| line.len() >= MIN_MASKED_LINE)
                .map(|line| line.to_string()),
        );
        for needle in needles {
            if masked.contains(&needle) {
                masked = masked.replace(&needle, GENERATED_KEY_MASK);
            }
        }
    }
    masked
}

/// PKCS#8 v1 DER for a fresh key. v1 everywhere: `jsonwebtoken`'s PEM reader
/// classifies the key by its algorithm OID and hands the RSA `RSAPrivateKey`
/// or the whole EC / Ed25519 document to AWS-LC, which accepts all three.
fn generate_pkcs8(family: ClientKeyFamily) -> Option<Vec<u8>> {
    let ecdsa = |alg: &'static EcdsaSigningAlgorithm| {
        EcdsaKeyPair::generate(alg)
            .and_then(|key| key.to_pkcs8v1())
            .map(|document| document.as_ref().to_vec())
            .ok()
    };
    match family {
        ClientKeyFamily::Rsa2048 => RsaKeyPair::generate(KeySize::Rsa2048)
            .and_then(|key| key.as_der())
            .map(|der| der.as_ref().to_vec())
            .ok(),
        ClientKeyFamily::P256 => ecdsa(&ECDSA_P256_SHA256_FIXED_SIGNING),
        ClientKeyFamily::P384 => ecdsa(&ECDSA_P384_SHA384_FIXED_SIGNING),
        ClientKeyFamily::Ed25519 => Ed25519KeyPair::generate()
            .and_then(|key| key.to_pkcs8v1())
            .map(|document| document.as_ref().to_vec())
            .ok(),
    }
}

/// RFC 7468 armour: base64 in 64-character lines.
fn pem_private_key(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        // Base64 output is ASCII, so every chunk is valid UTF-8.
        pem.push_str(&String::from_utf8_lossy(line));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithms_select_the_family_edge_parses_them_with() {
        for (alg, family) in [
            (Some("RS256"), ClientKeyFamily::Rsa2048),
            (Some("RS384"), ClientKeyFamily::Rsa2048),
            (Some("RS512"), ClientKeyFamily::Rsa2048),
            (Some("PS256"), ClientKeyFamily::Rsa2048),
            (Some("ES256"), ClientKeyFamily::P256),
            (Some("ES384"), ClientKeyFamily::P384),
            (Some("EdDSA"), ClientKeyFamily::Ed25519),
            // Edge's default, and values Edge refuses on the algorithm alone.
            (None, ClientKeyFamily::Rsa2048),
            (Some("es256"), ClientKeyFamily::Rsa2048),
            (Some("ES512"), ClientKeyFamily::Rsa2048),
        ] {
            assert_eq!(ClientKeyFamily::for_alg(alg), family, "{alg:?}");
        }
    }

    #[test]
    fn keys_are_cached_per_family_and_armoured() {
        let first = client_assertion_key_pem(ClientKeyFamily::P256).expect("P-256 key");
        assert!(std::ptr::eq(
            first,
            client_assertion_key_pem(ClientKeyFamily::P256).expect("cached key")
        ));
        assert!(
            first != client_assertion_key_pem(ClientKeyFamily::Ed25519).expect("Ed25519 key"),
            "two families share a key"
        );
        // Failure messages name the check, never the key.
        assert!(
            first.starts_with("-----BEGIN PRIVATE KEY-----\n"),
            "missing BEGIN armour"
        );
        assert!(
            first.ends_with("\n-----END PRIVATE KEY-----\n"),
            "missing END armour"
        );
        assert!(
            first.lines().all(|line| line.len() <= 64),
            "a PEM line exceeds 64 characters"
        );
    }

    #[test]
    fn generated_key_bodies_are_masked_in_every_rendering() {
        let pem = client_assertion_key_pem(ClientKeyFamily::Rsa2048).expect("RSA key");
        let body: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let renderings = [
            format!("error: echo\n{pem}"),
            format!("private_key_pem: \"{}\"", pem.replace('\n', "\\n")),
            serde_json::to_string(pem).expect("JSON"),
            format!("key: |\n  {}", pem.replace('\n', "\n  ")),
            format!("der={}", body.concat()),
        ];
        for (index, rendering) in renderings.iter().enumerate() {
            let masked = mask_generated_keys(rendering);
            assert!(
                body.iter()
                    .filter(|line| line.len() >= MIN_MASKED_LINE)
                    .all(|line| !masked.contains(line)),
                "rendering {index} left a key line unmasked"
            );
            assert!(masked.contains(GENERATED_KEY_MASK), "rendering {index}");
        }
        // Ordinary diagnostics pass through untouched.
        let plain = "error: proxy httpbin: unknown field `listen_path_typo`";
        assert_eq!(mask_generated_keys(plain), plain);
    }
}
