//! Modeled secret leaves of `Upstream.service_discovery`.
//!
//! Consumer credentials and plugin config are not the only secret-bearing
//! places in a gateway document. A discovery provider authenticates to its own
//! control plane, and `GET /backup` returns that credential verbatim like any
//! other field. Without a classification of its own it would be written into
//! the resource tree by `import`, printed by `diff`, and echoed by the
//! validator.
//!
//! This module is the single place that says *which* service-discovery leaves
//! are secret. Import capture, slot derivation, resolution, diff redaction,
//! validator scrubbing and the literal-credential audit all read the same
//! table, so a provider added later cannot be protected in one path and
//! forgotten in the other four.
//!
//! # What is in the table, and what deliberately is not
//!
//! Every modeled provider was reviewed field by field
//! ([`crate::config::schema::ServiceDiscoveryConfig`]):
//!
//! * `consul` — `token` is a Consul ACL token and is the one secret. `address`
//!   is the control-plane URL, `service_name`, `datacenter` and `tag` are
//!   selectors: all four name *what* is discovered, are needed to review a
//!   change, and are already covered by the `allowed_backend_domains` policy.
//!   An `address` must therefore carry no URL userinfo: credentials there are
//!   refused by import and by the security audit, and redacted from a diff
//!   (see [`consul_address_has_userinfo`]). The ACL token belongs in `token`.
//! * `dns_sd`, `kubernetes`, `mesh` — no secret-bearing field. Kubernetes
//!   discovery authenticates with the pod's own service-account token from
//!   the gateway's filesystem, never from this document; mesh discovery
//!   authenticates with SPIFFE identities.
//!
//! Adding a provider secret is one entry here plus its accessor arm in
//! [`secret_leaf`] / [`secret_leaf_mut`]; nothing else changes.

use crate::config::schema::{ServiceDiscoveryConfig, Upstream};

/// Reserved third slot component for brokered service-discovery strings.
///
/// Consumer slots put the credential type here (`keyauth`, `jwt`, …) and
/// plugin config puts `@plugin` (followed by the plugin type), so this keeps
/// discovery secrets in their own keyspace while preserving the shared
/// `<namespace>/<resource-id>/<kind>/…` bundle shape. The `@` prefix is what
/// makes the marker unmistakable: no ferrum-edge credential type starts with
/// one.
pub(crate) const SERVICE_DISCOVERY_SLOT_KIND: &str = "@service-discovery";

/// One modeled secret-bearing service-discovery field.
pub(crate) struct SdSecretField {
    /// Path under `service_discovery`, spelled as the document spells it.
    /// Also the slot path suffix: `consul`/`token` →
    /// `<ns>/<upstream>/@service-discovery/consul/token`.
    pub path: &'static [&'static str],
    /// Whether the broker may mint a fresh value for this field.
    ///
    /// `false` means `alloc=generate` is refused before any GitHub write: a
    /// random string is not a credential the *other* system will accept, so
    /// generating one produces a slot whose value can never authenticate.
    pub generatable: bool,
    /// Why a random value is useless here, for the refusal message.
    pub ungeneratable_reason: &'static str,
}

/// The modeled secret leaves, in slot order.
pub(crate) const SD_SECRET_FIELDS: &[SdSecretField] = &[SdSecretField {
    path: &["consul", "token"],
    generatable: false,
    ungeneratable_reason:
        "a Consul ACL token is minted by the Consul cluster and bound to its policies, so a random \
         value can never authenticate",
}];

/// Read one modeled secret leaf.
pub(crate) fn secret_leaf<'a>(
    discovery: &'a ServiceDiscoveryConfig,
    path: &[&str],
) -> Option<&'a String> {
    match path {
        ["consul", "token"] => discovery.consul.as_ref()?.token.as_ref(),
        _ => None,
    }
}

/// Mutable access to one modeled secret leaf's *slot*, so a caller can both
/// replace and clear it. `None` when the provider block itself is absent.
pub(crate) fn secret_leaf_mut<'a>(
    discovery: &'a mut ServiceDiscoveryConfig,
    path: &[&str],
) -> Option<&'a mut Option<String>> {
    match path {
        ["consul", "token"] => discovery.consul.as_mut().map(|consul| &mut consul.token),
        _ => None,
    }
}

/// Whether this discovery block's Consul `address` carries URL userinfo
/// (`scheme://user[:password]@host…`), a credential the address is never
/// allowed to hold.
pub(crate) fn consul_address_has_userinfo(discovery: &ServiceDiscoveryConfig) -> bool {
    consul_address_userinfo(discovery).is_some()
}

/// The userinfo of this discovery block's Consul `address`, if it has one.
pub(crate) fn consul_address_userinfo(discovery: &ServiceDiscoveryConfig) -> Option<String> {
    let consul = discovery.consul.as_ref()?;
    split_url_userinfo(&consul.address).map(|parts| parts.userinfo)
}

/// Whether detection had to normalize `address` (surrounding whitespace or
/// control characters, or an embedded tab or line break), so the bytes as
/// written may differ from the userinfo it reports.
pub(crate) fn address_is_normalized(address: &str) -> bool {
    address.trim_matches(|c: char| c <= ' ') != address || address.contains(['\t', '\n', '\r'])
}

/// `text` with the userinfo of a URL replaced by [`crate::secrets::REDACTION`],
/// or `None` when it carries none.
pub(crate) fn redact_url_userinfo(text: &str) -> Option<String> {
    let parts = split_url_userinfo(text)?;
    let redacted = format!("{}@{}", crate::secrets::REDACTION, parts.after);
    Some(match parts.scheme {
        Some(scheme) => format!("{scheme}://{redacted}"),
        None => redacted,
    })
}

struct UrlUserinfo {
    scheme: Option<String>,
    userinfo: String,
    after: String,
}

/// Find a URL's userinfo the way a lenient (WHATWG-style) parser would, and
/// err towards finding one: surrounding whitespace and control characters
/// and embedded tabs and newlines are ignored, any number of `/` or `\`
/// may follow the scheme (`https:///u:p@h`, `https:u:p@h`), and an `@`
/// anywhere before the first `/`, `\`, `?` or `#` counts, with or without a
/// scheme.
fn split_url_userinfo(text: &str) -> Option<UrlUserinfo> {
    let cleaned: String = text
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let (scheme, rest) = match cleaned.find(':') {
        Some(colon) if is_url_scheme(&cleaned[..colon]) => {
            (Some(cleaned[..colon].to_string()), &cleaned[colon + 1..])
        }
        _ => (None, cleaned.as_str()),
    };
    let rest = rest.trim_start_matches(['/', '\\']);
    let authority_end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let at = rest[..authority_end].rfind('@')?;
    Some(UrlUserinfo {
        scheme,
        userinfo: rest[..at].to_string(),
        after: rest[at + 1..].to_string(),
    })
}

fn is_url_scheme(candidate: &str) -> bool {
    let mut characters = candidate.chars();
    characters.next().is_some_and(|c| c.is_ascii_alphabetic())
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Every modeled secret leaf that this upstream actually carries a value for.
pub(crate) fn present_secrets(
    upstream: &Upstream,
) -> impl Iterator<Item = (&'static SdSecretField, &String)> {
    upstream.service_discovery.iter().flat_map(|discovery| {
        SD_SECRET_FIELDS
            .iter()
            .filter_map(move |field| secret_leaf(discovery, field.path).map(|v| (field, v)))
    })
}

/// Canonical broker slot for one service-discovery secret leaf.
pub(crate) fn slot(namespace: &str, upstream_id: &str, path: &[&str]) -> String {
    let mut pieces = vec![
        super::resolver::escape_slot_component(namespace),
        super::resolver::escape_slot_component(upstream_id),
        super::resolver::escape_slot_component(SERVICE_DISCOVERY_SLOT_KIND),
    ];
    pieces.extend(
        path.iter()
            .map(|part| super::resolver::escape_slot_component(part)),
    );
    pieces.join("/")
}

/// The `cred_key` half of a slot, for report entries and
/// `gitforgeops rotate --credential`.
pub(crate) fn cred_key(path: &[&str]) -> String {
    let mut pieces = vec![SERVICE_DISCOVERY_SLOT_KIND.to_string()];
    pieces.extend(
        path.iter()
            .map(|part| super::resolver::escape_slot_component(part)),
    );
    pieces.join("/")
}

/// Render a field path the way an operator reads it: `consul.token`.
pub(crate) fn render_path(path: &[&str]) -> String {
    path.join(".")
}
