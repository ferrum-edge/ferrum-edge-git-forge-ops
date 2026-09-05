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
/// plugin config puts `@plugin-config`, so this keeps discovery secrets in
/// their own keyspace while preserving the shared
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
