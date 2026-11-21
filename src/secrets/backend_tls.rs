//! Brokered backend TLS client keys on `Proxy` and `Upstream`.
//!
//! `backend_tls_client_key_path` names the private key a gateway presents to
//! a backend for mTLS. Ferrum Edge reads it as inline PEM when it starts with
//! `-----BEGIN `, so `GET /backup` can return the key itself. Inline key
//! material ([`super::tls_material::is_private_key_material`]) in this field is
//! a secret: import moves it into the migration bundle and writes
//! `${gh-env-secret:alloc=require}`, the resolver puts it back from the
//! bundle, and every redaction path removes it. A filesystem path or provider
//! URI names the key without disclosing it and stays literal.
//!
//! Slots use their own reserved kinds, one per resource kind, because a Proxy
//! and an Upstream may share an id in one namespace:
//!
//! * `<ns>/<proxy-id>/@proxy/backend_tls_client_key_path`
//! * `<ns>/<upstream-id>/@upstream/backend_tls_client_key_path`
//!
//! Generation is always refused: a random string is not a private key, and
//! the key has to match the certificate in `backend_tls_client_cert_path`.

use crate::config::schema::{Proxy, Upstream};
use crate::config::GatewayConfig;

/// The brokered field, spelled as the document spells it. Also the slot path
/// suffix.
pub(crate) const CLIENT_KEY_FIELD: &str = "backend_tls_client_key_path";

/// Reserved slot kind for brokered Proxy fields.
pub(crate) const PROXY_SLOT_KIND: &str = "@proxy";

/// Reserved slot kind for brokered Upstream fields.
pub(crate) const UPSTREAM_SLOT_KIND: &str = "@upstream";

/// Why the broker refuses to generate a client key.
pub(crate) const UNGENERATABLE_REASON: &str =
    "a backend TLS client key is a PEM private key that must match the certificate in \
     backend_tls_client_cert_path, so random bytes can never be one";

/// Which resource kind owns a brokered client key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendTlsOwner {
    Proxy,
    Upstream,
}

impl BackendTlsOwner {
    /// The resource kind as diagnostics spell it.
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Proxy => "Proxy",
            Self::Upstream => "Upstream",
        }
    }

    /// The reserved third slot component.
    pub(crate) fn slot_kind(self) -> &'static str {
        match self {
            Self::Proxy => PROXY_SLOT_KIND,
            Self::Upstream => UPSTREAM_SLOT_KIND,
        }
    }
}

/// Whether a slot's third component is one of this module's kinds.
pub(crate) fn is_slot_kind(kind: &str) -> bool {
    kind == PROXY_SLOT_KIND || kind == UPSTREAM_SLOT_KIND
}

/// Canonical broker slot of one resource's client key.
pub(crate) fn slot(owner: BackendTlsOwner, namespace: &str, id: &str) -> String {
    format!(
        "{}/{}/{}",
        super::resolver::escape_slot_component(namespace),
        super::resolver::escape_slot_component(id),
        cred_key(owner)
    )
}

/// The `cred_key` half of a slot, for report entries.
pub(crate) fn cred_key(owner: BackendTlsOwner) -> String {
    format!(
        "{}/{}",
        super::resolver::escape_slot_component(owner.slot_kind()),
        CLIENT_KEY_FIELD
    )
}

/// One declared client key, read-only.
pub(crate) struct ClientKey<'a> {
    pub owner: BackendTlsOwner,
    pub namespace: &'a str,
    pub id: &'a str,
    pub value: &'a String,
}

/// Every Proxy and Upstream client key `config` declares.
pub(crate) fn client_keys(config: &GatewayConfig) -> Vec<ClientKey<'_>> {
    let proxies = config.proxies.iter().filter_map(|proxy: &Proxy| {
        proxy
            .backend_tls_client_key_path
            .as_ref()
            .map(|value| ClientKey {
                owner: BackendTlsOwner::Proxy,
                namespace: &proxy.namespace,
                id: &proxy.id,
                value,
            })
    });
    let upstreams = config.upstreams.iter().filter_map(|upstream: &Upstream| {
        upstream
            .backend_tls_client_key_path
            .as_ref()
            .map(|value| ClientKey {
                owner: BackendTlsOwner::Upstream,
                namespace: &upstream.namespace,
                id: &upstream.id,
                value,
            })
    });
    proxies.chain(upstreams).collect()
}

/// One declared client key, writable. Rows owned by an API spec are
/// included; callers that skip them check `api_spec_owned`.
pub(crate) struct ClientKeyMut<'a> {
    pub owner: BackendTlsOwner,
    pub namespace: String,
    pub id: String,
    pub api_spec_owned: bool,
    pub value: &'a mut Option<String>,
}

/// Every Proxy and Upstream client-key slot in `config`, set or not.
pub(crate) fn client_keys_mut(config: &mut GatewayConfig) -> Vec<ClientKeyMut<'_>> {
    let GatewayConfig {
        proxies, upstreams, ..
    } = config;
    let proxies = proxies.iter_mut().map(|proxy| ClientKeyMut {
        owner: BackendTlsOwner::Proxy,
        namespace: proxy.namespace.clone(),
        id: proxy.id.clone(),
        api_spec_owned: proxy.api_spec_id.is_some(),
        value: &mut proxy.backend_tls_client_key_path,
    });
    let upstreams = upstreams.iter_mut().map(|upstream| ClientKeyMut {
        owner: BackendTlsOwner::Upstream,
        namespace: upstream.namespace.clone(),
        id: upstream.id.clone(),
        api_spec_owned: upstream.api_spec_id.is_some(),
        value: &mut upstream.backend_tls_client_key_path,
    });
    proxies.chain(upstreams).collect()
}

/// Whether a client-key value is inline private-key material rather than a
/// reference (a path, provider URI or broker placeholder).
pub(crate) fn is_client_key_material(value: &str) -> bool {
    super::tls_material::is_private_key_material(
        value,
        super::tls_material::tls_material_field(CLIENT_KEY_FIELD),
    )
}

/// Whether a [`super::tls_material::private_key_sites`] path in a serialized
/// Proxy or Upstream body is the brokered client-key field itself.
pub(crate) fn is_brokered_site(path: &[super::plugin_config::ConfigPathComponent]) -> bool {
    matches!(
        path,
        [super::plugin_config::ConfigPathComponent::Key(field)] if field == CLIENT_KEY_FIELD
    )
}

/// One Proxy or Upstream serialized whole, for sweeps over every field
/// (including undeclared passthrough fields), the way Edge sweeps a body.
pub(crate) struct ResourceBody<'a> {
    pub owner: BackendTlsOwner,
    pub namespace: &'a str,
    pub id: &'a str,
    pub api_spec_owned: bool,
    pub body: serde_json::Value,
}

/// Every Proxy and Upstream in `config`, serialized.
pub(crate) fn resource_bodies(
    config: &GatewayConfig,
) -> crate::error::Result<Vec<ResourceBody<'_>>> {
    let mut rows = Vec::with_capacity(config.proxies.len() + config.upstreams.len());
    for proxy in &config.proxies {
        rows.push(ResourceBody {
            owner: BackendTlsOwner::Proxy,
            namespace: &proxy.namespace,
            id: &proxy.id,
            api_spec_owned: proxy.api_spec_id.is_some(),
            body: serde_json::to_value(proxy)?,
        });
    }
    for upstream in &config.upstreams {
        rows.push(ResourceBody {
            owner: BackendTlsOwner::Upstream,
            namespace: &upstream.namespace,
            id: &upstream.id,
            api_spec_owned: upstream.api_spec_id.is_some(),
            body: serde_json::to_value(upstream)?,
        });
    }
    Ok(rows)
}
