//! Deterministic fake credentials for the validator's input document.
//!
//! `ferrum-edge validate` checks credential *shape*: a `jwt` or `hmac_auth`
//! secret must be at least 32 characters, a `basicauth` entry must carry a
//! `hmac_sha256:<64 hex>` hash in file mode, and so on. A PR-review run has
//! no credential bundle, so what reaches the validator is the placeholder
//! text itself — and `${gh-env-secret:alloc=generate}` is 30 characters, two
//! short of the floor. Every repo that brokers a `jwt` or `hmac_auth` secret
//! therefore failed validation in CI for a reason that has nothing to do with
//! the change under review.
//!
//! Brokered plugin config has the same problem in a different shape. The
//! sensitivity classifier brokers credential-bearing *endpoints* as well as
//! tokens, and the gateway parses those: a brokered `ldap_auth.ldap_url` comes
//! back as "'ldap_url' is not a valid URL: relative URL without a base", which
//! is a verdict on the brokering rather than on the configuration.
//!
//! So the validator gets stand-ins instead: an obviously fake value of
//! adequate *shape* — a 64-hex token, an `hmac_sha256:` digest, a
//! syntactically valid URL on a reserved `.invalid` host, or (for a
//! `private_key_jwt` key Edge signs with at admission) a throwaway key of the
//! selected algorithm's family, whichever the field calls for. Every shape but
//! the key is deterministic in the leaf's own broker slot. They exist for
//! exactly one file — the 0600 temp spec handed to `ferrum-edge validate` —
//! and are never exported, applied, written to state, or delivered.
//! `export --materialize` still refuses to run while any slot is unresolved;
//! `apply` still fails on `alloc=require` with no value.

use sha2::{Digest, Sha256};

use std::collections::{BTreeMap, BTreeSet};

use crate::config::GatewayConfig;
use crate::secrets::parse_placeholder;
use crate::secrets::plugin_config::{ConfigPathComponent, EndpointForm};
use crate::secrets::resolver::{consumer_credential_slot, ResolveReport, SlotStatus};
use crate::validate::client_key_standin::{client_assertion_key_pem, ClientKeyFamily};

/// Fixed marker every opaque stand-in starts with. It is deliberately
/// unmistakable: a value carrying this prefix anywhere but a validator temp
/// spec is a bug, and greppable as one.
pub const VALIDATION_STANDIN_PREFIX: &str = "gitforgeops-validation-standin-";

/// Host every URL-shaped stand-in points at.
///
/// `.invalid` is reserved by RFC 2606 and can never resolve, so a stand-in
/// that somehow escaped into a live configuration fails closed at connect
/// time instead of reaching a real host. Same greppability contract as
/// [`VALIDATION_STANDIN_PREFIX`].
pub const VALIDATION_STANDIN_HOST: &str = "gitforgeops-validation-standin.invalid";

/// Prefix ferrum-edge requires on a `basicauth` password hash, followed by 64
/// lowercase hex characters.
const BASIC_AUTH_HASH_PREFIX: &str = "hmac_sha256:";

/// The credential leaf whose value must be a gateway-computed HMAC digest
/// rather than free-form text.
const PASSWORD_HASH_LEAF: &str = "password_hash";

/// Build the stand-in for one credential leaf.
///
/// Deterministic in `slot`, so re-validating an unchanged repo produces a
/// byte-identical document (a validator that reports a value back does not
/// churn between runs), and distinct per slot, so a uniqueness constraint the
/// gateway enforces across credentials is still exercised.
///
/// Two shapes:
///
/// * `password_hash` → `hmac_sha256:<64 hex>`, the only shape ferrum-edge
///   accepts there. The digest is not a real HMAC under the gateway's secret
///   and could never authenticate anyone; it exists so the *format* check
///   passes.
/// * everything else → [`VALIDATION_STANDIN_PREFIX`] followed by 64 hex
///   characters, 95 in total. Comfortably past the 32-character floor
///   `jwt`/`hmac_auth` impose and well under the 4096-character ceiling.
pub fn validation_standin(slot: &str, leaf: Option<&str>) -> String {
    let digest = slot_digest(slot);

    if leaf == Some(PASSWORD_HASH_LEAF) {
        return format!("{BASIC_AUTH_HASH_PREFIX}{digest}");
    }
    format!("{VALIDATION_STANDIN_PREFIX}{digest}")
}

/// Build the stand-in for one brokered plugin-config leaf that the gateway
/// parses as a URL.
///
/// `<scheme>://gitforgeops-validation-standin.invalid/<64 hex>`: a
/// syntactically valid absolute URL, on a host RFC 2606 reserves as
/// permanently unresolvable, deterministic in `slot` for the same reasons
/// [`validation_standin`] is. The scheme comes from the field
/// ([`crate::secrets::plugin_config::endpoint_scheme`]) because several
/// plugins check it — `ldap_auth` wants `ldap`/`ldaps`, the Redis-backed
/// plugins want `redis`, `ws_logging` wants `wss` — and a stand-in that parses
/// but fails the scheme check would swap one spurious CI failure for another.
///
/// This is the shape for a field that accepts any path. A field whose path
/// the gateway constrains gets another `EndpointForm` instead.
pub fn validation_url_standin(slot: &str, scheme: &str) -> String {
    let digest = slot_digest(slot);
    format!("{scheme}://{VALIDATION_STANDIN_HOST}/{digest}")
}

/// Hex characters of the slot digest carried in a host label when the path
/// cannot carry it: 128 bits, comfortably distinct per slot and well inside
/// the 63-byte DNS label limit.
const HOST_LABEL_HEX: usize = 32;

/// The URL stand-in for an endpoint field of the given [`EndpointForm`].
///
/// * [`EndpointForm::DigestPath`] — [`validation_url_standin`].
/// * [`EndpointForm::RedisDatabase`] —
///   `redis://<32 hex>.gitforgeops-validation-standin.invalid/0`. Edge admits
///   a Redis URL path only when empty, `/`, or a canonical database number,
///   so per-slot uniqueness moves into a host label and the path selects
///   database 0. `redis` rather than `rediss`: Edge accepts either, and
///   `redis_tls: true` upgrades a `redis://` URL itself.
/// * [`EndpointForm::Origin`] —
///   `https://<32 hex>.gitforgeops-validation-standin.invalid/`, an origin with
///   the root path, the only path Edge admits there.
/// * [`EndpointForm::ModelTemplate`] — the digest path followed by
///   `/{model}`, the routing placeholder a `google_gemini` provider endpoint
///   must carry and every other provider type accepts.
fn shaped_url_standin(slot: &str, scheme: &str, form: EndpointForm) -> String {
    if form == EndpointForm::DigestPath {
        return validation_url_standin(slot, scheme);
    }
    let digest = slot_digest(slot);
    let label = digest.get(..HOST_LABEL_HEX).unwrap_or(&digest);
    match form {
        EndpointForm::DigestPath => validation_url_standin(slot, scheme),
        EndpointForm::RedisDatabase => format!("{scheme}://{label}.{VALIDATION_STANDIN_HOST}/0"),
        EndpointForm::Origin => format!("{scheme}://{label}.{VALIDATION_STANDIN_HOST}/"),
        EndpointForm::ModelTemplate => {
            format!("{scheme}://{VALIDATION_STANDIN_HOST}/{digest}/{{model}}")
        }
    }
}

fn slot_digest(slot: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slot.as_bytes());
    hex::encode(hasher.finalize())
}

/// Return a copy of `config` whose unresolved broker placeholders have been
/// replaced with stand-in values, or `None` when there were none (the
/// overwhelmingly common bundle-loaded case, which then validates the config
/// as-is with no clone).
///
/// Two sources covered by the stand-in contract (modeled service-discovery
/// fields remain byte-for-byte unchanged):
///
/// * **`Consumer.credentials`** — shape-checked by ferrum-edge (the
///   32-character `jwt`/`hmac_auth` floor, the `hmac_sha256:<64 hex>`
///   basicauth hash), so a 30-character placeholder literal fails validation
///   on the brokering rather than on the credential.
/// * **`PluginConfig.config`** — the same problem with a different shape. The
///   sensitivity classifier brokers credential-bearing *endpoints* as well as
///   tokens, and the gateway parses those: `ldap_auth` rejects
///   `${gh-env-secret:alloc=require}` with "not a valid URL". Endpoint-typed
///   leaves therefore get a URL with the field's own scheme and path shape
///   (`shaped_url_standin`), a `private_key_jwt` key gets a throwaway key of
///   the sibling `private_key_jwt_alg`'s family
///   (`validate::client_key_standin`), and everything else gets the
///   opaque token form. One leaf is omitted instead: an ambient-credential
///   Lambda `aws_endpoint_url`, which only an official AWS host can satisfy. Header maps are
///   rewritten value-side only, so `headers.x-honeycomb-team` keeps its key
///   and a plugin that validates required header *names* still sees them.
///
/// Nothing outside the 0600 temp spec handed to `ferrum-edge validate` ever
/// sees the result: the caller's `config` is untouched, and export, apply,
/// delivery and state all serialize that original.
/// This report-free API assumes an unresolved publication document. Resolved
/// snapshots must use [`crate::validate::run_validation_with_report`] so actual
/// values with placeholder syntax remain subject to validation.
pub fn with_validation_standins(config: &GatewayConfig) -> Option<GatewayConfig> {
    with_validation_standins_for_report(config, None).map(|input| input.config)
}

/// The validator input a stand-in pass produced.
pub(crate) struct StandinDocument {
    /// The patched copy written to the temp spec.
    pub(crate) config: GatewayConfig,
    /// Environment variables the validator process must not inherit for this
    /// document. Leaving an ambient-credential Lambda override out of the copy
    /// would otherwise let Edge fall back to the caller's
    /// `AWS_LAMBDA_ENDPOINT_URL` and grade an endpoint the repository never
    /// named.
    pub(crate) env_remove: Vec<&'static str>,
}

/// The variable Edge reads a Lambda endpoint from when a row sets no
/// `aws_endpoint_url`.
const AWS_LAMBDA_ENDPOINT_URL_ENV: &str = "AWS_LAMBDA_ENDPOINT_URL";

/// A report must describe the supplied resolved snapshot. Only explicitly
/// unresolved canonical slots are eligible; resolved or unreported values
/// reach the validator unchanged, even when their bytes look like placeholders.
/// Without a report, `config` is an unresolved publication document and valid
/// placeholder syntax remains sufficient (including file-mode apply).
pub(crate) fn with_validation_standins_for_report(
    config: &GatewayConfig,
    report: Option<&ResolveReport>,
) -> Option<StandinDocument> {
    let unresolved = report.map(|report| {
        let mut slots = std::collections::HashMap::new();
        for result in &report.results {
            // A contradictory duplicate cannot grant stand-in eligibility.
            let eligible = result.status != SlotStatus::Resolved;
            slots
                .entry(result.slot.as_str())
                .and_modify(|allowed| *allowed &= eligible)
                .or_insert(eligible);
        }
        slots
    });
    let eligible = |slot: &str| {
        unresolved
            .as_ref()
            .is_none_or(|slots| slots.get(slot) == Some(&true))
    };
    let credentials_brokered = config
        .consumers
        .iter()
        .any(|consumer| consumer.credentials.values().any(has_placeholder));
    let plugin_config_brokered = config
        .plugin_configs
        .iter()
        .any(|plugin| has_placeholder(&plugin.config));
    if !credentials_brokered && !plugin_config_brokered {
        return None;
    }

    let mut patched = config.clone();
    let mut changed = false;
    let mut omitted_lambda_endpoint = false;
    for consumer in &mut patched.consumers {
        let namespace = consumer.namespace.clone();
        let consumer_id = consumer.id.clone();
        for (credential_type, value) in consumer.credentials.iter_mut() {
            changed |= substitute_leaves(value, &mut Vec::new(), None, &|path| {
                let slot =
                    consumer_credential_slot(&namespace, &consumer_id, credential_type, path);
                eligible(&slot).then_some(slot)
            });
        }
    }

    for plugin in &mut patched.plugin_configs {
        // Classified before the walk mutates anything: the rules key on paths,
        // and replacing a string leaf never moves one. A client key's
        // algorithm is read from its sibling now for the same reason.
        let plugin_name = plugin.plugin_name.as_str();
        let client_keys =
            crate::secrets::plugin_config::client_assertion_key_paths(plugin_name, &plugin.config)
                .into_iter()
                .map(|path| {
                    let family =
                        ClientKeyFamily::for_alg(client_assertion_alg(&plugin.config, &path));
                    (path, family)
                })
                .collect();
        let context = PluginStandins {
            namespace: &plugin.namespace,
            plugin_id: &plugin.id,
            plugin_name,
            endpoints: crate::secrets::plugin_config::endpoint_paths(plugin_name, &plugin.config),
            ldap_scheme: crate::secrets::plugin_config::declared_ldap_scheme(
                plugin_name,
                &plugin.config,
            ),
            client_keys,
        };
        let omit_lambda_endpoint = omits_ambient_lambda_endpoint(plugin_name, &plugin.config)
            && eligible(&crate::secrets::resolver::plugin_config_slot(
                &plugin.namespace,
                &plugin.id,
                plugin_name,
                &[ConfigPathComponent::Key(AWS_ENDPOINT_URL.to_string())],
            ));
        let mut config = std::mem::take(&mut plugin.config);
        changed |= context.substitute(&mut config, &mut Vec::new(), &eligible);
        if omit_lambda_endpoint {
            if let Some(object) = config.as_object_mut() {
                let omitted = object.remove(AWS_ENDPOINT_URL).is_some();
                omitted_lambda_endpoint |= omitted;
                changed |= omitted;
            }
        }
        plugin.config = config;
    }

    changed.then(|| StandinDocument {
        config: patched,
        env_remove: if omitted_lambda_endpoint {
            vec![AWS_LAMBDA_ENDPOINT_URL_ENV]
        } else {
            Vec::new()
        },
    })
}

/// `serverless_function`'s Lambda endpoint override.
const AWS_ENDPOINT_URL: &str = "aws_endpoint_url";

/// Whether an unresolved `serverless_function` `aws_endpoint_url` must be
/// left out of the validator copy rather than stood in for.
///
/// A row that signs with ambient AWS credentials (`aws_credentials:
/// default_chain`, or `static` with either half of the key pair left to the
/// environment) may only send them to an official Lambda endpoint of its
/// region: Edge's shape-only admission
/// (`screen_shape_only_ambient_lambda_config`, v0.9.20 and later) refuses any
/// other `aws_endpoint_url` unless `allow_custom_endpoint_with_ambient_credentials`
/// is `true`. No `.invalid` stand-in can pass that check, and imitating an AWS
/// host would give up the stand-in's fail-closed property, so the override is
/// omitted and Edge validates the row against its default regional endpoint,
/// keeping the region and credential-mode checks. A resolved endpoint is
/// never touched: it is validated exactly as configured.
fn omits_ambient_lambda_endpoint(plugin_name: &str, config: &serde_json::Value) -> bool {
    if plugin_name != "serverless_function" {
        return false;
    }
    let text = |field: &str| config.get(field).and_then(serde_json::Value::as_str);
    let present = |field: &str| text(field).is_some_and(|value| !value.is_empty());
    let ambient = match text("aws_credentials") {
        Some("default_chain") => true,
        None | Some("static") => !present("aws_access_key_id") || !present("aws_secret_access_key"),
        // Edge refuses any other spelling outright.
        Some(_) => false,
    };
    text("provider") == Some("aws_lambda")
        && ambient
        && config.get("allow_custom_endpoint_with_ambient_credentials")
            != Some(&serde_json::Value::Bool(true))
        && text(AWS_ENDPOINT_URL)
            .is_some_and(|value| matches!(parse_placeholder(value), Some(Ok(_))))
}

/// The `private_key_jwt_alg` beside a client-assertion key, when it is a
/// string.
fn client_assertion_alg<'a>(
    config: &'a serde_json::Value,
    key_path: &[ConfigPathComponent],
) -> Option<&'a str> {
    let (_, parent) = key_path.split_last()?;
    crate::secrets::plugin_config::value_at(config, parent)?
        .get(crate::secrets::plugin_config::CLIENT_ASSERTION_ALG_FIELD)?
        .as_str()
}

/// What one plugin config's stand-ins are derived from, classified before the
/// walk replaces anything.
struct PluginStandins<'a> {
    namespace: &'a str,
    plugin_id: &'a str,
    plugin_name: &'a str,
    endpoints: BTreeSet<Vec<ConfigPathComponent>>,
    /// The LDAP scheme the config already commits to, which overrides the
    /// field's default (Edge refuses mixed `ldap` / `ldaps` endpoints).
    ldap_scheme: Option<&'static str>,
    client_keys: BTreeMap<Vec<ConfigPathComponent>, ClientKeyFamily>,
}

impl PluginStandins<'_> {
    fn substitute(
        &self,
        value: &mut serde_json::Value,
        path: &mut Vec<ConfigPathComponent>,
        eligible: &impl Fn(&str) -> bool,
    ) -> bool {
        let mut changed = false;
        match value {
            serde_json::Value::String(text) => {
                if !matches!(parse_placeholder(text), Some(Ok(_))) {
                    return false;
                }
                // The canonical broker slot, so a stand-in is distinct per
                // leaf and stable across runs for the same repository.
                let slot = crate::secrets::resolver::plugin_config_slot(
                    self.namespace,
                    self.plugin_id,
                    self.plugin_name,
                    path,
                );
                if !eligible(&slot) {
                    return false;
                }
                *text = self.standin(&slot, path);
                changed = true;
            }
            serde_json::Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    path.push(ConfigPathComponent::Key(key.clone()));
                    changed |= self.substitute(child, path, eligible);
                    path.pop();
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    path.push(ConfigPathComponent::Index(index));
                    changed |= self.substitute(child, path, eligible);
                    path.pop();
                }
            }
            _ => {}
        }
        changed
    }

    fn standin(&self, slot: &str, path: &[ConfigPathComponent]) -> String {
        if self.endpoints.contains(path) {
            let scheme = self.ldap_scheme.unwrap_or_else(|| {
                crate::secrets::plugin_config::endpoint_scheme(self.plugin_name, path)
            });
            let form = crate::secrets::plugin_config::endpoint_form(self.plugin_name, path);
            return shaped_url_standin(slot, scheme, form);
        }
        if let Some(pem) = self
            .client_keys
            .get(path)
            .and_then(|family| client_assertion_key_pem(*family))
        {
            return pem.to_string();
        }
        validation_standin(slot, None)
    }
}

fn has_placeholder(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => matches!(parse_placeholder(text), Some(Ok(_))),
        serde_json::Value::Object(map) => map.values().any(has_placeholder),
        serde_json::Value::Array(items) => items.iter().any(has_placeholder),
        _ => false,
    }
}

fn substitute_leaves(
    value: &mut serde_json::Value,
    path: &mut Vec<ConfigPathComponent>,
    leaf: Option<&str>,
    eligible_slot: &impl Fn(&[ConfigPathComponent]) -> Option<String>,
) -> bool {
    let mut changed = false;
    match value {
        serde_json::Value::String(text) => {
            if matches!(parse_placeholder(text), Some(Ok(_))) {
                if let Some(slot) = eligible_slot(path) {
                    *text = validation_standin(&slot, leaf);
                    changed = true;
                }
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(ConfigPathComponent::Key(key.clone()));
                let leaf = key.clone();
                changed |= substitute_leaves(child, path, Some(&leaf), eligible_slot);
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                // An index does not change which field the leaf is, so the
                // enclosing object key carries through.
                let inherited = leaf.map(str::to_string);
                changed |= substitute_leaves(child, path, inherited.as_deref(), eligible_slot);
                path.pop();
            }
        }
        _ => {}
    }
    changed
}
