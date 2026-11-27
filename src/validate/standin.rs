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
use crate::secrets::plugin_trigger;
use crate::secrets::resolver::{consumer_credential_slot, ResolveReport, SlotStatus};
use crate::validate::client_key_standin::{client_assertion_key_pem, ClientKeyFamily};

use super::pem_standin::validation_private_key_standin;

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
/// Three sources covered by the stand-in contract (modeled service-discovery
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
///   opaque token form. An ambient-credential Lambda `aws_endpoint_url`,
///   which only an official AWS host can satisfy, gets the row's default
///   regional Lambda origin. Header maps are
///   rewritten value-side only, so `headers.x-honeycomb-team` keeps its key
///   and a plugin that validates required header *names* still sees them.
///   A private-key source field gets a PEM-shaped stand-in
///   ([`super::pem_standin`]).
/// * **Proxy and Upstream `backend_tls_client_key_path`** — Edge parses an
///   inline key as PEM, so it gets the PEM-shaped stand-in too.
/// * **`PluginConfig.trigger`** — a brokered `header` / `query` / `cookie`
///   operand gets the opaque token form, which is also a valid literal
///   `regex`.
///
/// Nothing outside the 0600 temp spec handed to `ferrum-edge validate` ever
/// sees the result: the caller's `config` is untouched, and export, apply,
/// delivery and state all serialize that original.
/// This report-free API assumes an unresolved publication document. Resolved
/// snapshots must use [`crate::validate::run_validation_with_report`] so actual
/// values with placeholder syntax remain subject to validation.
pub fn with_validation_standins(config: &GatewayConfig) -> Option<GatewayConfig> {
    with_validation_standins_for_report(config, None)
}

/// A report must describe the supplied resolved snapshot. Only explicitly
/// unresolved canonical slots are eligible; resolved or unreported values
/// reach the validator unchanged, even when their bytes look like placeholders.
/// Without a report, `config` is an unresolved publication document and valid
/// placeholder syntax remains sufficient (including file-mode apply).
pub(crate) fn with_validation_standins_for_report(
    config: &GatewayConfig,
    report: Option<&ResolveReport>,
) -> Option<GatewayConfig> {
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
    let plugin_config_brokered = config.plugin_configs.iter().any(|plugin| {
        has_placeholder(&plugin.config)
            || plugin
                .trigger
                .as_ref()
                .is_some_and(|trigger| has_placeholder(&plugin_trigger::trigger_json(trigger)))
    });
    let backend_keys_brokered = crate::secrets::backend_tls::client_keys(config)
        .iter()
        .any(|key| matches!(parse_placeholder(key.value), Some(Ok(_))));
    if !credentials_brokered && !plugin_config_brokered && !backend_keys_brokered {
        return None;
    }

    let mut patched = config.clone();
    let mut changed = false;
    // The validator inherits this process's AWS environment, so a Lambda row
    // without a configured region resolves the same one there.
    let env_region = aws_environment_region();
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
            lambda_origin: ambient_lambda_origin(
                plugin_name,
                &plugin.config,
                env_region.as_deref(),
            ),
        };
        let paired_key_unresolved = unresolved_paired_key(
            plugin_name,
            &plugin.namespace,
            &plugin.id,
            &plugin.config,
            &eligible,
        );
        let mut config = std::mem::take(&mut plugin.config);
        changed |= context.substitute(&mut config, &mut Vec::new(), &eligible);
        plugin.config = config;
        if let Some((key_field, cert_field)) = paired_key_unresolved {
            if let Some(object) = plugin.config.as_object_mut() {
                object.remove(key_field);
                object.remove(cert_field);
                changed = true;
            }
        }
        changed |= substitute_trigger_operands(plugin, &eligible);
    }

    // A brokered `backend_tls_client_key_path` gets a PEM-shaped stand-in:
    // Edge parses the inline key (and would read the placeholder as a missing
    // file), but does not pair it with the certificate.
    for key in crate::secrets::backend_tls::client_keys_mut(&mut patched) {
        let Some(text) = key.value.as_mut() else {
            continue;
        };
        if !matches!(parse_placeholder(text), Some(Ok(_))) {
            continue;
        }
        let slot = crate::secrets::backend_tls::slot(key.owner, &key.namespace, &key.id);
        if eligible(&slot) {
            *text = validation_private_key_standin(&slot);
            changed = true;
        }
    }

    changed.then_some(patched)
}

/// The validator's copy of an admin-API document: each `basicauth` entry's
/// `password` becomes a `password_hash` stand-in.
///
/// The admin API takes a plaintext `password` and hashes it on write, which is
/// how GitForgeOps applies a brokered `basicauth/password` in api mode. The
/// pre-apply validator runs `ferrum-edge validate -m file`, which refuses a
/// plaintext `password` ("accepted only by Admin API writes"), so without this
/// every api-mode repository with a basicauth password failed validation, and
/// apply refused to run, whether or not the slot had a value. The stand-in is
/// [`validation_standin`]'s `password_hash` shape for the password's slot:
/// deterministic, distinct per slot, never a hash of the password, so the
/// resolved value is never written to the validator's temp spec.
///
/// An entry that already carries `password_hash` is left as it is, so a
/// password-and-hash conflict still reaches the validator. File mode does not
/// use this: a file-mode gateway really does need the hash.
pub fn with_admin_api_basicauth_standins(config: &GatewayConfig) -> Option<GatewayConfig> {
    let mut patched = config.clone();
    let mut changed = false;
    for consumer in &mut patched.consumers {
        let namespace = consumer.namespace.clone();
        let consumer_id = consumer.id.clone();
        let mut hash_entry = |entry: &mut serde_json::Map<String, serde_json::Value>,
                              mut path: Vec<ConfigPathComponent>| {
            if entry.contains_key(PASSWORD_HASH_LEAF)
                || !entry
                    .get("password")
                    .is_some_and(serde_json::Value::is_string)
            {
                return;
            }
            path.push(ConfigPathComponent::Key("password".to_string()));
            let slot = consumer_credential_slot(&namespace, &consumer_id, "basicauth", &path);
            entry.remove("password");
            entry.insert(
                PASSWORD_HASH_LEAF.to_string(),
                serde_json::Value::String(validation_standin(&slot, Some(PASSWORD_HASH_LEAF))),
            );
            changed = true;
        };
        match consumer.credentials.get_mut("basicauth") {
            Some(serde_json::Value::Array(items)) => {
                for (index, item) in items.iter_mut().enumerate() {
                    if let Some(entry) = item.as_object_mut() {
                        hash_entry(entry, vec![ConfigPathComponent::Index(index)]);
                    }
                }
            }
            Some(serde_json::Value::Object(entry)) => hash_entry(entry, Vec::new()),
            _ => {}
        }
    }
    changed.then_some(patched)
}

/// Replace each eligible brokered `trigger` operand
/// ([`crate::secrets::plugin_trigger`]) with the opaque [`validation_standin`]
/// of its trigger slot. That one form fits every operator Edge's trigger
/// admission checks: a non-empty `exact` / `prefix` entry under its
/// 1024-byte cap, and a `regex` under its 512-byte cap that compiles, since
/// the stand-in is lowercase letters, digits and `-` only, all literals.
/// Placeholder text would fail the regex check outright (`${` is not a valid
/// pattern), a verdict on the brokering rather than on the trigger.
fn substitute_trigger_operands(
    plugin: &mut crate::config::schema::PluginConfig,
    eligible: &impl Fn(&str) -> bool,
) -> bool {
    let Some(trigger) = plugin.trigger.as_ref() else {
        return false;
    };
    let mut json = plugin_trigger::trigger_json(trigger);
    let operands: Vec<Vec<ConfigPathComponent>> = plugin_trigger::trigger_operand_strings(&json)
        .into_iter()
        .filter(|(_, text)| matches!(parse_placeholder(text), Some(Ok(_))))
        .map(|(path, _)| path)
        .collect();
    let mut changed = false;
    for path in operands {
        let slot = crate::secrets::resolver::plugin_trigger_slot(
            &plugin.namespace,
            &plugin.id,
            &plugin.plugin_name,
            &path,
        );
        if !eligible(&slot) {
            continue;
        }
        if let Some(leaf) = plugin_trigger::trigger_value_mut(&mut json, &path) {
            *leaf = serde_json::Value::String(validation_standin(&slot, None));
            changed = true;
        }
    }
    if !changed {
        return false;
    }
    // Replacing one string with another never changes the trigger's shape, so
    // this cannot fail; if it somehow did, the validator would see the
    // placeholder and report it rather than a stand-in being lost silently.
    match plugin_trigger::trigger_from_json(plugin, json) {
        Ok(trigger) => {
            plugin.trigger = Some(trigger);
            true
        }
        Err(_) => false,
    }
}

/// `serverless_function`'s Lambda endpoint override.
const AWS_ENDPOINT_URL: &str = "aws_endpoint_url";

/// The validation-only `aws_endpoint_url` stand-in for a Lambda row that signs
/// with ambient AWS credentials, or `None` when the row gets the ordinary
/// origin stand-in.
///
/// Such a row (`aws_credentials: default_chain`, or `static` with either half
/// of the key pair left to the environment) may only send its credentials to
/// an official Lambda endpoint of its region: Edge's shape-only admission
/// (`screen_shape_only_ambient_lambda_config`, v0.9.20 and later) refuses any
/// other `aws_endpoint_url` unless `allow_custom_endpoint_with_ambient_credentials`
/// is `true`. No `.invalid` host can pass, and leaving the field out would
/// let Edge fall back to the caller's `AWS_LAMBDA_ENDPOINT_URL` and grade an
/// endpoint the repository never named. So the stand-in is the row's default
/// regional origin, `https://lambda.<region>.amazonaws.com/`
/// (`amazonaws.com.cn` for a `cn-*` region), exactly what Edge derives itself.
/// It names a real AWS host, but like every stand-in it only ever reaches the
/// 0600 temp spec, and `validate` dials nothing.
///
/// The region is the configured `aws_region`. When that is absent or empty
/// (Edge treats both as unset), it is the one Edge would resolve in the
/// validator, which inherits this process's environment: `env_region`
/// ([`aws_environment_region`]). Edge checks the endpoint against any region
/// first in that case, so with no usable environment region `us-east-1`
/// stands in. A configured region Edge would refuse (malformed, another
/// partition, not a string) keeps the ordinary stand-in, so Edge reports the
/// region rather than a guessed endpoint hiding it.
fn ambient_lambda_origin(
    plugin_name: &str,
    config: &serde_json::Value,
    env_region: Option<&str>,
) -> Option<String> {
    if plugin_name != "serverless_function" {
        return None;
    }
    let text = |field: &str| config.get(field).and_then(serde_json::Value::as_str);
    let present = |field: &str| text(field).is_some_and(|value| !value.is_empty());
    let ambient = match text("aws_credentials") {
        Some("default_chain") => true,
        None | Some("static") => !present("aws_access_key_id") || !present("aws_secret_access_key"),
        // Edge refuses any other spelling outright.
        Some(_) => false,
    };
    if text("provider") != Some("aws_lambda")
        || !ambient
        || config.get("allow_custom_endpoint_with_ambient_credentials")
            == Some(&serde_json::Value::Bool(true))
    {
        return None;
    }
    let region = match config.get("aws_region") {
        Some(serde_json::Value::String(region)) if !region.is_empty() => region.as_str(),
        None | Some(serde_json::Value::String(_)) => env_region
            .filter(|region| aws_region_dns_suffix(region).is_some())
            .unwrap_or(FALLBACK_AWS_REGION),
        Some(_) => return None,
    };
    let suffix = aws_region_dns_suffix(region)?;
    Some(format!("https://lambda.{region}.{suffix}/"))
}

/// The commercial region a Lambda stand-in uses when neither the row nor the
/// environment names one; any modelled region passes Edge's any-region check.
const FALLBACK_AWS_REGION: &str = "us-east-1";

/// The region Edge resolves from the environment for a row without one:
/// `AWS_DEFAULT_REGION`, then `AWS_REGION`, each only when non-empty.
fn aws_environment_region() -> Option<String> {
    ["AWS_DEFAULT_REGION", "AWS_REGION"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// The regional endpoint DNS suffix for a region of a partition Edge models
/// (its `aws_region_partition` grammar: `^(us|eu|ap|sa|ca|me|af|il|mx)-[a-z]+-\d+$`,
/// `^cn-[a-z]+-\d+$`, `^us-gov-[a-z]+-\d+$`, at most 63 bytes), or `None`.
fn aws_region_dns_suffix(region: &str) -> Option<&'static str> {
    const COMMERCIAL: &[&str] = &["us", "eu", "ap", "sa", "ca", "me", "af", "il", "mx"];
    if region.len() > 63 {
        return None;
    }
    let (suffix, rest) = if let Some(rest) = region.strip_prefix("us-gov-") {
        ("amazonaws.com", rest)
    } else if let Some(rest) = region.strip_prefix("cn-") {
        ("amazonaws.com.cn", rest)
    } else {
        let (prefix, rest) = region.split_once('-')?;
        if !COMMERCIAL.contains(&prefix) {
            return None;
        }
        ("amazonaws.com", rest)
    };
    let (area, number) = rest.split_once('-')?;
    let well_formed = !area.is_empty()
        && area.bytes().all(|byte| byte.is_ascii_lowercase())
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit());
    well_formed.then_some(suffix)
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
    /// The ambient-credential Lambda stand-in for `aws_endpoint_url`
    /// ([`ambient_lambda_origin`]).
    lambda_origin: Option<String>,
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
        if let (Some(origin), [ConfigPathComponent::Key(key)]) = (&self.lambda_origin, path) {
            if key == AWS_ENDPOINT_URL {
                return origin.clone();
            }
        }
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
        // A schema TLS private-key source (`dtls_key_path`,
        // `mesh_route_dispatch` backend `client_key_path`) is only PEM-framed
        // by Edge, so the deterministic marker PEM suffices; a paired DTLS key
        // is then omitted with its certificate ([`PAIRED_KEY_SOURCES`]).
        if crate::secrets::tls_material::is_plugin_key_source(self.plugin_name, path) {
            return validation_private_key_standin(slot);
        }
        validation_standin(slot, None)
    }
}

/// Private-key sources Edge's `validate` pairs with a certificate, as
/// `(plugin_name, key field, certificate field)`, top-level in the config.
///
/// `udp_logging`'s DTLS identity is loaded in the plugin file-dependency
/// phase, which requires the key to sign and to match `dtls_cert_path`
/// (`CertifiedKey::keys_match`). No stand-in can satisfy that, and a stand-in
/// that fails it would fail every bundle-less validation of the whole
/// document and every file-mode apply (which validates the publication
/// document). So while the key is unresolved the validation copy omits the
/// pair; Edge then uses an ephemeral DTLS identity and still validates the
/// rest of the plugin (host, port, CA source, batching). The pair itself is
/// validated wherever the bundle resolves the key (`validate`, `plan`,
/// `review` with a bundle).
const PAIRED_KEY_SOURCES: &[(&str, &str, &str)] =
    &[("udp_logging", "dtls_key_path", "dtls_cert_path")];

/// The `(key field, certificate field)` to omit from `config`'s validation
/// copy, when its paired private key is an eligible unresolved placeholder.
fn unresolved_paired_key(
    plugin_name: &str,
    namespace: &str,
    plugin_id: &str,
    config: &serde_json::Value,
    eligible: &impl Fn(&str) -> bool,
) -> Option<(&'static str, &'static str)> {
    let (_, key_field, cert_field) = PAIRED_KEY_SOURCES
        .iter()
        .find(|(name, _, _)| *name == plugin_name)?;
    // Omit the pair only when Edge would actually load it: DTLS enabled and
    // a certificate source present as a non-empty string. Otherwise the copy
    // keeps the declared shape, so Edge's own enablement, pairing and type
    // checks still run (on the PEM-shaped key stand-in).
    if config.get("dtls").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    if !config
        .get(*cert_field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|cert| !cert.trim().is_empty())
    {
        return None;
    }
    let text = config.get(*key_field)?.as_str()?;
    if !matches!(parse_placeholder(text), Some(Ok(_))) {
        return None;
    }
    let slot = crate::secrets::resolver::plugin_config_slot(
        namespace,
        plugin_id,
        plugin_name,
        &[ConfigPathComponent::Key((*key_field).to_string())],
    );
    eligible(&slot).then_some((*key_field, *cert_field))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(config: serde_json::Value, env_region: Option<&str>) -> Option<String> {
        ambient_lambda_origin("serverless_function", &config, env_region)
    }

    /// A row that leaves its region to the environment stands in with the
    /// region Edge resolves in the validator, or `us-east-1` when there is
    /// none Edge would accept; a configured region always wins.
    #[test]
    fn an_unconfigured_lambda_region_follows_the_environment() {
        let row = |region: Option<serde_json::Value>| {
            let mut config = serde_json::json!({
                "provider": "aws_lambda",
                "aws_credentials": "default_chain",
                "aws_function_name": "fn"
            });
            if let Some(region) = region {
                config["aws_region"] = region;
            }
            config
        };
        for (region, env_region, expected) in [
            (
                None,
                Some("eu-west-1"),
                Some("https://lambda.eu-west-1.amazonaws.com/"),
            ),
            (
                None,
                Some("cn-northwest-1"),
                Some("https://lambda.cn-northwest-1.amazonaws.com.cn/"),
            ),
            (None, None, Some("https://lambda.us-east-1.amazonaws.com/")),
            (
                None,
                Some("not-a-region"),
                Some("https://lambda.us-east-1.amazonaws.com/"),
            ),
            (
                Some(serde_json::json!("")),
                Some("ap-south-1"),
                Some("https://lambda.ap-south-1.amazonaws.com/"),
            ),
            (
                Some(serde_json::json!("us-gov-east-1")),
                Some("eu-west-1"),
                Some("https://lambda.us-gov-east-1.amazonaws.com/"),
            ),
            (
                Some(serde_json::json!("US-EAST-1")),
                Some("eu-west-1"),
                None,
            ),
            (Some(serde_json::json!(null)), Some("eu-west-1"), None),
        ] {
            assert_eq!(
                origin(row(region.clone()), env_region).as_deref(),
                expected,
                "{region:?} {env_region:?}"
            );
        }
    }
}
