//! Secret operands of a resource-level `PluginConfig.trigger`.
//!
//! A trigger decides whether one plugin instance runs for a request. Its
//! `header`, `query` and `cookie` predicates compare a value the *client*
//! sends, so an operand there (`value.exact[]`, `value.prefix[]`,
//! `value.regex`) can be a shared token: whoever knows it decides whether the
//! plugin runs, for example skipping a `waf` instance whose trigger is
//! `not: {match: {header: {name: x-skip, value: {exact: [<token>]}}}}`. Ferrum
//! Edge withholds exactly those operands from non-admin reads and
//! `/config/export` (`project_plugin_trigger_with` in its
//! `plugin_config_projection`), and this module is the one place that mirrors
//! that walk. Every other predicate (`method`, `path`, `host`, `sni`,
//! `protocol`, `source_cidr`, `namespace`, `proxy_id`, `listen_port`,
//! `consumer`, `external_identity`, `external_identity_authority`,
//! `auth_method`, `spiffe_id`), the field `name`, `presence`,
//! `multi_value`, `case_insensitive`, the match kinds and the tree structure
//! are routing facts or authenticated identity and stay reviewable.
//!
//! Users:
//!
//! * [`crate::config_export`] predicts the sites `/config/export`
//!   fingerprints from every site [`visit_trigger_sites`] reports, including
//!   the shapes Edge withholds wholesale.
//! * The broker (import capture, both resolver walks, validation stand-ins,
//!   diff masking and redaction, the literal-secret audit and the scrubber)
//!   uses the [`TriggerSite::Operand`] string sites only. Their canonical slot
//!   is `<ns>/<plugin-id>/@plugin/<plugin_name>/trigger/<path>`
//!   ([`crate::secrets::resolver::plugin_trigger_slot`]), with `<path>`
//!   running from the trigger root (`when/...`) and every array index kept.
//!
//! An operand is a secret on the same terms as a plugin-config operator value
//! (`RuleKind::Value` in [`super::plugin_config`]): a string of at least
//! [`MIN_SCRUB_LENGTH`] bytes is brokered, masked, scrubbed and literal-gated.
//! A shorter one (`exact: ["1"]`) could be neither stored by the bundle nor
//! scrubbed, so it stays an ordinary literal, and none is declared required
//! for display admission. A brokered placeholder is always long enough.

use serde_json::Value;

use super::plugin_config::{render_config_path, ConfigPathComponent};
use super::MIN_SCRUB_LENGTH;
use crate::config::schema::{PluginConfig, PluginTrigger};
use crate::config::GatewayConfig;

/// Trigger `match` predicates whose `value` operands a client presents, so
/// Edge withholds them (its `TRIGGER_CLIENT_FIELD_PREDICATES`).
pub(crate) const TRIGGER_CLIENT_FIELD_PREDICATES: [&str; 3] = ["header", "query", "cookie"];

/// Trigger `match` predicates Edge leaves visible. A leaf key in neither list
/// is not a predicate this build models, so Edge withholds its value whole.
pub(crate) const TRIGGER_VISIBLE_PREDICATES: [&str; 14] = [
    "method",
    "path",
    "host",
    "sni",
    "protocol",
    "source_cidr",
    "namespace",
    "proxy_id",
    "listen_port",
    "consumer",
    "external_identity",
    "external_identity_authority",
    "auth_method",
    "spiffe_id",
];

/// What [`visit_trigger_sites`] found at a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TriggerSite {
    /// One comparison operand of a client-field predicate: an `exact[]` or
    /// `prefix[]` entry, or `regex` (any operand key except a boolean
    /// `case_insensitive`).
    Operand,
    /// A shape a `PluginTrigger` cannot have, which Edge withholds as a whole
    /// rather than walking. A typed trigger never produces one.
    Withheld,
}

/// Visit every site of a serialized trigger that Edge withholds, in Edge's
/// order and with Edge's fail-closed rules: a non-object trigger or one
/// without `when`, a non-object node or leaf, a non-array `all` / `any`, a key
/// the schema does not define and a non-object `value` are
/// [`TriggerSite::Withheld`]. `null` is never a site. Paths are relative to
/// the trigger (the first component of a walked site is `when`).
pub(crate) fn visit_trigger_sites<'a>(
    trigger: &'a Value,
    visit: &mut dyn FnMut(&[ConfigPathComponent], &'a Value, TriggerSite),
) {
    let mut path = Vec::new();
    let Some(map) = trigger.as_object().filter(|map| map.contains_key("when")) else {
        site(trigger, &path, TriggerSite::Withheld, visit);
        return;
    };
    for (key, child) in map {
        path.push(ConfigPathComponent::Key(key.clone()));
        if key == "when" {
            node_sites(child, &mut path, visit);
        } else {
            site(child, &path, TriggerSite::Withheld, visit);
        }
        path.pop();
    }
}

fn site<'a>(
    value: &'a Value,
    path: &[ConfigPathComponent],
    kind: TriggerSite,
    visit: &mut dyn FnMut(&[ConfigPathComponent], &'a Value, TriggerSite),
) {
    if !value.is_null() {
        visit(path, value, kind);
    }
}

fn node_sites<'a>(
    node: &'a Value,
    path: &mut Vec<ConfigPathComponent>,
    visit: &mut dyn FnMut(&[ConfigPathComponent], &'a Value, TriggerSite),
) {
    let Some(map) = node.as_object() else {
        site(node, path, TriggerSite::Withheld, visit);
        return;
    };
    for (key, child) in map {
        path.push(ConfigPathComponent::Key(key.clone()));
        match (key.as_str(), child) {
            ("all" | "any", Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    path.push(ConfigPathComponent::Index(index));
                    node_sites(item, path, visit);
                    path.pop();
                }
            }
            ("not", child) => node_sites(child, path, visit),
            ("match", child) => leaf_sites(child, path, visit),
            (_, child) => site(child, path, TriggerSite::Withheld, visit),
        }
        path.pop();
    }
}

fn leaf_sites<'a>(
    leaf: &'a Value,
    path: &mut Vec<ConfigPathComponent>,
    visit: &mut dyn FnMut(&[ConfigPathComponent], &'a Value, TriggerSite),
) {
    let Some(map) = leaf.as_object() else {
        site(leaf, path, TriggerSite::Withheld, visit);
        return;
    };
    for (key, predicate) in map {
        if TRIGGER_VISIBLE_PREDICATES.contains(&key.as_str()) {
            continue;
        }
        path.push(ConfigPathComponent::Key(key.clone()));
        if TRIGGER_CLIENT_FIELD_PREDICATES.contains(&key.as_str()) {
            field_predicate_sites(predicate, path, visit);
        } else {
            site(predicate, path, TriggerSite::Withheld, visit);
        }
        path.pop();
    }
}

fn field_predicate_sites<'a>(
    predicate: &'a Value,
    path: &mut Vec<ConfigPathComponent>,
    visit: &mut dyn FnMut(&[ConfigPathComponent], &'a Value, TriggerSite),
) {
    let Some(map) = predicate.as_object() else {
        site(predicate, path, TriggerSite::Withheld, visit);
        return;
    };
    for (key, child) in map {
        if matches!(key.as_str(), "name" | "presence" | "multi_value") {
            continue;
        }
        path.push(ConfigPathComponent::Key(key.clone()));
        if key == "value" {
            operand_sites(child, path, visit);
        } else {
            site(child, path, TriggerSite::Withheld, visit);
        }
        path.pop();
    }
}

/// A trigger string match: every operand except a boolean `case_insensitive`
/// flag, entry by entry for the `exact` / `prefix` lists.
fn operand_sites<'a>(
    value: &'a Value,
    path: &mut Vec<ConfigPathComponent>,
    visit: &mut dyn FnMut(&[ConfigPathComponent], &'a Value, TriggerSite),
) {
    let Some(map) = value.as_object() else {
        site(value, path, TriggerSite::Withheld, visit);
        return;
    };
    for (key, operand) in map {
        if key == "case_insensitive" && operand.is_boolean() {
            continue;
        }
        path.push(ConfigPathComponent::Key(key.clone()));
        if let Value::Array(items) = operand {
            for (index, item) in items.iter().enumerate() {
                path.push(ConfigPathComponent::Index(index));
                site(item, path, TriggerSite::Operand, visit);
                path.pop();
            }
        } else {
            site(operand, path, TriggerSite::Operand, visit);
        }
        path.pop();
    }
}

/// The serialized form of a typed trigger, the document every walk here
/// reads. Paths into it are the paths of its broker slots.
pub(crate) fn trigger_json(trigger: &PluginTrigger) -> Value {
    // The trigger types hold only strings, lists, enums, booleans and
    // integers with derived `Serialize`, which cannot fail.
    serde_json::to_value(trigger).expect("a typed plugin trigger always serializes to JSON")
}

/// Every client-field operand holding a string, whatever its length.
pub(crate) fn trigger_operand_strings(trigger: &Value) -> Vec<(Vec<ConfigPathComponent>, &str)> {
    let mut found = Vec::new();
    visit_trigger_sites(trigger, &mut |path, value, kind| {
        if let (TriggerSite::Operand, Value::String(text)) = (kind, value) {
            found.push((path.to_vec(), text.as_str()));
        }
    });
    found
}

/// Whether an operand string is treated as a secret: long enough to broker
/// and scrub (see the module docs).
pub(crate) fn is_sensitive_trigger_operand(text: &str) -> bool {
    text.len() >= MIN_SCRUB_LENGTH
}

/// The client-field operands treated as secrets
/// ([`is_sensitive_trigger_operand`]).
pub(crate) fn sensitive_trigger_operands(trigger: &Value) -> Vec<(Vec<ConfigPathComponent>, &str)> {
    trigger_operand_strings(trigger)
        .into_iter()
        .filter(|(_, text)| is_sensitive_trigger_operand(text))
        .collect()
}

/// A trigger path the way an operator reads it:
/// `trigger.when.not.match.header.value.exact.[0]`.
pub(crate) fn render_trigger_path(path: &[ConfigPathComponent]) -> String {
    if path.is_empty() {
        return "trigger".to_string();
    }
    format!("trigger.{}", render_config_path(path))
}

/// Mutable access to the node at `path`, or `None` when it does not resolve.
pub(crate) fn trigger_value_mut<'a>(
    mut value: &'a mut Value,
    path: &[ConfigPathComponent],
) -> Option<&'a mut Value> {
    for part in path {
        value = match part {
            ConfigPathComponent::Key(key) => value.as_object_mut()?.get_mut(key)?,
            ConfigPathComponent::Index(index) => value.as_array_mut()?.get_mut(*index)?,
        };
    }
    Some(value)
}

/// Read a serialized trigger back into its typed form after a walk replaced
/// operand strings (which never changes its shape).
pub(crate) fn trigger_from_json(
    plugin: &PluginConfig,
    json: Value,
) -> crate::error::Result<PluginTrigger> {
    serde_json::from_value(json).map_err(|_| {
        crate::error::Error::Config(format!(
            "internal: plugin `{}/{}` trigger no longer deserializes after substituting its operands",
            plugin.namespace, plugin.id
        ))
    })
}

/// Refuse broker syntax anywhere in a trigger except a client-field operand.
///
/// Only those operands have a broker slot; a placeholder in `path`, `host`, a
/// field `name` or an identity match would never be resolved and would reach
/// the gateway as its literal text. Those predicates are reviewable routing
/// facts, so the remedy is to author them literally. Embedded or malformed
/// broker syntax counts, like the identity check. Names the path, never a
/// value.
pub fn validate_trigger_placeholders(cfg: &GatewayConfig) -> crate::error::Result<()> {
    for plugin in &cfg.plugin_configs {
        let Some(trigger) = plugin.trigger.as_ref() else {
            continue;
        };
        let json = trigger_json(trigger);
        let operands: std::collections::BTreeSet<Vec<ConfigPathComponent>> =
            trigger_operand_strings(&json)
                .into_iter()
                .map(|(path, _)| path)
                .collect();
        let mut path = Vec::new();
        if let Some(found) = placeholder_outside(&json, &mut path, &operands) {
            return Err(crate::error::Error::Config(format!(
                "plugin `{}/{}` ({}): '{}' holds broker placeholder syntax, but only the \
                 `value` operands of a trigger's header, query or cookie predicate are brokered; \
                 author this predicate literally",
                plugin.namespace,
                plugin.id,
                plugin.plugin_name,
                render_trigger_path(&found)
            )));
        }
    }
    Ok(())
}

fn placeholder_outside(
    value: &Value,
    path: &mut Vec<ConfigPathComponent>,
    operands: &std::collections::BTreeSet<Vec<ConfigPathComponent>>,
) -> Option<Vec<ConfigPathComponent>> {
    match value {
        Value::String(text) => (text.contains("${gh-env-secret:")
            && !operands.contains(path.as_slice()))
        .then(|| path.clone()),
        Value::Object(map) => map.iter().find_map(|(key, child)| {
            path.push(ConfigPathComponent::Key(key.clone()));
            let found = placeholder_outside(child, path, operands);
            path.pop();
            found
        }),
        Value::Array(items) => items.iter().enumerate().find_map(|(index, child)| {
            path.push(ConfigPathComponent::Index(index));
            let found = placeholder_outside(child, path, operands);
            path.pop();
            found
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The typed mirror and Edge's predicate list agree on the key each
    /// client-field predicate serializes under.
    #[test]
    fn client_field_predicates_match_the_typed_mirror() {
        for name in TRIGGER_CLIENT_FIELD_PREDICATES {
            let trigger: PluginTrigger = serde_json::from_value(serde_json::json!({
                "when": {"match": {name: {"name": "x", "value": {"exact": ["operand-value"]}}}}
            }))
            .unwrap();
            let json = trigger_json(&trigger);
            let found = trigger_operand_strings(&json);
            assert_eq!(found.len(), 1, "{name}");
            assert_eq!(found[0].1, "operand-value", "{name}");
        }
    }
}
