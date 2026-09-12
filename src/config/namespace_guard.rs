//! Fail-closed guard for a namespace filter that selects nothing.
//!
//! A mistyped `FERRUM_NAMESPACE` (or environment `namespace_filter`) used to
//! make `validate`, `plan`, and `diff --exit-on-drift` succeed against an
//! empty desired set while the on-disk tree and the live gateway still held
//! resources in other namespaces. This module is the shared diagnosis those
//! three commands apply.
//!
//! The refusal is an **error-severity finding**. It uses the same ordinary
//! error exit code as every other fail-closed CLI error ([`EMPTY_NAMESPACE_EXIT_CODE`],
//! `1`), not [`crate::verdict::DRIFT_EXIT_CODE`] (2). `--allow-empty-namespace`
//! is the CLI-only acknowledgement that downgrades it to a warning; there is
//! deliberately no environment variable, matching `--allow-credential-slot-remap`.

use std::collections::BTreeSet;

use crate::config::{GatewayConfig, schema::Resource};
use crate::diagnostics::{sanitize, sanitize_line};
use crate::policy::Severity;

/// Process exit code when a namespace filter selects zero desired resources
/// while the on-disk tree is non-empty, and the operator has not passed
/// `--allow-empty-namespace`.
///
/// Same value as an ordinary CLI error (`1`). Distinct from
/// [`crate::verdict::DRIFT_EXIT_CODE`] so a scheduled drift monitor can tell
/// "the filter matched nothing" from "the gateway drifted".
pub const EMPTY_NAMESPACE_EXIT_CODE: i32 = 1;

/// Snapshot of the active namespace filter against desired, on-disk, and
/// (when a live comparison ran) live inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceScope {
    /// Active filter (`FERRUM_NAMESPACE` or the environment `namespace_filter`).
    /// `None` means the run processes every namespace.
    pub filter: Option<String>,
    /// Directory namespaces that contributed at least one loaded resource,
    /// including mesh fragments. Sorted and de-duplicated.
    pub on_disk_namespaces: Vec<String>,
    /// Number of resource files loaded from the tree (after overlays, before
    /// the namespace filter). Mesh fragments count.
    pub on_disk_count: usize,
    /// Gateway resources plus in-scope mesh fragments after the filter.
    pub desired_count: usize,
    /// Live gateway resources in the filtered snapshot. `None` when the
    /// command does not talk to a gateway (`validate`) or comparison was
    /// skipped.
    pub live_count: Option<usize>,
    /// Namespaces `GET /namespaces` listed for this token, populated only
    /// when filtered live inventory was empty and the listing succeeded.
    pub live_namespaces: Vec<String>,
}

}

impl NamespaceScope {
    /// Count loaded resource files and the directory namespaces they occupy.
    pub fn on_disk_inventory(resources: &[(String, Resource)]) -> (usize, Vec<String>) {
        inventory_from_resources(resources)
    }

    /// Build the desired/on-disk half of the snapshot.
    pub fn from_loaded(
        filter: Option<&str>,
        resources: &[(String, Resource)],
        desired: &GatewayConfig,
        desired_mesh_count: usize,
    ) -> Self {
        let (on_disk_count, on_disk_namespaces) = inventory_from_resources(resources);
        Self::with_desired(
            filter,
            on_disk_namespaces,
            on_disk_count,
            desired,
            desired_mesh_count,
        )
    }

    /// Assemble a scope once desired selection has already run.
    pub fn with_desired(
        filter: Option<&str>,
        on_disk_namespaces: Vec<String>,
        on_disk_count: usize,
        desired: &GatewayConfig,
        desired_mesh_count: usize,
    ) -> Self {
        Self {
            filter: filter.map(str::to_string),
            on_disk_namespaces,
            on_disk_count,
            desired_count: gateway_resource_count(desired) + desired_mesh_count,
            live_count: None,
            live_namespaces: Vec::new(),
        }
    }

    /// Record filtered live resource counts. Does not probe unfiltered live
    /// namespaces; call [`Self::set_live_namespaces`] after `GET /namespaces`.
    pub fn set_live_count(&mut self, live_count: usize) {
        self.live_count = Some(live_count);
    }

    /// Record the namespaces the live listing returned.
    pub fn set_live_namespaces(&mut self, namespaces: Vec<String>) {
        self.live_namespaces = namespaces;
    }

    /// True when a filter is set, the desired set is empty, and the tree on
    /// disk is not. An empty repository is not a mismatch.
    pub fn empty_desired_mismatch(&self) -> bool {
        self.filter.is_some() && self.desired_count == 0 && self.on_disk_count > 0
    }

    /// True when filtered live inventory is empty solely because the filter
    /// matched no live namespace, while the token can see at least one other
    /// namespace. A listed namespace that equals the filter is an empty-but-
    /// matching namespace (a new slice), not a miss.
    pub fn live_filter_matched_nothing(&self) -> bool {
        let Some(filter) = self.filter.as_deref() else {
            return false;
        };
        if self.live_count != Some(0) {
            return false;
        }
        if self.live_namespaces.is_empty() {
            return false;
        }
        let filter_listed = self.live_namespaces.iter().any(|ns| ns == filter);
        let other_listed = self.live_namespaces.iter().any(|ns| ns != filter);
        !filter_listed && other_listed
    }

    /// Error-severity finding unless `--allow-empty-namespace` was passed.
    pub fn desired_finding(&self, allow_empty_namespace: bool) -> Option<NamespaceFilterFinding> {
        if !self.empty_desired_mismatch() {
            return None;
        }
        let severity = if allow_empty_namespace {
            Severity::Warning
        } else {
            Severity::Error
        };
        Some(NamespaceFilterFinding {
            severity,
            message: self.desired_mismatch_message(),
        })
    }

    /// Advisory when live inventory is empty because the filter matched
    /// nothing. Never fail-closed on its own; [`Self::desired_finding`] is
    /// what refuses the run when desired is also empty.
    pub fn live_warning(&self) -> Option<String> {
        if !self.live_filter_matched_nothing() {
            return None;
        }
        Some(self.live_mismatch_message())
    }

    /// Human-readable scope line for text output.
    pub fn text_line(&self) -> String {
        let filter = sanitize(self.filter.as_deref().unwrap_or("<all>"));
        let namespaces = format_namespace_list(&self.on_disk_namespaces);
        let live = match self.live_count {
            Some(count) => format!("  live={count}"),
            None => String::new(),
        };
        format!(
            "namespace={filter}  desired={}  on_disk={} ({namespaces}){live}",
            self.desired_count, self.on_disk_count
        )
    }

    /// Fields to add to existing JSON objects. Names are additive; callers
    /// must not rename `success`, `exit_code`, `stdout`, or `stderr`.
    pub fn json_fields(&self) -> serde_json::Value {
        let namespace = match &self.filter {
            Some(filter) => serde_json::Value::String(sanitize(filter)),
            None => serde_json::Value::Null,
        };
        let live_count = match self.live_count {
            Some(count) => serde_json::json!(count),
            None => serde_json::Value::Null,
        };
        serde_json::json!({
            "namespace": namespace,
            "desired_count": self.desired_count,
            "live_count": live_count,
            "on_disk_count": self.on_disk_count,
            "on_disk_namespaces": self
                .on_disk_namespaces
                .iter()
                .map(|ns| sanitize(ns))
                .collect::<Vec<_>>(),
            "live_namespaces": self
                .live_namespaces
                .iter()
                .map(|ns| sanitize(ns))
                .collect::<Vec<_>>(),
            "live_filter_matched_nothing": self.live_filter_matched_nothing(),
        })
    }

    fn desired_mismatch_message(&self) -> String {
        let filter = sanitize(self.filter.as_deref().unwrap_or("<unset>"));
        let namespaces = format_namespace_list(&self.on_disk_namespaces);
        sanitize_line(&format!(
            "namespace filter '{filter}' selected 0 desired resources \
             (desired={}, on_disk={}), but the resource tree contains resources in \
             namespace(s): {namespaces}. This usually means FERRUM_NAMESPACE or the \
             environment namespace_filter is mistyped. Re-run with a matching \
             namespace, omit the filter to process all namespaces, or pass \
             --allow-empty-namespace to continue.",
            self.desired_count, self.on_disk_count
        ))
    }

    fn live_mismatch_message(&self) -> String {
        let filter = sanitize(self.filter.as_deref().unwrap_or("<unset>"));
        let namespaces = format_namespace_list(&self.live_namespaces);
        let live = self.live_count.unwrap_or(0);
        sanitize_line(&format!(
            "namespace filter '{filter}' matched 0 live resources (live={live}), \
             but unfiltered live inventory lists namespace(s): {namespaces}. \
             Comparison is against an empty live set because the filter matched \
             nothing."
        ))
    }
}

/// One empty-namespace-filter finding. Severity `error` refuses the run;
/// `--allow-empty-namespace` demotes it to `warning`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceFilterFinding {
    pub severity: Severity,
    pub message: String,
}

impl NamespaceFilterFinding {
    pub fn is_error(&self) -> bool {
        self.severity.blocks_apply()
    }

    pub fn severity_label(&self) -> &'static str {
        self.severity.as_str()
    }
}

/// Gateway resources in a document. Mesh fragments are counted separately
/// because they are not fields on [`GatewayConfig`].
pub fn gateway_resource_count(config: &GatewayConfig) -> usize {
    config.proxies.len()
        + config.consumers.len()
        + config.upstreams.len()
        + config.plugin_configs.len()
}

/// Merge [`NamespaceScope::json_fields`] into an existing JSON document without
/// renaming keys the document already has.
pub fn merge_scope_json(
    formatted: &str,
    scope: &NamespaceScope,
    finding: Option<&NamespaceFilterFinding>,
) -> String {
    let mut value = match serde_json::from_str::<serde_json::Value>(formatted) {
        Ok(value) => value,
        Err(_) => return formatted.to_string(),
    };
    let Some(object) = value.as_object_mut() else {
        return formatted.to_string();
    };
    if let Some(fields) = scope.json_fields().as_object() {
        for (key, field) in fields {
            object.insert(key.clone(), field.clone());
        }
    }
    match finding {
        Some(finding) => {
            object.insert(
                "empty_namespace_filter".to_string(),
                serde_json::Value::String(finding.severity_label().to_string()),
            );
            object.insert(
                "empty_namespace_filter_message".to_string(),
                serde_json::Value::String(finding.message.clone()),
            );
        }
        None => {
            object.insert("empty_namespace_filter".to_string(), serde_json::Value::Null);
        }
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| formatted.to_string())
}

fn inventory_from_resources(resources: &[(String, Resource)]) -> (usize, Vec<String>) {
    let mut namespaces = BTreeSet::new();
    for (namespace, _) in resources {
        if !namespace.is_empty() {
            namespaces.insert(namespace.clone());
        }
    }
    (resources.len(), namespaces.into_iter().collect())
}

fn format_namespace_list(namespaces: &[String]) -> String {
    if namespaces.is_empty() {
        return "<none>".to_string();
    }
    namespaces
        .iter()
        .map(|namespace| sanitize(namespace))
        .collect::<Vec<_>>()
        .join(", ")
}
