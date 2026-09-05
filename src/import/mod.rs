pub mod from_api;
pub mod from_file;

pub use from_api::import_from_api;
pub use from_file::import_from_file;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::schema::{GatewayConfig, Resource};
use crate::http_client::BackupSnapshot;
use crate::secrets::{
    capture_and_redact_import_credentials, capture_and_redact_import_plugin_config_secrets,
    capture_and_redact_import_service_discovery_secrets, CredentialBundle, UnbrokeredPluginConfig,
    IMPORT_REQUIRED_PLACEHOLDER,
};

pub const IMPORT_MANIFEST_FILENAME: &str = ".gitforgeops-import.json";

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ImportResourceCounts {
    pub proxies: usize,
    pub consumers: usize,
    pub upstreams: usize,
    pub plugin_configs: usize,
    pub api_specs: usize,
    pub gateway_trust_bundles: usize,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ImportSourceMetadata {
    /// `api`, `file`, or `in-memory` (the public split_config helper).
    pub source_kind: String,
    /// Namespaces represented by this source payload, sorted lexically.
    pub namespaces: Vec<String>,
    pub config_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ferrum_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub counts: ImportResourceCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_counts: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_counts: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsupported_sections: Vec<String>,
}

impl ImportSourceMetadata {
    pub(crate) fn from_snapshot(
        source_kind: &str,
        namespaces: Vec<String>,
        snapshot: &BackupSnapshot,
    ) -> Self {
        Self {
            source_kind: source_kind.to_string(),
            namespaces,
            config_version: snapshot.config.version.clone(),
            ferrum_version: snapshot.ferrum_version.clone(),
            exported_at: snapshot.exported_at.clone(),
            source: snapshot.source.clone(),
            counts: ImportResourceCounts {
                proxies: snapshot.config.proxies.len(),
                consumers: snapshot.config.consumers.len(),
                upstreams: snapshot.config.upstreams.len(),
                plugin_configs: snapshot.config.plugin_configs.len(),
                api_specs: snapshot.extras.api_spec_count(),
                gateway_trust_bundles: snapshot.extras.trust_bundle_count(),
            },
            declared_counts: snapshot.counts.clone(),
            resource_counts: snapshot.resource_counts.clone(),
            unsupported_sections: snapshot.unsupported_sections.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ImportInventory {
    pub skipped_api_specs: usize,
    pub skipped_trust_bundles: usize,
    pub unsupported_sections: Vec<String>,
    pub sources: Vec<ImportSourceMetadata>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportResult {
    /// Number of proxy files written.
    pub proxies: usize,
    /// Number of consumer files written.
    pub consumers: usize,
    /// Number of upstream files written.
    pub upstreams: usize,
    /// Number of plugin config files written.
    pub plugin_configs: usize,
    /// API spec documents present in the source backup but **not** written.
    /// `Resource` models four kinds; API specs are managed through the admin
    /// API (`/api-specs`) and have no GitOps representation here.
    pub skipped_api_specs: usize,
    /// Gateway trust-bundle records present in the source backup but not
    /// written, for the same reason.
    pub skipped_trust_bundles: usize,
    /// Proxies / upstreams / plugin configs that carry an `api_spec_id` and
    /// were therefore **not** written as repo files.
    ///
    /// The gateway's OpenAPI-spec ingestion owns these: it creates, updates and
    /// deletes them whenever the spec is re-imported. Writing them into
    /// `resources/` would declare the repo their owner too, and the two owners
    /// then fight — every spec re-import shows up as drift, and every apply
    /// tries to push the repo's stale copy back. `diff` already reports them in
    /// their own "spec-owned" section, which is where they belong.
    pub skipped_spec_owned: usize,
    /// Number of literal credential leaves replaced with broker placeholders.
    pub redacted_credential_values: usize,
    /// Number of sensitive plugin-config strings replaced with broker
    /// placeholders. This includes schema-declared endpoints/header maps and
    /// fail-closed strings from custom plugin configs.
    pub redacted_plugin_config_values: usize,
    /// Number of modeled `Upstream.service_discovery` secrets (the Consul ACL
    /// token) replaced with broker placeholders.
    pub redacted_service_discovery_values: usize,
    /// Future/unknown top-level backup sections that this build cannot import.
    pub unsupported_sections: Vec<String>,
    /// Validated, non-secret provenance retained in the import manifest.
    pub sources: Vec<ImportSourceMetadata>,
    /// Non-builtin plugins whose config strings were left in the imported
    /// files because the sensitivity heuristics did not flag them. Surfaced
    /// by [`ImportResult::custom_plugin_review_notice`] so an operator reads
    /// them before committing.
    ///
    /// Deliberately kept out of the import manifest: the manifest is a
    /// stable, machine-readable inventory of *what was imported*, and this is
    /// a transient human review prompt about what the classifier could not
    /// judge. Nothing downstream keys on it.
    #[serde(skip)]
    pub unbrokered_plugin_config: Vec<UnbrokeredPluginConfig>,

    /// `Kind id: field, field` for every resource carrying an unmodelled
    /// top-level field the operator acknowledged with `--accept-unknown-field`.
    /// Surfaced by [`ImportResult::acknowledged_passthrough_notice`]. Kept out
    /// of the manifest for the same reason as `unbrokered_plugin_config`: it is
    /// a transient review prompt, not an inventory of what was imported.
    #[serde(skip)]
    pub acknowledged_passthrough: Vec<String>,
}

impl ImportResult {
    /// Operator-facing note about backup sections this tool does not import,
    /// or `None` when the backup carried none.
    pub fn unmanaged_sections_notice(&self) -> Option<String> {
        if self.skipped_api_specs == 0
            && self.skipped_trust_bundles == 0
            && self.skipped_spec_owned == 0
            && self.redacted_credential_values == 0
            && self.redacted_plugin_config_values == 0
            && self.redacted_service_discovery_values == 0
            && self.unsupported_sections.is_empty()
        {
            return None;
        }
        let mut notice = String::new();
        if self.skipped_api_specs > 0 || self.skipped_trust_bundles > 0 {
            notice.push_str(&format!(
                "Not imported: {} API spec(s) and {} gateway trust-bundle record(s). These are \
                 managed through the admin API (`/api-specs`, `/gateway-trust-bundles`), not \
                 through this repo, and are left untouched by `gitforgeops apply`.",
                self.skipped_api_specs, self.skipped_trust_bundles
            ));
        }
        if self.skipped_spec_owned > 0 {
            if !notice.is_empty() {
                notice.push(' ');
            }
            notice.push_str(&format!(
                "{} spec-provisioned resources skipped — managed by API spec ingestion. They carry \
                 an `api_spec_id`, so the gateway rewrites them on every spec import; committing \
                 them here would make the repo a second owner and produce permanent conflicts.",
                self.skipped_spec_owned
            ));
        }
        if self.redacted_credential_values > 0 {
            if !notice.is_empty() {
                notice.push(' ');
            }
            notice.push_str(&format!(
                "{} credential value(s) were replaced with `{IMPORT_REQUIRED_PLACEHOLDER}`; seed the derived GitHub Environment Secret slots before apply.",
                self.redacted_credential_values
            ));
        }
        if self.redacted_plugin_config_values > 0 {
            if !notice.is_empty() {
                notice.push(' ');
            }
            notice.push_str(&format!(
                "{} sensitive plugin config value(s) were replaced with `{IMPORT_REQUIRED_PLACEHOLDER}`; seed the derived GitHub Environment Secret slots before apply.",
                self.redacted_plugin_config_values
            ));
        }
        if self.redacted_service_discovery_values > 0 {
            if !notice.is_empty() {
                notice.push(' ');
            }
            notice.push_str(&format!(
                "{} service-discovery secret(s) were replaced with `{IMPORT_REQUIRED_PLACEHOLDER}`; seed the derived GitHub Environment Secret slots before apply.",
                self.redacted_service_discovery_values
            ));
        }
        if !self.unsupported_sections.is_empty() {
            if !notice.is_empty() {
                notice.push(' ');
            }
            // Section names come straight out of an untrusted backup
            // document. Printing them raw lets a crafted key inject ANSI
            // escapes or newlines into an operator's terminal and CI log, the
            // same hazard `source_metadata_notice` already routes around.
            notice.push_str(&format!(
                "Unsupported backup section(s) were not imported: {}.",
                self.unsupported_sections
                    .iter()
                    .map(|section| diagnostic_metadata(section))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Some(notice)
    }

    /// Loud per-plugin review list for the non-builtin plugins the operator
    /// allowed through with `--allow-plaintext-plugin-config`.
    ///
    /// gitforgeops has no schema for a plugin it does not know, so it brokers
    /// only what the key/URL sensitivity heuristics flag. Everything they did
    /// not flag makes the import *fail* unless the plugin was named on the
    /// command line (see `enforce_plaintext_plugin_config_allowance`) —
    /// capturing `mode: strict` into a GitHub Environment Secret makes the
    /// import unusable, and committing an unrecognized `authToken` is worse.
    /// This notice is what the accepted case prints: the exact leaves that
    /// were written verbatim on the operator's say-so.
    pub fn custom_plugin_review_notice(&self) -> Option<String> {
        if self.unbrokered_plugin_config.is_empty() {
            return None;
        }
        let mut notice = String::from(
            "WARNING: these plugin config values were written verbatim because --allow-plaintext-plugin-config named their plugin. This build has no schema for them, so only key/URL heuristics ran. Confirm once more that none of them is a credential before committing:",
        );
        for plugin in &self.unbrokered_plugin_config {
            let mut paths = plugin
                .paths
                .iter()
                .take(MAX_PATHS_PER_PLUGIN)
                .map(|path| diagnostic_metadata(path))
                .collect::<Vec<_>>();
            if plugin.paths.len() > MAX_PATHS_PER_PLUGIN {
                paths.push(format!(
                    "[{} more]",
                    plugin.paths.len() - MAX_PATHS_PER_PLUGIN
                ));
            }
            notice.push_str(&format!(
                "\n  PluginConfig {} ({}, plugin_name={}): {}",
                diagnostic_metadata(&plugin.plugin_id),
                diagnostic_metadata(&plugin.namespace),
                diagnostic_metadata(&plugin.plugin_name),
                paths.join(", ")
            ));
        }
        Some(notice)
    }

    /// Loud review list for unmodelled top-level fields carried into the tree
    /// under `--accept-unknown-field`.
    ///
    /// The acknowledgement asserts these are not credentials. It is an
    /// assertion, not a check — nothing in this build can verify it — so name
    /// every field that relied on it before the tree is committed.
    pub fn acknowledged_passthrough_notice(&self) -> Option<String> {
        if self.acknowledged_passthrough.is_empty() {
            return None;
        }
        Some(format!(
            "WARNING: these resources carry top-level fields this build does not model. They were written verbatim because `--accept-unknown-field` acknowledged them; gitforgeops did not and cannot check whether any of them is a credential. Read them before committing:\n  {}",
            self.acknowledged_passthrough.join("\n  ")
        ))
    }

    /// Bounded one-line source provenance suitable for CLI output. The same
    /// data is persisted in full in the machine-readable import manifest.
    pub fn source_metadata_notice(&self) -> Option<String> {
        if self.sources.is_empty() {
            return None;
        }
        const MAX_SOURCE_LINES: usize = 20;
        const MAX_NAMESPACES_PER_SOURCE: usize = 20;
        let mut lines = self
            .sources
            .iter()
            .take(MAX_SOURCE_LINES)
                .map(|source| {
                    let mut namespaces = source
                        .namespaces
                        .iter()
                        .take(MAX_NAMESPACES_PER_SOURCE)
                        .map(|value| diagnostic_metadata(value))
                        .collect::<Vec<_>>();
                    if source.namespaces.len() > MAX_NAMESPACES_PER_SOURCE {
                        namespaces.push(format!(
                            "[{} more in manifest]",
                            source.namespaces.len() - MAX_NAMESPACES_PER_SOURCE
                        ));
                    }
                    format!(
                        "Import source: kind={} namespaces={} config_version={} ferrum_version={} exported_at={} source={}",
                        diagnostic_metadata(&source.source_kind),
                        if namespaces.is_empty() {
                            "<none>".to_string()
                        } else {
                            namespaces.join(",")
                        },
                        diagnostic_metadata(&source.config_version),
                        source
                            .ferrum_version
                            .as_deref()
                            .map(diagnostic_metadata)
                            .unwrap_or_else(|| "<absent>".to_string()),
                        source
                            .exported_at
                            .as_deref()
                            .map(diagnostic_metadata)
                            .unwrap_or_else(|| "<absent>".to_string()),
                        source
                            .source
                            .as_deref()
                            .map(diagnostic_metadata)
                            .unwrap_or_else(|| "<absent>".to_string()),
                    )
                })
                .collect::<Vec<_>>();
        if self.sources.len() > MAX_SOURCE_LINES {
            lines.push(format!(
                "Import sources: {} additional source record(s) are available in {}",
                self.sources.len() - MAX_SOURCE_LINES,
                IMPORT_MANIFEST_FILENAME
            ));
        }
        Some(lines.join("\n"))
    }
}

fn diagnostic_metadata(value: &str) -> String {
    const MAX_CHARS: usize = 256;
    let mut sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .take(MAX_CHARS)
        .collect::<String>();
    if value.chars().count() > MAX_CHARS {
        sanitized.push_str("[truncated]");
    }
    sanitized
}

/// Split a flat gateway configuration into per-resource YAML files.
///
/// The function refuses unsafe path components, duplicate source resources that
/// would target the same path, and pre-existing output files. Callers should use
/// an empty output directory or clean it intentionally before importing.
///
/// # Warning for library callers: captured secrets are discarded
///
/// Every credential and sensitive plugin-config string in `config` is replaced
/// with [`IMPORT_REQUIRED_PLACEHOLDER`] before anything is written, and the
/// live values it captured are **dropped on return** — this entry point has
/// nowhere to put them. That is safe (nothing leaks) but lossy: the emitted
/// tree cannot be applied until every derived slot is seeded from somewhere
/// else, and if `config` was the only copy of those values, they are gone.
///
/// The CLI does not use this path. `import --from-api` / `--from-file` go
/// through `split_config_with_inventory`, which requires
/// `--credential-bundle-output` whenever the source carries a live secret and
/// writes the captured values to a private mode-0600 bundle *before* the
/// redacted tree. Prefer those unless you genuinely want the placeholders and
/// nothing else.
///
/// # Spec-owned resources are skipped
///
/// A proxy, upstream or plugin config carrying an `api_spec_id` belongs to the
/// gateway's OpenAPI-spec ingestion, which recreates it from the spec on every
/// import. Writing it into `resources/` would give it a second owner: the next
/// spec import rewrites the live copy, `diff` reports the repo's now-stale copy
/// as drift, and `apply` pushes it back — a conflict no edit resolves. They are
/// counted in [`ImportResult::skipped_spec_owned`] instead, and surfaced by
/// [`ImportResult::unmanaged_sections_notice`].
///
/// # Unmodelled resource fields fail closed
///
/// A top-level field this build's typed mirror does not model is carried
/// through `extra` and would be written into the tree verbatim, where the
/// credential broker never sees it. This entry point refuses every such field:
/// it applies [`ImportPassthroughPolicy::strict`]. The CLI's
/// `--accept-unknown-field <NAME>` (with `FERRUM_ALLOW_UNKNOWN_FIELDS=true`)
/// is the documented way to accept one after reading the source.
///
/// # Unrecognized plugins fail closed
///
/// A plugin this build has no schema for is classified by the key/URL
/// heuristics alone, and a string they do not flag would be committed as
/// written. This entry point allows none of that: an unclassifiable leaf is an
/// error. The CLI's `--allow-plaintext-plugin-config <plugin_name>` is the
/// documented way to accept them after reading the list.
pub fn split_config(
    config: &GatewayConfig,
    output_dir: &Path,
) -> crate::error::Result<ImportResult> {
    split_config_with_inventory(
        config,
        output_dir,
        ImportInventory::default(),
        None,
        false,
        &ImportPassthroughPolicy::strict(),
        &[],
    )
}

/// Two operator acknowledgements gate this path, and both are evaluated
/// before a single file is staged.
///
/// `passthrough_policy` governs top-level resource fields this build does not
/// model (`--accept-unknown-field` plus `FERRUM_ALLOW_UNKNOWN_FIELDS`); an
/// unacknowledged one aborts the whole import.
///
/// `allow_plaintext_plugin_config` holds exact `plugin_name`s whose
/// heuristically-unclassifiable config strings the operator has reviewed and
/// accepted as plaintext (`--allow-plaintext-plugin-config`). Any other plugin
/// with such a string aborts the import too.
pub(crate) fn split_config_with_inventory(
    config: &GatewayConfig,
    output_dir: &Path,
    inventory: ImportInventory,
    credential_bundle_output: Option<&Path>,
    require_credential_bundle: bool,
    passthrough_policy: &ImportPassthroughPolicy,
    allow_plaintext_plugin_config: &[String],
) -> crate::error::Result<ImportResult> {
    let mut safe_config = config.clone();
    reject_import_passthrough_fields(&safe_config, passthrough_policy)?;
    let acknowledged_passthrough = acknowledged_passthrough_review(&safe_config);
    let captured_credentials = capture_and_redact_import_credentials(&mut safe_config)?;
    let plugin_capture = capture_and_redact_import_plugin_config_secrets(&mut safe_config)?;
    let captured_discovery = capture_and_redact_import_service_discovery_secrets(&mut safe_config)?;
    let unbrokered_plugin_config = enforce_plaintext_plugin_config_allowance(
        plugin_capture.unbrokered,
        allow_plaintext_plugin_config,
    )?;
    let credential_count = captured_credentials.len();
    let plugin_config_count = plugin_capture.captured.len();
    let service_discovery_count = captured_discovery.len();
    let mut captured_secrets = captured_credentials;
    for (slot, value) in plugin_capture.captured {
        if captured_secrets.insert(slot.clone(), value).is_some() {
            return Err(crate::error::Error::Config(format!(
                "secret slot '{slot}' is produced by both a consumer credential and plugin config"
            )));
        }
    }
    for (slot, value) in captured_discovery {
        if captured_secrets.insert(slot.clone(), value).is_some() {
            return Err(crate::error::Error::Config(format!(
                "secret slot '{slot}' is produced by a service-discovery field and another resource"
            )));
        }
    }
    let mut result = ImportResult {
        skipped_api_specs: inventory.skipped_api_specs,
        skipped_trust_bundles: inventory.skipped_trust_bundles,
        unsupported_sections: inventory.unsupported_sections,
        sources: inventory.sources,
        redacted_credential_values: credential_count,
        redacted_plugin_config_values: plugin_config_count,
        redacted_service_discovery_values: service_discovery_count,
        unbrokered_plugin_config,
        acknowledged_passthrough,
        ..ImportResult::default()
    };
    if require_credential_bundle
        && !captured_secrets.is_empty()
        && credential_bundle_output.is_none()
    {
        return Err(crate::error::Error::Config(format!(
            "the source contains {} live secret value(s) across consumer credentials and plugin config; re-run import with --credential-bundle-output PATH to write their canonical broker slots to a private mode-0600 migration bundle outside the resource tree",
            captured_secrets.len()
        )));
    }
    if let Some(path) = credential_bundle_output {
        validate_migration_bundle_location(path, output_dir)?;
    }
    let mut targets = BTreeSet::new();
    let mut planned_writes = Vec::new();

    for proxy in &safe_config.proxies {
        if proxy.api_spec_id.is_some() {
            result.skipped_spec_owned += 1;
            continue;
        }
        let namespace = safe_path_component(&proxy.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("proxies");
        let resource = Resource::Proxy {
            spec: proxy.clone(),
        };
        let yaml = serialize_resource_yaml(&resource)?;
        let filename = resource_filename(&proxy.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.proxies += 1;
    }

    for consumer in &safe_config.consumers {
        let namespace = safe_path_component(&consumer.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("consumers");
        let resource = Resource::Consumer {
            spec: consumer.clone(),
        };
        let yaml = serialize_resource_yaml(&resource)?;
        let filename = resource_filename(&consumer.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.consumers += 1;
    }

    for upstream in &safe_config.upstreams {
        if upstream.api_spec_id.is_some() {
            result.skipped_spec_owned += 1;
            continue;
        }
        let namespace = safe_path_component(&upstream.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("upstreams");
        let resource = Resource::Upstream {
            spec: upstream.clone(),
        };
        let yaml = serialize_resource_yaml(&resource)?;
        let filename = resource_filename(&upstream.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.upstreams += 1;
    }

    for pc in &safe_config.plugin_configs {
        if pc.api_spec_id.is_some() {
            result.skipped_spec_owned += 1;
            continue;
        }
        let namespace = safe_path_component(&pc.namespace, "namespace")?;
        let dir = output_dir.join(namespace).join("plugins");
        let resource = Resource::PluginConfig { spec: pc.clone() };
        let yaml = serialize_resource_yaml(&resource)?;
        let filename = resource_filename(&pc.id, "id")?;
        plan_resource_file(&dir, filename, yaml, &mut targets, &mut planned_writes)?;
        result.plugin_configs += 1;
    }

    let manifest = ImportManifest {
        format_version: 1,
        import: &result,
    };
    let mut manifest_json = serde_json::to_string_pretty(&manifest)?;
    manifest_json.push('\n');
    planned_writes.push((output_dir.join(IMPORT_MANIFEST_FILENAME), manifest_json));

    // Validate the documented empty-destination contract before replacing a
    // pre-existing migration artifact. `publish_import_tree` repeats this
    // check immediately before staging/publication to close the race window.
    inspect_import_destination(output_dir)?;

    // Publish the private migration bundle first. If the later directory
    // rename fails, the complete credentials remain safely recoverable and a
    // retry can atomically replace this same file. The inverse order could
    // leave a published repo tree whose live credentials had already been
    // discarded from memory.
    if let Some(path) = credential_bundle_output {
        let bundle_json = render_migration_bundles(&captured_secrets)?;
        crate::apply::publish_private_export(
            path.to_str().ok_or_else(|| {
                crate::error::Error::Config(format!(
                    "credential migration bundle path {} is not valid UTF-8",
                    path.display()
                ))
            })?,
            bundle_json.as_bytes(),
        )?;
    }

    publish_import_tree(output_dir, planned_writes)?;

    Ok(result)
}

/// What `import` does with unknown top-level resource fields.
///
/// A gateway newer than this build returns fields the typed mirror does not
/// model. On the *load* path they are governed by `FERRUM_ALLOW_UNKNOWN_FIELDS`
/// and carried verbatim, because the operator wrote them and knows what they
/// are. Import is the opposite situation: the values come from the gateway,
/// nobody has read them, and the secret broker only redacts fields it models —
/// so an unmodelled `future_access_token` would be written into a resource
/// file and committed in plaintext. Import therefore fails closed by default
/// and needs a per-field acknowledgement to proceed.
#[derive(Debug, Clone, Default)]
pub struct ImportPassthroughPolicy {
    /// `FERRUM_ALLOW_UNKNOWN_FIELDS`. Required alongside an acknowledgement:
    /// without it the strict loader rejects the very tree import just wrote,
    /// so importing the field could only ever produce an unusable repo.
    pub allow_unknown_fields: bool,
    /// `--accept-unknown-field NAME`, repeatable. Names the operator has
    /// reviewed and asserts are not credentials. Deliberately not implied by
    /// `FERRUM_ALLOW_UNKNOWN_FIELDS`: that flag says "gitforgeops does not
    /// model this", which is not a statement about secrecy.
    pub acknowledged: BTreeSet<String>,
}

impl ImportPassthroughPolicy {
    /// Fail closed on everything. The default for library callers.
    pub fn strict() -> Self {
        Self::default()
    }
}

/// Every importable resource paired with its unknown top-level fields.
///
/// Spec-owned proxies, upstreams and plugin configs are excluded because they
/// are skipped rather than written; consumers carry no `api_spec_id`.
fn passthrough_fields(config: &GatewayConfig) -> Vec<(&'static str, &str, Vec<&str>)> {
    config
        .proxies
        .iter()
        .filter(|resource| resource.api_spec_id.is_none())
        .map(|resource| ("Proxy", resource.id.as_str(), &resource.extra))
        .chain(
            config
                .consumers
                .iter()
                .map(|resource| ("Consumer", resource.id.as_str(), &resource.extra)),
        )
        .chain(
            config
                .upstreams
                .iter()
                .filter(|resource| resource.api_spec_id.is_none())
                .map(|resource| ("Upstream", resource.id.as_str(), &resource.extra)),
        )
        .chain(
            config
                .plugin_configs
                .iter()
                .filter(|resource| resource.api_spec_id.is_none())
                .map(|resource| ("PluginConfig", resource.id.as_str(), &resource.extra)),
        )
        .filter(|(_, _, extra)| !extra.is_empty())
        .map(|(kind, id, extra)| {
            (
                kind,
                id,
                extra.keys().map(String::as_str).collect::<Vec<_>>(),
            )
        })
        .collect()
}

/// Refuse fields whose sensitivity this version cannot classify, before any
/// import output (including a migration bundle) is planned or published.
///
/// Field *names* are reported; values never are. A name that has not been
/// acknowledged is refused outright — this build cannot tell a display label
/// from a bearer token, and the broker will not redact what it does not model,
/// so writing it would commit a possible credential to Git.
fn reject_import_passthrough_fields(
    config: &GatewayConfig,
    policy: &ImportPassthroughPolicy,
) -> crate::error::Result<()> {
    let carried = passthrough_fields(config);
    if carried.is_empty() {
        return Ok(());
    }

    let mut unacknowledged: BTreeSet<&str> = BTreeSet::new();
    let mut offender: Option<(&str, &str)> = None;
    for (kind, id, fields) in &carried {
        for field in fields {
            if !policy.acknowledged.contains(*field) {
                unacknowledged.insert(field);
                offender.get_or_insert((kind, id));
            }
        }
    }

    if let Some((kind, id)) = offender {
        let names = unacknowledged
            .iter()
            .map(|field| diagnostic_metadata(field))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(crate::error::Error::Config(format!(
            "cannot safely import {kind} '{}': this build does not model the top-level field(s) [{names}], \
             so the credential broker cannot tell whether they hold secrets and would write them into the \
             resource tree verbatim. Upgrade gitforgeops to a version that models them, or — after reading \
             the source and confirming they are not credentials — re-run with \
             `--accept-unknown-field <NAME>` for each and FERRUM_ALLOW_UNKNOWN_FIELDS=true.",
            diagnostic_metadata(id)
        )));
    }

    if !policy.allow_unknown_fields {
        return Err(crate::error::Error::Config(
            "every unmodelled field in this source is acknowledged, but FERRUM_ALLOW_UNKNOWN_FIELDS is not set. \
             The strict loader would reject the resource files this import is about to write, so the tree \
             could not be validated or applied. Set FERRUM_ALLOW_UNKNOWN_FIELDS=true and re-run."
                .to_string(),
        ));
    }

    Ok(())
}

/// Human-readable list of the acknowledged unmodelled fields that were carried
/// into the tree, so they are reviewed before the import is committed.
fn acknowledged_passthrough_review(config: &GatewayConfig) -> Vec<String> {
    passthrough_fields(config)
        .into_iter()
        .map(|(kind, id, fields)| {
            format!(
                "{kind} {}: {}",
                diagnostic_metadata(id),
                fields
                    .iter()
                    .map(|field| diagnostic_metadata(field))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect()
}

/// Longest per-plugin path list rendered in a notice or a refusal. A crafted
/// backup could otherwise turn one plugin into a megabyte of terminal output.
const MAX_PATHS_PER_PLUGIN: usize = 50;

/// Refuse the import unless every unrecognized plugin holding an
/// unclassifiable config string has been named on the command line.
///
/// gitforgeops has no schema for such a plugin, so only the key/URL
/// sensitivity heuristics run over its config, and a vendor field they do not
/// recognize — `authToken`, `serviceCredential`, anything the naming
/// conventions missed — would be committed to Git exactly as the backup
/// returned it. The old behavior printed a warning after publishing the tree,
/// which is the wrong order: by the time an operator reads it, the value is on
/// disk and (once merged) in the repository's history.
///
/// So the default is now to fail, and the failure is recoverable in the only
/// way that is honest — the operator reads the named paths, decides that none
/// of them is a credential, and re-runs with
/// `--allow-plaintext-plugin-config <plugin_name>` for each plugin they
/// accepted. Heuristically-flagged leaves are brokered either way; the flag
/// only governs what the heuristics could *not* judge.
///
/// The refusal names the plugin id, its `plugin_name`, and every unclassified
/// path — and no values, because the whole point is that gitforgeops does not
/// know whether they are secrets.
fn enforce_plaintext_plugin_config_allowance(
    unbrokered: Vec<UnbrokeredPluginConfig>,
    allowed: &[String],
) -> crate::error::Result<Vec<UnbrokeredPluginConfig>> {
    let refused: Vec<&UnbrokeredPluginConfig> = unbrokered
        .iter()
        .filter(|plugin| !allowed.contains(&plugin.plugin_name))
        .collect();
    if refused.is_empty() {
        return Ok(unbrokered);
    }

    let mut message = String::from(
        "refusing to import plaintext plugin config: this build has no schema for the plugin(s) below, so only the key/URL sensitivity heuristics ran, and the string values at these paths would be committed to the repository as written. Read them at the source, and if none is a credential re-run with --allow-plaintext-plugin-config <plugin_name> for each (exact plugin_name, repeatable). Nothing has been written.",
    );
    for plugin in refused {
        let mut paths = plugin
            .paths
            .iter()
            .take(MAX_PATHS_PER_PLUGIN)
            .map(|path| diagnostic_metadata(path))
            .collect::<Vec<_>>();
        if plugin.paths.len() > MAX_PATHS_PER_PLUGIN {
            paths.push(format!(
                "[{} more]",
                plugin.paths.len() - MAX_PATHS_PER_PLUGIN
            ));
        }
        message.push_str(&format!(
            "\n  PluginConfig {} ({}, plugin_name={}): {}",
            diagnostic_metadata(&plugin.plugin_id),
            diagnostic_metadata(&plugin.namespace),
            diagnostic_metadata(&plugin.plugin_name),
            paths.join(", ")
        ));
    }
    Err(crate::error::Error::Config(message))
}

fn serialize_resource_yaml(resource: &Resource) -> crate::error::Result<String> {
    // HashMap-backed credential/tag fields otherwise inherit randomized map
    // iteration order. serde_json::Value uses a sorted map in this build, so
    // this intermediate representation makes byte output deterministic.
    let canonical = serde_json::to_value(resource)?;
    serde_yaml::to_string(&canonical).map_err(crate::error::Error::SerdeYaml)
}

#[derive(Serialize)]
struct ImportManifest<'a> {
    format_version: u32,
    import: &'a ImportResult,
}

fn plan_resource_file(
    dir: &Path,
    filename: String,
    yaml: String,
    targets: &mut BTreeSet<std::path::PathBuf>,
    planned_writes: &mut Vec<(std::path::PathBuf, String)>,
) -> crate::error::Result<()> {
    let path = dir.join(filename);
    if !targets.insert(path.clone()) {
        return Err(crate::error::Error::Config(format!(
            "import would write multiple resources to {}; duplicate namespace/kind/id in source config",
            path.display()
        )));
    }
    if path.exists() {
        return Err(crate::error::Error::Config(format!(
            "refusing to overwrite existing import target {}; choose an empty output directory or remove the file first",
            path.display()
        )));
    }
    planned_writes.push((path, yaml));
    Ok(())
}

fn render_migration_bundles(captured: &CredentialBundle) -> crate::error::Result<String> {
    let mut shards: BTreeMap<u32, CredentialBundle> = BTreeMap::from([(0, BTreeMap::new())]);
    let mut shard_sizes = BTreeMap::from([(0_u32, 2_usize)]); // `{}`

    for (slot, value) in captured {
        // Exact compact-JSON size, including escaping. Imported values are not
        // generated base64 and may contain quotes/control characters whose
        // encoded size is much larger than `value.len()`.
        let entry_size =
            serde_json::to_string(slot)?.len() + 1 + serde_json::to_string(value)?.len();
        let shard = (0..shards.len() as u32)
            .find(|candidate| {
                let current = shard_sizes.get(candidate).copied().unwrap_or(2);
                current + usize::from(current > 2) + entry_size
                    <= crate::secrets::bundle::BUNDLE_SOFT_LIMIT_BYTES
            })
            .unwrap_or(shards.len() as u32);
        if shard >= 100 {
            return Err(crate::error::Error::Config(
                "credential migration bundle would exceed GitHub's 100 environment-secret shard limit"
                    .to_string(),
            ));
        }
        let current = shard_sizes.get(&shard).copied().unwrap_or(2);
        let projected = current + usize::from(current > 2) + entry_size;
        if projected > crate::secrets::bundle::BUNDLE_SOFT_LIMIT_BYTES {
            return Err(crate::error::Error::Config(format!(
                "credential slot '{slot}' cannot fit within GitHub's credential-bundle secret size limit"
            )));
        }
        shard_sizes.insert(shard, projected);
        shards
            .entry(shard)
            .or_default()
            .insert(slot.clone(), value.clone());
    }

    let outer = shards
        .into_iter()
        .map(|(shard, bundle)| (crate::secrets::bundle::shard_secret_name(shard), bundle))
        .collect::<BTreeMap<_, _>>();
    let mut json = serde_json::to_string_pretty(&outer)?;
    json.push('\n');
    Ok(json)
}

fn validate_migration_bundle_location(
    bundle: &Path,
    output_dir: &Path,
) -> crate::error::Result<()> {
    let lexical_bundle = lexically_normalized_absolute(bundle)?;
    let lexical_output = lexically_normalized_absolute(output_dir)?;
    if lexical_bundle == lexical_output || lexical_bundle.starts_with(&lexical_output) {
        return Err(crate::error::Error::Config(format!(
            "credential migration bundle must be outside the import resource tree {}; choose a private path elsewhere",
            output_dir.display()
        )));
    }
    if let Some(worktree) = containing_git_worktree(&lexical_bundle)? {
        return Err(crate::error::Error::Config(format!(
            "credential migration bundle must be outside every Git worktree; {} is inside {}",
            lexical_bundle.display(),
            worktree.display()
        )));
    }

    // Repeat after resolving existing symlinked ancestors. The lexical check
    // prevents replacing a symlink *located* in the resource tree/repo; this
    // check prevents an outside-looking path from resolving back into one.
    let resolved_bundle = resolve_for_containment(bundle)?;
    let resolved_output = resolve_for_containment(output_dir)?;
    if resolved_bundle == resolved_output || resolved_bundle.starts_with(&resolved_output) {
        return Err(crate::error::Error::Config(format!(
            "credential migration bundle resolves inside the import resource tree {}; choose a private path elsewhere",
            output_dir.display()
        )));
    }
    if let Some(worktree) = containing_git_worktree(&resolved_bundle)? {
        return Err(crate::error::Error::Config(format!(
            "credential migration bundle must be outside every Git worktree; {} resolves inside {}",
            bundle.display(),
            worktree.display()
        )));
    }
    Ok(())
}

pub(crate) fn validate_migration_bundle_source(
    bundle: &Path,
    source: &Path,
) -> crate::error::Result<()> {
    let same_lexical_path =
        lexically_normalized_absolute(bundle)? == lexically_normalized_absolute(source)?;
    let same_resolved_path = resolve_for_containment(bundle)? == resolve_for_containment(source)?;
    if same_lexical_path || same_resolved_path {
        return Err(crate::error::Error::Config(format!(
            "credential migration bundle must be a separate file and may not overwrite its source backup {}",
            source.display()
        )));
    }
    Ok(())
}

fn lexically_normalized_absolute(path: &Path) -> crate::error::Result<PathBuf> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(crate::error::Error::Config(format!(
                        "path {} escapes the filesystem root",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(normalized)
}

fn containing_git_worktree(path: &Path) -> crate::error::Result<Option<PathBuf>> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    for ancestor in start.ancestors() {
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => return Ok(Some(ancestor.to_path_buf())),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(crate::error::Error::Io(source)),
        }
    }
    Ok(None)
}

/// Resolve existing symlinked ancestors while still accepting a final path
/// that does not exist yet, then normalize `.`/`..` components for a reliable
/// containment comparison.
///
/// The lexical normalization runs **first**, before the canonicalize walk.
/// `..` under an ancestor that does not exist otherwise walks the loop up to a
/// component whose `file_name()` is `None` — a path ending in `..` has no file
/// name — and reports "cannot resolve path … for containment validation",
/// which says nothing about the actual problem. Collapsing the components up
/// front turns `/nonexistent/../wanted` into `/wanted` and the check proceeds
/// normally. Normalizing before resolution can differ from the kernel's view
/// when a `..` crosses a symlink, but every symlinked *ancestor* that exists
/// is still canonicalized below, and the only decision made from the result is
/// a containment comparison that this makes stricter, not looser.
fn resolve_for_containment(path: &Path) -> crate::error::Result<PathBuf> {
    let absolute = lexically_normalized_absolute(path)?;
    let mut existing = absolute.as_path();
    let mut suffix = Vec::new();
    let canonical = loop {
        match std::fs::canonicalize(existing) {
            Ok(canonical) => break canonical,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    crate::error::Error::Config(format!(
                        "cannot resolve path {} for containment validation",
                        path.display()
                    ))
                })?;
                suffix.push(name.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    crate::error::Error::Config(format!(
                        "cannot resolve path {} for containment validation",
                        path.display()
                    ))
                })?;
            }
            Err(source) => return Err(crate::error::Error::Io(source)),
        }
    };
    Ok(suffix
        .into_iter()
        .rev()
        .fold(canonical, |resolved, component| resolved.join(component)))
}

/// Publish a complete import as one directory rename. Import is documented for
/// an empty destination; enforcing that contract lets a late parse/write error
/// leave the old tree untouched instead of stranding a partial migration that
/// a rerun then refuses to overwrite.
fn publish_import_tree(
    output_dir: &Path,
    planned_writes: Vec<(PathBuf, String)>,
) -> crate::error::Result<()> {
    let destination_existed = inspect_import_destination(output_dir)?;

    let parent = output_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".gitforgeops-import-")
        .tempdir_in(parent)?;

    for (target, yaml) in planned_writes {
        let relative = target.strip_prefix(output_dir).map_err(|_| {
            crate::error::Error::Config(format!(
                "planned import target {} escaped output directory {}",
                target.display(),
                output_dir.display()
            ))
        })?;
        let staged_path = staging.path().join(relative);
        if let Some(dir) = staged_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_path)?;
        file.write_all(yaml.as_bytes())?;
        file.sync_all()?;
    }

    apply_import_root_permissions(output_dir, staging.path())?;
    sync_import_directories(staging.path())?;

    // Re-check immediately before publication so a concurrent writer cannot be
    // replaced after the initial emptiness test.
    if destination_existed {
        let metadata = std::fs::symlink_metadata(output_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(crate::error::Error::Config(format!(
                "import output {} changed type while the import was being staged",
                output_dir.display()
            )));
        }
        if std::fs::read_dir(output_dir)?.next().is_some() {
            return Err(crate::error::Error::Config(format!(
                "import output directory {} changed while the import was being staged",
                output_dir.display()
            )));
        }
    } else {
        match std::fs::symlink_metadata(output_dir) {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(crate::error::Error::Config(format!(
                    "import output {} appeared while the import was being staged",
                    output_dir.display()
                )));
            }
            Err(source) => return Err(crate::error::Error::Io(source)),
        }
    }

    publish_staging_directory(staging.path(), output_dir, destination_existed)?;

    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;

    Ok(())
}

fn inspect_import_destination(output_dir: &Path) -> crate::error::Result<bool> {
    match std::fs::symlink_metadata(output_dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(crate::error::Error::Config(format!(
                    "import output {} must be an empty directory and may not be a symlink",
                    output_dir.display()
                )));
            }
            if std::fs::read_dir(output_dir)?.next().is_some() {
                return Err(crate::error::Error::Config(format!(
                    "refusing to import into non-empty output directory {}; choose an empty directory",
                    output_dir.display()
                )));
            }
            Ok(true)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(crate::error::Error::Io(source)),
    }
}

/// Persist the staged directory entries before making the root rename
/// durable. File contents were fsynced individually above; syncing every
/// directory closes the remaining crash window where a nested filename could
/// disappear after the root was published.
#[cfg(unix)]
fn sync_import_directories(root: &Path) -> crate::error::Result<()> {
    let mut directories = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| match entry {
            Ok(entry) if entry.file_type().is_dir() => Some(Ok(entry.into_path())),
            Ok(_) => None,
            Err(source) => Some(Err(crate::error::Error::Config(format!(
                "failed to inspect staged import tree: {source}"
            )))),
        })
        .collect::<crate::error::Result<Vec<_>>>()?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_import_directories(_root: &Path) -> crate::error::Result<()> {
    Ok(())
}

/// POSIX rename can atomically replace an existing empty directory. Keep the
/// destination in place until that single syscall so a crash can never leave
/// an absent tree. Platforms without that guarantee use a guarded fallback
/// and restore the empty directory if publication fails.
#[cfg(unix)]
fn publish_staging_directory(
    staged: &Path,
    output: &Path,
    _destination_existed: bool,
) -> crate::error::Result<()> {
    std::fs::rename(staged, output)?;
    Ok(())
}

#[cfg(not(unix))]
fn publish_staging_directory(
    staged: &Path,
    output: &Path,
    destination_existed: bool,
) -> crate::error::Result<()> {
    if destination_existed {
        std::fs::remove_dir(output)?;
    }
    if let Err(source) = std::fs::rename(staged, output) {
        if destination_existed && !output.exists() {
            let _ = std::fs::create_dir(output);
        }
        return Err(crate::error::Error::Io(source));
    }
    Ok(())
}

#[cfg(unix)]
fn apply_import_root_permissions(existing: &Path, staged: &Path) -> crate::error::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match std::fs::symlink_metadata(existing) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(crate::error::Error::Config(format!(
                "import output {} changed type while the import was being staged",
                existing.display()
            )));
        }
        Ok(metadata) => metadata.permissions().mode() & 0o777,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => 0o755,
        Err(source) => return Err(crate::error::Error::Io(source)),
    };
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_import_root_permissions(_existing: &Path, _staged: &Path) -> crate::error::Result<()> {
    Ok(())
}

/// Reject values that would break out of `output_dir` (path traversal, absolute
/// paths, null bytes). Resource identifiers originate from an admin API or
/// user YAML and must not be trusted as filesystem path components.
fn safe_path_component<'a>(value: &'a str, field: &str) -> crate::error::Result<&'a str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err(crate::error::Error::Config(format!(
            "unsafe {field} {value:?} — cannot use as filesystem path component"
        )));
    }
    Ok(value)
}

/// Filename for one imported resource, derived from its id.
///
/// A leading `_` is the loader's "intentionally disabled" marker, so an id like
/// `_internal-api` cannot become `_internal-api.yaml` — the file would be
/// written and then skipped on every subsequent load, silently dropping the
/// resource from desired state (and, in exclusive mode, pruning it). Failing
/// the whole import instead is no better: the id is the gateway's, the
/// operator cannot rename it from here, and one such resource dead-ends the
/// migration entirely.
///
/// So the leading character is percent-encoded — `_internal-api` becomes
/// `%5Finternal-api.yaml`. The loader reads a resource's identity from
/// `spec.id`, never from the filename, so the encoded name round-trips
/// unchanged. A leading `%` is encoded too (`%25…`), which keeps the mapping
/// injective: without it `%5Ffoo` and `_foo` would collide on one path (caught
/// by `plan_resource_file`, but as a confusing duplicate-target error).
fn resource_filename(id: &str, field: &str) -> crate::error::Result<String> {
    let safe = safe_path_component(id, field)?;
    let encoded = match safe.as_bytes().first() {
        Some(b'_') => format!("%5F{}", &safe[1..]),
        Some(b'%') => format!("%25{}", &safe[1..]),
        _ => safe.to_string(),
    };
    Ok(format!("{encoded}.yaml"))
}
