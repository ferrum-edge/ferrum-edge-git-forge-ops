use std::collections::HashMap;
use std::path::Path;

use walkdir::WalkDir;

use super::schema::{BackendScheme, GatewayConfig, MeshConfigSpec, Resource};

/// Everything one load+assemble pass produces.
///
/// Mesh configuration is deliberately **not** a field on `GatewayConfig`.
/// ferrum-edge does have a `mesh:` key on its own gateway document, but it is
/// inert there — gateway file mode never reads it, and there is no `mesh`
/// section on `GET /backup` / `POST /restore`. The only consumer of a mesh
/// document is a mesh-protocol node reading a *standalone*
/// `{version: "1", mesh: {...}}` file whose loader is `deny_unknown_fields`
/// and rejects `proxies:` outright. Keeping the two documents apart in the
/// type system is what stops mesh config from ever leaking into the gateway
/// output (or a gateway resource into the mesh document).
#[derive(Debug, Clone, Default)]
pub struct AssembledOutput {
    pub gateway: GatewayConfig,
    /// `None` when the repo declares no `MeshConfig` resources at all — the
    /// signal that no mesh document should be written or validated.
    pub mesh: Option<MeshConfigSpec>,
}

/// Assemble loaded resources into a `GatewayConfig` plus an optional merged
/// mesh document.
///
/// Sets each gateway resource's `namespace` field to the directory-inferred
/// namespace, unless the spec already has a non-default namespace explicitly
/// set, then canonicalizes consumer credentials via
/// [`normalize_consumer_credentials`] and proxy backend schemes via
/// [`normalize_proxy_backend_schemes`]. Mesh fragments are merged by
/// [`merge_mesh_fragments`].
pub fn assemble(resources: Vec<(String, Resource)>) -> crate::error::Result<AssembledOutput> {
    assemble_with_namespace_filter(resources, None)
}

/// [`assemble`], restricting **mesh fragments** to those loaded from
/// `resources/<namespace_filter>/mesh/`.
///
/// Gateway resources are intentionally left alone here: they carry their own
/// `namespace` field (which may override the directory), so they are filtered
/// downstream by `select_config_namespace` on the effective namespace. A mesh
/// fragment has no such field — its directory *is* its only handle — so the
/// filter has to be applied at merge time or not at all.
pub fn assemble_with_namespace_filter(
    resources: Vec<(String, Resource)>,
    namespace_filter: Option<&str>,
) -> crate::error::Result<AssembledOutput> {
    let mut config = GatewayConfig::default();
    let mut mesh_fragments: Vec<(String, MeshConfigSpec)> = Vec::new();

    for (namespace, resource) in resources {
        match resource {
            Resource::Proxy { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.proxies.push(spec);
            }
            Resource::Consumer { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.consumers.push(spec);
            }
            Resource::Upstream { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.upstreams.push(spec);
            }
            Resource::PluginConfig { mut spec } => {
                if spec.namespace == "ferrum" {
                    spec.namespace = namespace;
                }
                config.plugin_configs.push(spec);
            }
            Resource::MeshConfig { id, spec } => {
                if let Some(filter) = namespace_filter {
                    if namespace != filter {
                        continue;
                    }
                }
                let label = match id {
                    Some(id) if !id.trim().is_empty() => format!("{namespace}/mesh/{id}"),
                    _ => format!("{namespace}/mesh"),
                };
                mesh_fragments.push((label, spec));
            }
        }
    }

    normalize_consumer_credentials(&mut config);
    normalize_proxy_backend_schemes(&mut config);

    Ok(AssembledOutput {
        gateway: config,
        mesh: merge_mesh_fragments(mesh_fragments)?,
    })
}

/// Fold every `MeshConfig` fragment into the single document a mesh node
/// loads.
///
/// Every mesh node reads the *same* `{version, mesh}` document and derives its
/// own slice from it, so there is exactly one merged object no matter how many
/// files or namespaces contributed to it.
///
/// * **Collection fields concatenate** in load order. Cross-references inside
///   a mesh document (a service naming a workload's SPIFFE ID, a policy naming
///   a service) are resolved against the merged whole, so splitting a mesh
///   across files is purely an authoring convenience.
/// * **`workloads` and `services` additionally check identity.** Both have a
///   mesh-wide primary key (`spiffe_id`; `(name, namespace)`) — the same keys
///   overlays merge on — so two fragments defining one key differently is an
///   authoring conflict, not a longer list, and is rejected naming both
///   fragments. Byte-identical duplicates are deduplicated instead. See
///   [`merge_mesh_identified_collection`].
/// * **Scalar / singleton fields take the one value that is set.** Two
///   fragments setting the *same* value agree and are accepted; two fragments
///   setting *different* values are a genuine authoring conflict with no
///   defensible resolution (last-writer-wins would depend on directory walk
///   order), so it is an error naming both fragments.
///
/// Returns `None` when there were no fragments at all — distinct from
/// `Some(default)`, which would mean "a mesh document was authored and it
/// happens to be empty".
pub fn merge_mesh_fragments(
    fragments: Vec<(String, MeshConfigSpec)>,
) -> crate::error::Result<Option<MeshConfigSpec>> {
    if fragments.is_empty() {
        return Ok(None);
    }

    let mut merged = MeshConfigSpec::default();
    // Remembers which fragment last set each singleton, so a conflict error
    // can name both sides instead of just the loser.
    let mut singleton_origin: HashMap<&'static str, String> = HashMap::new();
    // Same, for the identified collections (`workloads`, `services`), keyed by
    // `<field>/<identity>`.
    let mut entry_origin: HashMap<String, String> = HashMap::new();

    for (origin, fragment) in fragments {
        let MeshConfigSpec {
            istio_root_namespace,
            workloads,
            services,
            mesh_policies,
            ext_authz_providers,
            peer_authentications,
            service_entries,
            request_authentications,
            telemetry_resources,
            destination_rules,
            virtual_service_cors_policies,
            proxy_configs,
            sidecars,
            waypoint_bindings,
            trust_bundles,
            multi_cluster,
            outbound_traffic_policy,
            extension_configs,
        } = fragment;

        // `workloads` and `services` have mesh-wide primary keys, so two
        // fragments defining the same one is an authoring conflict rather than
        // a longer list — see `merge_mesh_identified_collection`.
        merge_mesh_identified_collection(
            "workloads",
            &mut merged.workloads,
            workloads,
            ArrayIdentity::MeshWorkloadSpiffeId,
            &origin,
            &mut entry_origin,
        )?;
        merge_mesh_identified_collection(
            "services",
            &mut merged.services,
            services,
            ArrayIdentity::MeshServiceNameNamespace,
            &origin,
            &mut entry_origin,
        )?;
        merged.mesh_policies.extend(mesh_policies);
        merged.ext_authz_providers.extend(ext_authz_providers);
        merged.peer_authentications.extend(peer_authentications);
        merged.service_entries.extend(service_entries);
        merged
            .request_authentications
            .extend(request_authentications);
        merged.telemetry_resources.extend(telemetry_resources);
        merged.destination_rules.extend(destination_rules);
        merged
            .virtual_service_cors_policies
            .extend(virtual_service_cors_policies);
        merged.proxy_configs.extend(proxy_configs);
        merged.sidecars.extend(sidecars);
        merged.waypoint_bindings.extend(waypoint_bindings);
        merged.extension_configs.extend(extension_configs);

        merge_mesh_singleton(
            "istio_root_namespace",
            &mut merged.istio_root_namespace,
            istio_root_namespace,
            &origin,
            &mut singleton_origin,
        )?;
        merge_mesh_singleton(
            "trust_bundles",
            &mut merged.trust_bundles,
            trust_bundles,
            &origin,
            &mut singleton_origin,
        )?;
        merge_mesh_singleton(
            "multi_cluster",
            &mut merged.multi_cluster,
            multi_cluster,
            &origin,
            &mut singleton_origin,
        )?;
        merge_mesh_singleton(
            "outbound_traffic_policy",
            &mut merged.outbound_traffic_policy,
            outbound_traffic_policy,
            &origin,
            &mut singleton_origin,
        )?;
    }

    Ok(Some(merged))
}

/// Concatenate one mesh collection whose entries carry a mesh-wide identity,
/// rejecting two fragments that define the *same* identity differently.
///
/// The identity rules are the overlay rules ([`array_merge_identity`]):
/// workloads are keyed by `spiffe_id`, services by `(name, namespace)`. Those
/// are the mesh's own primary keys — a workload's SPIFFE ID is how every
/// policy, waypoint binding and authorization rule refers to it — so a merged
/// document holding two different entries under one key has no defensible
/// reading. Which one wins would depend on directory walk order, exactly the
/// reason [`merge_mesh_singleton`] refuses conflicting scalars.
///
/// Three cases:
///
/// * **New identity** — appended, and the fragment is remembered so a later
///   conflict can name both sides.
/// * **Same identity, deep-equal entry** — the fragments agree. Deduplicated
///   silently: shared boilerplate copied into two fragments is harmless, and
///   emitting the entry twice would be a document the gateway then has to
///   reconcile.
/// * **Same identity, different entry** — `Error::Config` naming the identity
///   and both fragments.
///
/// Entries with no readable identity (a workload with no `spiffe_id`, a
/// service missing `name` or `namespace`) are appended unchecked;
/// `ferrum-edge validate -m mesh` is the authority on required fields and
/// reports them far better than a merge-time guess could.
///
/// Every other mesh collection stays a plain concatenation: `mesh_policies`,
/// `peer_authentications`, `service_entries`, `destination_rules`, `sidecars`
/// and friends are lists of rules, where two entries that look similar are two
/// rules and both apply.
fn merge_mesh_identified_collection(
    field: &'static str,
    merged: &mut Vec<serde_json::Value>,
    incoming: Vec<serde_json::Value>,
    identity: ArrayIdentity,
    origin: &str,
    origins: &mut HashMap<String, String>,
) -> crate::error::Result<()> {
    for item in incoming {
        let Some(item_identity) = array_item_identity(&item, identity) else {
            merged.push(item);
            continue;
        };

        let existing = merged.iter().find(|candidate| {
            array_item_identity(candidate, identity).as_ref() == Some(&item_identity)
        });

        match existing {
            Some(existing) if *existing == item => continue,
            Some(_) => {
                let previous = origins
                    .get(&format!("{field}/{item_identity}"))
                    .cloned()
                    .unwrap_or_else(|| "<unknown>".to_string());
                return Err(crate::error::Error::Config(format!(
                    "conflicting mesh `{field}` entry {item_identity}: fragment {previous} and \
                     fragment {origin} both define it, with different contents. Mesh {field} are \
                     keyed by {}, so only one definition can apply — merge them into a single \
                     fragment, or give the entries distinct identities.",
                    identity_key_description(identity)
                )));
            }
            None => {
                origins.insert(format!("{field}/{item_identity}"), origin.to_string());
                merged.push(item);
            }
        }
    }
    Ok(())
}

/// Human-readable name of the fields an [`ArrayIdentity`] is built from, for
/// conflict messages.
fn identity_key_description(identity: ArrayIdentity) -> &'static str {
    match identity {
        ArrayIdentity::MeshWorkloadSpiffeId => "spiffe_id",
        ArrayIdentity::MeshServiceNameNamespace => "(name, namespace)",
        ArrayIdentity::Generic => "id / name",
    }
}

fn merge_mesh_singleton<T: PartialEq + std::fmt::Debug>(
    field: &'static str,
    slot: &mut Option<T>,
    incoming: Option<T>,
    origin: &str,
    origins: &mut HashMap<&'static str, String>,
) -> crate::error::Result<()> {
    let Some(incoming) = incoming else {
        return Ok(());
    };

    match slot {
        Some(existing) if *existing != incoming => {
            let previous = origins
                .get(field)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            Err(crate::error::Error::Config(format!(
                "conflicting mesh `{field}`: fragment {previous} sets {existing:?} but fragment \
                 {origin} sets {incoming:?}. A mesh document has exactly one value for this \
                 field — set it in one fragment, or make both fragments agree."
            )))
        }
        Some(_) => Ok(()),
        None => {
            *slot = Some(incoming);
            origins.insert(field, origin.to_string());
            Ok(())
        }
    }
}

/// Canonicalize every consumer credential to ferrum-edge's array-of-entries
/// form: `keyauth: {key: K}` becomes `keyauth: [{key: K}]`.
///
/// ferrum-edge stores each credential type as an **array**. A bare object is
/// tolerated by admin-API writes (normalized server-side), but `GET /backup`
/// always returns the array form — so a repo YAML written in the object form
/// diffs as modified against the live gateway on every single run, forever,
/// and `drift-check --exit-on-drift` never goes green. Normalizing here, once,
/// before anything diffs, hashes, or serializes, means the desired config and
/// the gateway's own representation agree.
///
/// Applied to **all** credential keys, recognized (`basicauth`, `keyauth`,
/// `jwt`, `hmac_auth`, `mtls_auth`) or not: the gateway normalizes every entry
/// in the map on write, so limiting this to the known five would leave custom
/// types drifting for exactly the same reason.
///
/// Only objects are wrapped. Arrays are already canonical (this function is
/// idempotent), and scalars are left alone — wrapping a string would change
/// its meaning, and ferrum-edge rejects that shape anyway with a better
/// message than gitforgeops could produce.
///
/// # Slot stability
///
/// This runs before `secrets::resolve_secrets` walks the credential tree, so
/// placeholders are now one array level deeper than they used to be. Slot
/// names are unaffected: the walker elides array index 0, so
/// `keyauth: {key: "${…}"}` and `keyauth: [{key: "${…}"}]` both derive
/// `<ns>/<id>/keyauth/key`. Existing allocations therefore survive the
/// upgrade instead of orphaning and regenerating. See
/// `secrets::resolver::is_elided`.
///
/// # Round-trip hazard
///
/// Omitting `keyauth`, `jwt`, `hmac_auth` or `mtls_auth` from a consumer
/// **deletes** those entries on the gateway; omitting `basicauth` or an
/// unrecognized type **preserves** what is already stored. Normalization does
/// not change which keys are present, so it cannot itself delete anything —
/// but it is worth knowing that an empty array (`keyauth: []`) is the
/// explicit "remove these" spelling, not a no-op.
pub fn normalize_consumer_credentials(config: &mut GatewayConfig) {
    for consumer in config.consumers.iter_mut() {
        for value in consumer.credentials.values_mut() {
            if value.is_object() {
                let entry = std::mem::replace(value, serde_json::Value::Null);
                *value = serde_json::Value::Array(vec![entry]);
            }
        }
    }
}

/// Resolve every HTTP-family proxy's `backend_scheme` to the value the gateway
/// will store for it.
///
/// ferrum-edge canonicalizes the field on write:
/// `Proxy::resolve_dispatch_kind_fields` (`src/config/types.rs`) sets
/// `backend_scheme = Some(effective_scheme())` for every **non-stream** proxy,
/// and the DB column defaults to `https` besides. So a proxy that omits the
/// field in the repo comes back from `GET /backup` as `backend_scheme: https`.
/// Without normalizing here, `compare_fields` sees desired `null` versus live
/// `"https"` and reports a Modify on every run, and `breaking.rs` reports
/// "backend_scheme changed" on every PR that touches such a proxy — drift and a
/// breaking-change banner that no edit can clear.
///
/// **Stream proxies are deliberately left alone.** The gateway does *not*
/// default a stream proxy's scheme (its `effective_scheme` returns a `tcp`
/// sentinel that is never dispatched on); it rejects the config in validation
/// instead. Inventing `tcp` here would convert a clear "stream proxy is missing
/// backend_scheme" validation error into a silently-wrong `tcp` proxy that may
/// have meant `tcps` or `udp`. The stream discriminator is `listen_port`, the
/// same one the gateway uses.
///
/// Idempotent: a proxy that already names a scheme keeps it, whatever it is.
pub fn normalize_proxy_backend_schemes(config: &mut GatewayConfig) {
    for proxy in config.proxies.iter_mut() {
        if proxy.backend_scheme.is_none() && !crate::plugin_catalog::is_stream_proxy(proxy) {
            proxy.backend_scheme = Some(BackendScheme::Https);
        }
    }
}

/// Deep-merge overlay resources into the base set by matching on resource
/// kind, effective namespace, and `id`.
///
/// Overlay files are **partial** — they only contain the fields to override,
/// not all required fields. This function parses them as raw YAML values
/// (not typed `Resource` structs) and merges into the base resource's JSON
/// representation. Arrays replace the base value by default so overlays can
/// narrow restrictive lists. A short, kind-specific list of arrays is
/// *additive* instead, merging by item identity — see
/// [`array_merge_identity`].
///
/// Mesh fragments participate on the same terms as the gateway kinds. They
/// match on `(namespace, "MeshConfig", fragment id)`, where the fragment id
/// defaults to the file stem on both sides, so
/// `overlays/<env>/<ns>/mesh/core.yaml` deep-merges onto
/// `resources/<ns>/mesh/core.yaml`.
pub fn apply_overlay(
    base: &mut [(String, Resource)],
    overlay_dir: &Path,
) -> crate::error::Result<()> {
    if !overlay_dir.is_dir() {
        return Ok(());
    }

    let mut base_index = HashMap::new();
    for (idx, (base_ns, base_res)) in base.iter().enumerate() {
        let key = resource_key(base_ns, base_res);
        if let Some(previous) = base_index.insert(key.clone(), idx) {
            return Err(crate::error::Error::Config(format!(
                "duplicate base resource key for overlay lookup: {}/{}/{} at indexes {} and {}",
                key.namespace, key.kind, key.id, previous, idx
            )));
        }
    }

    let overlay_fragments = load_overlay_fragments(overlay_dir)?;

    for overlay in overlay_fragments {
        let overlay_id = overlay_fragment_id(&overlay);

        if overlay_id.is_empty() {
            continue;
        }

        // A mesh fragment's namespace is its directory, full stop — there is
        // no `spec.namespace` to consult (the namespaces inside a mesh
        // document belong to its individual workloads and services).
        let overlay_ns = if overlay.kind == "MeshConfig" {
            overlay.namespace.clone()
        } else {
            overlay_effective_namespace(&overlay.value, &overlay.namespace)
        };
        let overlay_key = ResourceKey {
            kind: overlay.kind,
            namespace: overlay_ns,
            id: overlay_id,
        };

        match base_index
            .get(&overlay_key)
            .copied()
            .map(|idx| &mut base[idx])
        {
            Some((ref mut base_ns, ref mut base_resource)) => {
                let base_value = serde_json::to_value(&*base_resource)?;
                let merged =
                    deep_merge_values(base_value, overlay.value, &mut Vec::new(), overlay.kind);
                *base_resource = serde_json::from_value(merged)?;

                if *base_ns == "ferrum" && overlay_key.namespace != "ferrum" {
                    *base_ns = overlay_key.namespace;
                }
            }
            None => {
                return Err(crate::error::Error::OrphanOverlay {
                    id: format!(
                        "{}/{}/{}",
                        overlay_key.namespace, overlay_key.kind, overlay_key.id
                    ),
                    path: overlay_dir.to_path_buf(),
                });
            }
        }
    }

    Ok(())
}

/// Load overlay files as raw JSON values (not typed structs).
/// Overlay files are partial and may lack required fields.
struct OverlayFragment {
    namespace: String,
    kind: &'static str,
    /// File stem, used as the fragment id for kinds whose documents carry no
    /// `spec.id` (mesh).
    stem: String,
    value: serde_json::Value,
}

/// Identity an overlay fragment targets.
///
/// Gateway kinds address a resource by `spec.id`. Mesh fragments have no id
/// in the mesh schema, so they use the gitforgeops-side fragment name:
/// explicit top-level `id`, else the file stem — matching what
/// `loader::load_resources` stamps onto the base fragment.
fn overlay_fragment_id(overlay: &OverlayFragment) -> String {
    if overlay.kind == "MeshConfig" {
        return overlay
            .value
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .unwrap_or(overlay.stem.as_str())
            .to_string();
    }

    overlay
        .value
        .get("spec")
        .and_then(|s| s.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn load_overlay_fragments(overlay_dir: &Path) -> crate::error::Result<Vec<OverlayFragment>> {
    let mut results = Vec::new();

    let namespace_entries =
        std::fs::read_dir(overlay_dir).map_err(|source| crate::error::Error::FileRead {
            path: overlay_dir.to_path_buf(),
            source,
        })?;

    for ns_entry in namespace_entries {
        let ns_entry = ns_entry.map_err(|source| crate::error::Error::FileRead {
            path: overlay_dir.to_path_buf(),
            source,
        })?;

        let ns_path = ns_entry.path();
        if !ns_path.is_dir() {
            continue;
        }

        let namespace = ns_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ferrum")
            .to_string();

        for (subdir, kind) in [
            ("proxies", "Proxy"),
            ("consumers", "Consumer"),
            ("upstreams", "Upstream"),
            ("plugins", "PluginConfig"),
            ("mesh", "MeshConfig"),
        ] {
            let subdir_path = ns_path.join(subdir);
            if !subdir_path.is_dir() {
                continue;
            }

            for entry in WalkDir::new(&subdir_path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext != "yaml" && ext != "yml" {
                    continue;
                }
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if file_name.starts_with('_') {
                    continue;
                }

                let contents = std::fs::read_to_string(path).map_err(|source| {
                    crate::error::Error::FileRead {
                        path: path.to_path_buf(),
                        source,
                    }
                })?;

                // Parse as raw YAML then convert to JSON Value
                let yaml_value: serde_yaml::Value =
                    serde_yaml::from_str(&contents).map_err(|source| {
                        crate::error::Error::YamlParse {
                            path: path.to_path_buf(),
                            source,
                        }
                    })?;
                let json_value: serde_json::Value =
                    serde_json::to_value(yaml_value).map_err(crate::error::Error::SerdeJson)?;
                if let Some(declared_kind) = json_value.get("kind").and_then(|v| v.as_str()) {
                    if declared_kind != kind {
                        return Err(crate::error::Error::Config(format!(
                            "overlay file {} declares kind {declared_kind:?} but is under {subdir}/ ({kind})",
                            path.display()
                        )));
                    }
                }

                results.push(OverlayFragment {
                    namespace: namespace.clone(),
                    kind,
                    stem: path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .unwrap_or_default()
                        .to_string(),
                    value: json_value,
                });
            }
        }
    }

    Ok(results)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ResourceKey {
    kind: &'static str,
    namespace: String,
    id: String,
}

fn resource_key(directory_namespace: &str, resource: &Resource) -> ResourceKey {
    match resource {
        Resource::Proxy { spec } => ResourceKey {
            kind: "Proxy",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        Resource::Consumer { spec } => ResourceKey {
            kind: "Consumer",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        Resource::Upstream { spec } => ResourceKey {
            kind: "Upstream",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        Resource::PluginConfig { spec } => ResourceKey {
            kind: "PluginConfig",
            namespace: effective_namespace(directory_namespace, &spec.namespace),
            id: spec.id.clone(),
        },
        // Mesh fragments key on the directory namespace and the fragment name
        // (file stem unless the file declares an `id`). There is no
        // `spec.namespace` to override with: the namespaces in a mesh
        // document belong to its individual entries, not the document.
        Resource::MeshConfig { id, .. } => ResourceKey {
            kind: "MeshConfig",
            namespace: directory_namespace.to_string(),
            id: id.clone().unwrap_or_default(),
        },
    }
}

fn effective_namespace(directory_namespace: &str, spec_namespace: &str) -> String {
    if spec_namespace == "ferrum" {
        directory_namespace.to_string()
    } else {
        spec_namespace.to_string()
    }
}

fn overlay_effective_namespace(value: &serde_json::Value, directory_namespace: &str) -> String {
    value
        .get("spec")
        .and_then(|s| s.get("namespace"))
        .and_then(|v| v.as_str())
        .map(|ns| effective_namespace(directory_namespace, ns))
        .unwrap_or_else(|| directory_namespace.to_string())
}

fn deep_merge_values(
    base: serde_json::Value,
    overlay: serde_json::Value,
    path: &mut Vec<String>,
    kind: &'static str,
) -> serde_json::Value {
    use serde_json::Value;

    match (base, overlay) {
        (Value::Object(mut base_map), Value::Object(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                path.push(key.clone());
                let merged = if let Some(base_val) = base_map.remove(&key) {
                    deep_merge_values(base_val, overlay_val, path, kind)
                } else {
                    overlay_val
                };
                path.pop();
                base_map.insert(key, merged);
            }
            Value::Object(base_map)
        }
        (Value::Array(base_items), Value::Array(overlay_items)) => {
            match array_merge_identity(path, kind) {
                Some(identity) => merge_array_values(base_items, overlay_items, identity, kind),
                None => Value::Array(overlay_items),
            }
        }
        (_, overlay) => overlay,
    }
}

/// How an item inside an additive array is identified for merge purposes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ArrayIdentity {
    /// `id` / `plugin_config_id` / `name`, else `host:port:path` — covers
    /// `Proxy.spec.plugins` and `Upstream.spec.targets`.
    Generic,
    /// A mesh `Workload`, identified by its SPIFFE ID — the mesh's own
    /// primary key for a workload.
    MeshWorkloadSpiffeId,
    /// A mesh `MeshService`, identified by `(name, namespace)`. Name alone is
    /// not enough: the same service name legitimately exists in several mesh
    /// namespaces, and collapsing them would let a `staging` overlay silently
    /// rewrite the `prod` namespace's service.
    MeshServiceNameNamespace,
}

/// Decide whether an array at `path` (within a resource of `kind`) merges by
/// item identity instead of being replaced wholesale.
///
/// **Replace is the default and stays the default.** An overlay that sets a
/// list is usually narrowing it (allow-lists, CORS origins, retryable status
/// codes), and additive semantics would make narrowing impossible to express.
/// Only lists where an environment overlay plausibly wants to *add a member
/// or tweak one member's fields* are additive:
///
/// | kind | path | identity |
/// |---|---|---|
/// | Proxy | `spec.plugins` | `plugin_config_id` |
/// | Upstream | `spec.targets` | `host:port:path` |
/// | MeshConfig | `spec.workloads` | `spiffe_id` |
/// | MeshConfig | `spec.services` | `(name, namespace)` |
///
/// Every other mesh array (`mesh_policies`, `peer_authentications`,
/// `service_entries`, `destination_rules`, `sidecars`, ...) keeps replace
/// semantics: those are security- and routing-relevant policy lists where an
/// overlay saying "these are the peer authentications for staging" must mean
/// exactly that, not "these plus whatever the base declared".
fn array_merge_identity(path: &[String], kind: &'static str) -> Option<ArrayIdentity> {
    let [spec, field] = path else {
        return None;
    };
    if spec != "spec" {
        return None;
    }

    match (kind, field.as_str()) {
        ("MeshConfig", "workloads") => Some(ArrayIdentity::MeshWorkloadSpiffeId),
        ("MeshConfig", "services") => Some(ArrayIdentity::MeshServiceNameNamespace),
        ("MeshConfig", _) => None,
        (_, "plugins") | (_, "targets") => Some(ArrayIdentity::Generic),
        _ => None,
    }
}

fn merge_array_values(
    mut base_items: Vec<serde_json::Value>,
    overlay_items: Vec<serde_json::Value>,
    identity: ArrayIdentity,
    kind: &'static str,
) -> serde_json::Value {
    for overlay_item in overlay_items {
        if let Some(overlay_identity) = array_item_identity(&overlay_item, identity) {
            if let Some(position) = base_items.iter().position(|item| {
                array_item_identity(item, identity).as_ref() == Some(&overlay_identity)
            }) {
                let base_item =
                    std::mem::replace(&mut base_items[position], serde_json::Value::Null);
                base_items[position] =
                    deep_merge_values(base_item, overlay_item, &mut Vec::new(), kind);
            } else {
                base_items.push(overlay_item);
            }
        } else if !base_items.iter().any(|item| item == &overlay_item) {
            base_items.push(overlay_item);
        }
    }

    serde_json::Value::Array(base_items)
}

fn array_item_identity(value: &serde_json::Value, identity: ArrayIdentity) -> Option<String> {
    let map = value.as_object()?;

    match identity {
        ArrayIdentity::MeshWorkloadSpiffeId => map
            .get("spiffe_id")
            .and_then(|value| value.as_str())
            .map(|spiffe_id| format!("spiffe_id:{spiffe_id}")),
        ArrayIdentity::MeshServiceNameNamespace => {
            let name = map.get("name").and_then(|value| value.as_str())?;
            // A mesh service without an explicit namespace is not the same
            // service as one in `ferrum` — ferrum-edge resolves that default
            // itself, and guessing it here could merge two distinct entries.
            let namespace = map.get("namespace").and_then(|value| value.as_str())?;
            Some(format!("service:{namespace}/{name}"))
        }
        ArrayIdentity::Generic => {
            for key in ["id", "plugin_config_id", "name"] {
                if let Some(value) = map.get(key).and_then(|value| value.as_str()) {
                    return Some(format!("{key}:{value}"));
                }
            }

            if let (Some(host), Some(port)) = (
                map.get("host").and_then(|value| value.as_str()),
                map.get("port"),
            ) {
                let path = map
                    .get("path")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                return Some(format!("target:{host}:{port}:{path}"));
            }

            None
        }
    }
}
