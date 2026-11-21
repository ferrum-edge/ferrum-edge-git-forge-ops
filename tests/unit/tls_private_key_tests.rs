//! GHSA-57w7-mmcc-j8gg: inline PEM private keys in TLS fields.
//!
//! Ferrum Edge reads a TLS source field as inline PEM when it starts with
//! `-----BEGIN `, so Proxy and Upstream `backend_tls_client_key_path`,
//! `udp_logging` `dtls_key_path` and certificate fields holding a
//! certificate-plus-key bundle can carry a private key. Each boundary is
//! checked here: import (with the migration bundle), resolution, the
//! literal-secret gate, validator stand-ins, the scrubber, diff masking and
//! review-comment scrubbing. A filesystem path stays literal throughout.
//!
//! No test uses real key material. [`synthetic_key`] wraps the base64 of a
//! readable canary in private-key armour: the shared detector reads only the
//! armour (as Edge's does), and every redaction assertion checks that the
//! encoded canary never escapes.

use std::collections::BTreeMap;

use base64::Engine;
use gitforgeops::config::schema::GatewayConfig;
use gitforgeops::diff::security::{audit_security, security_blockers};
use gitforgeops::secrets::{CredentialBundle, SlotStatus};

const PLACEHOLDER: &str = "${gh-env-secret:alloc=require}";
const KEY_PATH: &str = "/etc/ferrum/tls/client.key";
const CERT_PATH: &str = "/etc/ferrum/tls/client.crt";
const PROXY_SLOT: &str = "ferrum/edge/@proxy/backend_tls_client_key_path";
const UPSTREAM_SLOT: &str = "ferrum/edge/@upstream/backend_tls_client_key_path";

/// The base64 body of [`synthetic_key`] for `canary`.
fn body(canary: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(canary)
}

/// Private-key armour around a synthetic body (see the module docs).
fn synthetic_key(canary: &str) -> String {
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        body(canary)
    )
}

/// Certificate armour around a synthetic body: public material.
fn synthetic_cert(canary: &str) -> String {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        body(canary)
    )
}

fn proxy(fields: serde_json::Value) -> serde_json::Value {
    let mut proxy = serde_json::json!({
        "id": "edge",
        "namespace": "ferrum",
        "listen_path": "/edge",
        "backend_scheme": "https",
        "backend_host": "backend.internal",
        "backend_port": 443
    });
    merge(&mut proxy, fields);
    proxy
}

fn upstream(fields: serde_json::Value) -> serde_json::Value {
    let mut upstream = serde_json::json!({
        "id": "edge",
        "namespace": "ferrum",
        "targets": [{"host": "backend.internal", "port": 443}]
    });
    merge(&mut upstream, fields);
    upstream
}

fn plugin(plugin_name: &str, config: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": "edge-plugin",
        "namespace": "ferrum",
        "plugin_name": plugin_name,
        "scope": "global",
        "config": config
    })
}

fn merge(base: &mut serde_json::Value, fields: serde_json::Value) {
    if let (Some(base), serde_json::Value::Object(fields)) = (base.as_object_mut(), fields) {
        base.extend(fields);
    }
}

fn gateway(document: serde_json::Value) -> GatewayConfig {
    serde_json::from_value(document).unwrap()
}

/// One row per place a private key can sit: the document, the canary, and
/// the broker slot import captures it under (`None`: import refuses it).
fn private_key_sites() -> Vec<(
    &'static str,
    GatewayConfig,
    &'static str,
    Option<&'static str>,
)> {
    vec![
        (
            "proxy client key",
            gateway(serde_json::json!({"proxies": [proxy(serde_json::json!({
                "backend_tls_client_cert_path": CERT_PATH,
                "backend_tls_client_key_path": synthetic_key("zq7-proxy-client-key"),
            }))]})),
            "zq7-proxy-client-key",
            Some(PROXY_SLOT),
        ),
        (
            "upstream client key",
            gateway(serde_json::json!({"upstreams": [upstream(serde_json::json!({
                "backend_tls_client_cert_path": synthetic_cert("public-upstream-cert"),
                "backend_tls_client_key_path": synthetic_key("zq7-upstream-client-key"),
            }))]})),
            "zq7-upstream-client-key",
            Some(UPSTREAM_SLOT),
        ),
        (
            "udp_logging dtls key",
            gateway(serde_json::json!({"plugin_configs": [plugin("udp_logging", serde_json::json!({
                "host": "logs.internal",
                "port": 5514,
                "dtls": true,
                "dtls_cert_path": CERT_PATH,
                "dtls_key_path": synthetic_key("zq7-dtls-client-key"),
            }))]})),
            "zq7-dtls-client-key",
            Some("ferrum/edge-plugin/@plugin/udp_logging/config/dtls_key_path"),
        ),
        (
            "mesh_route_dispatch backend tls key",
            gateway(serde_json::json!({"plugin_configs": [plugin("mesh_route_dispatch", serde_json::json!({
                "rules": [{"destination": {"backend_tls": {
                    "client_cert_path": CERT_PATH,
                    "client_key_path": synthetic_key("zq7-dispatch-client-key"),
                }}}]
            }))]})),
            "zq7-dispatch-client-key",
            Some(
                "ferrum/edge-plugin/@plugin/mesh_route_dispatch/config/rules/[0]/destination/backend_tls/client_key_path",
            ),
        ),
        (
            "proxy cert+key bundle",
            gateway(serde_json::json!({"proxies": [proxy(serde_json::json!({
                "backend_tls_client_cert_path": format!(
                    "{}{}",
                    synthetic_cert("public-proxy-cert"),
                    synthetic_key("zq7-proxy-bundled-key")
                ),
                "backend_tls_client_key_path": KEY_PATH,
            }))]})),
            "zq7-proxy-bundled-key",
            None,
        ),
        (
            "upstream CA field carrying a key",
            gateway(serde_json::json!({"upstreams": [upstream(serde_json::json!({
                "backend_tls_server_ca_cert_path": format!(
                    "{}{}",
                    synthetic_cert("public-upstream-ca"),
                    synthetic_key("zq7-upstream-ca-key")
                ),
            }))]})),
            "zq7-upstream-ca-key",
            None,
        ),
        (
            "udp_logging cert+key bundle",
            gateway(serde_json::json!({"plugin_configs": [plugin("udp_logging", serde_json::json!({
                "host": "logs.internal",
                "port": 5514,
                "dtls": true,
                "dtls_cert_path": format!(
                    "{}{}",
                    synthetic_cert("public-dtls-cert"),
                    synthetic_key("zq7-dtls-bundled-key")
                ),
                "dtls_key_path": KEY_PATH,
            }))]})),
            "zq7-dtls-bundled-key",
            None,
        ),
        (
            "custom plugin string holding a bare key",
            gateway(serde_json::json!({"plugin_configs": [plugin("acme_custom_tls", serde_json::json!({
                "material": synthetic_key("zq7-custom-plugin-key"),
            }))]})),
            "zq7-custom-plugin-key",
            Some("ferrum/edge-plugin/@plugin/acme_custom_tls/config/material"),
        ),
        (
            "builtin credential field holding a key",
            gateway(serde_json::json!({"plugin_configs": [plugin("ai_federation", serde_json::json!({
                "google_service_account_json": format!(
                    "{{\"client_email\": \"svc@example.invalid\", \"private_key\": {:?}}}",
                    synthetic_key("zq7-service-account-key")
                ),
            }))]})),
            "zq7-service-account-key",
            Some("ferrum/edge-plugin/@plugin/ai_federation/config/google_service_account_json"),
        ),
        (
            "udp_logging malformed dtls key",
            gateway(serde_json::json!({"plugin_configs": [plugin("udp_logging", serde_json::json!({
                "host": "logs.internal",
                "port": 5514,
                "dtls": true,
                "dtls_cert_path": CERT_PATH,
                "dtls_key_path": format!(
                    "-----BEGIN EC PARAMETERS-----\n{}\n-----END EC PARAMETERS-----\n",
                    body("zq7-dtls-malformed-key")
                ),
            }))]})),
            "zq7-dtls-malformed-key",
            Some("ferrum/edge-plugin/@plugin/udp_logging/config/dtls_key_path"),
        ),
        (
            "custom plugin cert+key bundle",
            gateway(serde_json::json!({"plugin_configs": [plugin("acme_custom_tls", serde_json::json!({
                "material": format!(
                    "{}{}",
                    synthetic_cert("public-custom-cert"),
                    synthetic_key("zq7-custom-bundled-key")
                ),
            }))]})),
            "zq7-custom-bundled-key",
            None,
        ),
        (
            "certificate field under a brokered parent",
            gateway(serde_json::json!({"plugin_configs": [plugin("acme_custom_tls", serde_json::json!({
                "credentials": {"client_certificate": format!(
                    "{}{}",
                    synthetic_cert("public-parent-cert"),
                    synthetic_key("zq7-parent-bundled-key")
                )},
            }))]})),
            "zq7-parent-bundled-key",
            None,
        ),
    ]
}

/// The same places holding a reference instead of material.
fn reference_only_gateway() -> GatewayConfig {
    gateway(serde_json::json!({
        "proxies": [proxy(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": KEY_PATH,
            "backend_tls_server_ca_cert_path": synthetic_cert("public-proxy-ca"),
        }))],
        "upstreams": [upstream(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": "vault://secret/tls#client.key",
        }))],
        "plugin_configs": [plugin("udp_logging", serde_json::json!({
            "host": "logs.internal",
            "port": 5514,
            "dtls": true,
            "dtls_cert_path": CERT_PATH,
            "dtls_key_path": KEY_PATH,
        }))]
    }))
}

fn capture_all(cfg: &mut GatewayConfig) -> gitforgeops::error::Result<CredentialBundle> {
    let mut captured = gitforgeops::secrets::capture_and_redact_import_backend_tls_keys(cfg)?;
    let plugins = gitforgeops::secrets::capture_and_redact_import_plugin_config_secrets(cfg)?;
    assert!(
        plugins.unbrokered.is_empty(),
        "a private key never needs a plaintext allowance: {:?}",
        plugins.unbrokered
    );
    captured.extend(plugins.captured);
    Ok(captured)
}

#[test]
fn import_capture_brokers_key_fields_and_refuses_keys_elsewhere() {
    for (name, mut cfg, canary, slot) in private_key_sites() {
        let result = capture_all(&mut cfg);
        match slot {
            Some(slot) => {
                let captured = result.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(
                    captured.keys().map(String::as_str).collect::<Vec<_>>(),
                    [slot],
                    "{name}"
                );
                assert!(captured[slot].contains(&body(canary)), "{name}");
                let written = serde_json::to_string(&cfg).unwrap();
                assert!(!written.contains(&body(canary)), "{name}: {written}");
                assert!(written.contains(PLACEHOLDER), "{name}");
            }
            None => {
                let message = result.expect_err(name).to_string();
                assert!(
                    message.contains("TLS private-key material"),
                    "{name}: {message}"
                );
                assert!(message.contains("Nothing has been written"), "{name}");
                assert!(!message.contains(&body(canary)), "{name}: {message}");
                assert!(!message.contains("BEGIN"), "{name}: {message}");
            }
        }
    }
}

#[test]
fn import_capture_keeps_paths_and_certificates_literal() {
    let mut cfg = reference_only_gateway();
    let before = serde_json::to_value(&cfg).unwrap();
    let captured = capture_all(&mut cfg).unwrap();
    assert!(captured.is_empty(), "{captured:?}");
    assert_eq!(serde_json::to_value(&cfg).unwrap(), before);
}

/// The CLI path end to end: the backup file goes in, the key lands in the
/// private migration bundle under its canonical slot, the resource tree
/// carries the placeholder and keeps the certificate and key paths, and the
/// tree resolves back to the original document from the bundle.
#[test]
fn file_import_moves_inline_keys_into_the_migration_bundle() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let proxy_key = synthetic_key("zq7-import-proxy-key");
    let dtls_key = synthetic_key("zq7-import-dtls-key").replace('\n', "\r\n");
    let original = gateway(serde_json::json!({
        "proxies": [proxy(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": proxy_key,
        }))],
        "upstreams": [upstream(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": KEY_PATH,
        }))],
        "plugin_configs": [plugin("udp_logging", serde_json::json!({
            "host": "logs.internal",
            "port": 5514,
            "dtls": true,
            "dtls_cert_path": CERT_PATH,
            "dtls_key_path": dtls_key,
        }))]
    }));
    std::fs::write(
        &backup_path,
        gitforgeops::yaml::to_string(&original).unwrap(),
    )
    .unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("migration.json");

    // Without a bundle path the import refuses before writing anything.
    let refused = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        None,
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("--credential-bundle-output"), "{refused}");
    assert!(!output.exists());

    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap();
    assert_eq!(result.redacted_backend_tls_key_values, 1);
    assert_eq!(result.redacted_plugin_config_values, 1);

    let raw_bundle = std::fs::read_to_string(&bundle_path).unwrap();
    let (merged, _) = gitforgeops::secrets::load_bundles_from_env(&raw_bundle).unwrap();
    assert_eq!(
        merged.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "ferrum/edge-plugin/@plugin/udp_logging/config/dtls_key_path",
            PROXY_SLOT
        ]
    );

    let proxy_yaml = std::fs::read_to_string(output.join("ferrum/proxies/edge.yaml")).unwrap();
    assert!(!proxy_yaml.contains("BEGIN"), "{proxy_yaml}");
    assert!(
        proxy_yaml.contains("backend_tls_client_key_path: ${gh-env-secret:alloc=require}"),
        "{proxy_yaml}"
    );
    assert!(proxy_yaml.contains(CERT_PATH), "{proxy_yaml}");
    let upstream_yaml = std::fs::read_to_string(output.join("ferrum/upstreams/edge.yaml")).unwrap();
    assert!(upstream_yaml.contains(KEY_PATH), "{upstream_yaml}");
    let plugin_yaml =
        std::fs::read_to_string(output.join("ferrum/plugins/edge-plugin.yaml")).unwrap();
    assert!(!plugin_yaml.contains("BEGIN"), "{plugin_yaml}");
    assert!(plugin_yaml.contains(CERT_PATH), "{plugin_yaml}");

    let resources = gitforgeops::config::load_resources(&output).unwrap();
    let mut assembled = gitforgeops::config::assemble(resources).unwrap().gateway;
    assert!(security_blockers(&audit_security(&assembled)).is_empty());
    let report = super::resolver_fixtures::resolve_secrets(&mut assembled, &merged).unwrap();
    assert!(report.unresolved().is_empty());
    assert_eq!(
        assembled.proxies[0].backend_tls_client_key_path,
        original.proxies[0].backend_tls_client_key_path
    );
    assert_eq!(
        assembled.plugin_configs[0].config["dtls_key_path"],
        original.plugin_configs[0].config["dtls_key_path"]
    );
    assert_eq!(
        assembled.upstreams[0]
            .backend_tls_client_key_path
            .as_deref(),
        Some(KEY_PATH)
    );
}

fn brokered_gateway(alloc: &str) -> GatewayConfig {
    let placeholder = format!("${{gh-env-secret:alloc={alloc}}}");
    gateway(serde_json::json!({
        "proxies": [proxy(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": placeholder,
        }))],
        "upstreams": [upstream(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": placeholder,
        }))],
        "plugin_configs": [plugin("udp_logging", serde_json::json!({
            "host": "logs.internal",
            "port": 5514,
            "dtls": true,
            "dtls_cert_path": CERT_PATH,
            "dtls_key_path": placeholder,
        }))]
    }))
}

const DTLS_SLOT: &str = "ferrum/edge-plugin/@plugin/udp_logging/config/dtls_key_path";

#[test]
fn brokered_keys_resolve_from_their_slots_and_fail_closed_without_them() {
    let bundle = BTreeMap::from([
        (PROXY_SLOT.to_string(), synthetic_key("zq7-seeded-proxy")),
        (
            UPSTREAM_SLOT.to_string(),
            synthetic_key("zq7-seeded-upstream"),
        ),
        (DTLS_SLOT.to_string(), synthetic_key("zq7-seeded-dtls")),
    ]);
    let mut resolved = brokered_gateway("require");
    let report = super::resolver_fixtures::resolve_secrets(&mut resolved, &bundle).unwrap();
    assert!(
        report.unresolved().is_empty(),
        "unexpected unresolved slots"
    );
    assert_eq!(
        resolved.proxies[0].backend_tls_client_key_path.as_deref(),
        Some(bundle[PROXY_SLOT].as_str())
    );
    assert_eq!(
        resolved.upstreams[0].backend_tls_client_key_path.as_deref(),
        Some(bundle[UPSTREAM_SLOT].as_str())
    );
    assert_eq!(
        resolved.plugin_configs[0].config["dtls_key_path"],
        bundle[DTLS_SLOT]
    );

    // Without the bundle every slot is a missing required value, the
    // placeholder stays, and the write path's last check names each slot.
    let mut unresolved = brokered_gateway("require");
    let report =
        super::resolver_fixtures::resolve_secrets(&mut unresolved, &CredentialBundle::new())
            .unwrap();
    let mut missing: Vec<&str> = report
        .missing_required()
        .iter()
        .map(|result| result.slot.as_str())
        .collect();
    missing.sort_unstable();
    assert_eq!(missing, [DTLS_SLOT, PROXY_SLOT, UPSTREAM_SLOT]);
    assert_eq!(
        unresolved.proxies[0].backend_tls_client_key_path.as_deref(),
        Some(PLACEHOLDER)
    );
    let mut slots = gitforgeops::secrets::unresolved_placeholder_slots(&unresolved).unwrap();
    slots.sort_unstable();
    assert_eq!(slots, [DTLS_SLOT, PROXY_SLOT, UPSTREAM_SLOT]);
}

#[test]
fn the_broker_never_generates_a_tls_private_key() {
    for alloc in ["generate", "rotate"] {
        let mut cfg = brokered_gateway(alloc);
        let error = super::resolver_fixtures::resolve_secrets(&mut cfg, &CredentialBundle::new())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("cannot generate a TLS private key"),
            "{alloc}: {error}"
        );
    }
    for slot in [PROXY_SLOT, UPSTREAM_SLOT, DTLS_SLOT] {
        let error = gitforgeops::secrets::resolver::check_generation_allowed(
            slot,
            None,
            32,
            &gitforgeops::config::GatewayMode::Api,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(slot), "{error}");
    }

    // A seeded slot resolves whatever the alloc mode says.
    let bundle = BTreeMap::from([
        (PROXY_SLOT.to_string(), synthetic_key("zq7-seeded-proxy")),
        (
            UPSTREAM_SLOT.to_string(),
            synthetic_key("zq7-seeded-upstream"),
        ),
        (DTLS_SLOT.to_string(), synthetic_key("zq7-seeded-dtls")),
    ]);
    let mut cfg = brokered_gateway("generate");
    let report = super::resolver_fixtures::resolve_secrets(&mut cfg, &bundle).unwrap();
    assert!(report
        .results
        .iter()
        .all(|result| result.status == SlotStatus::Resolved));
}

#[test]
fn literal_private_keys_are_apply_blockers_and_references_are_not() {
    for (name, cfg, canary, _) in private_key_sites() {
        let findings = audit_security(&cfg);
        let blockers = security_blockers(&findings);
        assert!(
            blockers
                .iter()
                .any(|finding| finding.message.contains("Literal TLS private key")),
            "{name}: {findings:?}"
        );
        for finding in &findings {
            assert!(!finding.message.contains(&body(canary)), "{name}");
            assert!(!finding.message.contains("BEGIN"), "{name}");
        }
    }

    for cfg in [reference_only_gateway(), brokered_gateway("require")] {
        let findings = audit_security(&cfg);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.message.contains("TLS private key")),
            "{findings:?}"
        );
    }
}

#[test]
fn scrubber_redacts_private_keys_in_every_line_ending_and_withholds_streams() {
    for (name, cfg, canary, _) in private_key_sites() {
        let scrubber = gitforgeops::secrets::SecretScrubber::from_gateway_config(&cfg);
        let key = synthetic_key(canary);
        // Each echo carries the key's encoded body: whole in either line
        // ending, or re-indented the way an emitter writes a block scalar.
        for echoed in [
            key.clone(),
            key.replace('\n', "\r\n"),
            format!("dtls_key_path: |\n    {}", body(canary)),
        ] {
            let scrubbed = scrubber.scrub(&format!("before {echoed} after"));
            assert!(!scrubbed.contains(&body(canary)), "{name}: {scrubbed}");
            assert!(scrubbed.contains("[REDACTED]"), "{name}: {scrubbed}");
        }
        // A PEM block is multi-line, so validator streams are withheld rather
        // than scrubbed in place.
        let output = scrubber.scrub_streams(&key, "");
        assert_eq!(
            output.suppressed,
            Some(gitforgeops::secrets::SuppressionReason::NotSafelyScrubbable),
            "{name}"
        );
        assert!(!output.stdout.contains(&body(canary)), "{name}");
    }

    // References register nothing.
    let scrubber =
        gitforgeops::secrets::SecretScrubber::from_gateway_config(&reference_only_gateway());
    assert!(scrubber.is_empty());
    assert_eq!(scrubber.scrub(KEY_PATH), KEY_PATH);
}

#[test]
fn scrubber_registers_resolved_keys_from_the_report() {
    // A seeded value that does not look like PEM is still a resolved secret.
    let bundle = BTreeMap::from([
        (
            PROXY_SLOT.to_string(),
            "zq7-seeded-opaque-proxy-key".to_string(),
        ),
        (
            UPSTREAM_SLOT.to_string(),
            synthetic_key("zq7-seeded-upstream"),
        ),
        (DTLS_SLOT.to_string(), synthetic_key("zq7-seeded-dtls")),
    ]);
    let mut resolved = brokered_gateway("require");
    let report = super::resolver_fixtures::resolve_secrets(&mut resolved, &bundle).unwrap();
    let scrubber =
        gitforgeops::secrets::SecretScrubber::from_gateway_config_with_report(&resolved, &report);
    for canary in ["zq7-seeded-upstream", "zq7-seeded-dtls"] {
        let scrubbed = scrubber.scrub(&synthetic_key(canary));
        assert!(!scrubbed.contains(&body(canary)), "{scrubbed}");
    }
    assert_eq!(
        scrubber.scrub("x zq7-seeded-opaque-proxy-key y"),
        "x [REDACTED] y"
    );
}

#[test]
fn validator_stand_ins_give_unresolved_keys_pem_shape_and_leave_paths_alone() {
    let cfg = brokered_gateway("require");
    let patched = gitforgeops::validate::with_validation_standins(&cfg).expect("stand-ins");
    let proxy_key = patched.proxies[0]
        .backend_tls_client_key_path
        .clone()
        .unwrap();
    let upstream_key = patched.upstreams[0]
        .backend_tls_client_key_path
        .clone()
        .unwrap();
    // Edge pairs the DTLS key with its certificate, which no stand-in can
    // satisfy: the copy omits the pair so the rest of the plugin validates.
    let dtls = patched.plugin_configs[0].config.as_object().unwrap();
    assert!(!dtls.contains_key("dtls_key_path"), "{dtls:?}");
    assert!(!dtls.contains_key("dtls_cert_path"), "{dtls:?}");
    assert_eq!(dtls["host"], "logs.internal");
    assert_eq!(dtls["dtls"], true);
    for (slot, key) in [(PROXY_SLOT, &proxy_key), (UPSTREAM_SLOT, &upstream_key)] {
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{key}");
        assert!(key.ends_with("-----END PRIVATE KEY-----\n"), "{key}");
        assert_eq!(
            *key,
            gitforgeops::validate::validation_private_key_standin(slot)
        );
        let encoded: String = key
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert!(decoded.starts_with(gitforgeops::validate::PEM_STANDIN_MARKER.as_bytes()));
    }
    assert_ne!(proxy_key, upstream_key, "stand-ins are distinct per slot");
    assert_eq!(
        patched.proxies[0].backend_tls_client_cert_path.as_deref(),
        Some(CERT_PATH)
    );
    // The original document keeps its placeholders.
    assert_eq!(
        cfg.proxies[0].backend_tls_client_key_path.as_deref(),
        Some(PLACEHOLDER)
    );

    assert!(gitforgeops::validate::with_validation_standins(&reference_only_gateway()).is_none());

    // A seeded DTLS key reaches the validator with its certificate; only an
    // unresolved one drops the pair.
    let bundle = BTreeMap::from([
        (PROXY_SLOT.to_string(), synthetic_key("zq7-seeded-proxy")),
        (
            UPSTREAM_SLOT.to_string(),
            synthetic_key("zq7-seeded-upstream"),
        ),
        (DTLS_SLOT.to_string(), synthetic_key("zq7-seeded-dtls")),
    ]);
    let mut resolved = brokered_gateway("require");
    super::resolver_fixtures::resolve_secrets(&mut resolved, &bundle).unwrap();
    assert!(gitforgeops::validate::with_validation_standins(&resolved).is_none());
    assert_eq!(
        resolved.plugin_configs[0].config["dtls_cert_path"],
        CERT_PATH
    );

    // A mesh_route_dispatch backend key is not paired: it gets the PEM
    // stand-in in place.
    let dispatch = gateway(
        serde_json::json!({"plugin_configs": [plugin("mesh_route_dispatch",
        serde_json::json!({"rules": [{"destination": {"backend_tls": {
            "client_cert_path": CERT_PATH,
            "client_key_path": PLACEHOLDER,
        }}}]}))]}),
    );
    let patched = gitforgeops::validate::with_validation_standins(&dispatch).unwrap();
    let tls = &patched.plugin_configs[0].config["rules"][0]["destination"]["backend_tls"];
    assert_eq!(tls["client_cert_path"], CERT_PATH);
    assert!(tls["client_key_path"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PRIVATE KEY-----\n"));
}

/// A map entry merely named like a key field (an `http_logging` header called
/// `private_key`) keeps its ordinary behaviour: the opaque stand-in and
/// ordinary generation rules. Only schema key sources are TLS keys.
#[test]
fn leaf_names_alone_do_not_make_a_tls_key_source() {
    let header = gateway(
        serde_json::json!({"plugin_configs": [plugin("http_logging", serde_json::json!({
            "endpoint_url": "https://collector.example/logs",
            "custom_headers": {"private_key": PLACEHOLDER},
        }))]}),
    );
    let patched = gitforgeops::validate::with_validation_standins(&header).unwrap();
    let stand_in = patched.plugin_configs[0].config["custom_headers"]["private_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        stand_in.starts_with(gitforgeops::validate::VALIDATION_STANDIN_PREFIX),
        "{stand_in}"
    );
    gitforgeops::secrets::resolver::check_generation_allowed(
        "ferrum/edge-plugin/@plugin/http_logging/config/custom_headers/private_key",
        None,
        32,
        &gitforgeops::config::GatewayMode::Api,
    )
    .unwrap();
    // The same leaf name at a real key source is refused.
    gitforgeops::secrets::resolver::check_generation_allowed(
        "ferrum/edge-plugin/@plugin/mesh_route_dispatch/config/rules/[0]/destination/backend_tls/client_key_path",
        None,
        32,
        &gitforgeops::config::GatewayMode::Api,
    )
    .unwrap_err();
}

/// A backup read through a redacting endpoint carries `[REDACTED]` where Edge
/// withheld TLS material. Import refuses it, as for every other secret, rather
/// than committing the sentinel.
#[test]
fn import_refuses_redacted_tls_material() {
    for cfg in [
        gateway(serde_json::json!({"proxies": [proxy(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": "[REDACTED]",
        }))]})),
        gateway(
            serde_json::json!({"upstreams": [upstream(serde_json::json!({
                "backend_tls_client_cert_path": "[REDACTED]",
                "backend_tls_client_key_path": KEY_PATH,
            }))]}),
        ),
        gateway(
            serde_json::json!({"plugin_configs": [plugin("udp_logging", serde_json::json!({
                "host": "logs.internal",
                "port": 5514,
                "dtls": true,
                "dtls_cert_path": CERT_PATH,
                "dtls_key_path": "[REDACTED]",
            }))]}),
        ),
    ] {
        let mut cfg = cfg;
        let message = capture_all(&mut cfg).unwrap_err().to_string();
        assert!(message.contains("reserved redaction sentinel"), "{message}");
    }
}

fn mask_without_bundle(desired: &GatewayConfig, actual: &mut GatewayConfig) {
    let mut resolved = desired.clone();
    let report =
        super::resolver_fixtures::resolve_secrets(&mut resolved, &CredentialBundle::new()).unwrap();
    gitforgeops::diff::mask_indeterminate_secret_values(&resolved, actual, &report);
}

#[test]
fn diff_masks_unresolved_keys_and_redacts_key_material_but_shows_paths() {
    let desired = brokered_gateway("require");
    let mut live = desired.clone();
    live.proxies[0].backend_tls_client_key_path = Some(synthetic_key("zq7-live-proxy"));
    live.upstreams[0].backend_tls_client_key_path = Some(synthetic_key("zq7-live-upstream"));
    live.plugin_configs[0].config["dtls_key_path"] =
        serde_json::json!(synthetic_key("zq7-live-dtls"));

    // An unresolved brokered key is not drift the run can prove.
    let mut actual = live.clone();
    mask_without_bundle(&desired, &mut actual);
    let diffs = gitforgeops::diff::compute_diff(&desired, &actual).unwrap();
    assert!(diffs.is_empty(), "{diffs:?}");

    // A sibling change is still reported, without the key.
    let mut actual = live.clone();
    actual.proxies[0].backend_tls_client_cert_path = Some("/etc/ferrum/tls/old.crt".to_string());
    mask_without_bundle(&desired, &mut actual);
    let diffs = gitforgeops::diff::compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1, "{diffs:?}");
    let rendered = format!("{:?}", diffs[0].details);
    assert!(rendered.contains("old.crt"), "{rendered}");
    assert!(!rendered.contains(&body("zq7-live-proxy")), "{rendered}");

    // A live key file or provider URI against an unresolved declaration is a
    // reference the run can compare: the move to the broker is shown.
    for live_reference in [KEY_PATH, "vault://secret/tls#client.key"] {
        let mut actual = live.clone();
        actual.proxies[0].backend_tls_client_key_path = Some(live_reference.to_string());
        actual.upstreams[0].backend_tls_client_key_path = Some(live_reference.to_string());
        mask_without_bundle(&desired, &mut actual);
        let diffs = gitforgeops::diff::compute_diff(&desired, &actual).unwrap();
        let kinds: Vec<&str> = diffs.iter().map(|diff| diff.kind.as_str()).collect();
        assert!(
            kinds.contains(&"Proxy") && kinds.contains(&"Upstream"),
            "{kinds:?}"
        );
        let rendered = format!("{diffs:?}");
        assert!(rendered.contains(live_reference), "{rendered}");
    }

    // Moving from inline material to a key file: the path is reviewable, the
    // key is not printed. A cert+key bundle leaf is redacted whole.
    let desired = gateway(serde_json::json!({
        "proxies": [proxy(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": KEY_PATH,
        }))],
        "upstreams": [upstream(serde_json::json!({
            "backend_tls_client_cert_path": CERT_PATH,
            "backend_tls_client_key_path": KEY_PATH,
        }))]
    }));
    let mut actual = desired.clone();
    actual.proxies[0].backend_tls_client_key_path = Some(synthetic_key("zq7-live-proxy"));
    actual.upstreams[0].backend_tls_client_cert_path = Some(format!(
        "{}{}",
        synthetic_cert("public-live-cert"),
        synthetic_key("zq7-live-bundle")
    ));
    let diffs = gitforgeops::diff::compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 2, "{diffs:?}");
    let rendered = format!("{diffs:?}");
    for canary in ["zq7-live-proxy", "zq7-live-bundle"] {
        assert!(!rendered.contains(&body(canary)), "{rendered}");
    }
    assert!(rendered.contains(KEY_PATH), "{rendered}");
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
    for diff in &diffs {
        for change in &diff.details {
            assert!(!change.old_value.contains("PRIVATE KEY"), "{change:?}");
            assert!(!change.new_value.contains("PRIVATE KEY"), "{change:?}");
        }
    }
}

/// A live key is registered from the live snapshot, so a review comment that
/// echoes it (here through a field name, which the changes table renders)
/// loses it at the PR comment's sink, whichever line endings it carries.
#[test]
fn review_comment_loses_live_private_keys() {
    use gitforgeops::diff::resource_diff::{DiffAction, FieldChange, ResourceDiff};
    use gitforgeops::review::pr_comment::{
        build_review_comment_with_preview, ReviewValidationStatus,
    };

    gitforgeops::display::enable_display_scrubbing_on_this_thread();
    for (name, cfg, canary, _) in private_key_sites() {
        gitforgeops::display::register_gateway_config(&cfg).unwrap();
        for echoed in [body(canary), synthetic_key(canary).replace('\n', "\r\n")] {
            let diffs = vec![ResourceDiff {
                action: DiffAction::Modify,
                kind: "Proxy".to_string(),
                id: "edge".to_string(),
                namespace: "ferrum".to_string(),
                details: vec![FieldChange {
                    field: format!("backend_tls_client_key_path {echoed}"),
                    old_value: String::new(),
                    new_value: String::new(),
                }],
            }];
            let comment = build_review_comment_with_preview(
                ReviewValidationStatus::Passed,
                "",
                &diffs,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                None,
                None,
                None,
                None,
                &gitforgeops::secrets::ResolveReport::default(),
                true,
                None,
                &[],
                &[],
                false,
            );
            let published = gitforgeops::display::scrub_text(&comment);
            assert!(!published.contains(&body(canary)), "{name}: {published}");
        }
    }
}

fn plugin_with_extra(field: &str, value: serde_json::Value) -> GatewayConfig {
    let mut entry = plugin(
        "udp_logging",
        serde_json::json!({"host": "logs.internal", "port": 5514}),
    );
    entry[field] = value;
    gateway(serde_json::json!({"plugin_configs": [entry]}))
}

/// An undeclared PluginConfig top-level field (kept only when the operator
/// acknowledges the unknown field) is unmodeled, so key material there is
/// refused, blocked, scrubbed and redacted, never brokered.
#[test]
fn plugin_passthrough_fields_are_swept_for_private_keys() {
    let bundle = format!(
        "{}{}",
        synthetic_cert("public-extra-cert"),
        synthetic_key("zq7-extra-field-key")
    );
    let mut cfg = plugin_with_extra("future_tls_bundle", serde_json::json!(bundle));
    assert!(cfg.plugin_configs[0]
        .extra
        .contains_key("future_tls_bundle"));

    let message = capture_all(&mut cfg.clone()).unwrap_err().to_string();
    assert!(message.contains("future_tls_bundle"), "{message}");
    assert!(message.contains("undeclared top-level field"), "{message}");
    assert!(!message.contains(&body("zq7-extra-field-key")), "{message}");

    let findings = audit_security(&cfg);
    assert!(security_blockers(&findings).iter().any(|finding| finding
        .message
        .contains("undeclared field 'future_tls_bundle'")));

    let scrubber = gitforgeops::secrets::SecretScrubber::from_gateway_config(&cfg);
    let scrubbed = scrubber.scrub(&synthetic_key("zq7-extra-field-key"));
    assert!(
        !scrubbed.contains(&body("zq7-extra-field-key")),
        "{scrubbed}"
    );

    let desired = cfg.clone();
    cfg.plugin_configs[0].extra.insert(
        "future_tls_bundle".to_string(),
        serde_json::json!(format!(
            "{}{}",
            synthetic_cert("public-extra-cert"),
            synthetic_key("zq7-extra-field-live")
        )),
    );
    let diffs = gitforgeops::diff::compute_diff(&desired, &cfg).unwrap();
    assert_eq!(diffs.len(), 1, "{diffs:?}");
    let rendered = format!("{diffs:?}");
    for canary in ["zq7-extra-field-key", "zq7-extra-field-live"] {
        assert!(!rendered.contains(&body(canary)), "{rendered}");
    }
    assert!(rendered.contains("future_tls_bundle"), "{rendered}");
}

/// The DTLS pair is omitted only when Edge would load it: DTLS enabled and a
/// certificate source present. Otherwise the declared shape reaches Edge.
#[test]
fn dtls_pair_is_omitted_only_when_enabled_with_a_certificate() {
    for (name, config, omitted) in [
        (
            "enabled with certificate",
            serde_json::json!({"dtls": true, "dtls_cert_path": CERT_PATH, "dtls_key_path": PLACEHOLDER}),
            true,
        ),
        (
            "dtls disabled",
            serde_json::json!({"dtls": false, "dtls_cert_path": CERT_PATH, "dtls_key_path": PLACEHOLDER}),
            false,
        ),
        (
            "dtls absent",
            serde_json::json!({"dtls_cert_path": CERT_PATH, "dtls_key_path": PLACEHOLDER}),
            false,
        ),
        (
            "certificate missing",
            serde_json::json!({"dtls": true, "dtls_key_path": PLACEHOLDER}),
            false,
        ),
        (
            "certificate empty",
            serde_json::json!({"dtls": true, "dtls_cert_path": "", "dtls_key_path": PLACEHOLDER}),
            false,
        ),
        (
            "certificate not a string",
            serde_json::json!({"dtls": true, "dtls_cert_path": 7, "dtls_key_path": PLACEHOLDER}),
            false,
        ),
    ] {
        let mut config = config;
        config["host"] = serde_json::json!("logs.internal");
        config["port"] = serde_json::json!(5514);
        let cfg =
            gateway(serde_json::json!({"plugin_configs": [plugin("udp_logging", config.clone())]}));
        let patched = gitforgeops::validate::with_validation_standins(&cfg).unwrap();
        let object = patched.plugin_configs[0].config.as_object().unwrap();
        if omitted {
            assert!(!object.contains_key("dtls_key_path"), "{name}");
            assert!(!object.contains_key("dtls_cert_path"), "{name}");
        } else {
            let key = object["dtls_key_path"].as_str().unwrap();
            assert!(
                key.starts_with("-----BEGIN PRIVATE KEY-----"),
                "{name}: {key}"
            );
            assert_eq!(
                object.get("dtls_cert_path"),
                config.get("dtls_cert_path"),
                "{name}"
            );
        }
    }
}

/// A seeded value is checked like the literal import would be: a
/// certificate-plus-key bundle at a certificate source or in an ordinary
/// string, or placeholder text at a TLS key source, is refused without
/// echoing the seed. A seeded key file path stays a valid reference.
#[test]
fn seeded_tls_values_are_checked_like_literals() {
    let bundle_value = format!(
        "{}{}",
        synthetic_cert("public-seeded-cert"),
        synthetic_key("zq7-seeded-bundle-key")
    );
    for (name, cfg, slot, seed) in [
        (
            "dtls certificate source",
            gateway(
                serde_json::json!({"plugin_configs": [plugin("udp_logging", serde_json::json!({
                    "host": "logs.internal", "port": 5514, "dtls": true,
                    "dtls_cert_path": PLACEHOLDER, "dtls_key_path": KEY_PATH,
                }))]}),
            ),
            "ferrum/edge-plugin/@plugin/udp_logging/config/dtls_cert_path",
            bundle_value.clone(),
        ),
        (
            "ordinary plugin string",
            gateway(
                serde_json::json!({"plugin_configs": [plugin("acme_custom_tls", serde_json::json!({
                    "material": PLACEHOLDER,
                }))]}),
            ),
            "ferrum/edge-plugin/@plugin/acme_custom_tls/config/material",
            bundle_value.clone(),
        ),
        (
            "proxy key placeholder text",
            brokered_gateway("require"),
            PROXY_SLOT,
            "${gh-env-secret:alloc=generate}".to_string(),
        ),
        (
            "dtls key placeholder text",
            brokered_gateway("require"),
            DTLS_SLOT,
            PLACEHOLDER.to_string(),
        ),
    ] {
        let mut cfg = cfg;
        let mut bundle = BTreeMap::from([(slot.to_string(), seed.clone())]);
        if slot == PROXY_SLOT || slot == DTLS_SLOT {
            for other in [PROXY_SLOT, UPSTREAM_SLOT, DTLS_SLOT] {
                bundle
                    .entry(other.to_string())
                    .or_insert_with(|| synthetic_key("zq7-other-seed"));
            }
        }
        let message = super::resolver_fixtures::resolve_secrets(&mut cfg, &bundle)
            .unwrap_err()
            .to_string();
        assert!(message.contains(slot), "{name}: {message}");
        assert!(!message.contains(&body("zq7-seeded-bundle-key")), "{name}");
        assert!(!message.contains("${gh-env-secret"), "{name}: {message}");
        let report = super::resolver_fixtures::report_secrets(&cfg, &bundle);
        assert!(report.is_err(), "{name}: the read-only walk refuses too");
    }

    // A seeded key file path at a key source is a reference, not text.
    let mut cfg = brokered_gateway("require");
    let bundle = BTreeMap::from([
        (PROXY_SLOT.to_string(), KEY_PATH.to_string()),
        (
            UPSTREAM_SLOT.to_string(),
            synthetic_key("zq7-seeded-upstream"),
        ),
        (DTLS_SLOT.to_string(), synthetic_key("zq7-seeded-dtls")),
    ]);
    super::resolver_fixtures::resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(
        cfg.proxies[0].backend_tls_client_key_path.as_deref(),
        Some(KEY_PATH)
    );
}

/// At a plugin TLS key source, an unresolved declaration masks only live key
/// material; a live key file or provider URI stays compared.
#[test]
fn plugin_key_source_masking_keeps_live_references_visible() {
    for (plugin_name, desired_config, pointer) in [
        (
            "udp_logging",
            serde_json::json!({"host": "logs.internal", "port": 5514, "dtls": true,
                "dtls_cert_path": CERT_PATH, "dtls_key_path": PLACEHOLDER}),
            "/dtls_key_path",
        ),
        (
            "mesh_route_dispatch",
            serde_json::json!({"rules": [{"destination": {"backend_tls": {
                "client_cert_path": CERT_PATH, "client_key_path": PLACEHOLDER}}}]}),
            "/rules/0/destination/backend_tls/client_key_path",
        ),
    ] {
        let desired =
            gateway(serde_json::json!({"plugin_configs": [plugin(plugin_name, desired_config)]}));
        for (live, visible) in [
            (synthetic_key("zq7-live-plugin-key"), false),
            (KEY_PATH.to_string(), true),
            ("vault://secret/tls#client.key".to_string(), true),
        ] {
            let mut actual = desired.clone();
            *actual.plugin_configs[0]
                .config
                .pointer_mut(pointer)
                .unwrap() = serde_json::json!(live);
            mask_without_bundle(&desired, &mut actual);
            let diffs = gitforgeops::diff::compute_diff(&desired, &actual).unwrap();
            assert_eq!(
                !diffs.is_empty(),
                visible,
                "{plugin_name} {live}: {diffs:?}"
            );
            assert!(!format!("{diffs:?}").contains(&body("zq7-live-plugin-key")));
        }
    }
}

/// Edge's other certificate sources (`mtls_auth` issuer CAs, SOAP trusted
/// certificates) never broker a key and refuse a redacted value; an intact
/// certificate there is left alone.
#[test]
fn edge_certificate_sources_refuse_keys_and_sentinels() {
    type Shape = fn(serde_json::Value) -> serde_json::Value;
    let shapes: [(&str, Shape); 3] = [
        (
            "mtls_auth",
            |v| serde_json::json!({"allowed_issuers": [{"ca_certificate_pem": v}]}),
        ),
        (
            "soap_ws_security",
            |v| serde_json::json!({"x509_signature": {"trusted_certs": [v]}}),
        ),
        (
            "soap_ws_security",
            |v| serde_json::json!({"saml": {"trusted_signing_certs": [v]}}),
        ),
    ];
    for (plugin_name, value) in shapes {
        let wrap = |text: String| {
            gateway(
                serde_json::json!({"plugin_configs": [plugin(plugin_name, value(serde_json::json!(text)))]}),
            )
        };
        let mut bare_key = wrap(synthetic_key("zq7-cert-source-key"));
        let message = capture_all(&mut bare_key).unwrap_err().to_string();
        assert!(
            message.contains("TLS private-key material"),
            "{plugin_name}: {message}"
        );
        assert!(
            security_blockers(&audit_security(&wrap(synthetic_key("zq7-cert-source-key"))))
                .iter()
                .any(|finding| finding.message.contains("keep only certificates"))
        );

        let mut redacted = wrap("[REDACTED]".to_string());
        let message = capture_all(&mut redacted).unwrap_err().to_string();
        assert!(
            message.contains("reserved redaction sentinel"),
            "{plugin_name}: {message}"
        );

        let mut intact = wrap(synthetic_cert("public-issuer"));
        let before = serde_json::to_value(&intact).unwrap();
        assert!(capture_all(&mut intact).unwrap().is_empty());
        assert_eq!(serde_json::to_value(&intact).unwrap(), before);
    }
}

/// A value at a TLS key source that carries the reserved broker prefix but
/// does not parse (here a missing closing brace) is refused by both resolver
/// walks and by import, naming the slot only: Edge would read it as a
/// filesystem path.
#[test]
fn malformed_broker_declarations_at_tls_key_sources_are_refused() {
    const MALFORMED: &str = "${gh-env-secret:alloc=require|len=40";
    let proxy_cfg = gateway(serde_json::json!({"proxies": [proxy(serde_json::json!({
        "backend_tls_client_cert_path": CERT_PATH,
        "backend_tls_client_key_path": MALFORMED,
    }))]}));
    let dtls_cfg = gateway(
        serde_json::json!({"plugin_configs": [plugin("udp_logging", serde_json::json!({
            "host": "logs.internal", "port": 5514, "dtls": true,
            "dtls_cert_path": CERT_PATH, "dtls_key_path": MALFORMED,
        }))]}),
    );
    for (cfg, slot) in [(proxy_cfg, PROXY_SLOT), (dtls_cfg, DTLS_SLOT)] {
        let bundle = BTreeMap::from([(slot.to_string(), synthetic_key("zq7-malformed-seed"))]);
        for message in [
            super::resolver_fixtures::resolve_secrets(&mut cfg.clone(), &bundle)
                .unwrap_err()
                .to_string(),
            super::resolver_fixtures::report_secrets(&cfg, &bundle)
                .unwrap_err()
                .to_string(),
            capture_all(&mut cfg.clone()).unwrap_err().to_string(),
        ] {
            assert!(message.contains(slot), "{message}");
            assert!(message.contains("malformed"), "{message}");
            assert!(!message.contains("len=40"), "{message}");
        }
    }

    // An ordinary key path still resolves as a reference.
    let mut cfg = reference_only_gateway();
    super::resolver_fixtures::resolve_secrets(&mut cfg, &CredentialBundle::new()).unwrap();
}

/// `export --materialize` refuses a malformed declaration at a TLS key source
/// before writing anything, even when the correctly named slot is seeded.
#[cfg(unix)]
#[test]
fn materialize_refuses_a_malformed_tls_key_declaration_before_output() {
    let dir = tempfile::tempdir().unwrap();
    let proxy_yaml = format!(
        "kind: Proxy\nspec:\n  id: edge\n  listen_path: /edge\n  backend_scheme: https\n  backend_host: backend.internal\n  backend_port: 443\n  backend_tls_client_cert_path: {CERT_PATH}\n  backend_tls_client_key_path: '${{gh-env-secret:alloc=require|len=40'\n"
    );
    let path = dir.path().join("resources/ferrum/proxies/edge.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, proxy_yaml).unwrap();
    let bundle = serde_json::json!({"FERRUM_CREDS_BUNDLE": {
        PROXY_SLOT: synthetic_key("zq7-materialize-seed")
    }})
    .to_string();
    let output = run_materialize(dir.path(), &bundle);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(PROXY_SLOT), "{stderr}");
    assert!(!stderr.contains(&body("zq7-materialize-seed")), "{stderr}");
    assert!(!dir.path().join("export.yaml").exists());
}

/// `gitforgeops export --materialize --output export.yaml` in `repo`, file
/// mode, hermetic, with `bundle` as `FERRUM_CREDS_JSON`.
#[cfg(unix)]
fn run_materialize(repo: &std::path::Path, bundle: &str) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;
    let validator = repo.join("ferrum-edge-stub");
    std::fs::write(&validator, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&validator, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dir = repo;
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_gitforgeops"));
    command
        .args(["export", "--materialize", "--output", "export.yaml"])
        .current_dir(dir)
        .env_clear();
    for name in ["PATH", "HOME", "TMPDIR"] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    command
        .env("FERRUM_GATEWAY_MODE", "file")
        .env(
            "FERRUM_FILE_OUTPUT_PATH",
            dir.join("published/resources.yaml"),
        )
        .env("FERRUM_EDGE_BINARY_PATH", &validator)
        .env("FERRUM_CREDS_JSON", bundle)
        .output()
        .unwrap()
}

/// A schema-declared signing key (`client_auth.private_key_pem`) may carry
/// its `PUBLIC KEY` record after the private key: that is a key, not a
/// certificate-plus-key bundle, as a literal on import and as a seed.
#[test]
fn signing_keys_with_a_trailing_public_key_stay_brokerable() {
    let signing_key = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n\
         -----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        body("zq7-signing-key"),
        body("public-signing-key")
    );
    for plugin_name in ["oidc_relying_party", "oauth2_introspection"] {
        let literal = |value: &str| {
            gateway(
                serde_json::json!({"plugin_configs": [plugin(plugin_name, serde_json::json!({
                    "providers": [{"client_auth": {"private_key_pem": value}}]
                }))]}),
            )
        };
        let slot = format!(
            "ferrum/edge-plugin/@plugin/{plugin_name}/config/providers/[0]/client_auth/private_key_pem"
        );
        let mut cfg = literal(&signing_key);
        let captured = capture_all(&mut cfg).unwrap();
        assert_eq!(captured.get(&slot), Some(&signing_key), "{plugin_name}");

        let mut brokered = literal(PLACEHOLDER);
        let bundle = BTreeMap::from([(slot.clone(), signing_key.clone())]);
        super::resolver_fixtures::resolve_secrets(&mut brokered, &bundle).unwrap();
    }

    // In an ordinary string a trailing public key is not a bundle either.
    let mut cfg = gateway(
        serde_json::json!({"plugin_configs": [plugin("acme_custom_tls", serde_json::json!({
            "material": signing_key,
        }))]}),
    );
    assert_eq!(capture_all(&mut cfg).unwrap().len(), 1);
}

/// A PluginConfig whose `config` is not an object still gets the TLS refusal:
/// a certificate-plus-key bundle in a certificate field fails the import with
/// no resource tree and no migration bundle written.
#[test]
fn non_object_plugin_config_roots_refuse_certificate_bundles_on_import() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let original = gateway(
        serde_json::json!({"plugin_configs": [plugin("acme_custom_tls", serde_json::json!([
            {"client_certificate": format!(
                "{}{}",
                synthetic_cert("public-array-cert"),
                synthetic_key("zq7-array-bundled-key")
            )}
        ]))]}),
    );
    std::fs::write(
        &backup_path,
        gitforgeops::yaml::to_string(&original).unwrap(),
    )
    .unwrap();
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("migration.json");
    let message = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(message.contains("TLS private-key material"), "{message}");
    assert!(
        !message.contains(&body("zq7-array-bundled-key")),
        "{message}"
    );
    assert!(!output.exists());
    assert!(!bundle_path.exists());
}

const CONSUL_SLOT: &str = "ferrum/edge/@service-discovery/consul/token";

fn consul_upstream(token: &str) -> serde_json::Value {
    upstream(serde_json::json!({
        "targets": [],
        "service_discovery": {"provider": "consul", "consul": {
            "address": "https://consul.internal:8501",
            "service_name": "edge",
            "token": token,
        }}
    }))
}

/// Key material in a field another capture brokers (a Consul token) is
/// refused on the original Upstream before any capture replaces it, and a
/// discovery seed holding key material is refused before publication.
#[test]
fn key_material_in_a_discovery_token_is_refused_on_import() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let bundled = format!(
        "{}{}",
        synthetic_cert("public-consul-cert"),
        synthetic_key("zq7-consul-bundled-key")
    );
    let original = gateway(serde_json::json!({"upstreams": [consul_upstream(&bundled)]}));
    std::fs::write(
        &backup_path,
        gitforgeops::yaml::to_string(&original).unwrap(),
    )
    .unwrap();
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("migration.json");
    let message = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(
        message.contains("service_discovery.consul.token"),
        "{message}"
    );
    assert!(
        !message.contains(&body("zq7-consul-bundled-key")),
        "{message}"
    );
    assert!(!output.exists());
    assert!(!bundle_path.exists());

    let mut brokered = gateway(serde_json::json!({"upstreams": [consul_upstream(PLACEHOLDER)]}));
    let seeds = BTreeMap::from([(CONSUL_SLOT.to_string(), bundled)]);
    let message = super::resolver_fixtures::resolve_secrets(&mut brokered, &seeds)
        .unwrap_err()
        .to_string();
    assert!(message.contains(CONSUL_SLOT), "{message}");
    assert!(
        !message.contains(&body("zq7-consul-bundled-key")),
        "{message}"
    );
}

#[cfg(unix)]
#[test]
fn materialize_refuses_key_material_seeded_for_a_discovery_token() {
    let dir = tempfile::tempdir().unwrap();
    let upstream_yaml = "kind: Upstream\nspec:\n  id: edge\n  targets: []\n  service_discovery:\n    provider: consul\n    consul:\n      address: https://consul.internal:8501\n      service_name: edge\n      token: '${gh-env-secret:alloc=require}'\n";
    let path = dir.path().join("resources/ferrum/upstreams/edge.yaml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, upstream_yaml).unwrap();
    let bundle = serde_json::json!({"FERRUM_CREDS_BUNDLE": {
        CONSUL_SLOT: format!("{}{}", synthetic_cert("public-consul-cert"), synthetic_key("zq7-consul-seed"))
    }})
    .to_string();
    let output = run_materialize(dir.path(), &bundle);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(CONSUL_SLOT), "{stderr}");
    assert!(!stderr.contains(&body("zq7-consul-seed")), "{stderr}");
    assert!(!dir.path().join("export.yaml").exists());
}

/// A well-formed broker declaration at the backend key field that carries a
/// line break the placeholder parser trims is a declaration, not key
/// material: the audit passes it and the resolver resolves it.
#[test]
fn multiline_broker_declarations_at_the_backend_key_field_are_declarations() {
    let declaration = "${gh-env-secret:\n  alloc=require}";
    assert!(matches!(
        gitforgeops::secrets::parse_placeholder(declaration),
        Some(Ok(_))
    ));
    let cfg = gateway(serde_json::json!({"proxies": [proxy(serde_json::json!({
        "backend_tls_client_cert_path": CERT_PATH,
        "backend_tls_client_key_path": declaration,
    }))]}));
    let findings = audit_security(&cfg);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.message.contains("TLS private key")),
        "{findings:?}"
    );
    let mut resolved = cfg.clone();
    let seeds = BTreeMap::from([(PROXY_SLOT.to_string(), synthetic_key("zq7-multiline-seed"))]);
    super::resolver_fixtures::resolve_secrets(&mut resolved, &seeds).unwrap();
    assert_eq!(
        resolved.proxies[0].backend_tls_client_key_path.as_deref(),
        Some(seeds[PROXY_SLOT].as_str())
    );
}
