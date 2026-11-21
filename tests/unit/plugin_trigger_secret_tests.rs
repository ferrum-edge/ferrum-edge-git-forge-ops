//! GHSA-vxj2-vppp-782j: the `header` / `query` / `cookie` value operands of a
//! `PluginConfig.trigger` are shared tokens (whoever knows one decides whether
//! the plugin runs), so every broker boundary treats them like plugin-config
//! secrets: import capture, resolution, validation stand-ins, the literal
//! gate, the scrubber, diff masking and redaction, and the review sink. Every
//! other predicate stays literal and reviewable.

use gitforgeops::config::schema::GatewayConfig;
use gitforgeops::diff::resource_diff::compute_diff;
use gitforgeops::diff::security::{audit_security, security_blockers};
use gitforgeops::secrets::{
    capture_and_redact_import_plugin_trigger_secrets, unresolved_placeholder_slots,
    CredentialBundle, SecretScrubber, SlotStatus, IMPORT_REQUIRED_PLACEHOLDER,
};

const PLACEHOLDER: &str = "${gh-env-secret:alloc=require}";

/// One trigger shape per client-field predicate and combinator Edge walks,
/// each with its synthetic operand(s), the reviewable text beside them, and
/// the broker slots import must capture.
fn trigger_cases() -> Vec<(
    &'static str,
    serde_json::Value,
    Vec<&'static str>,
    Vec<&'static str>,
)> {
    vec![
        (
            "header exact under not",
            serde_json::json!({"when": {"not": {"match": {"header": {
                "name": "x-skip-waf",
                "value": {"exact": ["synthetic-trigger-header"]}
            }}}}}),
            vec!["x-skip-waf"],
            vec!["ferrum/plugin/@plugin/waf/trigger/when/not/match/header/value/exact/[0]"],
        ),
        (
            "query prefix inside all, beside a path predicate",
            serde_json::json!({"when": {"all": [
                {"match": {"path": {"prefix": ["/admin-console"]}}},
                {"match": {"query": {
                    "name": "debug-mode",
                    "value": {"prefix": ["synthetic-trigger-query"]}
                }}}
            ]}}),
            vec!["/admin-console", "debug-mode"],
            vec!["ferrum/plugin/@plugin/waf/trigger/when/all/[1]/match/query/value/prefix/[0]"],
        ),
        (
            "cookie regex inside any, beside method and identity predicates",
            serde_json::json!({"when": {"any": [
                {"match": {"method": ["POST"]}},
                {"match": {"consumer": {"value": {"exact": ["partner-consumer"]}}}},
                {"not": {"match": {"cookie": {
                    "name": "session-tier",
                    "value": {"regex": "synthetic-trigger-cookie-[0-9]+", "case_insensitive": true}
                }}}}
            ]}}),
            vec!["POST", "partner-consumer", "session-tier"],
            vec!["ferrum/plugin/@plugin/waf/trigger/when/any/[2]/not/match/cookie/value/regex"],
        ),
        (
            "a short exact entry stays an ordinary setting beside a long one",
            serde_json::json!({"when": {"match": {"header": {
                "name": "x-env",
                "value": {"exact": ["on", "synthetic-trigger-second"]}
            }}}}),
            vec!["x-env", "\"on\""],
            vec!["ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[1]"],
        ),
    ]
}

fn trigger_gateway(trigger: serde_json::Value) -> GatewayConfig {
    serde_json::from_value(serde_json::json!({
        "version": "1",
        "plugin_configs": [{
            "id": "plugin",
            "namespace": "ferrum",
            "plugin_name": "waf",
            "scope": "global",
            "config": {"mode": "enforce"},
            "trigger": trigger
        }]
    }))
    .unwrap()
}

fn trigger_text(gateway: &GatewayConfig) -> String {
    serde_json::to_string(gateway.plugin_configs[0].trigger.as_ref().unwrap()).unwrap()
}

#[test]
fn trigger_operands_are_brokered_on_import() {
    for (label, trigger, visible, expected) in trigger_cases() {
        let mut gateway = trigger_gateway(trigger);
        let captured = capture_and_redact_import_plugin_trigger_secrets(&mut gateway).unwrap();
        let slots: Vec<&str> = captured.keys().map(String::as_str).collect();
        assert_eq!(slots, expected, "{label}");
        assert!(
            captured
                .values()
                .all(|value| value.starts_with("synthetic-")),
            "{label}"
        );
        let written = trigger_text(&gateway);
        assert!(!written.contains("synthetic-"), "{label}: {written}");
        assert!(
            written.contains(IMPORT_REQUIRED_PLACEHOLDER),
            "{label}: {written}"
        );
        for text in visible {
            assert!(written.contains(text), "{label}: {text} in {written}");
        }
    }
}

/// The captured bundle resolves every operand back byte for byte; without it
/// the placeholder is reported unresolved (and `alloc=require` missing), so
/// the write path's last check refuses it instead of sending the placeholder
/// text to the gateway.
#[test]
fn trigger_operands_resolve_from_the_bundle_and_fail_closed() {
    for (label, trigger, _, expected) in trigger_cases() {
        let original = trigger_gateway(trigger);
        let mut gateway = original.clone();
        let captured = capture_and_redact_import_plugin_trigger_secrets(&mut gateway).unwrap();

        let mut resolved = gateway.clone();
        let report = super::resolver_fixtures::resolve_secrets(&mut resolved, &captured).unwrap();
        assert_eq!(
            trigger_text(&resolved),
            trigger_text(&original),
            "{label}: resolution must restore the imported trigger"
        );
        let slots: Vec<&str> = report.results.iter().map(|r| r.slot.as_str()).collect();
        assert_eq!(slots, expected, "{label}");
        assert!(
            report
                .results
                .iter()
                .all(|r| r.status == SlotStatus::Resolved),
            "{label}"
        );
        assert!(unresolved_placeholder_slots(&resolved).unwrap().is_empty());

        let mut unresolved = gateway.clone();
        let report =
            super::resolver_fixtures::resolve_secrets(&mut unresolved, &CredentialBundle::new())
                .unwrap();
        let missing: Vec<&str> = report
            .missing_required()
            .iter()
            .map(|r| r.slot.as_str())
            .collect();
        assert_eq!(missing, expected, "{label}");
        assert_eq!(
            unresolved_placeholder_slots(&unresolved).unwrap(),
            expected,
            "{label}"
        );
    }
}

/// Only client-field operands have a slot. Broker syntax in any other trigger
/// predicate would never resolve, so it is refused before any walk, naming
/// the path and never a value.
#[test]
fn trigger_placeholders_outside_client_field_operands_are_refused() {
    for (label, trigger) in [
        (
            "path prefix",
            serde_json::json!({"when": {"match": {"path": {"prefix": [PLACEHOLDER]}}}}),
        ),
        (
            "header name",
            serde_json::json!({"when": {"match": {"header": {"name": PLACEHOLDER}}}}),
        ),
        (
            "consumer identity",
            serde_json::json!({"when": {"match": {"consumer": {"value": {"exact": [PLACEHOLDER]}}}}}),
        ),
    ] {
        let gateway = trigger_gateway(trigger);
        let error = super::resolver_fixtures::report_secrets(&gateway, &CredentialBundle::new())
            .unwrap_err()
            .to_string();
        assert!(error.contains("trigger.when.match."), "{label}: {error}");
        assert!(
            error.contains("only the `value` operands"),
            "{label}: {error}"
        );
        let mut resolved = gateway.clone();
        assert!(
            super::resolver_fixtures::resolve_secrets(&mut resolved, &CredentialBundle::new())
                .is_err(),
            "{label}"
        );
        assert!(
            gitforgeops::secrets::resolver::validate_identity_placeholders(&gateway).is_err(),
            "{label}"
        );
    }
}

/// A validator run without a bundle gets one opaque stand-in per brokered
/// operand: a non-empty value under Edge's 512-byte regex cap (and 1024-byte
/// value cap) made only of characters that are literals in a regex, so
/// `exact`, `prefix` and `regex` all pass trigger admission. Every other
/// predicate is untouched.
#[test]
fn trigger_validation_standins_fit_every_operator() {
    use gitforgeops::validate::standin::{with_validation_standins, VALIDATION_STANDIN_PREFIX};

    for (label, trigger, visible, expected) in trigger_cases() {
        let mut gateway = trigger_gateway(trigger);
        capture_and_redact_import_plugin_trigger_secrets(&mut gateway).unwrap();
        let patched = with_validation_standins(&gateway).expect("a brokered trigger operand");
        let text = trigger_text(&patched);
        assert!(!text.contains("${gh-env-secret:"), "{label}: {text}");
        for text_visible in visible {
            assert!(text.contains(text_visible), "{label}: {text}");
        }
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mut standins = Vec::new();
        collect_strings(&json, &mut standins);
        let standins: Vec<&String> = standins
            .iter()
            .filter(|value| value.starts_with(VALIDATION_STANDIN_PREFIX))
            .collect();
        assert_eq!(standins.len(), expected.len(), "{label}: {text}");
        for standin in standins {
            assert!(standin.len() <= 512, "{label}");
            assert!(
                standin
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{label}: {standin}"
            );
        }
        // The repository document itself is never changed.
        assert!(trigger_text(&gateway).contains(PLACEHOLDER), "{label}");
    }
}

fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|item| collect_strings(item, out)),
        serde_json::Value::Object(map) => map.values().for_each(|item| collect_strings(item, out)),
        _ => {}
    }
}

/// A committed operand blocks apply with an Error finding that names the
/// path and never the value; the brokered form passes; the scrubber removes
/// the value from validator output and keeps the field name readable.
#[test]
fn literal_trigger_operands_are_gated_and_scrubbed() {
    for (label, trigger, visible, expected) in trigger_cases() {
        let gateway = trigger_gateway(trigger);
        let findings = audit_security(&gateway);
        let blockers: Vec<_> = security_blockers(&findings)
            .into_iter()
            .filter(|finding| finding.message.contains("Literal plugin-trigger secret"))
            .collect();
        assert_eq!(blockers.len(), expected.len(), "{label}: {findings:?}");
        assert!(
            blockers[0].message.contains("'trigger.when."),
            "{label}: {}",
            blockers[0].message
        );
        for finding in &findings {
            assert!(!finding.message.contains("synthetic-"), "{label}");
        }

        let mut brokered = gateway.clone();
        capture_and_redact_import_plugin_trigger_secrets(&mut brokered).unwrap();
        assert!(
            !audit_security(&brokered)
                .iter()
                .any(|finding| finding.message.contains("plugin-trigger")),
            "{label}"
        );

        let scrubber = SecretScrubber::from_gateway_config(&gateway);
        let rendered = trigger_text(&gateway);
        let scrubbed = scrubber.scrub(&rendered);
        assert!(!scrubbed.contains("synthetic-"), "{label}: {scrubbed}");
        assert!(scrubbed.contains("[REDACTED]"), "{label}: {scrubbed}");
        for text in visible {
            assert!(scrubbed.contains(text), "{label}: {scrubbed}");
        }
    }
}

/// Short operands (`exact: ["on"]`) could be neither brokered nor scrubbed,
/// so like a short plugin-config operator value they are ordinary settings:
/// import keeps them, the gate lets them through, and validator output and a
/// live read are not refused over them.
#[test]
fn short_trigger_operands_stay_ordinary_settings() {
    gitforgeops::display::enable_display_scrubbing_on_this_thread();
    let original = trigger_gateway(serde_json::json!({"when": {"any": [
        {"match": {"header": {"name": "x-env", "value": {"exact": ["on"]}}}},
        {"match": {"query": {"name": "v", "value": {"prefix": ["2"]}}}},
        {"match": {"cookie": {"name": "ab", "value": {"regex": "^b$"}}}}
    ]}}));
    let mut gateway = original.clone();
    let captured = capture_and_redact_import_plugin_trigger_secrets(&mut gateway).unwrap();
    assert!(captured.is_empty());
    assert_eq!(trigger_text(&gateway), trigger_text(&original));
    assert!(!audit_security(&original)
        .iter()
        .any(|finding| finding.message.contains("plugin-trigger")));
    let output = SecretScrubber::from_gateway_config(&original).scrub_streams("validated", "");
    assert!(output.suppressed.is_none());
    gitforgeops::display::register_gateway_config(&original).unwrap();
}

/// Without a bundle, an unresolved brokered operand is compared as its
/// placeholder (no permanent false drift against the live token), while a
/// change to any other predicate is still reported, with the live operand
/// redacted from the rendered change.
#[test]
fn trigger_operand_drift_is_masked_and_redacted_per_leaf() {
    const LIVE: &str = "live-trigger-token-material";
    let desired = trigger_gateway(serde_json::json!({"when": {"all": [
        {"match": {"path": {"prefix": ["/admin-console"]}}},
        {"not": {"match": {"header": {"name": "x-skip-waf", "value": {"exact": [PLACEHOLDER]}}}}}
    ]}}));
    let live_trigger = |path: &str| {
        serde_json::json!({"when": {"all": [
            {"match": {"path": {"prefix": [path]}}},
            {"not": {"match": {"header": {"name": "x-skip-waf", "value": {"exact": [LIVE]}}}}}
        ]}})
    };

    let mut actual = trigger_gateway(live_trigger("/admin-console"));
    mask_without_bundle(&desired, &mut actual);
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert!(diffs.is_empty(), "{diffs:?}");

    let mut actual = trigger_gateway(live_trigger("/ops-console"));
    mask_without_bundle(&desired, &mut actual);
    let diffs = compute_diff(&desired, &actual).unwrap();
    assert_eq!(diffs.len(), 1, "{diffs:?}");
    assert_eq!(diffs[0].details.len(), 1, "{diffs:?}");
    let change = &diffs[0].details[0];
    assert_eq!(change.field, "trigger");
    assert!(change.old_value.contains("/ops-console"), "{change:?}");
    assert!(change.new_value.contains("/admin-console"), "{change:?}");
    assert!(change.old_value.contains("x-skip-waf"), "{change:?}");
    assert!(!change.old_value.contains(LIVE), "{change:?}");

    // Without masking (a literal on both sides), each side's operand is
    // redacted and the predicates around it stay readable.
    let desired = trigger_gateway(live_trigger("/admin-console"));
    let mut live = trigger_gateway(live_trigger("/admin-console"));
    if let Some(trigger) = live.plugin_configs[0].trigger.as_mut() {
        let mut json = serde_json::to_value(&*trigger).unwrap();
        json["when"]["all"][1]["not"]["match"]["header"]["value"]["exact"][0] =
            serde_json::json!("other-live-trigger-token");
        *trigger = serde_json::from_value(json).unwrap();
    }
    let diffs = compute_diff(&desired, &live).unwrap();
    let rendered = format!("{:?}", diffs[0].details);
    assert!(!rendered.contains(LIVE), "{rendered}");
    assert!(!rendered.contains("other-live-trigger-token"), "{rendered}");
    assert!(rendered.contains("[REDACTED]"), "{rendered}");
    assert!(rendered.contains("x-skip-waf"), "{rendered}");
    assert!(rendered.contains("/admin-console"), "{rendered}");
}

fn mask_without_bundle(desired: &GatewayConfig, actual: &mut GatewayConfig) {
    let mut resolved = desired.clone();
    let report =
        super::resolver_fixtures::resolve_secrets(&mut resolved, &CredentialBundle::new()).unwrap();
    gitforgeops::diff::mask_indeterminate_secret_values(&resolved, actual, &report);
}

/// Trigger slots share the plugin's typed keyspace: a slot stored for another
/// plugin type is a remap, and an array that shrank under a stored slot is a
/// remap too, both under the same policy as plugin-config slots. A trigger
/// slot of the plugin's own type is not foreign.
#[test]
fn trigger_slots_follow_plugin_slot_identity() {
    let gateway = trigger_gateway(serde_json::json!({"when": {"match": {"header": {
        "name": "x-skip-waf", "value": {"exact": [PLACEHOLDER]}
    }}}}));
    let own = "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]";

    let mut bundle = CredentialBundle::new();
    bundle.insert(own.to_string(), "seeded-trigger-token".to_string());
    let report = super::resolver_fixtures::report_secrets(&gateway, &bundle).unwrap();
    assert!(report.slot_remaps.is_empty(), "unexpected slot remaps");

    let mut retyped = bundle.clone();
    retyped.insert(
        "ferrum/plugin/@plugin/cors/trigger/when/match/header/value/exact/[0]".to_string(),
        "old-type-trigger-token".to_string(),
    );
    let error = super::resolver_fixtures::report_secrets(&gateway, &retyped)
        .unwrap_err()
        .to_string();
    assert!(error.contains("@plugin/cors/trigger"), "{error}");
    assert!(!error.contains("old-type-trigger-token"), "{error}");

    let mut shrunk = bundle;
    shrunk.insert(
        "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[1]".to_string(),
        "retired-trigger-token".to_string(),
    );
    let error = super::resolver_fixtures::report_secrets(&gateway, &shrunk)
        .unwrap_err()
        .to_string();
    assert!(error.contains("plugin trigger slot"), "{error}");
    assert!(!error.contains("retired-trigger-token"), "{error}");
}

/// End to end: a backup carrying a literal trigger token imports into a tree
/// with only placeholders, a private migration bundle holding the canonical
/// slot, and a document that resolves back to the original trigger.
#[test]
fn import_brokers_trigger_operands_and_round_trips_exactly() {
    let (_, trigger, _, expected) = trigger_cases().remove(1);
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let config = trigger_gateway(trigger);
    let original_trigger = trigger_text(&config);
    std::fs::write(&backup_path, gitforgeops::yaml::to_string(&config).unwrap()).unwrap();

    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("secret-migration.json");
    let result = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap();
    assert_eq!(result.redacted_plugin_trigger_values, 1);
    assert_eq!(result.redacted_plugin_config_values, 0);

    let plugin_yaml = std::fs::read_to_string(output.join("ferrum/plugins/plugin.yaml")).unwrap();
    assert!(!plugin_yaml.contains("synthetic-"), "{plugin_yaml}");
    assert!(plugin_yaml.contains(PLACEHOLDER), "{plugin_yaml}");
    assert!(plugin_yaml.contains("debug-mode"), "{plugin_yaml}");
    assert!(plugin_yaml.contains("/admin-console"), "{plugin_yaml}");

    let raw_bundle = std::fs::read_to_string(&bundle_path).unwrap();
    let (merged, _) = gitforgeops::secrets::load_bundles_from_env(&raw_bundle).unwrap();
    assert_eq!(
        merged.keys().map(String::as_str).collect::<Vec<_>>(),
        expected
    );

    let resources = gitforgeops::config::load_resources(&output).unwrap();
    let mut assembled = gitforgeops::config::assemble(resources).unwrap().gateway;
    super::resolver_fixtures::resolve_secrets(&mut assembled, &merged).unwrap();
    assert_eq!(trigger_text(&assembled), original_trigger);

    // Without a bundle destination, import refuses before writing anything.
    let refused_output = destination_parent.path().join("refused");
    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &refused_output,
        None,
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("--credential-bundle-output"), "{error}");
    assert!(!error.contains("synthetic-"), "{error}");
    assert!(!refused_output.exists());
}
