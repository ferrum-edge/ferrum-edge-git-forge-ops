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
            "every entry of a multi-entry exact list",
            serde_json::json!({"when": {"match": {"header": {
                "name": "x-env",
                "value": {"exact": ["synthetic-trigger-first", "synthetic-trigger-second"]}
            }}}}),
            vec!["x-env"],
            vec![
                "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]",
                "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[1]",
            ],
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
        let capture = capture_and_redact_import_plugin_trigger_secrets(&mut gateway).unwrap();
        assert!(capture.short.is_empty(), "{label}");
        let captured = capture.captured;
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
        let captured = capture_and_redact_import_plugin_trigger_secrets(&mut gateway)
            .unwrap()
            .captured;

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

/// Edge withholds every client-field operand whatever its length, so a short
/// one (`exact: ["on"]`) is a secret too: import brokers it (and lists its slot
/// for re-seeding), the literal gate blocks it, a diff redacts it by position,
/// and the broker refuses to resolve a value that short (it could not be
/// removed from free text). Free-text scrubbing keeps its 8-byte floor, so
/// validator output and a live read are not refused over a short operand.
#[test]
fn short_trigger_operands_are_secrets_too() {
    gitforgeops::display::enable_display_scrubbing_on_this_thread();
    let original = trigger_gateway(serde_json::json!({"when": {"any": [
        {"match": {"header": {"name": "x-skip-waf", "value": {"exact": ["on"]}}}},
        {"match": {"query": {"name": "debug-mode", "value": {"prefix": ["2"]}}}},
        {"match": {"cookie": {"name": "session-tier", "value": {"regex": "^b$"}}}}
    ]}}));
    let expected = [
        "ferrum/plugin/@plugin/waf/trigger/when/any/[0]/match/header/value/exact/[0]",
        "ferrum/plugin/@plugin/waf/trigger/when/any/[1]/match/query/value/prefix/[0]",
        "ferrum/plugin/@plugin/waf/trigger/when/any/[2]/match/cookie/value/regex",
    ];

    let mut gateway = original.clone();
    let capture = capture_and_redact_import_plugin_trigger_secrets(&mut gateway).unwrap();
    let slots: Vec<&str> = capture.captured.keys().map(String::as_str).collect();
    assert_eq!(slots, expected);
    assert_eq!(capture.short, expected);
    let written = trigger_text(&gateway);
    assert!(!written.contains("\"on\""), "{written}");
    assert!(!written.contains("^b$"), "{written}");
    assert!(written.contains("session-tier"), "{written}");

    let blockers: Vec<String> = security_blockers(&audit_security(&original))
        .into_iter()
        .filter(|finding| finding.message.contains("Literal plugin-trigger secret"))
        .map(|finding| finding.message.clone())
        .collect();
    assert_eq!(blockers.len(), 3, "{blockers:?}");
    assert!(blockers[0].contains("at least 8 bytes"), "{blockers:?}");

    // The captured short value is refused at resolution, naming the slot only.
    let mut resolved = gateway.clone();
    let error = super::resolver_fixtures::resolve_secrets(&mut resolved, &capture.captured)
        .unwrap_err()
        .to_string();
    assert!(error.contains("plugin trigger slot"), "{error}");
    assert!(error.contains("shorter than 8 bytes"), "{error}");
    assert!(!error.contains("\"on\""), "{error}");

    // A diff that touches the trigger redacts the short live operands.
    let desired = trigger_gateway(serde_json::json!({"when": {"any": [
        {"match": {"header": {"name": "x-skip-waf", "value": {"exact": ["off"]}}}},
        {"match": {"query": {"name": "debug-mode", "value": {"prefix": ["2"]}}}},
        {"match": {"cookie": {"name": "session-tier", "value": {"regex": "^b$"}}}}
    ]}}));
    let diffs = compute_diff(&desired, &original).unwrap();
    let change = &diffs[0].details[0];
    assert_eq!(change.field, "trigger");
    for side in [&change.old_value, &change.new_value] {
        assert!(!side.contains("\"on\""), "{side}");
        assert!(!side.contains("\"off\""), "{side}");
        assert!(!side.contains("\"2\""), "{side}");
        assert!(!side.contains("^b$"), "{side}");
        assert!(side.contains("x-skip-waf"), "{side}");
    }

    let output = SecretScrubber::from_gateway_config(&original).scrub_streams("validated", "");
    assert!(output.suppressed.is_none());
    gitforgeops::display::register_gateway_config(&original).unwrap();

    // A short operand cannot be substring-replaced, but validator output that
    // echoes it is withheld rather than printed (standalone `validate` runs no
    // literal gate).
    let echoed = trigger_gateway(serde_json::json!({"when": {"match": {"header": {
        "name": "x-skip-waf", "value": {"exact": ["zq9tok"]}
    }}}}));
    let output = SecretScrubber::from_gateway_config(&echoed).scrub_streams(
        "trigger.when.match.header.value.exact[0] = zq9tok is not allowed",
        "",
    );
    assert_eq!(
        output.suppressed,
        Some(gitforgeops::secrets::SuppressionReason::ResidualValue)
    );
    assert!(!output.stdout.contains("zq9tok"));
    assert!(!output.stderr.contains("zq9tok"));
}

/// `apply` resolves twice when it allocates: once against the bundle it
/// read, then again on the already-resolved document after the allocator
/// added new slots. A resolved trigger operand no longer spells a placeholder
/// but still owns its slot, so the second pass must not call it orphaned.
#[test]
fn trigger_retirement_survives_the_post_allocation_re_resolve() {
    let mut desired: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "consumers": [{
            "id": "app", "username": "app", "namespace": "ferrum",
            "credentials": {"keyauth": [{"key": "${gh-env-secret:alloc=generate}"}]}
        }],
        "plugin_configs": [{
            "id": "plugin", "namespace": "ferrum", "plugin_name": "waf", "scope": "global",
            "config": {"mode": "enforce"},
            "trigger": {"when": {"match": {"header": {"name": "x-skip-waf", "value": {"exact": [
                PLACEHOLDER, "${gh-env-secret:alloc=generate}"
            ]}}}}}
        }]
    }))
    .unwrap();
    let seeded = "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]";
    let generated = "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[1]";
    let mut bundle = CredentialBundle::new();
    bundle.insert(seeded.to_string(), "seeded-trigger-token".to_string());

    // First pass: the seeded operand resolves, two slots need allocation.
    let report = super::resolver_fixtures::resolve_secrets(&mut desired, &bundle).unwrap();
    assert_eq!(report.needs_allocation().len(), 2);
    assert!(report.slot_remaps.is_empty());

    // The allocator commits the new slots; the re-resolve runs on the
    // already-resolved document under the default (refusing) remap policy.
    bundle.insert(
        generated.to_string(),
        "generated-trigger-token-value".to_string(),
    );
    bundle.insert(
        "ferrum/app/keyauth/key".to_string(),
        "generated-consumer-key-value-0123456789".to_string(),
    );
    let report = super::resolver_fixtures::resolve_secrets(&mut desired, &bundle).unwrap();
    assert!(report.slot_remaps.is_empty());
    let text = trigger_text(&desired);
    assert!(text.contains("seeded-trigger-token"), "{text}");
    assert!(text.contains("generated-trigger-token-value"), "{text}");
    assert!(unresolved_placeholder_slots(&desired).unwrap().is_empty());
}

/// A repository author who writes an operand as a scalar where a list is
/// expected gets a decode error that names the field and the expected shape,
/// never the value: serde's own message would quote it.
#[test]
fn malformed_trigger_decode_errors_withhold_the_value() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("ferrum").join("plugins");
    std::fs::create_dir_all(&directory).unwrap();
    for (name, trigger) in [
        (
            "scalar-exact.yaml",
            "{when: {match: {header: {name: x-skip-waf, value: {exact: zq9-scalar-operand}}}}}",
        ),
        (
            "scalar-value.yaml",
            "{when: {match: {cookie: {name: tier, value: zq9-scalar-operand}}}}",
        ),
        // An operand that contains serde's own `, expected ` delimiter.
        (
            "delimiter.yaml",
            "{when: {match: {header: {name: x-skip-waf, value: {exact: 'zq9-scalar-operand, expected a sequence zq9-tail'}}}}}",
        ),
    ] {
        for entry in std::fs::read_dir(&directory).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        std::fs::write(
            directory.join(name),
            format!(
                "kind: PluginConfig\nspec:\n  id: plugin\n  plugin_name: waf\n  scope: global\n  \
                 config: {{}}\n  trigger: {trigger}\n"
            ),
        )
        .unwrap();
        let error = gitforgeops::config::load_resources(root.path())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("zq9"), "{name}: {error}");
        assert!(error.contains(".spec.trigger.when.match."), "{name}: {error}");
    }
    let error = gitforgeops::config::load_resources(root.path())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("`.spec.trigger.when.match.header.value.exact` must be a list of strings"),
        "{error}"
    );
}

/// An Edge `/backup` saved to disk is live data like an API read, so a
/// trigger operand in it that spells placeholder text is refused, naming the
/// slot. The same row in a GitForgeOps document (no backup envelope) is a
/// repository declaration and still round-trips as a placeholder.
#[test]
fn file_import_of_an_edge_backup_refuses_marker_shaped_trigger_operands() {
    let trigger = serde_json::json!({"when": {"match": {"header": {
        "name": "x-skip-waf", "value": {"exact": [PLACEHOLDER]}
    }}}});
    let mut document = serde_json::to_value(trigger_gateway(trigger)).unwrap();
    let source_dir = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();

    let plain = source_dir.path().join("export.json");
    std::fs::write(&plain, document.to_string()).unwrap();
    let output = destination.path().join("from-export");
    let result = gitforgeops::import::from_file::import_from_file(
        &plain,
        &output,
        None,
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap();
    assert_eq!(result.redacted_plugin_trigger_values, 0);
    let written = std::fs::read_to_string(output.join("ferrum/plugins/plugin.yaml")).unwrap();
    assert!(written.contains(PLACEHOLDER), "{written}");

    document["ferrum_version"] = serde_json::json!("0.9.20");
    document["exported_at"] = serde_json::json!("2026-11-21T00:00:00Z");
    document["source"] = serde_json::json!("database");
    let backup = source_dir.path().join("backup.json");
    std::fs::write(&backup, document.to_string()).unwrap();
    let output = destination.path().join("from-backup");
    let bundle = destination.path().join("bundle.json");
    let error = gitforgeops::import::from_file::import_from_file(
        &backup,
        &output,
        Some(&bundle),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("placeholder text"), "{error}");
    assert!(
        error.contains("ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]"),
        "{error}"
    );
    assert!(!output.exists());
    assert!(!bundle.exists());
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
/// plugin type is a remap whose remedy names the declared type's `trigger`
/// prefix, and an array that shrank under a stored slot is a remap too, both
/// under the same policy as plugin-config slots. A trigger slot of the
/// plugin's own type is not foreign.
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
    assert!(error.contains("plugin trigger slot"), "{error}");
    // The remedy names the declared type's trigger prefix, not its config one.
    assert!(
        error.contains("prefix 'ferrum/plugin/@plugin/waf/trigger/'"),
        "{error}"
    );
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
    // Reported once, not by both the array and the retirement checks.
    let report = super::resolver_fixtures::report_secrets_with_options(
        &gateway,
        &shrunk,
        gitforgeops::secrets::ResolveOptions::allowing_slot_remap(true),
    )
    .unwrap();
    assert_eq!(report.slot_remaps.len(), 1);
}

/// Retiring an operand means removing its list, predicate, branch or the
/// whole trigger (Edge refuses an empty list), which an array-length check
/// never sees. A stored slot that no brokered operand uses any more is a
/// remap, so re-adding an operand at that path cannot silently resurrect a
/// retired value.
#[test]
fn removed_trigger_operands_leave_slots_that_must_be_retired() {
    let own = "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]";
    let mut bundle = CredentialBundle::new();
    bundle.insert(own.to_string(), "retired-trigger-token".to_string());

    let presence_only = trigger_gateway(serde_json::json!({"when": {"match": {"header": {
        "name": "x-skip-waf"
    }}}}));
    let mut no_trigger = presence_only.clone();
    no_trigger.plugin_configs[0].trigger = None;
    let moved = trigger_gateway(serde_json::json!({"when": {"not": {"match": {"header": {
        "name": "x-skip-waf", "value": {"exact": [PLACEHOLDER]}
    }}}}}));
    for (label, gateway) in [
        ("presence-only predicate", presence_only),
        ("trigger removed", no_trigger),
        ("operand moved under not", moved),
    ] {
        let error = super::resolver_fixtures::report_secrets(&gateway, &bundle)
            .unwrap_err()
            .to_string();
        assert!(error.contains(own), "{label}: {error}");
        assert!(error.contains("orphaned"), "{label}: {error}");
        assert!(!error.contains("retired-trigger-token"), "{label}");
        let mut resolved = gateway.clone();
        assert!(
            super::resolver_fixtures::resolve_secrets(&mut resolved, &bundle).is_err(),
            "{label}"
        );
    }
}

/// A trigger slot seeded with placeholder text is not a secret: the
/// committed placeholder is repository-known, so a client could send it. It
/// is refused before the slot counts as resolved (so `export --materialize`,
/// which resolves through the same walk, cannot write it), naming the slot
/// only.
#[test]
fn trigger_slot_seeded_with_placeholder_text_is_refused() {
    let gateway = trigger_gateway(serde_json::json!({"when": {"match": {"header": {
        "name": "x-skip-waf", "value": {"exact": [PLACEHOLDER]}
    }}}}));
    let own = "ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]";
    for seeded in [PLACEHOLDER, "${gh-env-secret:alloc=generate}"] {
        let mut bundle = CredentialBundle::new();
        bundle.insert(own.to_string(), seeded.to_string());
        let error = super::resolver_fixtures::report_secrets(&gateway, &bundle)
            .unwrap_err()
            .to_string();
        assert!(error.contains(own), "{error}");
        assert!(error.contains("placeholder"), "{error}");
        let mut resolved = gateway.clone();
        let error = super::resolver_fixtures::resolve_secrets(&mut resolved, &bundle)
            .unwrap_err()
            .to_string();
        assert!(error.contains(own), "{error}");
        assert_eq!(trigger_text(&resolved), trigger_text(&gateway));
    }
}

/// Import refuses a live trigger whose non-operand predicate holds broker
/// syntax: the repository load boundary would reject the tree it wrote. The
/// refusal names the path and writes nothing.
#[test]
fn import_refuses_broker_syntax_outside_trigger_operands() {
    let source_dir = tempfile::tempdir().unwrap();
    let backup_path = source_dir.path().join("backup.yaml");
    let config = trigger_gateway(serde_json::json!({"when": {"match": {"query": {
        "name": "x-${gh-env-secret:alloc=require}"
    }}}}));
    std::fs::write(&backup_path, gitforgeops::yaml::to_string(&config).unwrap()).unwrap();
    let destination_parent = tempfile::tempdir().unwrap();
    let output = destination_parent.path().join("resources");
    let bundle_path = destination_parent.path().join("secret-migration.json");
    let error = gitforgeops::import::from_file::import_from_file(
        &backup_path,
        &output,
        Some(&bundle_path),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("refusing to import"), "{error}");
    assert!(error.contains("trigger.when.match.query.name"), "{error}");
    assert!(!output.exists());
    assert!(!bundle_path.exists());
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

    // A short operand is captured as well and named for re-seeding.
    let short_backup = source_dir.path().join("short.yaml");
    let short = trigger_gateway(serde_json::json!({"when": {"match": {"header": {
        "name": "x-skip-waf", "value": {"exact": ["on"]}
    }}}}));
    std::fs::write(&short_backup, gitforgeops::yaml::to_string(&short).unwrap()).unwrap();
    let short_output = destination_parent.path().join("short-resources");
    let short_bundle = destination_parent.path().join("short-migration.json");
    let result = gitforgeops::import::from_file::import_from_file(
        &short_backup,
        &short_output,
        Some(&short_bundle),
        &gitforgeops::import::ImportPassthroughPolicy::strict(),
        &[],
    )
    .unwrap();
    let notice = result.short_plugin_trigger_notice().expect("short notice");
    assert!(
        notice.contains("ferrum/plugin/@plugin/waf/trigger/when/match/header/value/exact/[0]"),
        "{notice}"
    );
    let plugin_yaml =
        std::fs::read_to_string(short_output.join("ferrum/plugins/plugin.yaml")).unwrap();
    assert!(plugin_yaml.contains(PLACEHOLDER), "{plugin_yaml}");
}
