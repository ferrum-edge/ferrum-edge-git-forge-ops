use std::collections::BTreeMap;

use gitforgeops::config::schema::{Consumer, GatewayConfig};
use gitforgeops::secrets::{
    bundle::{pick_shard, shard_secret_name},
    load_bundles_from_env, parse_placeholder, resolve_secrets, PlaceholderAlloc, SlotStatus,
};

#[test]
fn parse_placeholder_recognizes_valid_syntax() {
    let p = parse_placeholder("${gh-env-secret:alloc=generate}")
        .unwrap()
        .unwrap();
    assert_eq!(p.alloc, PlaceholderAlloc::Generate);
    assert_eq!(p.length_bytes, 32);

    let p = parse_placeholder("${gh-env-secret:alloc=require|len=48}")
        .unwrap()
        .unwrap();
    assert_eq!(p.alloc, PlaceholderAlloc::Require);
    assert_eq!(p.length_bytes, 48);

    let p = parse_placeholder("${gh-env-secret:}").unwrap().unwrap();
    assert_eq!(p.alloc, PlaceholderAlloc::Require); // default

    let p = parse_placeholder("${gh-env-secret:alloc=rotate}")
        .unwrap()
        .unwrap();
    assert_eq!(p.alloc, PlaceholderAlloc::Rotate);
}

#[test]
fn parse_placeholder_rejects_unknown_alloc() {
    let err = parse_placeholder("${gh-env-secret:alloc=steal}")
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("steal"));
}

#[test]
fn parse_placeholder_rejects_out_of_range_length() {
    let err = parse_placeholder("${gh-env-secret:alloc=generate|len=4}")
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("out of range"));

    let err = parse_placeholder("${gh-env-secret:alloc=generate|len=512}")
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("out of range"));
}

#[test]
fn parse_placeholder_ignores_non_matching_strings() {
    assert!(parse_placeholder("plain value").is_none());
    assert!(parse_placeholder("${env:FOO}").is_none());
    assert!(parse_placeholder("${gh-env-secret:alloc=generate").is_none()); // no closing brace
}

#[test]
fn load_bundles_handles_file_path_route() {
    // Verify load_bundles_from_env is happy with the same JSON whether it
    // comes from an inline env var or a file. The file route is what the
    // workflows now use to avoid env-block size limits at scale.
    let raw = r#"{"FERRUM_CREDS_BUNDLE": "{\"ferrum/app/api_key\":\"v1\"}"}"#;
    let (merged_from_inline, _) = load_bundles_from_env(raw).unwrap();

    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, raw.as_bytes()).unwrap();
    let contents = std::fs::read_to_string(file.path()).unwrap();
    let (merged_from_file, _) = load_bundles_from_env(&contents).unwrap();

    assert_eq!(merged_from_inline, merged_from_file);
    assert_eq!(
        merged_from_file.get("ferrum/app/api_key"),
        Some(&"v1".to_string())
    );
}

#[test]
fn load_bundles_parses_merged_map() {
    let raw = r#"{
        "FERRUM_CREDS_BUNDLE": "{\"ferrum/app/api_key\":\"v1\"}",
        "FERRUM_CREDS_BUNDLE_1": "{\"ferrum/app2/api_key\":\"v2\"}",
        "UNRELATED_SECRET": "ignored"
    }"#;
    let (merged, per_shard) = load_bundles_from_env(raw).unwrap();
    assert_eq!(merged.get("ferrum/app/api_key"), Some(&"v1".to_string()));
    assert_eq!(merged.get("ferrum/app2/api_key"), Some(&"v2".to_string()));
    assert_eq!(merged.len(), 2);
    assert_eq!(per_shard.len(), 2);
    assert!(per_shard.contains_key(&0));
    assert!(per_shard.contains_key(&1));
}

#[test]
fn load_bundles_rejects_duplicate_slots_across_shards() {
    let raw = r#"{
        "FERRUM_CREDS_BUNDLE": "{\"ferrum/app/api_key\":\"v1\"}",
        "FERRUM_CREDS_BUNDLE_1": "{\"ferrum/app/api_key\":\"v2\"}"
    }"#;

    let err = load_bundles_from_env(raw).unwrap_err().to_string();

    assert!(
        err.contains("appears in multiple bundle shards"),
        "expected duplicate-slot error, got: {err}"
    );
}

#[test]
fn shard_secret_name_strips_suffix_for_shard_zero() {
    assert_eq!(shard_secret_name(0), "FERRUM_CREDS_BUNDLE");
    assert_eq!(shard_secret_name(3), "FERRUM_CREDS_BUNDLE_3");
}

#[test]
fn existing_slot_stays_on_its_current_shard() {
    // Verifies the invariant that allocate_and_deliver must honor:
    // once a slot lives on shard N, subsequent writes should find it on N
    // regardless of how shard_count has grown. pick_shard alone wouldn't
    // guarantee this; allocate_and_deliver now consults the per-shard map
    // first. This test covers the bookkeeping directly.
    use gitforgeops::secrets::bundle::{pick_shard, CredentialBundle};

    let slot = "ferrum/app/api_key";

    // Start with the slot on shard 0.
    let mut shards: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
    shards
        .entry(0)
        .or_default()
        .insert(slot.to_string(), "v0".to_string());

    // Expand shard_count to 4 — as if we've grown since initial allocation.
    let shard_count = 4;

    // pick_shard would hash-pick among 0..4, which may or may not return 0.
    // The right behavior (as implemented in allocate_and_deliver) is to
    // notice existing_shard == Some(0) and keep writing there, so the
    // stale copy can't linger on a different shard.
    let existing = shards
        .iter()
        .find_map(|(s, bundle)| bundle.contains_key(slot).then_some(*s));
    assert_eq!(existing, Some(0));

    // Sanity: pick_shard is still deterministic for new slots.
    let fresh = pick_shard("ferrum/other/cred", 32, &shards, shard_count).unwrap();
    assert!(fresh < shard_count);
}

#[test]
fn pick_shard_is_deterministic_and_within_bounds() {
    let shards = BTreeMap::new();
    let a = pick_shard("slot-a", 32, &shards, 4).unwrap();
    let a_again = pick_shard("slot-a", 32, &shards, 4).unwrap();
    assert_eq!(a, a_again);
    assert!(a < 4);
}

#[test]
fn pick_shard_falls_back_to_other_shards_when_hash_target_full() {
    // A full hash-target shard must not hide free space on other existing
    // shards. Probe the remaining shards 0..shard_count before signaling
    // overflow.
    use gitforgeops::secrets::bundle::{pick_shard, CredentialBundle, BUNDLE_SOFT_LIMIT_BYTES};

    // Build 4 shards. Fill the slot's hash-target with junk past the soft
    // limit; leave the others empty.
    let slot = "ferrum/app/big-cred";
    let value_len = 256;
    let shard_count: u32 = 4;

    // Find which shard the hash points to (with empty shards, target is
    // selected purely by hash).
    let empty: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
    let target = pick_shard(slot, value_len, &empty, shard_count).unwrap();

    let mut shards: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
    let stuffing: String = "x".repeat(BUNDLE_SOFT_LIMIT_BYTES);
    shards
        .entry(target)
        .or_default()
        .insert("filler".to_string(), stuffing);

    let chosen = pick_shard(slot, value_len, &shards, shard_count)
        .expect("must find capacity in another shard, not return None");
    assert_ne!(
        chosen, target,
        "slot landed on the full hash-target instead of probing free shards"
    );
    assert!(chosen < shard_count);
}

#[test]
fn pick_shard_returns_none_only_when_all_shards_full() {
    // Probing must NOT mask a genuinely-full state — the caller still
    // needs the None signal to grow shard_count. Fill every shard past
    // the soft limit and confirm pick_shard returns None.
    use gitforgeops::secrets::bundle::{pick_shard, CredentialBundle, BUNDLE_SOFT_LIMIT_BYTES};

    let slot = "ferrum/app/another-cred";
    let value_len = 64;
    let shard_count: u32 = 3;

    let mut shards: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
    for s in 0..shard_count {
        shards
            .entry(s)
            .or_default()
            .insert(format!("filler-{s}"), "x".repeat(BUNDLE_SOFT_LIMIT_BYTES));
    }

    assert!(
        pick_shard(slot, value_len, &shards, shard_count).is_none(),
        "every shard is full; pick_shard must signal overflow with None"
    );
}

#[test]
fn resolver_replaces_known_slot_and_reports_resolved() {
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=require}".to_string()),
    );
    cfg.consumers.push(consumer);

    let mut bundle = BTreeMap::new();
    bundle.insert("ferrum/app/api_key".to_string(), "abcdef".to_string());

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
    assert_eq!(
        cfg.consumers[0].credentials.get("api_key").unwrap(),
        &serde_json::Value::String("abcdef".to_string())
    );
}

#[test]
fn resolver_reports_missing_required() {
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=require}".to_string()),
    );
    cfg.consumers.push(consumer);

    let bundle = BTreeMap::new();
    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.missing_required().len(), 1);
}

#[test]
fn report_secrets_does_not_mutate_config() {
    // File-mode apply MUST NOT replace `alloc=require` or `alloc=generate`
    // placeholders in `desired` before serializing to disk — otherwise
    // resolved values would land in the committed YAML. `report_secrets`
    // is the non-mutating path that file mode uses.
    use gitforgeops::secrets::report_secrets;

    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let placeholder = "${gh-env-secret:alloc=require}";
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String(placeholder.to_string()),
    );
    cfg.consumers.push(consumer);

    let mut bundle = BTreeMap::new();
    // Populate a matching bundle entry — resolve_secrets WOULD replace this,
    // but report_secrets must leave it alone.
    bundle.insert("ferrum/app/api_key".to_string(), "real-secret".to_string());

    let report = report_secrets(&cfg, &bundle).unwrap();

    // Report was populated correctly.
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, SlotStatus::Resolved);

    // Critical: `cfg` was NOT mutated.
    assert_eq!(
        cfg.consumers[0].credentials.get("api_key").unwrap(),
        &serde_json::Value::String(placeholder.to_string()),
        "report_secrets must not replace placeholders; doing so would leak credentials into the committed file-mode YAML"
    );
}

#[test]
fn skipping_resolve_preserves_placeholder_strings_verbatim() {
    // Simulates the `export` (without `--materialize`) path: we never call
    // resolve_secrets, so the placeholder lives on through YAML serialization
    // and is safe to commit.
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let placeholder = "${gh-env-secret:alloc=generate}";
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String(placeholder.to_string()),
    );
    cfg.consumers.push(consumer);

    // Intentionally don't call resolve_secrets — this is the export-without-
    // materialize path.
    let yaml = serde_yaml::to_string(&cfg).unwrap();
    assert!(
        yaml.contains(placeholder),
        "placeholder must survive YAML serialization when not materialized; got:\n{yaml}"
    );
    // And confirm no plaintext "leaked" — there's no way a real secret could
    // be in the output since we never touched the bundle.
    assert!(!yaml.contains("randomsecret"));
}

#[test]
fn resolver_replaces_rotate_placeholder_with_bundle_value() {
    // `alloc=rotate` with a valid bundle entry must resolve to that value —
    // identical to `alloc=generate`. Leaving the placeholder literal in
    // place would cause persistent false drift in diff/plan/review and
    // break `drift-check.yml --exit-on-drift`. Re-rotation of an already-
    // allocated slot is an explicit `gitforgeops rotate` operation, not
    // something apply/diff does automatically.
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=rotate}".to_string()),
    );
    cfg.consumers.push(consumer);

    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/api_key".to_string(),
        "current-allocated-value".to_string(),
    );

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(
        report.results[0].status,
        SlotStatus::Resolved,
        "rotate placeholder with a bundle entry should classify as Resolved (same as generate)"
    );
    assert_eq!(
        cfg.consumers[0].credentials.get("api_key").unwrap(),
        &serde_json::Value::String("current-allocated-value".to_string()),
        "rotate placeholder should resolve to the bundle value"
    );
}

#[test]
fn resolver_reports_rotate_without_bundle_value_as_needs_allocation() {
    // First-apply rotate: no bundle value yet. Classify as NeedsAllocation
    // so the allocator generates an initial value. Same semantics as
    // first-apply generate.
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=rotate}".to_string()),
    );
    cfg.consumers.push(consumer);

    let empty = BTreeMap::new();
    let report = resolve_secrets(&mut cfg, &empty).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, SlotStatus::NeedsAllocation);
}

#[test]
fn resolver_reports_needs_allocation_for_generate() {
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    cfg.consumers.push(consumer);

    let bundle = BTreeMap::new();
    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.needs_allocation().len(), 1);
}

#[test]
fn flat_and_nested_credentials_produce_distinct_slots() {
    // Escaped component paths keep a flat key `basic_auth.password` distinct
    // from a nested `basic_auth: { password: ... }` credential. The flat key
    // stays a single component (literal dot kept), and the nested path uses
    // two components.
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    // Flat top-level key with a literal dot in its name.
    consumer.credentials.insert(
        "basic_auth.password".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    // Nested object with the same logical dotted-name.
    let mut nested = serde_json::Map::new();
    nested.insert(
        "password".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    consumer
        .credentials
        .insert("basic_auth".to_string(), serde_json::Value::Object(nested));
    cfg.consumers.push(consumer);

    let bundle = BTreeMap::new();
    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    let slots: Vec<_> = report.results.iter().map(|r| r.slot.as_str()).collect();
    assert_eq!(slots.len(), 2, "each placeholder should get its own slot");
    assert!(
        slots.contains(&"ferrum/app/basic_auth.password"),
        "flat key slot missing from {slots:?}"
    );
    assert!(
        slots.contains(&"ferrum/app/basic_auth/password"),
        "nested path slot missing from {slots:?}"
    );
}

#[test]
fn resolver_reads_legacy_dotted_slot_for_nested_credentials() {
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let mut nested = serde_json::Map::new();
    nested.insert(
        "password".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    consumer
        .credentials
        .insert("basic_auth".to_string(), serde_json::Value::Object(nested));
    cfg.consumers.push(consumer);

    // Legacy bundle key used by pre-migration resolver behavior.
    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/basic_auth.password".to_string(),
        "legacy-secret".to_string(),
    );

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
    assert_eq!(
        cfg.consumers[0].credentials.get("basic_auth").unwrap(),
        &serde_json::Value::Object({
            let mut m = serde_json::Map::new();
            m.insert(
                "password".to_string(),
                serde_json::Value::String("legacy-secret".to_string()),
            );
            m
        })
    );
}

#[test]
fn slot_components_escape_slash_and_tilde_in_names() {
    // Namespaces/consumer-ids can in principle contain `/` or `~`. Those
    // characters are significant to the slot-path encoding (separator
    // and escape prefix) and must be escaped inside component values to
    // keep the encoding injective.
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "weird/id".to_string(),
        username: "weird/id".to_string(),
        namespace: "ns~with~tilde".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    cfg.consumers.push(consumer);

    let bundle = BTreeMap::new();
    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results.len(), 1);
    // `~` → `~0`, `/` → `~1`
    assert_eq!(report.results[0].slot, "ns~0with~0tilde/weird~1id/api_key");
}

#[test]
fn object_key_with_bracket_distinct_from_array_index() {
    // A literal object key `[0]` could collide with the array-index
    // component `[0]` emitted by the walker unless `[` is escaped inside
    // literal keys. Check that `foo: {"[0]": ...}` and `foo: [...]` with
    // a placeholder at index 0 produce distinct slots.
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    // Object with a literal "[0]" key.
    let mut bracket_obj = serde_json::Map::new();
    bracket_obj.insert(
        "[0]".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    consumer.credentials.insert(
        "literal".to_string(),
        serde_json::Value::Object(bracket_obj),
    );
    // Object with a literal "[1]" key.
    let mut bracket_obj_one = serde_json::Map::new();
    bracket_obj_one.insert(
        "[1]".to_string(),
        serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
    );
    consumer.credentials.insert(
        "literal_one".to_string(),
        serde_json::Value::Object(bracket_obj_one),
    );
    // Actual array with placeholder elements at index 0 and index 1.
    consumer.credentials.insert(
        "arr".to_string(),
        serde_json::Value::Array(vec![
            serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
            serde_json::Value::String("${gh-env-secret:alloc=generate}".to_string()),
        ]),
    );
    cfg.consumers.push(consumer);

    let bundle = BTreeMap::new();
    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    let slots: Vec<_> = report.results.iter().map(|r| r.slot.as_str()).collect();
    assert_eq!(slots.len(), 4);
    // `[` in object key escapes to `~2`; `]` is kept literal. Array index
    // emits `[N]` via the SlotComponent::ArrayIndex path without escape,
    // so the two forms remain distinct.
    assert!(
        slots.contains(&"ferrum/app/literal/~20]"),
        "literal [0] key should escape bracket: {slots:?}"
    );
    assert!(
        slots.contains(&"ferrum/app/literal_one/~21]"),
        "literal [1] key should escape bracket: {slots:?}"
    );
    // Index 0 is elided (legacy-compatible name); index 1 keeps its bracket.
    assert!(
        slots.contains(&"ferrum/app/arr"),
        "array index 0 should be elided: {slots:?}"
    );
    assert!(
        slots.contains(&"ferrum/app/arr/[1]"),
        "array index 1 should emit literal [1]: {slots:?}"
    );
}

#[test]
fn slot_path_matches_walker_for_nested_credentials_and_tilde() {
    // `gitforgeops rotate --credential <X>` calls slot_path(ns, id, X) to
    // look up the slot. report_secrets walks `consumer.credentials` and
    // recurses into nested objects, emitting one slot per leaf placeholder.
    //
    // Verify slot_path round-trips against the walker for the cases the CLI
    // is expected to support:
    //   - flat top-level key with a string placeholder
    //   - nested object placeholder addressed via `parent/child` in the CLI
    //   - keys containing `~` (must escape consistently in both directions)
    //
    // Literal `/` inside a flat key is intentionally NOT supported here —
    // see slot_path's doc comment for the rationale (no CLI escape that
    // round-trips through escape_slot_component without double-escaping).
    use gitforgeops::secrets::{report_secrets, slot_path};

    fn config_with_credential(cred_key: &str, value: serde_json::Value) -> GatewayConfig {
        let mut cfg = GatewayConfig::default();
        let mut consumer = Consumer {
            id: "app".to_string(),
            username: "app".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: Default::default(),
            acl_groups: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        consumer.credentials.insert(cred_key.to_string(), value);
        cfg.consumers.push(consumer);
        cfg
    }

    let placeholder = || serde_json::Value::String("${gh-env-secret:alloc=require}".to_string());

    // Case 1: flat top-level string credential → slot_path("api_key").
    {
        let cfg = config_with_credential("api_key", placeholder());
        let walker_slot = report_secrets(&cfg, &BTreeMap::new())
            .unwrap()
            .results
            .into_iter()
            .next()
            .unwrap()
            .slot;
        let cli_slot = slot_path("ferrum", "app", "api_key");
        assert_eq!(walker_slot, cli_slot, "flat top-level key");
    }

    // Case 2: nested object credential → CLI addresses with "parent/child".
    // This is the primary use case the split-on-`/` design supports —
    // walker recurses through the object value and emits a multi-component
    // slot.
    {
        let mut nested = serde_json::Map::new();
        nested.insert("password".to_string(), placeholder());
        let cfg = config_with_credential("basic_auth", serde_json::Value::Object(nested));
        let walker_slot = report_secrets(&cfg, &BTreeMap::new())
            .unwrap()
            .results
            .into_iter()
            .next()
            .unwrap()
            .slot;
        let cli_slot = slot_path("ferrum", "app", "basic_auth/password");
        assert_eq!(walker_slot, cli_slot, "nested object credential");
    }

    // Case 3: top-level key with `~` character. Walker treats it as a
    // single literal and escapes `~` → `~0`. CLI sees no `/`, so it also
    // produces a single literal segment with the same escape.
    {
        let cfg = config_with_credential("foo~bar", placeholder());
        let walker_slot = report_secrets(&cfg, &BTreeMap::new())
            .unwrap()
            .results
            .into_iter()
            .next()
            .unwrap()
            .slot;
        let cli_slot = slot_path("ferrum", "app", "foo~bar");
        assert_eq!(walker_slot, cli_slot, "top-level key containing ~");
    }
}

#[test]
fn pick_shard_with_staging_prevents_oversized_shard_in_batch() {
    // Allocation stages planned inserts during phase 1, so each candidate's
    // projected size accounts for earlier candidates in the same run. With
    // shard_count=1, every slot hashes to shard 0; without staging, phase 2
    // could serialize one oversized shard.
    use gitforgeops::secrets::bundle::{pick_shard, CredentialBundle};

    // 600-byte values × ~80 candidates ≈ 48 KB → well over the 40 KB soft
    // limit on a single shard.
    let value_len = 600usize;
    let candidate_count = 80usize;

    // Without staging: pick_shard against the same empty `shards` always
    // succeeds for shard 0, regardless of how many we've already planned.
    {
        let shards: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
        let mut allowed_to_zero = 0usize;
        for i in 0..candidate_count {
            let slot = format!("ferrum/app/cred-{i}");
            if pick_shard(&slot, value_len, &shards, 1) == Some(0) {
                allowed_to_zero += 1;
            }
        }
        assert_eq!(
            allowed_to_zero, candidate_count,
            "without staging, pick_shard wrongly accepts every candidate onto shard 0"
        );
    }

    // With staging (the new behavior): mutate a clone after each pick. Once
    // the projected shard size crosses the soft limit, pick_shard returns
    // None and the caller would grow shard_count.
    {
        let mut staged: BTreeMap<u32, CredentialBundle> = BTreeMap::new();
        let mut admitted_to_zero = 0usize;
        let mut rejected = 0usize;
        for i in 0..candidate_count {
            let slot = format!("ferrum/app/cred-{i}");
            match pick_shard(&slot, value_len, &staged, 1) {
                Some(0) => {
                    staged
                        .entry(0)
                        .or_default()
                        .insert(slot, "x".repeat(value_len));
                    admitted_to_zero += 1;
                }
                Some(other) => panic!("shard_count=1 must yield shard 0, got {other}"),
                None => rejected += 1,
            }
        }
        assert!(
            admitted_to_zero < candidate_count,
            "staging must reject some candidates once shard 0 fills"
        );
        assert!(rejected > 0, "at least one candidate must be rejected");
    }
}

// ---------------------------------------------------------------------------
// Canonical array-form credentials
//
// ferrum-edge stores every consumer credential type as an ARRAY of entries
// (`keyauth: [{key: "..."}]`). gitforgeops normalizes the bare-object form in
// the assembler, and the slot encoding elides array index 0 so that
// normalization does not rename — and thereby orphan — slots that were
// allocated back when the object form was what the examples shipped.
// ---------------------------------------------------------------------------

fn consumer_with(cred_key: &str, value: serde_json::Value) -> GatewayConfig {
    let mut cfg = GatewayConfig::default();
    let mut consumer = Consumer {
        id: "app".to_string(),
        username: "app".to_string(),
        namespace: "ferrum".to_string(),
        custom_id: None,
        credentials: Default::default(),
        acl_groups: vec![],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    consumer.credentials.insert(cred_key.to_string(), value);
    cfg.consumers.push(consumer);
    cfg
}

fn entry(field: &str, value: &str) -> serde_json::Value {
    serde_json::json!({ field: value })
}

const GENERATE: &str = "${gh-env-secret:alloc=generate}";
const REQUIRE: &str = "${gh-env-secret:alloc=require}";

#[test]
fn object_and_array_credential_forms_derive_the_same_slot() {
    // THE upgrade-safety invariant. A repo that shipped
    // `keyauth: {key: "${...}"}` allocated `ferrum/app/keyauth/key`. After
    // assembler normalization the same credential is
    // `keyauth: [{key: "${...}"}]` — and must still derive
    // `ferrum/app/keyauth/key`, or every existing consumer's API key gets
    // regenerated and redelivered on the next apply.
    use gitforgeops::secrets::report_secrets;

    let object_form = consumer_with("keyauth", entry("key", REQUIRE));
    let array_form = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", REQUIRE)]),
    );

    let slot_of = |cfg: &GatewayConfig| {
        report_secrets(cfg, &BTreeMap::new())
            .unwrap()
            .results
            .into_iter()
            .next()
            .unwrap()
            .slot
    };

    assert_eq!(slot_of(&object_form), "ferrum/app/keyauth/key");
    assert_eq!(
        slot_of(&array_form),
        slot_of(&object_form),
        "array index 0 must render as the legacy unindexed slot name"
    );
}

#[test]
fn second_array_entry_gets_an_indexed_slot() {
    // Index >= 1 appends `[N]`, so a consumer with two keyauth entries gets
    // two distinct slots rather than colliding on one.
    use gitforgeops::secrets::report_secrets;

    let cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", REQUIRE), entry("key", REQUIRE)]),
    );

    let report = report_secrets(&cfg, &BTreeMap::new()).unwrap();
    let mut slots: Vec<_> = report.results.iter().map(|r| r.slot.clone()).collect();
    slots.sort();
    assert_eq!(
        slots,
        vec![
            "ferrum/app/keyauth/[1]/key".to_string(),
            "ferrum/app/keyauth/key".to_string(),
        ]
    );
}

#[test]
fn slot_path_addresses_array_entries_from_the_cli() {
    use gitforgeops::secrets::slot_path;

    // Index 0 is elided, and an explicit `[0]` normalizes to the same slot.
    assert_eq!(
        slot_path("ferrum", "app", "keyauth/key"),
        "ferrum/app/keyauth/key"
    );
    assert_eq!(
        slot_path("ferrum", "app", "keyauth/[0]/key"),
        "ferrum/app/keyauth/key"
    );
    // Index >= 1 stays addressable — otherwise `gitforgeops rotate` could
    // never reach a consumer's second credential.
    assert_eq!(
        slot_path("ferrum", "app", "keyauth/[1]/key"),
        "ferrum/app/keyauth/[1]/key"
    );
    // Real credential types round-trip.
    for (cred, field) in [
        ("keyauth", "key"),
        ("jwt", "secret"),
        ("hmac_auth", "secret"),
        ("mtls_auth", "identity"),
        ("basicauth", "password"),
    ] {
        assert_eq!(
            slot_path("ferrum", "app", &format!("{cred}/{field}")),
            format!("ferrum/app/{cred}/{field}")
        );
    }
}

#[test]
fn slot_path_matches_walker_for_array_form_credentials() {
    // `gitforgeops rotate --credential keyauth/key` must find the slot the
    // walker emits for the canonical array form.
    use gitforgeops::secrets::{report_secrets, slot_path};

    let cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", REQUIRE), entry("key", REQUIRE)]),
    );
    let report = report_secrets(&cfg, &BTreeMap::new()).unwrap();
    let slots: Vec<_> = report.results.iter().map(|r| r.slot.clone()).collect();

    assert!(slots.contains(&slot_path("ferrum", "app", "keyauth/key")));
    assert!(slots.contains(&slot_path("ferrum", "app", "keyauth/[1]/key")));
}

#[test]
fn placeholder_inside_array_resolves_from_bundle_end_to_end() {
    // The full path the assembler now produces: placeholder nested inside a
    // one-element array, resolved in place from a bundle keyed on the
    // index-elided slot name.
    let mut cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", GENERATE)]),
    );

    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/keyauth/key".to_string(),
        "real-api-key".to_string(),
    );

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
    assert_eq!(report.results[0].cred_key, "keyauth/key");
    assert_eq!(
        cfg.consumers[0].credentials.get("keyauth").unwrap(),
        &serde_json::Value::Array(vec![entry("key", "real-api-key")]),
        "placeholder must be replaced in place, preserving the array shape"
    );
}

#[test]
fn explicit_index_zero_slot_from_an_older_bundle_still_resolves() {
    // A gitforgeops release between "walker handles arrays" and "index 0 is
    // elided" wrote `ferrum/app/keyauth/[0]/key`. That bundle must keep
    // resolving after the upgrade rather than orphaning and re-allocating.
    let mut cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", GENERATE)]),
    );

    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/keyauth/[0]/key".to_string(),
        "older-encoding-value".to_string(),
    );

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
    assert_eq!(
        cfg.consumers[0].credentials.get("keyauth").unwrap(),
        &serde_json::Value::Array(vec![entry("key", "older-encoding-value")])
    );
}

#[test]
fn legacy_dotted_slot_with_array_index_still_resolves() {
    // The oldest encoding: dotted path with a bracketed index.
    let mut cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", GENERATE)]),
    );

    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/keyauth[0].key".to_string(),
        "oldest-encoding-value".to_string(),
    );

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
}

// ---------------------------------------------------------------------------
// Value constraints
// ---------------------------------------------------------------------------

#[test]
fn redacted_sentinel_in_bundle_is_refused() {
    // `[REDACTED]` is what a normal GET returns for keyauth/jwt/hmac_auth
    // secrets — only GET /backup returns real values. A bundle holding it was
    // seeded wrong, and pushing it would install the literal string.
    use gitforgeops::secrets::REDACTED_SENTINEL;

    let mut cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", REQUIRE)]),
    );

    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/keyauth/key".to_string(),
        REDACTED_SENTINEL.to_string(),
    );

    let err = resolve_secrets(&mut cfg, &bundle).unwrap_err().to_string();
    assert!(
        err.contains("[REDACTED]") && err.contains("/backup"),
        "expected reserved-sentinel error, got: {err}"
    );
}

#[test]
fn jwt_generate_with_undersized_len_is_rejected_at_resolve_time() {
    // jwt/hmac_auth secrets must be >= 32 chars. len=16 yields 22 base64url
    // characters, so it must fail at plan time — before any GitHub write.
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    for cred_type in ["jwt", "hmac_auth"] {
        let mut cfg = consumer_with(
            cred_type,
            serde_json::Value::Array(vec![entry(
                "secret",
                "${gh-env-secret:alloc=generate|len=16}",
            )]),
        );
        let err = resolve_secrets_with_mode(&mut cfg, &BTreeMap::new(), GatewayMode::Api)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("at least 32 characters") && err.contains("len=24"),
            "expected {cred_type} minimum-length error, got: {err}"
        );
    }
}

#[test]
fn jwt_generate_with_default_len_is_accepted() {
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    let mut cfg = consumer_with(
        "jwt",
        serde_json::Value::Array(vec![entry("secret", GENERATE)]),
    );
    let report = resolve_secrets_with_mode(&mut cfg, &BTreeMap::new(), GatewayMode::Api).unwrap();
    assert_eq!(report.needs_allocation().len(), 1);
}

#[test]
fn keyauth_generate_with_small_len_is_still_allowed() {
    // The >= 32 char floor is jwt/hmac_auth only; keyauth just needs
    // non-empty and <= 4096.
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    let mut cfg = consumer_with(
        "keyauth",
        serde_json::Value::Array(vec![entry("key", "${gh-env-secret:alloc=generate|len=16}")]),
    );
    let report = resolve_secrets_with_mode(&mut cfg, &BTreeMap::new(), GatewayMode::Api).unwrap();
    assert_eq!(report.needs_allocation().len(), 1);
}

#[test]
fn already_allocated_undersized_jwt_slot_is_not_re_validated() {
    // The length check gates GENERATION. A slot that already has a value
    // resolves normally — we neither regenerate it nor block the apply on a
    // `len=` that is no longer used.
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    let mut cfg = consumer_with(
        "jwt",
        serde_json::Value::Array(vec![entry(
            "secret",
            "${gh-env-secret:alloc=generate|len=16}",
        )]),
    );
    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/jwt/secret".to_string(),
        "a-previously-allocated-secret-of-sufficient-length".to_string(),
    );

    let report = resolve_secrets_with_mode(&mut cfg, &bundle, GatewayMode::Api).unwrap();
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
}

#[test]
fn generate_credential_value_enforces_the_jwt_minimum() {
    // Allocator-side enforcement — the last line of defense for
    // `gitforgeops rotate`, whose --credential never passes through the
    // resolver's placeholder walk.
    use gitforgeops::secrets::generate_credential_value;

    let err = generate_credential_value("ferrum/app/jwt/secret", 16)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("at least 32 characters"),
        "expected minimum-length error, got: {err}"
    );

    let err = generate_credential_value("ferrum/app/hmac_auth/secret", 23)
        .unwrap_err()
        .to_string();
    assert!(err.contains("at least 32 characters"), "got: {err}");

    // 24 entropy bytes is the floor: exactly 32 base64url characters.
    let ok = generate_credential_value("ferrum/app/jwt/secret", 24).unwrap();
    assert_eq!(ok.chars().count(), 32);

    // Indexed slots resolve to the same credential type.
    assert!(generate_credential_value("ferrum/app/jwt/[1]/secret", 16).is_err());
}

#[test]
fn generate_credential_value_respects_the_value_cap_and_sentinel() {
    use gitforgeops::secrets::{generate_credential_value, MAX_CREDENTIAL_VALUE_CHARS};

    // The placeholder parser caps len= at 256 bytes -> 342 characters, well
    // under the gateway's 4096-character limit. Assert the invariant holds at
    // the top of the range.
    let value = generate_credential_value("ferrum/app/keyauth/key", 256).unwrap();
    assert!(value.chars().count() <= MAX_CREDENTIAL_VALUE_CHARS);
    assert_ne!(value, "[REDACTED]");
    // base64url has no `[`, so the sentinel is structurally unreachable.
    assert!(!value.contains('['));
}

// ---------------------------------------------------------------------------
// basicauth mode-awareness
// ---------------------------------------------------------------------------

#[test]
fn basicauth_generate_is_rejected_in_file_mode() {
    // A file-mode ferrum-edge hard-rejects a plaintext password; only the
    // admin API hashes one on write.
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    let mut cfg = consumer_with(
        "basicauth",
        serde_json::Value::Array(vec![entry("password", GENERATE)]),
    );

    let err = resolve_secrets_with_mode(&mut cfg, &BTreeMap::new(), GatewayMode::File)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("file-mode gateways require password_hash")
            && err.contains("FERRUM_BASIC_AUTH_HMAC_SECRET"),
        "expected actionable file-mode basicauth error, got: {err}"
    );
}

#[test]
fn basicauth_generate_is_allowed_in_api_mode() {
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    let mut cfg = consumer_with(
        "basicauth",
        serde_json::Value::Array(vec![entry("password", GENERATE)]),
    );

    let report = resolve_secrets_with_mode(&mut cfg, &BTreeMap::new(), GatewayMode::Api).unwrap();
    assert_eq!(report.needs_allocation().len(), 1);
    assert_eq!(report.results[0].slot, "ferrum/app/basicauth/password");
}

#[test]
fn basicauth_password_hash_generate_is_rejected_in_every_mode() {
    // `hmac_sha256:<64 hex>` is computed with the gateway's server-side
    // secret. Random bytes are never a valid hash, api mode included.
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    for mode in [GatewayMode::Api, GatewayMode::File] {
        let mut cfg = consumer_with(
            "basicauth",
            serde_json::Value::Array(vec![entry("password_hash", GENERATE)]),
        );
        let err = resolve_secrets_with_mode(&mut cfg, &BTreeMap::new(), mode)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot generate a basicauth password_hash"),
            "expected password_hash rejection, got: {err}"
        );
    }
}

#[test]
fn basicauth_already_allocated_resolves_in_file_mode() {
    // The mode check only gates allocation. A file-mode repo that set its own
    // password_hash (or resolved a previously allocated password) is fine.
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::resolve_secrets_with_mode;

    let mut cfg = consumer_with(
        "basicauth",
        serde_json::Value::Array(vec![entry("password_hash", REQUIRE)]),
    );
    let mut bundle = BTreeMap::new();
    bundle.insert(
        "ferrum/app/basicauth/password_hash".to_string(),
        format!("hmac_sha256:{}", "a".repeat(64)),
    );

    let report = resolve_secrets_with_mode(&mut cfg, &bundle, GatewayMode::File).unwrap();
    assert_eq!(report.results[0].status, SlotStatus::Resolved);
}
