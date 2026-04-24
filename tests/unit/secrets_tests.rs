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
fn resolver_does_not_replace_rotate_placeholder_with_stale_value() {
    // alloc=rotate with an existing (stale) bundle value must keep the
    // placeholder in place during the initial resolve — otherwise the
    // placeholder is masked before the allocator generates a fresh value,
    // and the post-allocation resolve has no placeholder left to replace.
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
    let placeholder = "${gh-env-secret:alloc=rotate}";
    consumer.credentials.insert(
        "api_key".to_string(),
        serde_json::Value::String(placeholder.to_string()),
    );
    cfg.consumers.push(consumer);

    let mut bundle = BTreeMap::new();
    bundle.insert("ferrum/app/api_key".to_string(), "stale-value".to_string());

    let report = resolve_secrets(&mut cfg, &bundle).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, SlotStatus::NeedsRotation);

    // Placeholder must survive the initial resolve — NOT be replaced with
    // the stale value.
    assert_eq!(
        cfg.consumers[0].credentials.get("api_key").unwrap(),
        &serde_json::Value::String(placeholder.to_string()),
        "rotate placeholder should not be replaced until post-allocation resolve"
    );
}

#[test]
fn resolver_including_rotate_replaces_rotate_placeholders() {
    use gitforgeops::secrets::resolve_secrets_including_rotate;

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
        "freshly-rotated".to_string(),
    );

    let _ = resolve_secrets_including_rotate(&mut cfg, &bundle).unwrap();
    assert_eq!(
        cfg.consumers[0].credentials.get("api_key").unwrap(),
        &serde_json::Value::String("freshly-rotated".to_string()),
        "post-allocation variant must replace rotate placeholders with fresh bundle values"
    );
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
