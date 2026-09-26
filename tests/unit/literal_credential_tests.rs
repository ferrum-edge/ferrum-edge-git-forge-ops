//! Coverage for `tests/fixtures/literal-credential/` and the brokered
//! `simple-config` sample.
//!
//! `simple-config/` is the copy-paste sample and must assemble without a
//! literal-credential apply blocker. This fixture is the opposite: a
//! committed `keyauth` key so the security gate still has an error-severity
//! finding to refuse. Inline CLI coverage of the same shape lives in
//! `apply_gate_tests.rs`.

use std::path::PathBuf;

use gitforgeops::config::{assemble, load_resources, GatewayConfig};
use gitforgeops::diff::security::{audit_security, consumer_security_blockers, security_blockers};

fn simple_config_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple-config")
}

fn literal_credential_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/literal-credential")
}

#[test]
fn simple_config_fixture_uses_a_brokered_placeholder() {
    let resources = load_resources(&simple_config_dir()).unwrap();
    let config = assemble(resources).expect("assemble").gateway;

    assert_eq!(
        config.consumers[0].credentials["keyauth"],
        serde_json::json!([{"key": "${gh-env-secret:alloc=require}"}]),
        "simple-config must ship the brokered on-disk form"
    );

    let findings = audit_security(&config);
    let blockers = security_blockers(&findings);
    assert!(
        blockers
            .iter()
            .all(|finding| !finding.message.contains("Literal credential")),
        "sample must not block apply on a literal credential: {findings:?}"
    );
}

#[test]
fn literal_credential_fixture_blocks_apply_without_echoing_the_value() {
    let resources = load_resources(&literal_credential_dir()).unwrap();
    assert_eq!(
        resources.len(),
        1,
        "literal-credential is a single-consumer negative case"
    );
    let config = assemble(resources).expect("assemble").gateway;
    assert_eq!(config.consumers.len(), 1);
    assert_eq!(config.consumers[0].id, "consumer-literal");

    let findings = audit_security(&config);
    let blockers = security_blockers(&findings);
    assert_eq!(
        blockers.len(),
        1,
        "expected exactly one apply-blocking finding: {findings:?}"
    );
    assert_eq!(blockers[0].kind, "Consumer");
    assert_eq!(blockers[0].id, "consumer-literal");
    assert_eq!(blockers[0].severity, "error");
    assert!(
        blockers[0].message.contains("Literal credential"),
        "{}",
        blockers[0].message
    );
    assert!(
        blockers[0].message.contains("keyauth"),
        "{}",
        blockers[0].message
    );
    for finding in &findings {
        assert!(
            !finding
                .message
                .contains("fixture-only-literal-not-a-secret"),
            "findings must not echo the committed value: {}",
            finding.message
        );
    }
}

/// `rotate` publishes one whole Consumer row, so it audits exactly that row:
/// every literal secret on it blocks, a literal identity does not, and a
/// literal on another Consumer or namespace does not block this rotation.
#[test]
fn consumer_row_blockers_cover_every_credential_on_the_published_row_only() {
    const BROKERED: &str = "${gh-env-secret:alloc=require}";
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "consumers": [
            {
                "id": "app", "username": "app", "namespace": "ferrum",
                "credentials": {
                    "keyauth": [{ "key": BROKERED }, { "key": "row-literal-one" }],
                    "basicauth": [{ "username": "public-identity", "password": BROKERED }],
                    "hmac_auth": [{ "secret": "row-literal-two" }]
                }
            },
            {
                "id": "other", "username": "other", "namespace": "ferrum",
                "credentials": { "keyauth": [{ "key": "other-row-literal" }] }
            },
            {
                "id": "app", "username": "app", "namespace": "platform",
                "credentials": { "keyauth": [{ "key": "other-namespace-literal" }] }
            }
        ]
    }))
    .unwrap();

    let blockers = consumer_security_blockers(&config, "ferrum", "app");
    let mut paths: Vec<&str> = blockers
        .iter()
        .filter_map(|finding| finding.message.split('\'').nth(1))
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, ["hmac_auth[0].secret", "keyauth[1].key"]);
    for finding in &blockers {
        assert_eq!(finding.namespace, "ferrum");
        assert_eq!(finding.id, "app");
        assert!(!finding.message.contains("row-literal"));
    }

    let brokered: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "consumers": [{
            "id": "app", "username": "app", "namespace": "ferrum",
            "credentials": {
                "keyauth": [{ "key": BROKERED }],
                "mtls_auth": [{ "identity": "public-identity" }]
            }
        }]
    }))
    .unwrap();
    assert!(consumer_security_blockers(&brokered, "ferrum", "app").is_empty());
    assert!(consumer_security_blockers(&config, "ferrum", "absent").is_empty());
}

/// YAML reads an unquoted `key: 12345` or `secret: true` as a number or a
/// boolean, not a string. The gateway still receives it as authentication
/// material, so a non-string scalar at a secret leaf blocks like any literal.
/// Identity leaves stay exempt whatever their scalar type.
#[test]
fn non_string_scalar_secret_leaves_are_literal_credentials() {
    let dir = tempfile::TempDir::new().unwrap();
    let consumers = dir.path().join("ferrum/consumers");
    std::fs::create_dir_all(&consumers).unwrap();
    std::fs::write(
        consumers.join("app.yaml"),
        "kind: Consumer\nspec:\n  id: app\n  username: app\n  credentials:\n    keyauth:\n      - key: 12345\n    hmac_auth:\n      - secret: true\n    jwt:\n      - secret: 1.5\n    basicauth:\n      - username: 1001\n        password: '${gh-env-secret:alloc=require}'\n",
    )
    .unwrap();
    let config = assemble(load_resources(dir.path()).unwrap())
        .expect("assemble")
        .gateway;
    let key = &config.consumers[0].credentials["keyauth"][0]["key"];
    assert!(key.is_number(), "fixture must use a YAML integer");

    let findings = audit_security(&config);
    let mut paths: Vec<&str> = security_blockers(&findings)
        .into_iter()
        .filter_map(|finding| finding.message.split('\'').nth(1))
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["hmac_auth[0].secret", "jwt[0].secret", "keyauth[0].key"]
    );
    for finding in &findings {
        assert!(!finding.message.contains("12345"));
    }
}
