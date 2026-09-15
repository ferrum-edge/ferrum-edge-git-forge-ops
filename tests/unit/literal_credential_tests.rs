//! Coverage for `tests/fixtures/literal-credential/` and the brokered
//! `simple-config` sample.
//!
//! `simple-config/` is the copy-paste sample and must assemble without a
//! literal-credential apply blocker. This fixture is the opposite: a
//! committed `keyauth` key so the security gate still has an error-severity
//! finding to refuse. Inline CLI coverage of the same shape lives in
//! `apply_gate_tests.rs`.

use std::path::PathBuf;

use gitforgeops::config::{assemble, load_resources};
use gitforgeops::diff::security::{audit_security, security_blockers};

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
