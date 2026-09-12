use gitforgeops::validate::{
    build_validate_args_for_mode, format_result, format_results, run_validation,
    scrubbed_env_names, validation_context_env, OutputFormat, ValidationResult,
    GATEWAY_VALIDATE_MODE, MESH_ALLOW_NO_CA_ENV, MESH_VALIDATE_MODE, VALIDATION_STANDIN_PREFIX,
};
use std::path::Path;

#[test]
fn github_annotations_escape_workflow_command_data() {
    let result = ValidationResult {
        success: false,
        exit_code: 1,
        stdout: String::new(),
        stderr: "error: bad value 100%".to_string(),
    };

    let output = format_result(&result, OutputFormat::GithubAnnotations);

    assert_eq!(output, "::error ::error: bad value 100%25\n");
}

#[test]
fn github_annotations_emit_generic_error_when_no_line_matches() {
    let result = ValidationResult {
        success: false,
        exit_code: 2,
        stdout: "schema rejected".to_string(),
        stderr: String::new(),
    };

    let output = format_result(&result, OutputFormat::GithubAnnotations);

    assert_eq!(output, "::error ::Validation failed with exit code 2\n");
}

#[cfg(unix)]
fn echo_validator(dir: &Path, name: &str, script: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let validator = dir.join(name);
    std::fs::write(&validator, script).unwrap();
    let mut permissions = std::fs::metadata(&validator).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&validator, permissions).unwrap();
    validator
}

/// A validator that echoes the spec it was handed on both streams, plus one
/// ordinary schema diagnostic that has nothing to do with credentials.
#[cfg(unix)]
const ECHO_SPEC_WITH_PROXY_ERROR: &str = "#!/bin/sh\ncat \"$7\"\necho 'error: proxy httpbin: unknown field `listen_path_typo`' >&2\ncat \"$7\" >&2\nexit 1\n";

#[cfg(unix)]
fn consumer_config(credentials: serde_json::Value) -> gitforgeops::config::schema::GatewayConfig {
    use gitforgeops::config::schema::{Consumer, GatewayConfig};

    GatewayConfig {
        consumers: vec![Consumer {
            labels: Default::default(),
            extra: Default::default(),
            id: "app".to_string(),
            username: "app".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: credentials
                .as_object()
                .expect("credentials object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            acl_groups: Vec::new(),
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        }],
        ..GatewayConfig::default()
    }
}

/// F1: a resolved (or literal) consumer credential is redacted from the
/// validator's diagnostics, and everything else the validator said survives.
#[cfg(unix)]
#[test]
fn resolved_credentials_are_redacted_but_other_diagnostics_survive() {
    let secret = "launch-secret-that-must-never-reach-diagnostics";
    let config = consumer_config(serde_json::json!({"keyauth": [{"key": secret}]}));

    for exit_code in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let validator = echo_validator(
            dir.path(),
            &format!("echo-validator-{exit_code}"),
            &ECHO_SPEC_WITH_PROXY_ERROR.replace("exit 1", &format!("exit {exit_code}")),
        );

        // Exit 1 is a completed schema rejection and comes back as a
        // `ValidationResult`; any other code is an execution failure and comes
        // back as `Error::ValidateProcess`. Redaction has already run in both
        // cases, so neither carries the secret and both keep the unrelated
        // diagnostic.
        match run_validation(&config, validator.to_str().unwrap()) {
            Ok(result) => {
                assert_eq!(exit_code, 1);
                assert!(!result.success);
                assert!(
                    !result.stdout.contains(secret),
                    "validator stdout exposed a credential fixture"
                );
                assert!(
                    !result.stderr.contains(secret),
                    "validator stderr exposed a credential fixture"
                );
                assert!(
                    result.stdout.contains("[REDACTED]"),
                    "the credential should be replaced in place, not dropped: {}",
                    result.stdout
                );
                assert!(
                    result.stderr.contains("unknown field `listen_path_typo`"),
                    "an unrelated schema diagnostic must stay visible: {}",
                    result.stderr
                );
                // The consumer id still identifies which resource failed.
                assert!(result.stdout.contains("app"), "{}", result.stdout);
            }
            Err(error) => {
                assert_eq!(exit_code, 2);
                let message = error.to_string();
                assert!(
                    message.contains("exited with code 2"),
                    "an abnormal exit must be reported as an execution error: {message}"
                );
                assert!(
                    !message.contains(secret),
                    "validator execution error exposed a credential fixture"
                );
                assert!(
                    message.contains("[REDACTED]"),
                    "the credential should be replaced in place, not dropped: {message}"
                );
                assert!(
                    message.contains("unknown field `listen_path_typo`"),
                    "an unrelated schema diagnostic must stay visible: {message}"
                );
            }
        }
    }
}

/// F1: a committed literal `keyauth.key` is redacted from validator
/// diagnostics, and everything else the validator said survives. The
/// `simple-config` sample is brokered; this uses an inline document so the
/// scrubber still has a known secret to match.
#[cfg(unix)]
#[test]
fn literal_fixture_credentials_do_not_blank_the_diagnostics() {
    let config =
        consumer_config(serde_json::json!({"keyauth": [{"key": "alice-secret-key-12345"}]}));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(
        !result.stderr.contains("alice-secret-key-12345"),
        "{}",
        result.stderr
    );
    assert!(
        result.stderr.contains("unknown field `listen_path_typo`"),
        "{}",
        result.stderr
    );
}

/// F1: `basicauth[].username` and `mtls_auth[].identity` are identities, not
/// secrets, so a diagnostic naming them stays readable.
#[cfg(unix)]
#[test]
fn credential_identity_fields_are_not_redacted() {
    let config = consumer_config(serde_json::json!({
        "basicauth": [{"username": "alice-login", "password": "alice-password-value"}],
        "mtls_auth": [{"identity": "CN=alice.example.internal"}],
    }));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(result.stdout.contains("alice-login"), "{}", result.stdout);
    assert!(
        result.stdout.contains("CN=alice.example.internal"),
        "{}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("alice-password-value"),
        "{}",
        result.stdout
    );
}

#[cfg(unix)]
#[test]
fn provenance_scrubs_legacy_brokered_identities_without_hiding_literal_identities() {
    use gitforgeops::secrets::{parse_placeholder, ResolveReport, ResolveResult, SlotStatus};

    // The resolver now refuses this input. Model a legacy resolved snapshot
    // directly to prove that the output defense does not trust classification
    // alone or blanket-redact every identity in the same document.
    let config = consumer_config(serde_json::json!({
        "basicauth": [
            {"username": "synthetic-legacy-login-secret"},
            {"username": "public-login"}
        ],
        "mtls_auth": [
            {"identity": "synthetic-legacy-mtls-secret"},
            {"identity": "public-client.example"}
        ]
    }));
    let mut report = ResolveReport::default();
    for cred_key in ["basicauth/username", "mtls_auth/identity"] {
        report.results.push(ResolveResult {
            consumer_id: "app".to_string(),
            namespace: "ferrum".to_string(),
            cred_key: cred_key.to_string(),
            slot: format!("ferrum/app/{cred_key}"),
            placeholder: parse_placeholder("${gh-env-secret:alloc=require}")
                .unwrap()
                .unwrap(),
            status: SlotStatus::Resolved,
        });
    }
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "legacy-echo", ECHO_SPEC_WITH_PROXY_ERROR);
    let result = gitforgeops::validate::run_validation_with_report(
        &config,
        validator.to_str().unwrap(),
        &report,
    )
    .unwrap();
    let review = gitforgeops::review::validate_for_review_with_report(
        &config,
        None,
        validator.to_str().unwrap(),
        &report,
    );
    for output in [&result.stdout, &result.stderr, &review.output] {
        assert!(!output.contains("synthetic-legacy-"), "{output}");
        assert!(output.contains("public-login"), "{output}");
        assert!(output.contains("public-client.example"), "{output}");
        assert!(output.contains("[REDACTED]"), "{output}");
    }
}

#[cfg(unix)]
#[test]
fn scrubber_provenance_preserves_canonical_indexed_escaped_slots_and_unresolved_siblings() {
    use gitforgeops::secrets::{resolve_secrets, SecretScrubber};
    use std::collections::BTreeMap;

    let placeholder = "${gh-env-secret:alloc=require}";
    let mut config = consumer_config(serde_json::json!({
        "basicauth": [{"username": "public-login"}],
        "keyauth": [
            {"key": placeholder, "a/b~[1]": placeholder, "unseeded": placeholder},
            {"key": placeholder}
        ]
    }));
    config.plugin_configs.push(
        serde_json::from_value(serde_json::json!({
            "id": "plugin", "namespace": "ferrum", "plugin_name": "custom", "scope": "global",
            "config": {"a/b~[1]": ["public-mode", placeholder]}
        }))
        .unwrap(),
    );
    config.upstreams.push(
        serde_json::from_value(serde_json::json!({
            "id": "discovery", "namespace": "ferrum", "targets": [],
            "service_discovery": {"provider": "consul", "consul": {
                "address": "https://consul.example", "service_name": "orders", "token": placeholder
            }}
        }))
        .unwrap(),
    );
    let slots = [
        "ferrum/app/keyauth/key",
        "ferrum/app/keyauth/a~1b~0~21]",
        "ferrum/app/keyauth/[1]/key",
        "ferrum/plugin/@plugin-config/config/a~1b~0~21]/[1]",
        "ferrum/discovery/@service-discovery/consul/token",
    ];
    let bundle: BTreeMap<String, String> = slots
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            (
                slot.to_string(),
                format!("${{gh-env-secret:alloc=require|len={}}}", 48 + index),
            )
        })
        .collect();
    let report = resolve_secrets(&mut config, &bundle).unwrap();
    assert_eq!(report.results.len(), 6);
    assert_eq!(report.missing_required().len(), 1);
    for slot in slots {
        assert!(report.results.iter().any(|result| result.slot == slot));
    }
    let scrubber = SecretScrubber::from_gateway_config_with_report(&config, &report);
    let text = format!(
        "public-login public-mode {placeholder} {}",
        bundle.values().cloned().collect::<Vec<_>>().join(" ")
    );
    let output = scrubber.scrub_streams(&text, &text);
    assert!(output.suppressed.is_none(), "{output:?}");
    for text in [&output.stdout, &output.stderr] {
        for value in bundle.values() {
            assert!(!text.contains(value), "{text}");
        }
        assert!(
            text.contains(placeholder),
            "unresolved sibling must stay public: {text}"
        );
        assert!(text.contains("public-login public-mode"), "{text}");
    }
}

/// F2: plugin-config secrets brokered by this release are scrubbed too, while
/// the plugin's non-sensitive settings stay visible.
#[cfg(unix)]
#[test]
fn resolved_plugin_config_secrets_are_redacted() {
    use gitforgeops::config::schema::{GatewayConfig, PluginConfig, PluginScope};

    let secret = "honeycomb-team-key-must-not-be-echoed";
    let config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            labels: Default::default(),
            extra: Default::default(),
            id: "otel".to_string(),
            plugin_name: "otel_tracing".to_string(),
            namespace: "ferrum".to_string(),
            config: serde_json::json!({
                "headers": {"x-honeycomb-team": secret},
                "sample_rate": "0.1"
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        }],
        ..GatewayConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(!result.stdout.contains(secret), "{}", result.stdout);
    assert!(!result.stderr.contains(secret), "{}", result.stderr);
    assert!(result.stdout.contains("sample_rate"), "{}", result.stdout);
    assert!(
        result.stderr.contains("unknown field `listen_path_typo`"),
        "{}",
        result.stderr
    );
}

/// A base64-wrapped echo of the credential is removed too.
#[cfg(unix)]
#[test]
fn common_encodings_of_a_secret_are_redacted() {
    use base64::Engine;

    let secret = "encoded-secret-value-should-not-survive";
    let config = consumer_config(serde_json::json!({"keyauth": [{"key": secret}]}));
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(
        dir.path(),
        "encoding-validator",
        &format!("#!/bin/sh\necho 'token={encoded}'\nexit 1\n"),
    );

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(!result.stdout.contains(&encoded), "{}", result.stdout);
    assert_eq!(result.stdout, "token=[REDACTED]\n");
}

/// Last-resort suppression: a credential too short to substring-replace
/// cannot be redacted without mangling the diagnostic, so the stream goes
/// instead of the secret.
#[cfg(unix)]
#[test]
fn a_secret_below_the_scrub_floor_falls_back_to_suppression() {
    let config = consumer_config(serde_json::json!({"keyauth": [{"key": "hunter2"}]}));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(!result.stdout.contains("hunter2"), "{}", result.stdout);
    assert!(!result.stderr.contains("hunter2"), "{}", result.stderr);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("survived redaction"),
        "{}",
        result.stderr
    );
}

#[cfg(unix)]
#[test]
fn validator_diagnostics_remain_available_for_placeholder_only_credentials() {
    let config = consumer_config(
        serde_json::json!({"keyauth": [{"key": "${gh-env-secret:alloc=require}"}]}),
    );
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    // Nothing is redacted: an unresolved placeholder is repository data.
    assert!(!result.stderr.contains("[REDACTED]"), "{}", result.stderr);
    assert!(
        result.stderr.contains("unknown field `listen_path_typo`"),
        "{}",
        result.stderr
    );
}

/// #96, second half: with no bundle loaded, the validator sees a stand-in of
/// adequate shape rather than the 30-character placeholder literal, so a repo
/// brokering a `jwt` or `hmac_auth` secret is graded on its structure.
#[cfg(unix)]
#[test]
fn unresolved_placeholders_reach_the_validator_as_shaped_standins() {
    let config = consumer_config(serde_json::json!({
        "jwt": [{"key": "app-issuer", "secret": "${gh-env-secret:alloc=generate}"}],
        "basicauth": [{
            "username": "app",
            "password_hash": "${gh-env-secret:alloc=require}"
        }],
    }));
    let dir = tempfile::tempdir().unwrap();
    // A validator that enforces ferrum-edge's own shape rules on what it was
    // handed: jwt secrets are >= 32 characters, password hashes are
    // `hmac_sha256:<64 hex>`.
    let validator = echo_validator(
        dir.path(),
        "shape-validator",
        r#"#!/bin/sh
secret=$(sed -n 's/.*[ -]secret: *//p' "$7" | tr -d '"')
hash=$(sed -n 's/.*[ -]password_hash: *//p' "$7" | tr -d '"')
if [ "${#secret}" -lt 32 ]; then
  echo "error: jwt secret must be at least 32 characters (got ${#secret})" >&2
  exit 1
fi
case "$hash" in
  hmac_sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "error: basicauth password_hash must be hmac_sha256:<64 hex>" >&2; exit 1 ;;
esac
echo "secret=$secret"
exit 0
"#,
    );

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(result.success, "{}{}", result.stdout, result.stderr);
    assert!(
        result.stdout.contains(VALIDATION_STANDIN_PREFIX),
        "the stand-in must be obviously fake: {}",
        result.stdout
    );
}

/// Stand-ins live only in the validator's temp spec: nothing else in the
/// process ever sees one, and they are stable between runs.
#[test]
fn validation_standins_are_deterministic_shaped_and_input_only() {
    use gitforgeops::config::schema::GatewayConfig;
    use gitforgeops::validate::{validation_standin, with_validation_standins};

    let first = validation_standin("ferrum/app/jwt/[0]/secret", Some("secret"));
    assert_eq!(
        first,
        validation_standin("ferrum/app/jwt/[0]/secret", Some("secret"))
    );
    assert_ne!(
        first,
        validation_standin("ferrum/other/jwt/[0]/secret", Some("secret"))
    );
    assert!(first.starts_with(VALIDATION_STANDIN_PREFIX));
    assert!(first.len() >= 64, "{first}");

    let hashed = validation_standin(
        "ferrum/app/basicauth/[0]/password_hash",
        Some("password_hash"),
    );
    assert!(hashed.starts_with("hmac_sha256:"), "{hashed}");
    assert_eq!(hashed.len(), "hmac_sha256:".len() + 64);

    // A config with no placeholders is handed to the validator untouched.
    assert!(with_validation_standins(&GatewayConfig::default()).is_none());
    let literal =
        consumer_config_for_standins(serde_json::json!({"keyauth": [{"key": "literal"}]}));
    assert!(with_validation_standins(&literal).is_none());

    // The caller's own config is never mutated — only the returned copy is.
    let placeholder = consumer_config_for_standins(
        serde_json::json!({"keyauth": [{"key": "${gh-env-secret:alloc=generate}"}]}),
    );
    let patched = with_validation_standins(&placeholder).expect("substitution");
    assert_eq!(
        placeholder.consumers[0].credentials["keyauth"][0]["key"],
        serde_json::json!("${gh-env-secret:alloc=generate}")
    );
    assert!(patched.consumers[0].credentials["keyauth"][0]["key"]
        .as_str()
        .expect("string")
        .starts_with(VALIDATION_STANDIN_PREFIX));
}

fn consumer_config_for_standins(
    credentials: serde_json::Value,
) -> gitforgeops::config::schema::GatewayConfig {
    use gitforgeops::config::schema::{Consumer, GatewayConfig};

    GatewayConfig {
        consumers: vec![Consumer {
            labels: Default::default(),
            extra: Default::default(),
            id: "app".to_string(),
            username: "app".to_string(),
            namespace: "ferrum".to_string(),
            custom_id: None,
            credentials: credentials
                .as_object()
                .expect("credentials object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            acl_groups: Vec::new(),
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        }],
        ..GatewayConfig::default()
    }
}

fn args_as_strings(settings: &str, spec: &str) -> Vec<String> {
    build_validate_args_for_mode(GATEWAY_VALIDATE_MODE, Path::new(settings), Path::new(spec))
        .into_iter()
        .map(|a| a.to_string_lossy().to_string())
        .collect()
}

#[test]
fn validate_args_pin_file_mode_and_settings() {
    let args = args_as_strings("/tmp/empty.conf", "/tmp/spec.yaml");

    assert_eq!(
        args,
        vec![
            "validate".to_string(),
            "-m".to_string(),
            "file".to_string(),
            "-s".to_string(),
            "/tmp/empty.conf".to_string(),
            "-c".to_string(),
            "/tmp/spec.yaml".to_string(),
        ]
    );
}

#[test]
fn validate_args_never_pass_a_format_flag() {
    // `ferrum-edge validate` has no `--format` / `--json` flag; formatting is
    // done gitforgeops-side by the reporter.
    let args = args_as_strings("/tmp/empty.conf", "/tmp/spec.yaml");

    assert!(!args.iter().any(|a| a.starts_with("--format")));
    assert!(!args.iter().any(|a| a == "--json"));
}

#[test]
fn env_scrub_targets_only_ferrum_variables() {
    let names = [
        "FERRUM_MODE",
        "FERRUM_GATEWAY_URL",
        "FERRUM_ADMIN_JWT_SECRET",
        // The mesh validation-only opt-out is scrubbed like every other
        // inherited variable; gitforgeops sets its own copy afterwards, so a
        // parent value can neither enable nor disable the child's context.
        "FERRUM_MESH_ALLOW_NO_CA",
        "PATH",
        "HOME",
        "TMPDIR",
        "FERRUMISH",
        "NOT_FERRUM_MODE",
        "ferrum_mode",
    ];

    let scrubbed = scrubbed_env_names(names);

    assert_eq!(
        scrubbed,
        vec![
            "FERRUM_MODE".to_string(),
            "FERRUM_GATEWAY_URL".to_string(),
            "FERRUM_ADMIN_JWT_SECRET".to_string(),
            "FERRUM_MESH_ALLOW_NO_CA".to_string(),
        ]
    );
}

#[test]
fn env_scrub_keeps_the_child_environment_usable() {
    let scrubbed = scrubbed_env_names(["PATH", "HOME", "LANG", "SSL_CERT_FILE"]);
    assert!(scrubbed.is_empty(), "{scrubbed:?}");
}

#[cfg(unix)]
fn executable_validator(exit_code: i32) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ferrum-edge-test-validator");
    std::fs::write(
        &path,
        format!("#!/bin/sh\nprintf '%s\\n' validator-diagnostic >&2\nexit {exit_code}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

#[cfg(unix)]
#[test]
fn validator_exit_one_is_a_completed_schema_rejection() {
    let temp = executable_validator(1);
    let path = temp.path().join("ferrum-edge-test-validator");

    let result = run_validation(&Default::default(), path.to_str().unwrap()).unwrap();
    assert!(!result.success);
    assert_eq!(result.exit_code, 1);
    assert!(result.stderr.contains("validator-diagnostic"));
}

#[cfg(unix)]
#[test]
fn abnormal_validator_exit_is_an_execution_error() {
    let temp = executable_validator(2);
    let path = temp.path().join("ferrum-edge-test-validator");

    let error = run_validation(&Default::default(), path.to_str().unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("exited with code 2"), "{error}");
    assert!(error.contains("validator-diagnostic"), "{error}");
}

/// A mesh document is validated in a different ferrum-edge mode than a gateway
/// document, and the two are not interchangeable: under `-m mesh`, ferrum-edge
/// infers the localized-file protocol from the `{version?, mesh}` shape handed
/// to `-c` and runs the same parse + normalize + slice-derivation pipeline a
/// mesh node runs at startup.
#[test]
fn mesh_validate_args_pin_mesh_mode_and_settings() {
    let args: Vec<String> = build_validate_args_for_mode(
        MESH_VALIDATE_MODE,
        Path::new("/tmp/empty.conf"),
        Path::new("/tmp/mesh.yaml"),
    )
    .into_iter()
    .map(|a| a.to_string_lossy().to_string())
    .collect();

    assert_eq!(
        args,
        vec![
            "validate".to_string(),
            "-m".to_string(),
            "mesh".to_string(),
            // `-s` still pins settings to an empty file so ferrum.conf
            // auto-discovery cannot fail an otherwise-valid mesh document.
            "-s".to_string(),
            "/tmp/empty.conf".to_string(),
            "-c".to_string(),
            "/tmp/mesh.yaml".to_string(),
        ]
    );
}

#[test]
fn gateway_and_mesh_modes_are_distinct() {
    assert_eq!(GATEWAY_VALIDATE_MODE, "file");
    assert_eq!(MESH_VALIDATE_MODE, "mesh");
    assert_ne!(
        build_validate_args_for_mode(GATEWAY_VALIDATE_MODE, Path::new("s"), Path::new("c")),
        build_validate_args_for_mode(MESH_VALIDATE_MODE, Path::new("s"), Path::new("c")),
        "the two documents must not be validated in the same ferrum-edge mode"
    );
}

/// ferrum-edge resolves `-m mesh` through the same workload-identity gate a
/// mesh node runs at startup and refuses ("mesh mode has no workload
/// identity") before it ever parses the document handed to `-c`. A CI runner
/// has no mesh node's SVID material, so the mesh pass needs ferrum-edge's own
/// validation-only opt-out or every repository declaring a `MeshConfig`
/// fragment fails on the execution context instead of on its content.
#[test]
fn mesh_validation_context_is_the_documented_no_ca_opt_out() {
    assert_eq!(MESH_ALLOW_NO_CA_ENV, "FERRUM_MESH_ALLOW_NO_CA");
    assert_eq!(
        validation_context_env(MESH_VALIDATE_MODE),
        vec![("FERRUM_MESH_ALLOW_NO_CA", "true")]
    );
}

/// The gateway pass has no identity gate to relax, and a gateway document must
/// never be graded under a relaxed mesh context. `-m file` therefore inherits
/// the scrubbed environment and nothing else.
#[test]
fn gateway_validation_context_injects_nothing() {
    assert!(
        validation_context_env(GATEWAY_VALIDATE_MODE).is_empty(),
        "{:?}",
        validation_context_env(GATEWAY_VALIDATE_MODE)
    );
    // Any mode that is not the mesh pass is treated the same way: the context
    // is an allow-list keyed on one exact mode, not a default.
    assert!(validation_context_env("dp").is_empty());
    assert!(validation_context_env("").is_empty());
}

/// A validator stub that reports the mode it was given and whether the mesh
/// validation-only opt-out reached its environment.
#[cfg(unix)]
const REPORT_MESH_CONTEXT: &str =
    "#!/bin/sh\nprintf 'mode=%s no_ca=%s\\n' \"$3\" \"${FERRUM_MESH_ALLOW_NO_CA-unset}\"\n";

#[cfg(unix)]
#[test]
fn mesh_validator_child_receives_the_no_ca_context() {
    use gitforgeops::config::MeshConfigSpec;
    use gitforgeops::validate::run_mesh_validation;

    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "mesh-context", REPORT_MESH_CONTEXT);
    let binary = validator.to_str().unwrap();

    let result = run_mesh_validation(&MeshConfigSpec::default(), binary).unwrap();

    assert!(result.success, "{result:?}");
    assert_eq!(result.stdout.trim(), "mode=mesh no_ca=true");
}

#[cfg(unix)]
#[test]
fn gateway_validator_child_never_receives_the_no_ca_context() {
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "gateway-context", REPORT_MESH_CONTEXT);

    let result = run_validation(&Default::default(), validator.to_str().unwrap()).unwrap();

    assert!(result.success, "{result:?}");
    assert_eq!(result.stdout.trim(), "mode=file no_ca=unset");
}

/// The context relaxes *where* the document may be validated, never *what*
/// counts as valid: a rejected mesh document is still a failed run, and the
/// validator's own diagnostic is surfaced unchanged. If a ferrum-edge build
/// ever refuses the variable itself, that refusal arrives the same way.
#[cfg(unix)]
#[test]
fn the_no_ca_context_does_not_soften_a_rejected_mesh_document() {
    use gitforgeops::config::MeshConfigSpec;
    use gitforgeops::validate::run_mesh_validation;

    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(
        dir.path(),
        "mesh-reject",
        "#!/bin/sh\necho \"no_ca=${FERRUM_MESH_ALLOW_NO_CA-unset}\" >&2\necho 'error: mesh.workloads[0]: unknown field' >&2\nexit 1\n",
    );
    let binary = validator.to_str().unwrap();

    let result = run_mesh_validation(&MeshConfigSpec::default(), binary).unwrap();

    assert!(!result.success);
    assert_eq!(result.exit_code, 1);
    assert!(result.stderr.contains("no_ca=true"), "{}", result.stderr);
    assert!(result.stderr.contains("unknown"), "{}", result.stderr);
}

fn result(success: bool, stdout: &str, stderr: &str) -> ValidationResult {
    ValidationResult {
        success,
        exit_code: if success { 0 } else { 1 },
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
    }
}

/// A repo with no mesh config must see byte-identical output to what it saw
/// before mesh support existed.
#[test]
fn format_results_without_mesh_is_unchanged() {
    let gateway = result(true, "Spec: OK\n", "");

    for format in [
        OutputFormat::Text,
        OutputFormat::Json,
        OutputFormat::GithubAnnotations,
    ] {
        assert_eq!(
            format_results(&gateway, None, format),
            format_result(&gateway, format)
        );
    }
}

#[test]
fn validation_json_with_namespace_scope_is_one_document() {
    let scope = gitforgeops::config::NamespaceScope::with_desired(
        Some("does-not-exist"),
        vec!["ferrum".to_string()],
        1,
        &Default::default(),
        0,
    );
    let finding = scope.desired_finding(false);
    let gateway = result(false, "Spec: rejected\n", "error: bad \"value\"\n");
    for mesh in [None, Some(result(true, "Mesh: OK\n", ""))] {
        let formatted = format_results(&gateway, mesh.as_ref(), OutputFormat::Json);
        let output = gitforgeops::config::merge_scope_json(&formatted, &scope, finding.as_ref());
        let value: serde_json::Value = serde_json::from_str(&output).expect("JSON-only output");
        assert_eq!(value["success"], false);
        let gateway_value = if mesh.is_some() {
            &value["gateway"]
        } else {
            &value
        };
        assert_eq!(gateway_value["exit_code"], 1);
        assert_eq!(gateway_value["stdout"], gateway.stdout);
        assert_eq!(gateway_value["stderr"], gateway.stderr);
        assert_eq!(value["namespace"], "does-not-exist");
        assert_eq!(value["desired_count"], 0);
        assert_eq!(value["empty_namespace_filter"], "error");
    }
}

#[test]
fn format_results_text_labels_both_documents() {
    let output = format_results(
        &result(true, "Spec: OK\n", ""),
        Some(&result(
            false,
            "",
            "Mesh spec validation failed: bad selector\n",
        )),
        OutputFormat::Text,
    );

    assert!(output.contains("Gateway document:"), "{output}");
    assert!(output.contains("Mesh document:"), "{output}");
    assert!(output.contains("Validation passed."), "{output}");
    assert!(output.contains("Validation failed."), "{output}");
    assert!(output.contains("bad selector"), "{output}");
}

#[test]
fn format_results_json_conjoins_success() {
    let json: serde_json::Value = serde_json::from_str(&format_results(
        &result(true, "", ""),
        Some(&result(false, "", "boom")),
        OutputFormat::Json,
    ))
    .expect("valid json");

    // Overall success is the conjunction: both documents get published, and a
    // node refusing either one is a broken deploy.
    assert_eq!(json["success"], serde_json::Value::Bool(false));
    assert_eq!(json["gateway"]["success"], serde_json::Value::Bool(true));
    assert_eq!(json["mesh"]["success"], serde_json::Value::Bool(false));
    assert_eq!(json["mesh"]["stderr"], "boom");
}

fn assert_json_stdout_ends_with_one_newline(output: &str) {
    assert!(
        output.ends_with('\n'),
        "JSON stdout must end with a newline: {output:?}"
    );
    assert!(
        !output.ends_with("\n\n"),
        "JSON stdout must not end with extra newlines: {output:?}"
    );
    serde_json::from_str::<serde_json::Value>(output).expect("JSON stdout must parse");
}

#[test]
fn format_json_ends_with_exactly_one_newline() {
    let output = format_result(&result(true, "Spec: OK\n", ""), OutputFormat::Json);
    assert_json_stdout_ends_with_one_newline(&output);
}

#[test]
fn format_results_json_ends_with_exactly_one_newline() {
    let single = format_results(&result(true, "", ""), None, OutputFormat::Json);
    assert_json_stdout_ends_with_one_newline(&single);

    let both = format_results(
        &result(true, "", ""),
        Some(&result(false, "", "boom")),
        OutputFormat::Json,
    );
    assert_json_stdout_ends_with_one_newline(&both);
}

#[test]
fn format_results_github_annotations_cover_both_documents() {
    let output = format_results(
        &result(false, "", "error: gateway is bad"),
        Some(&result(false, "", "error: mesh is bad")),
        OutputFormat::GithubAnnotations,
    );

    assert!(
        output.contains("::error ::error: gateway is bad"),
        "{output}"
    );
    assert!(output.contains("::error ::error: mesh is bad"), "{output}");
}

// ---------------------------------------------------------------------------
// #133: a brokered plugin-config field the gateway *parses* must reach the
// validator as something parseable. `${gh-env-secret:alloc=require}` is not a
// URL, and grading it as one fails the required secretless PR job on the
// brokering rather than on the configuration.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn plugin_config_for(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
) -> gitforgeops::config::schema::GatewayConfig {
    use gitforgeops::config::schema::{GatewayConfig, PluginConfig, PluginScope};

    GatewayConfig {
        plugin_configs: vec![PluginConfig {
            labels: Default::default(),
            extra: Default::default(),
            id: id.to_string(),
            plugin_name: plugin_name.to_string(),
            namespace: "ferrum".to_string(),
            config,
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            trigger: None,
            api_spec_id: None,
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        }],
        ..GatewayConfig::default()
    }
}

/// A validator that enforces what ferrum-edge's `ldap_auth` enforces: the
/// `ldap_url` must be an absolute URL with an `ldap`/`ldaps` scheme and a
/// host. Anything relative — a broker placeholder included — is rejected.
#[cfg(unix)]
const LDAP_URL_VALIDATOR: &str = r#"#!/bin/sh
url=$(sed -n 's/.*ldap_url: *//p' "$7" | tr -d '"' | tr -d "'")
case "$url" in
  ldap://?*|ldaps://?*) ;;
  *) echo "error: ldap_auth: 'ldap_url' is not a valid URL: relative URL without a base" >&2; exit 1 ;;
esac
echo "ldap_url=$url"
exit 0
"#;

#[cfg(unix)]
#[test]
fn brokered_plugin_urls_reach_the_validator_as_parseable_stand_ins() {
    use gitforgeops::validate::VALIDATION_STANDIN_HOST;

    let config = plugin_config_for(
        "ldap",
        "ldap_auth",
        serde_json::json!({
            "ldap_url": "${gh-env-secret:alloc=require}",
            "bind_dn_template": "uid={username},dc=example,dc=test"
        }),
    );
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "ldap-validator", LDAP_URL_VALIDATOR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(result.success, "{}{}", result.stdout, result.stderr);
    assert!(
        result
            .stdout
            .contains(&format!("ldaps://{VALIDATION_STANDIN_HOST}/")),
        "the stand-in must be an LDAPS URL on the reserved host: {}",
        result.stdout
    );

    // The stand-in lives in the temp spec only: the caller's config, and
    // therefore everything export / apply / state serialize, still holds the
    // placeholder.
    assert_eq!(
        config.plugin_configs[0].config["ldap_url"],
        serde_json::json!("${gh-env-secret:alloc=require}")
    );
    let exported = serde_yaml::to_string(&config).unwrap();
    assert!(
        exported.contains("${gh-env-secret:alloc=require}"),
        "{exported}"
    );
    assert!(!exported.contains(VALIDATION_STANDIN_HOST), "{exported}");
}

/// A nonsecret sibling that is genuinely wrong must still fail: stand-ins
/// replace brokered leaves, they do not soften validation.
#[cfg(unix)]
#[test]
fn a_broken_sibling_field_still_fails_with_a_stand_in_url() {
    let config = plugin_config_for(
        "ldap",
        "ldap_auth",
        serde_json::json!({"ldap_url": "${gh-env-secret:alloc=require}"}),
    );
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(
        dir.path(),
        "sibling-validator",
        "#!/bin/sh\ngrep -q 'bind_dn_template' \"$7\" || { echo 'error: ldap_auth: missing bind_dn_template' >&2; exit 1; }\nexit 0\n",
    );

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(!result.success);
    assert!(
        result.stderr.contains("missing bind_dn_template"),
        "{}",
        result.stderr
    );
}

/// Capture the actual private spec before checking its shape. The capture
/// stays inside the test's private directory and is never a diagnostic.
#[cfg(unix)]
fn capturing_validator(dir: &Path, checks: &str) -> std::path::PathBuf {
    echo_validator(
        dir,
        "capture-validator",
        &format!("#!/bin/sh\ncp \"$7\" \"$(dirname \"$0\")/input.yaml\" || exit 2\n{checks}"),
    )
}

#[cfg(unix)]
fn captured_validator_input(dir: &Path) -> gitforgeops::config::GatewayConfig {
    serde_yaml::from_slice(&std::fs::read(dir.join("input.yaml")).unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn resolved_placeholder_shaped_values_reach_shape_checks_verbatim() {
    use gitforgeops::secrets::resolve_secrets;
    use gitforgeops::validate::run_validation_with_report;
    use std::collections::BTreeMap;

    let placeholder = "${gh-env-secret:alloc=require}";
    let jwt_check = r#"
secret=$(sed -n 's/.*secret: *//p' "$7" | tr -d '"' | tr -d "'")
if [ "${#secret}" -lt 32 ]; then
  cat "$7"
  echo 'error: jwt secret must be at least 32 characters' >&2
  cat "$7" >&2
  exit 1
fi
exit 0
"#;
    for plugin in [false, true] {
        // Ordinary invalid and placeholder-shaped resolved values must fail;
        // unresolved placeholders and valid resolved values must still pass.
        for (seed, success) in [
            (None, true),
            (Some(placeholder), false),
            (Some("invalid-short-value"), false),
            (Some("ldaps://valid.example/long-enough-for-jwt"), true),
        ] {
            let mut config = if plugin {
                plugin_config_for(
                    "ldap",
                    "ldap_auth",
                    serde_json::json!({"ldap_url": placeholder}),
                )
            } else {
                consumer_config(serde_json::json!({"jwt": [{"secret": placeholder}]}))
            };
            let slot = if plugin {
                "ferrum/ldap/@plugin-config/config/ldap_url"
            } else {
                "ferrum/app/jwt/secret"
            };
            let bundle: BTreeMap<String, String> = seed
                .map(|value| (slot.to_string(), value.to_string()))
                .into_iter()
                .collect();
            let report = resolve_secrets(&mut config, &bundle).unwrap();
            let before = serde_yaml::to_string(&config).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let validator = capturing_validator(
                dir.path(),
                if plugin {
                    LDAP_URL_VALIDATOR
                } else {
                    jwt_check
                },
            );
            let result =
                run_validation_with_report(&config, validator.to_str().unwrap(), &report).unwrap();
            assert_eq!(result.success, success);
            assert_eq!(result.exit_code, i32::from(!success));
            let captured = captured_validator_input(dir.path());
            let actual = if plugin {
                captured.plugin_configs[0].config["ldap_url"]
                    .as_str()
                    .unwrap()
            } else {
                captured.consumers[0].credentials["jwt"][0]["secret"]
                    .as_str()
                    .unwrap()
            };
            if let Some(value) = seed {
                assert_eq!(actual, value);
                assert!(!result.stdout.contains(value));
                assert!(!result.stderr.contains(value));
            } else {
                assert!(actual.contains("gitforgeops-validation-standin"));
            }
            assert_eq!(serde_yaml::to_string(&config).unwrap(), before);
        }
    }
}

#[cfg(unix)]
#[test]
fn validator_standins_use_canonical_escaped_slots_and_preserve_discovery() {
    use gitforgeops::secrets::resolve_secrets;
    use gitforgeops::validate::{run_validation_with_report, validation_standin};
    use std::collections::BTreeMap;

    let placeholder = "${gh-env-secret:alloc=require}";
    let mut config = consumer_config(serde_json::json!({
        "keyauth": [
            {"a/b~[1]": [placeholder, placeholder]},
            {"a/b~[1]": [placeholder, placeholder]}
        ]
    }));
    config.consumers[0].namespace = "n/s~[".to_string();
    config.consumers[0].id = "a/p~[".to_string();
    let mut plugin = plugin_config_for(
        "p/l~[",
        "custom_fixture",
        serde_json::json!({"a/b~[1]": [placeholder, placeholder]}),
    );
    plugin.plugin_configs[0].namespace = "n/s~[".to_string();
    config.plugin_configs = plugin.plugin_configs;
    config.upstreams.push(
        serde_json::from_value(serde_json::json!({
            "id": "discovery", "namespace": "ferrum", "targets": [],
            "service_discovery": {"provider": "consul", "consul": {
                "address": "https://consul.example", "service_name": "orders", "token": placeholder
            }}
        }))
        .unwrap(),
    );
    let resolved_slots = [
        "n~1s~0~2/a~1p~0~2/keyauth/a~1b~0~21]",
        "n~1s~0~2/a~1p~0~2/keyauth/[1]/a~1b~0~21]/[1]",
        "n~1s~0~2/p~1l~0~2/@plugin-config/config/a~1b~0~21]/[0]",
        "ferrum/discovery/@service-discovery/consul/token",
    ];
    for seeded in [false, true] {
        let mut snapshot = config.clone();
        let bundle: BTreeMap<String, String> = resolved_slots
            .iter()
            .filter(|_| seeded)
            .map(|slot| (slot.to_string(), placeholder.to_string()))
            .collect();
        let report = resolve_secrets(&mut snapshot, &bundle).unwrap();
        assert_eq!(report.results.len(), 7);
        for slot in resolved_slots {
            assert!(report.results.iter().any(|result| result.slot == slot));
        }
        let before = serde_yaml::to_string(&snapshot).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let validator = capturing_validator(dir.path(), "exit 0\n");
        let result =
            run_validation_with_report(&snapshot, validator.to_str().unwrap(), &report).unwrap();
        assert!(result.success);
        let captured = captured_validator_input(dir.path());
        let credentials = &captured.consumers[0].credentials["keyauth"];
        for (entry, index, slot) in [
            (0, 0, resolved_slots[0]),
            (0, 1, "n~1s~0~2/a~1p~0~2/keyauth/a~1b~0~21]/[1]"),
            (1, 0, "n~1s~0~2/a~1p~0~2/keyauth/[1]/a~1b~0~21]"),
            (1, 1, resolved_slots[1]),
        ] {
            let expected = if seeded && resolved_slots.contains(&slot) {
                placeholder.to_string()
            } else {
                validation_standin(slot, Some("a/b~[1]"))
            };
            assert_eq!(credentials[entry]["a/b~[1]"][index], expected);
        }
        for (index, slot) in [
            resolved_slots[2],
            "n~1s~0~2/p~1l~0~2/@plugin-config/config/a~1b~0~21]/[1]",
        ]
        .iter()
        .enumerate()
        {
            let expected = if seeded && index == 0 {
                placeholder.to_string()
            } else {
                validation_standin(slot, None)
            };
            assert_eq!(
                captured.plugin_configs[0].config["a/b~[1]"][index],
                expected
            );
        }
        // Discovery has no stand-in contract: both resolved and unresolved
        // modeled fields must survive the validator hand-off verbatim.
        assert_eq!(
            serde_yaml::to_string(&captured.upstreams).unwrap(),
            serde_yaml::to_string(&snapshot.upstreams).unwrap()
        );
        assert_eq!(serde_yaml::to_string(&snapshot).unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn validator_report_never_grants_standins_to_unreported_or_conflicting_slots() {
    use gitforgeops::secrets::{resolve_secrets, ResolveReport, SlotStatus};
    use gitforgeops::validate::run_validation_with_report;

    let placeholder = "${gh-env-secret:alloc=require}";
    let mut config = consumer_config(serde_json::json!({"jwt": [{"secret": placeholder}]}));
    config.plugin_configs = plugin_config_for(
        "ldap",
        "ldap_auth",
        serde_json::json!({"ldap_url": placeholder}),
    )
    .plugin_configs;
    let report = resolve_secrets(&mut config, &Default::default()).unwrap();
    let mut wrong_slot = report.clone();
    wrong_slot.results[0].slot = "ferrum/app/jwt/[0]/secret".to_string();
    wrong_slot.results[1].slot = "ferrum/ldap/@plugin-config/config/ldap_url/[0]".to_string();
    let mut conflicting = report.clone();
    for mut resolved in report.results {
        resolved.status = SlotStatus::Resolved;
        conflicting.results.push(resolved);
    }
    for report in [ResolveReport::default(), wrong_slot, conflicting] {
        let dir = tempfile::tempdir().unwrap();
        let validator = capturing_validator(dir.path(), "exit 1\n");
        let result =
            run_validation_with_report(&config, validator.to_str().unwrap(), &report).unwrap();
        assert!(!result.success);
        let captured = captured_validator_input(dir.path());
        assert_eq!(
            captured.consumers[0].credentials["jwt"][0]["secret"],
            placeholder
        );
        assert_eq!(captured.plugin_configs[0].config["ldap_url"], placeholder);
    }
}

#[cfg(unix)]
#[test]
fn unresolved_reports_and_report_free_documents_keep_standins_for_every_alloc_mode() {
    use gitforgeops::secrets::resolve_secrets;
    use gitforgeops::validate::{run_validation_with_report, validation_standin};

    for alloc in ["require", "generate", "rotate"] {
        let placeholder = format!("${{gh-env-secret:alloc={alloc}}}");
        // Bare objects and canonical index-zero arrays identify the same slot.
        for credential in [
            serde_json::json!({"secret": placeholder}),
            serde_json::json!([{"secret": placeholder}]),
        ] {
            let mut config = consumer_config(serde_json::json!({"jwt": credential}));
            let report = resolve_secrets(&mut config, &Default::default()).unwrap();
            let before = serde_yaml::to_string(&config).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let validator = capturing_validator(dir.path(), "exit 0\n");
            for with_report in [false, true] {
                let binary = validator.to_str().unwrap();
                let result = if with_report {
                    run_validation_with_report(&config, binary, &report)
                } else {
                    run_validation(&config, binary)
                }
                .unwrap();
                assert!(result.success);
                let captured = captured_validator_input(dir.path());
                let jwt = &captured.consumers[0].credentials["jwt"];
                let entry = if jwt.is_array() { &jwt[0] } else { jwt };
                assert_eq!(
                    entry["secret"],
                    validation_standin("ferrum/app/jwt/secret", Some("secret"))
                );
                assert_eq!(serde_yaml::to_string(&config).unwrap(), before);
            }
        }
    }
}

/// Shape selection, without a subprocess: endpoint-typed leaves become URLs
/// with the scheme their plugin requires, token-typed leaves keep the opaque
/// 64-hex form, and a header map keeps its keys.
#[test]
fn plugin_config_stand_ins_are_shape_aware_and_input_only() {
    use gitforgeops::config::schema::{GatewayConfig, PluginConfig, PluginScope};
    use gitforgeops::validate::{
        with_validation_standins, VALIDATION_STANDIN_HOST, VALIDATION_STANDIN_PREFIX,
    };

    let plugin = |id: &str, plugin_name: &str, config: serde_json::Value| PluginConfig {
        labels: Default::default(),
        extra: Default::default(),
        id: id.to_string(),
        plugin_name: plugin_name.to_string(),
        namespace: "ferrum".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        trigger: None,
        api_spec_id: None,
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    };

    let placeholder = serde_json::json!("${gh-env-secret:alloc=require}");
    let config = GatewayConfig {
        plugin_configs: vec![
            plugin(
                "ldap",
                "ldap_auth",
                serde_json::json!({"ldap_url": placeholder}),
            ),
            plugin(
                "rl",
                "rate_limiting",
                serde_json::json!({"redis_url": placeholder, "limit": "100"}),
            ),
            plugin(
                "otel",
                "otel_tracing",
                serde_json::json!({
                    "endpoint": placeholder,
                    "headers": {"x-honeycomb-team": placeholder}
                }),
            ),
        ],
        ..GatewayConfig::default()
    };

    let patched = with_validation_standins(&config).expect("substitution");
    let value = |index: usize, path: &[&str]| -> String {
        let mut cursor = &patched.plugin_configs[index].config;
        for part in path {
            cursor = &cursor[*part];
        }
        cursor.as_str().expect("string leaf").to_string()
    };

    assert_eq!(
        value(0, &["ldap_url"]).split("://").next(),
        Some("ldaps"),
        "{}",
        value(0, &["ldap_url"])
    );
    assert!(value(1, &["redis_url"]).starts_with("redis://"));
    assert!(value(2, &["endpoint"]).starts_with("https://"));
    for index in 0..3 {
        assert!(
            value(index, &[["ldap_url", "redis_url", "endpoint"][index]])
                .contains(VALIDATION_STANDIN_HOST)
        );
    }

    // A non-endpoint leaf keeps the opaque token shape, and its header key is
    // untouched.
    let header = value(2, &["headers", "x-honeycomb-team"]);
    assert!(header.starts_with(VALIDATION_STANDIN_PREFIX), "{header}");
    assert!(patched.plugin_configs[2].config["headers"]
        .as_object()
        .expect("header map")
        .contains_key("x-honeycomb-team"));

    // A literal sibling is left exactly as written.
    assert_eq!(
        patched.plugin_configs[1].config["limit"],
        serde_json::json!("100")
    );

    // Distinct per slot, stable across calls, and never applied to the input.
    let again = with_validation_standins(&config).expect("substitution");
    assert_eq!(
        patched.plugin_configs[0].config,
        again.plugin_configs[0].config
    );
    assert_ne!(value(0, &["ldap_url"]), value(1, &["redis_url"]));
    assert_eq!(
        config.plugin_configs[0].config["ldap_url"],
        serde_json::json!("${gh-env-secret:alloc=require}")
    );
}

// ---------------------------------------------------------------------------
// Scrubbing fails closed for values a validator can re-encode. Substring
// replacement only protects a secret the child echoed as those exact bytes;
// a PEM key comes back as an indented block scalar and a quoted value comes
// back escaped, and a stream that merely *looks* redacted is worse than one
// that is withheld.
// ---------------------------------------------------------------------------

/// A validator that re-emits the spec as a YAML block scalar, the way a
/// multi-line value actually comes back: indented, wrapped, with no
/// contiguous copy of the original bytes anywhere in the output.
#[cfg(unix)]
const REENCODING_VALIDATOR: &str = r#"#!/bin/sh
echo 'error: consumer app: credential rejected'
echo 'key: |'
sed 's/^/  /' "$7"
exit 1
"#;

#[cfg(unix)]
#[test]
fn a_multi_line_secret_withholds_the_stream_instead_of_half_redacting_it() {
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----";
    let config = consumer_config(serde_json::json!({"mtls_auth": [{"private_key": pem}]}));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "reencoding-validator", REENCODING_VALIDATOR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("not safely scrubbable"),
        "the notice must name the reason: {}",
        result.stderr
    );
    // No line of the key survives, not even one the block scalar indented.
    for line in pem.lines() {
        assert!(!result.stderr.contains(line), "{}", result.stderr);
        assert!(!result.stdout.contains(line), "{}", result.stdout);
    }
}

/// A secret carrying a quote is re-encoded by every emitter that has to quote
/// it. The escaped form is a needle in its own right, so an ordinary
/// single-line diagnostic is still scrubbed rather than lost — but a value
/// that reaches the output through some *other* encoding still withholds.
#[test]
fn json_escaped_and_single_quoted_forms_of_a_secret_are_scrubbed() {
    use gitforgeops::secrets::SecretScrubber;

    let secret = "quote\"and'apostrophe-secret";
    let config = consumer_config_for_standins(serde_json::json!({
        "keyauth": [{"key": secret}]
    }));
    let scrubber = SecretScrubber::from_gateway_config(&config);

    // The JSON-escaped form (`\"`) and the single-quoted YAML form (`''`) are
    // both replaced, not merely detected.
    let json_form = format!(
        "key = \"{}\"",
        secret.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let yaml_form = format!("key = '{}'", secret.replace('\'', "''"));
    for text in [&json_form, &yaml_form] {
        let scrubbed = scrubber.scrub(text);
        assert!(scrubbed.contains("[REDACTED]"), "{scrubbed}");
        assert!(!scrubbed.contains("apostrophe-secret"), "{scrubbed}");
    }
}

/// ...and because a quote is also a re-encoding hazard, the stream as a whole
/// is withheld: the escaped needles above are a best effort, not a guarantee.
#[cfg(unix)]
#[test]
fn a_secret_carrying_a_quote_withholds_the_stream() {
    use gitforgeops::secrets::is_reencoding_hazard;

    assert!(is_reencoding_hazard("quote\"secret-value"));
    assert!(is_reencoding_hazard("multi\nline"));
    assert!(is_reencoding_hazard("trailing-space "));
    assert!(is_reencoding_hazard("comment#marker-value"));
    assert!(is_reencoding_hazard("mapping: indicator"));
    // The common case is untouched.
    assert!(!is_reencoding_hazard("Ax7Kd9QpLm2Rn4Tv6Wy8Zb0Ce3Fh5Jk"));

    let config = consumer_config(serde_json::json!({
        "keyauth": [{"key": "quote\"secret-value"}]
    }));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("not safely scrubbable"),
        "{}",
        result.stderr
    );
    assert!(!result.stderr.contains("secret-value"), "{}", result.stderr);
}

/// A validator that reproduces only part of a secret — a wrapped line, a
/// truncated echo — leaves no needle to replace, so the surviving run is
/// caught by the fragment scan.
#[cfg(unix)]
#[test]
fn a_surviving_fragment_of_a_secret_withholds_the_stream() {
    let secret = "Ax7Kd9QpLm2Rn4Tv6Wy8Zb0Ce3Fh5JkNp1Su4Xz7Bd0Gg";
    let fragment = &secret[..20];
    let config = consumer_config(serde_json::json!({"keyauth": [{"key": secret}]}));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(
        dir.path(),
        "truncating-validator",
        &format!("#!/bin/sh\necho 'error: key starts with {fragment}'\nexit 1\n"),
    );

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert_eq!(result.stdout, "");
    assert!(!result.stderr.contains(fragment), "{}", result.stderr);
    assert!(
        result.stderr.contains("12-byte run"),
        "the notice must name the reason: {}",
        result.stderr
    );
}

/// The narrowing that keeps the scan usable: a run the *document* already
/// contains in public text is printed by the validator whether or not a secret
/// exists, so it is not evidence of a leak. Here the header value embeds its
/// own header name.
#[cfg(unix)]
#[test]
fn a_public_run_shared_with_a_secret_does_not_withhold_the_stream() {
    let config = plugin_config_for(
        "otel",
        "otel_tracing",
        serde_json::json!({
            "headers": {"x-honeycomb-team": "x-honeycomb-team-issued-key-material"},
            "sample_rate": "0.1"
        }),
    );
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(
        !result.stdout.contains("issued-key-material"),
        "{}",
        result.stdout
    );
    assert!(result.stdout.contains("sample_rate"), "{}", result.stdout);
    assert!(
        result.stderr.contains("unknown field `listen_path_typo`"),
        "{}",
        result.stderr
    );
}

/// (d) The case that has to keep working: a single-line API key. Diagnostics
/// stay complete, the credential does not.
#[cfg(unix)]
#[test]
fn an_ordinary_single_line_secret_keeps_full_diagnostics() {
    let secret = "Ax7Kd9QpLm2Rn4Tv6Wy8Zb0Ce3Fh5Jk";
    let config = consumer_config(serde_json::json!({
        "keyauth": [{"key": secret}],
        "hmac_auth": [{"secret": "Zq3Wm8Nb5Vc2Xs9Df6Gh1Jk4Lp7Ty0R"}]
    }));
    let dir = tempfile::tempdir().unwrap();
    let validator = echo_validator(dir.path(), "echo-validator", ECHO_SPEC_WITH_PROXY_ERROR);

    let result = run_validation(&config, validator.to_str().unwrap()).unwrap();

    assert!(!result.stdout.contains(secret), "{}", result.stdout);
    assert!(result.stdout.contains("[REDACTED]"), "{}", result.stdout);
    assert!(
        result.stderr.contains("unknown field `listen_path_typo`"),
        "{}",
        result.stderr
    );
    assert!(
        !result.stderr.contains("withheld"),
        "an ordinary credential must not cost the diagnostics: {}",
        result.stderr
    );
}

#[cfg(unix)]
#[test]
fn review_validates_gateway_and_mesh_before_reporting_passed() {
    use gitforgeops::config::{GatewayConfig, MeshConfigSpec};
    use gitforgeops::review::{
        build_review_comment_with_status, validate_for_review, ReviewValidationStatus,
    };

    let dir = tempfile::tempdir().unwrap();
    let gateway = GatewayConfig::default();
    let mesh = MeshConfigSpec::default();
    for (script, include_mesh, expected) in [
        (
            "#!/bin/sh\necho mode-$3\nif [ \"$3\" = mesh ]; then echo 'mesh rejected' >&2; exit 1; fi\n",
            true,
            ReviewValidationStatus::Rejected,
        ),
        (
            "#!/bin/sh\necho mode-$3\nif [ \"$3\" = file ]; then echo 'gateway rejected' >&2; exit 1; fi\n",
            true,
            ReviewValidationStatus::Rejected,
        ),
        (
            "#!/bin/sh\necho mode-$3\n",
            true,
            ReviewValidationStatus::Passed,
        ),
        (
            "#!/bin/sh\necho mode-$3\nif [ \"$3\" = mesh ]; then exit 1; fi\n",
            false,
            ReviewValidationStatus::Passed,
        ),
    ] {
        let binary = echo_validator(dir.path(), "review-validator", script);
        let result = validate_for_review(
            &gateway,
            include_mesh.then_some(&mesh),
            binary.to_str().unwrap(),
        );
        assert_eq!(result.status, expected, "{}", result.output);
        assert!(result.output.contains("mode-file"));
        assert_eq!(result.output.contains("mode-mesh"), include_mesh);
        assert!(result.execution_error.is_none());
        let comment = build_review_comment_with_status(
            result.status,
            &result.output,
            &[],
            &[],
            &[],
            &[],
            None,
        );
        assert_eq!(
            comment.contains("Validation: PASSED"),
            expected == ReviewValidationStatus::Passed
        );
        if expected == ReviewValidationStatus::Rejected {
            assert!(comment.contains("Validation: FAILED"));
            assert!(comment.contains("rejected"));
        }
    }
    let result = validate_for_review(
        &gateway,
        Some(&mesh),
        dir.path().join("missing-validator").to_str().unwrap(),
    );
    assert_eq!(result.status, ReviewValidationStatus::ExecutionError);
    assert!(result.execution_error.is_some());
    assert!(result.output.contains("gateway validator execution error"));
    assert!(result.output.contains("mesh validator execution error"));
}
