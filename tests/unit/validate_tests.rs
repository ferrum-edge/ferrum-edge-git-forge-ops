use gitforgeops::validate::{
    build_validate_args_for_mode, format_result, format_results, run_validation,
    scrubbed_env_names, OutputFormat, ValidationResult, GATEWAY_VALIDATE_MODE, MESH_VALIDATE_MODE,
    VALIDATION_STANDIN_PREFIX,
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
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

/// F1: the fixture repo commits a literal `keyauth.key`. That used to blank
/// the whole stream on every fork PR; now only the key is redacted.
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

/// F2: plugin-config secrets brokered by this release are scrubbed too, while
/// the plugin's non-sensitive settings stay visible.
#[cfg(unix)]
#[test]
fn resolved_plugin_config_secrets_are_redacted() {
    use gitforgeops::config::schema::{GatewayConfig, PluginConfig, PluginScope};

    let secret = "honeycomb-team-key-must-not-be-echoed";
    let config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
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
            format_results(&gateway, None, format.clone()),
            format_result(&gateway, format)
        );
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
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
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
