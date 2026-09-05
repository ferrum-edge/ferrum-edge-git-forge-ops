use gitforgeops::config::repo_config::{DriftAlertOn, OwnershipMode, RepoConfig};
use gitforgeops::config::ApplyStrategy;
use std::io::Write;
use tempfile::NamedTempFile;

fn write_repo_config(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

#[test]
fn repo_config_defaults_to_shared_ownership() {
    let yaml = r#"
version: 1
environments:
  staging:
    overlay: staging
"#;
    let file = write_repo_config(yaml);
    let config = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    let env = config.environment("staging").unwrap();
    assert_eq!(env.ownership.mode, OwnershipMode::Shared);
    assert!(env.ownership.drift_report);
}

#[test]
fn repo_config_rejects_exclusive_without_namespaces() {
    let yaml = r#"
environments:
  staging:
    overlay: staging
    ownership:
      mode: exclusive
"#;
    let file = write_repo_config(yaml);
    let err = RepoConfig::load_from_path(file.path()).unwrap_err();
    assert!(err.to_string().contains("ownership.namespaces"));
}

#[test]
fn repo_config_rejects_full_replace_with_shared() {
    let yaml = r#"
environments:
  staging:
    overlay: staging
    apply_strategy: full_replace
    ownership:
      mode: shared
"#;
    let file = write_repo_config(yaml);
    let err = RepoConfig::load_from_path(file.path()).unwrap_err();
    assert!(err.to_string().contains("full_replace"));
}

#[test]
fn repo_config_accepts_exclusive_with_namespaces() {
    let yaml = r#"
environments:
  production:
    overlay: production
    apply_strategy: full_replace
    ownership:
      mode: exclusive
      namespaces: [ferrum, platform]
"#;
    let file = write_repo_config(yaml);
    let config = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    let env = config.environment("production").unwrap();
    assert_eq!(env.ownership.mode, OwnershipMode::Exclusive);
    assert_eq!(
        env.ownership.namespaces.as_deref().unwrap(),
        &["ferrum".to_string(), "platform".to_string()]
    );
    assert_eq!(env.apply_strategy, ApplyStrategy::FullReplace);
}

#[test]
fn repo_config_returns_none_when_missing() {
    let path = std::path::Path::new("/nonexistent/path/should/not/exist.yaml");
    assert!(RepoConfig::load_from_path(path).unwrap().is_none());
}

#[test]
fn repo_config_enumerates_environments_sorted() {
    let yaml = r#"
environments:
  zebra:
    overlay: z
  alpha:
    overlay: a
  mu:
    overlay: m
"#;
    let file = write_repo_config(yaml);
    let config = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    assert_eq!(config.environment_names(), vec!["alpha", "mu", "zebra"]);
}

#[test]
fn repo_config_emits_live_review_namespace_scopes() {
    let yaml = r#"
environments:
  all-shared:
    ownership:
      mode: shared
  filtered:
    namespace_filter: team-a
    live_review: false
    ownership:
      mode: shared
  production:
    ownership:
      mode: exclusive
      namespaces: [team-b, team-a, team-b]
"#;
    let file = write_repo_config(yaml);
    let config = RepoConfig::load_from_path(file.path()).unwrap().unwrap();

    let scopes = config.environment_scopes();

    assert_eq!(scopes[0].environment, "all-shared");
    assert!(scopes[0].live_review);
    assert_eq!(scopes[0].namespaces, None);
    assert!(!scopes[1].live_review);
    assert_eq!(
        scopes[1].namespaces.as_deref(),
        Some(&["team-a".to_string()][..])
    );
    assert_eq!(
        scopes[2].namespaces.as_deref(),
        Some(&["team-a".to_string(), "team-b".to_string()][..])
    );
}

#[test]
fn repo_config_rejects_prune_threshold_above_100() {
    // delete_pct in cmd_apply is 0..=100. A YAML value > 100 would make the
    // guard `delete_pct > threshold` never fire — mass deletions would
    // slip through. Reject at load time.
    let yaml = r#"
environments:
  staging:
    overlay: staging
    ownership:
      mode: shared
      large_prune_threshold_percent: 250
"#;
    let file = write_repo_config(yaml);
    let err = RepoConfig::load_from_path(file.path()).unwrap_err();
    assert!(
        err.to_string()
            .contains("large_prune_threshold_percent=250"),
        "expected out-of-range rejection, got: {err}"
    );
    assert!(err.to_string().contains("0..=100"));
}

#[test]
fn repo_config_accepts_prune_threshold_at_boundary() {
    // 0 (prune-guard always fires on any delete) and 100 (guard never fires,
    // equivalent to --allow-large-prune) are both valid.
    for n in [0, 1, 50, 100] {
        let yaml = format!(
            "environments:\n  staging:\n    overlay: staging\n    ownership:\n      mode: shared\n      large_prune_threshold_percent: {n}\n"
        );
        let file = write_repo_config(&yaml);
        assert!(
            RepoConfig::load_from_path(file.path()).is_ok(),
            "expected {n} to be accepted"
        );
    }
}

#[test]
fn repo_config_drift_alert_defaults_flag_managed_changes_only() {
    // Default drift_alert_on should alert on managed modifications/deletions
    // but NOT on unmanaged additions (admin-GUI-added resources are expected
    // in shared mode and shouldn't spam the drift check).
    let yaml = r#"
environments:
  staging:
    overlay: staging
"#;
    let file = write_repo_config(yaml);
    let config = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    let alert = &config
        .environment("staging")
        .unwrap()
        .ownership
        .drift_alert_on;
    assert!(alert.managed_modified);
    assert!(alert.managed_deleted);
    assert!(!alert.unmanaged_added);
}

#[test]
fn repo_config_drift_alert_defaults_survive_an_ownership_block_that_omits_them() {
    // Regression: `DriftAlertOn` used to derive `Default` (all false) while
    // its serde field defaults said true/true/false. An `ownership:` block
    // that omitted `drift_alert_on:` took the derived path and silently
    // muted the managed-modified and managed-deleted alerts that the
    // no-`ownership:` case above still raised, so the nightly drift check
    // failed open for every environment that configured ownership at all.
    let yaml = r#"
environments:
  staging:
    overlay: staging
    ownership:
      mode: shared
"#;
    let file = write_repo_config(yaml);
    let config = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    let alert = &config
        .environment("staging")
        .unwrap()
        .ownership
        .drift_alert_on;
    assert!(alert.managed_modified);
    assert!(alert.managed_deleted);
    assert!(!alert.unmanaged_added);

    // Every way of arriving at the defaults must agree: an absent block, an
    // empty block, and `DriftAlertOn::default()`.
    let empty_block: DriftAlertOn = serde_yaml::from_str("{}").unwrap();
    let derived = DriftAlertOn::default();
    for candidate in [&empty_block, &derived] {
        assert_eq!(candidate.managed_modified, alert.managed_modified);
        assert_eq!(candidate.managed_deleted, alert.managed_deleted);
        assert_eq!(candidate.unmanaged_added, alert.unmanaged_added);
    }
}

#[test]
fn repo_config_default_matches_the_serde_version_default() {
    // Same split, different type: a derived `Default` gave `version: 0`,
    // which `validate` rejects, while an absent `version:` parses as 1.
    let config = RepoConfig::default();
    assert_eq!(config.version, 1);
    assert!(config.environments.is_empty());
    assert!(config.default_environment.is_none());
}

#[test]
fn env_name_allowlist_rejects_shell_metacharacters() {
    use gitforgeops::config::resolved::validate_env_name_is_safe_path_component;
    for bad in [
        "",
        "..",
        ".",
        "foo bar",      // whitespace
        "foo/bar",      // separator
        "foo\\bar",     // separator
        "foo;rm -rf /", // shell metachar
        "foo`evil`",    // backtick
        "foo$x",        // dollar
        "foo\"bar",     // quote
        "foo\0bar",     // null
        "foo'bar",      // apostrophe
        "foo|bar",      // pipe
        "foo&bar",      // ampersand
    ] {
        assert!(
            validate_env_name_is_safe_path_component(bad).is_err(),
            "expected {bad:?} to be rejected by strict allowlist"
        );
    }
    for good in ["staging", "prod", "env-1", "team_alpha", "a", "A1_b-2"] {
        assert!(
            validate_env_name_is_safe_path_component(good).is_ok(),
            "expected {good:?} to pass strict allowlist"
        );
    }
}

#[test]
fn repo_config_rejects_env_name_with_shell_metacharacters() {
    // Full path: YAML loader + validator rejects a weaponized env name at
    // load time, so `envs --format json` can never emit a name that could
    // inject into a workflow shell command.
    let yaml = r#"
environments:
  "foo;rm -rf /":
    overlay: staging
"#;
    let file = write_repo_config(yaml);
    let err = RepoConfig::load_from_path(file.path()).unwrap_err();
    assert!(
        err.to_string().contains("disallowed characters"),
        "expected strict-allowlist rejection, got: {err}"
    );
}

#[test]
fn resolved_env_rejects_unsafe_environment_names() {
    // Environment names flow into `.state/<name>.json`. A name with path
    // separators or traversal segments would escape .state/ and could let
    // `state.save()` overwrite arbitrary repo files. Reject at validation
    // time so no command path uses an unsafe name.
    use gitforgeops::config::repo_config::{OwnershipConfig, OwnershipMode};
    use gitforgeops::config::resolved::{validate_env_name_is_safe_path_component, ResolvedEnv};
    use gitforgeops::config::ApplyStrategy;

    // Direct helper test: the unsafe cases.
    for bad in ["..", ".", "", "foo/bar", "foo\\bar", "foo\0bar"] {
        assert!(
            validate_env_name_is_safe_path_component(bad).is_err(),
            "expected {bad:?} to be rejected"
        );
    }
    // Normal names pass.
    for good in ["staging", "production", "env-with-dashes", "env_with_under"] {
        assert!(
            validate_env_name_is_safe_path_component(good).is_ok(),
            "expected {good:?} to be accepted"
        );
    }

    // End-to-end: ResolvedEnv::validate catches unsafe names.
    let r = ResolvedEnv {
        name: "../oops".to_string(),
        overlay: None,
        namespace_filter: None,
        apply_strategy: ApplyStrategy::Incremental,
        ownership: OwnershipConfig {
            mode: OwnershipMode::Shared,
            ..OwnershipConfig::default()
        },
    };
    let err = r.validate().unwrap_err();
    assert!(err.to_string().contains("../oops"));
}

#[test]
fn synthetic_default_honors_explicit_env_over_ferrum_env_var() {
    // Regression guard: with no repo config, resolve_env went through
    // synthetic_default which looked only at env_config.env_name
    // (FERRUM_ENV) and ignored the explicit `--env` selection that had
    // already been computed by resolve_env's `selected`. A call like
    // `gitforgeops --env prod apply` with FERRUM_ENV=default unset would
    // still resolve to "default" and write state to .state/default.json.
    use gitforgeops::config::env::{ApplyStrategy, EnvConfig, GatewayMode};
    use gitforgeops::config::resolve_env;

    fn base_env() -> EnvConfig {
        EnvConfig {
            gateway_url: None,
            admin_jwt_secret: None,
            admin_jwt_issuer: "ferrum-edge".to_string(),
            admin_jwt_role: "admin".to_string(),
            admin_jwt_audience: None,
            admin_jwt_ttl_secs: 3600,
            namespace_filter: None,
            allow_unknown_fields: false,
            gateway_mode: GatewayMode::Api,
            apply_strategy: ApplyStrategy::Incremental,
            overlay: None,
            env_name: None,
            github_repository: None,
            github_token: None,
            github_provisioner_token: None,
            creds_bundle_json: None,
            creds_bundle_json_file: None,
            file_output_path: "./assembled/resources.yaml".to_string(),
            mesh_file_output_path: "./assembled/mesh.yaml".to_string(),
            edge_binary_path: "ferrum-edge".to_string(),
            tls_no_verify: false,
            allow_insecure_http: false,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            gateway_connect_timeout_secs: 10,
            gateway_request_timeout_secs: 60,
            github_connect_timeout_secs: 10,
            github_request_timeout_secs: 30,
            gateway_max_retries: 3,
        }
    }

    // Case 1: `--env prod` passed, FERRUM_ENV unset. Resolves to "prod".
    let env_cfg = base_env();
    let resolved = resolve_env(None, &env_cfg, Some("prod")).unwrap();
    assert_eq!(resolved.name, "prod");

    // Case 2: `--env prod` passed, FERRUM_ENV=staging. Explicit wins.
    let mut env_cfg = base_env();
    env_cfg.env_name = Some("staging".to_string());
    let resolved = resolve_env(None, &env_cfg, Some("prod")).unwrap();
    assert_eq!(resolved.name, "prod");

    // Case 3: no explicit, FERRUM_ENV=staging. Falls back to FERRUM_ENV.
    let mut env_cfg = base_env();
    env_cfg.env_name = Some("staging".to_string());
    let resolved = resolve_env(None, &env_cfg, None).unwrap();
    assert_eq!(resolved.name, "staging");

    // Case 4: no explicit, no FERRUM_ENV. Falls back to "default".
    let env_cfg = base_env();
    let resolved = resolve_env(None, &env_cfg, None).unwrap();
    assert_eq!(resolved.name, "default");
}

#[test]
fn resolved_env_rejects_full_replace_plus_shared_from_env_vars() {
    // Regression guard: RepoConfig::validate blocks the combination in YAML,
    // but the synthetic-default path (no .gitforgeops/config.yaml, pure
    // env-var config) used to bypass the check. ResolvedEnv::validate now
    // enforces the same rule on every resolve_env path.
    use gitforgeops::config::env::{ApplyStrategy, EnvConfig, GatewayMode};
    use gitforgeops::config::resolve_env;

    let env_config = EnvConfig {
        gateway_url: None,
        admin_jwt_secret: None,
        admin_jwt_issuer: "ferrum-edge".to_string(),
        admin_jwt_role: "admin".to_string(),
        admin_jwt_audience: None,
        admin_jwt_ttl_secs: 3600,
        namespace_filter: None,
        allow_unknown_fields: false,
        gateway_mode: GatewayMode::Api,
        apply_strategy: ApplyStrategy::FullReplace,
        overlay: None,
        env_name: None,
        github_repository: None,
        github_token: None,
        github_provisioner_token: None,
        creds_bundle_json: None,
        creds_bundle_json_file: None,
        file_output_path: "./assembled/resources.yaml".to_string(),
        mesh_file_output_path: "./assembled/mesh.yaml".to_string(),
        edge_binary_path: "ferrum-edge".to_string(),
        tls_no_verify: false,
        allow_insecure_http: false,
        ca_cert: None,
        client_cert: None,
        client_key: None,
        gateway_connect_timeout_secs: 10,
        gateway_request_timeout_secs: 60,
        github_connect_timeout_secs: 10,
        github_request_timeout_secs: 30,
        gateway_max_retries: 3,
    };

    // No repo config → synthetic_default picks ownership=shared, carries
    // full_replace from env — incompatible combination.
    let err = resolve_env(None, &env_config, None).unwrap_err();
    assert!(
        err.to_string().contains("full_replace"),
        "expected full_replace+shared rejection, got: {err}"
    );
    assert!(err.to_string().contains("shared"));
}

#[test]
fn repo_config_rejects_unknown_default_environment() {
    let yaml = r#"
environments:
  staging:
    overlay: staging
default_environment: production
"#;
    let file = write_repo_config(yaml);
    let err = RepoConfig::load_from_path(file.path()).unwrap_err();
    assert!(err.to_string().contains("default_environment"));
}

#[test]
fn repo_config_rejects_empty_environments_map() {
    // An empty `environments` map would emit `[]` from `gitforgeops envs`,
    // and the matrix-job workflows gate on `outputs.envs != '[]'` — so
    // validate/apply/drift jobs would silently skip with no error,
    // producing a no-op pipeline from a "valid" config. The fix is to
    // hard-fail at config load. Operators who don't want a multi-env
    // config should delete the file entirely (synthetic-default kicks in).
    let yaml = r#"
environments: {}
"#;
    let file = write_repo_config(yaml);
    let err = RepoConfig::load_from_path(file.path()).unwrap_err();
    assert!(
        err.to_string().contains("empty `environments`"),
        "expected an empty-environments error, got: {err}"
    );
}

#[test]
fn repo_config_rejects_unknown_fields_at_every_owned_level() {
    let cases = [
        (
            "future_top_level",
            "version: 1\nenvironments:\n  staging: {}\nfuture_top_level: true\n",
        ),
        (
            "future_environment",
            "version: 1\nenvironments:\n  staging:\n    future_environment: true\n",
        ),
        (
            "future_ownership",
            "version: 1\nenvironments:\n  staging:\n    ownership:\n      future_ownership: true\n",
        ),
        (
            "future_drift_flag",
            "version: 1\nenvironments:\n  staging:\n    ownership:\n      drift_alert_on:\n        future_drift_flag: true\n",
        ),
    ];

    for (unknown, yaml) in cases {
        let file = write_repo_config(yaml);
        let error = RepoConfig::load_from_path(file.path()).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(unknown), "{message}");
        assert!(
            message.contains(&file.path().display().to_string()),
            "{message}"
        );
    }
}

#[test]
fn repo_config_rejects_unsupported_versions() {
    let file = write_repo_config("version: 2\nenvironments:\n  staging: {}\n");
    let error = RepoConfig::load_from_path(file.path()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("version 2"), "{message}");
    assert!(message.contains("expected version 1"), "{message}");
    assert!(
        message.contains(&file.path().display().to_string()),
        "{message}"
    );
}

#[test]
fn shipped_repo_config_example_satisfies_the_closed_schema() {
    let path = std::path::Path::new(".gitforgeops/config.example.yaml");
    let config = RepoConfig::load_from_path(path)
        .expect("the shipped example must parse")
        .expect("the shipped example must exist");
    assert_eq!(config.version, 1);
    assert_eq!(config.default_environment.as_deref(), Some("staging"));
}

/// Every overlay the shipped example selects has to exist in this repository.
/// The README tells operators to copy that file verbatim; an environment
/// pointing at a directory nobody shipped fails `validate` / `plan` / `apply`
/// for that environment, and the `validate-pr` matrix job with it.
#[test]
fn every_overlay_named_by_the_shipped_example_is_present_in_the_repository() {
    let config =
        RepoConfig::load_from_path(std::path::Path::new(".gitforgeops/config.example.yaml"))
            .unwrap()
            .unwrap();

    let overlays = std::path::Path::new(gitforgeops::config::OVERLAYS_ROOT);
    for name in config.environment_names() {
        let Some(overlay) = config
            .environment(&name)
            .and_then(|env| env.overlay.clone())
        else {
            continue;
        };
        let directory = overlays.join(&overlay);
        assert!(
            directory.is_dir(),
            "environment '{name}' selects overlay '{overlay}' but {} does not exist",
            directory.display()
        );
    }
}

#[test]
fn a_missing_overlay_directory_is_reported_up_front_with_environment_and_source() {
    use gitforgeops::config::env::EnvConfig;
    use gitforgeops::config::{resolve_env, validate_overlay_selection};

    let file = write_repo_config(
        "version: 1\nenvironments:\n  sandbox:\n    overlay: sandbox\ndefault_environment: sandbox\n",
    );
    let repo = RepoConfig::load_from_path(file.path()).unwrap().unwrap();
    let env_config = EnvConfig::default();
    let resolved = resolve_env(Some(&repo), &env_config, Some("sandbox")).unwrap();

    let overlays = tempfile::tempdir().unwrap();
    let error = validate_overlay_selection(&resolved, Some(&repo), overlays.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("environment 'sandbox'"), "{error}");
    assert!(error.contains("overlay 'sandbox'"), "{error}");
    assert!(
        error.contains(gitforgeops::config::REPO_CONFIG_PATH),
        "the message must name the file that declared the selection: {error}"
    );
    assert!(
        error.contains(&overlays.path().join("sandbox").display().to_string()),
        "{error}"
    );

    // Once the directory exists, the check is silent.
    std::fs::create_dir_all(overlays.path().join("sandbox")).unwrap();
    validate_overlay_selection(&resolved, Some(&repo), overlays.path()).unwrap();
}

#[test]
fn a_missing_overlay_from_the_env_var_blames_the_env_var_not_the_config_file() {
    use gitforgeops::config::env::EnvConfig;
    use gitforgeops::config::{resolve_env, validate_overlay_selection};

    let env_config = EnvConfig {
        overlay: Some("nope".to_string()),
        ..EnvConfig::default()
    };
    let resolved = resolve_env(None, &env_config, None).unwrap();

    let overlays = tempfile::tempdir().unwrap();
    let error = validate_overlay_selection(&resolved, None, overlays.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("FERRUM_OVERLAY"), "{error}");
    assert!(
        !error.contains(gitforgeops::config::REPO_CONFIG_PATH),
        "no repo config declared this overlay: {error}"
    );
}

#[test]
fn an_environment_without_an_overlay_is_never_checked() {
    use gitforgeops::config::env::EnvConfig;
    use gitforgeops::config::{resolve_env, validate_overlay_selection};

    let resolved = resolve_env(None, &EnvConfig::default(), None).unwrap();
    assert!(resolved.overlay.is_none());
    validate_overlay_selection(&resolved, None, std::path::Path::new("/nonexistent")).unwrap();
}
