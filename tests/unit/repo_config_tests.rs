use gitforgeops::config::repo_config::{OwnershipMode, RepoConfig};
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
