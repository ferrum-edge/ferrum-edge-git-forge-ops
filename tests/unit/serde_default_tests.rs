//! Every config struct with a hand-written `Default` also carries
//! container-level `#[serde(default)]`, so that impl is the single definition
//! of each field's default. These tests pin it: an empty document must
//! deserialize to exactly `T::default()`, field for field. A field added later
//! whose serde default drifts from the impl (the `DriftAlertOn` regression:
//! derived all-`false` beside `#[serde(default = "default_true")]`) fails here
//! without anyone having to list the field by name.

use std::io::Write;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use gitforgeops::config::repo_config::{
    DriftAlertOn, EnvironmentConfig, OwnershipConfig, RepoConfig,
};
use gitforgeops::policy::config::{
    load_policies_from_path, OverrideConfig, PolicyConfig, PolicyRules,
};
use gitforgeops::state::StateFile;

/// Compare through `serde_json::Value` so the check needs no `PartialEq` on
/// the config types and covers every field, including ones added later.
fn parsed<T: DeserializeOwned + Serialize>(document: &str) -> serde_json::Value {
    let value: T = serde_yaml::from_str(document).expect("document parses");
    serde_json::to_value(value).expect("value serializes")
}

fn default_of<T: Default + Serialize>() -> serde_json::Value {
    serde_json::to_value(T::default()).expect("default serializes")
}

fn assert_empty_document_is_default<T: Default + Serialize + DeserializeOwned>(name: &str) {
    assert_eq!(
        parsed::<T>("{}"),
        default_of::<T>(),
        "{name}: `{{}}` must deserialize to `Default::default()`"
    );
}

#[test]
fn repo_config_types_fill_missing_keys_from_default() {
    assert_empty_document_is_default::<DriftAlertOn>("DriftAlertOn");
    assert_empty_document_is_default::<OwnershipConfig>("OwnershipConfig");
    assert_empty_document_is_default::<EnvironmentConfig>("EnvironmentConfig");
    assert_empty_document_is_default::<RepoConfig>("RepoConfig");
}

#[test]
fn policy_config_types_fill_missing_keys_from_default() {
    assert_empty_document_is_default::<OverrideConfig>("OverrideConfig");
    assert_empty_document_is_default::<PolicyRules>("PolicyRules");
    assert_empty_document_is_default::<PolicyConfig>("PolicyConfig");
}

#[test]
fn state_file_fills_missing_keys_from_default() {
    // `StateFile` keeps its required keys (a ledger with no `environment` or
    // `resources` must not parse), so the document carries exactly those and
    // every optional key must come back as `StateFile::default()` has it.
    let document = format!(
        "version: {}\nenvironment: default\nresources: {{}}\n",
        StateFile::default().version
    );
    assert_eq!(parsed::<StateFile>(&document), default_of::<StateFile>());
}

#[test]
fn a_policy_file_without_a_version_line_loads() {
    // The loader's own tests all spell `version: 1` out; this is the path a
    // derived `Default` broke, so exercise the absent key end to end.
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"policies: {}\n").unwrap();
    let loaded = load_policies_from_path(file.path())
        .expect("loads")
        .expect("file exists");
    assert_eq!(loaded.version, PolicyConfig::default().version);
}

#[test]
fn the_agreement_check_sees_a_divergent_per_field_default() {
    // Proves the helper is not vacuous: a per-field serde default beside a
    // disagreeing `Default` impl is exactly the shape it must reject.
    #[derive(Serialize, Deserialize)]
    struct Divergent {
        #[serde(default = "one")]
        version: u32,
    }
    fn one() -> u32 {
        1
    }
    impl Default for Divergent {
        fn default() -> Self {
            Self { version: 2 }
        }
    }
    assert_ne!(parsed::<Divergent>("{}"), default_of::<Divergent>());
}
