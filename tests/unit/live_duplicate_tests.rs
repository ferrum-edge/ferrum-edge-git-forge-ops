use std::collections::{BTreeSet, HashSet};

use gitforgeops::config::{filter_config_by_namespace, GatewayConfig};
use gitforgeops::diff::{self, DiffOptions, OwnershipScope};
use gitforgeops::error::Error;
use gitforgeops::http_client::{BackupExtras, BackupSnapshot, SealStrictness};

pub(super) const KINDS: [(&str, &str); 4] = [
    ("proxies", "Proxy"),
    ("consumers", "Consumer"),
    ("upstreams", "Upstream"),
    ("plugin_configs", "PluginConfig"),
];
pub(super) const SECRET: &str = "duplicate-fixture-secret-never-in-diagnostics";

pub(super) fn duplicate_backup(section: &str, namespace: &str) -> serde_json::Value {
    let mut row = serde_json::json!({"id": "app", "namespace": namespace});
    match section {
        "proxies" => row["backend_host"] = "app.internal".into(),
        "consumers" => {
            row["username"] = "app".into();
            row["credentials"] = serde_json::json!({"keyauth": [{"key": SECRET}]});
        }
        "upstreams" => {
            row["targets"] = serde_json::json!([]);
            row["service_discovery"] = serde_json::json!({
                "provider": "consul",
                "consul": {"address": "http://consul:8500", "service_name": "app", "token": SECRET}
            });
        }
        "plugin_configs" => {
            row["plugin_name"] = "key_auth".into();
            row["scope"] = "global".into();
            row["config"] = serde_json::json!({"secret": SECRET});
        }
        _ => panic!("unknown test section"),
    }
    let mut different = row.clone();
    different["labels"] = serde_json::json!({"revision": "different"});
    let mut backup = serde_json::json!({});
    backup[section] = serde_json::json!([row, different]);
    backup
}

fn assert_duplicate(error: Error, kind: &str) {
    assert!(matches!(&error, Error::DuplicateLiveResource(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains(kind), "{message}");
    assert!(message.contains("app"), "{message}");
    assert!(!message.contains(SECRET), "{message}");
    assert!(!message.contains("revision"), "{message}");
}

#[test]
fn backup_and_direct_comparison_boundaries_refuse_every_duplicate_kind() {
    for (section, kind) in KINDS {
        for identical in [false, true] {
            for reverse in [false, true] {
                let mut body = duplicate_backup(section, "team");
                if identical {
                    body[section][1] = body[section][0].clone();
                }
                if reverse {
                    body[section].as_array_mut().unwrap().reverse();
                }
                let text = body.to_string();
                assert_duplicate(BackupSnapshot::from_body(&text).unwrap_err(), kind);
                assert_duplicate(
                    BackupSnapshot::from_scoped_body(&text, "team").unwrap_err(),
                    kind,
                );
                for strictness in [SealStrictness::Strict, SealStrictness::Advisory] {
                    assert_duplicate(
                        BackupSnapshot::from_value_with_strictness(body.clone(), strictness)
                            .unwrap_err(),
                        kind,
                    );
                }

                // Bypass the backup decoder exactly as a library caller can.
                let actual: GatewayConfig = serde_json::from_value(body.clone()).unwrap();
                body[section].as_array_mut().unwrap().truncate(1);
                let matching: GatewayConfig = serde_json::from_value(body).unwrap();
                let managed = HashSet::from([diff::resource_diff::state_key("team", kind, "app")]);
                for desired in [&matching, &GatewayConfig::default()] {
                    assert_duplicate(diff::compute_diff(desired, &actual).unwrap_err(), kind);
                    for fence in [None, Some(&managed)] {
                        assert_duplicate(
                            diff::compute_diff_with_ownership(desired, &actual, fence).unwrap_err(),
                            kind,
                        );
                    }
                    for scope in [
                        OwnershipScope::Exclusive,
                        OwnershipScope::Shared {
                            previously_managed: &managed,
                        },
                    ] {
                        assert_duplicate(
                            diff::compute_diff_with_scope(desired, &actual, scope).unwrap_err(),
                            kind,
                        );
                        for prune_spec_owned in [false, true] {
                            assert_duplicate(
                                diff::compute_diff_with_options(
                                    desired,
                                    &actual,
                                    scope,
                                    DiffOptions { prune_spec_owned },
                                )
                                .unwrap_err(),
                                kind,
                            );
                        }
                    }
                    let pending = managed.iter().cloned().collect::<BTreeSet<_>>();
                    assert_duplicate(
                        gitforgeops::apply::adoption_candidates(
                            desired,
                            &actual,
                            &BTreeSet::new(),
                            &BTreeSet::new(),
                        )
                        .unwrap_err(),
                        kind,
                    );
                    assert_duplicate(
                        gitforgeops::apply::pending_create_assertion_diffs(
                            desired, &actual, &pending, "team",
                        )
                        .unwrap_err(),
                        kind,
                    );
                    assert_duplicate(
                        gitforgeops::apply::preserve_spec_owned_graph(
                            desired,
                            &actual,
                            &BackupExtras::default(),
                            "team",
                        )
                        .unwrap_err(),
                        kind,
                    );
                }
            }
        }
    }
}

#[test]
fn identities_are_scoped_by_kind_and_namespace_and_filters_preserve_duplicates() {
    let mut body = serde_json::json!({});
    for (section, _) in KINDS {
        let mut rows = duplicate_backup(section, "team")[section].clone();
        rows[1]["namespace"] = "other".into();
        body[section] = rows;
    }
    let snapshot = BackupSnapshot::from_value(body).unwrap();
    assert!(diff::compute_diff(&snapshot.config, &snapshot.config)
        .unwrap()
        .is_empty());
    assert_eq!(
        diff::compute_diff(&GatewayConfig::default(), &snapshot.config)
            .unwrap()
            .len(),
        8
    );

    for (section, kind) in KINDS {
        let actual: GatewayConfig =
            serde_json::from_value(duplicate_backup(section, "team")).unwrap();
        let selected = filter_config_by_namespace(&actual, "team");
        assert_duplicate(
            diff::compute_diff(&GatewayConfig::default(), &selected).unwrap_err(),
            kind,
        );
        let unselected = filter_config_by_namespace(&actual, "other");
        assert!(diff::compute_diff(&GatewayConfig::default(), &unselected)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn crafted_backup_file_is_refused_before_import_publication() {
    for (section, kind) in KINDS {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("backup.json");
        let output = dir.path().join("resources");
        let bundle = dir.path().join("credentials.json");
        std::fs::write(&input, duplicate_backup(section, "team").to_string()).unwrap();
        let error = gitforgeops::import::import_from_file(
            &input,
            &output,
            Some(&bundle),
            &gitforgeops::import::ImportPassthroughPolicy::strict(),
            &[],
        )
        .unwrap_err();
        assert_duplicate(error, kind);
        assert!(!output.exists());
        assert!(!bundle.exists());
    }
}
