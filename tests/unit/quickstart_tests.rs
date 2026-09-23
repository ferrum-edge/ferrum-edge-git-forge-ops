//! Coverage for `tests/fixtures/quickstart/`: the copyable half of
//! `docs/quickstart.md`.
//!
//! A setup guide goes stale silently — a schema change, a loader rule, a new
//! fail-closed gate, and the copy-paste that worked last month now produces a
//! red first apply for the one person least equipped to debug it. This fixture
//! is the guide's examples verbatim, so that breakage lands here, in the pull
//! request that causes it.
//!
//! What is asserted is the set of promises the guide actually makes: the tree
//! loads under the strict loader, the overlay merges the way the guide says it
//! does, the shape is the minimal one it describes (one namespace, one
//! environment, shared ownership), and nothing in it can commit a secret.

use std::path::PathBuf;

use gitforgeops::config::repo_config::{OwnershipMode, RepoConfig};
use gitforgeops::config::{
    apply_overlay, assemble, load_resources, resolved::overlay_directory, AssembledOutput,
};
use gitforgeops::diff::security::{audit_security, security_blockers};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quickstart")
}

fn load(with_overlay: bool) -> AssembledOutput {
    let root = fixture_root();
    let mut resources = load_resources(&root.join("resources"))
        .expect("the quickstart tree must load under the strict loader");
    if with_overlay {
        let directory = overlay_directory(&root.join("overlays"), "production")
            .expect("the overlay the config selects must exist");
        apply_overlay(&mut resources, &directory).expect("overlay merges");
    }
    assemble(resources).expect("assemble")
}

fn repo_config() -> RepoConfig {
    RepoConfig::load_from_path(&fixture_root().join(".gitforgeops/config.yaml"))
        .expect("the quickstart repository config must load")
        .expect("the quickstart declares a config file")
}

#[test]
fn the_quickstart_tree_loads_and_assembles_under_strict_mode() {
    let assembled = load(false);
    let gateway = &assembled.gateway;
    assert_eq!(gateway.proxies.len(), 1, "{gateway:#?}");
    assert_eq!(gateway.upstreams.len(), 1, "{gateway:#?}");
    assert_eq!(gateway.consumers.len(), 1, "{gateway:#?}");
    assert_eq!(gateway.plugin_configs.len(), 1, "{gateway:#?}");
    assert!(assembled.mesh.is_none(), "the quickstart is api mode only");
}

#[test]
fn every_resource_lands_in_the_one_namespace_the_guide_describes() {
    // The guide's whole framing is "one gateway, one namespace, shared
    // ownership". Directory-inferred namespaces are what make that true
    // without any resource spelling it out.
    let gateway = load(true).gateway;
    let namespaces: std::collections::BTreeSet<&str> = gateway
        .proxies
        .iter()
        .map(|proxy| proxy.namespace.as_str())
        .chain(gateway.upstreams.iter().map(|item| item.namespace.as_str()))
        .chain(gateway.consumers.iter().map(|item| item.namespace.as_str()))
        .chain(
            gateway
                .plugin_configs
                .iter()
                .map(|item| item.namespace.as_str()),
        )
        .collect();
    assert_eq!(
        namespaces,
        ["ferrum"].into_iter().collect(),
        "{namespaces:?}"
    );
}

#[test]
fn the_production_overlay_changes_only_the_key_it_names() {
    // "Overlays deep-merge onto the resource of the same kind and id. Only the
    // keys named here change" — the guide's own words, checked.
    let base = load(false).gateway;
    let overlaid = load(true).gateway;

    let base_proxy = &base.proxies[0];
    let overlaid_proxy = &overlaid.proxies[0];
    assert_eq!(base_proxy.backend_host, "orders.internal");
    assert_eq!(overlaid_proxy.backend_host, "orders.prod.internal");
    assert_eq!(overlaid_proxy.id, base_proxy.id);
    assert_eq!(overlaid_proxy.listen_path, base_proxy.listen_path);
    assert_eq!(overlaid_proxy.backend_port, base_proxy.backend_port);
    assert_eq!(overlaid_proxy.name, base_proxy.name);
}

#[test]
fn the_declared_environment_matches_the_overlay_and_the_workflow_matrix() {
    let config = repo_config();
    assert_eq!(config.environment_names(), vec!["production".to_string()]);
    assert_eq!(config.default_environment.as_deref(), Some("production"));

    let environment = config.environment("production").expect("production entry");
    assert_eq!(environment.overlay.as_deref(), Some("production"));
    // Shared is what the guide promises: the repository manages only what it
    // has applied, and everything else on the gateway is reported, not pruned.
    assert!(matches!(environment.ownership.mode, OwnershipMode::Shared));
    // A missing overlay directory fails every command for the environment, so
    // the one the config names has to be in the tree.
    assert!(
        fixture_root().join("overlays/production").is_dir(),
        "overlays/production must exist"
    );
}

#[test]
fn the_environment_name_is_one_the_workflow_matrix_and_audit_accept() {
    // `envs --format json` feeds a GitHub Actions matrix and an
    // `environment:` binding, and `audit_settings.py` looks the same name up
    // through the REST API. The enumerator rejects anything outside this
    // pattern before a job is created.
    let pattern = regex_lite_matches("production");
    assert!(pattern, "environment names must be a safe path component");
}

/// The enumerator's contract, spelled out rather than pulled in as a dependency:
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`.
fn regex_lite_matches(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && name.len() <= 100
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[test]
fn the_quickstart_commits_no_credential_and_would_not_block_an_apply() {
    // `cmd_apply` runs this audit on the UNRESOLVED document before the state
    // lock, the bundle read and any gateway call. A guide whose copy-paste
    // trips that gate would teach a new operator that a first apply is
    // supposed to fail.
    let gateway = load(true).gateway;
    let findings = audit_security(&gateway);
    let blockers = security_blockers(&findings);
    assert!(blockers.is_empty(), "{blockers:#?}");
}

#[test]
fn the_consumer_credential_is_a_broker_placeholder_not_a_literal() {
    let source = std::fs::read_to_string(
        fixture_root().join("resources/ferrum/consumers/orders-client.yaml"),
    )
    .expect("read consumer");
    assert!(
        source.contains("${gh-env-secret:alloc=generate}"),
        "the quickstart must demonstrate first-apply allocation: {source}"
    );
}

#[test]
fn the_scoped_plugin_targets_the_proxy_the_guide_declares() {
    // A scoped plugin config whose `proxy_id` names a proxy this repository
    // does not declare is an error-severity security finding. The guide's two
    // files have to agree, and a copy-paste that renames one and not the other
    // is exactly the mistake this catches.
    let gateway = load(true).gateway;
    let plugin = &gateway.plugin_configs[0];
    let proxy = &gateway.proxies[0];
    assert_eq!(plugin.proxy_id.as_deref(), Some(proxy.id.as_str()));
    assert_eq!(plugin.namespace, proxy.namespace);
}

// -- the guide and the fixture are the same bytes --------------------------

/// Pull the YAML block that follows a `` `path`: `` heading line out of the
/// guide.
///
/// The guide introduces each file as ``` `resources/ferrum/proxies/orders.yaml`: ```
/// immediately before its fenced block, so the anchor is unambiguous without
/// parsing Markdown.
fn documented_block(guide: &str, path: &str) -> String {
    let anchor = format!("`{path}`:");
    let after = guide
        .split_once(&anchor)
        .unwrap_or_else(|| panic!("{path} is not introduced in docs/quickstart.md"))
        .1;
    let fenced = after
        .split_once("```yaml\n")
        .unwrap_or_else(|| panic!("{path} has no yaml block in docs/quickstart.md"))
        .1;
    fenced
        .split_once("\n```")
        .unwrap_or_else(|| panic!("{path}'s yaml block is unterminated"))
        .0
        .to_string()
        + "\n"
}

#[test]
fn every_file_the_guide_tells_you_to_copy_is_the_tested_fixture() {
    // The failure this prevents: someone edits a resource in the guide, the
    // fixture keeps passing, and the copy-paste a new operator actually runs
    // is the untested one. Byte equality is the only version of this check
    // that cannot rot.
    let guide = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/quickstart.md"),
    )
    .expect("read docs/quickstart.md");

    for relative in [
        ".gitforgeops/config.yaml",
        "resources/ferrum/upstreams/orders.yaml",
        "resources/ferrum/proxies/orders.yaml",
        "resources/ferrum/plugins/orders-key-auth.yaml",
        "resources/ferrum/consumers/orders-client.yaml",
        "overlays/production/ferrum/proxies/orders.yaml",
    ] {
        let fixture = std::fs::read_to_string(fixture_root().join(relative))
            .unwrap_or_else(|error| panic!("read fixture {relative}: {error}"));
        assert_eq!(
            documented_block(&guide, relative),
            fixture,
            "docs/quickstart.md and tests/fixtures/quickstart/{relative} have drifted"
        );
    }
}

/// Markdown is hard-wrapped, so a phrase can straddle a newline. Compare on
/// collapsed whitespace rather than on the wrap the author happened to choose.
fn guide_text() -> String {
    let raw = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/quickstart.md"),
    )
    .expect("read docs/quickstart.md");
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_guide_states_the_two_approvals_that_are_actually_required() {
    // The stale guidance this replaces claimed the branch ruleset needs an
    // approving review (it does not: `required_approving_review_count` is 0)
    // and offered a Repository Admin bypass as the solo-maintainer workaround.
    // The real constraint is the ENVIRONMENT approval plus self-review
    // prevention, which no bypass actor affects.
    let guide = guide_text();
    assert!(guide.contains("required_approving_review_count: 0"));
    assert!(guide.contains("prevent_self_review: true"));
    assert!(guide.contains("**A single-person repository cannot satisfy both halves.**"));
    // And it must not resurrect the bypass that does not solve this.
    assert!(!guide.contains("gh pr merge --admin"));
}

#[test]
fn the_guide_says_github_deployment_needs_the_committed_config() {
    let guide = guide_text();
    // The claim this corrects: that a one-environment setup needs no
    // `.gitforgeops/config.yaml`. It does not for local CLI use, and it
    // absolutely does for the bundled workflows.
    assert!(guide.contains("emits an empty matrix and deploys nothing"));
    assert!(guide.contains("fails its enumeration preflight"));
    assert!(guide.contains("Local CLI use does not need it"));
}

#[test]
fn the_guide_names_shipped_doctor_commands_and_local_tool_prerequisites() {
    let guide = guide_text();
    assert!(guide.contains("gitforgeops doctor` for local checks and GitHub metadata"));
    assert!(guide.contains("gitforgeops doctor --scope all --env production"));
    assert!(guide.contains("README: Setup doctor"));
    assert!(guide.contains("FERRUM_EDGE_BINARY_PATH=/path/to/ferrum-edge"));
    assert!(guide.contains("Ferrum Edge v0.9.5"));
    assert!(guide.contains("31573f0afab23694ce0cfe432f1220dd38099e3ee643e8c5d5b6d2bb3488297c"));
    assert!(guide.contains("Install `age`"));
    assert!(guide.contains("install `python3`"));
    assert!(guide.contains("gitforgeops-required-static-validation"));
    assert!(guide.contains("rust-ci-check"));
}

#[test]
fn the_bootstrap_explicitly_protects_production_before_secrets_are_set() {
    let guide = guide_text();
    let bootstrap = guide
        .split("## 3. Apply the settings baseline")
        .nth(1)
        .expect("quickstart has a settings-baseline step")
        .split("## 4. Commit the repository configuration")
        .next()
        .expect("settings-baseline step ends before repository configuration");

    assert_eq!(
        bootstrap
            .matches("--environment production \\ --reviewer")
            .count(),
        2,
        "both the plan and apply bootstrap commands must name production before config discovery is available"
    );
    assert!(
        bootstrap.contains("confirm the applied plan contains `CREATE environment production` or `UPDATE environment production`"),
        "operators must verify the protected environment was reconciled before installing secrets"
    );
}
