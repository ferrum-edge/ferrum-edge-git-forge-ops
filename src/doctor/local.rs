//! Checks that need no credential at all.
//!
//! Everything here is answerable from the repository on disk plus the process
//! environment, which makes it the tier a contributor can run on a laptop and
//! the tier that distinguishes "this is a template nobody has configured yet"
//! from "this is a deployment repository with a specific thing missing".

use std::path::{Path, PathBuf};

use super::{Check, Scope, Status};
use crate::config::env::GatewayMode;
use crate::config::repo_config::{RepoConfig, REPO_CONFIG_PATH};
use crate::config::EnvConfig;

/// Where the validator digest allowlist lives, and the resource tree root.
const VALIDATOR_PIN: &str = ".github/ferrum-edge-checksums.txt";
const RESOURCES_ROOT: &str = "./resources";
const OVERLAYS_ROOT: &str = "./overlays";
const REPO_CONFIG_EXAMPLE: &str = ".gitforgeops/config.example.yaml";

/// What kind of repository this is, which decides whether "unconfigured" is a
/// finding or the intended state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryKind {
    /// No `.gitforgeops/config.yaml`. Upstream's own copy, or a fresh clone
    /// nobody has configured. Deployment checks do not apply.
    Template,
    /// A committed repository config: this repository intends to deploy.
    Deployment,
}

pub fn repository_kind(root: &Path) -> RepositoryKind {
    if root.join(REPO_CONFIG_PATH).is_file() {
        RepositoryKind::Deployment
    } else {
        RepositoryKind::Template
    }
}

/// Run every secretless check against `root`.
///
/// `env` is the already-parsed process environment: a parse failure is itself
/// reported as a check by the caller, because `load_env_config` refuses
/// invalid enums and booleans before anything else runs.
pub fn run(root: &Path, env: Option<&EnvConfig>) -> Vec<Check> {
    let mut checks = Vec::new();
    let kind = repository_kind(root);
    checks.push(repository_shape(root, kind));

    let repo = match RepoConfig::load_from_path(&root.join(REPO_CONFIG_PATH)) {
        Ok(Some(config)) => {
            checks.push(Check::pass(
                "repo-config",
                "Repository configuration parses",
                Scope::Local,
                format!(
                    "{REPO_CONFIG_PATH} declares {} environment(s): {}",
                    config.environments.len(),
                    config.environment_names().join(", ")
                ),
            ));
            Some(config)
        }
        Ok(None) => {
            // A template is allowed to have none. A deployment repository
            // cannot reach this arm, because its presence is what defines the
            // kind — so this is purely the template's informational line.
            checks.push(
                Check::new(
                    "repo-config",
                    "Repository configuration parses",
                    Scope::Local,
                    Status::Skipped,
                    format!("no {REPO_CONFIG_PATH}; nothing declares a deployment environment"),
                )
                .remedy(format!(
                    "For GitHub Actions deployment, copy {REPO_CONFIG_EXAMPLE} to \
                     {REPO_CONFIG_PATH}, replace the example entries with your real \
                     environments, and commit it. Local CLI use does not need it."
                )),
            );
            None
        }
        Err(error) => {
            checks.push(
                Check::new(
                    "repo-config",
                    "Repository configuration parses",
                    Scope::Local,
                    Status::Fail,
                    format!("{REPO_CONFIG_PATH} did not load: {error}"),
                )
                .remedy(format!(
                    "Fix {REPO_CONFIG_PATH} until `gitforgeops envs` succeeds; the \
                     workflows enumerate environments with that command."
                )),
            );
            None
        }
    };

    checks.push(overlays(root, repo.as_ref()));
    checks.push(resources(root, kind));
    checks.push(policies(root));
    checks.extend(validator(root, env));

    if let Some(env) = env {
        checks.extend(mode_requirements(root, env, repo.as_ref(), kind));
    }
    checks
}

fn repository_shape(root: &Path, kind: RepositoryKind) -> Check {
    match kind {
        RepositoryKind::Template => Check::new(
            "repository-kind",
            "Template or deployment repository",
            Scope::Local,
            Status::Skipped,
            format!(
                "template repository: no {REPO_CONFIG_PATH}. `apply-on-merge.yml` \
                 emits an empty environment matrix and skips, and \
                 `trusted-pr-review.yml` resolves no live-review targets. Both are \
                 intentional, not failures."
            ),
        )
        .remedy(
            "Deployment repositories commit .gitforgeops/config.yaml. Keep repository \
             variable GITFORGEOPS_TEMPLATE_REPO=true on a copy customers clone from.",
        ),
        RepositoryKind::Deployment => Check::pass(
            "repository-kind",
            "Template or deployment repository",
            Scope::Local,
            format!(
                "deployment repository: {} declares environments, so the \
                 environment-bound workflows will bind them",
                root.join(REPO_CONFIG_PATH).display()
            ),
        ),
    }
}

fn overlays(root: &Path, repo: Option<&RepoConfig>) -> Check {
    let Some(repo) = repo else {
        return Check::new(
            "overlays",
            "Configured overlays exist",
            Scope::Local,
            Status::Skipped,
            "no repository configuration selects an overlay",
        );
    };
    let missing: Vec<String> = repo
        .environments
        .iter()
        .filter_map(|(name, env)| {
            let overlay = env.overlay.as_ref()?;
            let directory = PathBuf::from(root)
                .join(OVERLAYS_ROOT.trim_start_matches("./"))
                .join(overlay);
            (!directory.is_dir()).then(|| format!("{name} -> overlays/{overlay}"))
        })
        .collect();
    if missing.is_empty() {
        Check::pass(
            "overlays",
            "Configured overlays exist",
            Scope::Local,
            "every environment's overlay directory is present",
        )
    } else {
        // `resolved::validate_overlay_selection` already fails a real run on
        // this, but only for the environment being run. Reporting all of them
        // at once is the point of a doctor.
        Check::new(
            "overlays",
            "Configured overlays exist",
            Scope::Local,
            Status::Fail,
            format!("missing overlay directories: {}", missing.join(", ")),
        )
        .remedy(
            "Create the directory (an empty one is valid) or remove `overlay:` from \
             that environment. A configured overlay that is not in the tree fails \
             every command for that environment.",
        )
    }
}

fn resources(root: &Path, kind: RepositoryKind) -> Check {
    let directory = root.join(RESOURCES_ROOT.trim_start_matches("./"));
    let namespaces: Vec<String> = std::fs::read_dir(&directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    if !directory.is_dir() {
        return Check::new(
            "resources",
            "Resource tree is present",
            Scope::Local,
            Status::Fail,
            format!("{} does not exist", directory.display()),
        )
        .remedy("Create resources/<namespace>/{proxies,consumers,upstreams,plugins}/.");
    }
    if namespaces.is_empty() {
        let status = match kind {
            RepositoryKind::Template => Status::Skipped,
            RepositoryKind::Deployment => Status::Warn,
        };
        return Check::new(
            "resources",
            "Resource tree is present",
            Scope::Local,
            status,
            "resources/ contains no namespace directory",
        )
        .remedy(
            "Add resources/<namespace>/proxies/<id>.yaml. An empty tree applies \
             nothing; in exclusive mode it would prune the namespace instead.",
        );
    }
    let mut sorted = namespaces;
    sorted.sort();
    Check::pass(
        "resources",
        "Resource tree is present",
        Scope::Local,
        format!("namespaces on disk: {}", sorted.join(", ")),
    )
}

fn policies(root: &Path) -> Check {
    let path = root.join(crate::policy::config::POLICY_CONFIG_PATH);
    if !path.is_file() {
        return Check::new(
            "policies",
            "Policy configuration parses",
            Scope::Local,
            Status::Skipped,
            "no .gitforgeops/policies.yaml; every policy rule stays disabled",
        );
    }
    match crate::policy::config::load_policies_from_path(&path) {
        Ok(_) => Check::pass(
            "policies",
            "Policy configuration parses",
            Scope::Local,
            ".gitforgeops/policies.yaml loads",
        ),
        Err(error) => Check::new(
            "policies",
            "Policy configuration parses",
            Scope::Local,
            Status::Fail,
            format!("policy configuration did not load: {error}"),
        )
        .remedy(
            "A policy config that does not load blocks `plan` and `apply` outright. \
             Fix it before merging.",
        ),
    }
}

/// The gateway validator is a separate binary and its build is pinned by
/// content digest, so "is it installed" and "is the pin present" are two
/// different questions with two different answers.
fn validator(root: &Path, env: Option<&EnvConfig>) -> Vec<Check> {
    let binary = env
        .map(|env| env.edge_binary_path.clone())
        .unwrap_or_else(|| "ferrum-edge".to_string());
    let located = which_binary(&binary);
    let availability = match located {
        Some(path) => Check::pass(
            "validator-binary",
            "ferrum-edge validator is available",
            Scope::Local,
            format!("{binary} resolves to {path}"),
        ),
        None => Check::new(
            "validator-binary",
            "ferrum-edge validator is available",
            Scope::Local,
            Status::Fail,
            format!("{binary} is not on PATH"),
        )
        .remedy(
            "Install it with .github/scripts/install-ferrum-edge.sh, or point \
             FERRUM_EDGE_BINARY_PATH at the binary. `validate`, `plan`, `review` and \
             `apply` all shell out to it.",
        ),
    };

    let pin_path = root.join(VALIDATOR_PIN);
    let pin = match std::fs::read_to_string(&pin_path) {
        Ok(contents)
            if contents
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#')) =>
        {
            Check::pass(
                "validator-pin",
                "Validator digest allowlist is populated",
                Scope::Local,
                format!("{VALIDATOR_PIN} allowlists at least one build"),
            )
        }
        Ok(_) => Check::new(
            "validator-pin",
            "Validator digest allowlist is populated",
            Scope::Local,
            Status::Fail,
            format!("{VALIDATOR_PIN} has no allowlisted digest"),
        )
        .remedy(
            "Run .github/scripts/refresh-ferrum-edge-pin.sh. CI installs only \
             allowlisted builds, so an empty allowlist fails every validating job.",
        ),
        Err(_) => Check::new(
            "validator-pin",
            "Validator digest allowlist is populated",
            Scope::Local,
            Status::Fail,
            format!("{VALIDATOR_PIN} is missing"),
        )
        .remedy("Restore it from the template; it is what pins the trusted validator build."),
    };

    vec![availability, pin]
}

/// Absent deployment credentials mean different things in the two repository
/// shapes, and collapsing them is how a fresh template reports as broken.
fn credential_presence(
    kind: RepositoryKind,
    id: &'static str,
    title: &'static str,
    name: &str,
    present: bool,
) -> Check {
    match (kind, present) {
        (_, true) => Check::secret_presence(id, title, Scope::Local, name, true),
        (RepositoryKind::Template, false) => Check::new(
            id,
            title,
            Scope::Local,
            Status::Skipped,
            format!("{name} is not set; a template repository deploys nowhere"),
        ),
        (RepositoryKind::Deployment, false) => {
            Check::secret_presence(id, title, Scope::Local, name, false)
        }
    }
}

/// `which`, without assuming `which` exists.
fn which_binary(binary: &str) -> Option<String> {
    if binary.contains(std::path::MAIN_SEPARATOR) {
        return Path::new(binary).is_file().then(|| binary.to_string());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.display().to_string())
}

/// Requirements that depend on which mode the environment deploys in.
///
/// These are *presence* checks. A `FERRUM_ADMIN_JWT_SECRET` that is set but
/// wrong passes here and fails the gateway scope with a 401, which is exactly
/// the distinction an operator needs: "not configured" and "configured wrong"
/// have different fixes.
fn mode_requirements(
    root: &Path,
    env: &EnvConfig,
    repo: Option<&RepoConfig>,
    kind: RepositoryKind,
) -> Vec<Check> {
    let mut checks = Vec::new();
    match env.gateway_mode {
        GatewayMode::Api => {
            // A template has no deployment target, so absent gateway
            // credentials are the intended state rather than a blocker. On a
            // deployment repository the same absence is exactly what an
            // operator needs named.
            checks.push(
                credential_presence(
                    kind,
                    "gateway-url",
                    "Gateway URL is configured",
                    "FERRUM_GATEWAY_URL",
                    env.gateway_url.is_some(),
                )
                .remedy(
                    "api mode needs an https:// gateway URL. In CI it is an Environment \
                     Secret of the same name as the environment.",
                ),
            );
            checks.push(
                credential_presence(
                    kind,
                    "admin-jwt-secret",
                    "Admin JWT signing secret is configured",
                    "FERRUM_ADMIN_JWT_SECRET",
                    env.admin_jwt_secret.is_some(),
                )
                .remedy(
                    "api mode needs the gateway's signing secret (>= 32 characters). \
                     Presence is not correctness: the gateway scope proves whether the \
                     value and its claims are accepted.",
                ),
            );
            // Every api-mode command starts with `GET /backup`, which Ferrum
            // Edge serves to `admin` only. `/cluster` — the gateway scope's
            // token proof — has no role requirement, so a `viewer`/`operator`
            // token passes there and then 403s on the first real command.
            let admin_role = env.admin_jwt_role == "admin";
            checks.push(
                Check::new(
                    "admin-jwt-claims",
                    "Admin JWT claims are declared",
                    Scope::Local,
                    if admin_role {
                        Status::Pass
                    } else {
                        Status::Fail
                    },
                    format!(
                        "issuer={}, role={}, audience={}, ttl={}s — each must match the \
                         gateway's own configuration",
                        env.admin_jwt_issuer,
                        env.admin_jwt_role,
                        env.admin_jwt_audience.as_deref().unwrap_or("<unset>"),
                        env.admin_jwt_ttl_secs
                    ),
                )
                .remedy(format!(
                    "FERRUM_ADMIN_JWT_ROLE={} cannot run any gitforgeops command: \
                     `/backup`, `/restore`, `/batch` and consumer CRUD are admin-only. \
                     Unset it or set it to `admin`.",
                    env.admin_jwt_role
                )),
            );
        }
        GatewayMode::File => {
            let output = PathBuf::from(&env.file_output_path);
            let parent = output.parent().filter(|path| !path.as_os_str().is_empty());
            let writable = parent.map(|path| root.join(path).is_dir()).unwrap_or(true);
            checks.push(if writable {
                Check::pass(
                    "file-output",
                    "File-mode output directory exists",
                    Scope::Local,
                    format!(
                        "assembled documents will be written to {}",
                        env.file_output_path
                    ),
                )
            } else {
                Check::new(
                    "file-output",
                    "File-mode output directory exists",
                    Scope::Local,
                    Status::Fail,
                    format!(
                        "the parent directory of FERRUM_FILE_OUTPUT_PATH ({}) does not exist",
                        env.file_output_path
                    ),
                )
                .remedy(
                    "Create the directory, or point FERRUM_FILE_OUTPUT_PATH somewhere that exists.",
                )
            });
            checks.push(
                Check::new(
                    "file-mode-live-review",
                    "File-mode environments disable live review",
                    Scope::Local,
                    match repo {
                        Some(config)
                            if config
                                .environments
                                .values()
                                .any(|environment| environment.live_review) =>
                        {
                            Status::Warn
                        }
                        _ => Status::Pass,
                    },
                    "file mode has no Admin API: live PR review and drift checks have \
                 nothing to compare against",
                )
                .remedy(
                    "Set `live_review: false` on file-mode environments. The drift check \
                 reports them as Skipped rather than as checked.",
                ),
            );
        }
    }
    checks
}
