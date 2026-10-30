//! Checks that need no credential at all.
//!
//! Everything here is answerable from the repository on disk plus the process
//! environment, which makes it the tier a contributor can run on a laptop and
//! the tier that distinguishes "this is a template nobody has configured yet"
//! from "this is a deployment repository with a specific thing missing".
//!
//! Nothing here writes. Writability and executability are asked of the
//! operating system (`faccessat(2)` with `AT_EACCESS` on Unix), never tested
//! by creating a file.

use std::path::{Path, PathBuf};

use super::{Check, Scope, Status};
use crate::config::env::GatewayMode;
use crate::config::repo_config::{RepoConfig, REPO_CONFIG_PATH};
use crate::config::{resolve_env, EnvConfig, ResolvedEnv};
use crate::error::Error;

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

/// One environment a run could select, as the commands resolve it.
type Environment = (String, crate::error::Result<ResolvedEnv>);

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

    let environments = environments(repo.as_ref(), env);
    checks.push(overlays(root, repo.as_ref(), &environments));
    checks.push(resources(root, kind));
    checks.extend(resource_load(root, env, &environments));
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

/// Every environment a run could select, resolved exactly as the commands
/// resolve it (`resolve_env`: repository config first, `FERRUM_OVERLAY` and
/// `FERRUM_NAMESPACE` as fallbacks). Without a repository config, or with one
/// that declares no environment, that is the single synthetic environment.
///
/// An unparsed process environment resolves against the defaults: the
/// repository config's own selections are still checked, the `FERRUM_*`
/// fallbacks cannot be.
fn environments(repo: Option<&RepoConfig>, env: Option<&EnvConfig>) -> Vec<Environment> {
    let defaults = EnvConfig::default();
    let env = env.unwrap_or(&defaults);
    let names = repo.map(RepoConfig::environment_names).unwrap_or_default();
    if names.is_empty() {
        let resolved = resolve_env(repo, env, None);
        let name = resolved
            .as_ref()
            .map(|resolved| resolved.name.clone())
            .unwrap_or_else(|_| ResolvedEnv::default_env_name());
        return vec![(name, resolved)];
    }
    names
        .into_iter()
        .map(|name| {
            let resolved = resolve_env(repo, env, Some(&name));
            (name, resolved)
        })
        .collect()
}

fn overlays_root(root: &Path) -> PathBuf {
    root.join(OVERLAYS_ROOT.trim_start_matches("./"))
}

fn resources_root(root: &Path) -> PathBuf {
    root.join(RESOURCES_ROOT.trim_start_matches("./"))
}

fn overlays(root: &Path, repo: Option<&RepoConfig>, environments: &[Environment]) -> Check {
    let selecting: Vec<&ResolvedEnv> = environments
        .iter()
        .filter_map(|(_, resolved)| resolved.as_ref().ok())
        .filter(|resolved| resolved.overlay.is_some())
        .collect();
    if selecting.is_empty() {
        return Check::new(
            "overlays",
            "Configured overlays exist",
            Scope::Local,
            Status::Skipped,
            "neither the repository configuration nor FERRUM_OVERLAY selects an overlay",
        );
    }
    // `resolved::validate_overlay_selection` fails a real run on this, but
    // only for the environment being run. Reporting all of them at once is
    // the point of a doctor; the predicate is the same one.
    let overlays_root = overlays_root(root);
    let missing: Vec<String> = selecting
        .iter()
        .filter_map(|resolved| {
            let error =
                crate::config::validate_overlay_selection(resolved, repo, &overlays_root).err()?;
            let overlay = resolved.overlay.as_deref().unwrap_or_default();
            let declared = repo
                .and_then(|repo| repo.environment(&resolved.name))
                .and_then(|env| env.overlay.as_deref())
                == Some(overlay);
            let source = if declared {
                format!("declared in {REPO_CONFIG_PATH}")
            } else {
                "selected by FERRUM_OVERLAY".to_string()
            };
            Some(match error {
                // The "does not exist" refusal: the line above says it.
                Error::Config(_) => format!("{} -> overlays/{overlay} ({source})", resolved.name),
                // An overlay name the resolver refuses outright.
                other => format!(
                    "{} -> overlays/{overlay} ({source}): {other}",
                    resolved.name
                ),
            })
        })
        .collect();
    if missing.is_empty() {
        Check::pass(
            "overlays",
            "Configured overlays exist",
            Scope::Local,
            "every selected overlay directory is present",
        )
    } else {
        Check::new(
            "overlays",
            "Configured overlays exist",
            Scope::Local,
            Status::Fail,
            format!("missing overlay directories: {}", missing.join(", ")),
        )
        .remedy(
            "Create the directory (an empty one is valid), remove `overlay:` from \
             that environment, or unset FERRUM_OVERLAY. A selected overlay that is \
             not in the tree fails every command for that environment.",
        )
    }
}

fn resources(root: &Path, kind: RepositoryKind) -> Check {
    let directory = resources_root(root);
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
    // An unreadable tree is not an empty one: every command fails on it.
    let entries = match std::fs::read_dir(&directory)
        .and_then(|entries| entries.collect::<std::io::Result<Vec<_>>>())
    {
        Ok(entries) => entries,
        Err(error) => {
            return Check::new(
                "resources",
                "Resource tree is present",
                Scope::Local,
                Status::Fail,
                format!("{} cannot be read: {error}", directory.display()),
            )
            .remedy(
                "Every command loads the whole tree first. Fix the directory's \
                 permissions or ownership so this user can list and read it.",
            );
        }
    };
    let mut namespaces: Vec<String> = entries
        .iter()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
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
    namespaces.sort();
    Check::pass(
        "resources",
        "Resource tree is present",
        Scope::Local,
        format!("namespaces on disk: {}", namespaces.join(", ")),
    )
}

/// Load and assemble the tree for each environment through
/// [`crate::pipeline::load_and_assemble`], the boundary every command crosses
/// first. Offline: no bundle, no state file, no lock, no network. Parse
/// errors, unknown fields, symlinks, overlay mismatches, duplicate keys and
/// exclusive-scope violations surface here instead of from a command.
fn resource_load(root: &Path, env: Option<&EnvConfig>, environments: &[Environment]) -> Vec<Check> {
    const ID: &str = "resource-load";
    const TITLE: &str = "Resource tree loads and assembles";
    let Some(env) = env else {
        return vec![Check::new(
            ID,
            TITLE,
            Scope::Local,
            Status::Unknown,
            "the process environment did not parse, so the load options and \
             FERRUM_* fallbacks a run would use are unknown",
        )
        .remedy("Fix the process-environment finding, then re-run.")];
    };
    let resources_dir = resources_root(root);
    let overlays_root = overlays_root(root);
    environments
        .iter()
        .map(|(name, resolved)| {
            let outcome = match resolved {
                Ok(resolved) => crate::pipeline::load_and_assemble(
                    &resources_dir,
                    &overlays_root,
                    resolved,
                    env,
                ),
                Err(error) => Err(Error::Config(format!(
                    "environment '{name}' does not resolve: {error}"
                ))),
            };
            let check = match outcome {
                // `validate`, `plan`, `diff`, `apply` and `export` refuse a
                // filter that selects nothing from a non-empty tree unless
                // `--allow-empty-namespace` is passed, which doctor does not
                // take: judge it as they do by default. Doctor-local, so
                // `review`'s warning-only handling is untouched.
                Ok(assembled) => match assembled.namespace_scope.desired_finding(false) {
                    Some(finding) => Check::new(
                        ID,
                        TITLE,
                        Scope::Local,
                        Status::Fail,
                        crate::diagnostics::sanitize_line(&finding.message),
                    )
                    .remedy(
                        "`validate`, `plan`, `diff`, `apply` and `export` exit 1 on this \
                         selection. Fix FERRUM_NAMESPACE or the environment's \
                         `namespace_filter` so it names a namespace under resources/.",
                    ),
                    None => {
                        let gateway = &assembled.gateway;
                        Check::pass(
                            ID,
                            TITLE,
                            Scope::Local,
                            format!(
                                "{} proxies, {} consumers, {} upstreams, {} plugin configs, \
                             {} mesh fragment(s)",
                                gateway.proxies.len(),
                                gateway.consumers.len(),
                                gateway.upstreams.len(),
                                gateway.plugin_configs.len(),
                                assembled.mesh_sources.len(),
                            ),
                        )
                    }
                },
                // Already the `resources` check's failure: one missing
                // directory is one finding.
                Err(Error::NoResourcesDir(_)) => Check::new(
                    ID,
                    TITLE,
                    Scope::Local,
                    Status::Skipped,
                    "there is no resources/ directory to load (see the resource tree check)",
                ),
                Err(error) => Check::new(ID, TITLE, Scope::Local, Status::Fail, error.to_string())
                    .remedy(
                        "Every command (`validate`, `plan`, `apply`, ...) refuses on this \
                         before it reads credentials or contacts a gateway. \
                         `gitforgeops validate` reports the same error.",
                    ),
            };
            check.for_environment(name)
        })
        .collect()
}

fn policies(root: &Path) -> Check {
    let path = root.join(crate::policy::config::POLICY_CONFIG_PATH);
    match crate::policy::config::load_policies_from_path(&path) {
        Ok(None) => Check::new(
            "policies",
            "Policy configuration parses",
            Scope::Local,
            Status::Skipped,
            "no .gitforgeops/policies.yaml; every policy rule stays disabled",
        ),
        Ok(Some(_)) => Check::pass(
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
    let availability = match which_binary(&binary) {
        Located::Executable(path) => Check::pass(
            "validator-binary",
            "ferrum-edge validator is available",
            Scope::Local,
            format!("{binary} resolves to {path}"),
        ),
        Located::NotExecutable(path) => Check::new(
            "validator-binary",
            "ferrum-edge validator is available",
            Scope::Local,
            Status::Fail,
            format!("{binary} resolves to {path}, which is not executable"),
        )
        .remedy(
            "`validate`, `plan`, `review` and `apply` all execute it. Reinstall it \
             with .github/scripts/install-ferrum-edge.sh (which sets the execute bit \
             only after the digest matches), or `chmod +x` a binary you verified.",
        ),
        Located::Missing => Check::new(
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

/// Where a binary name resolved.
enum Located {
    Executable(String),
    /// A regular file, but this user may not execute it.
    NotExecutable(String),
    Missing,
}

/// Ask the operating system whether this process may `access` `path`, with
/// its **effective** user and group ids (`faccessat(AT_FDCWD, ..,
/// AT_EACCESS)`), which are what an `open` or `exec` would be judged by.
///
/// Falls back to `access(2)` (real ids) only where the effective check is
/// unavailable: Android, where rustix defines no `AT_EACCESS`, and a macOS
/// without `faccessat`, which rustix emulates with `access` and answers
/// `OPNOTSUPP` (or `NOSYS`) for any flag. Real and effective ids differ only
/// for a set-id process, which `gitforgeops` is not.
#[cfg(unix)]
fn effective_access(path: &Path, access: rustix::fs::Access) -> bool {
    #[cfg(not(target_os = "android"))]
    match rustix::fs::accessat(rustix::fs::CWD, path, access, rustix::fs::AtFlags::EACCESS) {
        Ok(()) => return true,
        Err(error)
            if error == rustix::io::Errno::OPNOTSUPP || error == rustix::io::Errno::NOSYS => {}
        Err(_) => return false,
    }
    rustix::fs::access(path, access).is_ok()
}

/// Whether this process may execute `path`.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    path.is_file() && effective_access(path, rustix::fs::Access::EXEC_OK)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// `which`, without assuming `which` exists. Like `which`, a non-executable
/// file earlier on `PATH` does not shadow an executable one later.
fn which_binary(binary: &str) -> Located {
    if binary.contains(std::path::MAIN_SEPARATOR) {
        let path = Path::new(binary);
        return if is_executable(path) {
            Located::Executable(binary.to_string())
        } else if path.is_file() {
            Located::NotExecutable(binary.to_string())
        } else {
            Located::Missing
        };
    }
    let Some(path) = std::env::var_os("PATH") else {
        return Located::Missing;
    };
    let candidates: Vec<PathBuf> = std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .filter(|candidate| candidate.is_file())
        .collect();
    if let Some(found) = candidates.iter().find(|candidate| is_executable(candidate)) {
        return Located::Executable(found.display().to_string());
    }
    match candidates.first() {
        Some(found) => Located::NotExecutable(found.display().to_string()),
        None => Located::Missing,
    }
}

/// Whether this process may create entries in the directory `path`, asked of
/// the operating system without creating one.
#[cfg(unix)]
fn directory_is_writable(path: &Path) -> bool {
    use rustix::fs::Access;
    effective_access(path, Access::WRITE_OK | Access::EXEC_OK)
}

#[cfg(not(unix))]
fn directory_is_writable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| !metadata.permissions().readonly())
}

/// Whether this process may open the existing `path` for writing.
#[cfg(unix)]
fn file_is_writable(path: &Path) -> bool {
    effective_access(path, rustix::fs::Access::WRITE_OK)
}

#[cfg(not(unix))]
fn file_is_writable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| !metadata.permissions().readonly())
}

/// Judge the destination the way the publication primitive
/// (`apply::file_target`) treats it. An existing destination that is not a
/// regular file, followed through symlinks (`destination_needs_direct_write`),
/// is written in place with no temp file: a directory there fails with "Is a
/// directory", and anything else (a device, a pipe) needs only its own write
/// permission. Otherwise the document goes to a temp file in the
/// destination's directory and is renamed over it, after `create_dir_all` on
/// that directory, so the question is whether the nearest existing ancestor
/// is a directory this process may write.
fn file_output(root: &Path, configured: &str) -> Check {
    const ID: &str = "file-output";
    const TITLE: &str = "File-mode output directory is writable";
    let output = root.join(configured);
    if let Ok(metadata) = std::fs::metadata(&output) {
        if metadata.is_dir() {
            return Check::new(
                ID,
                TITLE,
                Scope::Local,
                Status::Fail,
                format!(
                    "FERRUM_FILE_OUTPUT_PATH ({configured}) is a directory; publication \
                     writes the document to that path itself"
                ),
            )
            .remedy("Point FERRUM_FILE_OUTPUT_PATH at a file path, not a directory.");
        }
        if !metadata.is_file() {
            return if file_is_writable(&output) {
                Check::pass(
                    ID,
                    TITLE,
                    Scope::Local,
                    format!(
                        "assembled documents will be written directly to {configured}, \
                         which is not a regular file"
                    ),
                )
            } else {
                Check::new(
                    ID,
                    TITLE,
                    Scope::Local,
                    Status::Fail,
                    format!(
                        "FERRUM_FILE_OUTPUT_PATH ({configured}) is not a regular file and \
                         is not writable by this user"
                    ),
                )
                .remedy(
                    "Publication writes straight to an existing non-regular destination. \
                     Grant this user write access to it, or point FERRUM_FILE_OUTPUT_PATH \
                     at a regular file path.",
                )
            };
        }
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.to_path_buf());
    let mut ancestor = parent.as_path();
    while std::fs::symlink_metadata(ancestor).is_err() {
        match ancestor
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            Some(next) => ancestor = next,
            None => {
                ancestor = root;
                break;
            }
        }
    }
    let remedy = "Point FERRUM_FILE_OUTPUT_PATH at a location this user can write, or \
                  fix the directory's permissions. File-mode apply publishes with a temp \
                  file and a rename in that directory.";
    if !ancestor.is_dir() {
        return Check::new(
            ID,
            TITLE,
            Scope::Local,
            Status::Fail,
            format!(
                "FERRUM_FILE_OUTPUT_PATH ({configured}) cannot be created: {} is not a directory",
                ancestor.display()
            ),
        )
        .remedy(remedy);
    }
    if !directory_is_writable(ancestor) {
        return Check::new(
            ID,
            TITLE,
            Scope::Local,
            Status::Fail,
            format!(
                "FERRUM_FILE_OUTPUT_PATH ({configured}): {} is not writable by this user",
                ancestor.display()
            ),
        )
        .remedy(remedy);
    }
    let detail = if ancestor == parent.as_path() {
        format!("assembled documents will be written to {configured}")
    } else {
        format!(
            "assembled documents will be written to {configured}; its missing parent \
             directories will be created under {}",
            ancestor.display()
        )
    };
    Check::pass(ID, TITLE, Scope::Local, detail)
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
            checks.push(file_output(root, &env.file_output_path));
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
