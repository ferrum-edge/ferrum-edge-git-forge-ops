use std::path::PathBuf;

use crate::diagnostics::{safe, safe_block, safe_line, safe_path};

/// Every variant that carries repository- or gateway-sourced text renders it
/// through [`crate::diagnostics`]. An `Error` is printed to stderr — and, in
/// CI, into an Actions job log where a bare `\n` would let a resource id or a
/// YAML mapping key start a line that the runner parses as a workflow command.
/// Sanitizing in the format string keeps that guarantee independent of which
/// of the many `Display` call sites prints the error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", safe_block(.0))]
    BackupNamespace(String),

    #[error("failed to read file {}: {}", safe_path(path), safe(source))]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse YAML in {}: {}", safe_path(path), safe_block(source))]
    YamlParse {
        path: PathBuf,
        source: serde_yaml::Error,
    },

    #[error("unknown configuration field(s) in {}: {}", safe_path(path), safe_line(fields))]
    UnknownFields { path: PathBuf, fields: String },

    #[error("failed to traverse configuration tree at {}: {}", safe_path(path), safe(source))]
    WalkDir {
        path: PathBuf,
        source: walkdir::Error,
    },

    #[error("symbolic links are not allowed in configuration trees: {}", safe_path(.0))]
    ConfigSymlink(PathBuf),

    #[error("configuration path exists but is not a directory: {}", safe_path(.0))]
    ConfigNotDirectory(PathBuf),

    #[error("unknown resource kind {} in {}", safe(format!("{kind:?}")), safe_path(path))]
    UnknownKind { kind: String, path: PathBuf },

    #[error("missing 'kind' field in {}", safe_path(path))]
    MissingKind { path: PathBuf },

    #[error("missing 'spec' field in {}", safe_path(path))]
    MissingSpec { path: PathBuf },

    #[error("no resources directory found at {}", safe_path(.0))]
    NoResourcesDir(PathBuf),

    #[error(
        "overlay resource {} in {} has no matching base resource",
        safe(format!("{id:?}")),
        safe_path(path)
    )]
    OrphanOverlay { id: String, path: PathBuf },

    #[error("failed to parse state file {}: {}", safe_path(path), safe_block(source))]
    StateParse {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("ferrum-edge binary not found: {}", safe(.0))]
    BinaryNotFound(String),

    #[error("validation failed with {error_count} error(s)")]
    ValidationFailed { error_count: usize },

    #[error("ferrum-edge validate exited with code {code}: {}", safe_block(stderr))]
    ValidateProcess { code: i32, stderr: String },

    #[error("{}", safe_block(.0))]
    Config(String),

    #[error("API request failed ({status}): {}", safe_block(message))]
    ApiError { status: u16, message: String },

    /// The admin plane refuses config mutations: either `FERRUM_ADMIN_READ_ONLY`
    /// is set, the config database is unavailable, or the gateway runs in a mode
    /// (`file`, `dp`, `mesh`, `node_agent`) where writes are unconditionally off.
    /// Raised as a single whole-run error rather than once per resource.
    #[error("gateway admin API is read-only, refusing to apply: {}", safe_block(.0))]
    GatewayReadOnly(String),

    /// `POST /restore` refused because the namespace holds API specs the
    /// payload would delete. Carries the actionable remediation.
    #[error("{}", safe_block(.0))]
    ApiSpecsAtRisk(String),

    /// A `/restore` failed with an incomplete or unknown-outcome rollback. The
    /// namespace may be in a partially-restored state; retrying would re-run a
    /// destructive replace against unknown content.
    #[error(
        "restore failed and rollback did not complete cleanly — manual recovery required: {}",
        safe_block(.0)
    )]
    RestoreNeedsManualRecovery(String),

    /// A newer gateway returned a top-level backup section this client cannot
    /// safely carry through `/restore`. Omitting it could destroy data owned by
    /// that newer capability, so full-replace must stop before mutation.
    #[error("full-replace source is incomplete for this client: {}", safe_block(.0))]
    UnsupportedBackupSections(String),

    /// A write was durably committed but is not live yet (`applied: false`).
    /// Retrying would re-apply it; the caller must reconcile instead.
    #[error("write committed, awaiting reload ({}): {}", safe(reason), safe_block(message))]
    CommittedNotLive { reason: String, message: String },

    /// A non-idempotent POST may have committed even though the client did
    /// not receive a success response, and an authoritative follow-up read
    /// could not prove the exact desired resource set is live. Blind replay
    /// could duplicate the operation, so the run stops for reconciliation.
    #[error("ambiguous mutation outcome — no automatic replay was attempted: {}", safe_block(.0))]
    AmbiguousMutation(String),

    /// `GET /backup` served the in-memory snapshot instead of the database, so
    /// the live view may be stale and ownership metadata is incomplete.
    #[error("{}", safe_block(.0))]
    StaleGatewayView(String),

    /// A brokered credential array shrank while the bundle still stores a
    /// value for an index the array no longer owns. Slot identity is
    /// positional, so the stored value has either been handed to whichever
    /// entry shifted into its index or is waiting to be resurrected by the
    /// next entry added there. Carries the remediation; never a value.
    #[error("{}", safe_block(.0))]
    CredentialSlotRemap(String),

    #[error("JWT error: {}", safe_block(.0))]
    JwtError(String),

    #[error("gateway URL not configured: set FERRUM_GATEWAY_URL (in CI, add it to the GitHub Environment's secrets for this environment)")]
    NoGatewayUrl,

    #[error("JWT secret not configured: set FERRUM_ADMIN_JWT_SECRET (in CI, add it to the GitHub Environment's secrets for this environment)")]
    NoJwtSecret,

    #[error("HTTP client error: {}", safe_block(.0))]
    HttpClient(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
