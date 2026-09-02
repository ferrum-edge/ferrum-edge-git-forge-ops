use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read file {path}: {source}")]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse YAML in {path}: {source}")]
    YamlParse {
        path: PathBuf,
        source: serde_yaml::Error,
    },

    #[error("unknown resource kind {kind:?} in {path}")]
    UnknownKind { kind: String, path: PathBuf },

    #[error("missing 'kind' field in {path}")]
    MissingKind { path: PathBuf },

    #[error("missing 'spec' field in {path}")]
    MissingSpec { path: PathBuf },

    #[error("no resources directory found at {0}")]
    NoResourcesDir(PathBuf),

    #[error("overlay resource {id:?} in {path} has no matching base resource")]
    OrphanOverlay { id: String, path: PathBuf },

    #[error("failed to parse state file {path}: {source}")]
    StateParse {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("ferrum-edge binary not found: {0}")]
    BinaryNotFound(String),

    #[error("validation failed with {error_count} error(s)")]
    ValidationFailed { error_count: usize },

    #[error("ferrum-edge validate exited with code {code}: {stderr}")]
    ValidateProcess { code: i32, stderr: String },

    #[error("{0}")]
    Config(String),

    #[error("API request failed ({status}): {message}")]
    ApiError { status: u16, message: String },

    /// The admin plane refuses config mutations: either `FERRUM_ADMIN_READ_ONLY`
    /// is set, the config database is unavailable, or the gateway runs in a mode
    /// (`file`, `dp`, `mesh`, `node_agent`) where writes are unconditionally off.
    /// Raised as a single whole-run error rather than once per resource.
    #[error("gateway admin API is read-only, refusing to apply: {0}")]
    GatewayReadOnly(String),

    /// `POST /restore` refused because the namespace holds API specs the
    /// payload would delete. Carries the actionable remediation.
    #[error("{0}")]
    ApiSpecsAtRisk(String),

    /// A `/restore` failed with an incomplete or unknown-outcome rollback. The
    /// namespace may be in a partially-restored state; retrying would re-run a
    /// destructive replace against unknown content.
    #[error(
        "restore failed and rollback did not complete cleanly — manual recovery required: {0}"
    )]
    RestoreNeedsManualRecovery(String),

    /// A newer gateway returned a top-level backup section this client cannot
    /// safely carry through `/restore`. Omitting it could destroy data owned by
    /// that newer capability, so full-replace must stop before mutation.
    #[error("full-replace source is incomplete for this client: {0}")]
    UnsupportedBackupSections(String),

    /// A write was durably committed but is not live yet (`applied: false`).
    /// Retrying would re-apply it; the caller must reconcile instead.
    #[error("write committed, awaiting reload ({reason}): {message}")]
    CommittedNotLive { reason: String, message: String },

    /// A non-idempotent POST may have committed even though the client did
    /// not receive a success response, and an authoritative follow-up read
    /// could not prove the exact desired resource set is live. Blind replay
    /// could duplicate the operation, so the run stops for reconciliation.
    #[error("ambiguous mutation outcome — no automatic replay was attempted: {0}")]
    AmbiguousMutation(String),

    /// `GET /backup` served the in-memory snapshot instead of the database, so
    /// the live view may be stale and ownership metadata is incomplete.
    #[error("{0}")]
    StaleGatewayView(String),

    #[error("JWT error: {0}")]
    JwtError(String),

    #[error("gateway URL not configured: set FERRUM_GATEWAY_URL (in CI, add it to the GitHub Environment's secrets for this environment)")]
    NoGatewayUrl,

    #[error("JWT secret not configured: set FERRUM_ADMIN_JWT_SECRET (in CI, add it to the GitHub Environment's secrets for this environment)")]
    NoJwtSecret,

    #[error("HTTP client error: {0}")]
    HttpClient(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
