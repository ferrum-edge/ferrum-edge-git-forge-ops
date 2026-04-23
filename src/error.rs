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

    #[error("JWT error: {0}")]
    JwtError(String),

    #[error("gateway URL not configured (set FERRUM_GATEWAY_URL)")]
    NoGatewayUrl,

    #[error("JWT secret not configured (set FERRUM_ADMIN_JWT_SECRET)")]
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
