//! HS256 bearer tokens for the Ferrum Edge admin API.
//!
//! The gateway (`src/admin/jwt_auth.rs`) validates:
//!
//! | Claim  | Requirement                                                        |
//! |--------|--------------------------------------------------------------------|
//! | `iss`  | must equal the gateway's `FERRUM_ADMIN_JWT_ISSUER` (def `ferrum-edge`) |
//! | `role` | **required** string, one of `viewer` \| `operator` \| `admin`       |
//! | `sub`, `exp`, `iat`, `nbf`, `jti` | required                              |
//! | `aud`  | **forbidden** unless the gateway sets `FERRUM_ADMIN_JWT_AUDIENCE`   |
//! | `ns`   | required only under `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`     |
//! | TTL    | `exp - iat` ∈ (0, `FERRUM_ADMIN_JWT_MAX_TTL`]; `exp - now ≤ max+60` |
//!
//! Every claim is a direct field on [`Claims`] so it lands at the top level of
//! the payload. An earlier version stashed the extras in a non-flattened
//! `additional` field, which serialized as a literal `"additional": {}` member
//! and shipped no `role` — every request came back 401.

use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

use crate::config::env::{EnvConfig, DEFAULT_JWT_ISSUER, DEFAULT_JWT_ROLE, DEFAULT_JWT_TTL_SECS};

/// Value used for both `sub` and, historically, `iss`. `iss` is now taken from
/// configuration because the gateway matches it against its own setting; `sub`
/// stays free-form and identifies the client in the gateway's audit log.
pub const SUBJECT: &str = "gitforgeops";

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
    /// Required by the gateway on every admin route.
    role: String,
    /// Emitted only when an audience is configured — a stray `aud` is a hard
    /// rejection on a gateway that has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    /// Namespace scope, for gateways running with
    /// `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`. Omitted when the scope is
    /// unknown (all namespaces), which is what a non-tenancy gateway expects.
    #[serde(skip_serializing_if = "Option::is_none")]
    ns: Option<Vec<String>>,
}

/// Claim material for a minted admin token.
#[derive(Debug, Clone)]
pub struct JwtOptions {
    pub issuer: String,
    pub subject: String,
    pub role: String,
    pub audience: Option<String>,
    /// Namespaces this token is scoped to. Empty ⇒ no `ns` claim.
    pub namespaces: Vec<String>,
    pub ttl_secs: i64,
}

impl Default for JwtOptions {
    fn default() -> Self {
        Self {
            issuer: DEFAULT_JWT_ISSUER.to_string(),
            subject: SUBJECT.to_string(),
            role: DEFAULT_JWT_ROLE.to_string(),
            audience: None,
            namespaces: Vec::new(),
            ttl_secs: DEFAULT_JWT_TTL_SECS,
        }
    }
}

impl JwtOptions {
    /// Build options from resolved process configuration. The namespace scope
    /// starts at `FERRUM_NAMESPACE` when set; callers that know a wider scope
    /// (an exclusive environment's namespace list) refine it with
    /// [`JwtOptions::with_namespaces`].
    pub fn from_env(env: &EnvConfig) -> Self {
        Self {
            issuer: env.admin_jwt_issuer.clone(),
            subject: SUBJECT.to_string(),
            role: env.admin_jwt_role.clone(),
            audience: env.admin_jwt_audience.clone(),
            namespaces: env.namespace_filter.iter().cloned().collect(),
            ttl_secs: env.admin_jwt_ttl_secs,
        }
    }

    /// Replace the `ns` scope. Duplicates and empty entries are dropped; an
    /// empty result leaves the claim off entirely.
    pub fn with_namespaces<I, S>(mut self, namespaces: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = std::collections::BTreeSet::new();
        self.namespaces = namespaces
            .into_iter()
            .map(|n| n.as_ref().to_string())
            .filter(|n| !n.is_empty())
            .filter(|n| seen.insert(n.clone()))
            .collect();
        self
    }
}

/// Mint an HS256 token for the admin API.
pub fn mint_jwt(secret: &str, options: &JwtOptions) -> crate::error::Result<String> {
    let now = Utc::now().timestamp();
    // Guard against a nonsensical TTL reaching the wire as `exp <= iat`, which
    // the gateway rejects outright.
    let ttl = if options.ttl_secs > 0 {
        options.ttl_secs
    } else {
        DEFAULT_JWT_TTL_SECS
    };

    let claims = Claims {
        iss: options.issuer.clone(),
        sub: options.subject.clone(),
        exp: now + ttl,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        role: options.role.clone(),
        aud: options.audience.clone(),
        ns: if options.namespaces.is_empty() {
            None
        } else {
            Some(options.namespaces.clone())
        },
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| crate::error::Error::JwtError(e.to_string()))
}
