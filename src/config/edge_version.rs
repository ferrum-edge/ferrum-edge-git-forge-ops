//! Paired Ferrum Edge release version and version-aware resource adaptation.
//!
//! [`DEFAULT_EDGE_VERSION`] is the Ferrum Edge release the repository pins
//! (`validator.version` in `release/baseline.json`, `v0.9.21`;
//! `check_release_baseline.py` keeps the two equal). An environment paired with
//! a different Ferrum Edge release can declare it (`edge_version` in
//! `.gitforgeops/config.yaml`, or `FERRUM_EDGE_VERSION`), which selects
//! version-aware handling for gateway schema changes without forcing a
//! destructive repository-wide migration:
//!
//! * **`Proxy.pool_max_requests_per_connection`** — Ferrum Edge v0.9.20 and
//!   earlier accept and persist this field (a no-op carrier whose omission on
//!   write clears the stored value). Ferrum Edge v0.9.21 removed it while
//!   keeping `Proxy` `deny_unknown_fields` (`ferrum-edge#7218`). When paired
//!   with `< v0.9.21`, GitForgeOps accepts, emits and diffs the field verbatim.
//!   When paired with `>= v0.9.21`, GitForgeOps still accepts proxy files
//!   carrying it and omits the removed field from assembled desired state
//!   (validation, export, diff, file apply and API apply) with an explicit
//!   notice, so shared repository trees work across both pairings.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::GatewayConfig;
use crate::diagnostics::safe;
use crate::error::{Error, Result};

/// A parsed Ferrum Edge release version (`MAJOR.MINOR.PATCH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

/// Default paired Ferrum Edge version when neither the environment config nor
/// `FERRUM_EDGE_VERSION` selects one. Matches the release baseline's pinned
/// validator (`release/baseline.json`), which `check_release_baseline.py`
/// enforces.
pub const DEFAULT_EDGE_VERSION: EdgeVersion = EdgeVersion::new(0, 9, 21);

/// First Ferrum Edge release that removed `Proxy.pool_max_requests_per_connection`
/// (`ferrum-edge#7218`).
pub const POOL_MAX_REQUESTS_REMOVED_IN: EdgeVersion = EdgeVersion::new(0, 9, 21);

/// Wire name of the removed no-op proxy field.
pub const POOL_MAX_REQUESTS_FIELD: &str = "pool_max_requests_per_connection";

impl EdgeVersion {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse `MAJOR.MINOR.PATCH` with an optional leading lowercase `v`
    /// (for example `v0.9.20`, `0.9.20`, `v0.9.21`, `0.9.21`).
    ///
    /// Rejects whitespace, uppercase `V`, missing or extra components, signs,
    /// and prerelease/build suffixes so a typo never silently selects the wrong
    /// pairing.
    pub fn parse(raw: &str) -> Result<Self> {
        let stripped = raw.strip_prefix('v').unwrap_or(raw);
        let mut parts = stripped.split('.');
        let major = parse_component(parts.next(), raw)?;
        let minor = parse_component(parts.next(), raw)?;
        let patch = parse_component(parts.next(), raw)?;
        if parts.next().is_some() {
            return Err(invalid_edge_version(raw));
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// Whether this paired Ferrum Edge release accepts and persists
    /// `Proxy.pool_max_requests_per_connection`.
    ///
    /// True for v0.9.20 and earlier; false for v0.9.21 and later, where the
    /// no-op field was removed from Edge's `deny_unknown_fields` `Proxy` model
    /// (`ferrum-edge#7218`).
    pub fn supports_pool_max_requests_per_connection(self) -> bool {
        self < POOL_MAX_REQUESTS_REMOVED_IN
    }
}

fn parse_component(part: Option<&str>, raw: &str) -> Result<u64> {
    let part = part.ok_or_else(|| invalid_edge_version(raw))?;
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_edge_version(raw));
    }
    part.parse::<u64>().map_err(|_| invalid_edge_version(raw))
}

fn invalid_edge_version(raw: &str) -> Error {
    Error::Config(format!(
        "invalid Edge version {raw:?}: expected MAJOR.MINOR.PATCH with an optional leading 'v' \
         (for example v0.9.20 or v0.9.21)"
    ))
}

impl fmt::Display for EdgeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for EdgeVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for EdgeVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EdgeVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        EdgeVersion::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// One proxy field omitted from desired state because the paired Ferrum Edge
/// version removed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmittedProxyField {
    pub namespace: String,
    pub id: String,
    pub field: &'static str,
}

/// Adapt an assembled desired [`GatewayConfig`] for `edge_version`.
///
/// * When `edge_version.supports_pool_max_requests_per_connection()` is `true`
///   (`<= v0.9.20`, selected explicitly), `config` is untouched
///   and an empty list is returned: `pool_max_requests_per_connection` is
///   emitted and diffed verbatim, preserving v0.9.20's omission-clears
///   semantics.
/// * When `false` (`>= v0.9.21`, including [`DEFAULT_EDGE_VERSION`]),
///   `pool_max_requests_per_connection` is cleared
///   from every desired proxy that declared it, and each affected proxy is
///   returned so callers can emit an explicit operator notice. Live snapshots
///   from the gateway are never stripped here: if a v0.9.20 gateway still holds
///   the field while an environment mistakenly targets v0.9.21, diff continues
///   to surface the real difference.
pub fn adapt_gateway_for_edge_version(
    config: &mut GatewayConfig,
    edge_version: EdgeVersion,
) -> Vec<OmittedProxyField> {
    if edge_version.supports_pool_max_requests_per_connection() {
        return Vec::new();
    }

    let mut omitted = Vec::new();
    for proxy in &mut config.proxies {
        if proxy.pool_max_requests_per_connection.take().is_some() {
            omitted.push(OmittedProxyField {
                namespace: proxy.namespace.clone(),
                id: proxy.id.clone(),
                field: POOL_MAX_REQUESTS_FIELD,
            });
        }
    }
    omitted
}

/// Format an operator-facing notice when [`adapt_gateway_for_edge_version`]
/// omitted removed proxy fields for a newer Edge pairing. Returns `None` when
/// nothing was omitted.
pub fn format_omitted_proxy_fields_notice(
    edge_version: EdgeVersion,
    omitted: &[OmittedProxyField],
) -> Option<String> {
    if omitted.is_empty() {
        return None;
    }
    let proxies = omitted
        .iter()
        .map(|entry| format!("{}/{}", safe(&entry.namespace), safe(&entry.id)))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "omitted removed no-op Proxy field `{POOL_MAX_REQUESTS_FIELD}` for paired Ferrum Edge \
         {edge_version} (removed in {POOL_MAX_REQUESTS_REMOVED_IN}, ferrum-edge#7218) on {} \
         proxy/proxies: {proxies}. Only an environment explicitly paired with v0.9.20 or \
         earlier emits and diffs this field verbatim.",
        omitted.len()
    ))
}
