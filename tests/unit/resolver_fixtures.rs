//! The credential resolver with its gateway mode and options stated.
//!
//! Production passes the run's mode to
//! `report_secrets_with_mode_and_options` / `resolve_secrets_with_mode_and_options`
//! or reads it from the process (`resolve_secrets_with_options`). Tests state
//! it here instead, so a test that sets `FERRUM_GATEWAY_MODE` in the shared
//! process environment cannot change another test's result.

use gitforgeops::config::{GatewayConfig, GatewayMode};
use gitforgeops::error::Result;
use gitforgeops::secrets::{
    report_secrets_with_mode_and_options, resolve_secrets_with_mode_and_options, CredentialBundle,
    ResolveOptions, ResolveReport,
};

/// The strict, non-mutating walk an API-mode run makes, with default options.
pub fn report_secrets(cfg: &GatewayConfig, bundle: &CredentialBundle) -> Result<ResolveReport> {
    report_secrets_with_options(cfg, bundle, ResolveOptions::default())
}

/// [`report_secrets`] with the slot-remap verdict supplied.
pub fn report_secrets_with_options(
    cfg: &GatewayConfig,
    bundle: &CredentialBundle,
    options: ResolveOptions,
) -> Result<ResolveReport> {
    report_secrets_with_mode_and_options(cfg, bundle, GatewayMode::Api, options)
}

/// Resolution in an API-mode run, with default options.
pub fn resolve_secrets(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
) -> Result<ResolveReport> {
    resolve_secrets_with_mode(cfg, bundle, GatewayMode::Api)
}

/// Resolution in the given mode, with default options.
pub fn resolve_secrets_with_mode(
    cfg: &mut GatewayConfig,
    bundle: &CredentialBundle,
    mode: GatewayMode,
) -> Result<ResolveReport> {
    resolve_secrets_with_mode_and_options(cfg, bundle, mode, ResolveOptions::default())
}
