use crate::config::GatewayConfig;

use super::config::PolicyConfig;
use super::rules::{
    BackendSchemeRule, ForbidTlsVerifyDisabledRule, RequireAuthPluginRule, TimeoutBandsRule,
};
use super::{PolicyCheck, PolicyFinding};

pub fn build_registry(policy_cfg: &PolicyConfig) -> Vec<Box<dyn PolicyCheck>> {
    let mut rules: Vec<Box<dyn PolicyCheck>> = Vec::new();

    if policy_cfg.policies.proxy_timeout_bands.enabled {
        rules.push(Box::new(TimeoutBandsRule::new(
            policy_cfg.policies.proxy_timeout_bands.clone(),
        )));
    }
    if policy_cfg.policies.backend_scheme.enabled {
        rules.push(Box::new(BackendSchemeRule::new(
            policy_cfg.policies.backend_scheme.clone(),
        )));
    }
    if policy_cfg.policies.require_auth_plugin.enabled {
        rules.push(Box::new(RequireAuthPluginRule::new(
            policy_cfg.policies.require_auth_plugin.clone(),
        )));
    }
    if policy_cfg.policies.forbid_tls_verify_disabled.enabled {
        rules.push(Box::new(ForbidTlsVerifyDisabledRule::new(
            policy_cfg.policies.forbid_tls_verify_disabled.clone(),
        )));
    }

    rules
}

pub fn evaluate_policies(cfg: &GatewayConfig, policy_cfg: &PolicyConfig) -> Vec<PolicyFinding> {
    let registry = build_registry(policy_cfg);
    let mut all = Vec::new();
    for rule in registry {
        all.extend(rule.evaluate(cfg));
    }
    all
}
