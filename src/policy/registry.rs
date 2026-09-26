use crate::config::GatewayConfig;
use crate::diagnostics::{sanitize, sanitize_line};

use super::config::PolicyConfig;
use super::rules::{
    AllowedBackendDomainsRule, AllowedProxyPluginsRule, BackendSchemeRule,
    ForbidTlsVerifyDisabledRule, PluginNameIsKnownRule, PriorityOverrideRangeRule,
    RateLimitCompletenessRule, RequireAiGuardrailsRule, RequireAuthPluginRule, TimeoutBandsRule,
    WafEnforcementRule,
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
    if policy_cfg.policies.allowed_proxy_plugins.enabled {
        rules.push(Box::new(AllowedProxyPluginsRule::new(
            policy_cfg.policies.allowed_proxy_plugins.clone(),
        )));
    }
    if policy_cfg.policies.allowed_backend_domains.enabled {
        rules.push(Box::new(AllowedBackendDomainsRule::new(
            policy_cfg.policies.allowed_backend_domains.clone(),
        )));
    }
    if policy_cfg.policies.waf_enforcement.enabled {
        rules.push(Box::new(WafEnforcementRule::new(
            policy_cfg.policies.waf_enforcement.clone(),
        )));
    }
    if policy_cfg.policies.require_ai_guardrails.enabled {
        rules.push(Box::new(RequireAiGuardrailsRule::new(
            policy_cfg.policies.require_ai_guardrails.clone(),
        )));
    }
    if policy_cfg.policies.rate_limit_completeness.enabled {
        rules.push(Box::new(RateLimitCompletenessRule::new(
            policy_cfg.policies.rate_limit_completeness.clone(),
        )));
    }
    if policy_cfg.policies.plugin_name_is_known.enabled {
        rules.push(Box::new(PluginNameIsKnownRule::new(
            policy_cfg.policies.plugin_name_is_known.clone(),
        )));
    }
    if policy_cfg.policies.priority_override_range.enabled {
        rules.push(Box::new(PriorityOverrideRangeRule::new(
            policy_cfg.policies.priority_override_range.clone(),
        )));
    }

    rules
}

pub fn evaluate_policies(cfg: &GatewayConfig, policy_cfg: &PolicyConfig) -> Vec<PolicyFinding> {
    let registry = build_registry(policy_cfg);
    let mut all = Vec::new();
    for rule in registry {
        all.extend(rule.evaluate(cfg).into_iter().map(sanitize_finding));
    }
    all
}

/// Sanitize a finding's text once, where it leaves the rules.
///
/// Rule messages interpolate repository-authored ids, namespaces and plugin
/// names, and the CLI and PR comment print them. Sanitizing here rather than
/// in each rule gives every finding the guarantee `SecurityFinding` has: no
/// line break into an Actions log and no line beginning with `::`. See
/// [`crate::diagnostics`].
fn sanitize_finding(finding: PolicyFinding) -> PolicyFinding {
    PolicyFinding {
        kind: sanitize(&finding.kind),
        id: sanitize(&finding.id),
        namespace: sanitize(&finding.namespace),
        message: sanitize_line(&finding.message),
        remediation: finding.remediation.as_deref().map(sanitize_line),
        ..finding
    }
}
