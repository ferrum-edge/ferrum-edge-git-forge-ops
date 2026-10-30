use crate::diagnostics::{safe, safe_line};
use crate::policy::{github_override, PolicyFinding};
use crate::secrets::SecretScrubber;
use crate::verdict;

/// Format a blocking policy refusal, scrubbing resolved secrets when available.
pub fn refuse_policy_violations(
    findings: &[PolicyFinding],
    phase: &str,
    override_decision: Option<&github_override::OverrideDecision>,
    scrubber: Option<&SecretScrubber>,
) -> Option<String> {
    let gate = verdict::policy_blocker(findings)?;

    let mut output = format!(
        "Refusing to apply: {} policy violation(s) not covered by an override{}:\n",
        gate.count, phase
    );

    let blocking_findings = findings
        .iter()
        .filter(|finding| finding.is_blocking())
        .collect::<Vec<_>>();
    let mut details = String::new();
    for finding in &blocking_findings {
        details.push_str(&format!(
            "  [{}] {}: {}\n",
            finding.severity.as_str(),
            safe(&finding.rule_id),
            safe_line(&finding.message)
        ));
    }

    if let Some(scrubber) = scrubber {
        let scrubbed = scrubber.scrub_streams("", &details);
        if scrubbed.suppressed.is_some() {
            output.push_str(
                "Policy finding details were withheld because they may contain resolved secrets:\n",
            );
            for finding in &blocking_findings {
                output.push_str(&format!(
                    "  [{}] {}/{} {}\n",
                    safe(&finding.rule_id),
                    safe(&finding.kind),
                    safe(&finding.namespace),
                    safe(&finding.id)
                ));
            }
        } else {
            output.push_str(&scrubbed.stderr);
        }
    } else {
        output.push_str(&details);
    }
    if let Some(decision) = override_decision {
        if !decision.active {
            output.push_str(&format!(
                "(override inactive: {})\n",
                crate::diagnostics::safe_block(&decision.reason)
            ));
        }
    } else {
        output.push_str(&format!("({})\n", github_override::NO_PR_OVERRIDE_NOTE));
    }
    Some(output)
}

/// The api-mode policy re-check after credential resolution.
///
/// The override decision covers only blocking findings that also appear in
/// `reviewed`, the pre-resolution evaluation `plan` and `review` show. A
/// blocking finding that exists only in the resolved document refuses apply
/// even with an active override, and the refusal says why. `findings` is left
/// post-override for the audit trail. Values never appear in the note; finding
/// details go through `scrubber` like every other post-resolution refusal.
pub fn refuse_post_resolution_policy_violations(
    findings: &mut [PolicyFinding],
    reviewed: &[PolicyFinding],
    override_decision: Option<&github_override::OverrideDecision>,
    scrubber: Option<&SecretScrubber>,
) -> Option<String> {
    let uncovered = override_decision
        .map(|decision| github_override::apply_override_to_reviewed(findings, decision, reviewed))
        .unwrap_or(0);
    let mut output = refuse_policy_violations(
        findings,
        " (after credential resolution)",
        override_decision,
        scrubber,
    )?;
    if uncovered > 0 {
        output.push_str(&format!(
            "({uncovered} blocking finding(s) appeared only after credential resolution. The override covers only findings its review could see before resolution, so it does not cover them; plan and review never showed them.)\n"
        ));
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::policy::Severity;
    use crate::secrets::{
        PlaceholderAlloc, ResolveReport, ResolveResult, SecretPlaceholder, SecretScrubber,
        SlotStatus,
    };

    #[test]
    fn refusal_redacts_a_synthetic_resolved_value() {
        let secret = "Q7m2Vx9c2L";
        let config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "consumers": [{
                "id": "app",
                "username": "app",
                "namespace": "ferrum",
                "credentials": {"keyauth": [{"key": secret}]}
            }]
        }))
        .unwrap();
        let report = ResolveReport {
            results: vec![ResolveResult {
                consumer_id: "app".to_string(),
                namespace: "ferrum".to_string(),
                cred_key: "keyauth/key".to_string(),
                slot: crate::secrets::slot_path("ferrum", "app", "keyauth/key"),
                placeholder: SecretPlaceholder {
                    alloc: PlaceholderAlloc::Require,
                    length_bytes: 32,
                },
                status: SlotStatus::Resolved,
            }],
            ..ResolveReport::default()
        };
        let scrubber = SecretScrubber::from_gateway_config_with_report(&config, &report);
        let finding = PolicyFinding {
            rule_id: "synthetic_rule".to_string(),
            severity: Severity::Error,
            kind: "Consumer".to_string(),
            id: "app".to_string(),
            namespace: "ferrum".to_string(),
            message: format!("resolved value: {secret}"),
            remediation: None,
            overridden_by: None,
        };

        let output = refuse_policy_violations(&[finding], "", None, Some(&scrubber));
        let output = output.expect("blocking finding refuses apply");

        assert!(output.contains("[REDACTED]"), "{output}");
        assert!(!output.contains(secret), "{output}");
        assert!(!output.contains("details were withheld"), "{output}");
        assert!(output.contains("synthetic_rule"), "{output}");
        assert!(output.contains(github_override::NO_PR_OVERRIDE_NOTE));
    }
}
