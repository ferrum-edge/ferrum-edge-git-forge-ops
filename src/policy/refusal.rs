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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::policy::Severity;
    use crate::secrets::SecretScrubber;

    #[test]
    fn refusal_redacts_a_synthetic_resolved_value() {
        let secret = "synthetic-secret-value";
        let config: GatewayConfig = serde_json::from_value(serde_json::json!({
            "consumers": [{
                "id": "app",
                "username": "app",
                "namespace": "ferrum",
                "credentials": {"keyauth": [{"key": secret}]}
            }]
        }))
        .unwrap();
        let scrubber = SecretScrubber::from_gateway_config(&config);
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
        assert!(output.contains(github_override::NO_PR_OVERRIDE_NOTE));
    }
}
