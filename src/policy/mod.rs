pub mod config;
pub mod github_override;
pub mod registry;
pub mod rules;

use serde::{Deserialize, Serialize};

pub use config::{load_policies, OverrideConfig, PolicyConfig};
pub use github_override::{check_override, OverrideDecision};
pub use registry::{build_registry, evaluate_policies};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    #[default]
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }

    pub fn blocks_apply(&self) -> bool {
        matches!(self, Severity::Error)
    }
}

#[derive(Debug, Clone)]
pub struct PolicyFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub kind: String,
    pub id: String,
    pub namespace: String,
    pub message: String,
    pub remediation: Option<String>,
    pub overridden_by: Option<String>,
}

impl PolicyFinding {
    pub fn is_blocking(&self) -> bool {
        self.severity.blocks_apply() && self.overridden_by.is_none()
    }
}

pub trait PolicyCheck: Send + Sync {
    fn rule_id(&self) -> &str;
    fn evaluate(&self, cfg: &crate::config::GatewayConfig) -> Vec<PolicyFinding>;
}
