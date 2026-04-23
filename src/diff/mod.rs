pub mod best_practice;
pub mod breaking;
pub mod resource_diff;
pub mod security;

pub use best_practice::{check_best_practices, BestPractice};
pub use breaking::{detect_breaking_changes, BreakingChange};
pub use resource_diff::{compute_diff, DiffAction, FieldChange, ResourceDiff};
pub use security::{audit_security, SecurityFinding};
