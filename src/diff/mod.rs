pub mod best_practice;
pub mod breaking;
pub mod resource_diff;
pub mod security;

pub use best_practice::{check_best_practices, BestPractice};
pub use breaking::{detect_breaking_changes, BreakingChange};
pub use resource_diff::{
    compute_diff, compute_diff_with_ownership, compute_diff_with_scope, state_key,
    state_key_namespace, DiffAction, DiffResult, FieldChange, OwnershipScope, ResourceDiff,
    UnmanagedResource,
};
pub use security::{audit_security, SecurityFinding};
