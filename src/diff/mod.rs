pub mod best_practice;
pub mod breaking;
pub mod resource_diff;
pub mod security;

pub use best_practice::{check_best_practices, BestPractice};
pub use breaking::{detect_breaking_changes, detect_breaking_changes_with_policy, BreakingChange};
pub use resource_diff::{
    align_verified_basicauth_bindings, basicauth_password_binding,
    compute_consumer_basicauth_bindings, compute_diff, compute_diff_with_options,
    compute_diff_with_ownership, compute_diff_with_scope, consumer_has_plaintext_basicauth,
    consumer_matches_desired_except_basicauth, extract_basicauth_password_hash_at,
    is_sensitive_diff_field, is_valid_basicauth_binding_tag, mask_indeterminate_secret_values,
    state_key, state_key_kind, state_key_namespace, DiffAction, DiffOptions, DiffResult,
    FieldChange, OwnershipScope, ResourceDiff, SpecOwnedResource, UnmanagedResource,
};
pub use security::{
    audit_security, audit_security_with_policy, audit_security_with_scope,
    consumer_security_blockers, security_blockers, SecurityFinding, BLOCKING_SEVERITY,
};
