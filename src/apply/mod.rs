pub mod api_target;
pub mod file_target;

pub use api_target::{
    adoption_candidates, adoption_summary_line, all_deletes_missing_warning, apply_api,
    exclusive_prune_denominator, format_prune_percentage, incremental_prune_notice,
    large_prune_exceeds_threshold, operation_rank, order_diffs, pending_create_assertion_diffs,
    preflight_api_apply, preserve_spec_owned_graph, spec_owned_skip_messages, stale_view_block,
    validate_no_desired_spec_tags, AdoptionCandidate, AppliedOp, ApplyOptions, ApplyResult,
};
pub use file_target::{
    apply_file, apply_mesh_file, plan_mesh_publication, publish_export, publish_private_export,
    reconcile_mesh_file, render_file_yaml, render_mesh_yaml, MeshPublication, MeshRetractionScope,
    MESH_DOCUMENT_VERSION,
};

/// Ownership changes must be explicit in every apply preview.
pub const ADOPTION_PREVIEW_NOTICE: &str = "Adoption adds matching rows to the ownership ledger. \
    Shared mode issues an idempotent PUT after a fresh equality check and widens the delete fence: \
    removing a declaration later permits deletion. Exclusive mode records ownership without a PUT. \
    Changed or cached confirmation snapshots skip adoption.";
