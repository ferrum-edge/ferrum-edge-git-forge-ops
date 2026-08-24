pub mod api_target;
pub mod file_target;

pub use api_target::{
    apply_api, operation_rank, order_diffs, stale_view_block, AppliedOp, ApplyOptions, ApplyResult,
};
pub use file_target::{apply_file, render_file_yaml};
