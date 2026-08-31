pub mod github;
pub mod pr_comment;

pub use github::post_pr_comment;
pub use pr_comment::{build_review_comment, build_review_comment_v2, render_spec_owned};

pub fn live_comparison_precondition_error(namespaces: &[String]) -> Option<String> {
    namespaces.is_empty().then(|| {
        "Live gateway comparison skipped: no trusted namespaces were resolved for this review"
            .to_string()
    })
}
