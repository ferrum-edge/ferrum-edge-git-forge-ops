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

/// A privileged `--require-live` review is not complete unless its result is
/// durably posted to the pull request. Static/fork reviews may still fall back
/// to the step summary and stdout because their tokens are intentionally
/// read-only.
pub fn enforce_comment_delivery(
    require_live: bool,
    delivery_error: Option<&str>,
) -> crate::error::Result<()> {
    if let (true, Some(error)) = (require_live, delivery_error) {
        return Err(crate::error::Error::Config(format!(
            "trusted PR review could not post its result: {error}"
        )));
    }
    Ok(())
}
