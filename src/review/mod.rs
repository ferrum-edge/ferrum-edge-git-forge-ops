pub mod github;
pub mod pr_comment;

pub use github::{comment_status_is_retryable, enforce_required_comment_delivery, post_pr_comment};
pub use pr_comment::{
    build_review_comment, build_review_comment_v2, build_review_comment_v2_with_status,
    build_review_comment_with_status, environment_header, render_spec_owned,
    ReviewValidationStatus,
};

/// Prefix shared by every published "the live comparison did not happen" note.
const COMPARISON_SKIPPED: &str = "Live gateway comparison skipped";

/// Where the operator can read the part that is deliberately not published.
const SEE_JOB_LOG: &str = "The unredacted error is in the workflow job log; it is withheld here because the gateway URL is an environment secret and this comment is world-readable.";

/// Published wording for a `/backup` the gateway served from its in-memory
/// snapshot instead of the config database.
pub const STALE_LIVE_VIEW_REASON: &str = "Live gateway comparison skipped: the gateway answered `/backup` from its in-memory snapshot (`X-Data-Source: cached`) because its config database was unavailable, so the live view is stale. The comparison is withheld rather than published as authoritative.";

pub fn live_comparison_precondition_error(namespaces: &[String]) -> Option<String> {
    namespaces.is_empty().then(|| {
        "Live gateway comparison skipped: no trusted namespaces were resolved for this review"
            .to_string()
    })
}

/// A stale live view is not a live comparison.
///
/// `AdminClient::served_from_cache()` is set by any `/backup` that came back
/// with `X-Data-Source: cached`. A diff computed against that snapshot is worse
/// than no diff at all — rows the database already holds read as adds, and
/// removed rows read as live drift — so the caller drops the diff and reports
/// the degradation instead. `--require-live` then fails, which is the whole
/// point: a cached view cannot stand in for the live comparison the trusted
/// review promises.
pub fn stale_live_view_error(served_from_cache: bool) -> Option<String> {
    served_from_cache.then(|| STALE_LIVE_VIEW_REASON.to_string())
}

/// Render a live-comparison failure in a form that is safe to publish.
///
/// `cmd_review` posts its comment to a pull request and mirrors it into
/// `$GITHUB_STEP_SUMMARY`; on a public repository both are world-readable.
/// `FERRUM_GATEWAY_URL` is a GitHub Environment *secret*, and `reqwest`'s
/// `Display` appends `for url (<full url>)` to transport errors, so formatting
/// the raw error into the comment publishes the gateway's host and port.
/// Gateway response bodies reach the same place and are attacker-influencable
/// Markdown besides.
///
/// So nothing derived from the error text is published: the category and, for
/// an HTTP failure, the status code — which carry the diagnostic value a
/// reviewer needs — plus a pointer at the job log, where the caller still
/// writes the error in full.
pub fn redact_comparison_error(error: &crate::error::Error) -> String {
    use crate::error::Error;

    let cause = match error {
        Error::NoGatewayUrl => "this environment has no gateway URL configured",
        Error::NoJwtSecret => "this environment has no admin JWT secret configured",
        Error::JwtError(_) => "the admin token could not be minted",
        Error::HttpClient(_) => "the gateway could not be reached",
        Error::ApiError { status, .. } => {
            return format!(
                "{COMPARISON_SKIPPED}: the gateway answered HTTP {status}. {SEE_JOB_LOG}"
            );
        }
        Error::GatewayReadOnly(_) => "the gateway admin API is read-only",
        Error::StaleGatewayView(_) => "the gateway served a stale view of live state",
        Error::CommittedNotLive { .. } => "a gateway write is committed but not yet live",
        Error::Config(_) => "the gateway client configuration was rejected",
        _ => "the live comparison could not be completed",
    };
    format!("{COMPARISON_SKIPPED}: {cause}. {SEE_JOB_LOG}")
}

/// A privileged `--require-live` review must have actually compared against the
/// gateway. Any recorded `comparison_error` — unreachable gateway, no resolved
/// namespaces, or a stale cached view — means it did not.
pub fn enforce_live_comparison(
    require_live: bool,
    comparison_error: Option<&str>,
) -> crate::error::Result<()> {
    if let (true, Some(error)) = (require_live, comparison_error) {
        return Err(crate::error::Error::Config(format!(
            "trusted PR review requires a complete live gateway comparison: {error}"
        )));
    }
    Ok(())
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
