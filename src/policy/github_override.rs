use reqwest::Client;
use serde::Deserialize;

use crate::config::EnvConfig;

use super::config::OverrideConfig;

/// Printed by `plan` and `apply` when blocking findings exist but no GitHub
/// pull request is associated with the commit. Overrides stay CI/PR-only;
/// there is no local or environment-variable escape hatch. See
/// `README.md#overrides-are-evaluated-only-on-a-github-pull-request`.
pub const NO_PR_OVERRIDE_NOTE: &str =
    "No PR is associated with this commit; overrides were not evaluated. Policy overrides are evaluated only on a GitHub pull request; see README.md#overrides-are-evaluated-only-on-a-github-pull-request.";

#[derive(Debug, Clone)]
pub struct OverrideDecision {
    pub active: bool,
    pub approver: Option<String>,
    pub permission: Option<String>,
    pub reason: String,
    pub pr_number: Option<u64>,
    pub authorized_head: Option<String>,
    pub review_id: Option<u64>,
    pub applied_revision: Option<String>,
}

impl OverrideDecision {
    pub fn inactive(reason: &str) -> Self {
        Self {
            active: false,
            approver: None,
            permission: None,
            reason: reason.to_string(),
            pr_number: None,
            authorized_head: None,
            review_id: None,
            applied_revision: None,
        }
    }
}

/// The `=== Override ===` line `plan` prints for a decision. The approver is
/// GitHub's text, so only a [`crate::display::peer_text`] copy is quoted.
pub fn plan_override_note(decision: &OverrideDecision) -> String {
    match (decision.active, &decision.approver) {
        (true, Some(approver)) => format!(
            "Blocking findings overridden by @{}.",
            crate::display::peer_text(approver)
        ),
        (true, None) => "Blocking findings overridden.".to_string(),
        (false, _) => format!("Override inactive: {}.", decision.reason),
    }
}

/// The variable a workflow sets to name the PR an override is evaluated on.
pub const PR_NUMBER_ENV: &str = "GITFORGEOPS_PR_NUMBER";

/// Parse a [`PR_NUMBER_ENV`] value. Unset or blank is `None` (the caller may
/// fall back to the commit's associated PR); anything else must be a positive
/// decimal integer. A malformed value is an error rather than a silent
/// fallback, which could evaluate the override on a different PR.
pub fn parse_pr_number(value: Option<&str>) -> crate::error::Result<Option<u64>> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    match value.parse::<u64>() {
        Ok(number) if number > 0 && value.bytes().all(|b| b.is_ascii_digit()) => Ok(Some(number)),
        _ => Err(crate::error::Error::Config(format!(
            "{PR_NUMBER_ENV} is set but is not a positive integer; refusing to guess the pull request"
        ))),
    }
}

/// [`parse_pr_number`] over the process environment. A non-UTF-8 value is
/// malformed, not unset.
pub fn pr_number_from_env() -> crate::error::Result<Option<u64>> {
    match std::env::var(PR_NUMBER_ENV) {
        Ok(value) => parse_pr_number(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(crate::error::Error::Config(format!(
            "{PR_NUMBER_ENV} is set but is not a positive integer; refusing to guess the pull request"
        ))),
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Label {
    name: String,
}

#[derive(Debug, Deserialize)]
struct IssueEvent {
    event: String,
    #[serde(default)]
    label: Option<Label>,
    #[serde(default)]
    actor: Option<Actor>,
}

#[derive(Debug, Deserialize)]
struct Actor {
    login: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PullRequest {
    #[serde(default)]
    labels: Vec<Label>,
    head: Revision,
    merged: bool,
    merge_commit_sha: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Revision {
    sha: String,
}

/// Reviews carry a documented commit_id. Issue labeling events do not carry
/// the labeled-at head: their commit_id refers to an issue-referencing commit.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct OverrideReview {
    pub id: u64,
    pub commit_id: Option<String>,
    pub state: String,
    pub body: Option<String>,
    pub user: Option<ReviewAuthor>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ReviewAuthor {
    pub login: String,
}

/// The latest submitted review by the labeler must explicitly authorize this
/// label and this exact head. A later rejection, dismissal, or ordinary review
/// revokes the authorization; pending drafts cannot grant it.
pub fn authorized_review<'a>(
    reviews: &'a [OverrideReview],
    labeler: &str,
    label: &str,
    head: &str,
) -> Option<&'a OverrideReview> {
    if !super::override_input::is_revision(head) {
        return None;
    }
    let review = reviews.iter().rev().find(|review| {
        review.state != "PENDING"
            && review
                .user
                .as_ref()
                .is_some_and(|user| user.login == labeler)
    })?;
    let marker = format!("gitforgeops-override {label}");
    (matches!(review.state.as_str(), "APPROVED" | "COMMENTED")
        && review.commit_id.as_deref() == Some(head)
        && review
            .body
            .as_deref()
            .is_some_and(|body| body.trim() == marker))
    .then_some(review)
}

/// `GET /repos/{repo}/collaborators/{login}/permission`.
///
/// `permission` is GitHub's legacy field and only ever reports
/// `admin|write|read|none`: Maintain collapses to `write` and Triage to
/// `read`. The full role lives in `role_name`, which for a custom role is the
/// role's own name rather than one of the built-in ranks.
#[derive(Debug, Deserialize)]
pub struct PermissionResponse {
    pub permission: String,
    #[serde(default)]
    pub role_name: Option<String>,
}

impl PermissionResponse {
    /// The permission to rank against `overrides.required_permission`.
    ///
    /// Prefers `role_name` when it is one of the built-in ranks so a Maintain
    /// labeler satisfies `required_permission: maintain`. A custom role (or an
    /// absent `role_name`) falls back to the legacy base permission, which is
    /// the strongest rank GitHub vouches for.
    pub fn effective_permission(&self) -> &str {
        match self.role_name.as_deref() {
            Some(role) if OverrideConfig::permission_rank(role).is_some() => role,
            _ => &self.permission,
        }
    }
}

/// Consult the GitHub API to decide whether a policy override is active on the
/// given PR.
///
/// Override semantics (label + revision-bound review + current permission):
///   1. The PR must carry `override_cfg.require_label`.
///   2. The account that last added the label must hold at least
///      `override_cfg.required_permission` on the repo (admin/maintain/write).
///   3. That account's latest submitted review explicitly authorizes the current
///      head, and the actual desired/configuration/executable inputs match it.
///
/// Returns `OverrideDecision::inactive(...)` when the GitHub API is unreachable
/// or when any check fails; apply/review commands treat this as "no override,
/// policy still enforced."
pub async fn check_override(
    env_config: &EnvConfig,
    override_cfg: &OverrideConfig,
    pr_number: u64,
) -> crate::error::Result<OverrideDecision> {
    check_override_context(env_config, override_cfg, pr_number, false).await
}

/// Trusted review uses protected executable source alongside sanitized PR data.
/// Apply and plan always inspect their own working directory and cannot select
/// an unrelated source checkout with this review-only environment setting.
pub async fn check_review_override(
    env_config: &EnvConfig,
    override_cfg: &OverrideConfig,
    pr_number: u64,
) -> crate::error::Result<OverrideDecision> {
    check_override_context(env_config, override_cfg, pr_number, true).await
}

async fn check_override_context(
    env_config: &EnvConfig,
    override_cfg: &OverrideConfig,
    pr_number: u64,
    review_context: bool,
) -> crate::error::Result<OverrideDecision> {
    let token = match env_config.github_token.as_deref() {
        Some(t) => t,
        None => return Ok(OverrideDecision::inactive("GITHUB_TOKEN not set")),
    };
    let repo = match env_config.github_repository.as_deref() {
        Some(r) => r,
        None => return Ok(OverrideDecision::inactive("GITHUB_REPOSITORY not set")),
    };

    // Honor FERRUM_GITHUB_*_TIMEOUT_SECS. Without these, a stalled GitHub
    // API call during override checks hangs apply/review indefinitely,
    // blocking deployments or PR feedback on a transient GitHub incident.
    use std::time::Duration;
    let client = Client::builder()
        .user_agent("gitforgeops/0.1")
        .connect_timeout(Duration::from_secs(env_config.github_connect_timeout_secs))
        .timeout(Duration::from_secs(env_config.github_request_timeout_secs))
        // Bearer-token calls to api.github.com only: never follow a redirect
        // with the token, never downgrade to http://. Pagination follows the
        // `Link` header through fresh requests, not 3xx responses.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    check_override_at(
        &client,
        crate::secrets::DEFAULT_GITHUB_API_BASE,
        repo,
        token,
        override_cfg,
        pr_number,
        |tree, merged, merge_revision| {
            super::override_input::verify_current_input(
                tree,
                merged,
                merge_revision,
                review_context,
            )
        },
    )
    .await
}

/// [`check_override`] against an explicit API origin and input verifier.
///
/// Production passes [`crate::secrets::DEFAULT_GITHUB_API_BASE`] and
/// [`super::override_input::verify_current_input`]; tests pass a loopback stub
/// and a fixed verdict. Every request goes to a fixed path under `api_base`.
pub async fn check_override_at<F>(
    client: &Client,
    api_base: &str,
    repo: &str,
    token: &str,
    override_cfg: &OverrideConfig,
    pr_number: u64,
    verify_input: F,
) -> crate::error::Result<OverrideDecision>
where
    F: FnOnce(&serde_json::Value, bool, Option<&str>) -> Result<String, String>,
{
    let api_base = api_base.trim_end_matches('/');
    let pr_url = format!("{api_base}/repos/{repo}/pulls/{pr_number}");
    let pr: PullRequest = match fetch_json(client, &pr_url, token).await {
        Ok(value) => match serde_json::from_value(value) {
            Ok(pr) => pr,
            Err(e) => {
                return Ok(OverrideDecision::inactive(
                    &crate::http_client::malformed_response("parse PR", &e).to_string(),
                ))
            }
        },
        Err(e) => return Ok(OverrideDecision::inactive(&format!("fetch PR: {e}"))),
    };

    if !pr
        .labels
        .iter()
        .any(|l| l.name == override_cfg.require_label)
    {
        return Ok(OverrideDecision::inactive(&format!(
            "override label '{}' not present",
            override_cfg.require_label
        )));
    }

    // Issue events are paginated. On busy PRs the relevant `labeled` event
    // may live on a later page, so every numbered page is read from the fixed
    // API origin (never a response-supplied `Link` URL). We track the latest
    // matching `labeled` event across all pages and the matching `unlabeled`
    // events, so a label that was added, removed, and re-added is correctly
    // attributed to the last add.
    let approver = match find_override_labeler_at(
        client,
        api_base,
        repo,
        pr_number,
        token,
        &override_cfg.require_label,
    )
    .await
    {
        Ok(Some(login)) => login,
        Ok(None) => {
            return Ok(OverrideDecision::inactive(
                "no labeling event found for override label across all event pages",
            ))
        }
        Err(e) => return Ok(OverrideDecision::inactive(&format!("fetch events: {e}"))),
    };

    let permission = match fetch_permission_at(client, api_base, repo, &approver, token).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(OverrideDecision::inactive(&format!(
                "check permission for {}: {e}",
                crate::display::peer_text(&approver)
            )))
        }
    };

    if !override_cfg.is_sufficient(&permission) {
        // The login and permission are GitHub's text: the decision reads them
        // raw, the displayed reason quotes scrubbed copies.
        return Ok(OverrideDecision::inactive(&format!(
            "@{} has permission '{}', override requires '{}'",
            crate::display::peer_text(&approver),
            crate::display::peer_text(&permission),
            override_cfg.required_permission
        )));
    }

    let reviews = match fetch_reviews_at(client, api_base, repo, pr_number, token).await {
        Ok(reviews) => reviews,
        Err(_) => {
            return Ok(OverrideDecision::inactive(
                "cannot verify override review history",
            ))
        }
    };
    let review = match authorized_review(
        &reviews,
        &approver,
        &override_cfg.require_label,
        &pr.head.sha,
    ) {
        Some(review) => review,
        None => {
            return Ok(OverrideDecision::inactive(
                "labeler must submit a fresh review of the current head with body: gitforgeops-override <configured-label>",
            ))
        }
    };
    let tree_url = format!(
        "{api_base}/repos/{repo}/git/trees/{}?recursive=1",
        pr.head.sha
    );
    let tree = match fetch_json(client, &tree_url, token).await {
        Ok(tree) => tree,
        Err(_) => {
            return Ok(OverrideDecision::inactive(
                "cannot verify authorized input tree",
            ))
        }
    };
    let applied_revision = match verify_input(&tree, pr.merged, pr.merge_commit_sha.as_deref()) {
        Ok(revision) => revision,
        Err(reason) => return Ok(OverrideDecision::inactive(&reason)),
    };
    // Close the API-read window as far as a client can: a push, merge, or label
    // change while collecting evidence invalidates this decision.
    let current = fetch_json(client, &pr_url, token)
        .await
        .ok()
        .and_then(|value| serde_json::from_value::<PullRequest>(value).ok());
    if current.as_ref() != Some(&pr) {
        return Ok(OverrideDecision::inactive(
            "PR changed during override verification",
        ));
    }
    let current_labeler = find_override_labeler_at(
        client,
        api_base,
        repo,
        pr_number,
        token,
        &override_cfg.require_label,
    )
    .await
    .ok()
    .flatten();
    // The labeler's permission is part of the evidence: a demotion while the
    // rest was collected revokes the override like a relabel does.
    let permission_still_sufficient = fetch_permission_at(client, api_base, repo, &approver, token)
        .await
        .ok()
        .is_some_and(|permission| override_cfg.is_sufficient(&permission));
    let current_reviews = fetch_reviews_at(client, api_base, repo, pr_number, token)
        .await
        .ok();
    let current_review = current_reviews.as_ref().and_then(|reviews| {
        authorized_review(
            reviews,
            &approver,
            &override_cfg.require_label,
            &pr.head.sha,
        )
    });
    if current_labeler.as_deref() != Some(approver.as_str())
        || !permission_still_sufficient
        || current_review != Some(review)
    {
        return Ok(OverrideDecision::inactive(
            "override evidence changed during verification",
        ));
    }

    Ok(OverrideDecision {
        active: true,
        approver: Some(approver.clone()),
        permission: Some(permission.clone()),
        reason: format!(
            "overridden by @{} ({}), PR #{pr_number}, review {}, authorized head {}",
            crate::display::peer_text(&approver),
            crate::display::peer_text(&permission),
            review.id,
            crate::display::peer_text(&pr.head.sha)
        ),
        pr_number: Some(pr_number),
        authorized_head: Some(pr.head.sha),
        review_id: Some(review.id),
        applied_revision: Some(applied_revision),
    })
}

/// Walk every page of `/issues/{pr}/events`, returning the login of the user
/// who most recently added `label_name`. If that label was later removed
/// (`unlabeled` event is newer), returns `None`.
///
/// GitHub's `/issues/.../events` returns events in ascending time order, so
/// "latest" = highest page, later index within a page. We scan pages in order
/// and keep the most recent matching add event, tracking whether a later
/// unlabel supersedes it.
const MAX_ISSUE_EVENT_PAGES: usize = 20;
const PAGE_SIZE: usize = 100;

/// Decide whether a numbered page ends the listing.
///
/// A short page ends it only when no `Link` header announces a next page. A
/// short page that still claims `rel="next"` contradicts itself (GitHub may cap
/// `per_page` below the request, or the listing moved), so the read fails
/// closed instead of treating the history as complete. The announced URL is
/// never requested: the next read is always the next numbered page from the
/// fixed origin.
fn page_is_last(items: usize, announces_next: bool, what: &str) -> crate::error::Result<bool> {
    match (items < PAGE_SIZE, announces_next) {
        (false, _) => Ok(false),
        (true, false) => Ok(true),
        (true, true) => Err(crate::error::Error::Config(format!(
            "override {what} page is short but GitHub announces a next page; refusing an incomplete history"
        ))),
    }
}

/// The login that most recently added `label_name`, against an explicit API
/// origin (`None` when a later `unlabeled` event supersedes it).
///
/// Production passes [`crate::secrets::DEFAULT_GITHUB_API_BASE`]; tests pass a
/// loopback stub. Pages are requested by number from `api_base`. A response's
/// `Link` header is never followed, so the bearer token cannot be sent to a
/// host or path a response names; it is read only to refuse a short page that
/// still announces a next one. An exactly full page requires another read to
/// prove completeness, and reaching the page cap with a full page fails closed
/// so a later relabel cannot be missed.
pub async fn find_override_labeler_at(
    client: &Client,
    api_base: &str,
    repo: &str,
    pr_number: u64,
    token: &str,
    label_name: &str,
) -> crate::error::Result<Option<String>> {
    let api_base = api_base.trim_end_matches('/');
    let mut latest_labeler: Option<String> = None;

    for page in 1..=MAX_ISSUE_EVENT_PAGES {
        let url =
            format!("{api_base}/repos/{repo}/issues/{pr_number}/events?per_page=100&page={page}");
        let (value, announces_next) = fetch_json_page(client, &url, token).await?;
        let events: Vec<IssueEvent> = serde_json::from_value(value)
            .map_err(|e| crate::http_client::malformed_response("parse events", &e))?;
        let complete = page_is_last(events.len(), announces_next, "label event")?;

        for event in events {
            let matches_label = event
                .label
                .as_ref()
                .map(|l| l.name == label_name)
                .unwrap_or(false);
            if !matches_label {
                continue;
            }
            match event.event.as_str() {
                "labeled" => {
                    latest_labeler = event.actor.as_ref().map(|actor| actor.login.clone());
                }
                "unlabeled" => {
                    latest_labeler = None;
                }
                _ => {}
            }
        }

        if complete {
            return Ok(latest_labeler);
        }
    }

    Err(crate::error::Error::Config(
        "override label event history exceeds pagination safety cap; refusing stale approver attribution"
            .to_string(),
    ))
}

/// Every submitted review on the PR, oldest first, against an explicit API
/// origin. Production passes [`crate::secrets::DEFAULT_GITHUB_API_BASE`];
/// tests pass a loopback stub.
pub async fn fetch_reviews_at(
    client: &Client,
    api_base: &str,
    repo: &str,
    pr_number: u64,
    token: &str,
) -> crate::error::Result<Vec<OverrideReview>> {
    let api_base = api_base.trim_end_matches('/');
    let mut reviews = Vec::new();
    // Request numbered pages from the fixed API origin, never a supplied URL.
    // An exactly full final page requires another read to prove completeness,
    // and a short page that announces a next one fails closed.
    for page in 1..=MAX_ISSUE_EVENT_PAGES {
        let url =
            format!("{api_base}/repos/{repo}/pulls/{pr_number}/reviews?per_page=100&page={page}");
        let (value, announces_next) = fetch_json_page(client, &url, token).await?;
        let batch: Vec<OverrideReview> = serde_json::from_value(value)
            .map_err(|e| crate::http_client::malformed_response("parse reviews", &e))?;
        let complete = page_is_last(batch.len(), announces_next, "review")?;
        reviews.extend(batch);
        if complete {
            return Ok(reviews);
        }
    }
    Err(crate::error::Error::Config(
        "override review history exceeds pagination safety cap".into(),
    ))
}

/// What one `Link` header value says about a next page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextLink {
    /// The value parses unambiguously and no link-value has a `next` relation.
    Absent,
    /// The target of the link-value(s) with a `next` relation, as written.
    Next(String),
    /// The value is not an unambiguous RFC 8288 `#link-value` list, or names
    /// two different `next` targets.
    Ambiguous,
}

/// Classify one `Link` header value (RFC 8288): `rel` is matched
/// case-insensitively with a token or quoted-string value and optional
/// whitespace around `=`; relation types are space-separated and compared
/// case-insensitively; every comma-separated link-value is read, so a
/// malformed entry never hides a later one (it makes the whole value
/// [`NextLink::Ambiguous`]). Every relation type must be a valid
/// `reg-rel-type` or `ext-rel-type`, and every target a non-empty
/// `URI-Reference` without whitespace.
pub fn next_link(header: &str) -> NextLink {
    let Some(values) = link_values(header) else {
        return NextLink::Ambiguous;
    };
    let mut next: Option<String> = None;
    for (target, relations) in values {
        if !relations
            .iter()
            .any(|relation| relation.eq_ignore_ascii_case("next"))
        {
            continue;
        }
        match &next {
            Some(existing) if existing != &target => return NextLink::Ambiguous,
            _ => next = Some(target),
        }
    }
    next.map_or(NextLink::Absent, NextLink::Next)
}

/// The `next` target of a `Link` header value, or `None` when it names none
/// or does not parse unambiguously. Callers that must prove a listing
/// complete use [`next_link`] and treat [`NextLink::Ambiguous`] as more.
pub fn parse_next_link(header: &str) -> Option<String> {
    match next_link(header) {
        NextLink::Next(target) => Some(target),
        NextLink::Absent | NextLink::Ambiguous => None,
    }
}

/// Whether any `Link` header value announces a next page. An unreadable value
/// counts as an announcement, so a short page carrying it fails closed.
fn announces_next_page(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::LINK)
        .iter()
        .any(|value| match value.to_str() {
            Ok(text) => link_header_may_announce_next(text),
            Err(_) => true,
        })
}

/// Whether one `Link` header value may announce a next page: a `next`
/// relation, or any value that does not parse unambiguously, so a short page
/// carrying it fails closed. Only the relations are read: no URL is used.
pub fn link_header_may_announce_next(header: &str) -> bool {
    !matches!(next_link(header), NextLink::Absent)
}

/// An RFC 8288 `relation-type`: a `reg-rel-type` (`LOALPHA *( LOALPHA / DIGIT
/// / "." / "-" )`, compared case-insensitively, so either case is accepted) or
/// an `ext-rel-type` (an absolute URI: a scheme, `:`, then RFC 3986 URI
/// characters only). `,` and `;` are refused even inside an extension URI:
/// they are list and parameter separators in the header, so a type holding
/// one is treated as ambiguous rather than read either way.
fn is_relation_type(relation: &str) -> bool {
    let bytes = relation.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    if rest
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return true;
    }
    let Some(colon) = bytes.iter().position(|&byte| byte == b':') else {
        return false;
    };
    let scheme_ok = bytes[1..colon]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    let uri_ok = bytes[colon + 1..]
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+=%".contains(&byte));
    scheme_ok && uri_ok && colon + 1 < bytes.len()
}

/// Every link-value of one `Link` header value as `(target, relation types)`,
/// or `None` when the value is not an unambiguous RFC 8288 `#link-value` list.
fn link_values(header: &str) -> Option<Vec<(String, Vec<String>)>> {
    fn is_tchar(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
    }
    fn skip_ows(bytes: &[u8], at: &mut usize) {
        while *at < bytes.len() && matches!(bytes[*at], b' ' | b'\t') {
            *at += 1;
        }
    }
    fn token(bytes: &[u8], at: &mut usize) -> Option<String> {
        let start = *at;
        while *at < bytes.len() && is_tchar(bytes[*at]) {
            *at += 1;
        }
        (*at > start).then(|| String::from_utf8_lossy(&bytes[start..*at]).into_owned())
    }
    fn quoted(bytes: &[u8], at: &mut usize) -> Option<String> {
        // Caller has seen the opening quote.
        *at += 1;
        let mut value = Vec::new();
        while *at < bytes.len() {
            match bytes[*at] {
                b'"' => {
                    *at += 1;
                    return String::from_utf8(value).ok();
                }
                b'\\' => {
                    let escaped = *bytes.get(*at + 1)?;
                    value.push(escaped);
                    *at += 2;
                }
                byte => {
                    value.push(byte);
                    *at += 1;
                }
            }
        }
        None
    }

    let bytes = header.as_bytes();
    let mut at = 0;
    let mut values = Vec::new();
    loop {
        skip_ows(bytes, &mut at);
        match bytes.get(at) {
            None => return Some(values),
            // Empty list elements are allowed by the `#` rule.
            Some(b',') => {
                at += 1;
                continue;
            }
            Some(b'<') => {}
            Some(_) => return None,
        }
        // `<URI-Reference>`: a URI cannot contain a raw `<` or `>`.
        let close = bytes[at + 1..]
            .iter()
            .position(|byte| matches!(byte, b'<' | b'>'))?;
        if bytes[at + 1 + close] != b'>' {
            return None;
        }
        // A minimal `URI-Reference` check: non-empty visible ASCII, no
        // whitespace (`<` and `>` are already excluded).
        let target = &bytes[at + 1..at + 1 + close];
        if target.is_empty() || !target.iter().all(|byte| byte.is_ascii_graphic()) {
            return None;
        }
        let target = String::from_utf8(target.to_vec()).ok()?;
        at += close + 2;
        let mut relations = Vec::new();
        let mut last = false;
        loop {
            skip_ows(bytes, &mut at);
            match bytes.get(at) {
                None => {
                    last = true;
                    break;
                }
                Some(b',') => {
                    at += 1;
                    break;
                }
                Some(b';') => at += 1,
                Some(_) => return None,
            }
            skip_ows(bytes, &mut at);
            let name = token(bytes, &mut at)?;
            skip_ows(bytes, &mut at);
            let value = if bytes.get(at) == Some(&b'=') {
                at += 1;
                skip_ows(bytes, &mut at);
                Some(if bytes.get(at) == Some(&b'"') {
                    quoted(bytes, &mut at)?
                } else {
                    token(bytes, &mut at)?
                })
            } else {
                None
            };
            let name = name.to_ascii_lowercase();
            if name == "rel" {
                // A `rel` without a value names no relation unambiguously.
                // `relation-types`: relation types separated by `1*SP`, no
                // leading or trailing space; each must be a valid type.
                let value = value?;
                if value.is_empty() || value.starts_with(' ') || value.ends_with(' ') {
                    return None;
                }
                for relation in value.split(' ').filter(|relation| !relation.is_empty()) {
                    if !is_relation_type(relation) {
                        return None;
                    }
                    relations.push(relation.to_string());
                }
            } else if name == "rel*" {
                // An extended-notation relation is not unambiguously absent.
                return None;
            }
        }
        values.push((target, relations));
        if last {
            return Some(values);
        }
    }
}

async fn fetch_json(
    client: &Client,
    url: &str,
    token: &str,
) -> crate::error::Result<serde_json::Value> {
    Ok(fetch_json_page(client, url, token).await?.0)
}

/// [`fetch_json`] that also reports whether the response announces a next page.
async fn fetch_json_page(
    client: &Client,
    url: &str,
    token: &str,
) -> crate::error::Result<(serde_json::Value, bool)> {
    let resp = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        let body = crate::http_client::read_error_body(resp).await;
        return Err(crate::error::Error::ApiError {
            status,
            message: body,
        });
    }
    let announces_next = announces_next_page(resp.headers());
    let value = resp
        .json()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
    Ok((value, announces_next))
}

async fn fetch_permission_at(
    client: &Client,
    api_base: &str,
    repo: &str,
    login: &str,
    token: &str,
) -> crate::error::Result<String> {
    let url = format!("{api_base}/repos/{repo}/collaborators/{login}/permission");
    let value = fetch_json(client, &url, token).await?;
    let parsed: PermissionResponse = serde_json::from_value(value)
        .map_err(|e| crate::http_client::malformed_response("parse permission", &e))?;
    Ok(parsed.effective_permission().to_string())
}

/// Apply an override decision to a set of findings: sets `overridden_by` on any
/// finding whose severity currently blocks apply.
pub fn apply_override(findings: &mut [super::PolicyFinding], decision: &OverrideDecision) {
    if !decision.active {
        return;
    }
    let by = decision
        .approver
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    for finding in findings.iter_mut() {
        if finding.severity.blocks_apply() {
            finding.overridden_by = Some(by.clone());
        }
    }
}

/// The identity an override is bound to: rule, severity, resource and message
/// of a finding in the unresolved (committed) document. A finding after
/// credential resolution that differs in any of them is one the override
/// review did not accept.
fn reviewed_identity(finding: &super::PolicyFinding) -> FindingIdentity {
    (
        finding.rule_id.clone(),
        finding.severity,
        finding.kind.clone(),
        finding.namespace.clone(),
        finding.id.clone(),
        finding.message.clone(),
    )
}

/// Explains a blocking finding that only credential resolution produced.
pub const RESOLUTION_ONLY_REMEDIATION: &str = "appeared only after credential resolution; a policy override covers only findings in the committed (unresolved) configuration, so fix the resource or the credential value";

/// [`apply_override`] limited to blocking findings that also appear in
/// `reviewed`, the evaluation of the unresolved (committed) document.
///
/// api-mode apply re-evaluates policy after credential resolution. A blocking
/// finding that exists only in the resolved document is not a finding of the
/// reviewed revision's committed bytes, so the override does not cover it; it
/// stays blocking. Returns how many blocking findings were left uncovered for
/// that reason.
pub fn apply_override_to_reviewed(
    findings: &mut [super::PolicyFinding],
    decision: &OverrideDecision,
    reviewed: &[super::PolicyFinding],
) -> usize {
    if !decision.active {
        return 0;
    }
    let by = decision
        .approver
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    // A multiset: one unresolved finding covers one identical resolved
    // finding, never several.
    let mut reviewed = identity_counts(
        reviewed
            .iter()
            .filter(|finding| finding.severity.blocks_apply()),
    );
    let mut uncovered = 0;
    for finding in findings.iter_mut() {
        if !finding.severity.blocks_apply() {
            continue;
        }
        if take_identity(&mut reviewed, finding) {
            finding.overridden_by = Some(by.clone());
        } else {
            uncovered += 1;
        }
    }
    uncovered
}

type FindingIdentity = (String, super::Severity, String, String, String, String);

fn identity_counts<'a>(
    findings: impl Iterator<Item = &'a super::PolicyFinding>,
) -> std::collections::HashMap<FindingIdentity, usize> {
    let mut counts = std::collections::HashMap::new();
    for finding in findings {
        *counts.entry(reviewed_identity(finding)).or_insert(0) += 1;
    }
    counts
}

/// Consume one occurrence of `finding`'s identity; false once exhausted.
fn take_identity(
    counts: &mut std::collections::HashMap<FindingIdentity, usize>,
    finding: &super::PolicyFinding,
) -> bool {
    match counts.get_mut(&reviewed_identity(finding)) {
        Some(count) if *count > 0 => {
            *count -= 1;
            true
        }
        _ => false,
    }
}

/// The policy findings `plan` and `review` preview, gated exactly as `apply`
/// gates them.
///
/// `apply` refuses on the unresolved document with the whole override, then
/// (api mode only) on the resolved document with the override limited to
/// unresolved findings ([`apply_override_to_reviewed`]). The preview is the
/// unresolved findings plus, when `resolved` is given, every resolved finding
/// with no unresolved twin. Such a finding stays blocking under an active
/// override and carries [`RESOLUTION_ONLY_REMEDIATION`]. Returns the list and
/// how many blocking findings the override leaves uncovered.
pub fn preview_policy_findings(
    unresolved: &[super::PolicyFinding],
    resolved: Option<&[super::PolicyFinding]>,
    decision: Option<&OverrideDecision>,
) -> (Vec<super::PolicyFinding>, usize) {
    let mut preview = unresolved.to_vec();
    if let Some(decision) = decision {
        apply_override(&mut preview, decision);
    }
    let Some(resolved) = resolved else {
        return (preview, 0);
    };
    let mut resolved = resolved.to_vec();
    let uncovered = decision
        .map(|decision| apply_override_to_reviewed(&mut resolved, decision, unresolved))
        .unwrap_or(0);
    // Each unresolved finding has at most one resolved twin, matched in the
    // same order `apply_override_to_reviewed` covers them; the rest are
    // resolution-only.
    let mut twins = identity_counts(unresolved.iter());
    let active = decision.is_some_and(|decision| decision.active);
    let resolution_only: Vec<_> = resolved
        .into_iter()
        .filter(|finding| !take_identity(&mut twins, finding))
        .map(|mut finding| {
            if active && finding.is_blocking() {
                finding.remediation = Some(RESOLUTION_ONLY_REMEDIATION.to_string());
            }
            finding
        })
        .collect();
    preview.extend(resolution_only);
    (preview, uncovered)
}
