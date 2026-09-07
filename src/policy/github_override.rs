use reqwest::Client;
use serde::Deserialize;

use crate::config::EnvConfig;

use super::config::OverrideConfig;

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

#[derive(Debug, Deserialize)]
struct PermissionResponse {
    permission: String,
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
        .build()
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    let pr_url = format!("https://api.github.com/repos/{repo}/pulls/{pr_number}");
    let pr: PullRequest = match fetch_json(&client, &pr_url, token).await {
        Ok(value) => match serde_json::from_value(value) {
            Ok(pr) => pr,
            Err(e) => return Ok(OverrideDecision::inactive(&format!("parse PR: {e}"))),
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

    // Issue events are paginated (default 30 per page). On busy PRs the
    // relevant `labeled` event may live on a later page, so we must follow
    // the `Link: rel="next"` header rather than trusting a single response.
    // We track the latest matching `labeled` event across all pages and the
    // matching `unlabeled` events, so a label that was added, removed, and
    // re-added is correctly attributed to the last add.
    let approver =
        match find_override_labeler(&client, repo, pr_number, token, &override_cfg.require_label)
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

    let permission = match fetch_permission(&client, repo, &approver, token).await {
        Ok(p) => p,
        Err(e) => {
            return Ok(OverrideDecision::inactive(&format!(
                "check permission for {approver}: {e}"
            )))
        }
    };

    if !override_cfg.is_sufficient(&permission) {
        return Ok(OverrideDecision::inactive(&format!(
            "@{approver} has permission '{permission}', override requires '{}'",
            override_cfg.required_permission
        )));
    }

    let reviews = match fetch_reviews(&client, repo, pr_number, token).await {
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
        "https://api.github.com/repos/{repo}/git/trees/{}?recursive=1",
        pr.head.sha
    );
    let tree = match fetch_json(&client, &tree_url, token).await {
        Ok(tree) => tree,
        Err(_) => {
            return Ok(OverrideDecision::inactive(
                "cannot verify authorized input tree",
            ))
        }
    };
    let applied_revision = match super::override_input::verify_current_input(
        &tree,
        pr.merged,
        pr.merge_commit_sha.as_deref(),
        review_context,
    ) {
        Ok(revision) => revision,
        Err(reason) => return Ok(OverrideDecision::inactive(&reason)),
    };
    // Close the API-read window as far as a client can: a push, merge, or label
    // change while collecting evidence invalidates this decision.
    let current = fetch_json(&client, &pr_url, token)
        .await
        .ok()
        .and_then(|value| serde_json::from_value::<PullRequest>(value).ok());
    if current.as_ref() != Some(&pr) {
        return Ok(OverrideDecision::inactive(
            "PR changed during override verification",
        ));
    }
    let current_labeler =
        find_override_labeler(&client, repo, pr_number, token, &override_cfg.require_label)
            .await
            .ok()
            .flatten();
    let current_reviews = fetch_reviews(&client, repo, pr_number, token).await.ok();
    let current_review = current_reviews.as_ref().and_then(|reviews| {
        authorized_review(reviews, &approver, &override_cfg.require_label, &pr.head.sha)
    });
    if current_labeler.as_deref() != Some(approver.as_str()) || current_review != Some(review) {
        return Ok(OverrideDecision::inactive(
            "override evidence changed during verification",
        ));
    }

    Ok(OverrideDecision {
        active: true,
        approver: Some(approver.clone()),
        permission: Some(permission.clone()),
        reason: format!(
            "overridden by @{approver} ({permission}), PR #{pr_number}, review {}, authorized head {}",
            review.id, pr.head.sha
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

pub fn hit_pagination_safety_cap(page_idx: usize, has_next_page: bool) -> bool {
    page_idx + 1 == MAX_ISSUE_EVENT_PAGES && has_next_page
}

async fn find_override_labeler(
    client: &Client,
    repo: &str,
    pr_number: u64,
    token: &str,
    label_name: &str,
) -> crate::error::Result<Option<String>> {
    let mut next_url = Some(format!(
        "https://api.github.com/repos/{repo}/issues/{pr_number}/events?per_page=100"
    ));

    let mut latest_labeler: Option<String> = None;

    // Hard cap on pages so a pathological PR can't spin this forever.
    // Fail closed if the cap is reached while another page still exists;
    // otherwise a later relabel could supersede the actor we observed.
    for page_idx in 0..MAX_ISSUE_EVENT_PAGES {
        let url = match next_url.take() {
            Some(u) => u,
            None => break,
        };
        let resp = client
            .get(&url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body = resp.text().await.unwrap_or_default();
            return Err(crate::error::Error::ApiError {
                status,
                message: body,
            });
        }

        // Capture the Link header *before* consuming the body.
        next_url = resp
            .headers()
            .get(reqwest::header::LINK)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_next_link);

        let events: Vec<IssueEvent> = resp
            .json()
            .await
            .map_err(|e| crate::error::Error::HttpClient(format!("parse events: {e}")))?;

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

        if hit_pagination_safety_cap(page_idx, next_url.is_some()) {
            return Err(crate::error::Error::Config(
                "override label event history exceeds pagination safety cap; refusing stale approver attribution"
                    .to_string(),
            ));
        }
    }

    Ok(latest_labeler)
}

async fn fetch_reviews(
    client: &Client,
    repo: &str,
    pr_number: u64,
    token: &str,
) -> crate::error::Result<Vec<OverrideReview>> {
    let mut reviews = Vec::new();
    // Request numbered pages from the fixed API origin, never a supplied URL.
    // An exactly full final page requires another read to prove completeness.
    for page in 1..=MAX_ISSUE_EVENT_PAGES {
        let url = format!(
            "https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews?per_page=100&page={page}"
        );
        let batch: Vec<OverrideReview> =
            serde_json::from_value(fetch_json(client, &url, token).await?)?;
        let complete = batch.len() < 100;
        reviews.extend(batch);
        if complete {
            return Ok(reviews);
        }
    }
    Err(crate::error::Error::Config(
        "override review history exceeds pagination safety cap".into(),
    ))
}

/// Extract the `rel="next"` URL from a GitHub `Link` header. Returns `None`
/// when there is no next page.
pub fn parse_next_link(header: &str) -> Option<String> {
    for entry in header.split(',') {
        let entry = entry.trim();
        // Format: `<URL>; rel="next"`
        let (url_part, rel_part) = entry.split_once(';')?;
        let url = url_part
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        if rel_part.trim() == "rel=\"next\"" {
            return Some(url.to_string());
        }
    }
    None
}

async fn fetch_json(
    client: &Client,
    url: &str,
    token: &str,
) -> crate::error::Result<serde_json::Value> {
    let resp = client
        .get(url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    let status = resp.status().as_u16();
    if status >= 400 {
        let body = resp.text().await.unwrap_or_default();
        return Err(crate::error::Error::ApiError {
            status,
            message: body,
        });
    }
    resp.json()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))
}

async fn fetch_permission(
    client: &Client,
    repo: &str,
    login: &str,
    token: &str,
) -> crate::error::Result<String> {
    let url = format!("https://api.github.com/repos/{repo}/collaborators/{login}/permission");
    let value = fetch_json(client, &url, token).await?;
    let parsed: PermissionResponse = serde_json::from_value(value)?;
    Ok(parsed.permission)
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
