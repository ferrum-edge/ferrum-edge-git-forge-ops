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
}

impl OverrideDecision {
    pub fn inactive(reason: &str) -> Self {
        Self {
            active: false,
            approver: None,
            permission: None,
            reason: reason.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct PullRequest {
    #[serde(default)]
    labels: Vec<Label>,
}

#[derive(Debug, Deserialize)]
struct PermissionResponse {
    permission: String,
}

/// Consult the GitHub API to decide whether a policy override is active on the
/// given PR.
///
/// Override semantics (B2, label + write-permission):
///   1. The PR must carry `override_cfg.require_label`.
///   2. The account that last added the label must hold at least
///      `override_cfg.required_permission` on the repo (admin/maintain/write).
///
/// Returns `OverrideDecision::inactive(...)` when the GitHub API is unreachable
/// or when any check fails; apply/review commands treat this as "no override,
/// policy still enforced."
pub async fn check_override(
    env_config: &EnvConfig,
    override_cfg: &OverrideConfig,
    pr_number: u64,
) -> crate::error::Result<OverrideDecision> {
    let token = match env_config.github_token.as_deref() {
        Some(t) => t,
        None => return Ok(OverrideDecision::inactive("GITHUB_TOKEN not set")),
    };
    let repo = match env_config.github_repository.as_deref() {
        Some(r) => r,
        None => return Ok(OverrideDecision::inactive("GITHUB_REPOSITORY not set")),
    };

    let client = Client::builder()
        .user_agent("gitforgeops/0.1")
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

    Ok(OverrideDecision {
        active: true,
        approver: Some(approver.clone()),
        permission: Some(permission.clone()),
        reason: format!("overridden by @{approver} ({permission})"),
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
    for _ in 0..20 {
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
                    if let Some(actor) = event.actor.as_ref() {
                        latest_labeler = Some(actor.login.clone());
                    }
                }
                "unlabeled" => {
                    latest_labeler = None;
                }
                _ => {}
            }
        }
    }

    Ok(latest_labeler)
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
