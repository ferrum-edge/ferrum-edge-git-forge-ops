use std::env;
use std::time::Duration;

use crate::config::EnvConfig;

const MAX_COMMENT_RETRIES: u32 = 2;

pub fn comment_status_is_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

pub async fn post_pr_comment(
    env_config: &EnvConfig,
    pr_number: u64,
    comment: &str,
) -> crate::error::Result<()> {
    let token = env::var("GITHUB_TOKEN")
        .map_err(|_| crate::error::Error::Config("GITHUB_TOKEN not set".to_string()))?;
    let repo = env::var("GITHUB_REPOSITORY")
        .map_err(|_| crate::error::Error::Config("GITHUB_REPOSITORY not set".to_string()))?;

    let url = format!(
        "https://api.github.com/repos/{}/issues/{}/comments",
        repo, pr_number
    );

    let body = serde_json::json!({ "body": comment });

    // Same-shape bounds as the admin client: connect + total request.
    // Keeps `gitforgeops review --pr N` from hanging forever if GitHub's
    // API is slow or unreachable.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(env_config.github_connect_timeout_secs))
        .timeout(Duration::from_secs(env_config.github_request_timeout_secs))
        .build()
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    for attempt in 0..=MAX_COMMENT_RETRIES {
        let resp = client
            .post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "gitforgeops")
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            // A transport failure has ambiguous POST state, so never retry it
            // and risk creating a duplicate review comment.
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| Duration::from_secs(seconds.min(30)));
        if status < 400 {
            return Ok(());
        }
        let resp_body = resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<no body>"));
        if attempt < MAX_COMMENT_RETRIES && comment_status_is_retryable(status) {
            let delay = retry_after
                .unwrap_or_else(|| Duration::from_millis(500_u64.saturating_mul(1_u64 << attempt)));
            tokio::time::sleep(delay).await;
            continue;
        }
        return Err(crate::error::Error::ApiError {
            status,
            message: resp_body,
        });
    }
    Err(crate::error::Error::HttpClient(
        "GitHub comment retry loop ended unexpectedly".to_string(),
    ))
}
