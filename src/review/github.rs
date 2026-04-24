use std::env;
use std::time::Duration;

use crate::config::EnvConfig;

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

    let resp = client
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "gitforgeops")
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    let status = resp.status().as_u16();
    if status >= 400 {
        let resp_body = resp
            .text()
            .await
            .unwrap_or_else(|_| String::from("<no body>"));
        return Err(crate::error::Error::ApiError {
            status,
            message: resp_body,
        });
    }

    Ok(())
}
