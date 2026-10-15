use std::env;
use std::time::Duration;

use crate::config::EnvConfig;

const MAX_COMMENT_RETRIES: u32 = 2;

/// Which GitHub comment-POST failures are worth another attempt.
///
/// Only the transient-by-contract statuses: a request timeout, a rate-limit
/// or secondary-limit rejection, and an explicit "unavailable". Everything
/// else — 401/403 (bad token), 404 (wrong repo or PR), 422 (body rejected) —
/// is deterministic and retrying only delays the fallback path.
pub fn comment_status_is_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 503)
}

/// Promote a PR-comment delivery failure to a trusted-review failure after
/// the caller has written its step-summary/stdout fallback. Secretless and
/// fork reviews intentionally retain best-effort delivery.
pub fn enforce_required_comment_delivery(
    require_live: bool,
    delivery_error: &str,
) -> crate::error::Result<()> {
    if require_live {
        return Err(crate::error::Error::Config(format!(
            "trusted live review could not post its required PR comment: {delivery_error}"
        )));
    }
    Ok(())
}

/// Post `comment` to the PR. It is published, so it goes through the display
/// sink like stdout.
pub async fn post_pr_comment(
    env_config: &EnvConfig,
    pr_number: u64,
    comment: &str,
) -> crate::error::Result<()> {
    post_rendered_pr_comment(env_config, pr_number, &crate::display::scrub_text(comment)).await
}

/// Post a comment carrying ciphertext: its text parts are scrubbed, the
/// ciphertext is posted byte for byte ([`crate::display::Composed`]).
pub async fn post_composed_pr_comment(
    env_config: &EnvConfig,
    pr_number: u64,
    comment: &crate::display::Composed,
) -> crate::error::Result<()> {
    post_rendered_pr_comment(env_config, pr_number, &comment.render()).await
}

/// Post a body that already went through the display sink.
async fn post_rendered_pr_comment(
    env_config: &EnvConfig,
    pr_number: u64,
    comment: &str,
) -> crate::error::Result<()> {
    let token = env::var("GITHUB_TOKEN")
        .map_err(|_| crate::error::Error::Config("GITHUB_TOKEN not set".to_string()))?;
    let repo = env::var("GITHUB_REPOSITORY")
        .map_err(|_| crate::error::Error::Config("GITHUB_REPOSITORY not set".to_string()))?;
    post_comment_to(
        env_config,
        GITHUB_API_ORIGIN,
        &token,
        &repo,
        pr_number,
        comment,
    )
    .await
}

/// The only origin production comments are posted to.
const GITHUB_API_ORIGIN: &str = "https://api.github.com";

/// [`post_pr_comment`] against `api_origin`, so tests can point it at a
/// loopback server. Production always passes [`GITHUB_API_ORIGIN`].
async fn post_comment_to(
    env_config: &EnvConfig,
    api_origin: &str,
    token: &str,
    repo: &str,
    pr_number: u64,
    comment: &str,
) -> crate::error::Result<()> {
    let url = format!("{api_origin}/repos/{repo}/issues/{pr_number}/comments");

    // Callers hand in a body that already went through the display sink.
    let body = serde_json::json!({ "body": comment });

    // Same-shape bounds as the admin client: connect + total request.
    // Keeps `gitforgeops review --pr N` from hanging forever if GitHub's
    // API is slow or unreachable.
    //
    // Redirects are refused outright: `reqwest` replays the `Authorization`
    // header on a same-host redirect, and a 3xx off `POST .../comments` is
    // never a legitimate GitHub response, so following one would only ever
    // hand the token somewhere it was not minted for.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(env_config.github_connect_timeout_secs))
        .timeout(Duration::from_secs(env_config.github_request_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    for attempt in 0..=MAX_COMMENT_RETRIES {
        let resp = client
            .post(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "gitforgeops")
            .bearer_auth(token)
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
        // Only a 2xx is delivery. With redirects disabled a 3xx arrives here
        // as an un-followed response with no comment created, so it must fail
        // loudly rather than read as success.
        if (200..=299).contains(&status) {
            return Ok(());
        }
        // Bounded read, and only GitHub's structured `message` is shown: a
        // raw error body can be large or reflect the bearer token.
        let resp_body = crate::http_client::read_error_body(resp).await;
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

#[cfg(test)]
mod comment_error_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Answer one comment POST with HTTP 403 and `body`, and return the
    /// rendered error `post_comment_to` produced.
    async fn comment_error_for(body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 8192];
            let _ = socket.read(&mut request).await;
            let head = format!(
                "HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            // The client stops at its cap; the peer closing early is fine.
            let _ = socket.write_all(&body).await;
        });
        let config = EnvConfig {
            github_connect_timeout_secs: 5,
            github_request_timeout_secs: 30,
            ..Default::default()
        };
        let error = post_comment_to(&config, &origin, "synthetic-token", "acme/repo", 7, "hi")
            .await
            .expect_err("a 403 is not delivery");
        server.abort();
        error.to_string()
    }

    #[tokio::test]
    async fn an_oversized_unstructured_failure_is_withheld() {
        let mut body = b"echo: Authorization: Bearer synthetic-token ".to_vec();
        body.resize(4 * 1024 * 1024, b'x');
        let rendered = comment_error_for(body).await;
        assert!(rendered.contains("403"), "{rendered}");
        assert!(!rendered.contains("synthetic-token"), "{rendered}");
        assert!(rendered.contains("withheld"), "{rendered}");
        assert!(rendered.len() < 1024, "{} bytes rendered", rendered.len());
    }

    #[tokio::test]
    async fn a_structured_failure_is_one_bounded_line() {
        let body = serde_json::json!({
            "message": format!("Resource not accessible\nforged: ok {}", "y".repeat(2000)),
        })
        .to_string();
        let rendered = comment_error_for(body.into_bytes()).await;
        assert!(
            rendered.contains("Resource not accessible forged: ok"),
            "{rendered}"
        );
        assert!(!rendered.contains('\n'), "{rendered}");
        assert!(rendered.contains("[truncated]"), "{rendered}");
    }
}
