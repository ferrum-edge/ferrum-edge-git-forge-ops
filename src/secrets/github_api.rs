use base64::Engine;
use crypto_box::aead::OsRng;
use crypto_box::PublicKey;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

/// Production GitHub REST origin. Compiled in so Environment-secret writes
/// cannot be redirected by process environment. Tests pass a loopback stub
/// origin to [`fetch_public_key_at`] / [`put_environment_secret_at`].
pub const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";

/// The client for bearer-token calls to [`DEFAULT_GITHUB_API_BASE`]: PR
/// lookup, override checks, Environment-secret provisioning and SSH-key
/// discovery all use it.
///
/// - `FERRUM_GITHUB_CONNECT_TIMEOUT_SECS` / `FERRUM_GITHUB_REQUEST_TIMEOUT_SECS`
///   bound every call, so a stalled GitHub endpoint cannot hang an apply or a
///   review. The admin-gateway client has its own pair (`http_client.rs`).
/// - Redirects are never followed: a same-host 3xx keeps the `Authorization`
///   header, and no endpoint used here legitimately redirects.
/// - HTTPS only, so a downgraded `http://` URL never carries the token.
///
/// What a call sends (token or not, headers, retries) stays at its call site.
pub fn github_api_client(env_config: &crate::config::EnvConfig) -> crate::error::Result<Client> {
    github_api_client_builder(env_config)
        .https_only(true)
        .build()
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))
}

/// User-Agent every GitHub API request carries.
pub(crate) const GITHUB_API_USER_AGENT: &str = "gitforgeops/0.1";

/// [`github_api_client`] before its scheme guard, so the inline tests can
/// check the rest of the policy against a loopback `http://` stub.
fn github_api_client_builder(env_config: &crate::config::EnvConfig) -> reqwest::ClientBuilder {
    use std::time::Duration;
    Client::builder()
        .user_agent(GITHUB_API_USER_AGENT)
        .connect_timeout(Duration::from_secs(env_config.github_connect_timeout_secs))
        .timeout(Duration::from_secs(env_config.github_request_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvSecretPublicKey {
    pub key_id: String,
    pub key: String,
}

fn github_api_url(api_base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        api_base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn require_provisioner_token(token: &str) -> crate::error::Result<()> {
    if token.trim().is_empty() {
        return Err(crate::error::Error::Config(
            "FERRUM_GH_PROVISIONER_TOKEN not set; cannot allocate credential slots".into(),
        ));
    }
    Ok(())
}

/// Fetch the libsodium public key for an environment's secrets from the
/// GitHub API at `api_base`.
///
/// Production callers pass [`DEFAULT_GITHUB_API_BASE`]. Tests inject an
/// in-process loopback origin; TLS and bearer-token handling are unchanged.
pub async fn fetch_public_key_at(
    client: &Client,
    api_base: &str,
    repo: &str,
    environment: &str,
    token: &str,
) -> crate::error::Result<EnvSecretPublicKey> {
    require_provisioner_token(token)?;
    let url = github_api_url(
        api_base,
        &format!("repos/{repo}/environments/{environment}/secrets/public-key"),
    );
    let resp = client
        .get(&url)
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

    resp.json::<EnvSecretPublicKey>()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))
}

/// Encrypt `plaintext` with the given libsodium sealed-box public key.
/// Returns base64-encoded ciphertext, the format GitHub's PUT endpoint expects.
pub fn seal_secret(pubkey_b64: &str, plaintext: &[u8]) -> crate::error::Result<String> {
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(pubkey_b64)
        .map_err(|e| crate::error::Error::Config(format!("decode pubkey: {e}")))?;

    if pk_bytes.len() != 32 {
        return Err(crate::error::Error::Config(format!(
            "expected 32-byte curve25519 pubkey, got {} bytes",
            pk_bytes.len()
        )));
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let pk = PublicKey::from(pk_arr);

    let sealed = pk
        .seal(&mut OsRng, plaintext)
        .map_err(|e| crate::error::Error::HttpClient(format!("seal: {e}")))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(sealed))
}

/// Create or overwrite an environment secret through the GitHub API at
/// `api_base`.
///
/// Production callers pass [`DEFAULT_GITHUB_API_BASE`]. Tests inject an
/// in-process loopback origin; TLS and bearer-token handling are unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn put_environment_secret_at(
    client: &Client,
    api_base: &str,
    repo: &str,
    environment: &str,
    secret_name: &str,
    plaintext: &[u8],
    pubkey: &EnvSecretPublicKey,
    token: &str,
) -> crate::error::Result<()> {
    require_provisioner_token(token)?;
    let encrypted = seal_secret(&pubkey.key, plaintext)?;

    let url = github_api_url(
        api_base,
        &format!("repos/{repo}/environments/{environment}/secrets/{secret_name}"),
    );
    let body = json!({
        "encrypted_value": encrypted,
        "key_id": pubkey.key_id,
    });

    let resp = client
        .put(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&body)
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
    Ok(())
}

#[cfg(test)]
mod client_policy_tests {
    use super::*;
    use crate::config::EnvConfig;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;

    fn env_config() -> EnvConfig {
        EnvConfig {
            github_connect_timeout_secs: 5,
            github_request_timeout_secs: 30,
            ..Default::default()
        }
    }

    /// Everything but the scheme guard, against a loopback stub: a 3xx is
    /// handed back un-followed (the redirect target never sees a request,
    /// let alone the token) and the shared User-Agent is sent.
    #[tokio::test]
    async fn the_shared_policy_never_follows_a_redirect_and_names_itself() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let location = format!("http://{}/stolen", target.local_addr().unwrap());

        let stub = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", stub.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = stub.accept().unwrap();
            let mut request = [0_u8; 8192];
            let read = socket.read(&mut request).unwrap();
            let head = format!(
                "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            socket.write_all(head.as_bytes()).unwrap();
            String::from_utf8_lossy(&request[..read]).to_ascii_lowercase()
        });

        let client = github_api_client_builder(&env_config()).build().unwrap();
        let response = client
            .get(format!("{origin}/repos/acme/repo"))
            .bearer_auth("synthetic-token")
            .send()
            .await
            .unwrap();
        let request = server.join().unwrap();

        assert_eq!(response.status().as_u16(), 302);
        assert!(
            matches!(target.accept(), Err(ref e) if e.kind() == ErrorKind::WouldBlock),
            "the redirect target must never be contacted"
        );
        assert!(
            request.contains(&format!(
                "user-agent: {}\r\n",
                GITHUB_API_USER_AGENT.to_ascii_lowercase()
            )),
            "{request}"
        );
    }
}
