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

/// Fetch the libsodium public key for an environment's secrets.
pub async fn fetch_public_key(
    client: &Client,
    repo: &str,
    environment: &str,
    token: &str,
) -> crate::error::Result<EnvSecretPublicKey> {
    fetch_public_key_at(client, DEFAULT_GITHUB_API_BASE, repo, environment, token).await
}

/// [`fetch_public_key`] against an explicit API origin.
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
    if status >= 400 {
        let body = resp.text().await.unwrap_or_default();
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

/// Create or overwrite an environment secret on GitHub.
pub async fn put_environment_secret(
    client: &Client,
    repo: &str,
    environment: &str,
    secret_name: &str,
    plaintext: &[u8],
    pubkey: &EnvSecretPublicKey,
    token: &str,
) -> crate::error::Result<()> {
    put_environment_secret_at(
        client,
        DEFAULT_GITHUB_API_BASE,
        repo,
        environment,
        secret_name,
        plaintext,
        pubkey,
        token,
    )
    .await
}

/// [`put_environment_secret`] against an explicit API origin.
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
    if status >= 400 {
        let body = resp.text().await.unwrap_or_default();
        return Err(crate::error::Error::ApiError {
            status,
            message: body,
        });
    }
    Ok(())
}
