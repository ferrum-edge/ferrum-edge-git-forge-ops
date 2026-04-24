use base64::Engine;
use crypto_box::aead::OsRng;
use crypto_box::PublicKey;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Clone, Deserialize)]
pub struct EnvSecretPublicKey {
    pub key_id: String,
    pub key: String,
}

/// Fetch the libsodium public key for an environment's secrets.
pub async fn fetch_public_key(
    client: &Client,
    repo: &str,
    environment: &str,
    token: &str,
) -> crate::error::Result<EnvSecretPublicKey> {
    let url = format!(
        "https://api.github.com/repos/{repo}/environments/{environment}/secrets/public-key"
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
    let encrypted = seal_secret(&pubkey.key, plaintext)?;

    let url = format!(
        "https://api.github.com/repos/{repo}/environments/{environment}/secrets/{secret_name}"
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
