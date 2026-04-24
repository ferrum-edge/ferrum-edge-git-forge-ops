use std::io::Write;

use age::ssh::Recipient;
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub login: String,
    pub key_fingerprint: String,
    pub encrypted_b64: String,
}

#[derive(Debug, Deserialize)]
struct SshKey {
    key: String,
}

/// Fetch the PR author's SSH public keys from GitHub and age-encrypt `value`
/// to the first compatible key.
///
/// Returns `Ok(None)` when the user has no usable keys on file (the caller
/// surfaces this as a warning and can fall back to masked workflow output).
pub async fn deliver_to_author(
    client: &Client,
    login: &str,
    value: &[u8],
) -> crate::error::Result<Option<DeliveryResult>> {
    let url = format!("https://api.github.com/users/{login}/keys");
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "gitforgeops/0.1")
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

    let keys: Vec<SshKey> = resp
        .json()
        .await
        .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

    for ssh_key in keys {
        let trimmed = ssh_key.key.trim();
        let recipient = match trimmed.parse::<Recipient>() {
            Ok(r) => r,
            Err(_) => continue,
        };

        let fingerprint = fingerprint_for(trimmed).unwrap_or_else(|| "unknown".to_string());

        let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
            .ok_or_else(|| crate::error::Error::Config("age encryptor init".to_string()))?;

        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(
                age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
                    .map_err(|e| crate::error::Error::HttpClient(format!("age armor: {e}")))?,
            )
            .map_err(|e| crate::error::Error::HttpClient(format!("age wrap: {e}")))?;
        writer
            .write_all(value)
            .map_err(|e| crate::error::Error::HttpClient(format!("age write: {e}")))?;
        let armored = writer
            .finish()
            .map_err(|e| crate::error::Error::HttpClient(format!("age finish: {e}")))?;
        armored
            .finish()
            .map_err(|e| crate::error::Error::HttpClient(format!("age armor finish: {e}")))?;

        let encoded = String::from_utf8(out).unwrap_or_default();
        return Ok(Some(DeliveryResult {
            login: login.to_string(),
            key_fingerprint: fingerprint,
            encrypted_b64: encoded,
        }));
    }

    Ok(None)
}

fn fingerprint_for(openssh: &str) -> Option<String> {
    let parsed = ssh_key::PublicKey::from_openssh(openssh).ok()?;
    Some(parsed.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}
