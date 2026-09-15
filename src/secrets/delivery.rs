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

/// Age-encrypt bytes for a parsed SSH recipient.
///
/// Kept separate from GitHub key discovery so the supported Ed25519 and RSA
/// public-recipient paths can be exercised without network access. This
/// operation uses only public key material; gitforgeops never accepts an SSH
/// private key and never performs RSA signing or decryption.
pub fn encrypt_for_ssh_recipient(
    recipient: &Recipient,
    value: &[u8],
) -> crate::error::Result<String> {
    let recipients: [&dyn age::Recipient; 1] = [recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| crate::error::Error::Config(format!("age encryptor init: {e}")))?;

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

    String::from_utf8(out)
        .map_err(|e| crate::error::Error::HttpClient(format!("age output was not UTF-8: {e}")))
}

/// Fetch the PR author's SSH public keys from GitHub and age-encrypt `value`
/// to the first compatible key.
///
/// Returns `Ok(None)` only after all public-key pages were searched without a
/// usable recipient. Callers refuse credential publication when delivery is
/// required; incomplete discovery returns an error instead of "no usable keys".
pub async fn deliver_to_author(
    client: &Client,
    login: &str,
    value: &[u8],
) -> crate::error::Result<Option<DeliveryResult>> {
    let url = format!("https://api.github.com/users/{login}/keys");
    let Some((recipient, fingerprint)) = fetch_ssh_recipient(client, &url).await? else {
        return Ok(None);
    };
    let encoded = encrypt_for_ssh_recipient(&recipient, value)?;
    Ok(Some(DeliveryResult {
        login: login.to_string(),
        key_fingerprint: fingerprint,
        encrypted_b64: encoded,
    }))
}

/// Maximum key-discovery requests per delivery attempt.
pub const MAX_SSH_KEY_PAGES: usize = 20;

/// Discover the first age-compatible public recipient from a GitHub-style key
/// endpoint. Pagination stays on that endpoint and stops at a bounded page cap.
/// No credential plaintext is passed to key discovery.
pub async fn fetch_ssh_recipient(
    client: &Client,
    keys_url: &str,
) -> crate::error::Result<Option<(Recipient, String)>> {
    let mut first_url = reqwest::Url::parse(keys_url)
        .map_err(|e| crate::error::Error::Config(format!("SSH keys endpoint: {e}")))?;
    first_url.query_pairs_mut().append_pair("per_page", "100");
    let mut url = first_url.clone();
    for page in 0..MAX_SSH_KEY_PAGES {
        let resp = client
            .get(url.clone())
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
        let next = resp
            .headers()
            .get(reqwest::header::LINK)
            .map(|header| {
                header.to_str().map_err(|_| {
                    crate::error::Error::HttpClient("invalid SSH key pagination header".into())
                })
            })
            .transpose()?
            .and_then(crate::policy::github_override::parse_next_link);
        let keys: Vec<SshKey> = resp
            .json()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        for ssh_key in keys {
            let trimmed = ssh_key.key.trim();
            let recipient = match trimmed.parse::<Recipient>() {
                Ok(recipient) => recipient,
                Err(_) => continue,
            };
            let fingerprint = fingerprint_for(trimmed).unwrap_or_else(|| "unknown".to_string());
            return Ok(Some((recipient, fingerprint)));
        }
        let Some(next) = next else {
            return Ok(None);
        };
        if page + 1 == MAX_SSH_KEY_PAGES {
            return Err(crate::error::Error::Config(
                "SSH key discovery exceeds pagination safety cap; recipient search is incomplete"
                    .into(),
            ));
        }
        url = reqwest::Url::parse(&next).map_err(|_| {
            crate::error::Error::HttpClient("invalid SSH key pagination URL".into())
        })?;
        if url.origin() != first_url.origin()
            || url.path() != first_url.path()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(crate::error::Error::HttpClient(
                "SSH key pagination must stay on the original key endpoint".into(),
            ));
        }
    }
    Err(crate::error::Error::Config(
        "SSH key discovery did not complete".into(),
    ))
}

fn fingerprint_for(openssh: &str) -> Option<String> {
    let parsed = ssh_key::PublicKey::from_openssh(openssh).ok()?;
    Some(parsed.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}
