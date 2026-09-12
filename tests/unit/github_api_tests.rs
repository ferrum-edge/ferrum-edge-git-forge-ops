use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use gitforgeops::error::Error;
use gitforgeops::secrets::{
    allocate_and_deliver_at, fetch_public_key_at, parse_placeholder, put_environment_secret_at,
    rotate_and_deliver_at, slot_path, EnvSecretPublicKey, ResolveReport, ResolveResult,
    SlotStatus, DEFAULT_GITHUB_API_BASE,
};

const REPO: &str = "test/fixture";
const ENVIRONMENT: &str = "staging";
const TOKEN: &str = "synthetic-provisioner-token";
const SECRET_NAME: &str = "FERRUM_CREDS_BUNDLE";
const PLAINTEXT: &str = "synthetic-bundle-plaintext-not-a-github-secret";
const KEY_ID: &str = "fixture-key-id";
/// 32-byte X25519 public-key fixture. Not a GitHub production key.
const FIXTURE_PUBKEY_BYTES: [u8; 32] = [0x01; 32];

fn fixture_pubkey_b64() -> String {
    base64::engine::general_purpose::STANDARD.encode(FIXTURE_PUBKEY_BYTES)
}

fn fixture_pubkey() -> EnvSecretPublicKey {
    EnvSecretPublicKey {
        key_id: KEY_ID.into(),
        key: fixture_pubkey_b64(),
    }
}

fn public_key_body() -> String {
    serde_json::json!({
        "key_id": KEY_ID,
        "key": fixture_pubkey_b64(),
    })
    .to_string()
}

fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("gitforgeops/0.1")
        .timeout(Duration::from_secs(5))
        .build()
        .expect("test client")
}

fn public_key_path() -> String {
    format!("GET /repos/{REPO}/environments/{ENVIRONMENT}/secrets/public-key")
}

fn put_secret_path() -> String {
    format!("PUT /repos/{REPO}/environments/{ENVIRONMENT}/secrets/{SECRET_NAME}")
}

fn spawn_github_stub(routes: Vec<(String, u16, String)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = routes.clone();
            let requests = Arc::clone(&thread_requests);
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                requests.lock().expect("record request").push(request.clone());
                let (status, body) = routes
                    .iter()
                    .find(|(needle, _, _)| request.contains(needle))
                    .map(|(_, status, body)| (*status, body.as_str()))
                    .unwrap_or((404, "{\"message\":\"Not Found\"}"));
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .is_err()
                {
                    return;
                }
            });
        }
    });
    (format!("http://{addr}"), requests)
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        let mut buf = [0_u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        raw.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&raw).to_string();
        let Some(header_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let content_length = text
            .to_ascii_lowercase()
            .split("\r\n")
            .find_map(|line| {
                line.strip_prefix("content-length:")
                    .map(str::trim)
                    .map(String::from)
            })
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if raw.len() >= header_end + 4 + content_length {
            return Some(text);
        }
    }
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn assert_github_headers(request: &str) {
    assert_eq!(
        header_value(request, "Authorization"),
        Some(format!("Bearer {TOKEN}")),
        "provisioner token must be sent as a bearer credential"
    );
    assert_eq!(
        header_value(request, "Accept").as_deref(),
        Some("application/vnd.github+json")
    );
    assert_eq!(
        header_value(request, "X-GitHub-Api-Version").as_deref(),
        Some("2022-11-28")
    );
}

fn put_json(request: &str) -> serde_json::Value {
    let header_end = request.find("\r\n\r\n").expect("http header terminator");
    serde_json::from_str(&request[header_end + 4..]).expect("put json")
}

fn assert_api_error(err: &Error, expected_status: u16, needle: &str) {
    match err {
        Error::ApiError { status, message } => {
            assert_eq!(*status, expected_status);
            assert!(
                message.contains(needle),
                "status {expected_status} body should contain {needle:?}: {message}"
            );
        }
        other => panic!("expected ApiError({expected_status}), got {other}"),
    }
}

fn error_routes(status: u16, body: &str) -> Vec<(String, u16, String)> {
    vec![(public_key_path(), status, body.to_string())]
}

fn success_routes(put_status: u16) -> Vec<(String, u16, String)> {
    vec![
        (public_key_path(), 200, public_key_body()),
        (put_secret_path(), put_status, String::new()),
    ]
}

fn allocation_report() -> ResolveReport {
    let mut report = ResolveReport::default();
    report.results.push(ResolveResult {
        consumer_id: "app".into(),
        namespace: "ferrum".into(),
        cred_key: "keyauth/key".into(),
        slot: slot_path("ferrum", "app", "keyauth/key"),
        placeholder: parse_placeholder("${gh-env-secret:alloc=generate}")
            .unwrap()
            .unwrap(),
        status: SlotStatus::NeedsAllocation,
    });
    report
}

#[test]
fn production_github_api_base_is_compiled_in_https() {
    assert_eq!(DEFAULT_GITHUB_API_BASE, "https://api.github.com");
    assert!(DEFAULT_GITHUB_API_BASE.starts_with("https://"));
}

#[tokio::test]
async fn fetch_public_key_decodes_the_environment_key() {
    let (api_base, requests) = spawn_github_stub(vec![(public_key_path(), 200, public_key_body())]);
    let key = fetch_public_key_at(&test_client(), &api_base, REPO, ENVIRONMENT, TOKEN)
        .await
        .expect("fixture public key");
    assert_eq!(key.key_id, KEY_ID);
    assert_eq!(key.key, fixture_pubkey_b64());
    let recorded = requests.lock().expect("recorded");
    assert_eq!(recorded.len(), 1);
    assert!(recorded[0].starts_with(&public_key_path()));
    assert_github_headers(&recorded[0]);
}

#[tokio::test]
async fn fetch_public_key_accepts_a_trailing_slash_on_the_api_base() {
    let (api_base, requests) = spawn_github_stub(vec![(public_key_path(), 200, public_key_body())]);
    let key = fetch_public_key_at(&test_client(), &format!("{api_base}/"), REPO, ENVIRONMENT, TOKEN)
        .await
        .expect("trailing-slash origin");
    assert_eq!(key.key_id, KEY_ID);
    assert_eq!(requests.lock().expect("recorded").len(), 1);
}

#[tokio::test]
async fn fetch_public_key_maps_github_error_statuses() {
    for (status, body, needle) in [
        (401, "{\"message\":\"Bad credentials\"}", "Bad credentials"),
        (403, "{\"message\":\"Must have admin rights\"}", "admin rights"),
        (404, "{\"message\":\"Not Found\"}", "Not Found"),
        (
            422,
            "{\"message\":\"Validation Failed\"}",
            "Validation Failed",
        ),
        (500, "{\"message\":\"Internal Server Error\"}", "Internal"),
        (503, "{\"message\":\"Service Unavailable\"}", "Unavailable"),
    ] {
        let (api_base, requests) = spawn_github_stub(error_routes(status, body));
        let err = fetch_public_key_at(&test_client(), &api_base, REPO, ENVIRONMENT, TOKEN)
            .await
            .expect_err("github error status");
        assert_api_error(&err, status, needle);
        let recorded = requests.lock().expect("recorded");
        assert_eq!(recorded.len(), 1);
        assert_github_headers(&recorded[0]);
    }
}

#[tokio::test]
async fn fetch_public_key_rejects_malformed_json() {
    let (api_base, _) = spawn_github_stub(vec![(public_key_path(), 200, "not-json".to_string())]);
    let err = fetch_public_key_at(&test_client(), &api_base, REPO, ENVIRONMENT, TOKEN)
        .await
        .expect_err("malformed json");
    match err {
        Error::HttpClient(_) => {}
        other => panic!("malformed JSON must be HttpClient, got {other}"),
    }
}

#[tokio::test]
async fn fetch_public_key_rejects_a_payload_missing_the_key_field() {
    let (api_base, _) = spawn_github_stub(vec![(
        public_key_path(),
        200,
        "{\"key_id\":\"fixture-key-id\"}".to_string(),
    )]);
    let err = fetch_public_key_at(&test_client(), &api_base, REPO, ENVIRONMENT, TOKEN)
        .await
        .expect_err("missing key");
    match err {
        Error::HttpClient(_) => {}
        other => panic!("missing key field must be HttpClient, got {other}"),
    }
}

#[tokio::test]
async fn put_environment_secret_sends_a_sealed_box_and_key_id() {
    for status in [201_u16, 204] {
        let (api_base, requests) = spawn_github_stub(vec![(put_secret_path(), status, String::new())]);
        put_environment_secret_at(
            &test_client(),
            &api_base,
            REPO,
            ENVIRONMENT,
            SECRET_NAME,
            PLAINTEXT.as_bytes(),
            &fixture_pubkey(),
            TOKEN,
        )
        .await
        .unwrap_or_else(|err| panic!("PUT {status} must succeed: {err}"));
        let recorded = requests.lock().expect("recorded");
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].starts_with(&put_secret_path()));
        assert_github_headers(&recorded[0]);
        assert!(
            !recorded[0].contains(PLAINTEXT),
            "sealed PUT must not contain the fixture plaintext"
        );
        let content_type = header_value(&recorded[0], "Content-Type").unwrap_or_default();
        assert!(
            content_type.contains("application/json"),
            "PUT must send JSON: {content_type}"
        );
        let body = put_json(&recorded[0]);
        let encrypted = body["encrypted_value"]
            .as_str()
            .expect("encrypted_value string");
        assert!(!encrypted.is_empty());
        base64::engine::general_purpose::STANDARD
            .decode(encrypted)
            .expect("encrypted_value is standard base64");
        assert_eq!(body["key_id"].as_str(), Some(KEY_ID));
    }
}

#[tokio::test]
async fn put_environment_secret_maps_github_error_statuses() {
    for (status, body, needle) in [
        (401, "{\"message\":\"Bad credentials\"}", "Bad credentials"),
        (403, "{\"message\":\"Must have admin rights\"}", "admin rights"),
        (404, "{\"message\":\"Not Found\"}", "Not Found"),
        (
            422,
            "{\"message\":\"Validation Failed\"}",
            "Validation Failed",
        ),
        (500, "{\"message\":\"Internal Server Error\"}", "Internal"),
    ] {
        let (api_base, requests) = spawn_github_stub(vec![(put_secret_path(), status, body.to_string())]);
        let err = put_environment_secret_at(
            &test_client(),
            &api_base,
            REPO,
            ENVIRONMENT,
            SECRET_NAME,
            PLAINTEXT.as_bytes(),
            &fixture_pubkey(),
            TOKEN,
        )
        .await
        .expect_err("github put error");
        assert_api_error(&err, status, needle);
        assert_eq!(requests.lock().expect("recorded").len(), 1);
        assert!(
            !requests.lock().expect("recorded")[0].contains(PLAINTEXT),
            "error-path PUT must still send ciphertext, not plaintext"
        );
    }
}

#[test]
fn seal_secret_rejects_invalid_base64_and_wrong_length_keys() {
    let invalid = gitforgeops::secrets::github_api::seal_secret(
        "!!!not-base64!!!",
        PLAINTEXT.as_bytes(),
    )
    .expect_err("invalid base64");
    assert!(invalid.to_string().contains("decode pubkey"), "{invalid}");

    let short = base64::engine::general_purpose::STANDARD.encode([0x01_u8, 0x02, 0x03]);
    let wrong_len = gitforgeops::secrets::github_api::seal_secret(&short, PLAINTEXT.as_bytes())
        .expect_err("wrong length");
    assert!(wrong_len.to_string().contains("32-byte"), "{wrong_len}");

    let sealed = gitforgeops::secrets::github_api::seal_secret(
        &fixture_pubkey_b64(),
        PLAINTEXT.as_bytes(),
    )
    .expect("fixture key seals");
    assert_ne!(sealed, PLAINTEXT);
    assert!(!sealed.contains(PLAINTEXT));
    base64::engine::general_purpose::STANDARD
        .decode(&sealed)
        .expect("sealed output is standard base64");
}

#[tokio::test]
async fn put_environment_secret_does_not_contact_the_stub_when_the_key_is_invalid() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_base = format!("http://{}", listener.local_addr().unwrap());
    let bad = EnvSecretPublicKey {
        key_id: KEY_ID.into(),
        key: "!!!not-base64!!!".into(),
    };
    let err = put_environment_secret_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        SECRET_NAME,
        PLAINTEXT.as_bytes(),
        &bad,
        TOKEN,
    )
    .await
    .expect_err("invalid key");
    assert!(err.to_string().contains("decode pubkey"), "{err}");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "invalid public key must fail before any GitHub write"
    );
}

#[tokio::test]
async fn missing_provisioner_token_fails_closed_without_network_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_base = format!("http://{}", listener.local_addr().unwrap());
    for token in ["", "   "] {
        let fetch_err = fetch_public_key_at(&test_client(), &api_base, REPO, ENVIRONMENT, token)
            .await
            .expect_err("empty token fetch");
        assert!(
            fetch_err
                .to_string()
                .contains("FERRUM_GH_PROVISIONER_TOKEN not set"),
            "{fetch_err}"
        );
        let put_err = put_environment_secret_at(
            &test_client(),
            &api_base,
            REPO,
            ENVIRONMENT,
            SECRET_NAME,
            PLAINTEXT.as_bytes(),
            &fixture_pubkey(),
            token,
        )
        .await
        .expect_err("empty token put");
        assert!(
            put_err
                .to_string()
                .contains("FERRUM_GH_PROVISIONER_TOKEN not set"),
            "{put_err}"
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a missing provisioner token must not reach GitHub"
    );
}

#[tokio::test]
async fn allocate_and_deliver_puts_the_sealed_bundle_for_a_new_slot() {
    let (api_base, requests) = spawn_github_stub(success_routes(204));
    let report = allocation_report();
    let mut shards = BTreeMap::new();
    let mut shard_count = 1;
    let outcome = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &report,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("allocate against stub");
    assert_eq!(outcome.allocated.len(), 1);
    assert_eq!(
        outcome.allocated[0].slot,
        slot_path("ferrum", "app", "keyauth/key")
    );
    let generated = outcome.allocated[0].value.clone();
    assert!(shards[&0].contains_key(&outcome.allocated[0].slot));
    let recorded = requests.lock().expect("recorded");
    assert_eq!(recorded.len(), 2);
    assert!(recorded[0].starts_with(&public_key_path()));
    assert!(recorded[1].starts_with(&put_secret_path()));
    assert_github_headers(&recorded[0]);
    assert_github_headers(&recorded[1]);
    assert!(
        !recorded[1].contains(&generated),
        "allocator PUT must not contain the generated credential"
    );
    let body = put_json(&recorded[1]);
    assert_eq!(body["key_id"].as_str(), Some(KEY_ID));
    let encrypted = body["encrypted_value"]
        .as_str()
        .expect("encrypted_value string");
    base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .expect("allocator encrypted_value is standard base64");
}

#[tokio::test]
async fn allocate_and_deliver_maps_a_forbidden_public_key_fetch() {
    let (api_base, _) = spawn_github_stub(error_routes(
        403,
        "{\"message\":\"Must have admin rights\"}",
    ));
    let report = allocation_report();
    let mut shards = BTreeMap::new();
    let mut shard_count = 1;
    let failure = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &report,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect_err("forbidden fetch");
    assert_api_error(&failure.source, 403, "admin rights");
    assert!(failure.partial.allocated.is_empty());
    assert!(shards.is_empty());
}

#[tokio::test]
async fn rotate_and_deliver_puts_the_rotated_slot() {
    let (api_base, requests) = spawn_github_stub(success_routes(204));
    let slot = slot_path("ferrum", "app", "keyauth/key");
    let mut shards = BTreeMap::new();
    let mut shard_count = 1;
    let allocated = rotate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &slot,
        32,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("rotate against stub");
    assert_eq!(allocated.slot, slot);
    let generated = allocated.value.clone();
    assert!(shards[&0].contains_key(&slot));
    let recorded = requests.lock().expect("recorded");
    assert_eq!(recorded.len(), 2);
    assert!(recorded[0].starts_with(&public_key_path()));
    assert!(recorded[1].starts_with(&put_secret_path()));
    assert!(
        !recorded[1].contains(&generated),
        "rotation PUT must not contain the generated credential"
    );
}

#[tokio::test]
async fn rotate_and_deliver_maps_a_put_validation_error() {
    let (api_base, _) = spawn_github_stub(vec![
        (public_key_path(), 200, public_key_body()),
        (
            put_secret_path(),
            422,
            "{\"message\":\"Validation Failed\"}".to_string(),
        ),
    ]);
    let slot = slot_path("ferrum", "app", "keyauth/key");
    let original = BTreeMap::from([(
        0,
        BTreeMap::from([(slot.clone(), "existing-sensitive-value".to_string())]),
    )]);
    let mut shards = original.clone();
    let mut shard_count = 1;
    let failure = rotate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &slot,
        32,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect_err("put 422");
    assert_api_error(&failure.source, 422, "Validation Failed");
    assert!(failure.partial.allocated.is_empty());
    assert_eq!(shards, original);
    assert!(!failure.to_string().contains("existing-sensitive-value"));
}
