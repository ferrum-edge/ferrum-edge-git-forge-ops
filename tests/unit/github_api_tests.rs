use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use gitforgeops::error::Error;
use gitforgeops::secrets::{
    allocate_and_deliver_at, fetch_public_key_at, load_bundles_from_env, merge_bundles,
    parse_placeholder, put_environment_secret_at, rotate_and_deliver_at, slot_path,
    write_bundle_handoff, EnvSecretPublicKey, ResolveReport, ResolveResult, SlotStatus,
    DEFAULT_GITHUB_API_BASE,
};
use gitforgeops::verify::runner::run_check;
use gitforgeops::verify::{
    authorize_probe_slots, EnvironmentChecks, HeaderValue, Outcome, ProbeConsumerAllowlist,
    SmokeCheck, VERIFY_PROBE_LABEL,
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
    let routes = routes
        .into_iter()
        .map(|(needle, status, body)| (needle, status, body, String::new()))
        .collect();
    spawn_github_stub_with_headers(routes)
}

/// [`spawn_github_stub`] whose routes also carry extra response header lines.
/// `{base}` in a header is replaced with the stub's own origin, so a `Link`
/// header can point back at the stub.
fn spawn_github_stub_with_headers(
    routes: Vec<(String, u16, String, String)>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("stub addr");
    let base = format!("http://{addr}");
    let routes: Vec<(String, u16, String, String)> = routes
        .into_iter()
        .map(|(needle, status, body, headers)| {
            (needle, status, body, headers.replace("{base}", &base))
        })
        .collect();
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
                requests
                    .lock()
                    .expect("record request")
                    .push(request.clone());
                let (status, body, headers) = routes
                    .iter()
                    .find(|(needle, _, _, _)| request.contains(needle))
                    .map(|(_, status, body, headers)| (*status, body.as_str(), headers.as_str()))
                    .unwrap_or((404, "{\"message\":\"Not Found\"}", ""));
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{headers}\r\n{}",
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
    (base, requests)
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
    let key = fetch_public_key_at(
        &test_client(),
        &format!("{api_base}/"),
        REPO,
        ENVIRONMENT,
        TOKEN,
    )
    .await
    .expect("trailing-slash origin");
    assert_eq!(key.key_id, KEY_ID);
    assert_eq!(requests.lock().expect("recorded").len(), 1);
}

#[tokio::test]
async fn fetch_public_key_maps_github_error_statuses() {
    for (status, body, needle) in [
        (401, "{\"message\":\"Bad credentials\"}", "Bad credentials"),
        (
            403,
            "{\"message\":\"Must have admin rights\"}",
            "admin rights",
        ),
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
        let (api_base, requests) =
            spawn_github_stub(vec![(put_secret_path(), status, String::new())]);
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
        (
            403,
            "{\"message\":\"Must have admin rights\"}",
            "admin rights",
        ),
        (404, "{\"message\":\"Not Found\"}", "Not Found"),
        (
            422,
            "{\"message\":\"Validation Failed\"}",
            "Validation Failed",
        ),
        (500, "{\"message\":\"Internal Server Error\"}", "Internal"),
    ] {
        let (api_base, requests) =
            spawn_github_stub(vec![(put_secret_path(), status, body.to_string())]);
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

/// With redirects disabled on the production client, a 3xx arrives as an
/// un-followed response: nothing was written, so it must never read as a
/// committed secret. GitHub answers a successful put with 201/204 only.
#[tokio::test]
async fn put_environment_secret_rejects_redirect_statuses() {
    for status in [301, 302, 307, 308] {
        let (api_base, requests) =
            spawn_github_stub(vec![(put_secret_path(), status, String::new())]);
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
        .expect_err("a redirect is not a committed secret write");
        assert_api_error(&err, status, "");
        assert_eq!(requests.lock().expect("recorded").len(), 1);
    }
}

#[test]
fn seal_secret_rejects_invalid_base64_and_wrong_length_keys() {
    let invalid =
        gitforgeops::secrets::github_api::seal_secret("!!!not-base64!!!", PLAINTEXT.as_bytes())
            .expect_err("invalid base64");
    assert!(invalid.to_string().contains("decode pubkey"), "{invalid}");

    let short = base64::engine::general_purpose::STANDARD.encode([0x01_u8, 0x02, 0x03]);
    let wrong_len = gitforgeops::secrets::github_api::seal_secret(&short, PLAINTEXT.as_bytes())
        .expect_err("wrong length");
    assert!(wrong_len.to_string().contains("32-byte"), "{wrong_len}");

    let sealed =
        gitforgeops::secrets::github_api::seal_secret(&fixture_pubkey_b64(), PLAINTEXT.as_bytes())
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

/// A lenient report can carry an `alloc=generate` endpoint slot straight to
/// the allocator. The batch validation must refuse it before any GitHub
/// request, with the same verdict the strict resolver gives at plan time.
#[tokio::test]
async fn allocate_and_deliver_refuses_to_generate_a_plugin_endpoint_before_github() {
    let (api_base, requests) = spawn_github_stub(success_routes(204));
    let cfg: gitforgeops::config::schema::GatewayConfig =
        serde_json::from_value(serde_json::json!({
            "version": "1",
            "plugin_configs": [{
                "id": "ldap",
                "namespace": "ferrum",
                "plugin_name": "ldap_auth",
                "scope": "global",
                "config": {"ldap_url": "${gh-env-secret:alloc=generate}"}
            }]
        }))
        .unwrap();
    let report = gitforgeops::secrets::report_secrets_lenient(&cfg, &BTreeMap::new())
        .expect("the lenient walk reports instead of refusing");
    assert_eq!(report.needs_allocation().len(), 1);
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
    .expect_err("an endpoint URL cannot be generated");
    assert!(
        failure.source.to_string().contains("endpoint"),
        "{}",
        failure.source
    );
    assert!(failure.partial.allocated.is_empty());
    assert!(shards.is_empty());
    assert!(
        requests.lock().expect("recorded").is_empty(),
        "a refused batch must not reach GitHub"
    );
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

/// A stand-in data plane: `200` only for the credential it was told to expect,
/// `401` otherwise. Records the `X-API-Key` each request carried.
fn spawn_data_plane(expected: String) -> (String, Arc<Mutex<Vec<Option<String>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind data plane");
    let addr = listener.local_addr().expect("data plane addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let thread_seen = Arc::clone(&seen);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let Some(request) = read_request(&mut stream) else {
                continue;
            };
            let key = header_value(&request, "x-api-key");
            let status = if key.as_deref() == Some(expected.as_str()) {
                200
            } else {
                401
            };
            thread_seen.lock().expect("record request").push(key);
            let _ = write!(
                stream,
                "HTTP/1.1 {status} STUB\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
        }
    });
    (format!("http://{addr}"), seen)
}

/// #351: a slot the apply generates lives only in memory and in the GitHub
/// Environment Secret; the input bundle file is never updated, so a separate
/// verify that rereads it reports the slot missing. The handoff carries it:
/// the traffic check sends the newly generated value and passes, every
/// pre-existing slot on every shard survives, and a slot that is genuinely
/// missing still fails before any request is sent.
#[tokio::test]
async fn a_same_job_first_allocation_reaches_the_traffic_check_through_the_handoff() {
    let (api_base, _requests) = spawn_github_stub(success_routes(204));
    let seeded_a = slot_path("ferrum", "seeded-a", "keyauth/key");
    let seeded_b = slot_path("ferrum", "seeded-b", "keyauth/key");
    let pre_apply = BTreeMap::from([
        (
            0,
            BTreeMap::from([(seeded_a.clone(), "seeded-value-a".to_string())]),
        ),
        (
            1,
            BTreeMap::from([(seeded_b.clone(), "seeded-value-b".to_string())]),
        ),
    ]);
    let mut shards = pre_apply.clone();
    let mut shard_count = 2;
    let outcome = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &allocation_report(),
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("allocate against stub");
    let slot = outcome.allocated[0].slot.clone();
    let generated = outcome.allocated[0].value.clone();

    let directory = tempfile::tempdir().expect("tempdir");
    let handoff = directory.path().join("ferrum-creds-applied.json");
    write_bundle_handoff(&handoff, &shards).expect("write handoff");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&handoff)
            .expect("handoff metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "handoff must be owner-only");
    }
    let raw = std::fs::read_to_string(&handoff).expect("read handoff");
    let (finalized, per_shard) = load_bundles_from_env(&raw).expect("handoff is a bundle");
    assert!(per_shard == shards, "every shard is handed on unchanged");
    assert!(finalized[&seeded_a] == "seeded-value-a");
    assert!(finalized[&seeded_b] == "seeded-value-b");
    assert!(finalized.get(&slot) == Some(&generated));

    let header = HeaderValue::slot(slot.clone());
    let check = SmokeCheck {
        name: "orders route serves authenticated traffic".to_string(),
        method: "GET".to_string(),
        path: "/orders/healthz".to_string(),
        headers: BTreeMap::from([("X-API-Key".to_string(), header)]),
        expect_status: 200,
        timeout_secs: 5,
        attempts: 1,
        retry_backoff_ms: 0,
        replay_safe: false,
    };
    // `verify` authorizes the slot (an allowlisted, labelled probe Consumer)
    // before reading a bundle, and the runner sees only that projection.
    let desired: gitforgeops::config::schema::GatewayConfig =
        serde_json::from_value(serde_json::json!({
            "consumers": [{
                "id": "app",
                "username": "app",
                "namespace": "ferrum",
                "labels": { VERIFY_PROBE_LABEL: "true" },
                "credentials": {
                    "keyauth": [{ "key": "${gh-env-secret:alloc=generate}" }]
                }
            }]
        }))
        .expect("desired config");
    let allowlist = ProbeConsumerAllowlist::parse("ferrum/app").expect("allowlist");
    let checks = EnvironmentChecks {
        checks: vec![check.clone()],
    };
    let authorization = authorize_probe_slots("staging", &checks, &desired, Some(&allowlist))
        .expect("the probe slot is authorized");
    let (base_url, seen) = spawn_data_plane(generated.clone());

    // The pre-apply snapshot is what verify used to read: the slot is
    // missing, and the check fails before sending anything.
    let stale = authorization.project(&merge_bundles(&pre_apply)).unwrap();
    let result = run_check(&base_url, &check, &stale, None).await;
    assert_eq!(result.outcome, Outcome::Unreachable);
    assert_eq!(result.attempts, 0);
    assert!(result.detail.contains("not in the bundle"));
    assert!(seen.lock().expect("seen").is_empty());

    let finalized = authorization.project(&finalized).unwrap();
    let result = run_check(&base_url, &check, &finalized, None).await;
    assert_eq!(result.outcome, Outcome::Passed);
    assert_eq!(result.actual_status, Some(200));
    assert!(!result.detail.contains(&generated));
    let requests = seen.lock().expect("seen");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].as_deref() == Some(generated.as_str()),
        "the check must send the value this apply generated"
    );
}

// --- Partial allocation journal (#352) ---------------------------------------

const GENERATE: &str = "${gh-env-secret:alloc=generate}";
/// A clean apply long before this run: every allocation recorded here is newer.
const EARLIER_CLEAN_APPLY: &str = "2020-01-01T00:00:00+00:00";
/// Shard 0 then has room for exactly one new 24-character slot with a
/// 43-character value. The first candidate fits (`N + 88 <= 40960`), the second
/// does not (`N + 161 > 40960`), so it spills onto a new shard 1.
const FILLER_CHARS: usize = 40_836;

fn put_shard_path(shard: u32) -> String {
    format!(
        "PUT /repos/{REPO}/environments/{ENVIRONMENT}/secrets/{} ",
        gitforgeops::secrets::bundle::shard_secret_name(shard)
    )
}

fn new_consumers_cfg(ids: &[&str]) -> gitforgeops::config::schema::GatewayConfig {
    let mut consumers = Vec::new();
    for id in ids {
        consumers.push(serde_json::json!({
            "id": id,
            "username": id,
            "namespace": "ferrum",
            "credentials": {"keyauth": [{"key": GENERATE}]},
        }));
    }
    serde_json::from_value(serde_json::json!({
        "version": "1",
        "consumers": consumers,
    }))
    .unwrap()
}

/// The first resolve of `apply`: the ledger decides whether a stored
/// `alloc=generate` value is this environment's own or a revived one.
fn report_against_ledger(
    cfg: &gitforgeops::config::schema::GatewayConfig,
    bundle: &BTreeMap<String, String>,
    state: &gitforgeops::state::StateFile,
) -> gitforgeops::error::Result<ResolveReport> {
    use gitforgeops::config::GatewayMode;
    use gitforgeops::secrets::{
        report_secrets_with_mode_and_options, ConsumerCoverage, ConsumerLedger, ResolveOptions,
        SlotRemapPolicy,
    };

    let ledger = ConsumerLedger::from_state(state, ConsumerCoverage::Complete, &apply_binding());
    let options = ResolveOptions {
        slot_remap: SlotRemapPolicy::Refuse,
        consumer_ledger: Some(&ledger),
    };
    report_secrets_with_mode_and_options(cfg, bundle, GatewayMode::Api, options)
}

/// The apply both attempts in these tests belong to.
fn apply_binding() -> gitforgeops::state::AllocationBinding {
    gitforgeops::state::AllocationBinding::new(Some("revision-a"), Some("alice"))
}

fn status(report: &ResolveReport, slot: &str) -> Option<SlotStatus> {
    report
        .results
        .iter()
        .find(|result| result.slot == slot)
        .map(|result| result.status.clone())
}

fn put_requests(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    requests
        .lock()
        .expect("recorded")
        .iter()
        .filter(|request| request.starts_with("PUT "))
        .map(|request| request.lines().next().unwrap_or_default().to_string())
        .collect()
}

/// #352: a batch spanning two shards commits shard 0, then fails on shard 1.
/// The committed slot, and only it, is journaled as non-secret metadata. A
/// fresh process holding the saved ledger and the bundle as GitHub now holds
/// it resumes without `--allow-credential-slot-remap`: the committed slot
/// resolves to the value already delivered and only the unwritten one is
/// allocated. A stored value the ledger never recorded is still refused.
#[tokio::test]
async fn a_partially_committed_allocation_is_journaled_and_its_retry_resumes() {
    use gitforgeops::state::StateFile;

    let alpha = slot_path("ferrum", "alpha", "keyauth/key");
    let bravo = slot_path("ferrum", "bravo", "keyauth/key");
    let cfg = new_consumers_cfg(&["alpha", "bravo"]);
    let state = StateFile {
        environment: ENVIRONMENT.to_string(),
        last_applied_at: Some(EARLIER_CLEAN_APPLY.to_string()),
        ..StateFile::default()
    };
    let filler = BTreeMap::from([("filler".to_string(), "x".repeat(FILLER_CHARS))]);
    let mut shards = BTreeMap::from([(0, filler)]);
    let mut shard_count = state.credential_shard_count.max(1);

    let first = report_against_ledger(&cfg, &merge_bundles(&shards), &state)
        .expect("two first-time slots are ordinary allocation");
    assert_eq!(status(&first, &alpha), Some(SlotStatus::NeedsAllocation));
    assert_eq!(status(&first, &bravo), Some(SlotStatus::NeedsAllocation));

    // Routes match by substring, so shard 1's name must precede shard 0's.
    let bad_gateway = "{\"message\":\"Bad Gateway\"}".to_string();
    let mut routes = vec![(put_shard_path(1), 502, bad_gateway)];
    routes.extend(success_routes(204));
    let (api_base, requests) = spawn_github_stub(routes);
    let failure = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &first,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect_err("the second shard PUT fails");
    assert_api_error(&failure.source, 502, "Bad Gateway");
    assert_eq!(failure.partial.allocated.len(), 1);
    let committed = &failure.partial.allocated[0];
    assert_eq!(committed.slot, alpha);
    assert_eq!(committed.shard, 0);
    let committed_value = committed.value.clone();
    assert!(shards[&0].get(&alpha) == Some(&committed_value));
    assert!(!shards.contains_key(&1), "shard 1 never reached GitHub");
    let puts = put_requests(&requests);
    assert_eq!(puts.len(), 2);
    assert!(puts[0].starts_with(&put_shard_path(0)), "{puts:?}");
    assert!(puts[1].starts_with(&put_shard_path(1)), "{puts:?}");

    // Without a journal, the retry refuses the slot this apply wrote.
    let committed_bundle = merge_bundles(&shards);
    let unjournaled = report_against_ledger(&cfg, &committed_bundle, &state)
        .expect_err("an unrecorded committed slot reads as a revival")
        .to_string();
    assert!(
        unjournaled.contains(&format!("'{alpha}'")) && unjournaled.contains("revive"),
        "{unjournaled}"
    );

    let mut journaled = state.clone();
    journaled.record_allocation(&failure.partial, Some("run-1"), &apply_binding());
    assert_eq!(journaled.credentials.len(), 1);
    assert_eq!(journaled.credentials[&alpha].shard, 0);
    assert!(!journaled.credentials.contains_key(&bravo));
    assert_eq!(
        journaled.credential_shard_count, 1,
        "the failed shard is not claimed"
    );
    let saved = serde_json::to_string(&journaled).expect("serialize ledger");
    assert!(
        !saved.contains(&committed_value),
        "the ledger must not hold the credential value"
    );

    // A fresh process: the saved ledger and the bundle GitHub now holds.
    let reloaded: StateFile = serde_json::from_str(&saved).expect("reload ledger");
    let retry = report_against_ledger(&cfg, &committed_bundle, &reloaded)
        .expect("the retry recognizes its own committed slot");
    assert!(retry.slot_remaps.is_empty());
    assert_eq!(status(&retry, &alpha), Some(SlotStatus::Resolved));
    assert_eq!(status(&retry, &bravo), Some(SlotStatus::NeedsAllocation));

    let (api_base, requests) = spawn_github_stub(success_routes(204));
    let mut shard_count = reloaded.credential_shard_count.max(1);
    let outcome = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        None,
        &retry,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("the retry allocates what is still missing");
    assert_eq!(outcome.allocated.len(), 1, "alpha is not generated again");
    assert_eq!(outcome.allocated[0].slot, bravo);
    assert_eq!(outcome.allocated[0].shard, 1);
    let puts = put_requests(&requests);
    assert_eq!(puts.len(), 1, "shard 0 is not rewritten: {puts:?}");
    assert!(puts[0].starts_with(&put_shard_path(1)), "{puts:?}");
    let finalized = merge_bundles(&shards);
    assert!(finalized.get(&alpha) == Some(&committed_value));
    assert!(finalized.contains_key(&bravo));

    // The journal exempts exactly the slots this environment wrote. A stored
    // value for a Consumer the ledger never recorded is still a revival.
    let charlie = slot_path("ferrum", "charlie", "keyauth/key");
    let mut revived = committed_bundle.clone();
    revived.insert(charlie.clone(), "RETIRED-CHARLIE-KEY-VALUE".to_string());
    let with_charlie = new_consumers_cfg(&["alpha", "bravo", "charlie"]);
    let err = report_against_ledger(&with_charlie, &revived, &reloaded)
        .expect_err("a reused id must not inherit a retired value")
        .to_string();
    assert!(err.contains(&format!("'{charlie}'")), "{err}");
    assert!(!err.contains(&format!("'{alpha}'")), "{err}");
    assert!(!err.contains("RETIRED-CHARLIE"), "{err}");

    // Once a later clean apply supersedes the journal, the exemption lapses:
    // a Consumer that is still unrecorded then cannot claim the stored value.
    let superseded = StateFile {
        last_applied_at: Some("2999-01-01T00:00:00+00:00".to_string()),
        ..reloaded.clone()
    };
    let err = report_against_ledger(&cfg, &committed_bundle, &superseded)
        .expect_err("a journal older than the last clean apply is not a retry")
        .to_string();
    assert!(err.contains(&format!("'{alpha}'")), "{err}");
}

// --- Recipient key discovery once per batch (#365) ---------------------------

const RECIPIENT: &str = "alice";

fn keys_path() -> String {
    format!("GET /users/{RECIPIENT}/keys")
}

/// A deterministic Ed25519 recipient: its OpenSSH public key for the key
/// endpoint, and the matching age identity to decrypt deliveries.
fn recipient_keypair() -> (String, age::ssh::Identity) {
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]);
    let public = ssh_key::PublicKey::from(keypair.public)
        .to_openssh()
        .expect("encode public key");
    let private = ssh_key::PrivateKey::from(keypair)
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("encode private key");
    let identity =
        age::ssh::Identity::from_buffer(private.as_bytes(), None).expect("parse identity");
    (public, identity)
}

fn decrypt_delivery(armored: &str, identity: &age::ssh::Identity) -> String {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(armored.as_bytes()))
        .expect("age header");
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .expect("decrypt delivery");
    let mut plaintext = String::new();
    reader
        .read_to_string(&mut plaintext)
        .expect("read plaintext");
    plaintext
}

fn many_slot_report(count: usize) -> ResolveReport {
    let mut report = ResolveReport::default();
    for index in 0..count {
        let consumer = format!("app-{index}");
        report.results.push(ResolveResult {
            consumer_id: consumer.clone(),
            namespace: "ferrum".into(),
            cred_key: "keyauth/key".into(),
            slot: slot_path("ferrum", &consumer, "keyauth/key"),
            placeholder: parse_placeholder(GENERATE).unwrap().unwrap(),
            status: SlotStatus::NeedsAllocation,
        });
    }
    report
}

fn count_requests(requests: &Arc<Mutex<Vec<String>>>, prefix: &str) -> usize {
    requests
        .lock()
        .expect("recorded")
        .iter()
        .filter(|request| request.starts_with(prefix))
        .count()
}

/// #365: every slot in a batch goes to the same recipient, so the batch walks
/// the recipient's key pages once and encrypts each value locally. Each slot
/// still gets its own ciphertext, decryptable to its own value.
#[tokio::test]
async fn a_batch_discovers_the_recipient_key_once_for_every_slot() {
    const SLOTS: usize = 8;
    let (public_key, identity) = recipient_keypair();
    let keys_body = serde_json::json!([{"key": public_key}]).to_string();
    let mut routes = vec![(keys_path(), 200, keys_body)];
    routes.extend(success_routes(204));
    let (api_base, requests) = spawn_github_stub(routes);
    let report = many_slot_report(SLOTS);
    let mut shards = BTreeMap::new();
    let mut shard_count = 1;
    let outcome = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        Some(RECIPIENT),
        &report,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("allocate against stub");

    assert_eq!(outcome.allocated.len(), SLOTS);
    assert_eq!(
        count_requests(&requests, &keys_path()),
        1,
        "one key discovery serves the whole batch"
    );
    let discovery = requests
        .lock()
        .expect("recorded")
        .iter()
        .find(|request| request.starts_with(&keys_path()))
        .cloned()
        .expect("discovery request");
    assert_eq!(
        header_value(&discovery, "Authorization"),
        None,
        "the provisioner token must not reach public key discovery"
    );

    let mut ciphertexts = std::collections::BTreeSet::new();
    for slot in &outcome.allocated {
        let delivered = slot.delivered.as_ref().expect("every slot is delivered");
        assert_eq!(delivered.login, RECIPIENT);
        assert!(delivered.key_fingerprint.starts_with("SHA256:"));
        assert!(!delivered.encrypted_b64.contains(&slot.value));
        assert!(
            decrypt_delivery(&delivered.encrypted_b64, &identity) == slot.value,
            "slot {} must decrypt to its own value",
            slot.slot
        );
        ciphertexts.insert(delivered.encrypted_b64.clone());
    }
    assert_eq!(ciphertexts.len(), SLOTS, "each slot has its own ciphertext");
    let fingerprints: std::collections::BTreeSet<_> = outcome
        .allocated
        .iter()
        .filter_map(|slot| slot.delivered.as_ref())
        .map(|delivered| delivered.key_fingerprint.clone())
        .collect();
    assert_eq!(fingerprints.len(), 1, "one key snapshot for the batch");
}

/// #365: a failed or empty discovery refuses the whole batch after one
/// discovery walk, before the Environment Secret key is fetched or any shard
/// is written.
#[tokio::test]
async fn a_failed_batch_discovery_writes_nothing() {
    let not_found = "{\"message\":\"Not Found\"}".to_string();
    for (status, body, needle) in [
        (200, "[]".to_string(), "no compatible SSH public key"),
        (
            200,
            "[{\"key\":\"unsupported-public-key\"}]".to_string(),
            "no compatible SSH public key",
        ),
        (404, not_found, "Not Found"),
    ] {
        let mut routes = vec![(keys_path(), status, body)];
        routes.extend(success_routes(204));
        let (api_base, requests) = spawn_github_stub(routes);
        let report = many_slot_report(4);
        let mut shards = BTreeMap::new();
        let mut shard_count = 1;
        let failure = allocate_and_deliver_at(
            &test_client(),
            &api_base,
            REPO,
            ENVIRONMENT,
            TOKEN,
            Some(RECIPIENT),
            &report,
            &mut shards,
            &mut shard_count,
        )
        .await
        .expect_err("no recipient key means no allocation");
        assert!(
            failure.source.to_string().contains(needle),
            "{}",
            failure.source
        );
        assert!(failure.partial.allocated.is_empty());
        assert!(shards.is_empty());
        assert_eq!(shard_count, 1);
        assert_eq!(count_requests(&requests, &keys_path()), 1);
        assert_eq!(
            requests.lock().expect("recorded").len(),
            1,
            "discovery is the only request of a refused batch"
        );
    }
}

// --- Recipient hardening (#384) ----------------------------------------------

/// #384: rotation discovers the recipient's key against the injected API
/// origin, before the shard write, and delivers a ciphertext of the new value.
#[tokio::test]
async fn rotate_and_deliver_discovers_the_recipient_against_the_api_base() {
    let (public_key, identity) = recipient_keypair();
    let keys_body = serde_json::json!([{"key": public_key}]).to_string();
    let mut routes = vec![(keys_path(), 200, keys_body)];
    routes.extend(success_routes(204));
    let (api_base, requests) = spawn_github_stub(routes);
    let slot = slot_path("ferrum", "app", "keyauth/key");
    let mut shards = BTreeMap::new();
    let mut shard_count = 1;
    let allocated = rotate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        Some(RECIPIENT),
        &slot,
        32,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("rotate against stub");

    let delivered = allocated.delivered.as_ref().expect("rotation is delivered");
    assert_eq!(delivered.login, RECIPIENT);
    assert!(delivered.key_fingerprint.starts_with("SHA256:"));
    assert_eq!(
        decrypt_delivery(&delivered.encrypted_b64, &identity),
        allocated.value
    );
    let recorded = requests.lock().expect("recorded").clone();
    assert_eq!(recorded.len(), 3, "{recorded:?}");
    assert!(recorded[0].starts_with(&public_key_path()));
    assert!(recorded[1].starts_with(&keys_path()));
    assert!(recorded[2].starts_with(&put_secret_path()));
    assert_eq!(header_value(&recorded[1], "Authorization"), None);
}

/// #384: a key listing that spans two pages is walked once for the whole
/// batch: each page is requested exactly once however many slots it serves.
#[tokio::test]
async fn a_two_page_key_listing_is_walked_once_per_batch() {
    const SLOTS: usize = 4;
    let (public_key, identity) = recipient_keypair();
    let first_page = format!("GET /users/{RECIPIENT}/keys?per_page=100 ");
    let second_page = format!("GET /users/{RECIPIENT}/keys?per_page=100&page=2 ");
    let next = format!("{{base}}/users/{RECIPIENT}/keys?per_page=100&page=2");
    let link = format!("Link: <{next}>; rel=\"next\"\r\n");
    let mut routes = vec![
        (
            second_page.clone(),
            200,
            serde_json::json!([{"key": public_key}]).to_string(),
            String::new(),
        ),
        (
            first_page.clone(),
            200,
            "[{\"key\":\"unsupported-public-key\"}]".to_string(),
            link,
        ),
    ];
    routes.extend(
        success_routes(204)
            .into_iter()
            .map(|(needle, status, body)| (needle, status, body, String::new())),
    );
    let (api_base, requests) = spawn_github_stub_with_headers(routes);
    let report = many_slot_report(SLOTS);
    let mut shards = BTreeMap::new();
    let mut shard_count = 1;
    let outcome = allocate_and_deliver_at(
        &test_client(),
        &api_base,
        REPO,
        ENVIRONMENT,
        TOKEN,
        Some(RECIPIENT),
        &report,
        &mut shards,
        &mut shard_count,
    )
    .await
    .expect("allocate against stub");

    assert_eq!(outcome.allocated.len(), SLOTS);
    assert_eq!(count_requests(&requests, &first_page), 1);
    assert_eq!(count_requests(&requests, &second_page), 1);
    assert_eq!(count_requests(&requests, &keys_path()), 2);
    for slot in &outcome.allocated {
        let delivered = slot.delivered.as_ref().expect("every slot is delivered");
        assert_eq!(
            decrypt_delivery(&delivered.encrypted_b64, &identity),
            slot.value
        );
    }
}

/// #384: the discovered recipient exposes its login and fingerprint read-only.
#[tokio::test]
async fn a_discovered_recipient_reports_its_login_and_fingerprint() {
    use gitforgeops::secrets::discover_recipient_at;
    let (public_key, _) = recipient_keypair();
    let keys_body = serde_json::json!([{"key": public_key}]).to_string();
    let (api_base, _) = spawn_github_stub(vec![(keys_path(), 200, keys_body)]);
    let recipient = discover_recipient_at(&test_client(), &api_base, RECIPIENT)
        .await
        .expect("discovery")
        .expect("a compatible key");
    assert_eq!(recipient.login(), RECIPIENT);
    assert!(recipient.key_fingerprint().starts_with("SHA256:"));
    let delivered = recipient.encrypt(b"synthetic").expect("encrypt");
    assert_eq!(delivered.login, recipient.login());
    assert_eq!(delivered.key_fingerprint, recipient.key_fingerprint());
}

const INVALID_LOGINS: [&str; 12] = [
    "",
    "-alice",
    "alice/../../repos",
    "alice?per_page=1",
    "alice#x",
    "alice bob",
    "alice%2Fkeys",
    "alice\n",
    "[bot]",
    "alice[bot]x",
    "a012345678901234567890123456789012345678",
    "a0123456789012345678901234567890123[bot]",
];

#[test]
fn github_logins_follow_the_workflow_login_rule() {
    use gitforgeops::secrets::is_valid_github_login;
    for valid in [
        "a",
        "alice",
        "Alice-Bob",
        "0day",
        "dependabot[bot]",
        "a01234567890123456789012345678901234567",
        "a012345678901234567890123456789012[bot]",
    ] {
        assert!(is_valid_github_login(valid), "{valid:?}");
    }
    for invalid in INVALID_LOGINS {
        assert!(!is_valid_github_login(invalid), "{invalid:?}");
    }
}

/// #384: a login that is not a GitHub login never reaches the key endpoint
/// path, and a batch addressed to one writes nothing.
#[tokio::test]
async fn an_invalid_recipient_login_is_refused_before_any_request() {
    use gitforgeops::secrets::discover_recipient_at;
    for login in INVALID_LOGINS {
        let mut routes = vec![(String::from("GET /"), 200, "[]".to_string())];
        routes.extend(success_routes(204));
        let (api_base, requests) = spawn_github_stub(routes);
        let error = discover_recipient_at(&test_client(), &api_base, login)
            .await
            .expect_err("invalid login is refused");
        assert!(
            error.to_string().contains("not a valid GitHub login"),
            "{error}"
        );

        let report = many_slot_report(2);
        let mut shards = BTreeMap::new();
        let mut shard_count = 1;
        let failure = allocate_and_deliver_at(
            &test_client(),
            &api_base,
            REPO,
            ENVIRONMENT,
            TOKEN,
            Some(login),
            &report,
            &mut shards,
            &mut shard_count,
        )
        .await
        .expect_err("invalid login refuses the batch");
        assert!(failure.partial.allocated.is_empty());
        assert!(shards.is_empty());
        assert!(
            requests.lock().expect("recorded").is_empty(),
            "{login:?} must not reach GitHub"
        );
    }
}

const OVERRIDE_LABEL: &str = "gitforgeops/policy-override";

fn events_page(repo_pr: &str, page: usize) -> String {
    format!("GET /repos/{repo_pr}/events?per_page=100&page={page} ")
}

fn label_event(event: &str, login: &str) -> serde_json::Value {
    serde_json::json!({
        "event": event,
        "label": {"name": OVERRIDE_LABEL},
        "actor": {"login": login},
    })
}

fn full_events_page(first: serde_json::Value) -> String {
    let mut events = vec![first];
    events.extend((1..100).map(|_| serde_json::json!({"event": "commented"})));
    serde_json::Value::Array(events).to_string()
}

/// #545: override-label pagination requests numbered pages from the fixed API
/// origin and never follows a response's `Link` header, so the bearer token
/// cannot be sent to a host or path that a response names.
#[tokio::test]
async fn override_labeler_pagination_ignores_response_link_urls() {
    use gitforgeops::policy::github_override::find_override_labeler_at;
    let repo_pr = format!("{REPO}/issues/7");
    // A second loopback origin stands in for an attacker host. Page 1 names it
    // as `rel="next"` with the legitimate events path; page 2 names a
    // same-origin path outside the events endpoint.
    let (other_origin, other_requests) =
        spawn_github_stub(vec![(String::from("GET /"), 200, "[]".to_string())]);
    let off_origin_link = format!(
        "Link: <{other_origin}/repos/{repo_pr}/events?per_page=100&page=2>; rel=\"next\"\r\n"
    );
    let off_path_link = "Link: <{base}/steal?page=3>; rel=\"next\"\r\n".to_string();
    let routes = vec![
        (
            events_page(&repo_pr, 1),
            200,
            full_events_page(label_event("labeled", "earlier")),
            off_origin_link,
        ),
        (
            events_page(&repo_pr, 2),
            200,
            serde_json::json!([label_event("labeled", "maintainer")]).to_string(),
            off_path_link,
        ),
        (
            String::from("/steal"),
            200,
            serde_json::json!([label_event("labeled", "attacker")]).to_string(),
            String::new(),
        ),
    ];
    let (api_base, requests) = spawn_github_stub_with_headers(routes);
    // Page 2 is short yet announces a next page, so the history is refused as
    // incomplete (#562) rather than read to its end through the Link URL.
    let error = find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
        .await
        .expect_err("a short page that announces a next page is incomplete");
    assert!(
        error.to_string().contains("announces a next page"),
        "{error}"
    );

    let recorded = requests.lock().expect("recorded").clone();
    assert_eq!(recorded.len(), 2, "{recorded:?}");
    assert!(recorded[0].starts_with(&events_page(&repo_pr, 1)));
    assert!(recorded[1].starts_with(&events_page(&repo_pr, 2)));
    for request in &recorded {
        assert!(!request.contains("/steal"), "{request}");
        assert_github_headers(request);
    }
    assert!(
        other_requests.lock().expect("recorded").is_empty(),
        "the off-origin Link target must receive no request (and no token)"
    );
}

/// A later `unlabeled` event on a later page clears the approver.
#[tokio::test]
async fn override_labeler_honours_a_later_unlabel_on_a_later_page() {
    use gitforgeops::policy::github_override::find_override_labeler_at;
    let repo_pr = format!("{REPO}/issues/7");
    let routes = vec![
        (
            events_page(&repo_pr, 1),
            200,
            full_events_page(label_event("labeled", "maintainer")),
        ),
        (
            events_page(&repo_pr, 2),
            200,
            serde_json::json!([label_event("unlabeled", "maintainer")]).to_string(),
        ),
    ];
    let (api_base, _requests) = spawn_github_stub(routes);
    let labeler =
        find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
            .await
            .expect("labeler lookup");
    assert_eq!(labeler, None);
}

/// Reaching the page cap with a still-full page fails closed.
#[tokio::test]
async fn override_labeler_pagination_cap_fails_closed() {
    use gitforgeops::policy::github_override::find_override_labeler_at;
    let routes = vec![(
        format!("GET /repos/{REPO}/issues/7/events?per_page=100&page="),
        200,
        full_events_page(label_event("labeled", "maintainer")),
    )];
    let (api_base, requests) = spawn_github_stub(routes);
    let error = find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
        .await
        .expect_err("cap reached with more events");
    assert!(
        error.to_string().contains("pagination safety cap"),
        "{error}"
    );
    assert_eq!(requests.lock().expect("recorded").len(), 20);
}

/// #562: a short page ends the history only when GitHub does not announce a
/// next page. A short page with `rel="next"` fails closed; the announced URL
/// receives no request.
#[tokio::test]
async fn override_labeler_short_page_announcing_next_fails_closed() {
    use gitforgeops::policy::github_override::find_override_labeler_at;
    let repo_pr = format!("{REPO}/issues/7");
    let routes = vec![
        (
            events_page(&repo_pr, 1),
            200,
            serde_json::json!([label_event("labeled", "maintainer")]).to_string(),
            format!(
                "Link: <{{base}}/repos/{repo_pr}/events?per_page=100&page=2>; rel=\"next\", <{{base}}/repos/{repo_pr}/events?per_page=100&page=2>; rel=\"last\"\r\n"
            ),
        ),
        (
            events_page(&repo_pr, 2),
            200,
            serde_json::json!([label_event("unlabeled", "maintainer")]).to_string(),
            String::new(),
        ),
    ];
    let (api_base, requests) = spawn_github_stub_with_headers(routes);
    let error = find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
        .await
        .expect_err("short page with a next link is incomplete");
    assert!(
        error.to_string().contains("announces a next page"),
        "{error}"
    );
    let recorded = requests.lock().expect("recorded").clone();
    assert_eq!(recorded.len(), 1, "{recorded:?}");
}

/// A short final page whose `Link` header names only earlier pages completes.
#[tokio::test]
async fn override_labeler_short_page_with_only_prev_link_completes() {
    use gitforgeops::policy::github_override::find_override_labeler_at;
    let repo_pr = format!("{REPO}/issues/7");
    let routes = vec![
        (
            events_page(&repo_pr, 1),
            200,
            full_events_page(label_event("labeled", "earlier")),
            "Link: <{base}/next>; rel=\"next\"\r\n".to_string(),
        ),
        (
            events_page(&repo_pr, 2),
            200,
            serde_json::json!([label_event("labeled", "maintainer")]).to_string(),
            "Link: <{base}/p1>; rel=\"prev\", <{base}/p1>; rel=\"first\"\r\n".to_string(),
        ),
    ];
    let (api_base, requests) = spawn_github_stub_with_headers(routes);
    let labeler =
        find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
            .await
            .expect("labeler lookup");
    assert_eq!(labeler.as_deref(), Some("maintainer"));
    assert_eq!(requests.lock().expect("recorded").len(), 2);
}

fn reviews_page(page: usize) -> String {
    format!("GET /repos/{REPO}/pulls/7/reviews?per_page=100&page={page} ")
}

fn plain_review_json(id: u64, login: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "commit_id": "a".repeat(40),
        "state": "COMMENTED",
        "body": "ordinary",
        "user": {"login": login},
    })
}

/// #562: review pagination refuses a short page that announces a next page,
/// so a later revoking review on an unread page cannot be missed.
#[tokio::test]
async fn override_reviews_short_page_announcing_next_fails_closed() {
    use gitforgeops::policy::github_override::fetch_reviews_at;
    let routes = vec![
        (
            reviews_page(1),
            200,
            serde_json::json!([plain_review_json(1, "maintainer")]).to_string(),
            "Link: <{base}/steal?page=2>; rel=\"next\"\r\n".to_string(),
        ),
        (String::from("/steal"), 200, "[]".to_string(), String::new()),
    ];
    let (api_base, requests) = spawn_github_stub_with_headers(routes);
    let error = fetch_reviews_at(&test_client(), &api_base, REPO, 7, TOKEN)
        .await
        .expect_err("short review page with a next link is incomplete");
    assert!(
        error.to_string().contains("announces a next page"),
        "{error}"
    );
    let recorded = requests.lock().expect("recorded").clone();
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert!(!recorded[0].contains("/steal"));
}

/// Reviews keep reading numbered pages from the fixed origin past a full page.
#[tokio::test]
async fn override_reviews_walk_numbered_pages_from_the_fixed_origin() {
    use gitforgeops::policy::github_override::fetch_reviews_at;
    let full: Vec<_> = (1..=100)
        .map(|id| plain_review_json(id, "someone"))
        .collect();
    let routes = vec![
        (
            reviews_page(1),
            200,
            serde_json::Value::Array(full).to_string(),
            "Link: <{base}/steal?page=2>; rel=\"next\"\r\n".to_string(),
        ),
        (
            reviews_page(2),
            200,
            serde_json::json!([plain_review_json(101, "maintainer")]).to_string(),
            String::new(),
        ),
    ];
    let (api_base, requests) = spawn_github_stub_with_headers(routes);
    let reviews = fetch_reviews_at(&test_client(), &api_base, REPO, 7, TOKEN)
        .await
        .expect("reviews");
    assert_eq!(reviews.len(), 101);
    assert_eq!(reviews[100].id, 101);
    let recorded = requests.lock().expect("recorded").clone();
    assert_eq!(recorded.len(), 2, "{recorded:?}");
    assert!(recorded.iter().all(|request| !request.contains("/steal")));
}

/// `(needle, responses in order, extra header lines on every response)`.
type SequencedRoute = (String, Vec<(u16, String)>, String);

/// A loopback stub whose routes answer a sequence of responses: each request
/// matching a needle takes the next response, and the last one repeats.
fn spawn_sequenced_github_stub(routes: Vec<SequencedRoute>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let base = format!("http://{}", listener.local_addr().expect("stub addr"));
    let routes = Arc::new(Mutex::new(
        routes
            .into_iter()
            .map(|(needle, responses, headers)| {
                (
                    needle,
                    std::collections::VecDeque::from(responses),
                    headers.replace("{base}", &base),
                )
            })
            .collect::<Vec<_>>(),
    ));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_requests = Arc::clone(&requests);
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let routes = Arc::clone(&routes);
            let requests = Arc::clone(&thread_requests);
            std::thread::spawn(move || loop {
                let request = match read_request(&mut stream) {
                    Some(request) => request,
                    None => return,
                };
                requests
                    .lock()
                    .expect("record request")
                    .push(request.clone());
                let (status, body, headers) = {
                    let mut routes = routes.lock().expect("routes");
                    routes
                        .iter_mut()
                        .find(|(needle, _, _)| request.contains(needle.as_str()))
                        .and_then(|(_, responses, headers)| {
                            let response = if responses.len() > 1 {
                                responses.pop_front()
                            } else {
                                responses.front().cloned()
                            };
                            response.map(|(status, body)| (status, body, headers.clone()))
                        })
                        .unwrap_or((
                            404,
                            "{\"message\":\"Not Found\"}".to_string(),
                            String::new(),
                        ))
                };
                if write!(
                    stream,
                    "HTTP/1.1 {status} STUB\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{headers}\r\n{}",
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
    (base, requests)
}

/// Every route of a complete, valid override, with the labeler's permission
/// answered by `permissions` in order.
fn override_routes(permissions: &[(u16, &str)]) -> Vec<SequencedRoute> {
    let head = "a".repeat(40);
    let pr = serde_json::json!({
        "labels": [{"name": OVERRIDE_LABEL}],
        "head": {"sha": head},
        "merged": false,
        "merge_commit_sha": null,
    })
    .to_string();
    let review = serde_json::json!([{
        "id": 42,
        "commit_id": head,
        "state": "APPROVED",
        "body": format!("gitforgeops-override {OVERRIDE_LABEL}"),
        "user": {"login": "maintainer"},
    }])
    .to_string();
    vec![
        (
            format!("GET /repos/{REPO}/pulls/7 HTTP"),
            vec![(200, pr)],
            String::new(),
        ),
        (
            events_page(&format!("{REPO}/issues/7"), 1),
            vec![(
                200,
                serde_json::json!([label_event("labeled", "maintainer")]).to_string(),
            )],
            String::new(),
        ),
        (
            format!("GET /repos/{REPO}/collaborators/maintainer/permission"),
            permissions
                .iter()
                .map(|(status, permission)| {
                    (
                        *status,
                        serde_json::json!({"permission": permission, "role_name": permission})
                            .to_string(),
                    )
                })
                .collect(),
            String::new(),
        ),
        (reviews_page(1), vec![(200, review)], String::new()),
        (
            format!("GET /repos/{REPO}/git/trees/"),
            vec![(
                200,
                serde_json::json!({"truncated": false, "tree": []}).to_string(),
            )],
            String::new(),
        ),
    ]
}

/// Run the whole override check against a stub; the input verifier is a fixed
/// pass, so the decision reflects only the GitHub evidence.
async fn run_override_check(
    permissions: &[(u16, &str)],
) -> (gitforgeops::policy::OverrideDecision, usize) {
    run_override_routes(override_routes(permissions)).await
}

async fn run_override_routes(
    routes: Vec<SequencedRoute>,
) -> (gitforgeops::policy::OverrideDecision, usize) {
    use gitforgeops::policy::github_override::check_override_at;
    let (api_base, requests) = spawn_sequenced_github_stub(routes);
    let cfg = gitforgeops::policy::OverrideConfig {
        require_label: OVERRIDE_LABEL.into(),
        required_permission: "write".into(),
    };
    let decision = check_override_at(
        &test_client(),
        &api_base,
        REPO,
        TOKEN,
        &cfg,
        7,
        |_, _, _| Ok("b".repeat(40)),
    )
    .await
    .expect("override check");
    let permission_reads = requests
        .lock()
        .expect("recorded")
        .iter()
        .filter(|request| request.contains("/permission"))
        .count();
    (decision, permission_reads)
}

/// Stable evidence yields an active override; the harness is complete.
#[tokio::test]
async fn override_with_stable_evidence_is_active() {
    let (decision, permission_reads) = run_override_check(&[(200, "write")]).await;
    assert!(decision.active, "{}", decision.reason);
    assert_eq!(decision.approver.as_deref(), Some("maintainer"));
    assert_eq!(decision.review_id, Some(42));
    assert_eq!(permission_reads, 2);
}

/// #562: the final evidence pass re-reads the labeler's permission. A labeler
/// demoted from write to read while evidence was collected revokes it.
#[tokio::test]
async fn override_permission_demoted_during_verification_is_inactive() {
    let (decision, permission_reads) = run_override_check(&[(200, "write"), (200, "read")]).await;
    assert!(!decision.active);
    assert!(
        decision.reason.contains("override evidence changed"),
        "{}",
        decision.reason
    );
    assert_eq!(permission_reads, 2);
}

/// A permission read that fails in the final pass also revokes it.
#[tokio::test]
async fn override_permission_unreadable_during_final_pass_is_inactive() {
    let (decision, permission_reads) = run_override_check(&[(200, "write"), (500, "write")]).await;
    assert!(!decision.active, "{}", decision.reason);
    assert_eq!(permission_reads, 2);
}

/// `Link` header lines that may announce a next page: every short page
/// carrying one fails closed (#562 review). Each entry is the raw header
/// line(s) a stub response carries.
const AMBIGUOUS_OR_NEXT_LINKS: &[&str] = &[
    "Link: <{base}/x>; rel=next\r\n",
    "Link: <{base}/x>; rel = \"next\"\r\n",
    "Link: <{base}/x>; rel=\"prev next\"\r\n",
    "Link: <{base}/x>; REL=\"NEXT\"\r\n",
    "Link: <{base}/x>;rel=\"Next\"\r\n",
    "Link: <{base}/p1>; rel=\"prev\", <{base}/x>; rel=\"next\"\r\n",
    "Link: <{base}/p1>; title=\"a, b\"; rel=\"prev\", <{base}/x>; rel=next\r\n",
    "Link: <{base}/p1>; rel=\"prev\"\r\nLink: <{base}/x>; rel=\"next\"\r\n",
    "Link: not-a-link\r\n",
    "Link: <{base}/x\r\n",
    "Link: <{base}/x>; rel\r\n",
    "Link: <{base}/x>; rel=\r\n",
    "Link: <{base}/x>; rel=\"\"\r\n",
    "Link: <{base}/x>; rel=\"next\r\n",
    "Link: <{base}/x>; rel=prev next\r\n",
    "Link: <{base}/x>; rel*=UTF-8''next\r\n",
    "Link: <{base}/x> rel=\"prev\"\r\n",
    // Relation types outside the RFC 8288 grammar (#562 review round 2).
    "Link: <{base}/x>; rel=\"prev,next\"\r\n",
    "Link: <{base}/x>; rel=\"prev;next\"\r\n",
    "Link: <{base}/x>; rel=\" next\"\r\n",
    "Link: <{base}/x>; rel=\"prev \"\r\n",
    "Link: <{base}/x>; rel=\"prev\tnext\"\r\n",
    "Link: <{base}/x>; rel=\"next\\\"\"\r\n",
    "Link: <{base}/x>; rel=\"1next\"\r\n",
    "Link: <{base}/x>; rel=\"pr_ev\"\r\n",
    "Link: <{base}/x>; rel=\"https://example.com/a,next\"\r\n",
    // Malformed targets.
    "Link: <>; rel=\"prev\"\r\n",
    "Link: < {base}/x>; rel=\"prev\"\r\n",
    // Two different `next` targets.
    "Link: <{base}/a>; rel=\"next\", <{base}/b>; rel=\"next\"\r\n",
    // Targets and extension relation types outside RFC 3986 (#562 final).
    "Link: <https://api.github.com/%GG>; rel=\"prev\"\r\n",
    "Link: <https://api.github.com/x>; rel=\"https://example.com/%GG\"\r\n",
    "Link: <{base}/x%4>; rel=\"next\"\r\n",
    "Link: <{base}/x%>; rel=\"prev\"\r\n",
    "Link: <{base}/a|b>; rel=\"prev\"\r\n",
    "Link: <{base}/a\"b>; rel=\"prev\"\r\n",
    "Link: <{base}/a#b#c>; rel=\"prev\"\r\n",
    "Link: <{base}/x>; rel=\"https://example.com/a{b}\"\r\n",
];

/// `Link` header lines that unambiguously announce no next page.
const NO_NEXT_LINKS: &[&str] = &[
    "",
    "Link: <{base}/p1>; rel=\"prev\"\r\n",
    "Link: <{base}/p1>; rel=\"prev first\"\r\n",
    "Link: <{base}/p1>; rel=prev, <{base}/p0>; rel=\"first\"\r\n",
    "Link: <{base}/p1>; rel=\"prev\"; title=\"next page\"\r\n",
    "Link: <{base}/p1>; rel=\"nextish\"\r\n",
    "Link: <{base}/p1>; rel=\"prev  first\"\r\n",
    "Link: <{base}/p1>; rel=\"prev https://example.com/rels/page\"\r\n",
    "Link: <{base}/p1>; rel=\"prev.v2 first-page\"\r\n",
    "Link: <{base}/p1?q=a%2Cb&x=1#top>; rel=\"prev\"\r\n",
    "Link: <{base}/p1>; rel=\"prev https://example.com/rels/a%20b\"\r\n",
];

#[test]
fn link_header_parser_fails_closed_on_next_or_ambiguity() {
    use gitforgeops::policy::github_override::link_header_may_announce_next;
    // The stub substitutes its origin for `{base}`; so does this table.
    let base = |line: &str| line.replace("{base}", "http://127.0.0.1:1");
    for line in AMBIGUOUS_OR_NEXT_LINKS {
        // A single header line is checked here; multi-line entries are covered
        // end to end below.
        let line = base(line);
        let first = line.split("\r\n").next().unwrap();
        let value = first.strip_prefix("Link: ").unwrap();
        if line.matches("Link:").count() == 1 {
            assert!(link_header_may_announce_next(value), "{line:?}");
        }
    }
    for line in NO_NEXT_LINKS.iter().filter(|line| !line.is_empty()) {
        let line = base(line);
        let value = line.trim_end().strip_prefix("Link: ").unwrap();
        assert!(!link_header_may_announce_next(value), "{line:?}");
    }
}

#[tokio::test]
async fn short_event_and_review_pages_fail_closed_on_every_next_or_ambiguous_link() {
    use gitforgeops::policy::github_override::{fetch_reviews_at, find_override_labeler_at};
    let repo_pr = format!("{REPO}/issues/7");
    for line in AMBIGUOUS_OR_NEXT_LINKS {
        let (api_base, requests) = spawn_github_stub_with_headers(vec![(
            events_page(&repo_pr, 1),
            200,
            serde_json::json!([label_event("labeled", "maintainer")]).to_string(),
            line.to_string(),
        )]);
        let error =
            find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
                .await
                .expect_err(line);
        assert!(
            error.to_string().contains("announces a next page"),
            "{line:?}: {error}"
        );
        assert_eq!(requests.lock().expect("recorded").len(), 1, "{line:?}");

        let (api_base, requests) = spawn_github_stub_with_headers(vec![(
            reviews_page(1),
            200,
            serde_json::json!([plain_review_json(1, "maintainer")]).to_string(),
            line.to_string(),
        )]);
        let error = fetch_reviews_at(&test_client(), &api_base, REPO, 7, TOKEN)
            .await
            .expect_err(line);
        assert!(
            error.to_string().contains("announces a next page"),
            "{line:?}: {error}"
        );
        assert_eq!(requests.lock().expect("recorded").len(), 1, "{line:?}");
    }
    for line in NO_NEXT_LINKS {
        let (api_base, _) = spawn_github_stub_with_headers(vec![(
            events_page(&repo_pr, 1),
            200,
            serde_json::json!([label_event("labeled", "maintainer")]).to_string(),
            line.to_string(),
        )]);
        let labeler =
            find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
                .await
                .unwrap_or_else(|error| panic!("{line:?}: {error}"));
        assert_eq!(labeler.as_deref(), Some("maintainer"), "{line:?}");

        let (api_base, _) = spawn_github_stub_with_headers(vec![(
            reviews_page(1),
            200,
            serde_json::json!([plain_review_json(1, "maintainer")]).to_string(),
            line.to_string(),
        )]);
        let reviews = fetch_reviews_at(&test_client(), &api_base, REPO, 7, TOKEN)
            .await
            .unwrap_or_else(|error| panic!("{line:?}: {error}"));
        assert_eq!(reviews.len(), 1, "{line:?}");
    }
}

/// End to end: an ambiguous or next-announcing `Link` on the short events page
/// or the short reviews page leaves the override inactive.
#[tokio::test]
async fn override_is_inactive_when_a_short_page_link_may_announce_more() {
    for line in AMBIGUOUS_OR_NEXT_LINKS {
        for route in [1, 3] {
            let mut routes = override_routes(&[(200, "write")]);
            routes[route].2 = line.to_string();
            let (decision, _) = run_override_routes(routes).await;
            assert!(!decision.active, "route {route} {line:?}");
        }
    }
    for line in NO_NEXT_LINKS {
        let mut routes = override_routes(&[(200, "write")]);
        routes[1].2 = line.to_string();
        routes[3].2 = line.to_string();
        let (decision, _) = run_override_routes(routes).await;
        assert!(decision.active, "{line:?}: {}", decision.reason);
    }
}

/// The shared parser reads every link-value: a malformed entry never hides a
/// later one, and makes the whole value ambiguous rather than "no next".
#[test]
fn next_link_reads_every_link_value_and_flags_malformed_entries() {
    use gitforgeops::policy::github_override::{next_link, parse_next_link, NextLink};
    // An entry without parameters is a valid link-value with no relation.
    assert_eq!(
        next_link("<https://h/p1>, <https://h/p2>; rel=\"next\""),
        NextLink::Next("https://h/p2".into())
    );
    assert_eq!(
        parse_next_link("<https://h/p1>, <https://h/p2>; rel=\"next\"").as_deref(),
        Some("https://h/p2")
    );
    assert_eq!(
        next_link("<https://h/p0>; rel=\"prev\"; title=\"a, b\", <https://h/p2>; rel=next"),
        NextLink::Next("https://h/p2".into())
    );
    for malformed in [
        "garbage, <https://h/p2>; rel=\"next\"",
        "<https://h/p1> junk, <https://h/p2>; rel=\"next\"",
        "<https://h/p1>; rel=\"prev\", not-a-link",
    ] {
        assert_eq!(next_link(malformed), NextLink::Ambiguous, "{malformed}");
        assert_eq!(parse_next_link(malformed), None, "{malformed}");
    }
    assert_eq!(next_link("<https://h/p1>; rel=\"prev\""), NextLink::Absent);
}

/// SSH key discovery refuses an ambiguous `Link` header rather than ending the
/// recipient search early.
#[tokio::test]
async fn ssh_key_discovery_refuses_an_ambiguous_link_header() {
    use gitforgeops::secrets::discover_recipient_at;
    let first_page = format!("GET /users/{RECIPIENT}/keys?per_page=100 ");
    let second_page = format!("GET /users/{RECIPIENT}/keys?per_page=100&page=2");
    let (public_key, _) = recipient_keypair();
    let (api_base, requests) = spawn_github_stub_with_headers(vec![
        (
            second_page.clone(),
            200,
            serde_json::json!([{"key": public_key}]).to_string(),
            String::new(),
        ),
        (
            first_page,
            200,
            "[{\"key\":\"unsupported-public-key\"}]".to_string(),
            format!(
                "Link: garbage, <{{base}}/users/{RECIPIENT}/keys?per_page=100&page=2>; rel=\"next\"\r\n"
            ),
        ),
    ]);
    let error = discover_recipient_at(&test_client(), &api_base, RECIPIENT)
        .await
        .expect_err("ambiguous pagination is refused");
    assert!(
        error
            .to_string()
            .contains("invalid SSH key pagination header"),
        "{error}"
    );
    assert_eq!(count_requests(&requests, &second_page), 0);
}

/// An exactly full page followed by an empty one completes the history.
#[tokio::test]
async fn exactly_one_full_page_then_an_empty_page_completes() {
    use gitforgeops::policy::github_override::{fetch_reviews_at, find_override_labeler_at};
    let repo_pr = format!("{REPO}/issues/7");
    let (api_base, requests) = spawn_github_stub(vec![
        (
            events_page(&repo_pr, 1),
            200,
            full_events_page(label_event("labeled", "maintainer")),
        ),
        (events_page(&repo_pr, 2), 200, "[]".to_string()),
    ]);
    let labeler =
        find_override_labeler_at(&test_client(), &api_base, REPO, 7, TOKEN, OVERRIDE_LABEL)
            .await
            .expect("labeler lookup");
    assert_eq!(labeler.as_deref(), Some("maintainer"));
    assert_eq!(requests.lock().expect("recorded").len(), 2);

    let full: Vec<_> = (1..=100)
        .map(|id| plain_review_json(id, "someone"))
        .collect();
    let (api_base, requests) = spawn_github_stub(vec![
        (
            reviews_page(1),
            200,
            serde_json::Value::Array(full).to_string(),
        ),
        (reviews_page(2), 200, "[]".to_string()),
    ]);
    let reviews = fetch_reviews_at(&test_client(), &api_base, REPO, 7, TOKEN)
        .await
        .expect("reviews");
    assert_eq!(reviews.len(), 100);
    assert_eq!(requests.lock().expect("recorded").len(), 2);
}

/// A compatible key already on the page is used even when the page's `Link`
/// header is ambiguous: the refusal only guards a search that would continue.
#[tokio::test]
async fn ssh_key_discovery_uses_a_found_key_despite_an_ambiguous_link_header() {
    use gitforgeops::secrets::discover_recipient_at;
    let (public_key, _) = recipient_keypair();
    let (api_base, requests) = spawn_github_stub_with_headers(vec![(
        keys_path(),
        200,
        serde_json::json!([{"key": public_key}]).to_string(),
        "Link: garbage\r\n".to_string(),
    )]);
    let recipient = discover_recipient_at(&test_client(), &api_base, RECIPIENT)
        .await
        .expect("discovery")
        .expect("the compatible key on page 1");
    assert_eq!(recipient.login(), RECIPIENT);
    assert_eq!(count_requests(&requests, &keys_path()), 1);
}

/// SSH key discovery reads every `Link` header: a `next` in the second one is
/// followed (same origin and path), and an ambiguous second one is refused.
#[tokio::test]
async fn ssh_key_discovery_reads_every_link_header() {
    use gitforgeops::secrets::discover_recipient_at;
    let (public_key, _) = recipient_keypair();
    let first_page = format!("GET /users/{RECIPIENT}/keys?per_page=100 ");
    let second_page = format!("GET /users/{RECIPIENT}/keys?per_page=100&page=2");
    let routes = |second_header: String| {
        vec![
            (
                second_page.clone(),
                200,
                serde_json::json!([{"key": public_key}]).to_string(),
                String::new(),
            ),
            (
                first_page.clone(),
                200,
                "[{\"key\":\"unsupported-public-key\"}]".to_string(),
                format!(
                    "Link: <{{base}}/users/{RECIPIENT}/keys?per_page=100&page=1>; rel=\"prev\"\r\n{second_header}"
                ),
            ),
        ]
    };

    let (api_base, requests) = spawn_github_stub_with_headers(routes(format!(
        "Link: <{{base}}/users/{RECIPIENT}/keys?per_page=100&page=2>; rel=\"next\"\r\n"
    )));
    let recipient = discover_recipient_at(&test_client(), &api_base, RECIPIENT)
        .await
        .expect("discovery")
        .expect("the key on page 2");
    assert_eq!(recipient.login(), RECIPIENT);
    assert_eq!(count_requests(&requests, &second_page), 1);

    let (api_base, requests) = spawn_github_stub_with_headers(routes(format!(
        "Link: <{{base}}/users/{RECIPIENT}/keys?per_page=100&page=2>; rel=\"prev,next\"\r\n"
    )));
    let error = discover_recipient_at(&test_client(), &api_base, RECIPIENT)
        .await
        .expect_err("an ambiguous second header is refused");
    assert!(
        error
            .to_string()
            .contains("invalid SSH key pagination header"),
        "{error}"
    );
    assert_eq!(count_requests(&requests, &second_page), 0);
}
