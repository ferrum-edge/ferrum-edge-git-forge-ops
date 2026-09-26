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
use gitforgeops::verify::{HeaderValue, Outcome, SmokeCheck};

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
                requests
                    .lock()
                    .expect("record request")
                    .push(request.clone());
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
    let (base_url, seen) = spawn_data_plane(generated.clone());

    // The pre-apply snapshot is what verify used to read: the slot is
    // missing, and the check fails before sending anything.
    let stale = merge_bundles(&pre_apply);
    let result = run_check(&base_url, &check, &stale, None).await;
    assert_eq!(result.outcome, Outcome::Unreachable);
    assert_eq!(result.attempts, 0);
    assert!(result.detail.contains("not in the bundle"));
    assert!(seen.lock().expect("seen").is_empty());

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

    let ledger = ConsumerLedger::from_state(
        state,
        ConsumerCoverage::Complete,
        Some("revision-a"),
        Some("alice"),
    );
    let options = ResolveOptions {
        slot_remap: SlotRemapPolicy::Refuse,
        consumer_ledger: Some(&ledger),
    };
    report_secrets_with_mode_and_options(cfg, bundle, GatewayMode::Api, options)
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
    journaled.record_allocation(
        &failure.partial,
        Some("run-1"),
        Some("revision-a"),
        Some("alice"),
    );
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
