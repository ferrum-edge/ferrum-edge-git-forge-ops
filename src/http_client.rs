use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};

use crate::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::config::EnvConfig;
use crate::jwt::{self, JwtOptions};

/// Page size requested from paginated list endpoints. The server clamps to
/// 1000, so this is the largest single round-trip it will serve.
const LIST_PAGE_LIMIT: i64 = 1000;

/// Hard cap on how long a `Retry-After` may park a CLI run. The gateway sends
/// `Retry-After: 1` for admission contention; a pathological value should not
/// wedge CI.
const RETRY_AFTER_CAP: Duration = Duration::from_secs(30);

/// `POST /batch` body-size cap enforced by the gateway (1 MiB). We chunk below
/// it with headroom for the JSON envelope.
pub const BATCH_MAX_BODY_BYTES: usize = 1024 * 1024;
const BATCH_ENVELOPE_OVERHEAD: usize = 512;

/// Exact read-only refusal body the admin API returns for config mutations.
const READ_ONLY_MESSAGE: &str = "Admin API is in read-only mode";

/// Gateway modes in which the admin API refuses config writes unconditionally,
/// regardless of `FERRUM_ADMIN_READ_ONLY`.
const READ_ONLY_MODES: [&str; 4] = ["file", "dp", "mesh", "node_agent"];

/// Client for the Ferrum Edge Admin API.
///
/// The client owns a reusable `reqwest::Client`, so per-command gateway calls
/// share connection pooling, TLS configuration, JWT auth, and retry behavior.
pub struct AdminClient {
    client: Client,
    gateway_url: String,
    jwt_secret: String,
    jwt_options: JwtOptions,
    max_retries: u32,
    /// Set when any `GET /backup` came back with `X-Data-Source: cached`.
    /// Sticky and conservative: once the client has seen a cached view, every
    /// later prune decision in the same run is treated as potentially stale.
    saw_cached_backup: AtomicBool,
}

impl AdminClient {
    /// Build an Admin API client from resolved process/repo environment config.
    pub fn new(env: &EnvConfig) -> crate::error::Result<Self> {
        let gateway_url = env
            .gateway_url
            .clone()
            .ok_or(crate::error::Error::NoGatewayUrl)?;
        let jwt_secret = env
            .admin_jwt_secret
            .clone()
            .ok_or(crate::error::Error::NoJwtSecret)?;
        if jwt_secret.len() < 32 {
            return Err(crate::error::Error::Config(
                "FERRUM_ADMIN_JWT_SECRET must be at least 32 characters".to_string(),
            ));
        }

        // Timeouts prevent CI from hanging indefinitely when the gateway is
        // unreachable or slow. Defaults: connect 10s, total request 60s.
        // `/backup` on large configs or `/restore` on slow commits may need
        // the request timeout raised via env.
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(env.gateway_connect_timeout_secs))
            .timeout(Duration::from_secs(env.gateway_request_timeout_secs));

        if env.tls_no_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref ca_b64) = env.ca_cert {
            let ca_pem = base64::engine::general_purpose::STANDARD
                .decode(ca_b64)
                .map_err(|e| crate::error::Error::HttpClient(format!("CA cert decode: {e}")))?;
            let cert = reqwest::Certificate::from_pem(&ca_pem)
                .map_err(|e| crate::error::Error::HttpClient(format!("CA cert parse: {e}")))?;
            builder = builder
                .add_root_certificate(cert)
                .tls_built_in_root_certs(false);
        }

        match (env.client_cert.as_ref(), env.client_key.as_ref()) {
            (Some(cert_b64), Some(key_b64)) => {
                let cert_pem = base64::engine::general_purpose::STANDARD
                    .decode(cert_b64)
                    .map_err(|e| {
                        crate::error::Error::HttpClient(format!("client cert decode: {e}"))
                    })?;
                let key_pem = base64::engine::general_purpose::STANDARD
                    .decode(key_b64)
                    .map_err(|e| {
                        crate::error::Error::HttpClient(format!("client key decode: {e}"))
                    })?;
                let mut combined = cert_pem;
                combined.extend_from_slice(&key_pem);
                let identity = reqwest::Identity::from_pem(&combined)
                    .map_err(|e| crate::error::Error::HttpClient(format!("identity parse: {e}")))?;
                builder = builder.identity(identity);
            }
            (Some(_), None) => {
                return Err(crate::error::Error::Config(
                    "FERRUM_GATEWAY_CLIENT_CERT is set but FERRUM_GATEWAY_CLIENT_KEY is missing"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(crate::error::Error::Config(
                    "FERRUM_GATEWAY_CLIENT_KEY is set but FERRUM_GATEWAY_CLIENT_CERT is missing"
                        .to_string(),
                ));
            }
            (None, None) => {}
        }

        let client = builder
            .build()
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

        Ok(Self {
            client,
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            jwt_secret,
            jwt_options: JwtOptions::from_env(env),
            max_retries: env.gateway_max_retries,
            saw_cached_backup: AtomicBool::new(false),
        })
    }

    /// Narrow the `ns` claim minted into admin tokens to the namespaces this
    /// run actually touches. Only consulted by gateways running with
    /// `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true`; elsewhere it is inert.
    pub fn set_namespace_scope<I, S>(&mut self, namespaces: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.jwt_options = self.jwt_options.clone().with_namespaces(namespaces);
    }

    /// True when any `/backup` in this run was served from the in-memory
    /// snapshot rather than the config database.
    pub fn served_from_cache(&self) -> bool {
        self.saw_cached_backup.load(Ordering::Relaxed)
    }

    fn token(&self) -> crate::error::Result<String> {
        jwt::mint_jwt(&self.jwt_secret, &self.jwt_options)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.gateway_url, path)
    }

    /// Send an HTTP request with automatic retry on transient failures.
    ///
    /// The retry decision is made by [`classify_retry`] from the status code
    /// and the parsed error body, so semantics like "durably committed but not
    /// live" (`applied: false`) and "rollback incomplete" are honoured rather
    /// than blindly re-sending. `Retry-After` is respected when present,
    /// capped at [`RETRY_AFTER_CAP`].
    ///
    /// Request timeouts are still NOT retried — their state is ambiguous (the
    /// write may have applied). The higher-level workflow re-runs safely
    /// because `apply_incremental` re-diffs against live state.
    async fn send_with_retry<F>(
        &self,
        kind: RequestKind,
        build: F,
    ) -> crate::error::Result<RawResponse>
    where
        F: Fn() -> RequestBuilder,
    {
        let max_attempts = self.max_retries.saturating_add(1);
        let mut last_error: Option<String> = None;

        for attempt in 1..=max_attempts {
            match build().send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let data_source = header_string(&resp, "x-data-source");
                    let retry_after = parse_retry_after(header_string(&resp, "retry-after"));
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| String::from("<no body>"));

                    if status < 400 {
                        return Ok(RawResponse {
                            status,
                            body,
                            data_source,
                        });
                    }

                    let parsed = ApiErrorBody::parse(&body);
                    let retryable = classify_retry(status, &parsed, kind) == RetryDecision::Retry;
                    if retryable && attempt < max_attempts {
                        last_error = Some(format!("HTTP {status}"));
                        match retry_after {
                            Some(delay) => tokio::time::sleep(delay).await,
                            None => backoff_sleep(attempt).await,
                        }
                        continue;
                    }
                    return Ok(RawResponse {
                        status,
                        body,
                        data_source,
                    });
                }
                Err(e) if e.is_connect() && attempt < max_attempts => {
                    last_error = Some(e.to_string());
                    backoff_sleep(attempt).await;
                }
                Err(e) => return Err(crate::error::Error::HttpClient(e.to_string())),
            }
        }

        Err(crate::error::Error::HttpClient(format!(
            "retries exhausted after {max_attempts} attempts: {}",
            last_error.unwrap_or_else(|| "unknown".to_string())
        )))
    }

    /// Turn a completed response into `Ok(())` or a typed error.
    fn check(&self, resp: &RawResponse, kind: RequestKind) -> crate::error::Result<()> {
        if resp.status < 400 {
            return Ok(());
        }
        Err(map_api_error(resp.status, &resp.body, kind))
    }

    /// Authenticated `GET /health`. Carries `mode`, `ready` and
    /// `admin_writes_enabled` — the ahead-of-time signal for read-only mode.
    pub async fn get_health(&self) -> crate::error::Result<HealthStatus> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                self.client.get(self.url("/health")).bearer_auth(&token)
            })
            .await?;
        self.check(&resp, RequestKind::Read)?;
        serde_json::from_str::<HealthStatus>(&resp.body)
            .map_err(|e| crate::error::Error::HttpClient(format!("GET /health: {e}")))
    }

    /// Authenticated `GET /cluster`. CP/DP connection state, used for the
    /// best-effort post-apply convergence report.
    ///
    /// Advisory only: every caller must treat a failure as "unknown", never as
    /// an apply failure. Database/file-mode gateways answer with an
    /// informational `{mode, message}` rather than an error.
    pub async fn get_cluster(&self) -> crate::error::Result<ClusterStatus> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                self.client.get(self.url("/cluster")).bearer_auth(&token)
            })
            .await?;
        self.check(&resp, RequestKind::Read)?;
        serde_json::from_str::<ClusterStatus>(&resp.body)
            .map_err(|e| crate::error::Error::HttpClient(format!("GET /cluster: {e}")))
    }

    /// Fetch the namespace's live configuration plus the backup-only sections
    /// (`api_specs`, `gateway_trust_bundles`) that `GatewayConfig` does not
    /// model.
    pub async fn get_backup_snapshot(
        &self,
        namespace: &str,
    ) -> crate::error::Result<BackupSnapshot> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                self.client
                    .get(self.url("/backup"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        self.check(&resp, RequestKind::Read)?;

        let cached = resp
            .data_source
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("cached"))
            .unwrap_or(false);
        if cached {
            self.saw_cached_backup.store(true, Ordering::Relaxed);
        }

        let mut snapshot = BackupSnapshot::from_body(&resp.body)?;
        snapshot.cached = cached;
        Ok(snapshot)
    }

    /// Convenience wrapper for callers that only need the four managed
    /// resource kinds. Backup-only sections are dropped; use
    /// [`AdminClient::get_backup_snapshot`] when they matter.
    pub async fn get_backup(&self, namespace: &str) -> crate::error::Result<GatewayConfig> {
        Ok(self.get_backup_snapshot(namespace).await?.config)
    }

    /// List every namespace the token can see, following pagination.
    ///
    /// `GET /namespaces` answers `{data, pagination}` with a default page size
    /// of 100 (max 1000). Requesting the max and looping until the reported
    /// total is covered keeps `import --from-api` from silently truncating.
    pub async fn list_namespaces(&self) -> crate::error::Result<Vec<String>> {
        let token = self.token()?;
        let mut pages: Vec<Vec<String>> = Vec::new();
        let mut offset: i64 = 0;
        let mut accumulated: usize = 0;

        loop {
            let path = format!("/namespaces?offset={offset}&limit={LIST_PAGE_LIMIT}");
            let resp = self
                .send_with_retry(RequestKind::Read, || {
                    self.client.get(self.url(&path)).bearer_auth(&token)
                })
                .await?;
            self.check(&resp, RequestKind::Read)?;

            let page: Page<String> = serde_json::from_str(&resp.body)
                .map_err(|e| crate::error::Error::HttpClient(format!("GET /namespaces: {e}")))?;
            let total = page.pagination.as_ref().map(|p| p.total);
            let received = page.data.len();
            accumulated += received;
            pages.push(page.data);

            match next_page_offset(offset, received, total, accumulated) {
                Some(next) => offset = next,
                None => break,
            }
        }

        Ok(merge_pages(pages))
    }

    /// Replace a namespace's configuration atomically.
    ///
    /// `extras` carries the live `api_specs` / `gateway_trust_bundles` sections
    /// straight back through, so a full replace does not destroy resources that
    /// gitforgeops does not model. With `confirm_api_spec_deletion` the
    /// sections are dropped and the destructive opt-in is passed on the query
    /// string instead.
    pub async fn post_restore(
        &self,
        config: &GatewayConfig,
        namespace: &str,
        extras: &BackupExtras,
        confirm_api_spec_deletion: bool,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let body = build_restore_body(config, extras, confirm_api_spec_deletion)?;
        let path = if confirm_api_spec_deletion {
            "/restore?confirm=true&confirm_api_spec_deletion=true"
        } else {
            "/restore?confirm=true"
        };
        let resp = self
            .send_with_retry(RequestKind::Restore, || {
                self.client
                    .post(self.url(path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(&body)
            })
            .await?;
        self.check(&resp, RequestKind::Restore)
    }

    /// Create-only bulk import. All-or-nothing in one transaction; it cannot
    /// update, so callers must only send pure-Add sets.
    ///
    /// Returns `Ok(None)` on **501**, which standalone-MongoDB gateways answer
    /// with because they have no multi-document transaction — the caller falls
    /// back to per-resource CRUD.
    pub async fn post_batch(
        &self,
        batch: &BatchCreate,
        namespace: &str,
    ) -> crate::error::Result<Option<BatchCreated>> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .post(self.url("/batch"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(batch)
            })
            .await?;

        if resp.status == 501 {
            return Ok(None);
        }
        self.check(&resp, RequestKind::Mutation)?;

        // 201 `{"created": {...}}`. A gateway that answers 200 with no body is
        // still a success — fall back to the counts we sent.
        let created = serde_json::from_str::<BatchResponse>(&resp.body)
            .map(|r| r.created)
            .unwrap_or_else(|_| batch.counts());
        Ok(Some(created))
    }

    pub async fn create_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .post(self.url("/proxies"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(proxy)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn update_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        validate_resource_id_for_path(&proxy.id)?;
        let path = format!("/proxies/{}", proxy.id);
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(proxy)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    /// Delete a proxy without the server-side orphan cleanup.
    ///
    /// `cleanup_orphaned_upstream` defaults to `true` server-side: deleting a
    /// proxy also deletes the last-referenced hand-owned upstream. That
    /// invisible cascade makes the *next* diff-driven `DELETE /upstreams/{id}`
    /// answer 404 and wedges the run. gitforgeops owns the upstream lifecycle
    /// through its own diff, so it opts out and issues the upstream delete
    /// itself.
    pub async fn delete_proxy(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        validate_resource_id_for_path(id)?;
        let path = format!("/proxies/{id}?cleanup_orphaned_upstream=false");
        self.delete(&path, namespace).await
    }

    pub async fn create_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .post(self.url("/consumers"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(consumer)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn update_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        validate_resource_id_for_path(&consumer.id)?;
        let path = format!("/consumers/{}", consumer.id);
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(consumer)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn delete_consumer(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        validate_resource_id_for_path(id)?;
        let path = format!("/consumers/{id}");
        self.delete(&path, namespace).await
    }

    pub async fn create_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .post(self.url("/upstreams"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(upstream)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn update_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        validate_resource_id_for_path(&upstream.id)?;
        let path = format!("/upstreams/{}", upstream.id);
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(upstream)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn delete_upstream(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        validate_resource_id_for_path(id)?;
        let path = format!("/upstreams/{id}");
        self.delete(&path, namespace).await
    }

    pub async fn create_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .post(self.url("/plugins/config"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(pc)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn update_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        validate_resource_id_for_path(&pc.id)?;
        let path = format!("/plugins/config/{}", pc.id);
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(pc)
            })
            .await?;
        self.check(&resp, RequestKind::Mutation)
    }

    pub async fn delete_plugin_config(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<()> {
        validate_resource_id_for_path(id)?;
        let path = format!("/plugins/config/{id}");
        self.delete(&path, namespace).await
    }

    /// Shared DELETE path with 404 tolerance — see [`delete_succeeded`].
    async fn delete(&self, path: &str, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                self.client
                    .delete(self.url(path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        if delete_succeeded(resp.status) {
            return Ok(());
        }
        Err(map_api_error(
            resp.status,
            &resp.body,
            RequestKind::Mutation,
        ))
    }
}

// --- Response plumbing -------------------------------------------------------

/// A fully-read response. The body is buffered eagerly so the retry classifier
/// can inspect it before deciding whether to re-send.
#[derive(Debug, Clone)]
struct RawResponse {
    status: u16,
    body: String,
    data_source: Option<String>,
}

/// What kind of call is being made, for retry/error classification. `/restore`
/// gets its own kind because a failed restore has rollback semantics no other
/// endpoint shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Read,
    Mutation,
    Restore,
}

/// The admin API's shared error envelope. Every field is optional — the
/// gateway populates the subset relevant to the failure.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiErrorBody {
    #[serde(default)]
    pub error: Option<String>,
    /// `false` ⇒ the write is durable but not live yet. Retrying re-applies it.
    #[serde(default)]
    pub applied: Option<bool>,
    /// `config_rejected` | `reload_timeout` | `sequence_unavailable`.
    #[serde(default)]
    pub reason: Option<String>,
    /// `/restore` only: `completed` | `incomplete` | `not_needed` | `unknown_outcome`.
    #[serde(default)]
    pub rollback: Option<String>,
    /// `/restore` only: `connectivity` | `data_integrity`.
    #[serde(default)]
    pub failure_class: Option<String>,
    #[serde(default)]
    pub restore_errors: Option<Vec<serde_json::Value>>,
    /// Present on the 409 that guards API specs from a full replace.
    #[serde(default)]
    pub api_specs_at_risk: Option<serde_json::Value>,
    #[serde(default)]
    pub confirmation_required: Option<String>,
}

impl ApiErrorBody {
    /// Parse an error body, degrading to an empty envelope for non-JSON
    /// responses (proxies and load balancers emit HTML).
    pub fn parse(body: &str) -> Self {
        serde_json::from_str(body).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    Retry,
    NoRetry,
}

/// Decide whether a failed request may be re-sent.
///
/// Retryable statuses are connect failures (handled by the caller), 408, 429,
/// 500, 502, 503 and 504. **501 is never retried** — a standalone-MongoDB
/// gateway will answer it forever. Body markers override the status:
///
/// - `applied: false` ⇒ the write is durably committed but not live. Retrying
///   re-applies it (and a create answers 409 on the second attempt).
/// - `/restore` 500 with `rollback: incomplete | unknown_outcome` ⇒ the
///   namespace may be half-restored; a retry re-runs a destructive replace.
/// - `/restore` 503 with `failure_class: connectivity` ⇒ nothing was written,
///   safe to retry.
pub fn classify_retry(status: u16, body: &ApiErrorBody, kind: RequestKind) -> RetryDecision {
    if status == 501 {
        return RetryDecision::NoRetry;
    }
    if body.applied == Some(false) {
        return RetryDecision::NoRetry;
    }
    if kind == RequestKind::Restore {
        if status == 500 && rollback_needs_manual_recovery(body.rollback.as_deref()) {
            return RetryDecision::NoRetry;
        }
        if status == 503 && body.failure_class.as_deref() == Some("connectivity") {
            return RetryDecision::Retry;
        }
    }
    match status {
        408 | 429 | 500 | 502 | 503 | 504 => RetryDecision::Retry,
        _ => RetryDecision::NoRetry,
    }
}

fn rollback_needs_manual_recovery(rollback: Option<&str>) -> bool {
    matches!(rollback, Some("incomplete") | Some("unknown_outcome"))
}

/// A DELETE that answers 404 already achieved its goal. The gateway cascades
/// deletes server-side (proxy delete removes its scoped plugin configs), so a
/// diff-driven follow-up delete legitimately finds nothing. Treating it as an
/// error left the state entry in place and wedged every later run on the same
/// delete.
pub fn delete_succeeded(status: u16) -> bool {
    status < 400 || status == 404
}

/// Map a failing response to the most specific error variant available.
pub fn map_api_error(status: u16, body: &str, kind: RequestKind) -> crate::error::Error {
    let parsed = ApiErrorBody::parse(body);
    let message = parsed.error.clone().unwrap_or_else(|| body.to_string());

    if status == 403 && message.trim() == READ_ONLY_MESSAGE {
        return crate::error::Error::GatewayReadOnly(
            "the gateway rejected a config mutation with \"Admin API is in read-only mode\" \
             (FERRUM_ADMIN_READ_ONLY, an unavailable config database, or a file/dp/mesh/node_agent \
             gateway). No further resources were attempted."
                .to_string(),
        );
    }

    if status == 409 && parsed.api_specs_at_risk.is_some() {
        let at_risk = describe_api_specs_at_risk(&parsed.api_specs_at_risk);
        return crate::error::Error::ApiSpecsAtRisk(format!(
            "full_replace refused: the namespace holds API spec(s) this payload would delete ({at_risk}). \
             API specs are managed through the admin API, not this repo. Either keep them (the default: \
             gitforgeops carries the live `api_specs` section through the restore) or re-run \
             `gitforgeops apply --confirm-api-spec-deletion` to delete them deliberately. Gateway said: {message}"
        ));
    }

    if kind == RequestKind::Restore
        && status == 500
        && rollback_needs_manual_recovery(parsed.rollback.as_deref())
    {
        let rollback = parsed.rollback.as_deref().unwrap_or("unknown");
        let details = summarize_restore_errors(&parsed.restore_errors);
        return crate::error::Error::RestoreNeedsManualRecovery(format!(
            "rollback={rollback}; the namespace may hold a partially restored configuration. \
             Do NOT re-run apply — inspect the gateway with `gitforgeops diff`, restore from a known \
             backup if needed, then reconcile. Gateway said: {message}{details}"
        ));
    }

    if parsed.applied == Some(false) {
        return crate::error::Error::CommittedNotLive {
            reason: parsed
                .reason
                .clone()
                .unwrap_or_else(|| "unspecified".to_string()),
            message: format!(
                "{message} — the change is persisted but the running gateway has not picked it up. \
                 Re-applying would re-send an already-committed write; check gateway health instead."
            ),
        };
    }

    if status == 413 {
        return crate::error::Error::ApiError {
            status,
            message: format!(
                "{message} — payload exceeds the gateway's restore body limit \
                 (FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB, default 100 MiB). Split the namespace or \
                 switch to the incremental apply strategy."
            ),
        };
    }

    crate::error::Error::ApiError {
        status,
        message: if parsed.error.is_some() {
            message
        } else {
            body.to_string()
        },
    }
}

fn describe_api_specs_at_risk(at_risk: &Option<serde_json::Value>) -> String {
    match at_risk {
        Some(serde_json::Value::Array(items)) => format!("{} spec(s)", items.len()),
        Some(serde_json::Value::Number(n)) => format!("{n} spec(s)"),
        Some(other) => other.to_string(),
        None => "count unknown".to_string(),
    }
}

fn summarize_restore_errors(errors: &Option<Vec<serde_json::Value>>) -> String {
    match errors {
        Some(list) if !list.is_empty() => format!(
            "\nrestore_errors: {}",
            list.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        _ => String::new(),
    }
}

fn header_string(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

/// `Retry-After` in delta-seconds form, clamped to [`RETRY_AFTER_CAP`]. The
/// HTTP-date form is ignored — the admin API only emits seconds.
fn parse_retry_after(raw: Option<String>) -> Option<Duration> {
    let secs: u64 = raw?.trim().parse().ok()?;
    Some(Duration::from_secs(secs).min(RETRY_AFTER_CAP))
}

// --- Pagination --------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Pagination {
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub limit: i64,
    #[serde(default)]
    pub total: i64,
}

/// The `{data, pagination}` envelope every admin list endpoint returns.
#[derive(Debug, Clone, Deserialize)]
pub struct Page<T> {
    #[serde(default = "Vec::new")]
    pub data: Vec<T>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

/// Offset of the next page, or `None` when the listing is complete.
///
/// Terminates on an empty page (a server that ignores `offset` would otherwise
/// loop forever), on a non-advancing offset, on a missing pagination envelope,
/// and once the accumulated count covers the reported total.
pub fn next_page_offset(
    requested_offset: i64,
    received: usize,
    total: Option<i64>,
    accumulated: usize,
) -> Option<i64> {
    if received == 0 {
        return None;
    }
    let total = total?;
    if accumulated as i64 >= total {
        return None;
    }
    let next = requested_offset.saturating_add(received as i64);
    if next <= requested_offset {
        return None;
    }
    Some(next)
}

/// Flatten paged results, dropping duplicates while preserving first-seen
/// order. Namespaces are a union of registry rows and derived resource
/// namespaces, so a row can legitimately appear twice across page boundaries
/// if the set shifts mid-listing.
pub fn merge_pages(pages: Vec<Vec<String>>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();
    for page in pages {
        for item in page {
            if seen.insert(item.clone()) {
                merged.push(item);
            }
        }
    }
    merged
}

// --- Backup / restore --------------------------------------------------------

/// Sections of `GET /backup` that `GatewayConfig` deliberately does not model.
/// Held as opaque JSON so they can be carried back through `/restore` verbatim
/// without this tool having to understand (or version) their schema.
#[derive(Debug, Clone, Default)]
pub struct BackupExtras {
    /// `{section_version, items}`. Absent on cached-fallback exports.
    pub api_specs: Option<serde_json::Value>,
    /// Array; namespace singleton. Three-valued on restore: absent = no-op,
    /// present-empty = revoke, present non-empty = authoritative.
    pub gateway_trust_bundles: Option<serde_json::Value>,
}

impl BackupExtras {
    /// Number of API spec documents carried, for reporting.
    pub fn api_spec_count(&self) -> usize {
        match self.api_specs.as_ref().and_then(|v| v.get("items")) {
            Some(serde_json::Value::Array(items)) => items.len(),
            _ => 0,
        }
    }

    /// Number of trust-bundle records carried, for reporting.
    pub fn trust_bundle_count(&self) -> usize {
        match self.gateway_trust_bundles.as_ref() {
            Some(serde_json::Value::Array(items)) => items.len(),
            Some(_) => 1,
            None => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.api_specs.is_none() && self.gateway_trust_bundles.is_none()
    }
}

/// The full `BackupResponse` envelope.
#[derive(Debug, Clone, Default)]
pub struct BackupSnapshot {
    pub config: GatewayConfig,
    pub extras: BackupExtras,
    /// `X-Data-Source: cached` — the gateway served its in-memory snapshot
    /// because the config database was unavailable.
    pub cached: bool,
    pub ferrum_version: Option<String>,
    pub exported_at: Option<String>,
    pub source: Option<String>,
}

impl BackupSnapshot {
    /// Parse a backup body. The four managed sections deserialize into the
    /// permissive `GatewayConfig`; the rest is picked out by key so unknown
    /// future metadata is simply ignored.
    pub fn from_body(body: &str) -> crate::error::Result<Self> {
        let value: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| crate::error::Error::HttpClient(format!("GET /backup: {e}")))?;
        let config: GatewayConfig = serde_json::from_value(value.clone())
            .map_err(|e| crate::error::Error::HttpClient(format!("GET /backup: {e}")))?;

        let take = |key: &str| value.get(key).cloned();
        let text = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };

        Ok(Self {
            config,
            extras: BackupExtras {
                api_specs: take("api_specs"),
                gateway_trust_bundles: take("gateway_trust_bundles"),
            },
            cached: false,
            ferrum_version: text("ferrum_version"),
            exported_at: text("exported_at"),
            source: text("source"),
        })
    }
}

/// Build the `POST /restore` body.
///
/// `RestoreRequest` has no `additionalProperties: false`, so the serialized
/// `GatewayConfig` (including `version`, which the gateway validates against
/// `CURRENT_CONFIG_VERSION`) is accepted as-is. The backup-only sections are
/// spliced in as opaque values rather than being modeled on `GatewayConfig` —
/// that struct mirrors what this tool manages, and API specs are not it.
pub fn build_restore_body(
    config: &GatewayConfig,
    extras: &BackupExtras,
    confirm_api_spec_deletion: bool,
) -> crate::error::Result<serde_json::Value> {
    let mut body = serde_json::to_value(config)?;
    let serde_json::Value::Object(map) = &mut body else {
        return Err(crate::error::Error::Config(
            "gateway config did not serialize as a JSON object".to_string(),
        ));
    };

    if confirm_api_spec_deletion {
        // Explicit destructive opt-in: omit the sections so the restore wipes
        // them, and let the caller pass `confirm_api_spec_deletion=true`.
        return Ok(body);
    }

    if let Some(api_specs) = extras.api_specs.clone() {
        map.insert("api_specs".to_string(), api_specs);
    }
    if let Some(bundles) = extras.gateway_trust_bundles.clone() {
        map.insert("gateway_trust_bundles".to_string(), bundles);
    }
    Ok(body)
}

// --- Batch -------------------------------------------------------------------

/// `POST /batch` payload. Create-only, `additionalProperties: false`, so only
/// the four resource arrays are sent — no `version`, no backup metadata.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BatchCreate {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<Upstream>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<Consumer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<Proxy>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plugin_configs: Vec<PluginConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub struct BatchCreated {
    #[serde(default)]
    pub proxies: usize,
    #[serde(default)]
    pub consumers: usize,
    #[serde(default)]
    pub plugin_configs: usize,
    #[serde(default)]
    pub upstreams: usize,
}

impl BatchCreated {
    pub fn total(&self) -> usize {
        self.proxies + self.consumers + self.plugin_configs + self.upstreams
    }
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    #[serde(default)]
    created: BatchCreated,
}

impl BatchCreate {
    pub fn len(&self) -> usize {
        self.upstreams.len() + self.consumers.len() + self.proxies.len() + self.plugin_configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn counts(&self) -> BatchCreated {
        BatchCreated {
            proxies: self.proxies.len(),
            consumers: self.consumers.len(),
            plugin_configs: self.plugin_configs.len(),
            upstreams: self.upstreams.len(),
        }
    }
}

/// Split a batch so no single request exceeds the gateway's 1 MiB body cap.
///
/// Items are packed in dependency order (upstreams and consumers, then
/// proxies, then plugin configs), so a chunk boundary never puts a proxy in an
/// earlier request than the upstream it references. Each chunk is still
/// all-or-nothing on its own; the caller reports partial progress if a later
/// chunk fails.
///
/// A single item larger than the cap is emitted in a chunk of its own — the
/// gateway will reject it with 413, which is a clearer diagnostic than a
/// silent drop.
pub fn split_batch(
    batch: &BatchCreate,
    max_bytes: usize,
) -> crate::error::Result<Vec<BatchCreate>> {
    let budget = max_bytes.saturating_sub(BATCH_ENVELOPE_OVERHEAD).max(1);

    enum Item<'a> {
        Upstream(&'a Upstream),
        Consumer(&'a Consumer),
        Proxy(&'a Proxy),
        PluginConfig(&'a PluginConfig),
    }

    let mut ordered: Vec<(Item<'_>, usize)> = Vec::with_capacity(batch.len());
    for u in &batch.upstreams {
        ordered.push((Item::Upstream(u), serde_json::to_vec(u)?.len()));
    }
    for c in &batch.consumers {
        ordered.push((Item::Consumer(c), serde_json::to_vec(c)?.len()));
    }
    for p in &batch.proxies {
        ordered.push((Item::Proxy(p), serde_json::to_vec(p)?.len()));
    }
    for pc in &batch.plugin_configs {
        ordered.push((Item::PluginConfig(pc), serde_json::to_vec(pc)?.len()));
    }

    let mut chunks: Vec<BatchCreate> = Vec::new();
    let mut current = BatchCreate::default();
    let mut current_bytes = 0usize;

    for (item, size) in ordered {
        // `+ 1` accounts for the array separator between entries.
        if !current.is_empty() && current_bytes + size + 1 > budget {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        match item {
            Item::Upstream(u) => current.upstreams.push(u.clone()),
            Item::Consumer(c) => current.consumers.push(c.clone()),
            Item::Proxy(p) => current.proxies.push(p.clone()),
            Item::PluginConfig(pc) => current.plugin_configs.push(pc.clone()),
        }
        current_bytes += size + 1;
    }

    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
}

// --- Health ------------------------------------------------------------------

/// Authenticated `GET /health` projection. Only the fields gitforgeops acts on
/// are modeled; the endpoint returns considerably more.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HealthStatus {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub ready: Option<bool>,
    /// `cp`, `dp`, `database`, `file`, `mesh`, `node_agent`.
    #[serde(default)]
    pub mode: Option<String>,
    /// `false` ⇒ config-database mutations are refused right now.
    #[serde(default)]
    pub admin_writes_enabled: Option<bool>,
    #[serde(default)]
    pub config_rejected: Option<bool>,
}

/// Reason the gateway will refuse config writes, or `None` when it accepts
/// them. Runs before any mutation so an apply fails once, clearly, instead of
/// N times with a per-resource 403.
///
/// `admin_writes_enabled` is authoritative when present. Mode is a second
/// gate: file/dp/mesh/node_agent gateways are read-only unconditionally, and
/// older builds may not report the flag at all.
pub fn write_block_reason(health: &HealthStatus) -> Option<String> {
    if let Some(mode) = health.mode.as_deref() {
        let normalized = mode.to_ascii_lowercase();
        if READ_ONLY_MODES.contains(&normalized.as_str()) {
            return Some(format!(
                "gateway is running in `{mode}` mode, where the admin API never accepts config \
                 mutations. Point FERRUM_GATEWAY_URL at a database/cp-mode gateway, or switch \
                 FERRUM_GATEWAY_MODE=file and publish a config file instead."
            ));
        }
    }
    if health.admin_writes_enabled == Some(false) {
        return Some(format!(
            "GET /health reports admin_writes_enabled=false (status={}, mode={}). The admin API is \
             in read-only mode, its config database is unavailable, or the active failover pool \
             disallows writes.",
            health.status.as_deref().unwrap_or("unknown"),
            health.mode.as_deref().unwrap_or("unknown"),
        ));
    }
    None
}

// --- Cluster / convergence ---------------------------------------------------

/// `GET /cluster`, modeled loosely.
///
/// The endpoint returns one of three shapes (CP, DP, or an informational
/// `{mode, message}` for database/file gateways). Rather than a tagged enum
/// that breaks on an unknown `mode`, every field is optional and the union is
/// flattened: a shape this build has never seen still deserializes, and
/// [`convergence_summary`] just reports less.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClusterStatus {
    /// `cp` | `dp` | `database` | `file` | …
    #[serde(default)]
    pub mode: Option<String>,
    /// Set on the informational (non-CP/DP) shape.
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub connected_data_planes: Option<u64>,
    #[serde(default)]
    pub data_planes: Vec<ClusterNode>,
    #[serde(default)]
    pub connected_mesh_nodes: Option<u64>,
    #[serde(default)]
    pub mesh_nodes: Vec<ClusterNode>,
    /// DP mode: this node's view of its control plane.
    #[serde(default)]
    pub control_plane: Option<ControlPlaneStatus>,
}

/// A connected data-plane or mesh node as the CP reports it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClusterNode {
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub connected_at: Option<String>,
    /// RFC 3339. When the CP last broadcast config to this node.
    #[serde(default)]
    pub last_sync_at: Option<String>,
    /// Not in the CP-mode schema today, but read if a build starts reporting
    /// per-node divergence — the warning is worth surfacing wherever it shows.
    #[serde(default)]
    pub config_diverged: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ControlPlaneStatus {
    #[serde(default)]
    pub url: Option<String>,
    /// `online` | `offline`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub is_primary: Option<bool>,
    #[serde(default)]
    pub connected_since: Option<String>,
    #[serde(default)]
    pub last_config_received_at: Option<String>,
    /// Sticky: a non-empty ConfigSync delta was rejected and no authoritative
    /// snapshot has landed since.
    #[serde(default)]
    pub config_diverged: Option<bool>,
    #[serde(default)]
    pub config_diverged_since: Option<String>,
    #[serde(default)]
    pub config_divergence_recoveries_total: Option<u64>,
}

/// Text shown when `/cluster` could not be reached or parsed. Never a failure —
/// convergence is advisory, and a gateway that does not serve `/cluster` is
/// perfectly healthy.
pub const CONVERGENCE_UNAVAILABLE: &str = "convergence status unavailable";

impl ClusterStatus {
    /// Number of connected nodes, preferring the CP's own counters over the
    /// array lengths (they can disagree if a node disconnects mid-serialize).
    fn node_counts(&self) -> (u64, u64) {
        (
            self.connected_data_planes
                .unwrap_or(self.data_planes.len() as u64),
            self.connected_mesh_nodes
                .unwrap_or(self.mesh_nodes.len() as u64),
        )
    }

    fn nodes(&self) -> impl Iterator<Item = &ClusterNode> {
        self.data_planes.iter().chain(self.mesh_nodes.iter())
    }

    fn diverged(&self) -> bool {
        self.nodes().any(|n| n.config_diverged == Some(true))
            || self
                .control_plane
                .as_ref()
                .and_then(|cp| cp.config_diverged)
                == Some(true)
    }
}

/// One-line post-apply convergence report.
///
/// Pure, so the wording is unit-testable without a gateway. Callers hand it
/// whatever `/cluster` returned; anything the response does not carry is simply
/// left out of the line.
pub fn convergence_summary(status: &ClusterStatus) -> String {
    let mode = status.mode.as_deref().unwrap_or("unknown");

    if let Some(cp) = &status.control_plane {
        let mut line = format!(
            "convergence: mode={mode}, control plane {} is {}",
            cp.url.as_deref().unwrap_or("<unknown url>"),
            cp.status.as_deref().unwrap_or("unknown"),
        );
        if let Some(at) = &cp.last_config_received_at {
            line.push_str(&format!("; last config received {at}"));
        }
        if cp.config_diverged == Some(true) {
            line.push_str(&format!(
                "; WARNING: config_diverged since {}",
                cp.config_diverged_since.as_deref().unwrap_or("unknown")
            ));
        }
        return line;
    }

    let (data_planes, mesh_nodes) = status.node_counts();
    if data_planes == 0 && mesh_nodes == 0 && status.control_plane.is_none() {
        // Database/file-mode gateways answer `{mode, message}` — there is no
        // cluster to converge, which is information, not a warning.
        return match status.message.as_deref() {
            Some(message) => format!("convergence: mode={mode} ({message})"),
            None => format!("convergence: mode={mode}, no connected nodes reported"),
        };
    }

    let mut line = format!(
        "convergence: mode={mode}, {data_planes} data-plane node(s), {mesh_nodes} mesh node(s) connected"
    );
    match oldest_last_sync(status) {
        Some(oldest) => line.push_str(&format!("; oldest last_sync_at {oldest}")),
        None => line.push_str("; no last_sync_at reported"),
    }
    if status.diverged() {
        line.push_str("; WARNING: at least one node reports config_diverged");
    }
    line
}

/// The least-recently-synced node's `last_sync_at`, echoed back in its original
/// spelling.
///
/// Ordering is done on the parsed instant rather than the raw string, so a node
/// reporting a non-UTC offset does not sort as if it were UTC. Values that do
/// not parse as RFC 3339 are ignored — the summary is advisory and a garbage
/// stamp should not become the headline.
fn oldest_last_sync(status: &ClusterStatus) -> Option<&str> {
    status
        .nodes()
        .filter_map(|n| {
            let raw = n.last_sync_at.as_deref()?;
            let parsed = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
            Some((parsed, raw))
        })
        .min_by_key(|(parsed, _)| *parsed)
        .map(|(_, raw)| raw)
}

// --- Path safety -------------------------------------------------------------

/// Longest resource id the gateway accepts in a path segment.
const MAX_RESOURCE_ID_LEN: usize = 254;

/// Enforce the server's resource-id grammar before interpolating an id into a
/// URL path: `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`, at most 254 characters.
///
/// Aligned exactly with the gateway rather than merely being stricter, so an id
/// this tool accepts is one the gateway will accept too — and no id can smuggle
/// a `/`, `..` or query string into a different endpoint.
fn validate_resource_id_for_path(id: &str) -> crate::error::Result<()> {
    if id.is_empty() {
        return Err(crate::error::Error::Config(
            "resource id cannot be empty when used in API path".to_string(),
        ));
    }

    if id.chars().count() > MAX_RESOURCE_ID_LEN {
        return Err(crate::error::Error::Config(format!(
            "resource id exceeds the {MAX_RESOURCE_ID_LEN}-character limit: {id}",
        )));
    }

    let mut chars = id.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));

    if !first_ok || !rest_ok {
        return Err(crate::error::Error::Config(format!(
            "resource id contains unsafe characters for API path segment: {id} \
             (must match ^[a-zA-Z0-9][a-zA-Z0-9._-]*$)",
        )));
    }

    Ok(())
}

async fn backoff_sleep(attempt: u32) {
    // Full-jitter backoff based on 500ms · 2^(attempt-1), capped at 8s.
    // Keep a small floor so retries never hammer a recovering gateway with an
    // immediate zero-delay retry.
    let exp = attempt.saturating_sub(1).min(4);
    let cap_ms = (500u64 * (1u64 << exp)).min(8_000);
    let delay_ms = rand::random_range(100..=cap_ms.max(100));
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}
