use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};

use crate::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::config::EnvConfig;
use crate::config_export::ConfigExport;
use crate::diagnostics::{safe, safe_line};
use crate::jwt::{self, JwtOptions};

pub mod conditional;
use conditional::{ConsumerEvidence, ConditionalMetadata};

/// Most namespaces [`AdminClient::issues_entity_tags`] looks in for a row.
const ENTITY_TAG_PROBE_NAMESPACES: usize = 20;

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

/// Marker substring of the read-only refusal body the admin API returns for
/// config mutations. The canonical wording is
/// `"Admin API is in read-only mode"`, but the phrase reaches us wrapped in
/// several ways — prefixed by a middlebox, re-cased, or embedded in a longer
/// sentence by a newer build — so the classifier matches the distinctive part
/// case-insensitively rather than demanding the exact string.
const READ_ONLY_MARKER: &str = "read-only mode";

/// Gateway modes in which the admin API refuses config writes unconditionally,
/// regardless of `FERRUM_ADMIN_READ_ONLY`.
const READ_ONLY_MODES: [&str; 4] = ["file", "dp", "mesh", "node_agent"];

/// Client for the Ferrum Edge Admin API.
///
/// The client owns a reusable `reqwest::Client`, so per-command gateway calls
/// share connection pooling, TLS configuration, JWT auth, and retry behavior.
pub struct AdminClient {
    client: Client,
    gateway_url: url::Url,
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
    ///
    /// Private on purpose. A client built here mints admin tokens with no `ns`
    /// claim, which a gateway running `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM`
    /// rejects outright — and, worse, which a gateway *not* running it accepts
    /// for every namespace. [`AdminClient::new_scoped`] is the only public
    /// door, so a new call site has to say what it is allowed to touch.
    ///
    /// Transport construction enforces HTTPS, or plaintext to a literal
    /// loopback IP without a proxy, even when `env` was constructed directly
    /// rather than through [`crate::config::env::validate_gateway_transport`].
    fn new(env: &EnvConfig) -> crate::error::Result<Self> {
        let (client, gateway_url) = Self::build_transport(env)?;
        let jwt_secret = env
            .admin_jwt_secret
            .clone()
            .ok_or(crate::error::Error::NoJwtSecret)?;
        if jwt_secret.len() < 32 {
            return Err(crate::error::Error::Config(format!(
                "FERRUM_ADMIN_JWT_SECRET must be at least 32 characters to match \
                 ferrum-edge's minimum (got {})",
                jwt_secret.len()
            )));
        }
        Ok(Self {
            client,
            gateway_url,
            jwt_secret,
            jwt_options: JwtOptions::from_env(env),
            max_retries: env.gateway_max_retries,
            saw_cached_backup: AtomicBool::new(false),
        })
    }

    /// Build a read-only client whose tokens are signed with
    /// `FERRUM_ADMIN_JWT_VIEWER_SECRET` and scoped to `namespaces`.
    ///
    /// The gateway authorizes a token that verifies under its viewer secret as
    /// `viewer` whatever the token claims, so this client can read
    /// [`AdminClient::get_config_export`] and `GET /namespaces` but every
    /// write, and `GET /backup`, answers `403`. The admin secret is neither
    /// needed nor used. The token claims `role: viewer` so the gateway's logs
    /// do not show a role the key cannot grant.
    ///
    /// Refused, naming the settings and never the values: a missing viewer
    /// secret, one shorter than the gateway's 32-character minimum, and one
    /// equal to `FERRUM_ADMIN_JWT_SECRET` (the gateway refuses that pairing at
    /// startup, and such a "viewer" key would really be the admin key).
    pub fn new_viewer_scoped<I, S>(env: &EnvConfig, namespaces: I) -> crate::error::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let (transport, gateway_url) = Self::build_transport(env)?;
        let viewer_secret = check_viewer_secret(env)?.to_string();
        let mut client = Self {
            client: transport,
            gateway_url,
            jwt_secret: viewer_secret,
            jwt_options: JwtOptions::from_env(env),
            max_retries: env.gateway_max_retries,
            saw_cached_backup: AtomicBool::new(false),
        };
        client.jwt_options.role = crate::config_export::VIEWER_ROLE.to_string();
        client.set_namespace_scope(namespaces);
        Ok(client)
    }

    /// Build transport independently of the signing key. HTTPS clients also
    /// reject plaintext at send time; the loopback exception bypasses proxies
    /// so an environment proxy cannot forward credentials to a remote host.
    fn build_transport(env: &EnvConfig) -> crate::error::Result<(Client, url::Url)> {
        let gateway_url = env
            .gateway_url
            .as_deref()
            .ok_or(crate::error::Error::NoGatewayUrl)?;
        let parsed = credential_target(gateway_url)?;
        // Timeouts prevent CI from hanging indefinitely when the gateway is
        // unreachable or slow. Defaults: connect 10s, total request 60s.
        // `/backup` on large configs or `/restore` on slow commits may need
        // the request timeout raised via env.
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(env.gateway_connect_timeout_secs))
            .timeout(Duration::from_secs(env.gateway_request_timeout_secs))
            // Admin mutations must never be redirected. Following a 301/302
            // can rewrite POST to GET, while following a 307/308 can replay a
            // destructive body against a different authority or path.
            .redirect(reqwest::redirect::Policy::none());

        if parsed.scheme() == "https" {
            builder = builder.https_only(true);
        } else {
            builder = builder.no_proxy();
        }

        // Dev-only, and gated well before here: `FERRUM_TLS_NO_VERIFY` warns
        // loudly on every run and is refused under `GITHUB_ACTIONS` for any
        // gateway host that is not loopback. A private CA belongs in
        // `FERRUM_GATEWAY_CA_CERT` (below) instead of here.
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

        let client = match builder.build() {
            Ok(client) => client,
            Err(error) => {
                let message = transport_error("building the gateway HTTP client", error);
                return Err(crate::error::Error::HttpClient(message));
            }
        };

        Ok((client, parsed))
    }

    /// Build a client whose JWTs are scoped to the exact namespaces the
    /// command has resolved.
    ///
    /// The only public constructor. Keeping scoping in construction makes it
    /// difficult for a new admin-API call site to accidentally mint an
    /// unscoped token on gateways that require the `ns` claim.
    ///
    /// An empty `namespaces` deliberately still builds a client — some
    /// commands legitimately have no namespace set to declare — but it mints
    /// an unscoped token, so pass the resolved set whenever one exists.
    pub fn new_scoped<I, S>(env: &EnvConfig, namespaces: I) -> crate::error::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut client = Self::new(env)?;
        client.set_namespace_scope(namespaces);
        Ok(client)
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
        let mut target = self.gateway_url.as_str().trim_end_matches('/').to_string();
        target.push_str(path);
        target
    }

    /// [`AdminClient::authorize`] for a path under the gateway URL.
    fn authorized(&self, path: &str) -> crate::error::Result<Authorized<'_>> {
        self.authorize(self.url(path))
    }

    /// The only way to build a request that carries the admin bearer token.
    ///
    /// The token is minted, and attached, only after `url` is shown to be
    /// `https://`, or cleartext `http://` to a literal loopback IP
    /// ([`credential_target`]). Every admin call builds its request
    /// through the returned [`Authorized`], so no call can send the token to a
    /// remote host in cleartext, whatever was configured.
    fn authorize(&self, target: String) -> crate::error::Result<Authorized<'_>> {
        let parsed = credential_target(&target)?;
        let token = self.token()?;
        Ok(Authorized {
            client: &self.client,
            url: parsed,
            token,
        })
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
        // Set once an attempt got an HTTP response and was retried anyway: the
        // gateway saw that attempt, which may have committed a write. A retry
        // after a connect error does not count; nothing was sent.
        let mut answered_before = false;

        for attempt in 1..=max_attempts {
            match build().send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let data_source = header_string(&resp, "x-data-source");
                    if resp.headers().get_all("x-data-source").iter().any(|value| {
                        value.to_str().is_ok_and(|source| source.eq_ignore_ascii_case("cached"))
                    }) {
                        self.saw_cached_backup.store(true, Ordering::Relaxed);
                    }
                    let location = header_string(&resp, "location");
                    let etag = header_string(&resp, "etag");
                    let cache_control = header_string(&resp, "cache-control");
                    let retry_after = parse_retry_after(header_string(&resp, "retry-after"));
                    let evidence_headers_valid = ["etag", "cache-control", "x-data-source"]
                        .iter()
                        .all(|name| {
                            let values = resp.headers().get_all(*name);
                            values.iter().count() <= 1
                                && values.iter().all(|value| value.to_str().is_ok())
                        });
                    let body = resp
                        .text()
                        .await
                        .unwrap_or_else(|_| String::from("<no body>"));

                    if is_success_status(status) {
                        return Ok(RawResponse {
                            status,
                            body,
                            data_source,
                            location,
                            etag,
                            cache_control,
                            evidence_headers_valid,
                            retried: answered_before,
                        });
                    }

                    let parsed = ApiErrorBody::parse(&body);
                    let retryable = classify_retry(status, &parsed, kind) == RetryDecision::Retry;
                    if retryable && attempt < max_attempts {
                        last_error = Some(format!("HTTP {status}"));
                        answered_before = true;
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
                        location,
                        etag,
                        cache_control,
                        evidence_headers_valid,
                        retried: answered_before,
                    });
                }
                Err(e) if e.is_connect() && attempt < max_attempts => {
                    last_error = Some(transport_error("request to the gateway failed", e));
                    backoff_sleep(attempt).await;
                }
                Err(e) => {
                    let message = transport_error("request to the gateway failed", e);
                    return Err(crate::error::Error::HttpClient(message));
                }
            }
        }

        Err(crate::error::Error::HttpClient(format!(
            "retries exhausted after {max_attempts} attempts: {}",
            last_error.unwrap_or_else(|| "unknown".to_string())
        )))
    }

    /// Turn a completed response into `Ok(())` or a typed error.
    fn check(&self, resp: &RawResponse, kind: RequestKind) -> crate::error::Result<()> {
        if is_success_status(resp.status)
            && (kind == RequestKind::Read || ApiErrorBody::parse(&resp.body).applied != Some(false))
        {
            return Ok(());
        }
        Err(map_api_error_with_redirect_base(
            resp.status,
            &resp.body,
            kind,
            resp.location.as_deref(),
            Some(self.gateway_url.as_str()),
        ))
    }

    /// [`AdminClient::check`] for config mutations, with one extra step: an
    /// unclassified 403 is re-checked against `GET /health`.
    ///
    /// A read-only admin plane usually says so in the body, but not every
    /// deployment does — a proxy can rewrite the body, and some builds answer a
    /// bare 403. Consulting the authenticated health projection turns that into
    /// the same run-stopping [`crate::error::Error::GatewayReadOnly`] the
    /// explicit body produces, so the run reports "the plane refuses writes"
    /// once instead of N identical permission errors.
    ///
    /// Strictly best-effort: a `/health` that cannot be reached or that reports
    /// writes as enabled leaves the original 403 exactly as it was.
    async fn check_mutation(
        &self,
        resp: &RawResponse,
        kind: RequestKind,
    ) -> crate::error::Result<()> {
        match self.check(resp, kind) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.refine_mutation_error(e).await),
        }
    }

    async fn refine_mutation_error(&self, error: crate::error::Error) -> crate::error::Error {
        if !matches!(error, crate::error::Error::ApiError { status: 403, .. }) {
            return error;
        }
        match self.get_health().await {
            Ok(health) => match write_block_reason(&health) {
                Some(reason) => crate::error::Error::GatewayReadOnly(format!(
                    "the gateway answered 403 to a config mutation and GET /health confirms it \
                     will not accept writes: {reason} No further resources were attempted."
                )),
                None => error,
            },
            Err(_) => error,
        }
    }

    /// Authenticated `GET /health`. Carries `mode`, `ready` and
    /// `admin_writes_enabled` — the ahead-of-time signal for read-only mode.
    pub async fn get_health(&self) -> crate::error::Result<HealthStatus> {
        let target = self.authorized("/health")?;
        let resp = self
            .send_with_retry(RequestKind::Read, || target.request(Method::GET))
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
        let body = self.get_cluster_body().await?;
        parse_cluster_status(&body)
    }

    /// `GET /cluster` up to, but not including, parsing the body.
    ///
    /// Separates "the gateway accepted the token" (a 2xx) from "the body is a
    /// shape this build does not model", which `get_cluster` folds into one
    /// error. `doctor` needs the first answer even when the second fails.
    pub async fn get_cluster_body(&self) -> crate::error::Result<String> {
        let target = self.authorized("/cluster")?;
        let resp = self
            .send_with_retry(RequestKind::Read, || target.request(Method::GET))
            .await?;
        self.check(&resp, RequestKind::Read)?;
        Ok(resp.body)
    }

    /// Fetch the namespace's live configuration plus the backup-only sections
    /// (`api_specs`, `gateway_trust_bundles`) that `GatewayConfig` does not
    /// model.
    pub async fn get_backup_snapshot(
        &self,
        namespace: &str,
    ) -> crate::error::Result<BackupSnapshot> {
        let target = self.authorized("/backup")?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                target
                    .request(Method::GET)
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

        let mut snapshot = BackupSnapshot::from_scoped_body(&resp.body, namespace)?;
        snapshot.cached = cached || snapshot.source.as_deref() == Some("cached");
        if snapshot.cached {
            self.saw_cached_backup.store(true, Ordering::Relaxed);
        }
        // A live read never fails on the count seal (see `SealStrictness`),
        // but an operator should know the gateway's own inventory disagreed
        // with what it sent — and `import` turns the same notice into a hard
        // refusal, because that document becomes permanent repo state.
        if let Some(notice) = snapshot.seal_violation_notice() {
            eprintln!(
                "Warning: GET /backup for namespace '{}' returned a count seal that does not match the document ({}). The seal was discarded; resource data is used as received.",
                safe(namespace),
                safe_line(notice)
            );
        }
        Ok(snapshot)
    }

    /// `GET /config/export` for one namespace: the read-only, fingerprinted
    /// snapshot drift detection reads with a viewer credential.
    ///
    /// The request goes to `endpoint`, whose transport was checked when it was
    /// built ([`ExportEndpoint::from_env`]): the bearer token never travels
    /// over plain `http://` except to a literal loopback address. The URL is
    /// taken from the endpoint, not from this client, so the check is the one
    /// the request actually used.
    ///
    /// A cached export (`X-Data-Source: cached`, or `source: cached` in the
    /// body) sets the same sticky flag as a cached `/backup`. Refusals are
    /// explained in terms an operator can act on (see
    /// [`explain_config_export_refusal`]).
    pub async fn get_config_export(
        &self,
        endpoint: &ExportEndpoint,
        namespace: &str,
    ) -> crate::error::Result<ConfigExport> {
        let target = self.authorize(endpoint.as_str().to_string())?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                target
                    .request(Method::GET)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        if let Err(error) = self.check(&resp, RequestKind::Read) {
            return Err(explain_config_export_refusal(resp.status, namespace, error));
        }
        let header_cached = resp
            .data_source
            .as_deref()
            .is_some_and(|source| source.eq_ignore_ascii_case("cached"));
        let export = ConfigExport::from_response(&resp.body, namespace, header_cached)?;
        if export.cached {
            self.saw_cached_backup.store(true, Ordering::Relaxed);
        }
        Ok(export)
    }

    /// Fetch a backup that will be used to authorize gateway or ownership
    /// mutations. Unlike read-only live comparisons, mutation paths must not
    /// act on resource arrays that disagree with the gateway's count seal.
    pub async fn get_backup_snapshot_for_mutation(
        &self,
        namespace: &str,
    ) -> crate::error::Result<BackupSnapshot> {
        let snapshot = self.get_backup_snapshot(namespace).await?;
        snapshot.require_consistent_seal(namespace)?;
        Ok(snapshot)
    }

    /// Complete consumer evidence is admin-only, audit-admitted and never cached.
    pub async fn get_consumer_verification(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<Option<ConsumerEvidence>> {
        validate_resource_id_for_path(id)?;
        let path = format!("/consumers/{id}/verification");
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                target
                    .request(Method::GET)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        if !resp.evidence_headers_valid {
            return Err(conditional::invalid());
        }
        if resp.status == 404 {
            if resp
                .data_source
                .as_deref()
                .is_some_and(|source| source != "database")
            {
                return Err(conditional::invalid());
            }
            return Ok(None);
        }
        if resp.status != 200 {
            return Err(conditional::invalid());
        }
        ConsumerEvidence::from_response(
            &resp.body,
            namespace,
            id,
            resp.etag.as_deref(),
            resp.data_source.as_deref(),
            resp.cache_control.as_deref(),
        )
        .map(Some)
    }

    /// One primary transaction supplies every row and the namespace revision token.
    pub async fn get_conditional_backup(
        &self,
        namespace: &str,
    ) -> crate::error::Result<BackupSnapshot> {
        let target = self.authorized("/backup?conditional=true")?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                target
                    .request(Method::GET)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        if resp.status != 200 || !resp.evidence_headers_valid {
            return Err(conditional::invalid());
        }
        conditional::conditional_backup(
            &resp.body,
            namespace,
            resp.etag.as_deref(),
            resp.data_source.as_deref(),
            resp.cache_control.as_deref(),
        )
        .map_err(|error| {
            if matches!(error, crate::error::Error::StaleGatewayView(_)) {
                self.saw_cached_backup.store(true, Ordering::Relaxed);
            }
            error
        })
    }

    /// Capture only consumers this run might write; other incremental rows need no new route.
    pub async fn capture_consumer_evidence(
        &self,
        snapshot: &mut BackupSnapshot,
        namespace: &str,
        ids: &BTreeSet<String>,
    ) -> crate::error::Result<()> {
        for id in ids {
            let evidence = self
                .get_consumer_verification(id, namespace)
                .await?
                .ok_or_else(|| {
                    crate::error::Error::StalePlan(
                        "consumer disappeared while planning; re-run apply".to_string(),
                    )
                })?;
            let planned = snapshot
                .config
                .consumers
                .iter()
                .find(|row| row.id == *id)
                .ok_or_else(conditional::invalid)?;
            if !evidence.matches_archival(planned)? {
                return Err(crate::error::Error::StalePlan(
                    "consumer changed while capturing complete planned evidence; re-run apply"
                        .to_string(),
                ));
            }
            snapshot.extras.consumer_evidence.insert(id.clone(), evidence);
        }
        Ok(())
    }

    /// Recovery needs exact credentials; canonical archival exports cannot prove a write.
    pub async fn get_complete_backup(
        &self,
        namespace: &str,
    ) -> crate::error::Result<BackupSnapshot> {
        self.get_conditional_backup(namespace).await
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
        let mut pages: Vec<Vec<String>> = Vec::new();
        let mut offset: i64 = 0;
        let mut accumulated: usize = 0;

        loop {
            let path = format!("/namespaces?offset={offset}&limit={LIST_PAGE_LIMIT}");
            let target = self.authorized(&path)?;
            let resp = self
                .send_with_retry(RequestKind::Read, || target.request(Method::GET))
                .await?;
            self.check(&resp, RequestKind::Read)?;

            let page: Page<String> = serde_json::from_str(&resp.body)
                .map_err(|e| crate::error::Error::HttpClient(format!("GET /namespaces: {e}")))?;
            let total = page.pagination.as_ref().map(|p| p.total);
            let received = page.data.len();
            accumulated = accumulated.checked_add(received).ok_or_else(|| {
                crate::error::Error::HttpClient("GET /namespaces: row count overflow".to_string())
            })?;
            let next = next_page_offset(offset, received, LIST_PAGE_LIMIT, total, accumulated)?;
            pages.push(page.data);

            match next {
                Some(next) => offset = next,
                None => break,
            }
        }

        Ok(merge_pages(pages))
    }

    /// Replace a namespace's configuration atomically.
    ///
    /// `extras` carries a concurrency-safe `api_specs` section when one can be
    /// proven safe. Gateway trust bundles are deliberately never replayed by
    /// GitOps: an absent section is a server-side no-op, so a trust rotation
    /// that races an otherwise unrelated restore cannot be rolled back.
    pub async fn post_restore(
        &self,
        config: &GatewayConfig,
        namespace: &str,
        extras: &BackupExtras,
        confirm_api_spec_deletion: bool,
    ) -> crate::error::Result<()> {
        let token = extras
            .conditional
            .as_ref()
            .ok_or_else(conditional::invalid)?;
        if token.namespace != namespace {
            return Err(conditional::invalid());
        }
        let body = build_restore_body(config, extras, confirm_api_spec_deletion)?;
        let path = if confirm_api_spec_deletion {
            "/restore?confirm=true&confirm_api_spec_deletion=true"
        } else {
            "/restore?confirm=true"
        };
        let target = self.authorized(path)?;
        let resp = self
            .send_with_retry(RequestKind::Restore, || {
                target
                    .request(Method::POST)
                    .header("X-Ferrum-Namespace", namespace)
                    .header("If-Match", token.namespace_token.as_str())
                    .json(&body)
            })
            .await
            .map_err(|error| match error {
                // Once a non-idempotent restore request leaves this process,
                // a transport failure cannot prove whether the namespace was
                // replaced. Stop all later namespaces for reconciliation.
                crate::error::Error::HttpClient(message) => {
                    crate::error::Error::AmbiguousMutation(format!(
                        "POST /restore ended without an HTTP response: {message}. The namespace may already have been replaced; inspect it with `gitforgeops diff` before retrying."
                    ))
                }
                other => other,
            })?;
        if resp.status == 412 {
            return Err(crate::error::Error::StalePlan(
                "namespace changed after the coherent snapshot; conditional restore refused. \
                 Re-plan from current state; the prepared body was not replayed"
                    .to_string(),
            ));
        }
        self.check_mutation(&resp, RequestKind::Restore)
            .await
            .map_err(conditional::withhold_error)?;
        if resp.status != 200 {
            return Err(crate::error::Error::AmbiguousMutation(
                "conditional restore returned an unexpected success status; do not replay"
                    .to_string(),
            ));
        }
        conditional::require_restore_seal(&resp.body, &body)?;
        Ok(())
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
        let target = self.authorized("/batch")?;
        let resp = self
            .send_with_retry(RequestKind::NonIdempotentMutation, || {
                target
                    .request(Method::POST)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(batch)
            })
            .await
            .map_err(|error| {
                if batch.consumers.is_empty() {
                    error
                } else {
                    conditional::withhold_error(error)
                }
            })?;

        if is_success_status(resp.status) {
            conditional::parse_sensitive(&resp.body).map_err(|_| {
                crate::error::Error::AmbiguousMutation(
                    "batch acknowledgement is invalid; reconcile without replaying".to_string(),
                )
            })?;
        }
        if resp.status == 501 {
            let refusal = conditional::parse_sensitive(&resp.body)
                .ok()
                .and_then(|value| serde_json::from_value::<ApiErrorBody>(value).ok())
                .ok_or_else(|| {
                    crate::error::Error::AmbiguousMutation(
                        "batch rejection is invalid; do not fall back or replay".to_string(),
                    )
                })?;
            if refusal.applied.is_none() && refusal.rollback.is_none() {
                return Ok(None);
            }
            if refusal.applied != Some(false) {
                return Err(crate::error::Error::AmbiguousMutation(
                    "batch rejection contradicts a precommit refusal; do not replay".to_string(),
                ));
            }
        }
        self.check_mutation(&resp, RequestKind::NonIdempotentMutation)
            .await
            .map_err(|error| {
                if batch.consumers.is_empty() {
                    error
                } else {
                    conditional::withhold_error(error)
                }
            })?;

        // Only a complete acknowledgement proves this create transaction landed.
        // Keep the accepted 200 variant, but do not infer success from arbitrary
        // 2xx statuses or substitute the request's counts for missing evidence.
        if !matches!(resp.status, 200 | 201) {
            return Err(crate::error::Error::AmbiguousMutation(format!(
                "POST /batch returned unexpected success status {}; verify the committed rows",
                resp.status
            )));
        }
        let created = serde_json::from_str::<BatchResponse>(&resp.body)
            .map_err(|_| {
                crate::error::Error::AmbiguousMutation(
                    "POST /batch returned missing or malformed created counts".to_string(),
                )
            })?
            .created;
        if created != batch.counts() {
            return Err(crate::error::Error::AmbiguousMutation(format!(
                "POST /batch created counts {created:?} do not match submitted counts {:?}",
                batch.counts()
            )));
        }
        Ok(Some(created))
    }

    pub async fn create_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let target = self.authorized("/proxies")?;
        let resp = self
            .send_with_retry(RequestKind::NonIdempotentMutation, || {
                target
                    .request(Method::POST)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(proxy)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::NonIdempotentMutation)
            .await
    }

    pub async fn update_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        validate_resource_id_for_path(&proxy.id)?;
        let path = format!("/proxies/{}", proxy.id);
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                target
                    .request(Method::PUT)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(proxy)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::Mutation).await
    }

    /// Delete a proxy without the server-side orphan cleanup.
    ///
    /// `cleanup_orphaned_upstream` defaults to `true` server-side: deleting a
    /// proxy also deletes the last-referenced hand-owned upstream. That
    /// invisible cascade makes the *next* diff-driven `DELETE /upstreams/{id}`
    /// answer 404 and wedges the run. gitforgeops owns the upstream lifecycle
    /// through its own diff, so it opts out and issues the upstream delete
    /// itself.
    pub async fn delete_proxy(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<DeleteOutcome> {
        validate_resource_id_for_path(id)?;
        let path = format!("/proxies/{id}?cleanup_orphaned_upstream=false");
        self.delete(&path, namespace, None).await
    }

    pub async fn create_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let target = self.authorized("/consumers")?;
        let resp = self
            .send_with_retry(RequestKind::NonIdempotentMutation, || {
                target
                    .request(Method::POST)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(consumer)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::NonIdempotentMutation)
            .await
            .map_err(conditional::withhold_error)
    }

    pub async fn update_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        validate_resource_id_for_path(&consumer.id)?;
        let path = format!("/consumers/{}", consumer.id);
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                target
                    .request(Method::PUT)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(consumer)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::Mutation).await
    }

    pub async fn delete_consumer(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<DeleteOutcome> {
        validate_resource_id_for_path(id)?;
        let path = format!("/consumers/{id}");
        self.delete(&path, namespace, None).await
    }

    pub async fn create_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let target = self.authorized("/upstreams")?;
        let resp = self
            .send_with_retry(RequestKind::NonIdempotentMutation, || {
                target
                    .request(Method::POST)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(upstream)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::NonIdempotentMutation)
            .await
    }

    pub async fn update_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        validate_resource_id_for_path(&upstream.id)?;
        let path = format!("/upstreams/{}", upstream.id);
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                target
                    .request(Method::PUT)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(upstream)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::Mutation).await
    }

    pub async fn delete_upstream(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<DeleteOutcome> {
        validate_resource_id_for_path(id)?;
        let path = format!("/upstreams/{id}");
        self.delete(&path, namespace, None).await
    }

    pub async fn create_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let target = self.authorized("/plugins/config")?;
        let resp = self
            .send_with_retry(RequestKind::NonIdempotentMutation, || {
                target
                    .request(Method::POST)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(pc)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::NonIdempotentMutation)
            .await
    }

    pub async fn update_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        validate_resource_id_for_path(&pc.id)?;
        let path = format!("/plugins/config/{}", pc.id);
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                target
                    .request(Method::PUT)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(pc)
            })
            .await?;
        self.check_mutation(&resp, RequestKind::Mutation).await
    }

    pub async fn delete_plugin_config(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<DeleteOutcome> {
        validate_resource_id_for_path(id)?;
        let path = format!("/plugins/config/{id}");
        self.delete(&path, namespace, None).await
    }

    /// Read one proxy, consumer, upstream or plugin config for a conditional
    /// write: the row and the strong entity-tag Ferrum Edge issued for it.
    ///
    /// `Ok(None)` is a 404: no row holds the id. A row served from the
    /// gateway's in-memory cache (`X-Data-Source: cached`) is refused as a
    /// stale view, and a response without a strong `ETag` is refused as
    /// [`crate::error::Error::ConditionalWriteUnavailable`]. Ferrum Edge
    /// issues tags only for a read from its configuration database, so either
    /// answer means no write can be made conditional on what was read.
    pub async fn get_tagged(
        &self,
        kind: &str,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<Option<TaggedResource>> {
        if kind == "Consumer" {
            return Ok(self
                .get_consumer_verification(id, namespace)
                .await?
                .map(|evidence| TaggedResource {
                    etag: evidence.token.as_str().to_string(),
                    body: evidence.row,
                }));
        }
        let path = resource_path(kind, id)?;
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                target
                    .request(Method::GET)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        if resp.status == 404 {
            return Ok(None);
        }
        self.check(&resp, RequestKind::Read)?;
        let cached = resp
            .data_source
            .as_deref()
            .is_some_and(|source| source.eq_ignore_ascii_case("cached"));
        if cached {
            return Err(crate::error::Error::StaleGatewayView(format!(
                "Refusing to overwrite {kind} `{id}` in namespace `{namespace}`: the gateway \
                 served GET {path} from its in-memory cache (X-Data-Source: cached), which may \
                 predate the configuration database and carries no entity-tag to make the write \
                 conditional on. Wait for the database to recover and retry."
            )));
        }
        let Some(etag) = strong_entity_tag(resp.etag.as_deref()) else {
            return Err(crate::error::Error::ConditionalWriteUnavailable(format!(
                "GET {path} in namespace `{namespace}` returned no strong ETag, so a write to \
                 {kind} `{id}` cannot be made conditional (If-Match) on the row this run \
                 validated. Use a gateway build that issues strong ETags for proxies, consumers, \
                 upstreams and plugin configs, and qualify the exact released build to confirm it \
                 honors If-Match; this client does not detect a server that ignores the condition. \
                 No overwrite was attempted."
            )));
        };
        let body = serde_json::from_str(&resp.body).map_err(|_| {
            crate::error::Error::HttpClient(
                "invalid resource response; details withheld".to_string(),
            )
        })?;
        Ok(Some(TaggedResource { etag, body }))
    }

    /// `PUT` one resource only if its stored row still carries `etag`.
    ///
    /// A `412 Precondition Failed` is [`ConditionalUpdate::Refused`]: Ferrum
    /// Edge compares the tag and commits the write under one namespace
    /// admission lease, so a 412 proves the row changed after it was read and
    /// this attempt wrote nothing. After a retried attempt, the change may be
    /// that earlier attempt's own commit; the caller decides.
    pub async fn update_if_match<T: Serialize>(
        &self,
        kind: &str,
        id: &str,
        resource: &T,
        namespace: &str,
        etag: &str,
    ) -> crate::error::Result<ConditionalUpdate> {
        let path = resource_path(kind, id)?;
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                target
                    .request(Method::PUT)
                    .header("X-Ferrum-Namespace", namespace)
                    .header("If-Match", etag)
                    .json(resource)
            })
            .await?;
        if resp.status == 412 {
            return Ok(ConditionalUpdate::Refused(PreconditionRefusal {
                after_retry: resp.retried,
                message: precondition_failed_message("PUT", &path, resp.retried),
            }));
        }
        if kind == "Consumer" && is_success_status(resp.status) {
            conditional::parse_sensitive(&resp.body).map_err(|_| {
                crate::error::Error::AmbiguousMutation(
                    "consumer publication response is invalid; do not replay".to_string(),
                )
            })?;
        }
        self.check_mutation(&resp, RequestKind::Mutation)
            .await
            .map_err(|error| {
                if kind == "Consumer" {
                    conditional::withhold_error(error)
                } else {
                    error
                }
            })?;
        Ok(ConditionalUpdate::Applied)
    }

    /// Whether the gateway issues the strong `ETag` every conditional
    /// overwrite needs, learned from one existing row: `Some(true)` when that
    /// row has a strong entity tag, `Some(false)` when it does not, or `None`
    /// when no row was found to read. Reads only: a list page and one
    /// single-resource read.
    pub async fn issues_entity_tags(&self) -> crate::error::Result<Option<bool>> {
        let namespaces = self.list_namespaces().await?;
        for namespace in namespaces.iter().take(ENTITY_TAG_PROBE_NAMESPACES) {
            for kind in ["Proxy", "Upstream", "PluginConfig", "Consumer"] {
                let Some(id) = self.first_row_id(kind, namespace).await? else {
                    continue;
                };
                match self.get_tagged(kind, &id, namespace).await {
                    Ok(Some(_)) => return Ok(Some(true)),
                    Ok(None) => {}
                    Err(crate::error::Error::ConditionalWriteUnavailable(_)) => {
                        return Ok(Some(false));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(None)
    }

    /// The id of the first `kind` row in `namespace`, from one list page.
    async fn first_row_id(
        &self,
        kind: &str,
        namespace: &str,
    ) -> crate::error::Result<Option<String>> {
        let path = format!("{}?offset=0&limit=1", collection_path(kind)?);
        let target = self.authorized(&path)?;
        let resp = self
            .send_with_retry(RequestKind::Read, || {
                target
                    .request(Method::GET)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        self.check(&resp, RequestKind::Read)?;
        let page: Page<serde_json::Value> = serde_json::from_str(&resp.body).map_err(|_| {
            crate::error::Error::HttpClient(
                "invalid resource response; details withheld".to_string(),
            )
        })?;
        let id = page.data.first().and_then(|row| row["id"].as_str());
        Ok(id.map(str::to_string))
    }

    /// `DELETE` one resource only if its stored row still carries `etag`.
    /// A 404 is tolerated as for [`AdminClient::delete_proxy`]; a 412 is
    /// [`crate::error::Error::StalePlan`], as for
    /// [`AdminClient::update_if_match`]. A proxy is deleted without the
    /// server-side orphan cleanup, as [`AdminClient::delete_proxy`] explains.
    pub async fn delete_if_match(
        &self,
        kind: &str,
        id: &str,
        namespace: &str,
        etag: &str,
    ) -> crate::error::Result<DeleteOutcome> {
        let mut path = resource_path(kind, id)?;
        if kind == "Proxy" {
            path.push_str("?cleanup_orphaned_upstream=false");
        }
        self.delete(&path, namespace, Some(etag))
            .await
            .map_err(|error| {
                if kind == "Consumer" && !matches!(error, crate::error::Error::StalePlan(_)) {
                    conditional::withhold_error(error)
                } else {
                    error
                }
            })
    }

    /// Shared DELETE path with 404 tolerance — see [`delete_succeeded`].
    ///
    /// The 404 is reported (as [`DeleteOutcome::NotFound`]) rather than
    /// flattened into `Ok(())`: individually a 404 is benign, but a namespace
    /// where *every* delete 404s is the signature of a misrouted run, and the
    /// caller can only say that if it can count them.
    async fn delete(
        &self,
        path: &str,
        namespace: &str,
        if_match: Option<&str>,
    ) -> crate::error::Result<DeleteOutcome> {
        let target = self.authorized(path)?;
        let resp = self
            .send_with_retry(RequestKind::Mutation, || {
                let request = target
                    .request(Method::DELETE)
                    .header("X-Ferrum-Namespace", namespace);
                match if_match {
                    Some(etag) => request.header("If-Match", etag),
                    None => request,
                }
            })
            .await?;
        if resp.status == 412 && if_match.is_some() {
            let message = precondition_failed_message("DELETE", path, resp.retried);
            return Err(crate::error::Error::StalePlan(message));
        }
        if resp.status == 404 {
            return Ok(DeleteOutcome::NotFound);
        }
        if delete_succeeded(resp.status) {
            return Ok(DeleteOutcome::Deleted);
        }
        Err(self
            .refine_mutation_error(map_api_error_with_redirect_base(
                resp.status,
                &resp.body,
                RequestKind::Mutation,
                resp.location.as_deref(),
                Some(self.gateway_url.as_str()),
            ))
            .await)
    }
}

/// A request target the admin bearer token may be sent to, with that token.
///
/// Only [`AdminClient::authorize`] builds one, after checking the transport,
/// so every request that carries the token went through that check.
struct Authorized<'a> {
    client: &'a Client,
    url: url::Url,
    token: String,
}

impl Authorized<'_> {
    fn request(&self, method: Method) -> RequestBuilder {
        self.client
            .request(method, self.url.clone())
            .bearer_auth(&self.token)
    }
}

/// Parse the exact request target before attaching credentials. Retain the
/// parsed URL through request construction rather than sending the original
/// string after checking a separate representation. Plaintext requires a
/// literal loopback IP (`127.0.0.0/8`, `::1`), never a resolver-controlled name.
///
/// `FERRUM_ALLOW_INSECURE_HTTP=true` admits a cleartext gateway URL at
/// configuration time; it does not extend this to a remote host.
fn credential_target(target: &str) -> crate::error::Result<url::Url> {
    let parsed = url::Url::parse(target).map_err(|_| unusable_gateway_url())?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(crate::error::Error::Config(
            "FERRUM_GATEWAY_URL must not embed credentials (value withheld)".to_string(),
        ));
    }
    let allowed = match parsed.scheme() {
        "https" => true,
        "http" => match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        },
        _ => false,
    };
    if !allowed {
        return Err(cleartext_credential_refused());
    }
    Ok(parsed)
}

fn unusable_gateway_url() -> crate::error::Error {
    crate::error::Error::Config(
        "FERRUM_GATEWAY_URL is not a usable URL; the value is an environment secret and is \
         withheld"
            .to_string(),
    )
}

fn cleartext_credential_refused() -> crate::error::Error {
    crate::error::Error::Config(
        "refusing to send credentials unless the gateway uses https://, or cleartext http:// \
         to a literal loopback IP; the value is an environment secret and is withheld. Use \
         https://, or http:// only to 127.0.0.0/8 or [::1]. FERRUM_ALLOW_INSECURE_HTTP=true does not \
         extend cleartext to a remote host"
            .to_string(),
    )
}

/// One resource read for a conditional write.
#[derive(Clone)]
pub struct TaggedResource {
    /// The `ETag` header exactly as received (quoted), sent back verbatim in
    /// `If-Match`.
    pub etag: String,
    /// The complete row the tag describes. Consumers use the dedicated
    /// verification route; ordinary redacted consumer reads cannot authorize writes.
    pub body: serde_json::Value,
}

/// The single-resource admin path for a managed kind.
fn resource_path(kind: &str, id: &str) -> crate::error::Result<String> {
    validate_resource_id_for_path(id)?;
    let collection = collection_path(kind)?;
    Ok(format!("{collection}/{id}"))
}

/// The admin collection path for a managed kind.
fn collection_path(kind: &str) -> crate::error::Result<&'static str> {
    match kind {
        "Proxy" => Ok("/proxies"),
        "Consumer" => Ok("/consumers"),
        "Upstream" => Ok("/upstreams"),
        "PluginConfig" => Ok("/plugins/config"),
        other => {
            let message = format!("no admin endpoint for kind `{other}`");
            Err(crate::error::Error::Config(message))
        }
    }
}

/// The `ETag` value when it is one strong entity-tag (RFC 9110 §8.8.3).
///
/// A weak tag (`W/"…"`) never satisfies `If-Match`, and a list or malformed
/// value cannot name one representation, so neither can make a write
/// conditional.
pub fn strong_entity_tag(raw: Option<&str>) -> Option<String> {
    let tag = raw?.trim();
    let opaque = tag.strip_prefix('"')?.strip_suffix('"')?;
    let valid = !opaque.is_empty()
        && opaque
            .bytes()
            .all(|byte| byte == 0x21 || (0x23..=0x7e).contains(&byte));
    valid.then(|| tag.to_string())
}

/// What a conditional `PUT` ([`AdminClient::update_if_match`]) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalUpdate {
    Applied,
    /// `412 Precondition Failed`: the row no longer carries the tag.
    Refused(PreconditionRefusal),
}

/// A `412 Precondition Failed` answer to a conditional write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionRefusal {
    /// An earlier attempt of the same request reached the gateway and was
    /// retried, so it may itself have committed the write.
    pub after_retry: bool,
    pub message: String,
}

fn precondition_failed_message(method: &str, path: &str, retried: bool) -> String {
    let retried = if retried {
        " An earlier attempt of this request reached the gateway and was retried, so it may \
         itself have committed the write."
    } else {
        ""
    };
    format!(
        "not applied: the gateway answered 412 Precondition Failed to the conditional \
         {method} {path}, so the row changed after this run read and validated it and the \
         write was refused.{retried} Re-run apply to plan against the current gateway"
    )
}

/// Render a `reqwest` transport failure with its request URL removed.
///
/// `reqwest::Error`'s `Display` appends `for url (…)`; `FERRUM_GATEWAY_URL` is
/// a GitHub Environment secret, so that URL — its host, port and path prefix —
/// must never reach CI or local logs. [`reqwest::Error::without_url`] drops the
/// suffix, and `context` names the failed operation without restating the
/// endpoint.
fn transport_error(context: &str, error: reqwest::Error) -> String {
    // Name the transport class outright rather than deferring to reqwest's
    // top-level `Display`, which reads the same for a refused connection and a
    // timeout. The remaining failures keep reqwest's own text, stripped of the
    // `for url (…)` suffix it appends.
    if error.is_connect() {
        format!("{context}: could not connect")
    } else if error.is_timeout() {
        format!("{context}: timed out")
    } else {
        format!("{context}: {}", error.without_url())
    }
}

/// Classify a 3xx `Location` against the configured gateway base without
/// disclosing either value.
///
/// The `Location` header usually names the gateway — often a normalized
/// variant of `FERRUM_GATEWAY_URL` (an added slash, a canonicalized path) that
/// GitHub's exact-value masking would not match — so it must never be printed.
/// What an operator needs is the *shape* of the move: a different path on the
/// same origin, the same host under a changed scheme, a wholly different
/// origin, or a relative path. None of those name a host, port or path prefix.
fn describe_redirect(base: Option<&str>, location: Option<&str>) -> String {
    let Some(raw) = location.map(str::trim).filter(|value| !value.is_empty()) else {
        return "It carried no usable `Location` header. ".to_string();
    };
    let base = base.and_then(|raw| url::Url::parse(raw).ok());
    let destination = match url::Url::parse(raw) {
        Ok(parsed) => parsed,
        // A relative or scheme-relative reference still has to be classified:
        // resolve it against the base and compare, so `//other.host/x` is not
        // mistaken for a same-origin path.
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            match base.as_ref().and_then(|base| base.join(raw).ok()) {
                Some(resolved) => resolved,
                None => return "It pointed at a relative path. ".to_string(),
            }
        }
        Err(_) => {
            return "It carried a `Location` that is not a URL gitforgeops can classify. "
                .to_string();
        }
    };
    let Some(base) = base else {
        return "It pointed at another origin. ".to_string();
    };
    let same_host = destination.host_str() == base.host_str()
        && destination.port_or_known_default() == base.port_or_known_default();
    if !same_host {
        "It pointed at a different origin. ".to_string()
    } else if destination.scheme() == base.scheme() {
        "It pointed at the same origin under a different path. ".to_string()
    } else {
        format!(
            "It pointed at the same host under a changed scheme ({}://). ",
            destination.scheme()
        )
    }
}

/// Whether a tolerated DELETE actually removed something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    /// The gateway answered 404 — the resource was already gone.
    NotFound,
}

// --- Response plumbing -------------------------------------------------------

/// A fully-read response. The body is buffered eagerly so the retry classifier
/// can inspect it before deciding whether to re-send.
#[derive(Clone)]
struct RawResponse {
    status: u16,
    body: String,
    data_source: Option<String>,
    /// `Location`, kept only so a 3xx can name where the admin API is
    /// actually being served from. Redirects are never followed.
    location: Option<String>,
    /// `ETag`, which a single-resource `GET` carries for a conditional write.
    etag: Option<String>,
    cache_control: Option<String>,
    evidence_headers_valid: bool,
    /// An earlier attempt got an HTTP response and was retried. A conditional
    /// write answered `412` after that may have been refused because its own
    /// earlier attempt committed.
    retried: bool,
}

/// What kind of call is being made, for retry/error classification. `/restore`
/// gets its own kind because a failed restore has rollback semantics no other
/// endpoint shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Read,
    /// PUT and DELETE calls whose endpoint semantics are idempotent.
    Mutation,
    /// Create and batch POSTs. An error response can arrive after the server
    /// committed the write, so these are never replayed automatically.
    NonIdempotentMutation,
    Restore,
}

/// The admin API's shared error envelope. Every field is optional — the
/// gateway populates the subset relevant to the failure.
#[derive(Clone, Default, Deserialize)]
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
        conditional::parse_sensitive(body)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    Retry,
    NoRetry,
}

/// Decide whether a failed request may be re-sent.
///
/// Retryable statuses are connect failures (handled by the caller), 408, 429
/// and *every* 5xx except 501. The whole 5xx range is taken rather than an
/// allow-list of the four the gateway itself emits: a CDN or load balancer in
/// front of the admin API answers with its own vendor codes (520–527, 529,
/// 530, 561, 598, 599) which are transient by definition, and an allow-list
/// silently turns those into hard failures. **501 is never retried** — a
/// standalone-MongoDB gateway will answer it forever. Body markers override
/// the status:
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
    if kind == RequestKind::NonIdempotentMutation {
        return RetryDecision::NoRetry;
    }
    if kind == RequestKind::Restore {
        if rollback_needs_manual_recovery(body.rollback.as_deref()) {
            return RetryDecision::NoRetry;
        }
        if status == 503
            && body.failure_class.as_deref() == Some("connectivity")
            && body.applied.is_none()
            && body.rollback.is_none()
            && body.reason.is_none()
            && body.restore_errors.is_none()
        {
            return RetryDecision::Retry;
        }
        // A restore is destructive and not generally idempotent. Only the
        // gateway's explicit pre-commit connectivity marker proves replay is
        // safe; every other response requires reconciliation instead.
        return RetryDecision::NoRetry;
    }
    match status {
        // 501 already returned NoRetry above, so the range is safe to take
        // wholesale.
        408 | 429 => RetryDecision::Retry,
        s if (500..=599).contains(&s) => RetryDecision::Retry,
        _ => RetryDecision::NoRetry,
    }
}

fn rollback_needs_manual_recovery(rollback: Option<&str>) -> bool {
    matches!(rollback, Some("incomplete") | Some("unknown_outcome"))
}

/// The `GET /config/export` URL, checked for the transport a viewer bearer
/// token may use.
#[derive(Clone, PartialEq, Eq)]
pub struct ExportEndpoint {
    url: String,
}

/// The URL is derived from `FERRUM_GATEWAY_URL`, an environment secret, so it
/// renders `<redacted>` rather than the host, port and path prefix it names.
impl fmt::Debug for ExportEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportEndpoint")
            .field("url", &"<redacted>")
            .finish()
    }
}

impl ExportEndpoint {
    /// Build from `FERRUM_GATEWAY_URL`. See [`ExportEndpoint::from_gateway_url`].
    pub fn from_env(env: &EnvConfig) -> crate::error::Result<Self> {
        let gateway_url = env
            .gateway_url
            .as_deref()
            .ok_or(crate::error::Error::NoGatewayUrl)?;
        Self::from_gateway_url(gateway_url)
    }

    /// Accept `https://`, or plain `http://` only to a literal loopback IP
    /// address (`127.0.0.0/8` or `::1`; not a name such as `localhost`, which
    /// a resolver could point elsewhere). Embedded `user:password@` and every
    /// other scheme are refused. The admin client enforces the same transport
    /// rule for both credential tiers, independently of insecure opt-ins.
    pub fn from_gateway_url(gateway_url: &str) -> crate::error::Result<Self> {
        let parsed = url::Url::parse(gateway_url).map_err(invalid_gateway_url)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(crate::error::Error::Config(
                "FERRUM_GATEWAY_URL must not embed credentials".to_string(),
            ));
        }
        let loopback = match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        match parsed.scheme() {
            "https" => {}
            "http" if loopback => {}
            scheme => {
                return Err(crate::error::Error::Config(format!(
                    "refusing to send the viewer token to a {scheme}:// gateway URL: \
                     GET /config/export needs https://, or http:// to a literal loopback IP \
                     address (127.0.0.1 or [::1])"
                )))
            }
        }
        let base = gateway_url.trim_end_matches('/');
        let path = crate::config_export::CONFIG_EXPORT_PATH;
        Ok(Self {
            url: format!("{base}{path}"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }
}

fn invalid_gateway_url(error: url::ParseError) -> crate::error::Error {
    crate::error::Error::Config(format!("FERRUM_GATEWAY_URL is not a valid URL: {error}"))
}

/// Minimum length Ferrum Edge enforces for both admin JWT secrets.
const MIN_JWT_SECRET_LEN: usize = 32;

/// The configured `FERRUM_ADMIN_JWT_VIEWER_SECRET`, or a refusal that names
/// the settings involved and never either value.
///
/// Mirrors the gateway's own startup checks: at least 32 characters, and not
/// equal to `FERRUM_ADMIN_JWT_SECRET`.
pub fn check_viewer_secret(env: &EnvConfig) -> crate::error::Result<&str> {
    let Some(secret) = env.admin_jwt_viewer_secret.as_deref() else {
        return Err(crate::error::Error::Config(
            "FERRUM_ADMIN_JWT_VIEWER_SECRET is not set (in CI, add it to the GitHub \
             Environment's secrets for this environment)"
                .to_string(),
        ));
    };
    if secret.len() < MIN_JWT_SECRET_LEN {
        return Err(crate::error::Error::Config(format!(
            "FERRUM_ADMIN_JWT_VIEWER_SECRET must be at least {MIN_JWT_SECRET_LEN} characters to \
             match ferrum-edge's minimum (got {})",
            secret.len()
        )));
    }
    if env.admin_jwt_secret.as_deref() == Some(secret) {
        return Err(crate::error::Error::Config(
            "FERRUM_ADMIN_JWT_VIEWER_SECRET must differ from FERRUM_ADMIN_JWT_SECRET: the gateway \
             refuses that pairing, and a viewer key equal to the admin key grants admin"
                .to_string(),
        ));
    }
    Ok(secret)
}

/// Turn a failed `GET /config/export` into an error that says what to check.
///
/// - `404`: the gateway predates the export (Ferrum Edge v0.9.9).
/// - `401`: the viewer token was rejected (wrong secret or claim settings).
/// - `403`: the namespace is outside what the credential may read
///   (`FERRUM_ADMIN_JWT_VIEWER_NAMESPACES` or the token's `ns` claim).
///
/// Every other failure is returned unchanged.
pub fn explain_config_export_refusal(
    status: u16,
    namespace: &str,
    error: crate::error::Error,
) -> crate::error::Error {
    let remedy = match status {
        404 => {
            "the gateway does not serve GET /config/export, which needs Ferrum Edge v0.9.9 or \
             later. Upgrade the gateway, or unset FERRUM_ADMIN_JWT_VIEWER_SECRET so diff reads \
             GET /backup with the admin credential"
        }
        401 => {
            "the gateway rejected the viewer token. FERRUM_ADMIN_JWT_VIEWER_SECRET must equal the \
             gateway's FERRUM_ADMIN_JWT_VIEWER_SECRET, and FERRUM_ADMIN_JWT_ISSUER, \
             FERRUM_ADMIN_JWT_AUDIENCE and FERRUM_ADMIN_JWT_TTL_SECS must match its settings"
        }
        403 => {
            "the viewer credential may not read this namespace. Check the gateway's \
             FERRUM_ADMIN_JWT_VIEWER_NAMESPACES and namespace-claim settings"
        }
        _ => return error,
    };
    crate::error::Error::Config(format!(
        "GET /config/export for namespace '{}' failed: {remedy} ({error})",
        safe(namespace)
    ))
}

/// A DELETE that answers 404 already achieved its goal. The gateway cascades
/// deletes server-side (proxy delete removes its scoped plugin configs), so a
/// diff-driven follow-up delete legitimately finds nothing. Treating it as an
/// error left the state entry in place and wedged every later run on the same
/// delete.
pub fn delete_succeeded(status: u16) -> bool {
    is_success_status(status) || status == 404
}

fn is_success_status(status: u16) -> bool {
    (200..=299).contains(&status)
}

/// Map a failing response to the most specific error variant available.
pub fn map_api_error(status: u16, body: &str, kind: RequestKind) -> crate::error::Error {
    map_api_error_with_location(status, body, kind, None)
}

/// [`map_api_error`] with the response's `Location` header, which only the 3xx
/// arm consults.
///
/// This base-less form has no configured gateway URL to compare against, so it
/// can only say whether a destination is relative or an absolute URL at some
/// unclassifiable other origin. A live call site holds the base URL and uses
/// [`map_api_error_with_redirect_base`] to classify the relationship fully.
pub fn map_api_error_with_location(
    status: u16,
    body: &str,
    kind: RequestKind,
    location: Option<&str>,
) -> crate::error::Error {
    map_api_error_with_redirect_base(status, body, kind, location, None)
}

/// [`map_api_error_with_location`] with the configured gateway base URL, so the
/// 3xx arm can describe how a redirect's `Location` relates to it without
/// echoing either value.
pub fn map_api_error_with_redirect_base(
    status: u16,
    body: &str,
    kind: RequestKind,
    location: Option<&str>,
    base: Option<&str>,
) -> crate::error::Error {
    let parsed = ApiErrorBody::parse(body);
    let message = parsed.error.clone().unwrap_or_else(|| body.to_string());

    // The client is built with `redirect::Policy::none()` so a destructive
    // body is never replayed against a different authority, which means a 3xx
    // arrives here as a plain failure. Without this arm it read as "API error
    // (301): " with an empty body, and the actual cause — an admin URL that
    // has moved, or a load balancer terminating TLS and bouncing http→https —
    // was invisible. Applies to reads as much as to mutations.
    if (300..=399).contains(&status) {
        let destination = describe_redirect(base, location);
        return crate::error::Error::ApiError {
            status,
            message: format!(
                "the gateway answered a redirect (HTTP {status}) instead of a response. \
                 {destination}gitforgeops never follows redirects on admin calls — a 301/302 \
                 would rewrite a POST into a GET and a 307/308 would replay a destructive body \
                 against another origin. Point FERRUM_GATEWAY_URL at the final origin (scheme, \
                 host, port and any path prefix) and re-run."
            ),
        };
    }

    if status == 403 && is_read_only_refusal(&message) {
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
             API specs are managed through the admin API, not this repo. Use incremental apply to keep \
             them, or re-run `gitforgeops apply --confirm-api-spec-deletion` to delete the complete \
             ownership graph deliberately. Gateway said: {message}"
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

    if kind == RequestKind::Restore
        && (matches!(status, 408 | 429) || (500..=599).contains(&status))
        && !(status == 503 && parsed.failure_class.as_deref() == Some("connectivity"))
        && !matches!(
            parsed.rollback.as_deref(),
            Some("completed") | Some("not_needed")
        )
    {
        return crate::error::Error::AmbiguousMutation(format!(
            "POST /restore returned HTTP {status} without proving a pre-commit rejection or completed rollback. The namespace may already have been replaced; inspect it with `gitforgeops diff` before retrying. Gateway said: {message}"
        ));
    }

    if status == 413 {
        // The advice depends on which body was too large: only `/restore` has
        // its own (much larger) limit and a strategy-level workaround.
        let advice = match kind {
            RequestKind::Restore => "payload exceeds the gateway's restore body limit \
                 (FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB, default 100 MiB). Split the namespace or \
                 switch to the incremental apply strategy."
                .to_string(),
            RequestKind::NonIdempotentMutation => format!(
                "the create or POST /batch body exceeds the gateway's admin request body limit. \
                 Incremental apply chunks POST /batch bodies under {BATCH_MAX_BODY_BYTES} bytes \
                 (1 MiB) and never splits a proxy/scoped-plugin dependency group, so a single \
                 resource or dependency group above that size cannot be sent. Reduce that \
                 resource or group."
            ),
            RequestKind::Mutation | RequestKind::Read => {
                "the request body exceeds the gateway's admin request body limit. Reduce the size \
                 of this resource."
                    .to_string()
            }
        };
        return crate::error::Error::ApiError {
            status,
            message: format!("{message} — {advice}"),
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

/// Does a 403 body say the admin plane is refusing writes?
///
/// Matching the canonical body byte-for-byte was too brittle: the refusal
/// arrives re-cased, whitespace-padded, or wrapped in a longer sentence
/// depending on the build and on whatever sits in front of the gateway, and a
/// missed match downgrades a whole-run stop into N per-resource errors. Keyed
/// on the distinctive phrase instead. Narrow enough that the other 403s
/// (namespace-claim and role rejections) never match.
pub fn is_read_only_refusal(message: &str) -> bool {
    message.to_ascii_lowercase().contains(READ_ONLY_MARKER)
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
    let mut values = resp.headers().get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok().map(str::to_string)
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

/// Bound raw rows, including duplicates, even when a server supplies a total.
/// A server can ignore offsets and keep returning pages with a misleading total.
const MAX_PAGINATED_ROWS: usize = 100_000;

/// Offset of the next page, or `None` when the listing is complete.
///
/// An empty page or a covered total completes the listing. Without an envelope,
/// a short page completes it; a full page needs another request. Exceeding the
/// row bound, reaching it without completion evidence, or overflowing the next
/// offset is an error: callers must never mistake a safety stop for inventory.
pub fn next_page_offset(
    requested_offset: i64,
    received: usize,
    limit: i64,
    total: Option<i64>,
    accumulated: usize,
) -> crate::error::Result<Option<i64>> {
    let limit_error = || {
        crate::error::Error::HttpClient(format!(
            "GET /namespaces: pagination safety limit of {MAX_PAGINATED_ROWS} rows reached before a complete inventory could be established"
        ))
    };
    if accumulated > MAX_PAGINATED_ROWS {
        return Err(limit_error());
    }
    let complete = received == 0
        || match total {
            Some(total) => (accumulated as u128) >= total.max(0) as u128,
            None => limit <= 0 || (received as u128) < limit as u128,
        };
    if complete {
        return Ok(None);
    }
    if accumulated == MAX_PAGINATED_ROWS {
        return Err(limit_error());
    }
    let next = i64::try_from(received)
        .ok()
        .and_then(|received| requested_offset.checked_add(received))
        .filter(|next| *next > requested_offset)
        .ok_or_else(|| {
            crate::error::Error::HttpClient(
                "GET /namespaces: pagination offset overflow; inventory is incomplete".to_string(),
            )
        })?;
    Ok(Some(next))
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
/// Held as opaque JSON for fail-closed inspection. API specs require
/// concurrency-safe restore handling; trust bundles are never replayed by
/// GitOps because restore omission preserves their current live value.
#[derive(Clone, Default)]
pub struct BackupExtras {
    /// `{section_version, items}`. Absent on cached-fallback exports.
    pub api_specs: Option<serde_json::Value>,
    /// Array; namespace singleton. Three-valued on restore: absent = no-op,
    /// present-empty = revoke, present non-empty = authoritative.
    pub gateway_trust_bundles: Option<serde_json::Value>,
    /// Top-level sections returned by a newer gateway that this build does not
    /// understand. Incremental reconciliation can leave them alone; a
    /// full-replace must fail closed rather than omit them from `/restore`.
    pub unsupported_sections: Vec<String>,
    /// Copy of [`BackupSnapshot::unmodeled_nested_fields`], carried here so
    /// every apply path that receives a live view also learns which rows it
    /// cannot rewrite without truncating them.
    pub unmodeled_nested_fields: Vec<UnmodeledNestedField>,
    /// Original coherent snapshot token. Never refreshed to authorize an old body.
    pub conditional: Option<ConditionalMetadata>,
    /// Complete stored rows captured before allocation, separate from comparison views.
    pub consumer_evidence: std::collections::BTreeMap<String, ConsumerEvidence>,
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
        self.api_specs.is_none()
            && self.gateway_trust_bundles.is_none()
            && self.unsupported_sections.is_empty()
            && self.unmodeled_nested_fields.is_empty()
    }
}

/// How a count seal that disagrees with the decoded document is treated.
///
/// The seal is an anti-truncation device, and the two consumers want opposite
/// things from a disagreement:
///
/// * **Import** reads a document once and turns it into the repository's
///   permanent desired state. A seal that does not match means the source may
///   be truncated, and publishing a partial tree is unrecoverable, so it is a
///   hard error.
/// * **Read-only live comparisons** (`diff`, `plan`, review, drift-check) run against a
///   gateway whose seal is emitted by a different codebase on every request.
///   A gateway that omits `counts.upstreams`, or a cached-fallback export that
///   elides `api_specs` while retaining `counts.api_specs`, would otherwise
///   take those commands down over metadata that no mutation is authorized
///   from. Record the disagreement, drop the seal, and keep going. Apply and
///   API-target mutation paths re-establish strictness before using the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStrictness {
    /// Import: a disagreeing seal fails the read.
    Strict,
    /// Live reads: a disagreeing seal is recorded in
    /// [`BackupSnapshot::seal_violations`] and the seal itself is discarded.
    Advisory,
}

/// The full `BackupResponse` envelope.
#[derive(Clone, Default)]
pub struct BackupSnapshot {
    pub config: GatewayConfig,
    pub extras: BackupExtras,
    /// `X-Data-Source: cached` — the gateway served its in-memory snapshot
    /// because the config database was unavailable.
    pub cached: bool,
    pub ferrum_version: Option<String>,
    pub exported_at: Option<String>,
    pub source: Option<String>,
    /// Backup-provided count inventory. Validated against the decoded
    /// resource and extra sections before it is retained for import
    /// provenance.
    pub counts: Option<serde_json::Value>,
    /// File-mode anti-truncation seal, when importing a gitforgeops/ferrum
    /// flat document rather than an admin backup.
    pub resource_counts: Option<serde_json::Value>,
    /// Top-level sections not understood by this gitforgeops build. Import
    /// reports these explicitly instead of silently discarding future backup
    /// capabilities.
    pub unsupported_sections: Vec<String>,
    /// Count-seal disagreements found while decoding. Always empty under
    /// [`SealStrictness::Strict`] (the decode returns `Err` instead); under
    /// [`SealStrictness::Advisory`] this is what the caller warns about, and
    /// `counts` / `resource_counts` are `None`.
    pub seal_violations: Vec<String>,
    /// Fields inside a modeled nested structure of a resource (for example
    /// `retry.future_option` on a Proxy) that this build does not model.
    ///
    /// Unknown *top-level* resource fields survive in each resource's
    /// `#[serde(flatten)]` `extra` map; nested ones cannot, so the typed decode
    /// discards them. They are recorded here instead so import can refuse the
    /// source rather than publish a silently truncated resource tree, and apply
    /// refuses to rewrite the affected rows (the list is also carried on
    /// [`BackupExtras::unmodeled_nested_fields`]). Read-only live comparisons
    /// ignore it.
    pub unmodeled_nested_fields: Vec<UnmodeledNestedField>,
}

/// One unmodeled field found below the top level of a backup resource. Every
/// member comes from an untrusted document; sanitize before printing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmodeledNestedField {
    /// `Proxy`, `Consumer`, `Upstream` or `PluginConfig`, or the raw backup
    /// section name when the path could not be attributed to a resource.
    pub kind: String,
    pub namespace: String,
    pub id: String,
    /// Resource-relative path in the repository loader's notation, for
    /// example `.spec.targets[0].future_option`.
    pub path: String,
}

/// Most distinct offenders one unmodeled-nested-field diagnostic lists. A
/// crafted backup could otherwise turn one refusal into megabytes of output.
pub const MAX_LISTED_UNMODELED_NESTED_FIELDS: usize = 20;

/// Render the distinct offenders as sanitized
/// `Kind 'id' (namespace 'ns'): path` entries in a stable order, listing at
/// most [`MAX_LISTED_UNMODELED_NESTED_FIELDS`] followed by an
/// `…and N more` entry.
pub fn describe_unmodeled_nested_fields<'a>(
    fields: impl IntoIterator<Item = &'a UnmodeledNestedField>,
) -> Vec<String> {
    let offenders = fields
        .into_iter()
        .map(|field| {
            (
                field.kind.as_str(),
                field.namespace.as_str(),
                field.id.as_str(),
                field.path.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut entries = offenders
        .iter()
        .take(MAX_LISTED_UNMODELED_NESTED_FIELDS)
        .map(|(kind, namespace, id, path)| {
            format!(
                "{} '{}' (namespace '{}'): {}",
                safe(kind),
                safe(id),
                safe(namespace),
                safe(path)
            )
        })
        .collect::<Vec<_>>();
    if offenders.len() > MAX_LISTED_UNMODELED_NESTED_FIELDS {
        entries.push(format!(
            "…and {} more",
            offenders.len() - MAX_LISTED_UNMODELED_NESTED_FIELDS
        ));
    }
    entries
}

impl BackupSnapshot {
    /// Validate wire identities before repository-oriented defaults can invent them.
    pub fn from_scoped_body(body: &str, namespace: &str) -> crate::error::Result<Self> {
        let value: serde_json::Value = serde_json::from_str(body).map_err(|_| {
            crate::error::Error::HttpClient("invalid backup response; details withheld".to_string())
        })?;
        for section in ["proxies", "consumers", "upstreams", "plugin_configs"] {
            if let Some(rows) = value.get(section).and_then(serde_json::Value::as_array) {
                for row in rows {
                    if row.get("namespace").and_then(serde_json::Value::as_str) != Some(namespace) {
                        let id = row
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?");
                        return Err(crate::error::Error::BackupNamespace(format!(
                            "namespace-scoped backup for {namespace:?} returned {section} {id:?} \
                             with a missing or foreign namespace; refusing the snapshot"
                        )));
                    }
                }
            }
        }
        Self::from_value_with_strictness(value, SealStrictness::Advisory)
    }

    /// Parse a backup body. The four managed sections deserialize into the
    /// permissive `GatewayConfig`; the rest is picked out by key. Unknown
    /// future top-level sections are retained by name so full-replace can fail
    /// closed instead of silently deleting data it cannot carry through.
    pub fn from_body(body: &str) -> crate::error::Result<Self> {
        let value: serde_json::Value = serde_json::from_str(body).map_err(|_| {
            crate::error::Error::HttpClient("invalid backup response; details withheld".to_string())
        })?;
        // Live reads are advisory: see [`SealStrictness`]. Callers that turn a
        // backup into permanent repository state re-check
        // `seal_violations` and refuse.
        Self::from_value_with_strictness(value, SealStrictness::Advisory)
    }

    /// Parse an already-decoded JSON/YAML-compatible backup value with the
    /// import path's strict seal enforcement.
    pub fn from_value(value: serde_json::Value) -> crate::error::Result<Self> {
        Self::from_value_with_strictness(value, SealStrictness::Strict)
    }

    /// Parse an already-decoded JSON/YAML-compatible backup value. Shared by
    /// API and file import so both paths inventory the same opaque sections.
    pub fn from_value_with_strictness(
        mut value: serde_json::Value,
        strictness: SealStrictness,
    ) -> crate::error::Result<Self> {
        // Lift the non-`GatewayConfig` sections *out* of the document rather
        // than copying them out of it: a production `/backup` is megabytes of
        // JSON, and cloning the whole tree just to keep two keys doubled peak
        // memory for every namespace fetched. `GatewayConfig` ignores unknown
        // keys, so removing them changes nothing about what it deserializes.
        let mut extras = BackupExtras::default();
        let mut ferrum_version = None;
        let mut exported_at = None;
        let mut source = None;
        let mut counts = None;
        let mut resource_counts = None;
        let mut unsupported_sections = Vec::new();
        if let Some(map) = value.as_object_mut() {
            // Pinned to ferrum-edge's `BackupPayload` (`src/admin/backup.rs`),
            // which is constructed in exactly one place
            // (`src/admin/mod.rs`, the `GET /backup` handler) and serializes
            // these eleven fields — `gateway_trust_bundles` and `api_specs`
            // being `Option`, so they are absent on filtered and
            // cached-fallback exports.
            //
            // `resource_counts` is the twelfth and is *not* a gateway section:
            // it is gitforgeops' own file-mode anti-truncation seal
            // (`apply::file_target`), allow-listed so a round-trip through a
            // locally exported document is not misread as an unknown section.
            //
            // Deliberately fail-closed: anything else here stops full replace
            // (`ensure_restore_sections_supported`) rather than being silently
            // dropped from a `/restore` body that would then delete it. Update
            // this list in step with the companion, never by widening it to
            // whatever a gateway happens to send.
            const KNOWN_TOP_LEVEL: &[&str] = &[
                "version",
                "proxies",
                "consumers",
                "plugin_configs",
                "upstreams",
                "api_specs",
                "gateway_trust_bundles",
                "ferrum_version",
                "exported_at",
                "source",
                "counts",
                "resource_counts",
            ];
            unsupported_sections = map
                .keys()
                .filter(|key| !KNOWN_TOP_LEVEL.contains(&key.as_str()))
                .cloned()
                .collect();
            unsupported_sections.sort();
            extras.unsupported_sections = unsupported_sections.clone();
            for key in &unsupported_sections {
                map.remove(key);
            }

            extras.api_specs = take_api_specs(map)?;
            extras.gateway_trust_bundles = take_trust_bundles(map)?;
            ferrum_version = take_optional_string(map, "ferrum_version")?;
            exported_at = take_optional_string(map, "exported_at")?;
            source = take_optional_string(map, "source")?;
            // Integrity metadata is not part of GatewayConfig, but import
            // validates and inventories it rather than silently stripping it.
            counts = map.remove("counts");
            resource_counts = map.remove("resource_counts");
        }

        // `serde_ignored` reports every field the typed mirror skipped. Unknown
        // top-level sections were removed above and unknown top-level resource
        // fields land in each resource's flattened `extra` map, so what is
        // reported here is exactly the nested data the decode would lose.
        let mut ignored = Vec::new();
        let config: GatewayConfig = serde_ignored::deserialize(value, |path| {
            ignored.push(ignored_backup_field(&path));
        })
        .map_err(|_| {
            crate::error::Error::Config("invalid backup payload; details withheld".to_string())
        })?;
        crate::config::validate_unique_live_resource_keys(&config)?;
        let unmodeled_nested_fields: Vec<UnmodeledNestedField> = ignored
            .into_iter()
            .map(|field| field.attribute(&config))
            .collect();
        extras.unmodeled_nested_fields = unmodeled_nested_fields.clone();
        let mut seal_violations = Vec::new();
        counts = canonicalize_count_seal(
            "counts",
            counts.as_ref(),
            &config,
            &extras,
            true,
            &mut seal_violations,
        );
        resource_counts = canonicalize_count_seal(
            "resource_counts",
            resource_counts.as_ref(),
            &config,
            &extras,
            false,
            &mut seal_violations,
        );
        if matches!(strictness, SealStrictness::Strict) {
            if let Some(violation) = seal_violations.first() {
                return Err(crate::error::Error::Config(violation.clone()));
            }
        }

        Ok(Self {
            config,
            extras,
            cached: false,
            ferrum_version,
            exported_at,
            source,
            counts,
            resource_counts,
            unsupported_sections,
            seal_violations,
            unmodeled_nested_fields,
        })
    }

    /// One-line operator summary of every count-seal disagreement, or `None`
    /// when the seal agreed (or was absent).
    pub fn seal_violation_notice(&self) -> Option<String> {
        if self.seal_violations.is_empty() {
            return None;
        }
        Some(self.seal_violations.join("; "))
    }

    /// Refuse to use a potentially truncated live backup for a mutation.
    pub fn require_consistent_seal(&self, namespace: &str) -> crate::error::Result<()> {
        if let Some(notice) = self.seal_violation_notice() {
            return Err(crate::error::Error::Config(format!(
                "refusing to mutate namespace '{namespace}': the backup's count seal does not match the document it sealed ({notice}). The snapshot may be truncated; retry after the gateway returns a consistent backup"
            )));
        }
        Ok(())
    }
}

/// A field `serde_ignored` reported while decoding a backup, split into the
/// resource section, the resource's index in it, and the remaining path.
struct IgnoredBackupField {
    section: String,
    index: Option<usize>,
    path: String,
}

enum IgnoredPathSegment {
    Key(String),
    Index(usize),
}

fn ignored_path_segments(path: &serde_ignored::Path<'_>, segments: &mut Vec<IgnoredPathSegment>) {
    match path {
        serde_ignored::Path::Root => {}
        serde_ignored::Path::Seq { parent, index } => {
            ignored_path_segments(parent, segments);
            segments.push(IgnoredPathSegment::Index(*index));
        }
        serde_ignored::Path::Map { parent, key } => {
            ignored_path_segments(parent, segments);
            segments.push(IgnoredPathSegment::Key(key.clone()));
        }
        // `Option` / newtype traversal is a decoding detail, not part of the
        // document's shape.
        serde_ignored::Path::Some { parent }
        | serde_ignored::Path::NewtypeStruct { parent }
        | serde_ignored::Path::NewtypeVariant { parent } => {
            ignored_path_segments(parent, segments);
        }
    }
}

fn ignored_backup_field(path: &serde_ignored::Path<'_>) -> IgnoredBackupField {
    let mut segments = Vec::new();
    ignored_path_segments(path, &mut segments);
    let mut segments = segments.into_iter().peekable();
    let section = match segments.next() {
        Some(IgnoredPathSegment::Key(section)) => section,
        Some(IgnoredPathSegment::Index(index)) => index.to_string(),
        None => String::new(),
    };
    let index = match segments.peek() {
        Some(IgnoredPathSegment::Index(index)) => Some(*index),
        _ => None,
    };
    if index.is_some() {
        segments.next();
    }
    let mut rendered = String::from(if index.is_some() { ".spec" } else { "" });
    for segment in segments {
        match segment {
            IgnoredPathSegment::Key(key) => {
                rendered.push('.');
                rendered.push_str(&key);
            }
            IgnoredPathSegment::Index(index) => {
                rendered.push('[');
                rendered.push_str(&index.to_string());
                rendered.push(']');
            }
        }
    }
    IgnoredBackupField {
        section,
        index,
        path: rendered,
    }
}

impl IgnoredBackupField {
    /// Name the resource the field belongs to, using the decoded identity.
    fn attribute(self, config: &GatewayConfig) -> UnmodeledNestedField {
        let identity = self.index.and_then(|index| match self.section.as_str() {
            "proxies" => config
                .proxies
                .get(index)
                .map(|resource| ("Proxy", &resource.namespace, &resource.id)),
            "consumers" => config
                .consumers
                .get(index)
                .map(|resource| ("Consumer", &resource.namespace, &resource.id)),
            "upstreams" => config
                .upstreams
                .get(index)
                .map(|resource| ("Upstream", &resource.namespace, &resource.id)),
            "plugin_configs" => config
                .plugin_configs
                .get(index)
                .map(|resource| ("PluginConfig", &resource.namespace, &resource.id)),
            _ => None,
        });
        match identity {
            Some((kind, namespace, id)) => UnmodeledNestedField {
                kind: kind.to_string(),
                namespace: namespace.clone(),
                id: id.clone(),
                path: self.path,
            },
            None => UnmodeledNestedField {
                kind: self.section,
                namespace: String::new(),
                id: self
                    .index
                    .map(|index| format!("[{index}]"))
                    .unwrap_or_default(),
                path: self.path,
            },
        }
    }
}

/// Validate a count seal and retain only the numeric fields this build
/// understands. The source document is untrusted input: copying arbitrary
/// extra values from `counts` into the import manifest would create a covert
/// path for credential material to enter the otherwise non-secret resource
/// tree.
///
/// Disagreements are appended to `violations` rather than returned as errors,
/// and a seal with any disagreement is discarded (`None`) instead of being
/// half-retained. The caller decides what a violation means; see
/// [`SealStrictness`].
fn canonicalize_count_seal(
    section_name: &str,
    value: Option<&serde_json::Value>,
    config: &GatewayConfig,
    extras: &BackupExtras,
    include_backup_extras: bool,
    violations: &mut Vec<String>,
) -> Option<serde_json::Value> {
    let value = value?;
    let Some(object) = value.as_object() else {
        violations.push(format!(
            "invalid backup payload: top-level '{section_name}' must be an object"
        ));
        return None;
    };
    let before = violations.len();
    let mut canonical = serde_json::Map::new();

    for (key, actual) in [
        ("proxies", config.proxies.len()),
        ("consumers", config.consumers.len()),
        ("plugin_configs", config.plugin_configs.len()),
        ("upstreams", config.upstreams.len()),
    ] {
        // Ferrum Edge's file seal predates the upstream section and permits
        // `resource_counts.upstreams` to be omitted only when the decoded
        // document actually contains zero upstreams. Database backup `counts`
        // remains a complete four-kind seal.
        let omitted_zero_upstreams =
            section_name == "resource_counts" && key == "upstreams" && actual == 0;
        check_declared_count(
            section_name,
            object,
            key,
            actual,
            !omitted_zero_upstreams,
            violations,
        );
        canonical.insert(key.to_string(), serde_json::json!(actual));
    }
    if include_backup_extras {
        for (key, actual) in [
            ("api_specs", extras.api_spec_count()),
            ("gateway_trust_bundles", extras.trust_bundle_count()),
        ] {
            check_declared_count(section_name, object, key, actual, false, violations);
            if object.contains_key(key) {
                canonical.insert(key.to_string(), serde_json::json!(actual));
            }
        }
    }
    if violations.len() != before {
        return None;
    }
    Some(serde_json::Value::Object(canonical))
}

fn check_declared_count(
    section_name: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    actual: usize,
    required: bool,
    violations: &mut Vec<String>,
) {
    let Some(value) = object.get(key) else {
        if required {
            violations.push(format!(
                "invalid backup payload: top-level '{section_name}' is missing required count '{key}'"
            ));
        }
        return;
    };
    let Some(declared) = value.as_u64().and_then(|count| usize::try_from(count).ok()) else {
        violations.push(format!(
            "invalid backup payload: '{section_name}.{key}' must be a non-negative integer"
        ));
        return;
    };
    if declared != actual {
        violations.push(format!(
            "invalid backup payload: '{section_name}.{key}' declares {declared} but the document contains {actual}"
        ));
    }
}

/// Remove optional string metadata while rejecting a present malformed value.
fn take_optional_string(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> crate::error::Result<Option<String>> {
    match map.remove(key) {
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(serde_json::Value::Null) | None => Ok(None),
        Some(other) => Err(crate::error::Error::Config(format!(
            "invalid backup payload: top-level '{key}' must be a string when present, got {}",
            json_type_name(&other)
        ))),
    }
}

fn take_api_specs(
    map: &mut serde_json::Map<String, serde_json::Value>,
) -> crate::error::Result<Option<serde_json::Value>> {
    let Some(value) = map.remove("api_specs") else {
        return Ok(None);
    };
    let items = value.as_object().and_then(|section| section.get("items"));
    if !matches!(items, Some(serde_json::Value::Array(_))) {
        return Err(crate::error::Error::Config(format!(
            "invalid backup payload: top-level 'api_specs' must be an object containing an 'items' array, got {}",
            json_type_name(&value)
        )));
    }
    Ok(Some(value))
}

fn take_trust_bundles(
    map: &mut serde_json::Map<String, serde_json::Value>,
) -> crate::error::Result<Option<serde_json::Value>> {
    let Some(value) = map.remove("gateway_trust_bundles") else {
        return Ok(None);
    };
    if !value.is_array() {
        return Err(crate::error::Error::Config(format!(
            "invalid backup payload: top-level 'gateway_trust_bundles' must be an array, got {}",
            json_type_name(&value)
        )));
    }
    Ok(Some(value))
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Build the `POST /restore` body.
///
/// `RestorePayload` has no `deny_unknown_fields`, so the serialized
/// `GatewayConfig` (including `version`, which the gateway validates against
/// `CURRENT_CONFIG_VERSION`) is accepted as-is. The backup-only sections are
/// spliced in as opaque values rather than being modeled on `GatewayConfig` —
/// that struct mirrors what this tool manages, and API specs are not it.
///
/// The `api_specs` section travels with the spec-owned rows the caller already
/// merged into `config`: the gateway validates the two halves against each
/// other and rejects either one on its own. An **empty** section is
/// deliberately dropped instead of forwarded — the gateway reads `items: []`
/// as an intentional wipe, whereas an absent section makes it count the
/// namespace's live specs and answer `409` if any exist, which is the only
/// guard against a spec created after our backup was taken.
pub fn build_restore_body(
    config: &GatewayConfig,
    extras: &BackupExtras,
    confirm_api_spec_deletion: bool,
) -> crate::error::Result<serde_json::Value> {
    let mut body = serde_json::to_value(config)?;
    if !body.is_object() {
        return Err(crate::error::Error::Config(
            "gateway config did not serialize as a JSON object".to_string(),
        ));
    }

    if !confirm_api_spec_deletion {
        if let Some(api_specs) = extras.api_specs.as_ref() {
            let items = api_specs
                .get("items")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    crate::error::Error::Config(
                        "refusing restore: `api_specs` is not an object with an `items` array"
                            .to_string(),
                    )
                })?;
            let carry = !items.is_empty();
            if let (true, Some(map)) = (carry, body.as_object_mut()) {
                map.insert("api_specs".to_string(), api_specs.clone());
            }
        }
    }
    // Trust roots have their own authoritative API and revision. Restore's
    // absent-section contract preserves the current live value, whereas
    // replaying the earlier backup value creates a lost-update race.
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
    pub proxies: usize,
    pub consumers: usize,
    pub plugin_configs: usize,
    pub upstreams: usize,
}

impl BatchCreated {
    pub fn total(&self) -> usize {
        self.proxies + self.consumers + self.plugin_configs + self.upstreams
    }
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
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
/// plugin/proxy groups). Associated proxies and plugin configs in this batch
/// stay in one transaction: scoped configs require their proxy to exist and
/// proxies require their referenced configs. Each chunk is still
/// all-or-nothing on its own; the caller reports partial progress if a later
/// chunk fails.
///
/// A single dependency group larger than the cap is emitted on its own — the
/// gateway will reject it with 413, which is a clearer diagnostic than a
/// silent drop.
///
/// Takes the batch **by value**: every resource ends up in exactly one chunk,
/// so moving them through costs nothing where borrowing forced a clone of the
/// entire payload (on top of the caller's clone out of `desired`).
pub fn split_batch(batch: BatchCreate, max_bytes: usize) -> crate::error::Result<Vec<BatchCreate>> {
    let budget = max_bytes.saturating_sub(BATCH_ENVELOPE_OVERHEAD).max(1);
    let mut chunks: Vec<BatchCreate> = Vec::new();
    let mut current = BatchCreate::default();
    let mut current_bytes = 0usize;

    for group in batch_dependency_groups(batch) {
        // Counting a complete envelope per group is conservative and keeps
        // the actual merged body below the cap whenever each group fits.
        let size = serde_json::to_vec(&group)?.len();
        if !current.is_empty() && current_bytes + size > budget {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.upstreams.extend(group.upstreams);
        current.consumers.extend(group.consumers);
        current.plugin_configs.extend(group.plugin_configs);
        current.proxies.extend(group.proxies);
        current_bytes += size;
    }

    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
}

/// Connected proxy/plugin create components must never cross a chunk boundary.
///
/// Also used by incremental apply to withhold only the create groups whose
/// proxy references a PluginConfig that failed to write, so one blocked
/// group cannot prevent unrelated groups from reaching `POST /batch`.
pub(crate) fn batch_dependency_groups(mut batch: BatchCreate) -> Vec<BatchCreate> {
    fn root(parents: &mut [usize], mut index: usize) -> usize {
        while parents[index] != index {
            parents[index] = parents[parents[index]];
            index = parents[index];
        }
        index
    }

    // Stable component roots and payload order regardless of caller input.
    // Association order inside each proxy remains untouched.
    batch
        .upstreams
        .sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
    batch
        .consumers
        .sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
    batch
        .plugin_configs
        .sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
    batch
        .proxies
        .sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
    let mut groups = Vec::new();
    for upstream in batch.upstreams {
        groups.push(BatchCreate {
            upstreams: vec![upstream],
            ..Default::default()
        });
    }
    for consumer in batch.consumers {
        groups.push(BatchCreate {
            consumers: vec![consumer],
            ..Default::default()
        });
    }
    let plugin_count = batch.plugin_configs.len();
    let mut parents: Vec<_> = (0..plugin_count + batch.proxies.len()).collect();
    let plugins: std::collections::BTreeMap<_, _> = batch
        .plugin_configs
        .iter()
        .enumerate()
        .map(|(i, p)| ((p.namespace.as_str(), p.id.as_str()), i))
        .collect();
    let proxies: std::collections::BTreeMap<_, _> = batch
        .proxies
        .iter()
        .enumerate()
        .map(|(i, p)| ((p.namespace.as_str(), p.id.as_str()), plugin_count + i))
        .collect();
    let mut join = |a, b| {
        let a = root(&mut parents, a);
        let b = root(&mut parents, b);
        parents[b] = a;
    };
    for (i, proxy) in batch.proxies.iter().enumerate() {
        for association in &proxy.plugins {
            if let Some(&plugin) = plugins.get(&(
                proxy.namespace.as_str(),
                association.plugin_config_id.as_str(),
            )) {
                join(plugin, plugin_count + i);
            }
        }
    }
    for (i, plugin) in batch.plugin_configs.iter().enumerate() {
        if plugin.scope != crate::config::schema::PluginScope::Proxy {
            continue;
        }
        if let Some(proxy) = plugin
            .proxy_id
            .as_deref()
            .and_then(|id| proxies.get(&(plugin.namespace.as_str(), id)))
        {
            join(i, *proxy);
        }
    }
    let mut connected = std::collections::BTreeMap::<usize, BatchCreate>::new();
    for (i, plugin) in batch.plugin_configs.into_iter().enumerate() {
        connected
            .entry(root(&mut parents, i))
            .or_default()
            .plugin_configs
            .push(plugin);
    }
    for (i, proxy) in batch.proxies.into_iter().enumerate() {
        connected
            .entry(root(&mut parents, plugin_count + i))
            .or_default()
            .proxies
            .push(proxy);
    }
    groups.extend(connected.into_values());
    groups
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

/// Parse a `GET /cluster` body.
pub fn parse_cluster_status(body: &str) -> crate::error::Result<ClusterStatus> {
    serde_json::from_str::<ClusterStatus>(body)
        .map_err(|e| crate::error::Error::HttpClient(format!("GET /cluster: {e}")))
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

/// Characters that would let an id escape its path segment.
const PATH_UNSAFE_CHARS: [char; 5] = ['/', '\\', '?', '#', '%'];

/// Reject ids that cannot be safely interpolated into a URL path segment.
///
/// This is a **path-safety** check, deliberately *not* a re-implementation of
/// the server's id grammar (`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`). The two are not
/// the same job, and conflating them breaks reconciliation: a gateway can
/// hold resources whose ids predate the current grammar (or were created
/// through another client), and refusing to build a URL for them means the
/// repo can never delete or update them — the namespace stops converging, with
/// no way out short of hand-editing the database. Validating what the gateway
/// *would accept on create* is the gateway's job; ours is only to guarantee
/// the id lands in the segment we aimed it at.
///
/// So `~`, a leading `-`, `_` or `.`, and anything else the grammar happens to
/// exclude are all allowed through: the gateway will answer 400 or 404 for an
/// id it genuinely dislikes, which is the honest outcome. What is refused is
/// everything that changes *which* endpoint is addressed — the separators in
/// [`PATH_UNSAFE_CHARS`], the relative segments `.` and `..`, and any
/// non-printable or non-ASCII byte (which would otherwise be percent-encoded,
/// silently changing the id, or smuggle a control character into the request
/// line).
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

    if id == "." || id == ".." {
        return Err(crate::error::Error::Config(format!(
            "resource id contains unsafe characters for API path segment: {id} \
             (relative path segments would address a different endpoint)",
        )));
    }

    // `is_ascii_graphic` is 0x21..=0x7E: excludes control characters, DEL,
    // space, and every non-ASCII byte.
    let safe = id
        .chars()
        .all(|c| c.is_ascii_graphic() && !PATH_UNSAFE_CHARS.contains(&c));

    if !safe {
        return Err(crate::error::Error::Config(format!(
            "resource id contains unsafe characters for API path segment: {id} \
             (must be printable ASCII with no {})",
            PATH_UNSAFE_CHARS
                .iter()
                .map(|c| format!("`{c}`"))
                .collect::<Vec<_>>()
                .join(" ")
        )));
    }

    Ok(())
}

/// Test-visible wrapper for [`validate_resource_id_for_path`].
///
/// Exposed so the accept/reject matrix can be exercised without a gateway —
/// the alternative is a network round-trip per id, which the suite forbids.
pub fn resource_id_is_path_safe(id: &str) -> crate::error::Result<()> {
    validate_resource_id_for_path(id)
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

impl fmt::Debug for TaggedResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaggedResource(<redacted>)")
    }
}

impl fmt::Debug for BackupExtras {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupExtras(<redacted>)")
    }
}

impl fmt::Debug for BackupSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupSnapshot(<redacted>)")
    }
}

impl fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawResponse(<redacted>)")
    }
}

impl fmt::Debug for ApiErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiErrorBody(<redacted>)")
    }
}
