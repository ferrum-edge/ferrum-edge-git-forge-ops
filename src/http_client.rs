use std::time::Duration;

use base64::Engine;
use rand::Rng;
use reqwest::{Client, RequestBuilder, Response};

use crate::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::config::EnvConfig;
use crate::jwt;

/// Client for the Ferrum Edge Admin API.
///
/// The client owns a reusable `reqwest::Client`, so per-command gateway calls
/// share connection pooling, TLS configuration, JWT auth, and retry behavior.
pub struct AdminClient {
    client: Client,
    gateway_url: String,
    jwt_secret: String,
    max_retries: u32,
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
            max_retries: env.gateway_max_retries,
        })
    }

    fn token(&self) -> crate::error::Result<String> {
        jwt::mint_jwt(&self.jwt_secret)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.gateway_url, path)
    }

    /// Send an HTTP request with automatic retry on transient failures.
    ///
    /// Retries on:
    /// - Connection errors (`is_connect()`) — the server never saw the request
    /// - HTTP 5xx and 429 — server-side transient issue, typically safe to retry
    ///
    /// Does NOT retry on:
    /// - HTTP 4xx (other than 429) — permanent, caller error
    /// - Request timeouts — ambiguous state; the request may have applied.
    ///   The higher-level workflow can re-run safely because the Ferrum
    ///   admin API is idempotent for PUT/DELETE/POST-batch/POST-restore,
    ///   and because `apply_incremental` re-diffs against live state.
    ///
    /// Backoff is exponential (500ms · 2^attempt) with a cap of 8s. No
    /// jitter — retry volume from a single CLI run is too low to matter.
    async fn send_with_retry<F>(&self, build: F) -> crate::error::Result<Response>
    where
        F: Fn() -> RequestBuilder,
    {
        let max_attempts = self.max_retries.saturating_add(1);
        let mut last_error: Option<String> = None;

        for attempt in 1..=max_attempts {
            let result = build().send().await;
            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let retryable = status == 429 || (500..600).contains(&status);
                    if retryable && attempt < max_attempts {
                        last_error = Some(format!("HTTP {status}"));
                        backoff_sleep(attempt).await;
                        continue;
                    }
                    return Ok(resp);
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

    async fn check_response(&self, resp: Response) -> crate::error::Result<()> {
        let status = resp.status().as_u16();
        if status >= 400 {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| String::from("<no body>"));
            return Err(crate::error::Error::ApiError {
                status,
                message: body,
            });
        }
        Ok(())
    }

    pub async fn get_backup(&self, namespace: &str) -> crate::error::Result<GatewayConfig> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .get(self.url("/backup"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| String::from("<no body>"));
            return Err(crate::error::Error::ApiError {
                status,
                message: body,
            });
        }

        resp.json::<GatewayConfig>()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))
    }

    pub async fn list_namespaces(&self) -> crate::error::Result<Vec<String>> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| self.client.get(self.url("/namespaces")).bearer_auth(&token))
            .await?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| String::from("<no body>"));
            return Err(crate::error::Error::ApiError {
                status,
                message: body,
            });
        }

        resp.json::<Vec<String>>()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))
    }

    pub async fn post_restore(
        &self,
        config: &GatewayConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(self.url("/restore?confirm=true"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(config)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn post_batch(
        &self,
        config: &GatewayConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(self.url("/batch"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(config)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn create_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(self.url("/proxies"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(proxy)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn update_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/proxies/{}", proxy.id);
        let resp = self
            .send_with_retry(|| {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(proxy)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn delete_proxy(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/proxies/{id}");
        let resp = self
            .send_with_retry(|| {
                self.client
                    .delete(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn create_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(self.url("/consumers"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(consumer)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn update_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/consumers/{}", consumer.id);
        let resp = self
            .send_with_retry(|| {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(consumer)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn delete_consumer(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/consumers/{id}");
        let resp = self
            .send_with_retry(|| {
                self.client
                    .delete(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn create_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(self.url("/upstreams"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(upstream)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn update_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/upstreams/{}", upstream.id);
        let resp = self
            .send_with_retry(|| {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(upstream)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn delete_upstream(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/upstreams/{id}");
        let resp = self
            .send_with_retry(|| {
                self.client
                    .delete(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn create_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(self.url("/plugins/config"))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(pc)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn update_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/plugins/config/{}", pc.id);
        let resp = self
            .send_with_retry(|| {
                self.client
                    .put(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
                    .json(pc)
            })
            .await?;
        self.check_response(resp).await
    }

    pub async fn delete_plugin_config(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let token = self.token()?;
        let path = format!("/plugins/config/{id}");
        let resp = self
            .send_with_retry(|| {
                self.client
                    .delete(self.url(&path))
                    .bearer_auth(&token)
                    .header("X-Ferrum-Namespace", namespace)
            })
            .await?;
        self.check_response(resp).await
    }
}

async fn backoff_sleep(attempt: u32) {
    // Full-jitter backoff based on 500ms · 2^(attempt-1), capped at 8s.
    let exp = attempt.saturating_sub(1).min(4);
    let cap_ms = (500u64 * (1u64 << exp)).min(8_000);
    let delay_ms = rand::rng().random_range(0..=cap_ms);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}
