use std::time::Duration;

use base64::Engine;
use reqwest::Client;

use crate::config::schema::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};
use crate::config::EnvConfig;
use crate::jwt;

pub struct AdminClient {
    client: Client,
    gateway_url: String,
    jwt_secret: String,
}

impl AdminClient {
    pub fn new(env: &EnvConfig) -> crate::error::Result<Self> {
        let gateway_url = env
            .gateway_url
            .clone()
            .ok_or(crate::error::Error::NoGatewayUrl)?;
        let jwt_secret = env
            .admin_jwt_secret
            .clone()
            .ok_or(crate::error::Error::NoJwtSecret)?;

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
        })
    }

    fn token(&self) -> crate::error::Result<String> {
        jwt::mint_jwt(&self.jwt_secret)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.gateway_url, path)
    }

    async fn check_response(&self, resp: reqwest::Response) -> crate::error::Result<()> {
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
        let resp = self
            .client
            .get(self.url("/backup"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

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
        let resp = self
            .client
            .get(self.url("/namespaces"))
            .bearer_auth(self.token()?)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;

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
        let resp = self
            .client
            .post(self.url("/restore?confirm=true"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(config)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn post_batch(
        &self,
        config: &GatewayConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .post(self.url("/batch"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(config)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn create_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let resp = self
            .client
            .post(self.url("/proxies"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(proxy)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn update_proxy(&self, proxy: &Proxy, namespace: &str) -> crate::error::Result<()> {
        let resp = self
            .client
            .put(self.url(&format!("/proxies/{}", proxy.id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(proxy)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn delete_proxy(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/proxies/{}", id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn create_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .post(self.url("/consumers"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(consumer)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn update_consumer(
        &self,
        consumer: &Consumer,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .put(self.url(&format!("/consumers/{}", consumer.id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(consumer)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn delete_consumer(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/consumers/{}", id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn create_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .post(self.url("/upstreams"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(upstream)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn update_upstream(
        &self,
        upstream: &Upstream,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .put(self.url(&format!("/upstreams/{}", upstream.id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(upstream)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn delete_upstream(&self, id: &str, namespace: &str) -> crate::error::Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/upstreams/{}", id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn create_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .post(self.url("/plugins/config"))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(pc)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn update_plugin_config(
        &self,
        pc: &PluginConfig,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .put(self.url(&format!("/plugins/config/{}", pc.id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .json(pc)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }

    pub async fn delete_plugin_config(
        &self,
        id: &str,
        namespace: &str,
    ) -> crate::error::Result<()> {
        let resp = self
            .client
            .delete(self.url(&format!("/plugins/config/{}", id)))
            .bearer_auth(self.token()?)
            .header("X-Ferrum-Namespace", namespace)
            .send()
            .await
            .map_err(|e| crate::error::Error::HttpClient(e.to_string()))?;
        self.check_response(resp).await
    }
}
