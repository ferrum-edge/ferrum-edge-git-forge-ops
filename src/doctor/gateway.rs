//! The trusted tier: does this environment's credential actually work?
//!
//! Everything below is a **read**. `AdminClient` construction validates the
//! transport configuration (scheme, CA, mTLS pairing) before a socket opens;
//! then two calls answer two different questions:
//!
//! * `GET /health` — is the gateway reachable over this transport, and does it
//!   accept admin writes? Ferrum Edge serves `/health` **without
//!   authentication**, so an answer here says nothing about the token.
//! * `GET /cluster` — does the gateway accept the token we mint? It sits behind
//!   the admin JWT gate with no role requirement, so a 401/403 there is the
//!   signing secret or a claim being wrong, and a 200 is proof they are right.
//!
//! No mutating endpoint is reachable from here, which is why the module exposes
//! only these two calls.
//!
//! The point of running it at all is that presence is not correctness. A
//! `FERRUM_ADMIN_JWT_SECRET` that is set but wrong passes every local check and
//! then answers 401 in the middle of an apply. This turns that into a named
//! finding with the four claim settings printed beside it.

use super::{Check, Scope, Status};
use crate::config::env::GatewayMode;
use crate::config::EnvConfig;
use crate::http_client::AdminClient;

/// Reads only. Returns one group of checks for the given environment.
pub async fn run(environment: &str, env: &EnvConfig) -> Vec<Check> {
    if matches!(env.gateway_mode, GatewayMode::File) {
        return vec![Check::new(
            "gateway-reachable",
            "Gateway is reachable",
            Scope::Gateway,
            Status::Skipped,
            "file mode has no Admin API to contact",
        )
        .for_environment(environment)];
    }

    if env.gateway_url.is_none() || env.admin_jwt_secret.is_none() {
        return vec![Check::new(
            "gateway-reachable",
            "Gateway is reachable",
            Scope::Gateway,
            Status::Unknown,
            "no gateway URL or signing secret in this process environment",
        )
        .for_environment(environment)
        .remedy(
            "Gateway checks need the environment's own credentials. In CI they come \
             from the GitHub Environment; locally, export them (or run this scope \
             from a trusted context) before asking whether the gateway accepts them.",
        )];
    }

    let client = match AdminClient::new_scoped(env, std::iter::empty::<&str>()) {
        Ok(client) => client,
        Err(error) => {
            return vec![Check::new(
                "gateway-transport",
                "Gateway transport configuration is valid",
                Scope::Gateway,
                Status::Fail,
                format!("the admin client could not be built: {error}"),
            )
            .for_environment(environment)
            .remedy(
                "This is a configuration error, not a network one: check the URL \
                 scheme (https:// unless FERRUM_ALLOW_INSECURE_HTTP=true), and that \
                 FERRUM_GATEWAY_CLIENT_CERT and FERRUM_GATEWAY_CLIENT_KEY are either \
                 both set or both unset.",
            )];
        }
    };

    let mut checks = vec![Check::pass(
        "gateway-transport",
        "Gateway transport configuration is valid",
        Scope::Gateway,
        "URL scheme, CA trust material and mTLS pairing are accepted",
    )
    .for_environment(environment)];

    match client.get_health().await {
        Ok(health) => {
            checks.push(
                Check::pass(
                    "gateway-reachable",
                    "Gateway is reachable",
                    Scope::Gateway,
                    format!(
                        "GET /health (unauthenticated) answered: mode={}, ready={}, \
                         admin_writes_enabled={}",
                        health.mode.as_deref().unwrap_or("unknown"),
                        health
                            .ready
                            .map(|ready| ready.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        health
                            .admin_writes_enabled
                            .map(|enabled| enabled.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                    ),
                )
                .for_environment(environment),
            );
            // A read-only control plane accepts every read and refuses every
            // write, so an apply would get all the way to the first mutation
            // before finding out.
            if health.admin_writes_enabled == Some(false) {
                checks.push(
                    Check::new(
                        "gateway-writable",
                        "Gateway accepts administrative writes",
                        Scope::Gateway,
                        Status::Fail,
                        "the gateway reports admin_writes_enabled=false",
                    )
                    .for_environment(environment)
                    .remedy(
                        "Reads work, so drift checks and review still function, but \
                         `apply` will refuse at its health preflight. Re-enable admin \
                         writes on the gateway before deploying.",
                    ),
                );
            }
        }
        Err(error) => {
            checks.push(
                Check::new(
                    "gateway-reachable",
                    "Gateway is reachable",
                    Scope::Gateway,
                    Status::Fail,
                    format!("GET /health failed: {error}"),
                )
                .for_environment(environment)
                .remedy(
                    "The gateway was not reached. Check the URL, network path, and — \
                     for a private CA — that FERRUM_GATEWAY_CA_CERT holds the \
                     base64-encoded PEM that signs the gateway's certificate.",
                ),
            );
            // Nothing below can be answered once /health failed; say so rather
            // than leaving the token question silently absent.
            checks.push(
                Check::new(
                    "gateway-token",
                    "Gateway accepts our admin token",
                    Scope::Gateway,
                    Status::Unknown,
                    "not attempted: the gateway did not answer /health",
                )
                .for_environment(environment),
            );
            return checks;
        }
    }

    // The authenticated half. `/cluster` passes the admin JWT gate and has no
    // role requirement, so its answer is about the token and nothing else.
    match client.get_cluster().await {
        Ok(cluster) => checks.push(
            Check::pass(
                "gateway-token",
                "Gateway accepts our admin token",
                Scope::Gateway,
                format!(
                    "GET /cluster accepted the minted token; {}",
                    crate::http_client::convergence_summary(&cluster)
                ),
            )
            .for_environment(environment),
        ),
        Err(error) => {
            let message = error.to_string();
            let rejected = message.contains("401") || message.contains("403");
            checks.push(
                Check::new(
                    "gateway-token",
                    "Gateway accepts our admin token",
                    Scope::Gateway,
                    if rejected {
                        Status::Fail
                    } else {
                        Status::Unknown
                    },
                    format!("GET /cluster failed: {message}"),
                )
                .for_environment(environment)
                .remedy(if rejected {
                    // The four claim settings are the usual cause, and an
                    // unset one means "use the default", not "send nothing".
                    format!(
                        "The gateway was reached but rejected the token. The signing \
                         secret and every claim must equal the gateway's own \
                         configuration: issuer={}, role={}, audience={}, ttl={}s. \
                         `/backup` and `/restore` are admin-only, and a gateway with no \
                         audience rejects a token that carries one.",
                        env.admin_jwt_issuer,
                        env.admin_jwt_role,
                        env.admin_jwt_audience.as_deref().unwrap_or("<unset>"),
                        env.admin_jwt_ttl_secs,
                    )
                } else {
                    "The authenticated read did not complete, so whether the gateway \
                     accepts this token is not known. Re-run once the gateway answers \
                     GET /cluster."
                        .to_string()
                }),
            );
        }
    }

    checks
}
