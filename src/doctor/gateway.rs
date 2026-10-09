//! The trusted tier: does this environment's credential actually work?
//!
//! Everything below is a **read**. `AdminClient` construction validates the
//! transport configuration (scheme, CA, mTLS pairing) before a socket opens;
//! then three questions are asked:
//!
//! * `GET /health` — is the gateway reachable over this transport, and does it
//!   accept admin writes? Ferrum Edge serves `/health` **without
//!   authentication**, so an answer here says nothing about the token. The
//!   token only decides the tier: `admin_writes_enabled` is absent from the
//!   minimal tier, and that is reported as unknown, never as writable.
//! * `GET /cluster` — does the gateway accept the token we mint? It sits behind
//!   the admin JWT gate with no role requirement, so a 401/403 there is the
//!   signing secret or a claim being wrong, and a 200 proves the gateway
//!   accepts the token. It does not prove the role: `/backup` and every write
//!   need `admin`, which the local `admin-jwt-claims` check enforces.
//!
//!   The one exception is a namespace-scoped token. The client is scoped to
//!   the environment's namespace filter, so its token carries an `ns` claim
//!   whenever the environment has one, as the tokens `apply` mints do. Ferrum
//!   Edge v0.9.16 and later refuse every fleet-global route, `/cluster`
//!   included, to such a token with `403`. That refusal is expected, so the
//!   token is instead proven by `GET /namespaces`, which Edge keeps open to
//!   namespace-scoped tokens, and the missing cluster view is reported as
//!   skipped with its reason.
//! * `GET /namespaces`, one list page and one single-resource `GET` — does the
//!   gateway issue the strong `ETag` incremental apply needs to send every
//!   overwrite conditionally? This checks for the tag only; it does not test
//!   whether the gateway honors `If-Match`.
//!
//! No mutating endpoint is reachable from here: every call is a `GET`.
//!
//! The point of running it at all is that presence is not correctness. A
//! `FERRUM_ADMIN_JWT_SECRET` that is set but wrong passes every local check and
//! then answers 401 in the middle of an apply. This turns that into a named
//! finding with the four claim settings printed beside it.

use super::{Check, Scope, Status};
use crate::config::env::GatewayMode;
use crate::config::EnvConfig;
use crate::http_client::{health_tier_remedy, AdminClient};

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

    let client = match AdminClient::new_scoped(env, env.namespace_filter.iter()) {
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
                        "GET /health answered: mode={}, ready={}, admin_writes_enabled={}",
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
            } else if health.admin_writes_enabled.is_none() {
                // The minimal tier. `apply` still proceeds (its preflight is
                // advisory), but `rotate` refuses an unknown write state.
                checks.push(
                    Check::new(
                        "gateway-writable",
                        "Gateway accepts administrative writes",
                        Scope::Gateway,
                        Status::Unknown,
                        "GET /health did not report admin_writes_enabled; credential \
                         rotation will refuse until it does",
                    )
                    .for_environment(environment)
                    .remedy(health_tier_remedy(client.is_namespace_bounded())),
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
    // Classification keys on the typed status, never on the error text: that
    // text carries the gateway's body and, for transport errors, the URL, so a
    // `401`/`403` substring there proves nothing.
    match client.get_cluster_body().await {
        Ok(body) => {
            // A 2xx already proves the token was accepted. A body this build
            // cannot parse only loses the convergence detail.
            let convergence = match crate::http_client::parse_cluster_status(&body) {
                Ok(cluster) => crate::http_client::convergence_summary(&cluster),
                Err(error) => format!("cluster status unavailable ({error})"),
            };
            checks.push(
                Check::pass(
                    "gateway-token",
                    "Gateway accepts our admin token",
                    Scope::Gateway,
                    format!("GET /cluster accepted the minted token; {convergence}"),
                )
                .for_environment(environment),
            )
        }
        Err(error) if client.is_namespace_bounded_refusal(&error) => {
            checks.extend(
                namespace_bounded_token_checks(&client, env)
                    .await
                    .into_iter()
                    .map(|check| check.for_environment(environment)),
            );
        }
        Err(error) => {
            let rejected = matches!(
                error,
                crate::error::Error::ApiError {
                    status: 401 | 403,
                    ..
                }
            );
            let message = error.to_string();
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
                    rejected_token_remedy(env)
                } else {
                    "The authenticated read did not complete, so whether the gateway \
                     accepts this token is not known. Re-run once the gateway answers \
                     GET /cluster."
                        .to_string()
                }),
            );
        }
    }

    let conditional = conditional_write_check(&client).await;
    checks.push(conditional.for_environment(environment));
    checks.extend(
        snapshot_checks(&client, env.namespace_filter.as_deref())
            .await
            .into_iter()
            .map(|check| check.for_environment(environment)),
    );
    checks
}

/// The four claim settings are the usual cause of a rejected token, and an
/// unset one means "use the default", not "send nothing".
fn rejected_token_remedy(env: &EnvConfig) -> String {
    format!(
        "The gateway was reached but rejected the token. The signing secret and every claim \
         must equal the gateway's own configuration: issuer={}, role={}, audience={}, ttl={}s. \
         `/backup` and `/restore` are admin-only, and a gateway with no audience rejects a \
         token that carries one.",
        env.admin_jwt_issuer,
        env.admin_jwt_role,
        env.admin_jwt_audience.as_deref().unwrap_or("<unset>"),
        env.admin_jwt_ttl_secs,
    )
}

/// `GET /cluster` refused a namespace-scoped token with `403`, which Ferrum
/// Edge v0.9.16 and later do on every fleet-global route. Prove the token on
/// `GET /namespaces` instead (open to namespace-scoped tokens, filtered to
/// the claim) and report the cluster view as skipped rather than failed.
async fn namespace_bounded_token_checks(client: &AdminClient, env: &EnvConfig) -> Vec<Check> {
    const ID: &str = "gateway-token";
    const TITLE: &str = "Gateway accepts our admin token";
    let error = match client.list_namespaces().await {
        Ok(_) => {
            return vec![
                Check::pass(
                    ID,
                    TITLE,
                    Scope::Gateway,
                    "GET /namespaces accepted the minted namespace-scoped token (GET /cluster \
                     refused it as fleet-global)",
                ),
                Check::new(
                    "gateway-cluster-view",
                    "Cluster view is readable",
                    Scope::Gateway,
                    Status::Skipped,
                    "cluster view not available to a namespace-scoped credential: GET /cluster \
                     is fleet-global, and the gateway refuses it to a token carrying an `ns` \
                     claim",
                )
                .remedy(
                    "Expected on Ferrum Edge v0.9.16 and later. This environment's token is \
                     scoped by its namespace filter, and apply, rotate, review and drift \
                     checks use only routes open to it; the post-apply convergence line \
                     reports the cluster view as unavailable. Read cluster state with a \
                     separate operator credential outside GitForgeOps; do not widen this \
                     environment's token.",
                ),
            ];
        }
        Err(error) => error,
    };
    let rejected = matches!(
        error,
        crate::error::Error::ApiError {
            status: 401 | 403,
            ..
        }
    );
    let status = if rejected {
        Status::Fail
    } else {
        Status::Unknown
    };
    let remedy = if rejected {
        rejected_token_remedy(env)
    } else {
        "The authenticated read did not complete, so whether the gateway accepts this token \
         is not known. Re-run once the gateway answers GET /namespaces."
            .to_string()
    };
    let detail = format!(
        "GET /cluster refused the namespace-scoped token and GET /namespaces failed: {error}"
    );
    let check = Check::new(ID, TITLE, Scope::Gateway, status, detail);
    vec![check.remedy(remedy)]
}

/// Does the gateway issue the strong `ETag` every incremental overwrite is
/// made conditional on?
async fn conditional_write_check(client: &AdminClient) -> Check {
    const ID: &str = "gateway-conditional-writes";
    const TITLE: &str = "Gateway issues strong entity tags";
    match client.issues_entity_tags().await {
        Ok(Some(true)) => Check::pass(
            ID,
            TITLE,
            Scope::Gateway,
            "a single-resource GET returned a strong ETag, so apply can send every modify \
             and delete with If-Match",
        ),
        Ok(Some(false)) => Check::new(
            ID,
            TITLE,
            Scope::Gateway,
            Status::Fail,
            "a single-resource GET returned no strong ETag",
        )
        .remedy(
            "Use a gateway that issues a strong ETag for single-resource reads. Incremental \
             apply sends every modify and delete with If-Match on the row it validated. \
             Qualify the exact released gateway build to confirm it honors If-Match; this \
             check tests for the tag only.",
        ),
        Ok(None) => Check::new(
            ID,
            TITLE,
            Scope::Gateway,
            Status::Unknown,
            "no proxy, upstream, plugin config or consumer exists yet to read, so there is \
             nothing to overwrite",
        ),
        Err(error) => Check::new(
            ID,
            TITLE,
            Scope::Gateway,
            Status::Unknown,
            format!("the entity-tag read did not complete: {error}"),
        ),
    }
}

/// GET-only discovery proves response capabilities, never conditional commit enforcement.
async fn snapshot_checks(client: &AdminClient, namespace: Option<&str>) -> Vec<Check> {
    const SNAPSHOT: &str = "gateway-conditional-snapshot";
    const SNAPSHOT_TITLE: &str = "Coherent namespace snapshots";
    const CONSUMER: &str = "gateway-consumer-verification";
    const CONSUMER_TITLE: &str = "Complete consumer verification";
    let namespaces = match namespace {
        Some(namespace) => Ok(vec![namespace.to_string()]),
        None => client.list_namespaces().await,
    };
    let unknown =
        |id, title, message: &str| Check::new(id, title, Scope::Gateway, Status::Unknown, message);
    let namespace = namespaces
        .ok()
        .and_then(|namespaces| namespaces.into_iter().next());
    let Some(namespace) = namespace else {
        return vec![
            unknown(
                SNAPSHOT,
                SNAPSHOT_TITLE,
                "no namespace is available to probe; support is unknown",
            ),
            unknown(
                CONSUMER,
                CONSUMER_TITLE,
                "no consumer is available to probe; support is unknown",
            ),
        ];
    };
    match client.get_conditional_backup(&namespace).await {
        Ok(snapshot) => {
            let mut checks = vec![Check::pass(
                SNAPSHOT,
                SNAPSHOT_TITLE,
                Scope::Gateway,
                "GET returned a sealed coherent namespace token and complete row maps. \
                 This read does not prove restore enforces If-Match; qualify the exact \
                 released build.",
            )];
            let check = match snapshot.config.consumers.first() {
                Some(consumer) => {
                    match client
                        .get_consumer_verification(&consumer.id, &namespace)
                        .await
                    {
                        Ok(Some(_)) => Check::pass(
                            CONSUMER,
                            CONSUMER_TITLE,
                            Scope::Gateway,
                            "GET returned complete stored consumer evidence and a strong row \
                             token; enforcement still needs exact-build qualification",
                        ),
                        _ => unknown(
                            CONSUMER,
                            CONSUMER_TITLE,
                            "verification did not return valid authoritative evidence; \
                             consumer writes will refuse",
                        ),
                    }
                }
                None => unknown(
                    CONSUMER,
                    CONSUMER_TITLE,
                    "no consumer is available to probe; support is unknown",
                ),
            };
            checks.push(check);
            checks
        }
        Err(_) => vec![
            unknown(
                SNAPSHOT,
                SNAPSHOT_TITLE,
                "conditional snapshot evidence is unavailable; full replacement will refuse",
            ),
            unknown(
                CONSUMER,
                CONSUMER_TITLE,
                "no complete consumer was available to probe; support is unknown",
            ),
        ],
    }
}
