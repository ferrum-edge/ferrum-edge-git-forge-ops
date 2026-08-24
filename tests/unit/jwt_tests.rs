use base64::Engine as _;
use gitforgeops::config::env::EnvConfig;
use gitforgeops::jwt::{mint_jwt, JwtOptions};

const SECRET: &str = "test-secret-key-that-is-at-least-32-chars-long";

fn payload_of(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload should be base64url");
    serde_json::from_slice(&raw).expect("payload should be JSON")
}

#[test]
fn mint_jwt_produces_valid_token() {
    let token = mint_jwt(SECRET, &JwtOptions::default()).unwrap();
    assert!(!token.is_empty());
    assert_eq!(token.split('.').count(), 3);
}

#[test]
fn mint_jwt_contains_required_claims() {
    let claims = payload_of(&mint_jwt(SECRET, &JwtOptions::default()).unwrap());

    assert_eq!(claims["sub"], "gitforgeops");
    assert!(claims["exp"].is_number());
    assert!(claims["iat"].is_number());
    assert!(claims["nbf"].is_number());
    assert!(claims["jti"].is_string());
    assert!(!claims["jti"].as_str().unwrap().is_empty());
}

#[test]
fn mint_jwt_defaults_issuer_to_the_gateways_expected_value() {
    // The gateway matches `iss` against its own FERRUM_ADMIN_JWT_ISSUER
    // (default "ferrum-edge"). Minting "gitforgeops" here produced a 401
    // InvalidIssuer on every single request.
    let claims = payload_of(&mint_jwt(SECRET, &JwtOptions::default()).unwrap());
    assert_eq!(claims["iss"], "ferrum-edge");
}

#[test]
fn mint_jwt_honours_issuer_override() {
    let options = JwtOptions {
        issuer: "my-gateway".to_string(),
        ..JwtOptions::default()
    };
    let claims = payload_of(&mint_jwt(SECRET, &options).unwrap());
    assert_eq!(claims["iss"], "my-gateway");
}

#[test]
fn mint_jwt_emits_role_claim_at_the_top_level() {
    // The regression this guards: the extra claims used to live in a
    // non-flattened `additional` field, so the payload carried a literal
    // "additional": {} member and no `role` — 401 "Missing admin role claim".
    let claims = payload_of(&mint_jwt(SECRET, &JwtOptions::default()).unwrap());

    assert_eq!(claims["role"], "admin");
    assert!(
        claims.get("additional").is_none(),
        "claims must be flattened into the payload, got: {claims}"
    );
}

#[test]
fn mint_jwt_honours_role_override() {
    let options = JwtOptions {
        role: "viewer".to_string(),
        ..JwtOptions::default()
    };
    let claims = payload_of(&mint_jwt(SECRET, &options).unwrap());
    assert_eq!(claims["role"], "viewer");
}

#[test]
fn mint_jwt_omits_audience_unless_configured() {
    // RFC 7519 §4.1.3 strict default: a gateway with no configured audience
    // rejects any token that carries `aud`.
    let claims = payload_of(&mint_jwt(SECRET, &JwtOptions::default()).unwrap());
    assert!(
        claims.get("aud").is_none(),
        "aud must be absent by default, got: {claims}"
    );
}

#[test]
fn mint_jwt_emits_audience_when_configured() {
    let options = JwtOptions {
        audience: Some("ferrum-admin".to_string()),
        ..JwtOptions::default()
    };
    let claims = payload_of(&mint_jwt(SECRET, &options).unwrap());
    assert_eq!(claims["aud"], "ferrum-admin");
}

#[test]
fn mint_jwt_omits_ns_claim_when_scope_is_unknown() {
    let claims = payload_of(&mint_jwt(SECRET, &JwtOptions::default()).unwrap());
    assert!(
        claims.get("ns").is_none(),
        "ns must be absent when no namespace scope is known, got: {claims}"
    );
}

#[test]
fn mint_jwt_emits_ns_claim_as_an_array_when_scoped() {
    let options = JwtOptions::default().with_namespaces(["team-alpha", "team-beta"]);
    let claims = payload_of(&mint_jwt(SECRET, &options).unwrap());

    let ns = claims["ns"].as_array().expect("ns should be an array");
    assert_eq!(ns.len(), 2);
    assert_eq!(ns[0], "team-alpha");
    assert_eq!(ns[1], "team-beta");
}

#[test]
fn with_namespaces_drops_duplicates_and_empties() {
    let options = JwtOptions::default().with_namespaces(["a", "", "a", "b"]);
    assert_eq!(options.namespaces, vec!["a".to_string(), "b".to_string()]);

    // An all-empty scope leaves the claim off entirely rather than emitting
    // `ns: []`, which a tenancy-enforcing gateway would read as "no access".
    let empty = JwtOptions::default().with_namespaces(Vec::<String>::new());
    let claims = payload_of(&mint_jwt(SECRET, &empty).unwrap());
    assert!(claims.get("ns").is_none());
}

#[test]
fn mint_jwt_default_ttl_is_one_hour() {
    // Server acceptance is FERRUM_ADMIN_JWT_MAX_TTL + 60 (default 3600+60),
    // so 3600 passes with headroom.
    let claims = payload_of(&mint_jwt(SECRET, &JwtOptions::default()).unwrap());
    let exp = claims["exp"].as_i64().unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(exp - iat, 3600);
}

#[test]
fn mint_jwt_honours_ttl_override_and_rejects_nonpositive() {
    let options = JwtOptions {
        ttl_secs: 120,
        ..JwtOptions::default()
    };
    let claims = payload_of(&mint_jwt(SECRET, &options).unwrap());
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        120
    );

    // A zero/negative TTL would serialize as `exp <= iat`, which the gateway
    // rejects outright — fall back to the default instead.
    let bad = JwtOptions {
        ttl_secs: 0,
        ..JwtOptions::default()
    };
    let claims = payload_of(&mint_jwt(SECRET, &bad).unwrap());
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        3600
    );
}

#[test]
fn jwt_options_from_env_picks_up_configuration() {
    let env = EnvConfig {
        admin_jwt_issuer: "gw".to_string(),
        admin_jwt_role: "operator".to_string(),
        admin_jwt_audience: Some("aud-1".to_string()),
        admin_jwt_ttl_secs: 900,
        namespace_filter: Some("team-alpha".to_string()),
        ..EnvConfig::default()
    };
    let options = JwtOptions::from_env(&env);

    assert_eq!(options.issuer, "gw");
    assert_eq!(options.role, "operator");
    assert_eq!(options.audience.as_deref(), Some("aud-1"));
    assert_eq!(options.ttl_secs, 900);
    // FERRUM_NAMESPACE seeds the ns scope; a wider scope is applied later by
    // AdminClient::set_namespace_scope.
    assert_eq!(options.namespaces, vec!["team-alpha".to_string()]);
}

#[test]
fn jwt_options_from_env_defaults_are_gateway_compatible() {
    let options = JwtOptions::from_env(&EnvConfig::default());
    assert_eq!(options.issuer, "ferrum-edge");
    assert_eq!(options.role, "admin");
    assert!(options.audience.is_none());
    assert!(options.namespaces.is_empty());
    assert_eq!(options.ttl_secs, 3600);
}
