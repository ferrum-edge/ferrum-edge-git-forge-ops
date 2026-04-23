use gitforgeops::jwt::mint_jwt;

#[test]
fn mint_jwt_produces_valid_token() {
    let secret = "test-secret-key-that-is-at-least-32-chars-long";
    let token = mint_jwt(secret).unwrap();

    assert!(!token.is_empty());

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
}

#[test]
fn mint_jwt_contains_required_claims() {
    use base64::Engine as _;

    let secret = "test-secret-key-that-is-at-least-32-chars-long";
    let token = mint_jwt(secret).unwrap();

    let parts: Vec<&str> = token.split('.').collect();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();

    assert_eq!(claims["iss"], "gitforgeops");
    assert_eq!(claims["sub"], "gitforgeops");
    assert!(claims["exp"].is_number());
    assert!(claims["iat"].is_number());
    assert!(claims["nbf"].is_number());
    assert!(claims["jti"].is_string());
    assert!(!claims["jti"].as_str().unwrap().is_empty());
}
