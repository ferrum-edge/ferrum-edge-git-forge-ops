use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
    additional: serde_json::Value,
}

pub fn mint_jwt(secret: &str) -> crate::error::Result<String> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        iss: "gitforgeops".to_string(),
        sub: "gitforgeops".to_string(),
        exp: now + 3600,
        iat: now,
        nbf: now,
        jti: Uuid::new_v4().to_string(),
        additional: serde_json::json!({}),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| crate::error::Error::JwtError(e.to_string()))
}
