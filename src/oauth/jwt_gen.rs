use candid::Principal;

use super::{AuthCodeClaims, AuthQuery};

fn current_timestamp() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize
}

pub fn generate_code_grant_jwt(
    encoding_key: &jsonwebtoken::EncodingKey,
    user_principal: Principal,
    host: &str,
    query: AuthQuery,
) -> String {
    let iat = current_timestamp();

    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &AuthCodeClaims {
            aud: query.client_id.clone(),
            iat,
            exp: iat + 10 * 60,
            iss: host.to_string(),
            sub: user_principal.to_string(),
            inner: query,
        },
        encoding_key,
    )
    .expect("Failed to encode JWT")
}
