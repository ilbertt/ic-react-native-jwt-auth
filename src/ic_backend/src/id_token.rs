use jsonwebtoken_rustcrypto::{
    crypto::verify, decode_header, errors::ErrorKind, Algorithm, DecodingKey, TokenData,
};
use serde::{Deserialize, Serialize};

use crate::utils::{base64_decode, unix_timestamp};

/// The maximum age of an ID token (checked against the `iat` claim).
/// This value is arbitrary and should be reasonably small.
const MAX_IAT_AGE_SECONDS: u64 = 10 * 60; // 10 minutes

pub type IdTokenResult<T> = std::result::Result<T, ErrorKind>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Auth0JWK {
    pub kty: String,
    pub r#use: String,
    pub n: String,
    pub e: String,
    pub kid: String,
    pub x5t: String,
    pub x5c: Vec<String>,
    pub alg: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Auth0JWKSet {
    pub keys: Vec<Auth0JWK>,
}

impl Auth0JWKSet {
    fn find_key(&self, kid: &str) -> Option<&Auth0JWK> {
        self.keys.iter().find(|it| it.kid == kid)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub sub: String,
    pub sid: String,
    pub nonce: String,
}

/// Takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(ErrorKind::InvalidToken),
        }
    }};
}

pub fn decode(
    token: &str,
    jwks: &str,
    expected_alg: Algorithm,
) -> IdTokenResult<TokenData<JWTClaims>> {
    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, _) = expect_two!(message.rsplitn(2, '.'));

    let jwks: Auth0JWKSet = serde_json::from_str(jwks).map_err(|e| ErrorKind::Json(e))?;

    let header = decode_header(token).map_err(|e| e.into_kind())?;
    let key_id = header.kid.as_ref().unwrap();
    let jwk = jwks.find_key(key_id).unwrap();
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| e.into_kind())?;

    if expected_alg != header.alg {
        return Err(ErrorKind::InvalidAlgorithm);
    }

    if !verify(signature, message, &key, header.alg).map_err(|e| e.into_kind())? {
        return Err(ErrorKind::InvalidSignature);
    }

    let decoded_claims =
        String::from_utf8(base64_decode(claims.as_ref())?).map_err(|e| ErrorKind::Utf8(e))?;
    let claims: JWTClaims =
        serde_json::from_str(&decoded_claims).map_err(|e| ErrorKind::Json(e))?;

    Ok(TokenData { header, claims })
}

#[derive(Debug)]
pub enum ValidationError {
    TokenExpired,
    IatTooOld,
    IssuerMismatch,
    AudienceMismatch,
}

pub fn validate(claims: &JWTClaims, issuer: &str, audience: &str) -> Result<(), ValidationError> {
    let time = unix_timestamp();

    if claims.exp < time {
        return Err(ValidationError::TokenExpired);
    }

    if claims.iat + MAX_IAT_AGE_SECONDS < time {
        return Err(ValidationError::IatTooOld);
    }

    if claims.iss != issuer {
        return Err(ValidationError::IssuerMismatch);
    }

    if claims.aud != audience {
        return Err(ValidationError::AudienceMismatch);
    }

    Ok(())
}
