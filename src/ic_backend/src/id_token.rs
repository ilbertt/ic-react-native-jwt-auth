use jsonwebtoken_rustcrypto::{
    crypto::verify, decode_header, errors::ErrorKind, Algorithm, DecodingKey, TokenData,
};
use serde::{Deserialize, Serialize};

use crate::{
    state,
    utils::{base64_decode, unix_timestamp, NANOS_IN_SECONDS},
};

/// The maximum age of an ID token (checked against the `iat` claim).
/// This value is arbitrary and should be reasonably small.
const MAX_IAT_AGE_SECONDS: u64 = 10 * 60; // 10 minutes

// ignore rust-analyzer errors on these environment variables
// compilation succeeds if you've correctly set the .env file
pub const AUTH0_ISSUER: &str = env!("ID_TOKEN_ISSUER_BASE_URL"); // expected to have a trailing slash
const AUTH0_AUDIENCE: &str = env!("ID_TOKEN_AUDIENCE");

pub type IdToken = TokenData<JWTClaims>;
pub type IdTokenResult<T> = std::result::Result<T, ErrorKind>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct JWTClaims {
    pub iss: String,
    pub aud: String,
    /// Issued at (seconds since unix epoch)
    pub iat: u64,
    /// Expires at (seconds since unix epoch)
    pub exp: u64,
    pub sub: String,
    pub nonce: String,
}

impl JWTClaims {
    pub fn expiration_timestamp_ns(&self) -> u64 {
        self.exp * NANOS_IN_SECONDS
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        let time = unix_timestamp();

        if self.exp < time {
            return Err(ValidationError::TokenExpired);
        }

        if self.iat + MAX_IAT_AGE_SECONDS < time {
            return Err(ValidationError::IatTooOld);
        }

        if self.iss != AUTH0_ISSUER {
            return Err(ValidationError::IssuerMismatch);
        }

        if self.aud != AUTH0_AUDIENCE {
            return Err(ValidationError::AudienceMismatch);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ValidationError {
    TokenExpired,
    IatTooOld,
    IssuerMismatch,
    AudienceMismatch,
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

pub fn decode(token: &str, expected_alg: Algorithm) -> IdTokenResult<IdToken> {
    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (claims, _) = expect_two!(message.rsplitn(2, '.'));

    let jwks = state::jwks(|s| s.clone().ok_or(ErrorKind::NoWorkingKey))?;

    let header = decode_header(token).map_err(|e| e.into_kind())?;
    let key_id = header.jwk_set_headers.kid.as_ref().unwrap();
    let jwk = jwks.find_key(key_id).unwrap();
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| e.into_kind())?;
    let header_alg = header
        .general_headers
        .alg
        .ok_or(ErrorKind::InvalidAlgorithm)?;

    if expected_alg != header_alg {
        return Err(ErrorKind::InvalidAlgorithm);
    }

    if !verify(signature, message, &key, header_alg).map_err(|e| e.into_kind())? {
        return Err(ErrorKind::InvalidSignature);
    }

    let decoded_claims = String::from_utf8(base64_decode(claims)?).map_err(ErrorKind::Utf8)?;
    let claims: JWTClaims = serde_json::from_str(&decoded_claims).map_err(ErrorKind::Json)?;

    Ok(IdToken { header, claims })
}
