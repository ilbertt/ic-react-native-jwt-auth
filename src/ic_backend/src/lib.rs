use candid::Principal;
use ic_cdk::*;
use jsonwebtoken_rustcrypto::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Auth0JWK {
    kty: String,
    r#use: String,
    n: String,
    e: String,
    kid: String,
    x5t: String,
    x5c: Vec<String>,
    alg: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Auth0JWKSet {
    keys: Vec<Auth0JWK>,
}

impl Auth0JWKSet {
    fn find_key(&self, kid: &str) -> Option<&Auth0JWK> {
        self.keys.iter().find(|it| it.kid == kid)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct JWTClaims {
    nickname: String,
    name: String,
    picture: String,
    updated_at: String,
    email: String,
    email_verified: bool,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    sub: String,
    sid: String,
    nonce: String,
}

const AUTH0_JWKS: &[u8] = include_bytes!("jwks.json");

#[update]
fn login(jwt: String) -> String {
    let session_principal = caller();

    let jwks: Auth0JWKSet = serde_json::from_slice(AUTH0_JWKS).unwrap();

    let header = decode_header(&jwt).unwrap();
    let key_id = header.kid.unwrap();
    let jwk = jwks.find_key(&key_id).unwrap();

    let token = decode::<JWTClaims>(
        &jwt,
        &DecodingKey::from_rsa_components(&jwk.n, &jwk.e).unwrap(),
        &Validation::new(Algorithm::RS256),
    )
    .unwrap();

    let nonce = hex::decode(&token.claims.nonce).unwrap();

    assert_eq!(session_principal, Principal::from_slice(&nonce));

    format!("Hello, {}!", token.claims.sub)
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some packages) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
