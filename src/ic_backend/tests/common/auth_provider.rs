use base64::{engine::general_purpose, Engine as _};
use ic_backend::types::{Auth0JWK, Auth0JWKSet};
use jwt_simple::prelude::*;

// ignore rust-analyzer errors on these environment variables
// compilation succeeds if you've correctly set the .env file
const AUTH0_ISSUER: &str = env!("ID_TOKEN_ISSUER_BASE_URL"); // expected to have a trailing slash
const AUTH0_AUDIENCE: &str = env!("ID_TOKEN_AUDIENCE");

const KEY_ID: &str = "integration_tests_key_id";

fn component_to_base64(component: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(component)
}

pub fn initialize_auth_provider() -> (RS256KeyPair, Auth0JWKSet) {
    let key_pair = create_key_pair();
    let jwks = create_jwks(&key_pair);

    (key_pair, jwks)
}

pub fn create_key_pair() -> RS256KeyPair {
    RS256KeyPair::generate(2048).unwrap().with_key_id(KEY_ID)
}

pub fn create_jwks(key_pair: &RS256KeyPair) -> Auth0JWKSet {
    let pk = key_pair.public_key();
    let components = pk.to_components();
    Auth0JWKSet {
        keys: vec![Auth0JWK {
            kid: key_pair.key_id().as_ref().unwrap().to_string(),
            kty: "RSA".to_string(),
            alg: RS256KeyPair::jwt_alg_name().to_string(),
            r#use: "sig".to_string(),
            n: component_to_base64(&components.n),
            e: component_to_base64(&components.e),
            // not needed
            x5c: vec!["".to_string()],
            x5t: "".to_string(),
        }],
    }
}

pub fn create_jwt(
    key_pair: &RS256KeyPair,
    sub: &str,
    nonce: &str,
    valid_for: Duration,
) -> (String, JWTClaims<NoCustomClaims>) {
    let claims = Claims::create(valid_for)
        .with_issuer(AUTH0_ISSUER)
        .with_audience(AUTH0_AUDIENCE)
        .with_subject(sub)
        .with_nonce(nonce);
    let jwt = key_pair.sign(claims.clone()).unwrap();

    (jwt, claims)
}
