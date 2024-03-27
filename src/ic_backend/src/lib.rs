mod id_token;
mod utils;

use candid::Principal;
use ic_cdk::*;
use jsonwebtoken_rustcrypto::Algorithm;

use crate::id_token::{decode, validate};

const AUTH0_JWKS: &[u8] = include_bytes!("jwks.json");
// ignore rust-analyzer errors on these environment variables
// compilation succeeds if you've correctly set the .env file
const AUTH0_ISSUER: &str = env!("ID_TOKEN_ISSUER_BASE_URL");
const AUTH0_AUDIENCE: &str = env!("ID_TOKEN_AUDIENCE");

#[update]
fn login(jwt: String) -> String {
    let session_principal = caller();

    let token = decode(
        &jwt,
        std::str::from_utf8(AUTH0_JWKS).unwrap(),
        Algorithm::RS256,
    )
    .unwrap();

    validate(&token.claims, AUTH0_ISSUER, AUTH0_AUDIENCE).unwrap();

    let nonce = hex::decode(&token.claims.nonce).unwrap();
    let jwt_principal = Principal::self_authenticating(nonce.as_slice());

    assert_eq!(session_principal, jwt_principal);

    token.claims.sub
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some packages) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
