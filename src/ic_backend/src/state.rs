use std::time::Duration;

use canister_sig_util::signature_map::SignatureMap;
use ic_backend_types::Auth0JWKSet;
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpMethod,
};
use ic_cdk::{api::management_canister::main::raw_rand, trap};
use ic_cdk::{print, spawn};
use ic_cdk_timers::set_timer_interval;

use crate::{id_token::AUTH0_ISSUER, SALT, STATE};

pub type Salt = [u8; 32];

pub const EMPTY_SALT: Salt = [0; 32];

// fetch JWKS every 1 hour
const JWKS_FETCH_INTERVAL: Duration = Duration::from_secs(60 * 60);

pub struct State {
    pub sigs: SignatureMap,
    pub jwks: Option<Auth0JWKSet>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            sigs: SignatureMap::default(),
            jwks: None,
        }
    }
}

pub async fn init() {
    ensure_salt_initialized().await;

    fetch_and_store_jwks().await.unwrap();
    start_jwks_fetch_interval();
}

pub async fn ensure_salt_initialized() {
    let salt = SALT.with_borrow(|s| s.get().to_owned());
    if salt == EMPTY_SALT {
        let salt = random_salt().await;
        SALT.with_borrow_mut(|s| s.set(salt).unwrap());
    }
}

pub fn salt() -> Salt {
    SALT.with_borrow(|s| s.get().to_owned())
}

pub fn signature_map<R>(f: impl FnOnce(&SignatureMap) -> R) -> R {
    STATE.with_borrow(|s| f(&s.sigs))
}

pub fn signature_map_mut<R>(f: impl FnOnce(&mut SignatureMap) -> R) -> R {
    STATE.with_borrow_mut(|s| f(&mut s.sigs))
}

pub fn jwks_mut<R>(f: impl FnOnce(&mut Option<Auth0JWKSet>) -> R) -> R {
    STATE.with_borrow_mut(|s| f(&mut s.jwks))
}

pub fn jwks<R>(f: impl FnOnce(&Option<Auth0JWKSet>) -> R) -> R {
    STATE.with_borrow(|s| f(&s.jwks))
}

pub async fn fetch_and_store_jwks() -> Result<(), String> {
    // the response should be around 3KB, so we set a limit of 10KB
    const MAX_RESPONSE_BYTES: u128 = 10_000;
    // formula from https://internetcomputer.org/docs/current/developer-docs/gas-cost#special-features
    // we don't have any request bytes, so we can skip adding them in the calculation
    let cycles: u128 = (3_000_000 + (60_000 * 13)) * 13 + ((800 * 13) * MAX_RESPONSE_BYTES);

    let (res,) = http_request(
        CanisterHttpRequestArgument {
            url: format!("{AUTH0_ISSUER}.well-known/jwks.json"),
            method: HttpMethod::GET,
            headers: vec![],
            body: None,
            max_response_bytes: Some(MAX_RESPONSE_BYTES.try_into().unwrap()),
            transform: None,
        },
        cycles,
    )
    .await
    .map_err(|e| format!("Error fetching JWKS: {:?}", e))?;

    let jwks: Auth0JWKSet =
        serde_json::from_slice(&res.body).map_err(|e| format!("Error parsing JWKS: {:?}", e))?;
    store_jwks(jwks.clone());

    print(&format!(
        "Fetched JWKS. JSON Web Keys available: {}",
        jwks.keys.len()
    ));

    Ok(())
}

pub fn store_jwks(jwks: Auth0JWKSet) {
    jwks_mut(|j| *j = Some(jwks));
}

fn start_jwks_fetch_interval() {
    async fn wrapper() {
        fetch_and_store_jwks().await.unwrap();
    }

    set_timer_interval(JWKS_FETCH_INTERVAL, || {
        spawn(wrapper());
    });
}

/// Calls raw rand to retrieve a random salt (32 bytes).
async fn random_salt() -> Salt {
    let res: Vec<u8> = match raw_rand().await {
        Ok((res,)) => res,
        Err((_, err)) => trap(&format!("failed to get salt: {err}")),
    };
    let salt: Salt = res[..].try_into().unwrap_or_else(|_| {
        trap(&format!(
            "expected raw randomness to be of length 32, got {}",
            res.len()
        ));
    });
    salt
}
