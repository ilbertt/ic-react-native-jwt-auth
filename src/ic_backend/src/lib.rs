mod delegation;
mod hash;
mod id_token;
mod state;
mod types;
mod users;
mod utils;

use candid::Principal;
use ic_cdk::*;
use ic_cdk_timers::set_timer;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap, StableCell,
};
use id_token::IdToken;
use jsonwebtoken_rustcrypto::Algorithm;
use serde_bytes::ByteBuf;
use std::{cell::RefCell, time::Duration};

use crate::{
    state::{Salt, State, EMPTY_SALT},
    types::{
        AuthenticatedResponse, GetDelegationResponse, PrepareDelegationResponse, SessionKey,
        Timestamp, UserSub,
    },
};

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

thread_local! {
    /* flexible */ static STATE: RefCell<State> = RefCell::new(State::default());

    /* stable */ static SALT: RefCell<StableCell<Salt, Memory>> = RefCell::new(
        StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), EMPTY_SALT).unwrap()
    );

    /* stable */ static PRINCIPAL_USER_SUB: RefCell<StableBTreeMap<Blob<29>, UserSub, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );
}

#[init]
fn init() {
    set_timer(Duration::ZERO, || {
        spawn(state::init());
    });
}

#[post_upgrade]
fn post_upgrade() {
    set_timer(Duration::ZERO, || {
        spawn(state::init());
    });
}

fn check_authorization(caller: Principal, jwt: String) -> Result<(IdToken, SessionKey), String> {
    let token = id_token::decode(&jwt, Algorithm::RS256).map_err(|e| format!("{:?}", e))?;

    token.claims.validate().map_err(|e| format!("{:?}", e))?;

    let nonce = {
        let nonce = hex::decode(&token.claims.nonce).map_err(|e| format!("{:?}", e))?;
        ByteBuf::from(nonce)
    };
    let token_principal = Principal::self_authenticating(&nonce);
    if caller != token_principal {
        return Err("caller and token principal mismatch".to_string());
    }

    Ok((token, nonce))
}

#[update]
async fn prepare_delegation(jwt: String) -> PrepareDelegationResponse {
    let session_principal = caller();

    let (token, session_key) = match check_authorization(session_principal, jwt) {
        Ok(res) => res,
        Err(e) => {
            trap(&e);
        }
    };

    let sub = token.claims.clone().sub;
    let expiration = token.claims.expiration_timestamp_ns();
    let user_key = delegation::prepare_delegation(&sub, session_key, expiration).await;

    let principal = delegation::get_principal(&sub);
    users::register_user(principal, sub);

    PrepareDelegationResponse {
        user_key,
        expiration,
    }
}

#[query]
fn get_delegation(jwt: String, expiration: Timestamp) -> GetDelegationResponse {
    let session_principal = caller();

    let (token, session_key) = match check_authorization(session_principal, jwt) {
        Ok(res) => res,
        Err(e) => {
            trap(&e);
        }
    };

    let sub = &token.claims.sub;
    delegation::get_delegation(sub, session_key, expiration)
}

#[query]
fn authenticated() -> AuthenticatedResponse {
    let caller = caller();

    match users::get_user_sub(caller) {
        Some(sub) => {
            print(format!("sub: {} principal: {}", sub, caller.to_text(),));

            AuthenticatedResponse {
                user_sub: sub,
                user_principal: caller,
            }
        }
        None => trap("No user found"),
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some packages) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
