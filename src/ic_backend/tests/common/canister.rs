use candid::Principal;
use ic_backend_types::{Auth0JWKSet, GetDelegationResponse, PrepareDelegationResponse};
use pocket_ic::{query_candid_as, update_candid_as, CallError, ErrorCode, UserError};

use super::test_env::TestEnv;

pub fn initialize_canister(env: &TestEnv, jwks: Auth0JWKSet) {
    set_jwks(env, env.controller(), jwks).unwrap();
}

pub fn extract_trap_message(res: CallError) -> String {
    match res {
        CallError::UserError(UserError {
            code: ErrorCode::CanisterCalledTrap,
            description,
        }) => description,
        _ => panic!("expected trap"),
    }
}

pub fn prepare_delegation(
    env: &TestEnv,
    sender: Principal,
    jwt: String,
) -> Result<PrepareDelegationResponse, CallError> {
    update_candid_as(
        env.pic(),
        env.canister_id(),
        sender,
        "prepare_delegation",
        (jwt,),
    )
    .map(|(res,)| res)
}

pub fn get_delegation(
    env: &TestEnv,
    sender: Principal,
    jwt: String,
    expiration: u64,
) -> Result<GetDelegationResponse, CallError> {
    query_candid_as(
        env.pic(),
        env.canister_id(),
        sender,
        "get_delegation",
        (jwt, expiration),
    )
    .map(|(res,)| res)
}

pub fn sync_jwks(env: &TestEnv, sender: Principal) -> Result<(), CallError> {
    update_candid_as(env.pic(), env.canister_id(), sender, "sync_jwks", ()).map(|(res,)| res)
}

pub fn set_jwks(env: &TestEnv, sender: Principal, jwks: Auth0JWKSet) -> Result<(), CallError> {
    update_candid_as(env.pic(), env.canister_id(), sender, "set_jwks", (jwks,)).map(|(res,)| res)
}
