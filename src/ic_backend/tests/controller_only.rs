pub mod common;

use common::{
    canister::{extract_trap_message, get_jwks, set_jwks, sync_jwks},
    identity::generate_random_identity,
    test_env,
};
use ic_agent::Identity;
use ic_backend_types::Auth0JWKSet;

#[test]
fn test_sync_jwks_controller_only() {
    let env = test_env::create_test_env();

    let sender = generate_random_identity().sender().unwrap();

    let res = sync_jwks(&env, sender).unwrap_err();

    assert!(extract_trap_message(res).contains("caller is not a controller"));
}

#[test]
fn test_set_jwks_controller_only() {
    let env = test_env::create_test_env();

    let sender = generate_random_identity().sender().unwrap();

    let res = set_jwks(&env, sender, Auth0JWKSet { keys: vec![] }).unwrap_err();

    assert!(extract_trap_message(res).contains("caller is not a controller"));
}

#[test]
fn test_set_jwks_once() {
    let env = test_env::create_test_env();

    // initially, the canister doesn't have the jwks
    let canister_jwks = get_jwks(&env, env.controller()).unwrap();
    assert!(canister_jwks.is_none());

    // set dummy jwks
    let jwks = Auth0JWKSet { keys: vec![] };
    set_jwks(&env, env.controller(), jwks.clone()).unwrap();

    // now the canister has the jwks
    let canister_jwks = get_jwks(&env, env.controller()).unwrap().unwrap();
    assert_eq!(canister_jwks, jwks);

    // try to set the jwks again
    let res = set_jwks(&env, env.controller(), jwks).unwrap_err();
    assert!(extract_trap_message(res)
        .contains("JWKS already set. Call sync_jwks to fetch the JWKS from the auth provider"));
}

#[test]
fn test_get_jwks_controller_only() {
    let env = test_env::create_test_env();

    let sender = generate_random_identity().sender().unwrap();

    let res = get_jwks(&env, sender).unwrap_err();

    assert!(extract_trap_message(res).contains("caller is not a controller"));
}
