mod common;

use common::{
    canister::{extract_trap_message, set_jwks, sync_jwks},
    identity::generate_random_identity,
    test_env,
};
use ic_agent::Identity;
use ic_backend::types::Auth0JWKSet;

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
