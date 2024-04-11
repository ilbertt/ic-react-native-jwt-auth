mod common;

use ic_agent::Identity;
use jwt_simple::prelude::*;

use common::{
    auth_provider::{create_jwt, initialize_auth_provider},
    canister::{initialize_canister, prepare_delegation},
    identity::{generate_random_identity, pk_to_hex},
    test_env::create_test_env,
};

use crate::common::canister::extract_trap_message;

const NANOS_IN_SECONDS: u64 = 1_000_000_000;

const JWT_VALID_FOR_HOURS: u64 = 10;

#[test]
fn test_prepare_delegation() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (claims, jwt) = create_jwt(
        &auth_provider_key_pair,
        "test",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = prepare_delegation(&env, identity.sender().unwrap(), jwt).unwrap();

    assert_eq!(
        res.expiration,
        claims.expires_at.unwrap().as_secs() * NANOS_IN_SECONDS
    )
}

#[test]
fn test_prepare_delegation_wrong_identity() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (_, jwt) = create_jwt(
        &auth_provider_key_pair,
        "test",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let wrong_identity = generate_random_identity();
    let res = prepare_delegation(&env, wrong_identity.sender().unwrap(), jwt).unwrap_err();

    assert!(extract_trap_message(res).contains("caller and token principal mismatch"));
}
