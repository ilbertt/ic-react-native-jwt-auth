mod common;

use candid::Principal;
use ic_agent::Identity;
use ic_backend_types::{AuthenticatedResponse, GetDelegationResponse, PrepareDelegationResponse};
use jwt_simple::prelude::*;

use common::{
    auth_provider::{create_jwt, initialize_auth_provider},
    canister::{
        authenticated, extract_trap_message, get_delegation, initialize_canister,
        prepare_delegation,
    },
    identity::{delegated_identity_from_delegation, generate_random_identity, pk_to_hex},
    test_env::{create_test_env, upgrade_canister},
};

/// Same as on Auth0
const JWT_VALID_FOR_HOURS: u64 = 10;

#[test]
fn test_authenticated_no_user() {
    let env = create_test_env();
    let (_, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let res = authenticated(&env, identity.sender().unwrap()).unwrap_err();

    assert!(extract_trap_message(res).contains("No user found"));
}

#[test]
fn test_authenticated() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let user_sub = "test_sub".to_string();

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        &user_sub,
        &pk_to_hex(&session_identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse {
        expiration,
        user_key,
    } = prepare_delegation(&env, session_principal, jwt.clone()).unwrap();
    let signed_delegation = match get_delegation(&env, session_principal, jwt, expiration).unwrap()
    {
        GetDelegationResponse::SignedDelegation(delegation) => delegation,
        _ => panic!("expected GetDelegationResponse::SignedDelegation"),
    };

    // construct the delegated identity
    let user_identity =
        delegated_identity_from_delegation(user_key, session_identity, signed_delegation);
    let user_principal = user_identity.sender().unwrap();

    let res = authenticated(&env, user_principal).unwrap();

    assert_eq!(
        res,
        AuthenticatedResponse {
            user_principal,
            user_sub,
        },
    );
}

#[test]
fn test_authenticated_wrong_identity() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse { expiration, .. } =
        prepare_delegation(&env, session_principal, jwt.clone()).unwrap();
    get_delegation(&env, session_principal, jwt, expiration).unwrap();

    // use the session identity to call the authenticated method
    let res = authenticated(&env, session_principal).unwrap_err();
    assert!(extract_trap_message(res).contains("No user found"));

    // use another identity to call the authenticated method
    let wrong_identity = generate_random_identity();
    let res = authenticated(&env, wrong_identity.sender().unwrap()).unwrap_err();
    assert!(extract_trap_message(res).contains("No user found"));
}

#[test]
fn test_authenticated_anonymous() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse { expiration, .. } =
        prepare_delegation(&env, session_principal, jwt.clone()).unwrap();
    get_delegation(&env, session_principal, jwt, expiration).unwrap();

    let res = authenticated(&env, Principal::anonymous()).unwrap_err();
    // the anonymous principal is not serialized to Blob of length 29
    assert!(
        extract_trap_message(res).contains("range end index 29 out of range for slice of length 1")
    );
}

#[test]
fn test_authenticated_across_upgrades() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks.clone());

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse {
        expiration,
        user_key,
    } = prepare_delegation(&env, session_principal, jwt.clone()).unwrap();
    let signed_delegation = match get_delegation(&env, session_principal, jwt, expiration).unwrap()
    {
        GetDelegationResponse::SignedDelegation(delegation) => delegation,
        _ => panic!("expected GetDelegationResponse::SignedDelegation"),
    };

    let user_identity =
        delegated_identity_from_delegation(user_key, session_identity, signed_delegation);
    let user_principal = user_identity.sender().unwrap();

    let res_before_upgrade = authenticated(&env, user_principal).unwrap();

    // upgrade the canister
    upgrade_canister(&env);
    initialize_canister(&env, jwks);

    let res_after_upgrade = authenticated(&env, user_principal).unwrap();

    assert_eq!(res_before_upgrade, res_after_upgrade);
}
