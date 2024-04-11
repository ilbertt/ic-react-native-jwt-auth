mod common;

use std::time::SystemTime;

use candid::Principal;
use ic_agent::Identity;
use ic_backend_types::{
    Delegation, GetDelegationResponse, PrepareDelegationResponse, SignedDelegation,
};
use jwt_simple::prelude::*;

use common::{
    auth_provider::{create_jwt, initialize_auth_provider},
    canister::{get_delegation, initialize_canister, prepare_delegation},
    identity::{generate_random_identity, pk_to_hex},
    test_env::create_test_env,
};

use crate::common::canister::extract_trap_message;

const NANOS_IN_SECONDS: u64 = 1_000_000_000;

/// Same as on the canister
const MAX_IAT_AGE_SECONDS: u64 = 10 * 60; // 10 minutes
/// Same as on Auth0
const JWT_VALID_FOR_HOURS: u64 = 10;

#[test]
fn test_prepare_delegation() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (jwt, claims) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
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
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let wrong_identity = generate_random_identity();
    let res = prepare_delegation(&env, wrong_identity.sender().unwrap(), jwt).unwrap_err();

    assert!(extract_trap_message(res).contains("caller and token principal mismatch"));
}

#[test]
fn test_prepare_delegation_anonymous() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = prepare_delegation(&env, Principal::anonymous(), jwt).unwrap_err();

    assert!(extract_trap_message(res).contains("caller and token principal mismatch"));
}

#[test]
fn test_prepare_delegation_wrong_claims() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (_, claims) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    // wrong issuer
    {
        let mut claims = claims.clone();
        claims.issuer = Some("wrong".to_string());
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = prepare_delegation(&env, identity.sender().unwrap(), jwt).unwrap_err();

        assert!(extract_trap_message(res).contains("IssuerMismatch"));
    }

    // wrong audience
    {
        let mut claims = claims.clone();
        claims.audiences = Some(Audiences::AsString("wrong".to_string()));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = prepare_delegation(&env, identity.sender().unwrap(), jwt).unwrap_err();

        assert!(extract_trap_message(res).contains("AudienceMismatch"));
    }

    // iat too old
    {
        let mut claims = claims.clone();
        let issued_at = claims.issued_at.unwrap();

        let time = SystemTime::UNIX_EPOCH
            .checked_add(issued_at.into())
            .unwrap();
        env.pic().set_time(time);

        claims.issued_at = Some(issued_at - Duration::from_secs(MAX_IAT_AGE_SECONDS + 1));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = prepare_delegation(&env, identity.sender().unwrap(), jwt).unwrap_err();

        assert!(extract_trap_message(res).contains("IatTooOld"));
    }

    // expired
    {
        let mut claims = claims.clone();
        let expires_at = claims.expires_at.unwrap();

        let time = SystemTime::UNIX_EPOCH
            .checked_add(expires_at.into())
            .unwrap();
        env.pic().set_time(time);

        claims.expires_at = Some(expires_at - Duration::from_secs(1));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = prepare_delegation(&env, identity.sender().unwrap(), jwt).unwrap_err();

        assert!(extract_trap_message(res).contains("TokenExpired"));
    }
}

#[test]
fn test_get_delegation() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let identity_public_key = identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse { expiration, .. } =
        prepare_delegation(&env, identity.sender().unwrap(), jwt.clone()).unwrap();

    let res = get_delegation(&env, identity.sender().unwrap(), jwt, expiration).unwrap();

    match res {
        GetDelegationResponse::SignedDelegation(SignedDelegation {
            delegation:
                Delegation {
                    targets,
                    pubkey,
                    expiration,
                },
            ..
        }) => {
            assert_eq!(pubkey, identity_public_key);
            assert_eq!(expiration, expiration);
            assert!(targets.is_none());
        }
        _ => panic!("Expected SignedDelegation"),
    }
}

#[test]
fn test_get_delegation_wrong_sub() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let identity_public_key = identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse { expiration, .. } =
        prepare_delegation(&env, identity.sender().unwrap(), jwt).unwrap();

    let (wrong_jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "wrong_sub",
        &pk_to_hex(&identity_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = get_delegation(&env, identity.sender().unwrap(), wrong_jwt, expiration).unwrap();

    assert_eq!(res, GetDelegationResponse::NoSuchDelegation);
}

#[test]
fn test_get_delegation_wrong_expiration() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let identity_public_key = identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    prepare_delegation(&env, identity.sender().unwrap(), jwt.clone()).unwrap();

    let res = get_delegation(&env, identity.sender().unwrap(), jwt, 0).unwrap();

    assert_eq!(res, GetDelegationResponse::NoSuchDelegation);
}

#[test]
fn test_get_delegation_wrong_identity() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let wrong_identity = generate_random_identity();
    let res = get_delegation(&env, wrong_identity.sender().unwrap(), jwt, 0).unwrap_err();

    assert!(extract_trap_message(res).contains("caller and token principal mismatch"));
}

#[test]
fn test_get_delegation_anonymous() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let identity = generate_random_identity();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&identity.public_key().unwrap()),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = get_delegation(&env, Principal::anonymous(), jwt, 0).unwrap_err();

    assert!(extract_trap_message(res).contains("caller and token principal mismatch"));
}
