pub mod common;

use std::time::SystemTime;

use candid::Principal;
use ic_agent::Identity;
use ic_backend_types::{
    GetDelegationResponse, PrepareDelegationResponse, SignedDelegation, UserKey,
};
use ic_representation_independent_hash::{representation_independent_hash, Value};
use jwt_simple::prelude::*;

use common::{
    auth_provider::{create_jwt, initialize_auth_provider},
    canister::{extract_trap_message, get_delegation, initialize_canister, prepare_delegation},
    identity::{generate_random_identity, pk_to_hex},
    test_env::{create_test_env, upgrade_canister, TestEnv},
};

const NANOS_IN_SECONDS: u64 = 1_000_000_000;

/// Same as on the canister
const MAX_IAT_AGE_SECONDS: u64 = 10 * 60; // 10 minutes
/// Same as on Auth0
const JWT_VALID_FOR_HOURS: u64 = 10;

fn verify_delegation(
    env: &TestEnv,
    user_key: UserKey,
    signed_delegation: &SignedDelegation,
    root_key: &[u8],
) {
    const DOMAIN_SEPARATOR: &[u8] = b"ic-request-auth-delegation";

    // The signed message is a signature domain separator
    // followed by the representation independent hash of a map with entries
    // pubkey, expiration and targets (if any), using the respective values from the delegation.
    // See https://internetcomputer.org/docs/current/references/ic-interface-spec#authentication for details
    let key_value_pairs = vec![
        (
            "pubkey".to_string(),
            Value::Bytes(signed_delegation.delegation.pubkey.clone().into_vec()),
        ),
        (
            "expiration".to_string(),
            Value::Number(signed_delegation.delegation.expiration),
        ),
    ];
    let mut msg: Vec<u8> = Vec::from([(DOMAIN_SEPARATOR.len() as u8)]);
    msg.extend_from_slice(DOMAIN_SEPARATOR);
    msg.extend_from_slice(&representation_independent_hash(&key_value_pairs));

    env.pic()
        .verify_canister_signature(
            msg,
            signed_delegation.signature.clone().into_vec(),
            user_key.into_vec(),
            root_key.to_vec(),
        )
        .expect("delegation signature invalid");
}

#[test]
fn test_prepare_delegation() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, claims) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = prepare_delegation(&env, session_principal, jwt).unwrap();

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

    let session_identity = generate_random_identity();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
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

    let session_identity = generate_random_identity();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
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

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (_, claims) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    // wrong issuer
    {
        let mut claims = claims.clone();
        claims.issuer = Some("wrong".to_string());
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = prepare_delegation(&env, session_principal, jwt).unwrap_err();

        assert!(extract_trap_message(res).contains("IssuerMismatch"));
    }

    // wrong audience
    {
        let mut claims = claims.clone();
        claims.audiences = Some(Audiences::AsString("wrong".to_string()));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = prepare_delegation(&env, session_principal, jwt).unwrap_err();

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
        let res = prepare_delegation(&env, session_principal, jwt).unwrap_err();

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
        let res = prepare_delegation(&env, session_principal, jwt).unwrap_err();

        assert!(extract_trap_message(res).contains("TokenExpired"));
    }
}

#[test]
fn test_prepare_delegation_across_upgrades() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks.clone());

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res_before_upgrade = prepare_delegation(&env, session_principal, jwt.clone()).unwrap();

    upgrade_canister(&env);
    initialize_canister(&env, jwks);

    let res_after_upgrade = prepare_delegation(&env, session_principal, jwt).unwrap();

    assert_eq!(res_before_upgrade.user_key, res_after_upgrade.user_key);
}

#[test]
fn test_prepare_delegation_different_sessions() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks.clone());

    let session1_identity = generate_random_identity();
    let session1_principal = session1_identity.sender().unwrap();
    let session1_public_key = session1_identity.public_key().unwrap();
    let (jwt1, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session1_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res_session1 = prepare_delegation(&env, session1_principal, jwt1).unwrap();

    let session2_identity = generate_random_identity();
    let session2_principal = session2_identity.sender().unwrap();
    let session2_public_key = session2_identity.public_key().unwrap();
    let (jwt2, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session2_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res_session2 = prepare_delegation(&env, session2_principal, jwt2).unwrap();

    assert_eq!(res_session1.user_key, res_session2.user_key);
}

#[test]
fn test_get_delegation() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse {
        expiration,
        user_key,
    } = prepare_delegation(&env, session_principal, jwt.clone()).unwrap();

    let res = get_delegation(&env, session_principal, jwt, expiration).unwrap();

    match res {
        GetDelegationResponse::SignedDelegation(signed_delegation) => {
            assert_eq!(signed_delegation.delegation.pubkey, session_public_key);
            assert_eq!(signed_delegation.delegation.expiration, expiration);
            assert!(signed_delegation.delegation.targets.is_none());

            verify_delegation(&env, user_key, &signed_delegation, env.root_ic_key());
        }
        _ => panic!("Expected SignedDelegation"),
    }
}

#[test]
fn test_get_delegation_wrong_sub() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let PrepareDelegationResponse { expiration, .. } =
        prepare_delegation(&env, session_principal, jwt).unwrap();

    let (wrong_jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "wrong_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = get_delegation(&env, session_principal, wrong_jwt, expiration).unwrap();

    assert_eq!(res, GetDelegationResponse::NoSuchDelegation);
}

#[test]
fn test_get_delegation_wrong_expiration() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    prepare_delegation(&env, session_principal, jwt.clone()).unwrap();

    let res = get_delegation(&env, session_principal, jwt, 0).unwrap();

    assert_eq!(res, GetDelegationResponse::NoSuchDelegation);
}

#[test]
fn test_get_delegation_wrong_identity() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
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

    let session_identity = generate_random_identity();
    let session_public_key = session_identity.public_key().unwrap();
    let (jwt, _) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    let res = get_delegation(&env, Principal::anonymous(), jwt, 0).unwrap_err();

    assert!(extract_trap_message(res).contains("caller and token principal mismatch"));
}

#[test]
fn test_get_delegation_wrong_claims() {
    let env = create_test_env();
    let (auth_provider_key_pair, jwks) = initialize_auth_provider();
    initialize_canister(&env, jwks);

    let session_identity = generate_random_identity();
    let session_principal = session_identity.sender().unwrap();
    let session_public_key = session_identity.public_key().unwrap();
    let (_, claims) = create_jwt(
        &auth_provider_key_pair,
        "test_sub",
        &pk_to_hex(&session_public_key),
        Duration::from_hours(JWT_VALID_FOR_HOURS),
    );

    // wrong issuer
    {
        let mut claims = claims.clone();
        claims.issuer = Some("wrong".to_string());
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = get_delegation(&env, session_principal, jwt, 0).unwrap_err();

        assert!(extract_trap_message(res).contains("IssuerMismatch"));
    }

    // wrong audience
    {
        let mut claims = claims.clone();
        claims.audiences = Some(Audiences::AsString("wrong".to_string()));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = get_delegation(&env, session_principal, jwt, 0).unwrap_err();

        assert!(extract_trap_message(res).contains("AudienceMismatch"));
    }

    // iat too old
    {
        let mut claims = claims.clone();
        let issued_at = claims.issued_at.unwrap();

        env.set_canister_time(issued_at.into());

        claims.issued_at = Some(issued_at - Duration::from_secs(MAX_IAT_AGE_SECONDS + 1));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = get_delegation(&env, session_principal, jwt, 0).unwrap_err();

        assert!(extract_trap_message(res).contains("IatTooOld"));
    }

    // expired
    {
        let mut claims = claims.clone();
        let expires_at = claims.expires_at.unwrap();

        env.set_canister_time(expires_at.into());

        claims.expires_at = Some(expires_at - Duration::from_secs(1));
        let jwt = auth_provider_key_pair.sign(claims).unwrap();
        let res = get_delegation(&env, session_principal, jwt, 0).unwrap_err();

        assert!(extract_trap_message(res).contains("TokenExpired"));
    }
}
