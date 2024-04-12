use candid::Principal;
use canister_sig_util::{
    delegation_signature_msg, hash_bytes,
    signature_map::{SignatureMap, LABEL_SIG},
    CanisterSigPublicKey,
};
use ic_backend_types::{
    Delegation, GetDelegationResponse, PublicKey, SessionKey, SignedDelegation, Timestamp, UserKey,
    UserSub,
};
use ic_cdk::{api::set_certified_data, id};
use ic_certification::{labeled_hash, Hash};
use serde_bytes::ByteBuf;

use crate::state;

pub async fn prepare_delegation(
    user_sub: &UserSub,
    session_key: SessionKey,
    expiration: Timestamp,
) -> UserKey {
    state::ensure_salt_initialized().await;
    let seed = calculate_seed(user_sub);

    state::signature_map_mut(|sigs| {
        add_delegation_signature(sigs, session_key, seed.as_ref(), expiration);
    });
    update_root_hash();

    ByteBuf::from(der_encode_canister_sig_key(seed.to_vec()))
}

pub fn get_delegation(
    user_sub: &UserSub,
    session_key: SessionKey,
    expiration: Timestamp,
) -> GetDelegationResponse {
    state::signature_map(|sigs| {
        let message_hash = delegation_signature_msg_hash(&session_key, expiration);
        match sigs.get_signature_as_cbor(&calculate_seed(user_sub), message_hash, None) {
            Ok(signature) => GetDelegationResponse::SignedDelegation(SignedDelegation {
                delegation: Delegation {
                    pubkey: session_key,
                    expiration,
                    targets: None,
                },
                signature: ByteBuf::from(signature),
            }),
            Err(_) => GetDelegationResponse::NoSuchDelegation,
        }
    })
}

pub fn get_principal(user_sub: &UserSub) -> Principal {
    let seed = calculate_seed(user_sub);
    let public_key = der_encode_canister_sig_key(seed.to_vec());
    Principal::self_authenticating(public_key)
}

fn calculate_seed(user_sub: &UserSub) -> Hash {
    let salt = state::salt();

    let mut blob: Vec<u8> = vec![];
    blob.push(salt.len() as u8);
    blob.extend_from_slice(&salt);

    let user_sub_blob = user_sub.bytes();
    blob.push(user_sub_blob.len() as u8);
    blob.extend(user_sub_blob);

    hash_bytes(blob)
}

fn update_root_hash() {
    state::signature_map(|sigs| {
        let prefixed_root_hash = labeled_hash(LABEL_SIG, &sigs.root_hash());
        set_certified_data(&prefixed_root_hash[..]);
    })
}

fn delegation_signature_msg_hash(pubkey: &PublicKey, expiration: Timestamp) -> Hash {
    let msg = delegation_signature_msg(pubkey, expiration, None);
    hash_bytes(msg)
}

fn add_delegation_signature(
    sigs: &mut SignatureMap,
    pk: PublicKey,
    seed: &[u8],
    expiration: Timestamp,
) {
    let msg_hash = delegation_signature_msg_hash(&pk, expiration);
    sigs.add_signature(seed, msg_hash);
}

fn der_encode_canister_sig_key(seed: Vec<u8>) -> Vec<u8> {
    let my_canister_id = id();
    CanisterSigPublicKey::new(my_canister_id, seed).to_der()
}
