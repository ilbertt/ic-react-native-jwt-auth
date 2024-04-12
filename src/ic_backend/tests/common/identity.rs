use ic_agent::identity::{
    BasicIdentity, DelegatedIdentity, Delegation as IcDelegation,
    SignedDelegation as IcSignedDelegation,
};
use ic_backend_types::SignedDelegation;
use ring::{rand::SystemRandom, signature::Ed25519KeyPair};
use serde_bytes::ByteBuf;

pub fn generate_random_identity() -> BasicIdentity {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    BasicIdentity::from_key_pair(key_pair)
}

pub fn pk_to_hex(pk: &[u8]) -> String {
    hex::encode(pk)
}

pub fn delegated_identity_from_delegation(
    user_key: ByteBuf,
    session_identity: BasicIdentity,
    signed_delegation: SignedDelegation,
) -> DelegatedIdentity {
    DelegatedIdentity::new(
        user_key.to_vec(),
        Box::new(session_identity),
        vec![IcSignedDelegation {
            delegation: IcDelegation {
                pubkey: signed_delegation.delegation.pubkey.to_vec(),
                expiration: signed_delegation.delegation.expiration,
                targets: signed_delegation.delegation.targets,
            },
            signature: signed_delegation.signature.to_vec(),
        }],
    )
}
