use ic_agent::identity::BasicIdentity;
use ring::{rand::SystemRandom, signature::Ed25519KeyPair};

pub fn generate_random_identity() -> BasicIdentity {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    BasicIdentity::from_key_pair(key_pair)
}

pub fn pk_to_hex(pk: &[u8]) -> String {
    hex::encode(pk)
}
