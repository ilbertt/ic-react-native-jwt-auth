use base64::{engine::general_purpose, Engine};
use candid::Principal;
use ic_cdk::api::time;
use ic_stable_structures::storable::Blob;
use jsonwebtoken_rustcrypto::errors::ErrorKind;

use crate::id_token::IdTokenResult;

pub const NANOS_IN_SECONDS: u64 = 1_000_000_000;

/// Returns the current unix timestamp in seconds
pub fn unix_timestamp() -> u64 {
    time() / NANOS_IN_SECONDS
}

pub fn base64_decode(input: &str) -> IdTokenResult<Vec<u8>> {
    let engine = general_purpose::URL_SAFE_NO_PAD;
    engine.decode(input).map_err(ErrorKind::Base64)
}

pub fn principal_to_blob(principal: Principal) -> Blob<29> {
    principal.as_slice()[..29].try_into().unwrap()
}
