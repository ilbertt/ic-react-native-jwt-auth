use base64::{engine::general_purpose, Engine};
use candid::Principal;
use ic_cdk::api::time;
use ic_stable_structures::storable::Blob;
use jsonwebtoken_rustcrypto::errors::ErrorKind;

use crate::id_token::IdTokenResult;

/// Returns the current unix timestamp in seconds
pub fn unix_timestamp() -> u64 {
    time() / 1_000_000_000
}

pub fn base64_decode(input: &str) -> IdTokenResult<Vec<u8>> {
    let engine = general_purpose::URL_SAFE_NO_PAD;
    // let engine = base64::engine::GeneralPurpose::new(
    //     &base64::alphabet::URL_SAFE,
    //     base64::engine::GeneralPurposeConfig::new()
    //         .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    // );
    engine.decode(input).map_err(|e| ErrorKind::Base64(e))
}

pub fn principal_to_blob(principal: Principal) -> Blob<29> {
    principal.as_slice()[..29].try_into().unwrap()
}
