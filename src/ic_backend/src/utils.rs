use base64::Engine;
use ic_cdk::api::time;
use jsonwebtoken_rustcrypto::errors::ErrorKind;

use crate::id_token::IdTokenResult;

/// Returns the current unix timestamp in seconds
pub fn unix_timestamp() -> u64 {
    time() / 1_000_000_000
}

pub fn base64_decode(input: &str) -> IdTokenResult<Vec<u8>> {
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    );
    Ok(engine.decode(input).map_err(|e| ErrorKind::Base64(e))?)
}
