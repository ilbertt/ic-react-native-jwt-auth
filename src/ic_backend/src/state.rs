use canister_sig_util::signature_map::SignatureMap;
use ic_cdk::{api::management_canister::main::raw_rand, trap};

use crate::{SALT, STATE};

pub type Salt = [u8; 32];

pub const EMPTY_SALT: Salt = [0; 32];

pub struct State {
    pub sigs: SignatureMap,
}

impl Default for State {
    fn default() -> Self {
        Self {
            sigs: SignatureMap::default(),
        }
    }
}

pub async fn init() {
    ensure_salt_initialized().await;
}

pub async fn ensure_salt_initialized() {
    let salt = SALT.with_borrow(|s| s.get().to_owned());
    if salt == EMPTY_SALT {
        let salt = random_salt().await;
        SALT.with_borrow_mut(|s| s.set(salt).unwrap());
    }
}

pub fn salt() -> Salt {
    SALT.with_borrow(|s| s.get().to_owned())
}

pub fn signature_map<R>(f: impl FnOnce(&SignatureMap) -> R) -> R {
    STATE.with_borrow(|s| f(&s.sigs))
}

pub fn signature_map_mut<R>(f: impl FnOnce(&mut SignatureMap) -> R) -> R {
    STATE.with_borrow_mut(|s| f(&mut s.sigs))
}

/// Calls raw rand to retrieve a random salt (32 bytes).
async fn random_salt() -> Salt {
    let res: Vec<u8> = match raw_rand().await {
        Ok((res,)) => res,
        Err((_, err)) => trap(&format!("failed to get salt: {err}")),
    };
    let salt: Salt = res[..].try_into().unwrap_or_else(|_| {
        trap(&format!(
            "expected raw randomness to be of length 32, got {}",
            res.len()
        ));
    });
    salt
}
