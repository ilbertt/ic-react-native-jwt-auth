use canister_sig_util::signature_map::SignatureMap;
use ic_cdk::{api::management_canister::main::raw_rand, trap};

use crate::STATE;

pub type Salt = [u8; 32];

const EMPTY_SALT: Salt = [0; 32];

pub struct State {
    pub salt: Salt,
    pub sigs: SignatureMap,
}

impl Default for State {
    fn default() -> Self {
        Self {
            salt: EMPTY_SALT,
            sigs: SignatureMap::default(),
        }
    }
}

pub async fn init() {
    ensure_salt_initialized().await;
}

pub async fn ensure_salt_initialized() {
    let salt = STATE.with(|s| s.borrow().salt);
    if salt == EMPTY_SALT {
        let salt = random_salt().await;
        STATE.with(|s| s.borrow_mut().salt = salt);
    }
}

pub fn salt() -> Salt {
    STATE.with(|s| s.borrow().salt)
}

pub fn signature_map<R>(f: impl FnOnce(&SignatureMap) -> R) -> R {
    STATE.with(|s| f(&s.borrow().sigs))
}

pub fn signature_map_mut<R>(f: impl FnOnce(&mut SignatureMap) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut().sigs))
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
