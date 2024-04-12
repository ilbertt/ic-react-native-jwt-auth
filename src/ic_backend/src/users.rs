use candid::Principal;
use ic_backend_types::UserSub;

use crate::{utils::principal_to_blob, PRINCIPAL_USER_SUB};

pub fn register_user(principal: Principal, user_sub: UserSub) {
    PRINCIPAL_USER_SUB.with_borrow_mut(|s| s.insert(principal_to_blob(principal), user_sub));
}

pub fn get_user_sub(principal: Principal) -> Option<UserSub> {
    PRINCIPAL_USER_SUB.with_borrow(|s| s.get(&principal_to_blob(principal)))
}
