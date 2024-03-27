use candid::{CandidType, Deserialize, Principal};
use serde_bytes::ByteBuf;

pub type UserSub = String;
pub type PublicKey = ByteBuf;
pub type SessionKey = PublicKey;
pub type UserKey = PublicKey;
pub type Timestamp = u64; // in nanos since epoch
pub type Signature = ByteBuf;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Delegation {
    pub pubkey: PublicKey,
    pub expiration: Timestamp,
    pub targets: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: Signature,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PrepareDelegationResponse {
    pub user_key: UserKey,
    pub expiration: Timestamp,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum GetDelegationResponse {
    #[serde(rename = "signed_delegation")]
    SignedDelegation(SignedDelegation),
    #[serde(rename = "no_such_delegation")]
    NoSuchDelegation,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct AuthenticatedResponse {
    pub user_sub: UserSub,
    pub user_principal: Principal,
}
