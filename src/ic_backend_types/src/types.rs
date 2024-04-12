use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub type UserSub = String;
pub type PublicKey = ByteBuf;
pub type SessionKey = PublicKey;
pub type UserKey = PublicKey;
pub type Timestamp = u64; // in nanos since epoch
pub type Signature = ByteBuf;

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct Delegation {
    pub pubkey: PublicKey,
    pub expiration: Timestamp,
    pub targets: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: Signature,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct PrepareDelegationResponse {
    pub user_key: UserKey,
    pub expiration: Timestamp,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum GetDelegationResponse {
    #[serde(rename = "signed_delegation")]
    SignedDelegation(SignedDelegation),
    #[serde(rename = "no_such_delegation")]
    NoSuchDelegation,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct AuthenticatedResponse {
    pub user_sub: UserSub,
    pub user_principal: Principal,
}

#[derive(CandidType, Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Auth0JWK {
    pub kty: String,
    pub r#use: String,
    pub n: String,
    pub e: String,
    pub kid: String,
    pub x5t: String,
    pub x5c: Vec<String>,
    pub alg: String,
}

#[derive(CandidType, Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Auth0JWKSet {
    pub keys: Vec<Auth0JWK>,
}

impl Auth0JWKSet {
    pub fn find_key(&self, kid: &str) -> Option<&Auth0JWK> {
        self.keys.iter().find(|it| it.kid == kid)
    }
}
