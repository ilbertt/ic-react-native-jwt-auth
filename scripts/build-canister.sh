#!/bin/bash

set -e

# load environment variables
source .env

# download Auth0 JWKS
mkdir -p data
curl -s -o data/jwks.json $ID_TOKEN_ISSUER_BASE_URL.well-known/jwks.json

# generate types
dfx generate ic_backend

# build canister
cargo build --target wasm32-unknown-unknown --release -p ic_backend --locked
