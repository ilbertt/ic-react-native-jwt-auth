#!/bin/bash

set -e

# download Auth0 JWKS
mkdir -p data
source .env
curl -s -o data/jwks.json https://$EXPO_PUBLIC_AUTH0_TENANT_DOMAIN/.well-known/jwks.json

# generate types
dfx generate ic_backend

# build canister
cargo build --target wasm32-unknown-unknown --release -p ic_backend --locked
