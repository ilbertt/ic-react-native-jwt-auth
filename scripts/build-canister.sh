#!/bin/bash

set -e

# load environment variables
source .env

# download Auth0 JWKS
JWKS_JSON_URL=$ID_TOKEN_ISSUER_BASE_URL.well-known/jwks.json
JWKS_JSON_PATH=data/jwks.json

echo -e "\nDownloading Auth0 JWKS from $JWKS_JSON_URL"
mkdir -p data
curl -s -o $JWKS_JSON_PATH $JWKS_JSON_URL
echo -e "Saved Auth0 JWKS to $JWKS_JSON_PATH\n"

# generate types
dfx generate ic_backend

# build canister
echo -e "\nBuilding canister..."
ID_TOKEN_ISSUER_BASE_URL=$ID_TOKEN_ISSUER_BASE_URL \
ID_TOKEN_AUDIENCE=$ID_TOKEN_AUDIENCE \
cargo build --target wasm32-unknown-unknown --release -p ic_backend --locked

echo -e "\nDone!\n"
