#!/bin/bash

set -e

# load environment variables
source .env

# generate types
dfx generate ic_backend

# build canister
echo -e "\nBuilding canister..."
ID_TOKEN_ISSUER_BASE_URL=$ID_TOKEN_ISSUER_BASE_URL \
ID_TOKEN_AUDIENCE=$ID_TOKEN_AUDIENCE \
cargo build --target wasm32-unknown-unknown --release -p ic_backend --locked

echo -e "\nDone!\n"
