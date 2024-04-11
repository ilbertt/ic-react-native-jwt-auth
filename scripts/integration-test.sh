#!/bin/bash

set -e

ID_TOKEN_ISSUER_BASE_URL="http://integration-test.local/"
ID_TOKEN_AUDIENCE="integration-test-audience"

./scripts/download-pocket-ic.sh

./scripts/build-canister.sh --issuer $ID_TOKEN_ISSUER_BASE_URL --audience $ID_TOKEN_AUDIENCE

BIN_DIR="$(pwd)/bin"

ID_TOKEN_ISSUER_BASE_URL=$ID_TOKEN_ISSUER_BASE_URL \
ID_TOKEN_AUDIENCE=$ID_TOKEN_AUDIENCE \
POCKET_IC_MUTE_SERVER=1 \
POCKET_IC_BIN="$BIN_DIR/pocket-ic" \
TEST_CANISTER_WASM_PATH="$BIN_DIR/ic_backend.wasm" \
cargo test --package ic_backend --test '*'
