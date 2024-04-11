#!/bin/bash

set -e

# load environment variables
source .env

# parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --issuer)
      ID_TOKEN_ISSUER_BASE_URL="$2"
      shift # past argument
      shift # past value
      ;;
    --audience)
      ID_TOKEN_AUDIENCE="$2"
      shift # past argument
      shift # past value
      ;;
  esac
done

# generate types
dfx generate ic_backend

# build canister
echo -e "\nBuilding canister..."
echo -e "JWT Issuer: $ID_TOKEN_ISSUER_BASE_URL\nJWT Audience: $ID_TOKEN_AUDIENCE\n"

ID_TOKEN_ISSUER_BASE_URL=$ID_TOKEN_ISSUER_BASE_URL \
ID_TOKEN_AUDIENCE=$ID_TOKEN_AUDIENCE \
cargo build --target wasm32-unknown-unknown --release -p ic_backend --locked

echo -e "\nDone!\n"
