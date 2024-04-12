#!/bin/bash

set -e

LOAD_ENV_FILE=true

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
    --ignore-env-file)
      LOAD_ENV_FILE=false
      shift # past argument
      ;;
  esac
done

# load environment variables from .env
if [[ "$LOAD_ENV_FILE" = true ]]; then
  echo -e "\nLoading environment variables from .env file...\n"
  source .env
fi

# generate types
dfx generate ic_backend

# build canister
echo -e "\nBuilding canister..."
echo -e "JWT Issuer: $ID_TOKEN_ISSUER_BASE_URL\nJWT Audience: $ID_TOKEN_AUDIENCE\n"

ID_TOKEN_ISSUER_BASE_URL=$ID_TOKEN_ISSUER_BASE_URL \
ID_TOKEN_AUDIENCE=$ID_TOKEN_AUDIENCE \
cargo build --target wasm32-unknown-unknown --release -p ic_backend --locked

echo -e "\nDone!\n"
