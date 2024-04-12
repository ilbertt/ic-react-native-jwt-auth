#!/bin/bash

set -e

ID_TOKEN_ISSUER_BASE_URL="http://unit-test.local/" \
ID_TOKEN_AUDIENCE="unit-test-audience" \
cargo test --package ic_backend --lib
