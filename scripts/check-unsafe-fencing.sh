#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(( ($(nproc) + 1) >> 1 ))}"

# Requires the pinned toolchain, both cross-target standard libraries, and OpenSSL.
# Check libraries without linking or attempting to run cross-target tests.
for configuration in native windows wasm; do
  case "${configuration}" in
    native) args=(--features crypto_openssl) ;;
    windows) args=(--target x86_64-pc-windows-gnu --features crypto_windows) ;;
    wasm) args=(--target wasm32-unknown-unknown --features crypto_webcrypto) ;;
  esac
  cargo check --locked --workspace --lib --no-default-features "${args[@]}"
done
