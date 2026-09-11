#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

target="${1:?Usage: check-clippy.sh <target-triple>}"
case "$target" in
  x86_64-unknown-linux-gnu) backend=crypto_openssl ;;
  x86_64-pc-windows-msvc) backend=crypto_windows ;;
  wasm32-unknown-unknown) backend=crypto_webcrypto ;;
  *) echo "Unsupported Clippy target: $target" >&2; exit 1 ;;
esac

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(( ($(nproc) + 1) >> 1 ))}"
args=(--workspace --all-targets --locked --target "$target")
cargo clippy "${args[@]}" -- -D warnings
cargo clippy "${args[@]}" --no-default-features --features "$backend" -- -D warnings
# KDS is currently exercised by CI on Linux and WASM.
if [[ "$target" != x86_64-pc-windows-msvc ]]; then
  cargo clippy "${args[@]}" --no-default-features \
    --features "$backend,tee-attestation-verification-lib/kds" -- -D warnings
fi
