#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MANIFEST_PATH="${ROOT}/crypto/Cargo.toml"

dependency_tree() {
  cargo tree \
    --locked \
    --manifest-path "${MANIFEST_PATH}" \
    --target "$1" \
    --edges normal \
    --prefix none
}

require_dependency() {
  local tree="$1"
  local dependency="$2"
  local target="$3"

  if ! grep -Eq "^${dependency} v" <<<"${tree}"; then
    echo "${target}: expected ${dependency} in the default dependency graph" >&2
    return 1
  fi
}

reject_dependency() {
  local tree="$1"
  local dependency="$2"
  local target="$3"

  if grep -Eq "^${dependency} v" <<<"${tree}"; then
    echo "${target}: unexpected ${dependency} in the default dependency graph" >&2
    return 1
  fi
}

linux_tree="$(dependency_tree x86_64-unknown-linux-gnu)"
require_dependency "${linux_tree}" openssl x86_64-unknown-linux-gnu
reject_dependency "${linux_tree}" windows x86_64-unknown-linux-gnu
reject_dependency "${linux_tree}" pkcs1 x86_64-unknown-linux-gnu
reject_dependency "${linux_tree}" x509-cert x86_64-unknown-linux-gnu

windows_tree="$(dependency_tree x86_64-pc-windows-msvc)"
require_dependency "${windows_tree}" windows x86_64-pc-windows-msvc
reject_dependency "${windows_tree}" openssl x86_64-pc-windows-msvc
reject_dependency "${windows_tree}" openssl-sys x86_64-pc-windows-msvc
reject_dependency "${windows_tree}" pkcs1 x86_64-pc-windows-msvc
reject_dependency "${windows_tree}" x509-cert x86_64-pc-windows-msvc

wasm_tree="$(dependency_tree wasm32-unknown-unknown)"
require_dependency "${wasm_tree}" pkcs1 wasm32-unknown-unknown
require_dependency "${wasm_tree}" x509-cert wasm32-unknown-unknown
reject_dependency "${wasm_tree}" openssl wasm32-unknown-unknown
reject_dependency "${wasm_tree}" openssl-sys wasm32-unknown-unknown
reject_dependency "${wasm_tree}" windows wasm32-unknown-unknown
