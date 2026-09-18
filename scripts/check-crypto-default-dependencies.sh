#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MANIFEST_PATH="${ROOT}/crypto/Cargo.toml"

dependency_tree() {
  local target="$1"
  shift
  cargo tree \
    --locked \
    --manifest-path "${MANIFEST_PATH}" \
    --target "${target}" \
    --edges normal \
    --prefix none \
    "$@"
}

require_dependency() {
  local tree="$1"
  local dependency="$2"
  local target="$3"

  if ! grep -Eq "^${dependency} v" <<<"${tree}"; then
    echo "${target}: expected ${dependency} in the production dependency graph" >&2
    return 1
  fi
}

reject_dependency() {
  local tree="$1"
  local dependency="$2"
  local target="$3"

  if grep -Eq "^${dependency} v" <<<"${tree}"; then
    echo "${target}: unexpected ${dependency} in the production dependency graph" >&2
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

for target in x86_64-unknown-linux-gnu x86_64-pc-windows-msvc; do
  case "${target}" in
    x86_64-unknown-linux-gnu) backend=crypto_openssl; native_dependency=openssl ;;
    x86_64-pc-windows-msvc) backend=crypto_windows; native_dependency=windows ;;
  esac
  tree="$(dependency_tree "${target}" --no-default-features --features "${backend},x509")"
  require_dependency "${tree}" "${native_dependency}" "${target} (${backend},x509)"
  for dependency in x509-cert pkcs1 der spki; do
    reject_dependency "${tree}" "${dependency}" "${target} (${backend},x509)"
  done
done

echo "Default and native x509 production dependency graphs passed."
