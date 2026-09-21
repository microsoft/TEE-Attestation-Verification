#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(( ($(nproc) + 1) >> 1 ))}"

case "${1:-native}" in
    native)
        cargo test --locked -p tee-attestation-verification-didx509 \
            -p tee-attestation-verification-maybe-async \
            -p tee-attestation-verification-caci
        ;;
    wasm)
        wasm-pack test --node --locked --no-default-features --features crypto_webcrypto
        ;;
    dependencies)
        dependencies="$(cargo tree --locked -p tee-attestation-verification-didx509 \
            --target all --edges normal --prefix none --format '{p}')"
        case "$dependencies" in
            *"serde_json v"*)
                printf 'serde_json must remain a dev-dependency, not a production dependency\n' >&2
                exit 1
                ;;
        esac
        for backend in crypto_openssl crypto_windows; do
            case "$backend" in
                crypto_openssl) target=x86_64-unknown-linux-gnu ;;
                crypto_windows) target=x86_64-pc-windows-msvc ;;
            esac
            native_dependencies="$(cargo tree --locked -p tee-attestation-verification-didx509 \
                -p tee-attestation-verification-caci \
                --no-default-features --features "$backend" --target "$target" \
                --edges normal --prefix none --format '{p}')"
            if grep -Eq '^(x509-cert|pkcs1|der|spki) v' <<< "$native_dependencies"; then
                printf '%s DID and CACI dependencies must not include Rust ASN.1/certificate decoders\n' "$backend" >&2
                exit 1
            fi
        done
        ;;
    differential)
        # Requires g++, pkg-config, OpenSSL headers and an openssl CLI >= 3.4.
        python3 -B -m unittest discover -s fuzz/differential -p 'test_*.py'
        python3 -B fuzz/differential/fuzz.py --iterations "${2:-50}" --seed "${3:-1}"
        ;;
    *)
        printf 'Usage: bash didx509/scripts/check.sh [native|wasm|dependencies|differential [iterations [seed]]]\n' >&2
        exit 2
        ;;
esac
