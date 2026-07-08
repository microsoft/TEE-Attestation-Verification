# WASM consumer API tests

These tests import the generated `tee_attestation_verification_ffi.js` package as
a JavaScript consumer would and exercise the exported wasm API surface. They are
intended to catch accidental JS API compatibility breaks.

From the repository root:

```sh
cd ffi
wasm-pack build --target nodejs --out-dir ../target/wasm-consumer-tests/pkg --no-default-features --features crypto_pure_rust
cd ..
node --test ffi/tests/wasm-consumer/api-consumption.test.cjs
```
