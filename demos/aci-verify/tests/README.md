# aci-verify end-to-end tests

Playwright tests that drive the `demos/aci-verify/` page in a real browser and
run the Confidential ACI fixture through the staged ACI WASM bindings.

## How to run

From the repository root, build the ACI WASM package:

```sh
rustup toolchain install nightly
rustup +nightly component add rust-src
cargo install wasm-bindgen-cli --version 0.2.122 --locked

cargo +nightly build -Z build-std=std,panic_abort \
  --manifest-path aci/Cargo.toml \
  --target wasm64-unknown-unknown \
  --no-default-features \
  --features "crypto_webcrypto" \
  --release
wasm-bindgen --target web \
  --out-dir demos/aci-verify/aci_pkg \
  target/wasm64-unknown-unknown/release/tee_attestation_verification_aci.wasm
```

Install JS dependencies and run:

```sh
cd demos/aci-verify/tests
npm install
npm test
```
