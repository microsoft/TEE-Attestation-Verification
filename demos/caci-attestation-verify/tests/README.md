# caci-attestation-verify end-to-end tests

Playwright tests that drive the `demos/caci-attestation-verify/` page in a real browser and
run the Confidential CACI fixture through the staged CACI WASM bindings.

## How to run

From the repository root, build the CACI WASM package:

ACI depends on EverParse CBOR code that requires a 64-bit `usize`. Build it as
`wasm64-unknown-unknown` with nightly `build-std`; the target does not have a
prebuilt `rust-std` component, so install `rust-src` and do not run 
`rustup target add wasm64-unknown-unknown`.

```sh
rustup toolchain install nightly
rustup +nightly component add rust-src
cargo install wasm-bindgen-cli --version 0.2.122 --locked

cargo +nightly build -Z build-std=std,panic_abort \
  --manifest-path caci/Cargo.toml \
  --target wasm64-unknown-unknown \
  --no-default-features \
  --features "crypto_webcrypto" \
  --release
wasm-bindgen --target web \
  --out-dir demos/caci-attestation-verify/caci_pkg \
  target/wasm64-unknown-unknown/release/tee_attestation_verification_caci.wasm
```

Install JS dependencies and run:

```sh
cd demos/caci-attestation-verify/tests
npm install
npm test
```
