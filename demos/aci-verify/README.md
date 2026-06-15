# aci-verify — Confidential ACI WASM verification demo

A standalone HTML/JS page that exercises the top-level
`tee-attestation-verification-aci` WASM bindings. It verifies an SNP
attestation report, UVM endorsement, and Confidential ACI relying-party policy,
then renders the verified `REPORT_DATA`.

All processing happens client-side; the page makes no network calls other than
loading its own WASM module.

## Build and run

From the repository root, build the ACI WASM package as wasm64, emitting
`aci_pkg/` directly inside this demo directory:

ACI depends on EverParse CBOR code that requires a 64-bit `usize`. Build it as
`wasm64-unknown-unknown` with nightly `build-std`; the target does not have a
prebuilt `rust-std` component, so install `rust-src` and do not run
`rustup target add wasm64-unknown-unknown`.

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

Serve this directory over HTTP:

```sh
cd demos/aci-verify
python3 -m http.server 8000
```

Open <http://localhost:8000/> in a browser.

## Inputs

- **Attestation report** — 1184-byte binary (upload) or hex string.
- **AMD certificate bundle** — `host-amd-cert-base64`.
- **UVM endorsement COSE** — base64-encoded COSE_Sign1.
- **Policy digests** — trusted `HOST_DATA` SHA-256 digests, one hex digest
  per line.
- **Minimum TCB JSON** — optional JSON map of CPUID hex to TCB hex, for example
  `{ "00a00f11": "04000000000018db" }`. Leave empty to skip the minimum TCB
  policy check.
- **UVM feed** and **minimum UVM SVN**.

Fixtures are shipped in `./test-data/`.

Use **Load good example from manifest** to populate the form from
`test-data/manifest.json`. The manifest points at the attestation, AMD bundle,
and UVM endorsement fixtures and includes known-good policy fields.
