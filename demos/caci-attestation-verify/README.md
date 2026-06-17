# caci-attestation-verify — Confidential CACI WASM verification demo

A standalone HTML/JS page that exercises the top-level
`tee-attestation-verification-caci` WASM bindings. It verifies an SNP
attestation report, UVM endorsement, and Confidential CACI relying-party policy,
then renders the verified `REPORT_DATA`.

All processing happens client-side; the page makes no network calls other than
loading its own WASM module.

## Build and run

Use either a release bundle or a local build.

### Option A: use a release bundle

Download `tav-caci-<version>.tar.gz` from the matching GitHub release, then
extract it into the demo's expected `caci_pkg/` directory:

```sh
cd demos/caci-attestation-verify
mkdir -p caci_pkg
tar -xzf /path/to/tav-caci-<version>.tar.gz --strip-components=1 -C caci_pkg
python3 -m http.server 8000
```

Open <http://localhost:8000/> in a browser.

### Option B: build from source

From the repository root, build the CACI WASM package as wasm64, emitting
`caci_pkg/` directly inside this demo directory:

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

Serve this directory over HTTP:

```sh
cd demos/caci-attestation-verify
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
