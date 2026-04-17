# web-verify — minimal WASM verification demo

A standalone HTML/JS page that exercises the WASM bindings from `ffi.rs`
(specifically `wasm::verify_attestation_async`) and renders the verified
SEV-SNP attestation report.

All processing happens client-side; the page makes no network calls other
than loading its own WASM module.

## Build and run

All commands run from the **repository root**.

1. Build the WASM package with the WebCrypto backend (produces `pkg/`, which
   `demos/web-verify/index.html` imports via a relative path):

   ```sh
   wasm-pack build --target web -- --no-default-features --features "crypto_webcrypto,kds"
   ```

2. Serve the repository root over HTTP. Browsers will not load WASM modules
   from `file://` URLs, and serving from inside `demos/web-verify/` would put
   `pkg/` out of reach of the `../../pkg/` import.

   ```sh
   python3 -m http.server 8000
   ```

3. Open <http://localhost:8000/demos/web-verify/> in a browser.

After editing Rust sources, rerun step 1 and hard-refresh the browser.

## Inputs

Four inputs, each accepting either a file upload or pasted text:

- **Attestation report** — 1184-byte binary (upload) or hex string (textarea).
- **VCEK**, **ASK**, **ARK** — PEM-encoded certificates.

Test fixtures (Milan) shipped in the repo:

- `tests/test_data/milan_attestation_report.bin`
- `src/pinned_arks/milan_ark.pem`
- `tests/test_data/milan_ask.pem`
- `tests/test_data/milan_vcek.pem`

## Scope of verification

A successful result means the page has verified:

- the ARK → ASK → VCEK certificate chain, and
- the attestation report signature against the VCEK.

It does **not** check:

- that the supplied ARK is a genuine AMD root (the demo uses whatever ARK
  you provide — see `src/pinned_arks/` for the pinned roots),
- TCB freshness,
- the debug or single-socket policy bits,
- whether `measurement` or `report_data` match any expected value.

This is a demo for exploring the WASM surface, not a complete verifier.
