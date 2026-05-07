# web-verify-kernel — minimal WASM verification demo

A standalone HTML/JS page that exercises the WASM bindings from `ffi.rs`
(specifically `wasm::verify_attestation_async`) and renders the verified
SEV-SNP attestation report.

All processing happens client-side; the page makes no network calls other
than loading its own WASM module.

## Build and run

1. From the **repository root**, build the WASM package with the WebCrypto
   backend, emitting `pkg/` directly inside this demo directory (which is
   what `index.html` imports via `./pkg/...`):

   ```sh
   wasm-pack build --target web --out-dir demos/web-verify-kernel/pkg --no-default-features --features "crypto_webcrypto"
   ```

2. Serve **this directory** over HTTP.

   ```sh
   cd demos/web-verify-kernel
   python3 -m http.server 8000
   ```

3. Open <http://localhost:8000/> in a browser.

After editing Rust sources, rerun step 1 and hard-refresh the browser.

## Inputs

Four inputs, each accepting either a file upload or pasted text:

- **Attestation report** — 1184-byte binary (upload) or hex string (textarea).
- **VCEK**, **ASK**, **ARK** — PEM-encoded certificates.

Test fixtures shipped alongside the demo in `./test-data/`:

- Milan: `milan_attestation_report.bin`, `milan_vcek.pem`, `milan_ask.pem`,
  `milan_ark.pem`.
- Turin: `turin_attestation_report.bin`, `turin_vcek.pem`, `turin_ask.pem`,
  `turin_ark.pem`.

These are mirrors of upstream files in `tests/test_data/` and
`src/pinned_arks/`.

## Scope of verification

A successful result means the page has verified:

- that the supplied ARK public key matches the pinned AMD root for the report's
  processor generation,
- the ARK → ASK → VCEK certificate chain,
- the attestation report signature against the VCEK, and
- report/VCEK TCB extension matching.

It does **not** check:

- TCB freshness or revocation status,
- the debug or single-socket policy bits,
- whether `measurement` or `report_data` match any expected value.

This is a demo for exploring the WASM surface, not a complete verifier.
