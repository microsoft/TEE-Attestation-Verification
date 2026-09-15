# Web Attester Demo

A browser-based demo that verifies a backend service's TEE attestation before trusting it. Uses the verification library compiled to WASM with the WebCrypto backend.

## How it works

1. The frontend fetches a raw 1184-byte SEV-SNP attestation report from the backend
2. The WASM verification library validates the report signature and certificate chain (via AMD KDS)
3. Application-level measurements are checked against expected values in `config.js`
4. If verification passes, the app UI loads and begins fetching data from the trusted backend
5. If verification fails, a block page is shown with the error

## Setup

### Build the WASM package

From the repository root:

```bash
# TODO: depending on how we implement the attester service, we may ideally opt
# to use the verification kernel with cert collateral, rather than kds. 
wasm-pack build --target web --no-default-features --features "crypto_webcrypto,kds"
```

Then symlink the output into this directory:

```bash
ln -s ../../pkg demos/web-attester/pkg
```

### Configure the backend

Edit `config.js` to point at your attester service:

```js
backendUrl: "http://localhost:8080",
attestationEndpoint: "/api/attestation",  // must return raw 1184-byte report
dataEndpoint: "/api/data",                // application data (JSON)
```

Set expected measurements to match your deployment, or leave as `null` to skip checks:

```js
expectedMeasurements: {
  measurement: "abcdef...",    // SHA-384 hex (96 chars)
  policy: "196608",           // decimal u64
  reportDataPrefix: "aa00..", // hex prefix
  hostData: "bb11..",         // hex (64 chars)
},
```

### Backend requirements

The backend must expose:

- **`GET /api/attestation`** — Returns the raw SEV-SNP attestation report as `application/octet-stream` (exactly 1184 bytes)
- **`GET /api/data`** — Returns JSON application data (only fetched after attestation succeeds)

### Serve the demo

Any static file server works:

```bash
cd demos/web-attester
python3 -m http.server 3000
```

Then open `http://localhost:3000`.
