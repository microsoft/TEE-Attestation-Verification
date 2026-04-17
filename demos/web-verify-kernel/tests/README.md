# web-verify-kernel end-to-end tests

Playwright test that drives the `demos/web-verify-kernel/` page in a real browser,
runs the Milan attestation fixture through `verify_attestation_async`, and
diffs the rendered output against `milan_report.expected.txt`.

## Prerequisites

From the repository root, build the WASM package first:

```sh
wasm-pack build --target web --no-default-features --features "crypto_webcrypto"
```

Install JS dependencies and a Chromium browser for Playwright:

```sh
cd demos/web-verify-kernel/tests
npm install
npx playwright install chromium
```

On systems where Playwright's bundled Chromium can't find its shared
libraries (e.g. NixOS), use the `playwright-driver.browsers` package from
nixpkgs instead:

```sh
nix-shell -p playwright-driver.browsers --run '
  export PLAYWRIGHT_BROWSERS_PATH=$(nix-build "<nixpkgs>" -A playwright-driver.browsers --no-out-link)
  export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
  export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
  npm test
'
```

## Running

```sh
npm test
```

The Playwright config starts its own `python3 -m http.server` rooted at the
repo, so no separate server is needed.

## Regenerating the golden file

Run the test with `UPDATE_GOLDEN=1` to capture the current rendered output
into `milan_report.expected.txt`:

```sh
npm run update-golden
```

Do this after any intentional change to `demo.js` rendering or to the WASM
accessors exposed from `src/snp/ffi.rs`.
