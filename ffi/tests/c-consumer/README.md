# C ABI consumer tests

These tests link the built `tee-attestation-verification-ffi` library and drive
the exported C ABI through the installed `tav/*.h` headers, exactly as an
external C consumer would. They are intended to catch accidental breaks in the
shipped C ABI (symbols, signatures, return codes, and ownership contract) that
the in-crate Rust unit tests cannot observe, since those never cross the real
ABI boundary.

The CBOR and COSE tests use the shared `TavCborHandle` API. Coverage includes
borrowed parsing, deep-copied payloads, direct and nested child views, validated
COSE_Sign1 views, parent-first freeing, map key equality, and depth limits.
Failed reads preserve scalar and borrowed outputs; failed navigation clears
owned output slots.

The suite uses [doctest](https://github.com/doctest/doctest), vendored as a
single header under `vendor/doctest.h` (MIT licensed).

From the repository root:

```sh
cmake -S ffi/tests/c-consumer -B target/c-consumer-tests
cmake --build target/c-consumer-tests
ctest --test-dir target/c-consumer-tests --output-on-failure
```

Select the crypto backend with `-DTAV_BACKEND_FEATURES=crypto_openssl`
(the default), or link the static library with `-DTAV_LINK_STATIC=ON`.
