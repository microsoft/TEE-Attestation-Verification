# C FFI demo

This demo builds the main Rust crate and links a C program against the public
header in `include/tav/tav.h`. It links dynamically by default, or statically
when configured with `-DTAV_LINK_STATIC=ON`.

Run these commands from this directory:

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/tav-c-ffi-demo \
  ../../attestation/tests/test_data/milan_attestation_report.bin \
  ../../attestation/src/pinned_arks/milan_ark.pem \
  ../../attestation/tests/test_data/milan_ask.pem \
  ../../attestation/tests/test_data/milan_vcek.pem
```

To build the same demo with static linking:

```sh
cmake -S . -B build-static -G Ninja -DTAV_LINK_STATIC=ON
cmake --build build-static
./build-static/tav-c-ffi-demo \
  ../../attestation/tests/test_data/milan_attestation_report.bin \
  ../../attestation/src/pinned_arks/milan_ark.pem \
  ../../attestation/tests/test_data/milan_ask.pem \
  ../../attestation/tests/test_data/milan_vcek.pem
```

The CMake build invokes:

```sh
cargo build --manifest-path attestation/Cargo.toml --no-default-features --features crypto_openssl
```
