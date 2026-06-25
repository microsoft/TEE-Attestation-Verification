# COSE C FFI demo

This Linux-only demo builds the COSE Rust crate and links a C program against
the public header in `include/tav/cose.h`. It parses a CBOR payload and
deconstructs it through borrowed child handles returned by the C FFI.

Run these commands from this directory:

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/tav-cose-c-ffi-demo "$(cat test-data/caci-uvm-endorsement.hex)"
```

To build the same demo with static linking:

```sh
cmake -S . -B build-static -G Ninja -DTAV_LINK_STATIC=ON
cmake --build build-static
./build-static/tav-cose-c-ffi-demo "$(cat test-data/caci-uvm-endorsement.hex)"
```

The CMake build invokes:

```sh
cargo build --manifest-path cose/Cargo.toml --no-default-features --features crypto_openssl
```
