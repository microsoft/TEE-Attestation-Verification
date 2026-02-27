# C++ Example — TEE Attestation Verification

This example demonstrates calling the Rust `tav_snp_verify_attestation`
function from C++ via the library's C FFI.

## Prerequisites

| Tool | Version |
|------|---------|
| Rust toolchain (`cargo`) | stable |
| CMake | >= 3.14 |
| C++17 compiler (gcc / clang) | any recent |
| OpenSSL (development headers + libraries) | >= 1.1 |

## Build

```bash
cd c/examples/cpp
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

This will:
1. Detect the repo root (in-tree build) and use `c/CMakeLists.txt`.
2. Run `cargo build --release` to produce the static library (`.a`).
3. Find OpenSSL on the host via `find_package(OpenSSL)`.
4. Compile and link the C++ example against both.

## Run

```bash
./verify_example <report.bin> <vcek.pem> <ask.pem> <ark.pem>
```

For example, using the included test data:

```bash
./verify_example \
    ../../../../tests/test_data/milan_attestation_report.bin \
    ../../../../tests/test_data/milan_vcek.pem \
    ../../../../tests/test_data/milan_ask.pem \
    ../../../../src/pinned_arks/milan_ark.pem
```

On success, all report fields are printed:

```
verification succeeded

  version:          3
  guest_svn:        2
  policy:           0x3001f
  ...
```

On failure, an error code and message are printed:

```
verification failed (code 103): Certificate chain error: ...
```

## Linking in your own project

The `c/CMakeLists.txt` creates a `tee_attestation_verification` imported
library target that carries OpenSSL and system dependencies (pthread, dl, m)
as transitive `INTERFACE_LINK_LIBRARIES`. In your own CMake project:

```cmake
target_link_libraries(my_app PRIVATE tee_attestation_verification)
```

## Out-of-tree / standalone usage

When this `c/examples/cpp/` directory is copied out of the repository, CMake
will automatically fetch the repo via `FetchContent` from GitHub — no manual
clone required.
