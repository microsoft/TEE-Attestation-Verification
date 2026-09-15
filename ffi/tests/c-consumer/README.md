# C ABI consumer tests

These tests link the built `tee-attestation-verification-ffi` library and drive
the exported C ABI through the installed `tav/*.h` headers, exactly as an
external C consumer would. They are intended to catch accidental breaks in the
shipped C ABI (symbols, signatures, return codes, and ownership contract) that
the in-crate Rust unit tests cannot observe, since those never cross the real
ABI boundary.

The CBOR/COSE coverage exercises independently owned direct and nested child
views, validated COSE_Sign1 views, parent-first freeing, and failure
out-parameters.

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

## Run with sanitizers

On native x86_64 Linux, install Clang 18 with compiler-rt, CMake, OpenSSL
development files, pkg-config, and rustup. From the repository root, run:

```sh
rustup toolchain install nightly-2026-02-01 --profile minimal --component rust-src
export CARGO_BUILD_JOBS="$(( ($(nproc) + 1) >> 1 ))"
export CMAKE_BUILD_PARALLEL_LEVEL="$CARGO_BUILD_JOBS"
cmake -S ffi/tests/c-consumer -B target/c-consumer-sanitizers \
	-DCMAKE_CXX_COMPILER=clang++-18 \
	-DTAV_LINK_STATIC=ON \
	-DTAV_SANITIZERS=ON
cmake --build target/c-consumer-sanitizers
ctest --test-dir target/c-consumer-sanitizers --output-on-failure
```

`TAV_SANITIZERS` rebuilds the Rust FFI, its Rust dependencies, and the standard
library with nightly ASan. The explicit target keeps host build scripts
uninstrumented. Cargo artifacts stay in the CMake build directory, separate
from normal builds. This mode replaces inherited Rust flags.

The C++ consumer compiles with `-fsanitize=address,undefined`. Rust uses
`-Zsanitizer=address -Zexternal-clangrt`, so Clang supplies the single ASan
runtime when linking the static Rust archive into the test executable.
Sanitizer mode rejects shared linking and non-Clang compilers. Normal shared
and static builds remain unchanged.

CTest enables leak detection and stops on ASan or UBSan errors. UBSan recovery
is also disabled at compile time, so violations fail the CI job.
UBSan covers the C++ consumer, not Rust. System OpenSSL is not instrumented.
The dedicated `ci-ffi-sanitizers.yml` workflow runs this configuration on
Ubuntu 24.04. Keep its nightly pin and the CMake nightly pin in sync.
