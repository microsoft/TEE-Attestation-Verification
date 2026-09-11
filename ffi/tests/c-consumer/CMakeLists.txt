cmake_minimum_required(VERSION 3.20)

project(tav-c-consumer-tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The C ABI consumer tests support Linux only.")
endif()

# Crypto backend the Rust library is built with (matches the CI matrix).
set(TAV_BACKEND_FEATURES "crypto_openssl" CACHE STRING
    "Cargo feature selecting the crypto backend for the FFI library")
option(TAV_LINK_STATIC "Link the tests against the Rust static library" OFF)
option(TAV_SANITIZERS "Instrument Rust with ASan and the consumer with ASan/UBSan" OFF)

get_filename_component(TAV_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(TAV_CARGO_TARGET_DIR "${TAV_REPO_ROOT}/target")
set(TAV_CARGO_COMMAND cargo build)
set(TAV_CARGO_OPTIONS)
set(TAV_RUST_PROFILE_DIR "${TAV_CARGO_TARGET_DIR}/debug")

if(TAV_SANITIZERS)
    if(NOT TAV_LINK_STATIC OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang"
       OR NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64"
       OR CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR
            "TAV_SANITIZERS requires native x86_64 Linux, Clang, and TAV_LINK_STATIC=ON.")
    endif()
    # Keep host build scripts uninstrumented and normal Cargo artifacts separate.
    set(TAV_CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo")
    set(TAV_RUST_PROFILE_DIR "${TAV_CARGO_TARGET_DIR}/x86_64-unknown-linux-gnu/debug")
    set(TAV_CARGO_COMMAND "${CMAKE_COMMAND}" -E env
        --unset=CARGO_ENCODED_RUSTFLAGS
        "RUSTFLAGS=-Zsanitizer=address -Zexternal-clangrt -Cforce-frame-pointers=yes"
        cargo +nightly-2026-02-01 build)
    set(TAV_CARGO_OPTIONS --locked -Zbuild-std
        --target x86_64-unknown-linux-gnu
        --target-dir "${TAV_CARGO_TARGET_DIR}")
endif()

if(TAV_LINK_STATIC)
    set(TAV_RUST_LIBRARY_KIND STATIC)
    set(TAV_RUST_LIBRARY_NAME
        "${CMAKE_STATIC_LIBRARY_PREFIX}tee_attestation_verification_ffi${CMAKE_STATIC_LIBRARY_SUFFIX}")
else()
    set(TAV_RUST_LIBRARY_KIND SHARED)
    set(TAV_RUST_LIBRARY_NAME "libtee_attestation_verification_ffi.so")
endif()
set(TAV_RUST_LIBRARY "${TAV_RUST_PROFILE_DIR}/${TAV_RUST_LIBRARY_NAME}")
set(TAV_TEST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${TAV_RUST_LIBRARY_NAME}")

add_custom_target(tav_c_abi ALL
    COMMAND
        ${TAV_CARGO_COMMAND}
        --manifest-path "${TAV_REPO_ROOT}/ffi/Cargo.toml"
        --no-default-features
        --features "${TAV_BACKEND_FEATURES}"
        ${TAV_CARGO_OPTIONS}
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${TAV_RUST_LIBRARY}"
        "${TAV_TEST_LIBRARY}"
    WORKING_DIRECTORY "${TAV_REPO_ROOT}"
    BYPRODUCTS "${TAV_TEST_LIBRARY}"
    COMMENT "Building tee-attestation-verification-ffi C ABI"
    VERBATIM)

add_library(tav ${TAV_RUST_LIBRARY_KIND} IMPORTED GLOBAL)
add_dependencies(tav tav_c_abi)
set_target_properties(tav PROPERTIES IMPORTED_LOCATION "${TAV_TEST_LIBRARY}")

if(TAV_LINK_STATIC)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
    set_property(TARGET tav APPEND PROPERTY INTERFACE_LINK_LIBRARIES
        OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

add_executable(tav-c-consumer-tests
    main.cpp
    utils.cpp
    snp.cpp
    cose.cpp
    caci.cpp)
target_include_directories(tav-c-consumer-tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor"
    "${TAV_REPO_ROOT}/ffi/include")
target_compile_definitions(tav-c-consumer-tests PRIVATE TAV_REPO_ROOT="${TAV_REPO_ROOT}")
target_link_libraries(tav-c-consumer-tests PRIVATE tav)
target_compile_options(tav-c-consumer-tests PRIVATE -Wall -Wextra)

if(TAV_SANITIZERS)
    target_compile_options(tav-c-consumer-tests PRIVATE
        -fsanitize=address,undefined -fno-sanitize-recover=all
        -fno-omit-frame-pointer -g)
    # Rust's static library omits compiler-rt. Clang owns the single ASan runtime.
    target_link_options(tav-c-consumer-tests PRIVATE -fsanitize=address,undefined)
endif()

if(NOT TAV_LINK_STATIC)
    set_target_properties(tav-c-consumer-tests PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN")
endif()

enable_testing()
add_test(NAME c-consumer COMMAND tav-c-consumer-tests)
if(TAV_SANITIZERS)
    set_tests_properties(c-consumer PROPERTIES ENVIRONMENT
        "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1;UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
endif()
