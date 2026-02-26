cmake_minimum_required(VERSION 3.14)
project(tee_attestation_verification LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Build the Rust static library via cargo
# ---------------------------------------------------------------------------
get_filename_component(_crate_root "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(TAV_CARGO_MANIFEST "${_crate_root}/Cargo.toml")

# Cargo features – defaults include crypto_pure_rust + serde.
# Set TAV_CARGO_FEATURES before including this file to override.
if(NOT DEFINED TAV_CARGO_FEATURES)
    set(TAV_CARGO_FEATURES "--features=crypto_openssl --no-default-features")
endif()

# Determine cargo profile + output dir
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_BUILD_FLAGS "")
    set(CARGO_OUT_DIR "debug")
else()
    set(CARGO_BUILD_FLAGS "--release")
    set(CARGO_OUT_DIR "release")
endif()

# Path to the static archive that cargo will produce.
set(TAV_STATIC_LIB
    "${_crate_root}/target/${CARGO_OUT_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}tee_attestation_verification_lib${CMAKE_STATIC_LIBRARY_SUFFIX}")

add_custom_command(
    OUTPUT  "${TAV_STATIC_LIB}"
    COMMAND cargo build ${CARGO_BUILD_FLAGS}
            --manifest-path "${TAV_CARGO_MANIFEST}"
            --lib
    COMMENT "Building tee-attestation-verification (Rust) …"
    VERBATIM
)

add_custom_target(cargo_build_tee_attestation_verification DEPENDS "${TAV_STATIC_LIB}")

# ---------------------------------------------------------------------------
# Imported library target: tee_attestation_verification
# ---------------------------------------------------------------------------
# Consumers just need:  target_link_libraries(my_app PRIVATE tee_attestation_verification)
add_library(tee_attestation_verification STATIC IMPORTED GLOBAL)
set_target_properties(tee_attestation_verification PROPERTIES
    IMPORTED_LOCATION "${TAV_STATIC_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
add_dependencies(tee_attestation_verification cargo_build_tee_attestation_verification)

# Transitive dependencies required at final link time.
find_package(OpenSSL REQUIRED)
set_property(TARGET tee_attestation_verification APPEND PROPERTY INTERFACE_LINK_LIBRARIES
    OpenSSL::SSL OpenSSL::Crypto)

if(UNIX)
    set_property(TARGET tee_attestation_verification APPEND PROPERTY INTERFACE_LINK_LIBRARIES
        pthread dl m)
endif()
