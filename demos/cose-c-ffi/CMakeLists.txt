cmake_minimum_required(VERSION 3.20)

project(tav-cose-c-ffi-demo C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The COSE C FFI demo supports Linux only.")
endif()

option(TAV_LINK_STATIC "Link the demo against the Rust static library" OFF)

get_filename_component(TAV_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(TAV_CARGO_TARGET_DIR "${TAV_REPO_ROOT}/target")

if(TAV_LINK_STATIC)
    set(TAV_RUST_LIBRARY_KIND STATIC)
    set(TAV_RUST_LIBRARY_NAME
        "${CMAKE_STATIC_LIBRARY_PREFIX}tee_attestation_verification_cose${CMAKE_STATIC_LIBRARY_SUFFIX}")
    set(TAV_RUST_LIBRARY "${TAV_CARGO_TARGET_DIR}/debug/${TAV_RUST_LIBRARY_NAME}")
else()
    set(TAV_RUST_LIBRARY_KIND SHARED)
    set(TAV_RUST_LIBRARY_NAME "libtee_attestation_verification_cose.so")
    set(TAV_RUST_LIBRARY "${TAV_CARGO_TARGET_DIR}/debug/${TAV_RUST_LIBRARY_NAME}")
endif()
set(TAV_DEMO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${TAV_RUST_LIBRARY_NAME}")

add_custom_target(tav_cose_c_abi ALL
    COMMAND
        cargo build
        --manifest-path "${TAV_REPO_ROOT}/cose/Cargo.toml"
        --no-default-features
        --features crypto_openssl
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${TAV_RUST_LIBRARY}"
        "${TAV_DEMO_LIBRARY}"
    WORKING_DIRECTORY "${TAV_REPO_ROOT}"
    BYPRODUCTS "${TAV_DEMO_LIBRARY}"
    COMMENT "Building tee-attestation-verification-cose C ABI"
    VERBATIM)

add_library(tav_cose ${TAV_RUST_LIBRARY_KIND} IMPORTED GLOBAL)
add_dependencies(tav_cose tav_cose_c_abi)
set_target_properties(tav_cose PROPERTIES
    IMPORTED_LOCATION "${TAV_DEMO_LIBRARY}")

if(TAV_LINK_STATIC)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
    set_property(TARGET tav_cose APPEND PROPERTY INTERFACE_LINK_LIBRARIES
        OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

add_executable(tav-cose-c-ffi-demo demo.c)
target_include_directories(tav-cose-c-ffi-demo PRIVATE "${TAV_REPO_ROOT}/include")
target_link_libraries(tav-cose-c-ffi-demo PRIVATE tav_cose)
target_compile_options(tav-cose-c-ffi-demo PRIVATE -Wall -Wextra -Werror)

if(NOT TAV_LINK_STATIC)
    add_custom_command(
        TARGET tav-cose-c-ffi-demo
        POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${TAV_DEMO_LIBRARY}"
            "$<TARGET_FILE_DIR:tav-cose-c-ffi-demo>"
        VERBATIM)
endif()

if(NOT TAV_LINK_STATIC)
    set_target_properties(tav-cose-c-ffi-demo PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN")
endif()
