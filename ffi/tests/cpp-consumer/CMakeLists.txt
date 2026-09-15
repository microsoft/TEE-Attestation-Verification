cmake_minimum_required(VERSION 3.20)

project(tav-cpp-consumer-tests C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The C++ wrapper consumer tests support Linux only.")
endif()

# Crypto backend the Rust library is built with (matches the CI matrix).
set(TAV_BACKEND_FEATURES "crypto_openssl" CACHE STRING
    "Cargo feature selecting the crypto backend for the FFI library")
option(TAV_LINK_STATIC "Link the tests against the Rust static library" OFF)

get_filename_component(TAV_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(TAV_CARGO_TARGET_DIR "${TAV_REPO_ROOT}/target")

foreach(header IN ITEMS byte_buffer.h errors.h utils.h snp.h cbor.h cose.h caci.h byte_buffer.hpp errors.hpp snp.hpp cbor.hpp)
    if(header MATCHES "\\.hpp$")
        set(extensions cpp)
    else()
        set(extensions c cpp)
    endif()
    foreach(extension IN LISTS extensions)
        set(source "${CMAKE_CURRENT_BINARY_DIR}/${header}.${extension}")
        file(GENERATE OUTPUT "${source}" CONTENT "#include <tav/${header}>\n#include <tav/${header}>\n")
        add_library("header-${header}-${extension}" OBJECT "${source}")
        target_include_directories("header-${header}-${extension}" PRIVATE "${TAV_REPO_ROOT}/ffi/include")
    endforeach()
endforeach()

if(TAV_LINK_STATIC)
    set(TAV_RUST_LIBRARY_KIND STATIC)
    set(TAV_RUST_LIBRARY_NAME
        "${CMAKE_STATIC_LIBRARY_PREFIX}tee_attestation_verification_ffi${CMAKE_STATIC_LIBRARY_SUFFIX}")
else()
    set(TAV_RUST_LIBRARY_KIND SHARED)
    set(TAV_RUST_LIBRARY_NAME "libtee_attestation_verification_ffi.so")
endif()
set(TAV_RUST_LIBRARY "${TAV_CARGO_TARGET_DIR}/debug/${TAV_RUST_LIBRARY_NAME}")
set(TAV_TEST_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${TAV_RUST_LIBRARY_NAME}")

add_custom_target(tav_cpp_abi ALL
    COMMAND
        cargo build
        --manifest-path "${TAV_REPO_ROOT}/ffi/Cargo.toml"
        --no-default-features
        --features "${TAV_BACKEND_FEATURES}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${TAV_RUST_LIBRARY}"
        "${TAV_TEST_LIBRARY}"
    WORKING_DIRECTORY "${TAV_REPO_ROOT}"
    BYPRODUCTS "${TAV_TEST_LIBRARY}"
    COMMENT "Building tee-attestation-verification-ffi C ABI"
    VERBATIM)

add_library(tav_cpp ${TAV_RUST_LIBRARY_KIND} IMPORTED GLOBAL)
add_dependencies(tav_cpp tav_cpp_abi)
set_target_properties(tav_cpp PROPERTIES IMPORTED_LOCATION "${TAV_TEST_LIBRARY}")

# A static archive leaves the crate's own dependencies for the consumer to
# resolve; the shared library carries them itself.
if(TAV_LINK_STATIC)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
    set_property(TARGET tav_cpp APPEND PROPERTY INTERFACE_LINK_LIBRARIES
        OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

add_executable(tav-cpp-consumer-tests main.cpp snp.cpp moves.cpp)
target_include_directories(tav-cpp-consumer-tests PRIVATE
    "${TAV_REPO_ROOT}/ffi/tests/c-consumer/vendor"
    "${TAV_REPO_ROOT}/ffi/include")
target_compile_definitions(tav-cpp-consumer-tests PRIVATE TAV_REPO_ROOT="${TAV_REPO_ROOT}")
target_link_libraries(tav-cpp-consumer-tests PRIVATE tav_cpp)
target_compile_options(tav-cpp-consumer-tests PRIVATE
    -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer)
target_link_options(tav-cpp-consumer-tests PRIVATE -fsanitize=address)

if(NOT TAV_LINK_STATIC)
    set_target_properties(tav-cpp-consumer-tests PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN")
endif()

enable_testing()
add_test(NAME cpp-consumer COMMAND tav-cpp-consumer-tests)
find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
add_test(NAME cpp-error-code-completeness
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/check_error_codes.py")
