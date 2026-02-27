cmake_minimum_required(VERSION 3.14)
project(tav_cpp_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# 1. Fetch the tee-attestation-verification library
# ---------------------------------------------------------------------------

# Here we use a relative import as the files are available
# use this if you want to vendor the library
get_filename_component(_c_dir "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(_repo_root "${_c_dir}/.." ABSOLUTE)
add_subdirectory("${_c_dir}" "${CMAKE_CURRENT_BINARY_DIR}/tee_attestation_verification")

# Comment the above and uncomment this to instead fetch the code
#
# include(FetchContent)
# message(STATUS "Fetching tee-attestation-verification from GitHub …")
# FetchContent_Declare(
#     tee_attestation_verification_repo
#     GIT_REPOSITORY https://github.com/microsoft/TEE-Attestation-Verification.git
#     GIT_TAG        main
# )
# FetchContent_Populate(tee_attestation_verification_repo)
# add_subdirectory(
#     "${tee_attestation_verification_repo_SOURCE_DIR}/c"
#     "${tee_attestation_verification_repo_BINARY_DIR}")

# ---------------------------------------------------------------------------
# 2. Build the C++ example
# ---------------------------------------------------------------------------
add_executable(verify_example main.cpp)
target_link_libraries(verify_example PRIVATE tee_attestation_verification)
