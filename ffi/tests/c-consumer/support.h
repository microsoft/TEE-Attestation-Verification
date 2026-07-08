// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared helpers for the C ABI consumer tests. Each translation unit includes
// this header plus doctest, and contributes TEST_CASEs for one API surface.

#pragma once

#include "doctest.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

extern "C" {
#include "tav/caci.h"
#include "tav/cose.h"
#include "tav/snp.h"
#include "tav/utils.h"
}

#ifndef TAV_REPO_ROOT
#error "TAV_REPO_ROOT must be defined by the build system"
#endif

namespace tav_test {

// Mirrors c_ffi::utils::MAX_INPUT_LEN (1 GiB); not exported by the headers.
constexpr size_t kMaxInputLen = 1024ull * 1024ull * 1024ull;

inline std::vector<uint8_t> read_file(const std::string &relative) {
    std::string path = std::string(TAV_REPO_ROOT) + "/" + relative;
    FILE *file = std::fopen(path.c_str(), "rb");
    REQUIRE_MESSAGE(file != nullptr, "failed to open fixture: " << path);
    std::fseek(file, 0, SEEK_END);
    long size = std::ftell(file);
    REQUIRE(size >= 0);
    std::rewind(file);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (size > 0) {
        REQUIRE(std::fread(bytes.data(), 1, bytes.size(), file) == bytes.size());
    }
    std::fclose(file);
    return bytes;
}

} // namespace tav_test
