// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Example: verify an SEV-SNP attestation report from C++ using the
// tee-attestation-verification Rust library via its C FFI.
//
// Usage:
//   ./verify_example <report.bin> <vcek.pem> <ask.pem> <ark.pem>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "tee_attestation_verification.h"

/// Read an entire file into a byte vector.
static std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "error: cannot open " << path << "\n";
        std::exit(1);
    }
    auto size = ifs.tellg();
    ifs.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    ifs.read(reinterpret_cast<char *>(buf.data()), size);
    return buf;
}

/// Print the first N bytes of a buffer as hex.
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        std::printf("%02x", data[i]);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0]
                  << " <report.bin> <vcek.pem> <ask.pem> <ark.pem>\n";
        return 1;
    }

    auto report_bytes = read_file(argv[1]);
    auto vcek = read_file(argv[2]);
    auto ask  = read_file(argv[3]);
    auto ark  = read_file(argv[4]);

    TAVError *err = nullptr;
    const TAVSNPAttestationReport *report = tav_snp_verify_attestation(
        report_bytes.data(), report_bytes.size(),
        ark.data(),  ark.size(),
        ask.data(),  ask.size(),
        vcek.data(), vcek.size(),
        &err
    );

    if (report == nullptr) {
        std::cerr << "verification failed (code "
                  << tav_error_code(err) << "): "
                  << tav_error_message(err) << "\n";
        tav_free_error(err);
        return 1;
    }

    std::cout << "verification succeeded\n\n";

    std::cout << "  version:           " << report->version       << "\n"
              << "  guest_svn:         " << report->guest_svn     << "\n"
              << "  policy:            0x" << std::hex << report->policy << std::dec << "\n"
              << "  family_id:         "; print_hex(report->family_id, sizeof(report->family_id));
    std::cout << "\n"
              << "  image_id:          "; print_hex(report->image_id, sizeof(report->image_id));
    std::cout << "\n"
              << "  vmpl:              " << report->vmpl          << "\n"
              << "  signature_algo:    " << report->signature_algo << "\n"
              << "  platform_version:  "; print_hex(report->platform_version.raw, sizeof(report->platform_version.raw));
    std::cout << "\n"
              << "  platform_info:     0x" << std::hex << report->platform_info << std::dec << "\n"
              << "  flags:             0x" << std::hex << report->flags << std::dec << "\n"
              << "  report_data:       "; print_hex(report->report_data, sizeof(report->report_data));
    std::cout << "\n"
              << "  measurement:       "; print_hex(report->measurement, sizeof(report->measurement));
    std::cout << "\n"
              << "  host_data:         "; print_hex(report->host_data, sizeof(report->host_data));
    std::cout << "\n"
              << "  id_key_digest:     "; print_hex(report->id_key_digest, sizeof(report->id_key_digest));
    std::cout << "\n"
              << "  author_key_digest: "; print_hex(report->author_key_digest, sizeof(report->author_key_digest));
    std::cout << "\n"
              << "  report_id:         "; print_hex(report->report_id, sizeof(report->report_id));
    std::cout << "\n"
              << "  report_id_ma:      "; print_hex(report->report_id_ma, sizeof(report->report_id_ma));
    std::cout << "\n"
              << "  reported_tcb:      "; print_hex(report->reported_tcb.raw, sizeof(report->reported_tcb.raw));
    std::cout << "\n"
              << "  cpuid_fam_id:      " << static_cast<unsigned>(report->cpuid_fam_id) << "\n"
              << "  cpuid_mod_id:      " << static_cast<unsigned>(report->cpuid_mod_id) << "\n"
              << "  cpuid_step:        " << static_cast<unsigned>(report->cpuid_step)    << "\n"
              << "  chip_id:           "; print_hex(report->chip_id, sizeof(report->chip_id));
    std::cout << "\n"
              << "  committed_tcb:     "; print_hex(report->committed_tcb.raw, sizeof(report->committed_tcb.raw));
    std::cout << "\n"
              << "  current_build:     " << static_cast<unsigned>(report->current_build) << "\n"
              << "  current_minor:     " << static_cast<unsigned>(report->current_minor) << "\n"
              << "  current_major:     " << static_cast<unsigned>(report->current_major) << "\n"
              << "  committed_build:   " << static_cast<unsigned>(report->committed_build) << "\n"
              << "  committed_minor:   " << static_cast<unsigned>(report->committed_minor) << "\n"
              << "  committed_major:   " << static_cast<unsigned>(report->committed_major) << "\n"
              << "  launch_tcb:        "; print_hex(report->launch_tcb.raw, sizeof(report->launch_tcb.raw));
    std::cout << "\n"
              << "  signature.r:       "; print_hex(report->signature.r, sizeof(report->signature.r));
    std::cout << "\n"
              << "  signature.s:       "; print_hex(report->signature.s, sizeof(report->signature.s));
    std::cout << "\n";

    return 0;
}
