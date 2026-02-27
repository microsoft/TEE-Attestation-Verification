/* Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Pure C header for TEE Attestation Verification library.
 *
 * Link against the static library (libtee_attestation_verification_lib.a)
 * and system dependencies: -lpthread -ldl -lm
 */

#ifndef TEE_ATTESTATION_VERIFICATION_H
#define TEE_ATTESTATION_VERIFICATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------- */
/* Error handling                                                          */
/* ----------------------------------------------------------------------- */

/** Error code categories.  Must stay in sync with Rust TAVErrorCode enum.
 *  Numbering convention:
 *    1:       FFI/input parsing failures (bad report, bad PEM, etc.)
 *    101-105: attestation verification failures
 */
enum TAVErrorCode {
    TAV_ERROR_INVALID_ARGUMENT          = 1,
    TAV_ERROR_UNSUPPORTED_PROCESSOR     = 101,
    TAV_ERROR_INVALID_ROOT_CERTIFICATE  = 102,
    TAV_ERROR_CERTIFICATE_CHAIN         = 103,
    TAV_ERROR_SIGNATURE_VERIFICATION    = 104,
    TAV_ERROR_TCB_VERIFICATION          = 105
};

/** Opaque error handle.
 *  Must be freed with tav_free_error() when non-null.
 */
struct TAVError;

/** Get the error category code from an error handle. */
enum TAVErrorCode tav_error_code(const struct TAVError *err);

/** Get a NUL-terminated error message from an error handle.
 *  The returned string is valid until tav_free_error() is called.
 *  Do NOT free the returned pointer. */
const char *tav_error_message(const struct TAVError *err);

/** Free an error returned by tav_snp_verify_attestation().
 *  Safe to call with NULL (no-op). */
void tav_free_error(struct TAVError *err);


/* ----------------------------------------------------------------------- */
/* TCB version structures                                                  */
/* ----------------------------------------------------------------------- */

/** Raw 8-byte TCB version.  Interpret via the Milan/Genoa or Turin layout. */
struct TAVSNPTcbVersionRaw {
    uint8_t raw[8];
};

/** TCB version layout for Milan / Genoa processors. */
struct TAVSNPTcbVersionMilanGenoa {
    uint8_t boot_loader;
    uint8_t tee;
    uint8_t reserved[4];
    uint8_t snp;
    uint8_t microcode;
};

/** TCB version layout for Turin processors. */
struct TAVSNPTcbVersionTurin {
    uint8_t fmc;
    uint8_t boot_loader;
    uint8_t tee;
    uint8_t snp;
    uint8_t reserved[3];
    uint8_t microcode;
};

/* ----------------------------------------------------------------------- */
/* Signature                                                               */
/* ----------------------------------------------------------------------- */

struct TAVSNPSignature {
    uint8_t r[72];
    uint8_t s[72];
    uint8_t reserved[512 - 144];
};

/* ----------------------------------------------------------------------- */
/* SNP Attestation Report (0x4A0 = 1184 bytes)                             */
/* ----------------------------------------------------------------------- */
/* See AMD SEV-SNP ABI Specification, Table 23: ATTESTATION_REPORT.        */
/* Layout matches the Rust #[repr(C)] AttestationReport exactly.           */

struct TAVSNPAttestationReport {
    uint32_t              version;           /* 0x000 */
    uint32_t              guest_svn;         /* 0x004 */
    uint64_t              policy;            /* 0x008 */
    uint8_t               family_id[16];     /* 0x010 */
    uint8_t               image_id[16];      /* 0x020 */
    uint32_t              vmpl;              /* 0x030 */
    uint32_t              signature_algo;    /* 0x034 */
    struct TAVSNPTcbVersionRaw  platform_version;  /* 0x038 */
    uint64_t              platform_info;     /* 0x040 */
    uint32_t              flags;             /* 0x048 */
    uint32_t              reserved0;         /* 0x04C */
    uint8_t               report_data[64];   /* 0x050 */
    uint8_t               measurement[48];   /* 0x090 */
    uint8_t               host_data[32];     /* 0x0C0 */
    uint8_t               id_key_digest[48]; /* 0x0E0 */
    uint8_t               author_key_digest[48]; /* 0x110 */
    uint8_t               report_id[32];     /* 0x140 */
    uint8_t               report_id_ma[32];  /* 0x160 */
    struct TAVSNPTcbVersionRaw  reported_tcb;      /* 0x180 */
    uint8_t               cpuid_fam_id;      /* 0x188 */
    uint8_t               cpuid_mod_id;      /* 0x189 */
    uint8_t               cpuid_step;        /* 0x18A */
    uint8_t               reserved1[21];     /* 0x18B */
    uint8_t               chip_id[64];       /* 0x1A0 */
    struct TAVSNPTcbVersionRaw  committed_tcb;     /* 0x1E0 */
    uint8_t               current_build;     /* 0x1E8 */
    uint8_t               current_minor;     /* 0x1E9 */
    uint8_t               current_major;     /* 0x1EA */
    uint8_t               reserved2;         /* 0x1EB */
    uint8_t               committed_build;   /* 0x1EC */
    uint8_t               committed_minor;   /* 0x1ED */
    uint8_t               committed_major;   /* 0x1EE */
    uint8_t               reserved3;         /* 0x1EF */
    struct TAVSNPTcbVersionRaw  launch_tcb;        /* 0x1F0 */
    uint8_t               reserved4[168];    /* 0x1F8 */
    struct TAVSNPSignature   signature;         /* 0x2A0 */
};

/* ----------------------------------------------------------------------- */
/* FFI verify functions                                                    */
/* ----------------------------------------------------------------------- */

/**
 * Verify an SEV-SNP attestation report using caller-provided ARK, ASK,
 * and VCEK certificates (all PEM-encoded).
 *
 * @param report_ptr    Pointer to the raw attestation report (1184 bytes).
 * @param report_len    Length of the report buffer in bytes.
 * @param ark_pem_ptr   Pointer to the PEM-encoded ARK certificate.
 * @param ark_pem_len   Length of the ARK PEM buffer in bytes.
 * @param ask_pem_ptr   Pointer to the PEM-encoded ASK certificate.
 * @param ask_pem_len   Length of the ASK PEM buffer in bytes.
 * @param vcek_pem_ptr  Pointer to the PEM-encoded VCEK certificate.
 * @param vcek_pem_len  Length of the VCEK PEM buffer in bytes.
 * @param err_out       On failure, set to an opaque error handle that must
 *                      be freed with tav_free_error().  Must not be NULL.
 *
 * @return On success, a pointer into report_ptr reinterpreted as an
 *         TAVSNPAttestationReport.  The pointer borrows from report_ptr — the
 *         caller must keep the report buffer alive while using it.
 *         On failure, returns NULL and sets *err_out.
 */
const struct TAVSNPAttestationReport *tav_snp_verify_attestation(
    const uint8_t        *report_ptr,
    size_t                report_len,
    const uint8_t        *ark_pem_ptr,
    size_t                ark_pem_len,
    const uint8_t        *ask_pem_ptr,
    size_t                ask_pem_len,
    const uint8_t        *vcek_pem_ptr,
    size_t                vcek_pem_len,
    struct TAVError     **err_out
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TEE_ATTESTATION_VERIFICATION_H */
