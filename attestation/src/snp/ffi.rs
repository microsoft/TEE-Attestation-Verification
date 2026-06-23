// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI types and target-specific bindings for SNP attestation verification.
//!
//! [`crate::snp::ffi::ErrorCode`] and [`crate::snp::ffi::VerifyError`] classify
//! verification failures in a form suitable for non-Rust callers.
//! Target-specific bindings live under submodules; the `wasm` submodule is
//! compiled only for WASM targets and exposes the caller-provided-certificate
//! WebAssembly API. The `c` submodule is compiled for native targets and exports
//! the C ABI declared in `include/tav/tav.h`.

use crate::snp::verify::VerificationError;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error categories for verification failures.
///
/// The numbering convention is stable and intended to match the C FFI
/// `TAVErrorCode` values:
/// - 1: input parsing / validation
/// - 2: null error handle passed to an error accessor
/// - 101–105: attestation verification (mapped from [`VerificationError`])
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(target_family = "wasm", repr(u32))]
#[cfg_attr(not(target_family = "wasm"), repr(C))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Input bytes or certificate text could not be parsed.
    InvalidArgument = 1,
    /// A null `TavError` pointer was passed to a C error accessor.
    ErrorCodeIsNull = 2,
    /// The report's processor family/model is not supported.
    UnsupportedProcessor = 101,
    /// The selected or provided ARK certificate is not a valid trusted root.
    InvalidRootCertificate = 102,
    /// The ARK → ASK → VCEK certificate chain could not be verified.
    CertificateChainError = 103,
    /// The attestation report signature could not be verified with the VCEK.
    SignatureVerificationError = 104,
    /// Report TCB values did not match the corresponding VCEK extensions.
    TcbVerificationError = 105,
}

/// An error returned by the verify functions.
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Debug)]
pub struct VerifyError {
    code: ErrorCode,
    message: String,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifyError {
    /// The error category.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter))]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The human-readable error message.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter))]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl VerifyError {
    // Only used by the wasm module today; the C FFI layer will use it too
    // when it lands. Silence dead_code on builds without any consumer.
    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    pub(crate) fn invalid_argument(message: String) -> Self {
        Self {
            code: ErrorCode::InvalidArgument,
            message,
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VerifyError {}

impl From<VerificationError> for VerifyError {
    fn from(e: VerificationError) -> Self {
        let code = match &e {
            VerificationError::UnsupportedProcessor(_) => ErrorCode::UnsupportedProcessor,
            VerificationError::InvalidRootCertificate(_) => ErrorCode::InvalidRootCertificate,
            VerificationError::CertificateChainError(_) => ErrorCode::CertificateChainError,
            VerificationError::SignatureVerificationError(_) => {
                ErrorCode::SignatureVerificationError
            }
            VerificationError::TcbVerificationError(_) => ErrorCode::TcbVerificationError,
        };
        Self {
            code,
            message: e.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error mapping test (backend-independent; runs on native CI)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_from_all_verification_error_variants() {
        // Exhaustive match: adding a new VerificationError variant forces the
        // compiler to update this test alongside the From impl.
        fn expected_code(err: &VerificationError) -> ErrorCode {
            match err {
                VerificationError::UnsupportedProcessor(_) => ErrorCode::UnsupportedProcessor,
                VerificationError::InvalidRootCertificate(_) => ErrorCode::InvalidRootCertificate,
                VerificationError::CertificateChainError(_) => ErrorCode::CertificateChainError,
                VerificationError::SignatureVerificationError(_) => {
                    ErrorCode::SignatureVerificationError
                }
                VerificationError::TcbVerificationError(_) => ErrorCode::TcbVerificationError,
            }
        }

        let cases = [
            VerificationError::UnsupportedProcessor("x".into()),
            VerificationError::InvalidRootCertificate("x".into()),
            VerificationError::CertificateChainError("x".into()),
            VerificationError::SignatureVerificationError("x".into()),
            VerificationError::TcbVerificationError("x".into()),
        ];

        for verif_err in cases {
            let want = expected_code(&verif_err);
            let err = VerifyError::from(verif_err);
            assert_eq!(err.code(), want);
        }
    }

    #[test]
    fn invalid_argument_error_preserves_code_and_message() {
        let err = VerifyError::invalid_argument("bad input".into());

        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "bad input");
    }

    #[test]
    fn display_prints_message() {
        let err = VerifyError::from(VerificationError::CertificateChainError("broken".into()));

        assert_eq!(err.to_string(), "Certificate chain error: broken");
    }

    #[test]
    fn c_header_error_codes_match_rust_error_codes() {
        let header = include_str!("../../../include/tav/tav.h");

        assert_eq!(c_header_error_code(header, "TAV_ERROR_OK"), Some(0));

        let expected = [
            (
                "TAV_ERROR_INVALID_ARGUMENT",
                ErrorCode::InvalidArgument as i32,
            ),
            (
                "TAV_ERROR_ERROR_CODE_IS_NULL",
                ErrorCode::ErrorCodeIsNull as i32,
            ),
            (
                "TAV_ERROR_UNSUPPORTED_PROCESSOR",
                ErrorCode::UnsupportedProcessor as i32,
            ),
            (
                "TAV_ERROR_INVALID_ROOT_CERTIFICATE",
                ErrorCode::InvalidRootCertificate as i32,
            ),
            (
                "TAV_ERROR_CERTIFICATE_CHAIN_ERROR",
                ErrorCode::CertificateChainError as i32,
            ),
            (
                "TAV_ERROR_SIGNATURE_VERIFICATION_ERROR",
                ErrorCode::SignatureVerificationError as i32,
            ),
            (
                "TAV_ERROR_TCB_VERIFICATION_ERROR",
                ErrorCode::TcbVerificationError as i32,
            ),
        ];

        for (name, rust_value) in expected {
            assert_eq!(
                c_header_error_code(header, name),
                Some(rust_value),
                "{name} in include/tav/tav.h must match Rust ErrorCode"
            );
        }
    }

    fn c_header_error_code(header: &str, name: &str) -> Option<i32> {
        let line = header
            .lines()
            .find(|line| line.trim_start().starts_with(name))?;
        let (_, value) = line.split_once('=')?;
        value.trim().trim_end_matches(',').parse().ok()
    }
}

#[cfg(not(target_family = "wasm"))]
pub mod c {
    //! C ABI bindings for caller-provided-certificate SNP attestation verification.
    //!
    //! This module exports the symbols declared in `include/tav/tav.h`.
    //!
    //! [`tav_snp_verify_attestation`] returns a null [`TavError`] pointer on
    //! success and an owned [`TavError`] pointer on failure. On success it
    //! writes an owned [`TAVSnpAttestationReport`] handle to `out_report`.
    //! Callers release these handles with [`tav_error_free`] and
    //! [`tav_snp_attestation_report_free`].
    //!
    //! Report accessors assume their pointers are valid handles
    //! returned by this library. Passing null, dangling, freed, or otherwise
    //! invalid pointers to report accessors is undefined behavior. Error
    //! accessors are defensive for null pointers: [`tav_error_code`] returns
    //! [`ErrorCode::ErrorCodeIsNull`] and [`tav_error_message`] returns a static
    //! diagnostic string. Freeing a null report or error pointer is a no-op.
    //!
    //! Byte-slice report accessors return borrowed views by writing a pointer
    //! and length to caller-provided out-parameters. The borrowed pointer remains
    //! valid only until the owning report handle is freed, and must not be freed
    //! by the caller.

    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;

    use zerocopy::FromBytes;

    use super::{ErrorCode, VerifyError};
    use crate::snp::verify::{self, ChainVerification};
    use crate::{certificate_from_pem, AttestationReport};

    const MAX_VERIFY_INPUT_LEN: usize = 1024 * 1024 * 1024;
    const NULL_ERROR_MESSAGE: &[u8] = b"null TAVError pointer\0";

    pub struct TAVSnpAttestationReport {
        bytes: Vec<u8>,
    }

    pub struct TavError {
        code: ErrorCode,
        message: CString,
    }

    impl TavError {
        fn invalid_argument(message: impl Into<String>) -> Self {
            VerifyError::invalid_argument(message.into()).into()
        }
    }

    impl From<VerifyError> for TavError {
        fn from(value: VerifyError) -> Self {
            Self {
                code: value.code(),
                message: c_string(value.message()),
            }
        }
    }

    impl TAVSnpAttestationReport {
        fn report(&self) -> &AttestationReport {
            AttestationReport::ref_from_bytes(&self.bytes).expect(
                "TAVSnpAttestationReport is only constructed from verified bytes so parsing should not fail",
            )
        }
    }

    fn c_string(message: String) -> CString {
        CString::new(message.replace('\0', "\\0")).expect("NUL bytes were replaced")
    }

    macro_rules! scalar_accessor {
        ($name:ident, $return_ty:ty, |$report:ident| $value:expr) => {
            #[no_mangle]
            pub unsafe extern "C" fn $name(report: *const TAVSnpAttestationReport) -> $return_ty {
                let report = unsafe { &*report };
                let $report = report.report();
                $value
            }
        };
    }

    macro_rules! bytes_accessor {
        ($name:ident, |$report:ident| $value:expr) => {
            #[no_mangle]
            pub unsafe extern "C" fn $name(
                report: *const TAVSnpAttestationReport,
                data: *mut *const u8,
                len: *mut usize,
            ) {
                let report = unsafe { &*report };
                let $report = report.report();
                let bytes = $value;
                unsafe {
                    *data = bytes.as_ptr();
                    *len = bytes.len();
                }
            }
        };
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_snp_verify_attestation(
        report_bytes: *const u8,
        report_len: usize,
        ark_pem: *const u8,
        ark_pem_len: usize,
        ask_pem: *const u8,
        ask_pem_len: usize,
        vcek_pem: *const u8,
        vcek_pem_len: usize,
        out_report: *mut *mut TAVSnpAttestationReport,
    ) -> *mut TavError {
        let result = (|| -> Result<TAVSnpAttestationReport, TavError> {
            if out_report.is_null() {
                return Err(TavError::invalid_argument("out_report pointer is null"));
            }
            if unsafe { !(*out_report).is_null() } {
                return Err(TavError::invalid_argument(
                    "out_report must point to NULL before verification",
                ));
            }

            if report_bytes.is_null() {
                return Err(TavError::invalid_argument(
                    "attestation report pointer is null",
                ));
            }
            if report_len == 0 {
                return Err(TavError::invalid_argument("attestation report is empty"));
            }
            if report_len > MAX_VERIFY_INPUT_LEN {
                return Err(TavError::invalid_argument(
                    "attestation report exceeds maximum input size",
                ));
            }
            let report_bytes = unsafe { std::slice::from_raw_parts(report_bytes, report_len) };
            let report = AttestationReport::ref_from_bytes(report_bytes).map_err(|_| {
                TavError::invalid_argument(format!(
                    "Invalid attestation report: expected {} bytes, got {}",
                    std::mem::size_of::<AttestationReport>(),
                    report_len
                ))
            })?;

            if ark_pem.is_null() {
                return Err(TavError::invalid_argument("ARK pointer is null"));
            }
            if ark_pem_len == 0 {
                return Err(TavError::invalid_argument("ARK is empty"));
            }
            if ark_pem_len > MAX_VERIFY_INPUT_LEN {
                return Err(TavError::invalid_argument("ARK exceeds maximum input size"));
            }
            let ark_pem = unsafe { std::slice::from_raw_parts(ark_pem, ark_pem_len) };
            let ark = certificate_from_pem(ark_pem).map_err(|error| {
                TavError::invalid_argument(format!("Failed to parse ARK PEM: {error}"))
            })?;

            if ask_pem.is_null() {
                return Err(TavError::invalid_argument("ASK pointer is null"));
            }
            if ask_pem_len == 0 {
                return Err(TavError::invalid_argument("ASK is empty"));
            }
            if ask_pem_len > MAX_VERIFY_INPUT_LEN {
                return Err(TavError::invalid_argument("ASK exceeds maximum input size"));
            }
            let ask_pem = unsafe { std::slice::from_raw_parts(ask_pem, ask_pem_len) };
            let ask = certificate_from_pem(ask_pem).map_err(|error| {
                TavError::invalid_argument(format!("Failed to parse ASK PEM: {error}"))
            })?;

            if vcek_pem.is_null() {
                return Err(TavError::invalid_argument("VCEK pointer is null"));
            }
            if vcek_pem_len == 0 {
                return Err(TavError::invalid_argument("VCEK is empty"));
            }
            if vcek_pem_len > MAX_VERIFY_INPUT_LEN {
                return Err(TavError::invalid_argument(
                    "VCEK exceeds maximum input size",
                ));
            }
            let vcek_pem = unsafe { std::slice::from_raw_parts(vcek_pem, vcek_pem_len) };
            let vcek = certificate_from_pem(vcek_pem).map_err(|error| {
                TavError::invalid_argument(format!("Failed to parse VCEK PEM: {error}"))
            })?;

            verify::sync::verify_attestation(
                report,
                &vcek,
                &ChainVerification::WithProvidedArk {
                    ask: &ask,
                    ark: &ark,
                },
            )
            .map_err(VerifyError::from)
            .map_err(TavError::from)?;

            Ok(TAVSnpAttestationReport {
                bytes: report_bytes.to_vec(),
            })
        })();

        match result {
            Ok(report) => {
                unsafe {
                    *out_report = Box::into_raw(Box::new(report));
                }
                ptr::null_mut()
            }
            Err(error) => Box::into_raw(Box::new(error)),
        }
    }

    scalar_accessor!(tav_snp_attestation_report_version, u32, |report| report
        .version
        .get());
    scalar_accessor!(tav_snp_attestation_report_guest_svn, u32, |report| report
        .guest_svn
        .get());
    scalar_accessor!(tav_snp_attestation_report_policy, u64, |report| report
        .policy
        .get());
    scalar_accessor!(tav_snp_attestation_report_policy_abi_minor, u8, |report| {
        report.policy().abi_minor()
    });
    scalar_accessor!(tav_snp_attestation_report_policy_abi_major, u8, |report| {
        report.policy().abi_major()
    });
    scalar_accessor!(tav_snp_attestation_report_policy_smt, bool, |report| report
        .policy()
        .smt());
    scalar_accessor!(
        tav_snp_attestation_report_policy_migrate_ma,
        bool,
        |report| report.policy().migrate_ma()
    );
    scalar_accessor!(tav_snp_attestation_report_policy_debug, bool, |report| {
        report.policy().debug()
    });
    scalar_accessor!(
        tav_snp_attestation_report_policy_single_socket,
        bool,
        |report| report.policy().single_socket()
    );
    scalar_accessor!(
        tav_snp_attestation_report_policy_cxl_allow,
        bool,
        |report| report.policy().cxl_allow()
    );
    scalar_accessor!(
        tav_snp_attestation_report_policy_mem_aes_256_xts,
        bool,
        |report| report.policy().mem_aes_256_xts()
    );
    scalar_accessor!(tav_snp_attestation_report_policy_rapl_dis, bool, |report| {
        report.policy().rapl_dis()
    });
    scalar_accessor!(
        tav_snp_attestation_report_policy_ciphertext_hiding_dram,
        bool,
        |report| report.policy().ciphertext_hiding_dram()
    );
    scalar_accessor!(
        tav_snp_attestation_report_policy_page_swap_disable,
        bool,
        |report| report.policy().page_swap_disable()
    );
    scalar_accessor!(tav_snp_attestation_report_vmpl, u32, |report| report
        .vmpl
        .get());
    scalar_accessor!(tav_snp_attestation_report_signature_algo, u32, |report| {
        report.signature_algo.get()
    });
    scalar_accessor!(tav_snp_attestation_report_platform_info, u64, |report| {
        report.platform_info.get()
    });
    scalar_accessor!(tav_snp_attestation_report_flags, u32, |report| report
        .flags
        .get());
    scalar_accessor!(
        tav_snp_attestation_report_flags_author_key_en,
        bool,
        |report| report.flags().author_key_en()
    );
    scalar_accessor!(
        tav_snp_attestation_report_flags_mask_chip_key,
        bool,
        |report| report.flags().mask_chip_key()
    );
    scalar_accessor!(tav_snp_attestation_report_flags_signing_key, u8, |report| {
        report.flags().signing_key().raw()
    });
    scalar_accessor!(tav_snp_attestation_report_cpuid_fam_id, u8, |report| report
        .cpuid_fam_id);
    scalar_accessor!(tav_snp_attestation_report_cpuid_mod_id, u8, |report| report
        .cpuid_mod_id);
    scalar_accessor!(tav_snp_attestation_report_cpuid_step, u8, |report| report
        .cpuid_step);
    scalar_accessor!(tav_snp_attestation_report_current_build, u8, |report| {
        report.current_build
    });
    scalar_accessor!(tav_snp_attestation_report_current_minor, u8, |report| {
        report.current_minor
    });
    scalar_accessor!(tav_snp_attestation_report_current_major, u8, |report| {
        report.current_major
    });
    scalar_accessor!(tav_snp_attestation_report_committed_build, u8, |report| {
        report.committed_build
    });
    scalar_accessor!(tav_snp_attestation_report_committed_minor, u8, |report| {
        report.committed_minor
    });
    scalar_accessor!(tav_snp_attestation_report_committed_major, u8, |report| {
        report.committed_major
    });

    bytes_accessor!(tav_snp_attestation_report_family_id, |report| &report
        .family_id);
    bytes_accessor!(tav_snp_attestation_report_image_id, |report| &report
        .image_id);
    bytes_accessor!(tav_snp_attestation_report_platform_version, |report| {
        &report.platform_version.raw
    });
    bytes_accessor!(tav_snp_attestation_report_report_data, |report| &report
        .report_data);
    bytes_accessor!(tav_snp_attestation_report_measurement, |report| &report
        .measurement);
    bytes_accessor!(tav_snp_attestation_report_host_data, |report| &report
        .host_data);
    bytes_accessor!(tav_snp_attestation_report_id_key_digest, |report| &report
        .id_key_digest);
    bytes_accessor!(tav_snp_attestation_report_author_key_digest, |report| {
        &report.author_key_digest
    });
    bytes_accessor!(tav_snp_attestation_report_report_id, |report| &report
        .report_id);
    bytes_accessor!(tav_snp_attestation_report_report_id_ma, |report| &report
        .report_id_ma);
    bytes_accessor!(tav_snp_attestation_report_reported_tcb, |report| &report
        .reported_tcb
        .raw);
    bytes_accessor!(tav_snp_attestation_report_chip_id, |report| &report.chip_id);
    bytes_accessor!(tav_snp_attestation_report_committed_tcb, |report| &report
        .committed_tcb
        .raw);
    bytes_accessor!(tav_snp_attestation_report_launch_tcb, |report| &report
        .launch_tcb
        .raw);
    bytes_accessor!(tav_snp_attestation_report_signature_r, |report| &report
        .signature
        .r);
    bytes_accessor!(tav_snp_attestation_report_signature_s, |report| &report
        .signature
        .s);

    #[no_mangle]
    pub unsafe extern "C" fn tav_snp_attestation_report_free(report: *mut TAVSnpAttestationReport) {
        if !report.is_null() {
            unsafe {
                drop(Box::from_raw(report));
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_error_code(error: *const TavError) -> ErrorCode {
        if error.is_null() {
            return ErrorCode::ErrorCodeIsNull;
        }

        let error = unsafe { &*error };
        error.code
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_error_message(error: *const TavError) -> *const c_char {
        if error.is_null() {
            return NULL_ERROR_MESSAGE.as_ptr().cast();
        }

        let error = unsafe { &*error };
        error.message.as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_error_free(error: *mut TavError) {
        if !error.is_null() {
            unsafe {
                drop(Box::from_raw(error));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn verify_rejects_inputs_larger_than_one_gib() {
            let mut report = ptr::null_mut();

            let error = unsafe {
                tav_snp_verify_attestation(
                    std::ptr::NonNull::<u8>::dangling().as_ptr(),
                    MAX_VERIFY_INPUT_LEN + 1,
                    std::ptr::NonNull::<u8>::dangling().as_ptr(),
                    1,
                    std::ptr::NonNull::<u8>::dangling().as_ptr(),
                    1,
                    std::ptr::NonNull::<u8>::dangling().as_ptr(),
                    1,
                    &mut report,
                )
            };

            assert!(!error.is_null());
            let error = unsafe { Box::from_raw(error) };
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert_eq!(
                error.message.to_str().unwrap(),
                "attestation report exceeds maximum input size"
            );
            assert!(report.is_null());
        }

        #[test]
        fn error_accessors_handle_null_errors_defensively() {
            let message = unsafe { tav_error_message(ptr::null()) };

            assert_eq!(
                unsafe { tav_error_code(ptr::null()) },
                ErrorCode::ErrorCodeIsNull
            );
            assert!(!message.is_null());
            assert_eq!(
                unsafe { std::ffi::CStr::from_ptr(message) }
                    .to_str()
                    .unwrap(),
                "null TAVError pointer"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// WASM bindings
// ---------------------------------------------------------------------------

#[cfg(target_family = "wasm")]
pub mod wasm {
    //! `wasm_bindgen` bindings exposing verified SNP attestation reports to JS.
    //!
    //! SnpAttestationReport is opaque and can only be obtained through successful
    //! verification with `verify_attestation_async`. Its accessor methods return
    //! fields from the verified report bytes.
    //!
    //! See `demos/web-verify-kernel/README.md` in the repository for a runnable
    //! browser demo that uses these bindings.

    use js_sys::Array;
    use wasm_bindgen::prelude::*;
    use zerocopy::{FromBytes, IntoBytes};

    use super::VerifyError;
    use crate::crypto::{CertificateBackend, Crypto};
    use crate::snp::report::AttestationReport;
    use crate::snp::verify::ChainVerification;

    /// A cryptographically verified SEV-SNP attestation report.
    ///
    /// Obtained from [`verify_attestation_async`]. Accessor methods return
    /// fields from the verified report bytes.
    #[wasm_bindgen]
    #[derive(Debug)]
    pub struct SnpAttestationReport {
        bytes: Vec<u8>,
    }

    /// Verify an SEV-SNP attestation report.
    ///
    /// Takes ownership of `report_bytes`. Parses PEM-encoded ARK, ASK, and
    /// VCEK certificates, verifies the full certificate chain and report
    /// signature, and on success returns a [`SnpAttestationReport`] wrapping
    /// the verified bytes.
    #[wasm_bindgen]
    #[cfg(async_crypto)]
    pub async fn verify_attestation_async(
        report_bytes: Vec<u8>,
        ark_pem: &str,
        ask_pem: &str,
        vcek_pem: &str,
    ) -> Result<SnpAttestationReport, VerifyError> {
        // Parse: report length check + PEM parses (all produce InvalidArgument).
        parse_report(&report_bytes)?;
        let ark = parse_pem("ARK", ark_pem)?;
        let ask = parse_pem("ASK", ask_pem)?;
        let vcek = parse_pem("VCEK", vcek_pem)?;

        // Re-borrow the report for verification (ref_from_bytes is zero-copy
        // and we've already validated the length above).
        let report = parse_report(&report_bytes)?;

        crate::snp::verify::asynchronous::verify_attestation(
            report,
            &vcek,
            &ChainVerification::WithProvidedArk {
                ask: &ask,
                ark: &ark,
            },
        )
        .await
        .map_err(VerifyError::from)?;

        Ok(SnpAttestationReport {
            bytes: report_bytes,
        })
    }

    /// Split a PEM certificate bundle into individual PEM certificates.
    ///
    /// Parses the bundle with the active crypto backend and returns certificates
    /// in the same order they appeared in the input.
    #[wasm_bindgen]
    pub fn split_certificate_bundle(pem_bundle: &str) -> Result<Array, String> {
        if pem_bundle.trim().is_empty() {
            return Err("Certificate bundle PEM is empty".into());
        }

        let certificates = Crypto::from_pem_chain(pem_bundle.as_bytes())
            .map_err(|e| format!("Failed to parse certificate bundle PEM: {e}"))?;

        let split = Array::new();
        for certificate in certificates {
            let pem = Crypto::to_pem(&certificate)
                .map_err(|e| format!("Failed to encode certificate PEM: {e}"))?;
            split.push(&JsValue::from_str(&pem));
        }

        Ok(split)
    }

    fn parse_report(bytes: &[u8]) -> Result<&AttestationReport, VerifyError> {
        AttestationReport::ref_from_bytes(bytes).map_err(|_| {
            VerifyError::invalid_argument(format!(
                "Invalid attestation report: expected {} bytes, got {}",
                std::mem::size_of::<AttestationReport>(),
                bytes.len(),
            ))
        })
    }

    fn parse_pem(name: &str, pem: &str) -> Result<crate::crypto::Certificate, VerifyError> {
        Crypto::from_pem(pem.as_bytes())
            .map_err(|e| VerifyError::invalid_argument(format!("Failed to parse {name} PEM: {e}")))
    }

    // -----------------------------------------------------------------------
    // Accessor methods
    //
    // Each method re-parses `self.bytes` via zero-copy `ref_from_bytes`. The
    // struct's invariants (verified length at construction) make this
    // infallible, so we `.expect()` on the parse.
    // -----------------------------------------------------------------------

    impl SnpAttestationReport {
        pub fn from_verified_report(report: AttestationReport) -> Self {
            Self {
                bytes: report.as_bytes().to_vec(),
            }
        }

        pub fn report(&self) -> &AttestationReport {
            AttestationReport::ref_from_bytes(&self.bytes)
                .expect("SnpAttestationReport is only constructed from verified bytes so this parse should not fail")
        }
    }

    #[wasm_bindgen]
    impl SnpAttestationReport {
        // -- Scalar fields --

        #[wasm_bindgen(getter)]
        pub fn version(&self) -> u32 {
            self.report().version.get()
        }

        #[wasm_bindgen(getter)]
        pub fn guest_svn(&self) -> u32 {
            self.report().guest_svn.get()
        }

        #[wasm_bindgen(getter)]
        pub fn policy(&self) -> u64 {
            self.report().policy.get()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_abi_minor(&self) -> u8 {
            self.report().policy().abi_minor()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_abi_major(&self) -> u8 {
            self.report().policy().abi_major()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_smt(&self) -> bool {
            self.report().policy().smt()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_migrate_ma(&self) -> bool {
            self.report().policy().migrate_ma()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_debug(&self) -> bool {
            self.report().policy().debug()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_single_socket(&self) -> bool {
            self.report().policy().single_socket()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_cxl_allow(&self) -> bool {
            self.report().policy().cxl_allow()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_mem_aes_256_xts(&self) -> bool {
            self.report().policy().mem_aes_256_xts()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_rapl_dis(&self) -> bool {
            self.report().policy().rapl_dis()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_ciphertext_hiding_dram(&self) -> bool {
            self.report().policy().ciphertext_hiding_dram()
        }

        #[wasm_bindgen(getter)]
        pub fn policy_page_swap_disable(&self) -> bool {
            self.report().policy().page_swap_disable()
        }

        #[wasm_bindgen(getter)]
        pub fn vmpl(&self) -> u32 {
            self.report().vmpl.get()
        }

        #[wasm_bindgen(getter)]
        pub fn signature_algo(&self) -> u32 {
            self.report().signature_algo.get()
        }

        #[wasm_bindgen(getter)]
        pub fn platform_info(&self) -> u64 {
            self.report().platform_info.get()
        }

        #[wasm_bindgen(getter)]
        pub fn flags(&self) -> u32 {
            self.report().flags.get()
        }

        #[wasm_bindgen(getter)]
        pub fn flags_author_key_en(&self) -> bool {
            self.report().flags().author_key_en()
        }

        #[wasm_bindgen(getter)]
        pub fn flags_mask_chip_key(&self) -> bool {
            self.report().flags().mask_chip_key()
        }

        #[wasm_bindgen(getter)]
        pub fn flags_signing_key(&self) -> u8 {
            self.report().flags().signing_key().raw()
        }

        // -- Single-byte fields --

        #[wasm_bindgen(getter)]
        pub fn cpuid_fam_id(&self) -> u8 {
            self.report().cpuid_fam_id
        }

        #[wasm_bindgen(getter)]
        pub fn cpuid_mod_id(&self) -> u8 {
            self.report().cpuid_mod_id
        }

        #[wasm_bindgen(getter)]
        pub fn cpuid_step(&self) -> u8 {
            self.report().cpuid_step
        }

        #[wasm_bindgen(getter)]
        pub fn current_build(&self) -> u8 {
            self.report().current_build
        }

        #[wasm_bindgen(getter)]
        pub fn current_minor(&self) -> u8 {
            self.report().current_minor
        }

        #[wasm_bindgen(getter)]
        pub fn current_major(&self) -> u8 {
            self.report().current_major
        }

        #[wasm_bindgen(getter)]
        pub fn committed_build(&self) -> u8 {
            self.report().committed_build
        }

        #[wasm_bindgen(getter)]
        pub fn committed_minor(&self) -> u8 {
            self.report().committed_minor
        }

        #[wasm_bindgen(getter)]
        pub fn committed_major(&self) -> u8 {
            self.report().committed_major
        }

        // -- Byte-array fields (returned as Vec<u8>) --

        #[wasm_bindgen(getter)]
        pub fn family_id(&self) -> Vec<u8> {
            self.report().family_id.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn image_id(&self) -> Vec<u8> {
            self.report().image_id.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn platform_version(&self) -> Vec<u8> {
            self.report().platform_version.raw.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn report_data(&self) -> Vec<u8> {
            self.report().report_data.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn measurement(&self) -> Vec<u8> {
            self.report().measurement.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn host_data(&self) -> Vec<u8> {
            self.report().host_data.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn id_key_digest(&self) -> Vec<u8> {
            self.report().id_key_digest.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn author_key_digest(&self) -> Vec<u8> {
            self.report().author_key_digest.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn report_id(&self) -> Vec<u8> {
            self.report().report_id.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn report_id_ma(&self) -> Vec<u8> {
            self.report().report_id_ma.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn reported_tcb(&self) -> Vec<u8> {
            self.report().reported_tcb.raw.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn chip_id(&self) -> Vec<u8> {
            self.report().chip_id.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn committed_tcb(&self) -> Vec<u8> {
            self.report().committed_tcb.raw.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn launch_tcb(&self) -> Vec<u8> {
            self.report().launch_tcb.raw.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn signature_r(&self) -> Vec<u8> {
            self.report().signature.r.to_vec()
        }

        #[wasm_bindgen(getter)]
        pub fn signature_s(&self) -> Vec<u8> {
            self.report().signature.s.to_vec()
        }
    }

    #[cfg(test)]
    mod split_tests {
        use super::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        const MILAN_ARK: &str = include_str!("../pinned_arks/milan_ark.pem");
        const MILAN_ASK: &str = include_str!("../../tests/test_data/milan_ask.pem");

        #[wasm_bindgen_test]
        fn split_certificate_bundle_returns_pem_certificates_in_order() {
            let bundle = format!("{MILAN_ASK}\n{MILAN_ARK}");

            let split = split_certificate_bundle(&bundle).expect("bundle should split");

            assert_eq!(split.length(), 2);
            assert_certificate_matches_pem(&split, 0, MILAN_ASK);
            assert_certificate_matches_pem(&split, 1, MILAN_ARK);
        }

        #[wasm_bindgen_test]
        fn split_certificate_bundle_rejects_empty_bundle() {
            let err = match split_certificate_bundle("") {
                Ok(_) => panic!("empty bundle should fail"),
                Err(err) => err,
            };

            assert!(err.contains("empty"));
        }

        #[wasm_bindgen_test]
        fn split_certificate_bundle_rejects_invalid_pem() {
            let err = match split_certificate_bundle("not a pem") {
                Ok(_) => panic!("invalid bundle should fail"),
                Err(err) => err,
            };

            assert!(err.contains("certificate bundle PEM"));
        }

        fn assert_certificate_matches_pem(split: &Array, index: u32, expected_pem: &str) {
            let actual_pem = split
                .get(index)
                .as_string()
                .expect("split certificate should be a PEM string");
            let actual = Crypto::from_pem(actual_pem.as_bytes())
                .expect("split certificate PEM should parse");
            let expected =
                Crypto::from_pem(expected_pem.as_bytes()).expect("fixture PEM should parse");

            assert_eq!(
                Crypto::to_der(&actual).expect("split certificate should encode as DER"),
                Crypto::to_der(&expected).expect("fixture certificate should encode as DER")
            );
        }
    }

    #[cfg(all(test, async_crypto))]
    mod tests {
        use super::super::ErrorCode;
        use super::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        const MILAN_REPORT: &[u8] =
            include_bytes!("../../tests/test_data/milan_attestation_report.bin");
        const MILAN_ARK: &str = include_str!("../pinned_arks/milan_ark.pem");
        const MILAN_ASK: &str = include_str!("../../tests/test_data/milan_ask.pem");
        const MILAN_VCEK: &str = include_str!("../../tests/test_data/milan_vcek.pem");

        #[wasm_bindgen_test]
        async fn verify_valid_attestation_returns_report() {
            let report =
                verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ARK, MILAN_ASK, MILAN_VCEK)
                    .await
                    .expect("verify should succeed");

            // Sanity-check a few getters — versions and sizes should be as
            // expected for the Milan test fixture.
            // Milan fixture is a version-3 report.
            assert_eq!(report.version(), 3);
            assert_eq!(report.measurement().len(), 48);
            assert_eq!(report.report_data().len(), 64);
            assert_eq!(report.chip_id().len(), 64);
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_empty_report() {
            let err = verify_attestation_async(Vec::new(), MILAN_ARK, MILAN_ASK, MILAN_VCEK)
                .await
                .expect_err("empty report should fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("expected 1184 bytes, got 0"));
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_truncated_report() {
            let err = verify_attestation_async(
                MILAN_REPORT[..100].to_vec(),
                MILAN_ARK,
                MILAN_ASK,
                MILAN_VCEK,
            )
            .await
            .expect_err("truncated report should fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_invalid_ark_pem() {
            let err =
                verify_attestation_async(MILAN_REPORT.to_vec(), "not a pem", MILAN_ASK, MILAN_VCEK)
                    .await
                    .expect_err("invalid ARK should fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("ARK PEM"));
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_invalid_ask_pem() {
            let err =
                verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ARK, "not a pem", MILAN_VCEK)
                    .await
                    .expect_err("invalid ASK should fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("ASK PEM"));
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_invalid_vcek_pem() {
            let err =
                verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ARK, MILAN_ASK, "not a pem")
                    .await
                    .expect_err("invalid VCEK should fail");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("VCEK PEM"));
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_wrong_ark() {
            // Use ASK in place of ARK — should fail root certificate validation.
            let err =
                verify_attestation_async(MILAN_REPORT.to_vec(), MILAN_ASK, MILAN_ASK, MILAN_VCEK)
                    .await
                    .expect_err("wrong ARK should fail");
            assert_eq!(err.code(), ErrorCode::InvalidRootCertificate);
        }

        #[wasm_bindgen_test]
        async fn verify_rejects_corrupted_report_body() {
            let mut corrupted = MILAN_REPORT.to_vec();
            corrupted[100] ^= 0xFF;
            let err = verify_attestation_async(corrupted, MILAN_ARK, MILAN_ASK, MILAN_VCEK)
                .await
                .expect_err("corrupted report should fail");
            assert_eq!(err.code(), ErrorCode::SignatureVerificationError);
        }
    }
}
