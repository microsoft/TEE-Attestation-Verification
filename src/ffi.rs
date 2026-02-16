// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C FFI bindings for TEE attestation verification.
//!
//! Errors are returned as an opaque `TAVError` pointer (NULL means success).
//! Use [`tav_error_code`] to get the error category, [`tav_error_message`] to
//! get a human-readable description, and [`tav_free_error`] to release it.

use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

use zerocopy::FromBytes;

use crate::crypto::{Certificate, Crypto, CryptoBackend};
use crate::snp::report::AttestationReport;
use crate::snp::verify::{self, SevVerificationError};

// ---------------------------------------------------------------------------
// Error code enum
// ---------------------------------------------------------------------------

/// Error categories exposed over FFI.
///
/// Numbering convention:
/// - 1..=3: FFI/input parsing failures
/// - 101..=105: attestation verification failures (mapped from SevVerificationError)
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum TAVErrorCode {
    /// Invalid arguments passed to the function (bad report, bad PEM, etc.).
    InvalidArgument = 1,
    /// Processor model is unsupported.
    UnsupportedProcessor = 101,
    /// The provided ARK does not match the pinned root certificate.
    InvalidRootCertificate = 102,
    /// Certificate chain verification failed (ARK -> ASK -> VCEK).
    CertificateChainError = 103,
    /// Attestation report signature verification failed.
    SignatureVerificationError = 104,
    /// TCB values in certificate do not match the report.
    TcbVerificationError = 105,
}

/// Structured, heap-allocated error returned across FFI.
pub struct TAVError {
    code: TAVErrorCode,
    message: CString,
}

impl TAVError {
    fn new(code: TAVErrorCode, msg: String) -> Self {
        Self {
            code,
            message: CString::new(msg).unwrap_or_default(),
        }
    }

    fn invalid_argument(msg: String) -> Self {
        Self::new(TAVErrorCode::InvalidArgument, msg)
    }
}

impl From<SevVerificationError> for TAVError {
    fn from(e: SevVerificationError) -> Self {
        let code = match &e {
            SevVerificationError::UnsupportedProcessor(_) => TAVErrorCode::UnsupportedProcessor,
            SevVerificationError::InvalidRootCertificate(_) => TAVErrorCode::InvalidRootCertificate,
            SevVerificationError::CertificateChainError(_) => TAVErrorCode::CertificateChainError,
            SevVerificationError::SignatureVerificationError(_) => {
                TAVErrorCode::SignatureVerificationError
            }
            SevVerificationError::TcbVerificationError(_) => TAVErrorCode::TcbVerificationError,
        };
        Self::new(code, e.to_string())
    }
}

/// Write `err` through `out` and return `null`.
unsafe fn set_error(out: *mut *mut TAVError, err: TAVError) -> *const AttestationReport {
    *out = Box::into_raw(Box::new(err));
    std::ptr::null()
}

// ---------------------------------------------------------------------------
// Input parsing helpers
// ---------------------------------------------------------------------------

unsafe fn parse_report(ptr: *const u8, len: usize) -> Result<&'static AttestationReport, TAVError> {
    let bytes = slice::from_raw_parts(ptr, len);
    AttestationReport::ref_from_bytes(bytes).map_err(|_| {
        TAVError::invalid_argument(format!(
            "Invalid attestation report: expected {} bytes, got {}",
            std::mem::size_of::<AttestationReport>(),
            len,
        ))
    })
}

fn parse_pem(name: &str, pem: &[u8]) -> Result<Certificate, TAVError> {
    Crypto::from_pem(pem)
        .map_err(|e| TAVError::invalid_argument(format!("Failed to parse {name} PEM: {e}")))
}

// ---------------------------------------------------------------------------
// Verification entry point
// ---------------------------------------------------------------------------

/// Verify an SEV-SNP attestation report using caller-provided ARK, ASK, and
/// VCEK certificates (all PEM-encoded).
///
/// # Returns
/// On success, a pointer into `report_ptr` reinterpreted as an
/// [`AttestationReport`].  The pointer borrows from the caller's buffer —
/// the caller must keep `report_ptr` alive while using the return value.
///
/// On failure, returns `NULL` and sets `*err_out` to an opaque error handle.
/// Use [`tav_error_code`], [`tav_error_message`], and [`tav_free_error`] to
/// inspect and release the error.
///
/// # Safety
/// All pointer/length pairs must be valid readable memory.
/// `err_out` must be a valid, non-null pointer to a `*mut TAVError`.
#[no_mangle]
pub unsafe extern "C" fn tav_verify_attestation(
    report_ptr: *const u8,
    report_len: usize,
    ark_pem_ptr: *const u8,
    ark_pem_len: usize,
    ask_pem_ptr: *const u8,
    ask_pem_len: usize,
    vcek_pem_ptr: *const u8,
    vcek_pem_len: usize,
    err_out: *mut *mut TAVError,
) -> *const AttestationReport {
    let inner = || -> Result<&AttestationReport, TAVError> {
        let report = parse_report(report_ptr, report_len)?;
        let ark = parse_pem("ARK", slice::from_raw_parts(ark_pem_ptr, ark_pem_len))?;
        let ask = parse_pem("ASK", slice::from_raw_parts(ask_pem_ptr, ask_pem_len))?;
        let vcek = parse_pem("VCEK", slice::from_raw_parts(vcek_pem_ptr, vcek_pem_len))?;
        verify::verify_attestation(report, &vcek, Some(&ask), Some(&ark))
            .map_err(TAVError::from)?;
        Ok(report)
    };

    match inner() {
        Ok(report) => report as *const AttestationReport,
        Err(e) => set_error(err_out, e),
    }
}

// ---------------------------------------------------------------------------
// Error accessors
// ---------------------------------------------------------------------------

/// Get the error code from an error handle.
///
/// # Safety
/// `err` must be a non-null pointer returned by [`tav_verify_attestation`].
#[no_mangle]
pub unsafe extern "C" fn tav_error_code(err: *const TAVError) -> TAVErrorCode {
    (*err).code
}

/// Get a NUL-terminated error message from an error handle.
///
/// The returned pointer is valid until [`tav_free_error`] is called on this
/// error.  Do **not** free the returned string.
///
/// # Safety
/// `err` must be a non-null pointer returned by [`tav_verify_attestation`].
#[no_mangle]
pub unsafe extern "C" fn tav_error_message(err: *const TAVError) -> *const c_char {
    (*err).message.as_ptr()
}

/// Free an error previously returned by [`tav_verify_attestation`].
///
/// Safe to call with NULL (no-op).
///
/// # Safety
/// `err` must be a pointer returned by [`tav_verify_attestation`], or NULL.
#[no_mangle]
pub unsafe extern "C" fn tav_free_error(err: *mut TAVError) {
    if !err.is_null() {
        drop(Box::from_raw(err));
    }
}
