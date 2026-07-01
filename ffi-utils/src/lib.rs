// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared FFI types and constants.

use std::ffi::CString;
#[cfg(not(target_family = "wasm"))]
use std::os::raw::c_char;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(not(target_family = "wasm"))]
const NULL_ERROR_MESSAGE: &[u8] = b"null TavError pointer\0";

/// Shared error codes returned by the public C ABI error accessors.
///
/// The numeric values must match `include/tav/utils.h`.
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = ErrorCode))]
#[cfg_attr(target_family = "wasm", repr(u32))]
#[cfg_attr(not(target_family = "wasm"), repr(C))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TavErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    ErrorIsNull = 2,

    UnsupportedProcessor = 101,
    InvalidRootCertificate = 102,
    CertificateChainError = 103,
    SignatureVerificationError = 104,
    TcbVerificationError = 105,

    CoseCbor = 201,
    CoseUnexpectedType = 202,
    CoseUnsupportedAlgorithm = 203,
    CoseKeyImport = 204,
    CoseVerification = 205,

    CaciCose = 301,
    CaciCertificate = 302,
    CaciDidX509 = 303,
    CaciSignature = 304,
    CaciMeasurement = 305,
    CaciPolicy = 306,
}

/// Shared error handle returned by public C ABI functions.
#[derive(Debug)]
pub struct TavError {
    code: TavErrorCode,
    message: CString,
}

impl TavError {
    pub fn new(code: TavErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: c_string(message.into()),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(TavErrorCode::InvalidArgument, message)
    }

    pub fn into_raw(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }

    pub fn code(&self) -> TavErrorCode {
        self.code
    }

    pub fn message(&self) -> String {
        self.message.to_string_lossy().into_owned()
    }
}

fn c_string(message: String) -> CString {
    CString::new(message.replace('\0', "\\0")).expect("NUL bytes were replaced")
}

impl std::fmt::Display for TavError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for TavError {}

#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_error_code(error: *const TavError) -> TavErrorCode {
    if error.is_null() {
        return TavErrorCode::ErrorIsNull;
    }

    unsafe { (*error).code }
}

#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_error_message(error: *const TavError) -> *const c_char {
    if error.is_null() {
        return NULL_ERROR_MESSAGE.as_ptr().cast();
    }

    unsafe { (*error).message.as_ptr() }
}

#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_error_free(error: *mut TavError) {
    if !error.is_null() {
        unsafe {
            drop(Box::from_raw(error));
        }
    }
}

/// Owned byte buffer returned by public C ABI functions.
///
/// `data` points to a library-owned allocation of `len` bytes. Release it with
/// [`tav_byte_buffer_free`], which frees the allocation and resets the buffer to
/// `{ data: NULL, len: 0 }`.
#[repr(C)]
#[derive(Debug)]
pub struct TavByteBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl TavByteBuffer {
    /// An empty buffer with a null data pointer.
    pub const fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Take ownership of `bytes` and expose it as a C byte buffer.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into().into_boxed_slice();
        let len = bytes.len();
        let data = Box::into_raw(bytes).cast::<u8>();
        Self { data, len }
    }
}

#[cfg(not(target_family = "wasm"))]
#[no_mangle]
pub unsafe extern "C" fn tav_byte_buffer_free(bytes: *mut TavByteBuffer) {
    if bytes.is_null() {
        return;
    }

    let bytes = unsafe { &mut *bytes };
    if !bytes.data.is_null() {
        let data = std::ptr::slice_from_raw_parts_mut(bytes.data, bytes.len);
        unsafe {
            drop(Box::from_raw(data));
        }
        bytes.data = std::ptr::null_mut();
        bytes.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_header_error_codes_match_rust_enum() {
        let header = include_str!("../../include/tav/utils.h");

        for (name, value) in [
            ("TAV_ERROR_OK", TavErrorCode::Ok as i32),
            (
                "TAV_ERROR_INVALID_ARGUMENT",
                TavErrorCode::InvalidArgument as i32,
            ),
            ("TAV_ERROR_ERROR_IS_NULL", TavErrorCode::ErrorIsNull as i32),
            (
                "TAV_ERROR_UNSUPPORTED_PROCESSOR",
                TavErrorCode::UnsupportedProcessor as i32,
            ),
            (
                "TAV_ERROR_INVALID_ROOT_CERTIFICATE",
                TavErrorCode::InvalidRootCertificate as i32,
            ),
            (
                "TAV_ERROR_CERTIFICATE_CHAIN_ERROR",
                TavErrorCode::CertificateChainError as i32,
            ),
            (
                "TAV_ERROR_SIGNATURE_VERIFICATION_ERROR",
                TavErrorCode::SignatureVerificationError as i32,
            ),
            (
                "TAV_ERROR_TCB_VERIFICATION_ERROR",
                TavErrorCode::TcbVerificationError as i32,
            ),
            ("TAV_ERROR_CBOR", TavErrorCode::CoseCbor as i32),
            (
                "TAV_ERROR_UNEXPECTED_TYPE",
                TavErrorCode::CoseUnexpectedType as i32,
            ),
            (
                "TAV_ERROR_UNSUPPORTED_ALGORITHM",
                TavErrorCode::CoseUnsupportedAlgorithm as i32,
            ),
            ("TAV_ERROR_KEY_IMPORT", TavErrorCode::CoseKeyImport as i32),
            (
                "TAV_ERROR_VERIFICATION",
                TavErrorCode::CoseVerification as i32,
            ),
            ("TAV_ERROR_CACI_COSE", TavErrorCode::CaciCose as i32),
            (
                "TAV_ERROR_CACI_CERTIFICATE",
                TavErrorCode::CaciCertificate as i32,
            ),
            ("TAV_ERROR_CACI_DID_X509", TavErrorCode::CaciDidX509 as i32),
            (
                "TAV_ERROR_CACI_SIGNATURE",
                TavErrorCode::CaciSignature as i32,
            ),
            (
                "TAV_ERROR_CACI_MEASUREMENT",
                TavErrorCode::CaciMeasurement as i32,
            ),
            ("TAV_ERROR_CACI_POLICY", TavErrorCode::CaciPolicy as i32),
        ] {
            assert_eq!(
                c_header_enum_value(header, name),
                Some(value),
                "{name} in include/tav/utils.h must match Rust TavErrorCode"
            );
        }
    }

    #[test]
    fn domain_specific_error_codes_are_unique() {
        let header = include_str!("../../include/tav/utils.h");
        let mut seen = std::collections::BTreeMap::new();

        for (name, value) in c_header_error_codes(header) {
            if matches!(value, 0 | 1 | 2) {
                continue;
            }
            if let Some(previous) = seen.insert(value, name) {
                panic!("{name} collides with {previous} at error code {value}");
            }
        }
    }

    fn c_header_enum_value(header: &str, name: &str) -> Option<i32> {
        let line = header
            .lines()
            .find(|line| line.trim_start().starts_with(name))?;
        let (_, value) = line.split_once('=')?;
        value.trim().trim_end_matches(',').parse().ok()
    }

    fn c_header_error_codes(header: &str) -> Vec<(&str, i32)> {
        header
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if !line.starts_with("TAV_ERROR_") {
                    return None;
                }
                let (name, value) = line.split_once('=')?;
                Some((
                    name.trim(),
                    value.trim().trim_end_matches(',').parse().ok()?,
                ))
            })
            .collect()
    }
}
