// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_family = "wasm")]
mod wasm {
    use cose::ffi::wasm::CborValue as WasmCborValue;
    use js_sys::{Array, Uint8Array};
    use std::collections::BTreeMap;
    use wasm_bindgen::{prelude::*, JsCast};

    use crate::{asynchronous, AciError, SNP_HOST_DATA_LEN};
    use attestation::snp::{ffi::wasm::SnpAttestationReport, report::TcbVersionRaw, Cpuid};
    use crypto::{CertificateBackend, Crypto};

    /// Split a PEM certificate bundle into individual PEM certificates.
    ///
    /// Parses the bundle with the active crypto backend and returns certificates
    /// in the same order they appeared in the input.
    #[wasm_bindgen]
    pub fn split_pem_bundle(pem_bundle: &str) -> Result<Array, String> {
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

    /// Verify an SEV-SNP attestation report with caller-provided endorsements.
    ///
    /// `amd_endorsements` must contain exactly three byte arrays ordered as
    /// `[vcek, ask, ark]`.
    #[wasm_bindgen]
    #[cfg(async_crypto)]
    pub async fn verify_snp_attestation_with_cert_chain_async(
        attestation_report: Vec<u8>,
        amd_endorsements: Array,
    ) -> Result<SnpAttestationReport, String> {
        if amd_endorsements.length() != 3 {
            return Err(format!(
                "expected AMD endorsements [vcek, ask, ark], got {} certificate(s)",
                amd_endorsements.length()
            ));
        }
        let amd_endorsements = byte_array_values(amd_endorsements, "AMD endorsement")?;
        let endorsement_refs = [
            amd_endorsements[0].as_slice(),
            amd_endorsements[1].as_slice(),
            amd_endorsements[2].as_slice(),
        ];

        let attestation = asynchronous::verify_attestation(&attestation_report, &endorsement_refs)
            .await
            .map_err(wasm_error)?;

        Ok(SnpAttestationReport::from_verified_report(attestation))
    }

    /// Verify an ACI/UVM endorsement COSE blob with a caller-pinned did:x509 root.
    #[wasm_bindgen]
    #[cfg(async_crypto)]
    pub async fn verify_uvm_endorsement_async(
        uvm_endorsement: Vec<u8>,
        trusted_didx509: &str,
    ) -> Result<WasmCborValue, String> {
        let inner = asynchronous::verify_uvm_endorsement(&uvm_endorsement, trusted_didx509)
            .await
            .map_err(wasm_error)?;
        Ok(WasmCborValue::from_native(inner))
    }

    /// Verify Confidential CACI relying-party policy over staged verified artifacts.
    ///
    /// `minimum_tcb_json`, when non-empty, must be a JSON map from CPUID hex
    /// strings to TCB hex strings, for example `{ "00a10f11": "04000000000018db" }`.
    /// In the future this can be checked against a transparent statement from CACI.
    #[wasm_bindgen]
    pub async fn verify_caci_attestation(
        attestation: &SnpAttestationReport,
        minimum_tcb_json: &str,
        trusted_caci_execution_policies: Array,
        uvm: &WasmCborValue,
        uvm_feed: &str,
        minimum_svn: u64,
    ) -> Result<Vec<u8>, String> {
        let minimum_tcb = parse_minimum_tcb_json(minimum_tcb_json)?;
        let trusted_caci_execution_policies = byte_array_values(
            trusted_caci_execution_policies,
            "trusted CACI execution policy",
        )?
        .iter()
        .map(|policy| parse_host_data_policy(policy))
        .collect::<Result<Vec<_>, _>>()?;
        if trusted_caci_execution_policies.is_empty() {
            return Err(
                "at least one trusted CACI execution policy digest is required".to_string(),
            );
        }
        asynchronous::verify_caci_attestation(
            *attestation.report(),
            minimum_tcb,
            trusted_caci_execution_policies,
            uvm.as_native().clone(),
            uvm_feed,
            minimum_svn,
        )
        .await
        .map(|report_data| report_data.to_vec())
        .map_err(wasm_error)
    }

    fn byte_array_values(values: Array, name: &str) -> Result<Vec<Vec<u8>>, String> {
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value
                    .dyn_into::<Uint8Array>()
                    .map(|bytes| bytes.to_vec())
                    .map_err(|_| format!("{name} at index {index} must be a Uint8Array"))
            })
            .collect()
    }

    fn parse_minimum_tcb_json(json: &str) -> Result<Vec<(Cpuid, TcbVersionRaw)>, String> {
        if json.trim().is_empty() {
            return Ok(Vec::new());
        }
        let map: BTreeMap<String, String> = serde_json::from_str(json)
            .map_err(|e| format!("failed to parse minimum TCB JSON: {e}"))?;
        map.into_iter()
            .map(|(cpuid, tcb)| Ok((parse_cpuid_hex(&cpuid)?, parse_tcb_hex(&tcb)?)))
            .collect()
    }

    fn parse_cpuid_hex(hex: &str) -> Result<Cpuid, String> {
        if hex.len() != 8 {
            return Err(format!("CPUID must be 8 hex characters, got {}", hex.len()));
        }
        let bytes =
            crypto::hex::from_hex(hex).map_err(|e| format!("invalid CPUID hex {hex:?}: {e}"))?;
        let value = u32::from_be_bytes(bytes.try_into().expect("CPUID hex length already checked"));
        Ok(Cpuid::from(value))
    }

    fn parse_tcb_hex(hex: &str) -> Result<TcbVersionRaw, String> {
        let bytes = crypto::hex::from_hex(hex)?;
        let raw = bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!("TCB version must be 8 bytes, got {}", bytes.len())
        })?;
        Ok(TcbVersionRaw { raw })
    }

    fn parse_host_data_policy(bytes: &[u8]) -> Result<[u8; SNP_HOST_DATA_LEN], String> {
        bytes.try_into().map_err(|_| {
            format!(
                "trusted CACI execution policy digest must be {SNP_HOST_DATA_LEN} bytes, got {}",
                bytes.len()
            )
        })
    }

    fn wasm_error(error: AciError) -> String {
        error.to_string()
    }
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
pub mod c {
    //! C ABI bindings for staged Confidential ACI attestation verification.
    //!
    //! This module exports the symbols declared in `include/tav/caci.h`.

    use std::ffi::CStr;
    use std::os::raw::c_char;
    use std::ptr;

    use attestation::snp::ffi::c::TAVSnpAttestationReport;
    use attestation::snp::report::TcbVersionRaw;
    use attestation::snp::verify::VerificationError;
    use cose::ffi::c::TavCborValue;
    use std::ffi::CString;

    use crate::{snp, synchronous, AciError, SNP_HOST_DATA_LEN};

    const MAX_INPUT_LEN: usize = 1024 * 1024 * 1024; // 1 GiB
    const TCB_VERSION_LEN: usize = std::mem::size_of::<TcbVersionRaw>();
    const NULL_ERROR_MESSAGE: &[u8] = b"null TavCaciError pointer\0";

    /// Error codes returned by [`tav_caci_error_code`].
    ///
    /// The numeric values must match the `TAV_CACI_ERROR_*` enum in
    /// `include/tav/caci.h`. Codes 101-105 mirror the wrapped SNP verification
    /// failures; 301-306 are CACI-policy specific.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TavCaciErrorCode {
        Ok = 0,
        InvalidArgument = 1,
        ErrorCodeIsNull = 2,

        UnsupportedProcessor = 101,
        InvalidRootCertificate = 102,
        CertificateChainError = 103,
        SignatureVerificationError = 104,
        TcbVerificationError = 105,

        CaciCose = 301,
        CaciCertificate = 302,
        CaciDidX509 = 303,
        CaciSignature = 304,
        CaciMeasurement = 305,
        CaciPolicy = 306,
    }

    /// Owned error handle returned by the CACI C ABI.
    pub struct TavCaciError {
        code: TavCaciErrorCode,
        message: CString,
    }

    impl TavCaciError {
        fn new(code: TavCaciErrorCode, message: impl Into<String>) -> Self {
            Self {
                code,
                message: c_string(message.into()),
            }
        }

        fn invalid_argument(message: impl Into<String>) -> Self {
            Self::new(TavCaciErrorCode::InvalidArgument, message)
        }
    }

    /// Owned byte buffer returned by the CACI C ABI. Release it with
    /// [`tav_caci_byte_buffer_free`].
    #[repr(C)]
    #[derive(Debug)]
    pub struct TavCaciByteBuffer {
        data: *mut u8,
        len: usize,
    }

    impl TavCaciByteBuffer {
        fn empty() -> Self {
            Self {
                data: ptr::null_mut(),
                len: 0,
            }
        }

        fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
            let bytes = bytes.into().into_boxed_slice();
            let len = bytes.len();
            let data = Box::into_raw(bytes).cast::<u8>();
            Self { data, len }
        }
    }

    fn c_string(message: String) -> CString {
        CString::new(message.replace('\0', "\\0")).expect("NUL bytes were replaced")
    }

    impl From<AciError> for TavCaciError {
        fn from(value: AciError) -> Self {
            let code = match &value {
                AciError::InvalidAmdEndorsements(_) | AciError::InvalidAttestation(_) => {
                    TavCaciErrorCode::InvalidArgument
                }
                AciError::AttestationVerification(error) => match error {
                    VerificationError::UnsupportedProcessor(_) => {
                        TavCaciErrorCode::UnsupportedProcessor
                    }
                    VerificationError::InvalidRootCertificate(_) => {
                        TavCaciErrorCode::InvalidRootCertificate
                    }
                    VerificationError::CertificateChainError(_) => {
                        TavCaciErrorCode::CertificateChainError
                    }
                    VerificationError::SignatureVerificationError(_) => {
                        TavCaciErrorCode::SignatureVerificationError
                    }
                    VerificationError::TcbVerificationError(_) => {
                        TavCaciErrorCode::TcbVerificationError
                    }
                },
                AciError::Certificate(_) => TavCaciErrorCode::CaciCertificate,
                AciError::DidX509(_) => TavCaciErrorCode::CaciDidX509,
                AciError::Cose(_) => TavCaciErrorCode::CaciCose,
                AciError::Signature(_) => TavCaciErrorCode::CaciSignature,
                AciError::Measurement(_) => TavCaciErrorCode::CaciMeasurement,
                AciError::Policy(_) => TavCaciErrorCode::CaciPolicy,
            };
            Self::new(code, value.to_string())
        }
    }

    fn into_error(error: TavCaciError) -> *mut TavCaciError {
        Box::into_raw(Box::new(error))
    }

    fn into_result(result: Result<(), TavCaciError>) -> *mut TavCaciError {
        match result {
            Ok(()) => ptr::null_mut(),
            Err(error) => into_error(error),
        }
    }

    unsafe fn cose_error_to_caci(error: *mut cose::ffi::c::TavCoseError) -> TavCaciError {
        let message = unsafe { CStr::from_ptr(cose::ffi::c::tav_cose_error_message(error)) }
            .to_string_lossy()
            .into_owned();
        unsafe {
            cose::ffi::c::tav_cose_error_free(error);
        }
        TavCaciError::new(
            TavCaciErrorCode::CaciCose,
            format!("failed to materialize verified UVM CBOR: {message}"),
        )
    }

    unsafe fn input_bytes<'a>(
        data: *const u8,
        len: usize,
        name: &str,
        allow_empty: bool,
    ) -> Result<&'a [u8], TavCaciError> {
        if len == 0 {
            if allow_empty {
                return Ok(&[]);
            }
            return Err(TavCaciError::invalid_argument(format!("{name} is empty")));
        }
        if data.is_null() {
            return Err(TavCaciError::invalid_argument(format!(
                "{name} pointer is null"
            )));
        }
        if len > MAX_INPUT_LEN {
            return Err(TavCaciError::invalid_argument(format!(
                "{name} exceeds maximum input size"
            )));
        }
        Ok(unsafe { std::slice::from_raw_parts(data, len) })
    }

    unsafe fn input_text<'a>(
        data: *const c_char,
        len: usize,
        name: &str,
        allow_empty: bool,
    ) -> Result<&'a str, TavCaciError> {
        let bytes = unsafe { input_bytes(data.cast(), len, name, allow_empty) }?;
        std::str::from_utf8(bytes).map_err(|error| {
            TavCaciError::invalid_argument(format!("{name} is not valid UTF-8: {error}"))
        })
    }

    unsafe fn out_ptr<T>(out: *mut T, name: &str) -> Result<(), TavCaciError> {
        if out.is_null() {
            return Err(TavCaciError::invalid_argument(format!(
                "{name} pointer is null"
            )));
        }
        Ok(())
    }

    unsafe fn owned_out_ptr<T>(out: *mut *mut T, name: &str) -> Result<(), TavCaciError> {
        unsafe { out_ptr(out, name) }?;
        // Matches tav_verify_snp_attestation: the slot must contain NULL on
        // entry. A non-NULL slot is rejected without being overwritten, so a
        // caller can never silently leak a live handle by reusing a variable.
        if unsafe { !(*out).is_null() } {
            return Err(TavCaciError::invalid_argument(format!(
                "{name} must point to NULL before verification"
            )));
        }
        Ok(())
    }

    unsafe fn byte_buffer_out_ptr(
        out: *mut TavCaciByteBuffer,
        name: &str,
    ) -> Result<(), TavCaciError> {
        unsafe { out_ptr(out, name) }?;
        unsafe {
            *out = TavCaciByteBuffer::empty();
        }
        Ok(())
    }

    unsafe fn attestation_report<'a>(
        report: *const TAVSnpAttestationReport,
    ) -> Result<&'a attestation::snp::report::AttestationReport, TavCaciError> {
        if report.is_null() {
            return Err(TavCaciError::invalid_argument("report is null"));
        }
        Ok(unsafe { (*report).report() })
    }

    unsafe fn uvm_endorsement_handle<'a>(
        uvm_endorsement: *const TavCborValue,
    ) -> Result<&'a cose::CborValue, TavCaciError> {
        if uvm_endorsement.is_null() {
            return Err(TavCaciError::invalid_argument("uvm_endorsement is null"));
        }
        // TavCborValue is a repr(transparent) C handle over cose::CborValue.
        Ok(unsafe { &*uvm_endorsement.cast::<cose::CborValue>() })
    }

    unsafe fn minimum_tcb_entries(
        cpuids: *const u32,
        values: *const u8,
        count: usize,
    ) -> Result<Vec<(snp::Cpuid, TcbVersionRaw)>, TavCaciError> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if cpuids.is_null() {
            return Err(TavCaciError::invalid_argument(
                "minimum_tcb_cpuids pointer is null",
            ));
        }
        if count > MAX_INPUT_LEN / TCB_VERSION_LEN {
            return Err(TavCaciError::invalid_argument(
                "minimum_tcb exceeds maximum input size",
            ));
        }
        let values_len = count * TCB_VERSION_LEN;
        let values = unsafe { input_bytes(values, values_len, "minimum_tcb_values", false) }?;
        let cpuids = unsafe { std::slice::from_raw_parts(cpuids, count) };

        Ok(cpuids
            .iter()
            .zip(values.chunks_exact(TCB_VERSION_LEN))
            .map(|(&cpuid, chunk)| {
                (
                    snp::Cpuid::from(cpuid),
                    TcbVersionRaw {
                        raw: chunk
                            .try_into()
                            .expect("chunks_exact produced fixed-size chunks"),
                    },
                )
            })
            .collect())
    }

    unsafe fn parse_trusted_policy_digests(
        data: *const u8,
        count: usize,
    ) -> Result<Vec<[u8; SNP_HOST_DATA_LEN]>, TavCaciError> {
        if count == 0 {
            return Err(TavCaciError::invalid_argument(
                "at least one trusted policy digest is required",
            ));
        }
        if count > MAX_INPUT_LEN / SNP_HOST_DATA_LEN {
            return Err(TavCaciError::invalid_argument(
                "trusted_policy_digests exceeds maximum input size",
            ));
        }
        let len = count * SNP_HOST_DATA_LEN;
        let bytes = unsafe { input_bytes(data, len, "trusted_policy_digests", false) }?;
        Ok(bytes
            .chunks_exact(SNP_HOST_DATA_LEN)
            .map(|chunk| {
                chunk
                    .try_into()
                    .expect("chunks_exact produced fixed-size chunks")
            })
            .collect())
    }

    fn write_owned_bytes(
        bytes: impl Into<Vec<u8>>,
        out_bytes: *mut TavCaciByteBuffer,
    ) -> Result<(), TavCaciError> {
        unsafe { byte_buffer_out_ptr(out_bytes, "out_report_data") }?;
        unsafe {
            *out_bytes = TavCaciByteBuffer::from_bytes(bytes);
        }
        Ok(())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_verify_caci_uvm_endorsement(
        uvm_endorsement: *const u8,
        uvm_endorsement_len: usize,
        trusted_didx509: *const c_char,
        trusted_didx509_len: usize,
        out_uvm_endorsement: *mut *mut TavCborValue,
    ) -> *mut TavCaciError {
        into_result((|| {
            unsafe { owned_out_ptr(out_uvm_endorsement, "out_uvm_endorsement") }?;
            let uvm_endorsement = unsafe {
                input_bytes(
                    uvm_endorsement,
                    uvm_endorsement_len,
                    "uvm_endorsement",
                    false,
                )
            }?;
            let trusted_didx509 = unsafe {
                input_text(
                    trusted_didx509,
                    trusted_didx509_len,
                    "trusted_didx509",
                    false,
                )
            }?;
            synchronous::verify_uvm_endorsement(uvm_endorsement, trusted_didx509)
                .map_err(TavCaciError::from)?;
            let cose_error = unsafe {
                cose::ffi::c::tav_cbor_value_from_bytes(
                    uvm_endorsement.as_ptr(),
                    uvm_endorsement.len(),
                    out_uvm_endorsement,
                )
            };
            if !cose_error.is_null() {
                return Err(unsafe { cose_error_to_caci(cose_error) });
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_verify_caci_attestation(
        attestation: *const TAVSnpAttestationReport,
        minimum_tcb_cpuids: *const u32,
        minimum_tcb_values: *const u8,
        minimum_tcb_count: usize,
        trusted_policy_digests: *const u8,
        trusted_policy_digest_count: usize,
        uvm_endorsement: *const TavCborValue,
        uvm_feed: *const c_char,
        uvm_feed_len: usize,
        minimum_svn: u64,
        out_report_data: *mut TavCaciByteBuffer,
    ) -> *mut TavCaciError {
        into_result((|| {
            unsafe { byte_buffer_out_ptr(out_report_data, "out_report_data") }?;
            let attestation = unsafe { attestation_report(attestation) }?;
            let minimum_tcb = unsafe {
                minimum_tcb_entries(minimum_tcb_cpuids, minimum_tcb_values, minimum_tcb_count)
            }?;
            let trusted_policy_digests = unsafe {
                parse_trusted_policy_digests(trusted_policy_digests, trusted_policy_digest_count)
            }?;
            let uvm_endorsement = unsafe { uvm_endorsement_handle(uvm_endorsement) }?;
            let uvm_feed = unsafe { input_text(uvm_feed, uvm_feed_len, "uvm_feed", false) }?;
            let report_data = synchronous::verify_caci_attestation(
                *attestation,
                minimum_tcb,
                trusted_policy_digests,
                uvm_endorsement.clone(),
                uvm_feed,
                minimum_svn,
            )
            .map_err(TavCaciError::from)?;
            write_owned_bytes(report_data, out_report_data)
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_caci_error_code(error: *const TavCaciError) -> TavCaciErrorCode {
        if error.is_null() {
            return TavCaciErrorCode::ErrorCodeIsNull;
        }

        unsafe { (*error).code }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_caci_error_message(error: *const TavCaciError) -> *const c_char {
        if error.is_null() {
            return NULL_ERROR_MESSAGE.as_ptr().cast();
        }

        unsafe { (*error).message.as_ptr() }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_caci_error_free(error: *mut TavCaciError) {
        if !error.is_null() {
            unsafe {
                drop(Box::from_raw(error));
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_caci_byte_buffer_free(bytes: *mut TavCaciByteBuffer) {
        if bytes.is_null() {
            return;
        }

        let bytes = unsafe { &mut *bytes };
        if !bytes.data.is_null() {
            let data = std::ptr::slice_from_raw_parts_mut(bytes.data, bytes.len);
            unsafe {
                drop(Box::from_raw(data));
            }
            bytes.data = ptr::null_mut();
            bytes.len = 0;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn c_header_enums_match_rust_enums() {
            let caci_header = include_str!("../../include/tav/caci.h");

            for (name, value) in [
                ("TAV_CACI_ERROR_OK", TavCaciErrorCode::Ok as i32),
                (
                    "TAV_CACI_ERROR_INVALID_ARGUMENT",
                    TavCaciErrorCode::InvalidArgument as i32,
                ),
                (
                    "TAV_CACI_ERROR_ERROR_CODE_IS_NULL",
                    TavCaciErrorCode::ErrorCodeIsNull as i32,
                ),
                (
                    "TAV_CACI_ERROR_UNSUPPORTED_PROCESSOR",
                    TavCaciErrorCode::UnsupportedProcessor as i32,
                ),
                (
                    "TAV_CACI_ERROR_INVALID_ROOT_CERTIFICATE",
                    TavCaciErrorCode::InvalidRootCertificate as i32,
                ),
                (
                    "TAV_CACI_ERROR_CERTIFICATE_CHAIN_ERROR",
                    TavCaciErrorCode::CertificateChainError as i32,
                ),
                (
                    "TAV_CACI_ERROR_SIGNATURE_VERIFICATION_ERROR",
                    TavCaciErrorCode::SignatureVerificationError as i32,
                ),
                (
                    "TAV_CACI_ERROR_TCB_VERIFICATION_ERROR",
                    TavCaciErrorCode::TcbVerificationError as i32,
                ),
                ("TAV_CACI_ERROR_COSE", TavCaciErrorCode::CaciCose as i32),
                (
                    "TAV_CACI_ERROR_CERTIFICATE",
                    TavCaciErrorCode::CaciCertificate as i32,
                ),
                (
                    "TAV_CACI_ERROR_DID_X509",
                    TavCaciErrorCode::CaciDidX509 as i32,
                ),
                (
                    "TAV_CACI_ERROR_SIGNATURE",
                    TavCaciErrorCode::CaciSignature as i32,
                ),
                (
                    "TAV_CACI_ERROR_MEASUREMENT",
                    TavCaciErrorCode::CaciMeasurement as i32,
                ),
                ("TAV_CACI_ERROR_POLICY", TavCaciErrorCode::CaciPolicy as i32),
            ] {
                assert_eq!(
                    c_header_enum_value(caci_header, name),
                    Some(value),
                    "{name} in include/tav/caci.h must match Rust"
                );
            }
        }

        #[test]
        fn owned_out_pointer_must_be_null_on_entry() {
            // A live (non-NULL) owned out-pointer is rejected without being
            // dereferenced or overwritten, matching tav_verify_snp_attestation.
            let sentinel = ptr::NonNull::<TavCborValue>::dangling().as_ptr();
            let mut uvm = sentinel;
            let err = unsafe {
                tav_verify_caci_uvm_endorsement(ptr::null(), 0, ptr::null(), 0, &mut uvm)
            };

            assert!(!err.is_null());
            assert_eq!(uvm, sentinel);
            unsafe {
                assert_eq!(tav_caci_error_code(err), TavCaciErrorCode::InvalidArgument);
                tav_caci_error_free(err);
            }
        }

        #[test]
        fn byte_buffer_out_parameter_is_write_only() {
            let mut bytes = TavCaciByteBuffer {
                data: ptr::NonNull::<u8>::dangling().as_ptr(),
                len: usize::MAX,
            };
            let err = unsafe {
                tav_verify_caci_attestation(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null(),
                    0,
                    0,
                    &mut bytes,
                )
            };

            assert!(!err.is_null());
            assert!(bytes.data.is_null());
            assert_eq!(bytes.len, 0);
            unsafe { tav_caci_error_free(err) };
        }

        #[test]
        fn byte_buffer_free_is_defensive_for_null_and_empty_buffers() {
            unsafe { tav_caci_byte_buffer_free(ptr::null_mut()) };

            let mut bytes = TavCaciByteBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            unsafe { tav_caci_byte_buffer_free(&mut bytes) };
            assert!(bytes.data.is_null());
            assert_eq!(bytes.len, 0);
        }

        #[test]
        fn error_accessors_handle_null_errors_defensively() {
            let message = unsafe { tav_caci_error_message(ptr::null()) };

            assert_eq!(
                unsafe { tav_caci_error_code(ptr::null()) },
                TavCaciErrorCode::ErrorCodeIsNull
            );
            assert!(!message.is_null());
            assert_eq!(
                unsafe { std::ffi::CStr::from_ptr(message) }
                    .to_str()
                    .unwrap(),
                "null TavCaciError pointer"
            );
        }

        fn c_header_enum_value(header: &str, name: &str) -> Option<i32> {
            header.lines().find_map(|line| {
                let (lhs, rhs) = line.split_once('=')?;
                // Token-exact match on the enumerator name so a code whose name
                // is a prefix of another cannot bind to the wrong line.
                if lhs.trim() != name {
                    return None;
                }
                rhs.trim().trim_end_matches(',').parse().ok()
            })
        }
    }
}
