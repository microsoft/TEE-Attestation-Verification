// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_family = "wasm")]
pub mod wasm {
    use js_sys::Array;
    use wasm_bindgen::prelude::*;

    use crate::CborValue as NativeCborValue;

    /// JavaScript wrapper around an owned CBOR value.
    #[wasm_bindgen]
    #[derive(Clone)]
    pub struct CborValue {
        inner: NativeCborValue,
    }

    impl CborValue {
        pub fn from_native(inner: NativeCborValue) -> Self {
            Self { inner }
        }

        pub fn as_native(&self) -> &NativeCborValue {
            &self.inner
        }

        pub fn into_native(self) -> NativeCborValue {
            self.inner
        }
    }

    #[wasm_bindgen]
    impl CborValue {
        /// Parse a CBOR document from bytes.
        pub fn from_bytes(bytes: &[u8]) -> Result<CborValue, String> {
            NativeCborValue::from_bytes(bytes).map(CborValue::from_native)
        }

        /// Serialize this value as deterministic CBOR bytes.
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            self.inner.to_bytes()
        }

        /// Return the CBOR major type represented by this value.
        pub fn kind(&self) -> String {
            match self.inner {
                NativeCborValue::Int(_) => "int",
                NativeCborValue::Simple(_) => "simple",
                NativeCborValue::ByteString(_) => "bytes",
                NativeCborValue::TextString(_) => "text",
                NativeCborValue::Array(_) => "array",
                NativeCborValue::Map(_) => "map",
                NativeCborValue::Tagged { .. } => "tagged",
            }
            .to_string()
        }

        pub fn int(&self) -> Result<i64, String> {
            match &self.inner {
                NativeCborValue::Int(value) => Ok(*value),
                other => Err(format!("Expected Int, got {:?}", other)),
            }
        }

        pub fn simple(&self) -> Result<u8, String> {
            match &self.inner {
                NativeCborValue::Simple(value) => Ok(*value),
                other => Err(format!("Expected Simple, got {:?}", other)),
            }
        }

        pub fn bytes(&self) -> Result<Vec<u8>, String> {
            match &self.inner {
                NativeCborValue::ByteString(value) => Ok(value.clone()),
                other => Err(format!("Expected ByteString, got {:?}", other)),
            }
        }

        pub fn text(&self) -> Result<String, String> {
            match &self.inner {
                NativeCborValue::TextString(value) => Ok(value.clone()),
                other => Err(format!("Expected TextString, got {:?}", other)),
            }
        }

        pub fn tag(&self) -> Result<u64, String> {
            match &self.inner {
                NativeCborValue::Tagged { tag, .. } => Ok(*tag),
                other => Err(format!("Expected Tagged, got {:?}", other)),
            }
        }

        pub fn tagged_payload(&self) -> Result<CborValue, String> {
            match &self.inner {
                NativeCborValue::Tagged { payload, .. } => {
                    Ok(CborValue::from_native(payload.as_ref().clone()))
                }
                other => Err(format!("Expected Tagged, got {:?}", other)),
            }
        }

        pub fn len(&self) -> Result<u32, String> {
            self.inner
                .len()?
                .try_into()
                .map_err(|_| "CBOR container length does not fit u32".to_string())
        }

        pub fn array_at(&self, index: u32) -> Result<CborValue, String> {
            self.inner
                .array_at(index as usize)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_at_int(&self, key: i64) -> Result<CborValue, String> {
            self.inner
                .map_at_int(key)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_at_text(&self, key: &str) -> Result<CborValue, String> {
            self.inner
                .map_at_str(key)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_at(&self, key: &CborValue) -> Result<CborValue, String> {
            self.inner
                .map_at(key.as_native())
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn map_entry_at(&self, index: u32) -> Result<Array, String> {
            map_entry_at(&self.inner, index).map(|(key, value)| {
                let entry = Array::new();
                entry.push(&CborValue::from_native(key.clone()).into());
                entry.push(&CborValue::from_native(value.clone()).into());
                entry
            })
        }

        pub fn map_key_at(&self, index: u32) -> Result<CborValue, String> {
            map_entry_at(&self.inner, index).map(|(key, _)| CborValue::from_native(key.clone()))
        }

        pub fn map_value_at(&self, index: u32) -> Result<CborValue, String> {
            map_entry_at(&self.inner, index).map(|(_, value)| CborValue::from_native(value.clone()))
        }

        pub fn as_cose_sign1(&self) -> Result<CoseSign1, String> {
            crate::cose_sign1(&self.inner)
                .cloned()
                .map(CoseSign1::from_native)
        }
    }

    /// JavaScript wrapper around a COSE_Sign1 array.
    #[wasm_bindgen]
    #[derive(Clone)]
    pub struct CoseSign1 {
        inner: NativeCborValue,
    }

    impl CoseSign1 {
        pub fn from_native(inner: NativeCborValue) -> Self {
            Self { inner }
        }
    }

    #[wasm_bindgen]
    impl CoseSign1 {
        pub fn protected(&self) -> Result<Vec<u8>, String> {
            required_bytes(
                self.inner.array_at(crate::COSE_SIGN1_PROTECTED)?,
                "protected",
            )
        }

        pub fn unprotected(&self) -> Result<CborValue, String> {
            self.inner
                .array_at(crate::COSE_SIGN1_UNPROTECTED)
                .cloned()
                .map(CborValue::from_native)
        }

        pub fn payload(&self) -> Result<Vec<u8>, String> {
            required_bytes(self.inner.array_at(crate::COSE_SIGN1_PAYLOAD)?, "payload")
        }

        pub fn signature(&self) -> Result<Vec<u8>, String> {
            required_bytes(
                self.inner.array_at(crate::COSE_SIGN1_SIGNATURE)?,
                "signature",
            )
        }

        pub fn protected_header(&self) -> Result<CborValue, String> {
            NativeCborValue::from_bytes(&self.protected()?).map(CborValue::from_native)
        }
    }

    /// Verify an embedded-payload COSE_Sign1 signature over the envelope's own
    /// payload field, using the active asynchronous crypto backend.
    ///
    /// `spki_der` is the DER-encoded SubjectPublicKeyInfo of the signer key and
    /// `cose_alg` is the COSE algorithm identifier (for example `-7` for ES256).
    #[cfg(async_crypto)]
    #[wasm_bindgen]
    pub async fn verify_cose_sign1_embedded(
        sign1: &CoseSign1,
        spki_der: Vec<u8>,
        cose_alg: i64,
    ) -> Result<(), String> {
        let protected = sign1.protected()?;
        let payload = sign1.payload()?;
        let signature = sign1.signature()?;
        verify_cose_sign1(&protected, &payload, &signature, &spki_der, cose_alg).await
    }

    /// Verify a detached-payload COSE_Sign1 signature using the active
    /// asynchronous crypto backend.
    ///
    /// The COSE payload field must be nil; the covered `payload` bytes are
    /// supplied by the caller.
    #[cfg(async_crypto)]
    #[wasm_bindgen]
    pub async fn verify_cose_sign1_detached(
        sign1: &CoseSign1,
        payload: Vec<u8>,
        spki_der: Vec<u8>,
        cose_alg: i64,
    ) -> Result<(), String> {
        match sign1.inner.array_at(crate::COSE_SIGN1_PAYLOAD) {
            Ok(NativeCborValue::Simple(crate::CBOR_SIMPLE_NULL)) => {}
            Ok(NativeCborValue::ByteString(_)) => {
                return Err("detached payload verification requires nil COSE payload; use verify_cose_sign1_embedded for byte string payloads".into());
            }
            _ => return Err("detached payload verification requires nil COSE payload".into()),
        }
        let protected = sign1.protected()?;
        let signature = sign1.signature()?;
        verify_cose_sign1(&protected, &payload, &signature, &spki_der, cose_alg).await
    }

    #[cfg(async_crypto)]
    async fn verify_cose_sign1(
        protected: &[u8],
        payload: &[u8],
        signature: &[u8],
        spki_der: &[u8],
        cose_alg: i64,
    ) -> Result<(), String> {
        use crypto::{AsyncCryptoBackend, AsyncKeyBackend};

        let algorithm = crate::signature_key_algorithm_for_cose_alg(cose_alg)?;
        let key = <<crypto::Crypto as AsyncCryptoBackend>::Key as AsyncKeyBackend>::from_spki_der(
            spki_der, algorithm,
        )
        .await
        .map_err(|error| error.to_string())?;
        crate::asynchronous::cose_verify1(&key, algorithm, protected, payload, signature).await
    }

    pub fn required_bytes(value: &NativeCborValue, name: &str) -> Result<Vec<u8>, String> {
        match value {
            NativeCborValue::ByteString(bytes) => Ok(bytes.clone()),
            _ => Err(format!("{name} must be a byte string")),
        }
    }

    fn map_entry_at(
        value: &NativeCborValue,
        index: u32,
    ) -> Result<(&NativeCborValue, &NativeCborValue), String> {
        value
            .iter_map()?
            .nth(index as usize)
            .ok_or_else(|| format!("Index {index} out of bounds"))
    }
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
pub mod c {
    //! C ABI bindings for CBOR navigation and COSE_Sign1 verification.
    //!
    //! This module exports the symbols declared in `include/tav/cose.h`.
    //!
    //! `TavCborValue` handles returned by [`tav_cbor_value_from_bytes`] are
    //! owned and must be released with [`tav_cbor_value_free`]. Child accessors
    //! return borrowed handles into the owned root. Borrowed handles must not be
    //! freed and remain valid only while the ancestor owned handle is alive.

    use std::os::raw::c_char;
    use std::ptr;

    use crypto::{CryptoBackend, KeyBackend};
    use ffi_utils::{TavByteBuffer, TavError, TavErrorCode};

    use crate::{cose_sign1, signature_key_algorithm_for_cose_alg, CborValue as NativeCborValue};

    const MAX_INPUT_LEN: usize = 1024 * 1024 * 1024;

    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TavCborKind {
        Int = 1,
        Simple = 2,
        Bytes = 3,
        Text = 4,
        Array = 5,
        Map = 6,
        Tagged = 7,
    }

    #[repr(transparent)]
    pub struct TavCborValue {
        inner: NativeCborValue,
    }

    trait TavErrorExt {
        fn cbor(message: impl Into<String>) -> Self;
        fn unexpected_type(message: impl Into<String>) -> Self;
    }

    impl TavErrorExt for TavError {
        fn cbor(message: impl Into<String>) -> Self {
            Self::new(TavErrorCode::CoseCbor, message)
        }

        fn unexpected_type(message: impl Into<String>) -> Self {
            Self::new(TavErrorCode::CoseUnexpectedType, message)
        }
    }

    impl TavCborValue {
        fn from_native(inner: NativeCborValue) -> Self {
            Self { inner }
        }

        fn as_native(&self) -> &NativeCborValue {
            &self.inner
        }

        fn borrowed(value: &NativeCborValue) -> *const Self {
            value as *const NativeCborValue as *const Self
        }
    }

    fn into_error(error: TavError) -> *mut TavError {
        error.into_raw()
    }

    fn into_result(result: Result<(), TavError>) -> *mut TavError {
        match result {
            Ok(()) => ptr::null_mut(),
            Err(error) => into_error(error),
        }
    }

    unsafe fn input_bytes<'a>(
        data: *const u8,
        len: usize,
        name: &str,
        allow_empty: bool,
    ) -> Result<&'a [u8], TavError> {
        if len == 0 {
            if allow_empty {
                return Ok(&[]);
            }
            return Err(TavError::invalid_argument(format!("{name} is empty")));
        }
        if data.is_null() {
            return Err(TavError::invalid_argument(format!(
                "{name} pointer is null"
            )));
        }
        if len > MAX_INPUT_LEN {
            return Err(TavError::invalid_argument(format!(
                "{name} exceeds maximum input size"
            )));
        }
        Ok(unsafe { std::slice::from_raw_parts(data, len) })
    }

    unsafe fn input_text<'a>(
        data: *const c_char,
        len: usize,
        name: &str,
    ) -> Result<&'a str, TavError> {
        let bytes = unsafe { input_bytes(data.cast(), len, name, true) }?;
        std::str::from_utf8(bytes).map_err(|error| {
            TavError::invalid_argument(format!("{name} is not valid UTF-8: {error}"))
        })
    }

    unsafe fn out_ptr<T>(out: *mut T, name: &str) -> Result<(), TavError> {
        if out.is_null() {
            return Err(TavError::invalid_argument(format!(
                "{name} pointer is null"
            )));
        }
        Ok(())
    }

    unsafe fn owned_out_ptr<T>(out: *mut *mut T, name: &str) -> Result<(), TavError> {
        unsafe { out_ptr(out, name) }?;
        // Matches tav_verify_snp_attestation: the slot must contain NULL on
        // entry. A non-NULL slot is rejected without being overwritten, so a
        // caller can never silently leak a live handle by reusing a variable.
        if unsafe { !(*out).is_null() } {
            return Err(TavError::invalid_argument(format!(
                "{name} must point to NULL before verification"
            )));
        }
        Ok(())
    }

    unsafe fn borrowed_out_ptr<T>(out: *mut *const T, name: &str) -> Result<(), TavError> {
        unsafe { out_ptr(out, name) }
    }

    unsafe fn byte_buffer_out_ptr(out: *mut TavByteBuffer, name: &str) -> Result<(), TavError> {
        unsafe { out_ptr(out, name) }?;
        unsafe {
            *out = TavByteBuffer::empty();
        }
        Ok(())
    }

    unsafe fn cbor_value<'a>(
        value: *const TavCborValue,
        name: &str,
    ) -> Result<&'a NativeCborValue, TavError> {
        if value.is_null() {
            return Err(TavError::invalid_argument(format!("{name} is null")));
        }
        Ok(unsafe { (*value).as_native() })
    }

    fn kind(value: &NativeCborValue) -> TavCborKind {
        match value {
            NativeCborValue::Int(_) => TavCborKind::Int,
            NativeCborValue::Simple(_) => TavCborKind::Simple,
            NativeCborValue::ByteString(_) => TavCborKind::Bytes,
            NativeCborValue::TextString(_) => TavCborKind::Text,
            NativeCborValue::Array(_) => TavCborKind::Array,
            NativeCborValue::Map(_) => TavCborKind::Map,
            NativeCborValue::Tagged { .. } => TavCborKind::Tagged,
        }
    }

    fn borrowed_bytes<'a>(value: &'a NativeCborValue, name: &str) -> Result<&'a [u8], TavError> {
        match value {
            NativeCborValue::ByteString(bytes) => Ok(bytes),
            _ => Err(TavError::unexpected_type(format!(
                "{name} must be a byte string"
            ))),
        }
    }

    fn require_detached_payload(sign1: &NativeCborValue) -> Result<(), TavError> {
        match sign1_field(sign1, crate::COSE_SIGN1_PAYLOAD, "payload")? {
            NativeCborValue::Simple(crate::CBOR_SIMPLE_NULL) => Ok(()),
            NativeCborValue::ByteString(_) => Err(TavError::unexpected_type(
                "detached payload verification requires nil COSE payload; use embedded verification for byte string payloads",
            )),
            _ => Err(TavError::unexpected_type(
                "detached payload verification requires nil COSE payload",
            )),
        }
    }

    fn sign1_field<'a>(
        sign1: &'a NativeCborValue,
        index: usize,
        name: &str,
    ) -> Result<&'a NativeCborValue, TavError> {
        sign1
            .array_at(index)
            .map_err(|error| TavError::cbor(format!("Failed to read {name}: {error}")))
    }

    fn map_entry_at(
        value: &NativeCborValue,
        index: usize,
    ) -> Result<(&NativeCborValue, &NativeCborValue), TavError> {
        value
            .iter_map()
            .map_err(TavError::cbor)?
            .nth(index)
            .ok_or_else(|| TavError::cbor(format!("Index {index} out of bounds")))
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_from_bytes(
        bytes: *const u8,
        len: usize,
        out_value: *mut *mut TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { owned_out_ptr(out_value, "out_value") }?;
            let bytes = unsafe { input_bytes(bytes, len, "CBOR bytes", false) }?;
            let value = NativeCborValue::from_bytes(bytes).map_err(TavError::cbor)?;
            unsafe {
                *out_value = Box::into_raw(Box::new(TavCborValue::from_native(value)));
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_to_bytes(
        value: *const TavCborValue,
        out_bytes: *mut TavByteBuffer,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { byte_buffer_out_ptr(out_bytes, "out_bytes") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let bytes = value.to_bytes().map_err(TavError::cbor)?;
            unsafe {
                *out_bytes = TavByteBuffer::from_bytes(bytes);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_kind(value: *const TavCborValue) -> TavCborKind {
        kind(unsafe { (*value).as_native() })
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_int(
        value: *const TavCborValue,
        out: *mut i64,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let int = match value {
                NativeCborValue::Int(value) => *value,
                _ => return Err(TavError::unexpected_type("value must be an int")),
            };
            unsafe {
                *out = int;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_simple(
        value: *const TavCborValue,
        out: *mut u8,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let simple = match value {
                NativeCborValue::Simple(value) => *value,
                _ => return Err(TavError::unexpected_type("value must be simple")),
            };
            unsafe {
                *out = simple;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_bytes(
        value: *const TavCborValue,
        data: *mut *const u8,
        len: *mut usize,
    ) -> *mut TavError {
        into_result((|| {
            unsafe {
                borrowed_out_ptr(data, "data")?;
                out_ptr(len, "len")?;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let bytes = borrowed_bytes(value, "value")?;
            unsafe {
                *data = bytes.as_ptr();
                *len = bytes.len();
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_text(
        value: *const TavCborValue,
        text: *mut *const c_char,
        len: *mut usize,
    ) -> *mut TavError {
        into_result((|| {
            unsafe {
                borrowed_out_ptr(text, "text")?;
                out_ptr(len, "len")?;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let value = match value {
                NativeCborValue::TextString(value) => value.as_bytes(),
                _ => return Err(TavError::unexpected_type("value must be text")),
            };
            unsafe {
                *text = value.as_ptr().cast();
                *len = value.len();
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_tag(
        value: *const TavCborValue,
        out: *mut u64,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let tag = match value {
                NativeCborValue::Tagged { tag, .. } => *tag,
                _ => return Err(TavError::unexpected_type("value must be tagged")),
            };
            unsafe {
                *out = tag;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_tagged_payload(
        value: *const TavCborValue,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let payload = match value {
                NativeCborValue::Tagged { payload, .. } => payload.as_ref(),
                _ => return Err(TavError::unexpected_type("value must be tagged")),
            };
            unsafe {
                *out_value = TavCborValue::borrowed(payload);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_len(
        value: *const TavCborValue,
        out: *mut usize,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let value_len = value.len().map_err(TavError::cbor)?;
            unsafe {
                *out = value_len;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_array_at(
        value: *const TavCborValue,
        index: usize,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let child = value.array_at(index).map_err(TavError::cbor)?;
            unsafe {
                *out_value = TavCborValue::borrowed(child);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_at_int(
        value: *const TavCborValue,
        key: i64,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let child = value.map_at_int(key).map_err(TavError::cbor)?;
            unsafe {
                *out_value = TavCborValue::borrowed(child);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_at_text(
        value: *const TavCborValue,
        key: *const c_char,
        key_len: usize,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let key = unsafe { input_text(key, key_len, "key") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let child = value.map_at_str(key).map_err(TavError::cbor)?;
            unsafe {
                *out_value = TavCborValue::borrowed(child);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_at(
        value: *const TavCborValue,
        key: *const TavCborValue,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let key = unsafe { cbor_value(key, "key") }?;
            let child = value.map_at(key).map_err(TavError::cbor)?;
            unsafe {
                *out_value = TavCborValue::borrowed(child);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_has_int_key(
        value: *const TavCborValue,
        key: i64,
        out: *mut bool,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            unsafe {
                *out = false;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let has_key = value.map_has_int_key(key).map_err(TavError::cbor)?;
            unsafe {
                *out = has_key;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_has_text_key(
        value: *const TavCborValue,
        key: *const c_char,
        key_len: usize,
        out: *mut bool,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            unsafe {
                *out = false;
            }
            let key = unsafe { input_text(key, key_len, "key") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let has_key = value.map_has_str_key(key).map_err(TavError::cbor)?;
            unsafe {
                *out = has_key;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_has_key(
        value: *const TavCborValue,
        key: *const TavCborValue,
        out: *mut bool,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            unsafe {
                *out = false;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let key = unsafe { cbor_value(key, "key") }?;
            let has_key = value.map_has_key(key).map_err(TavError::cbor)?;
            unsafe {
                *out = has_key;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_entry_at(
        value: *const TavCborValue,
        index: usize,
        out_key: *mut *const TavCborValue,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_key, "out_key") }?;
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let (key, child) = map_entry_at(value, index)?;
            unsafe {
                *out_key = TavCborValue::borrowed(key);
                *out_value = TavCborValue::borrowed(child);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_validate_cose_sign1(
        value: *const TavCborValue,
        out_sign1: *mut *const TavCborValue,
    ) -> *mut TavError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_sign1, "out_sign1") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let sign1 = cose_sign1(value).map_err(TavError::cbor)?;
            unsafe {
                *out_sign1 = TavCborValue::borrowed(sign1);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_free(value: *mut TavCborValue) {
        if !value.is_null() {
            unsafe {
                drop(Box::from_raw(value));
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_verify_cose_sign1_embedded(
        sign1: *const TavCborValue,
        spki_der: *const u8,
        spki_der_len: usize,
        cose_alg: i32,
    ) -> *mut TavError {
        into_result((|| {
            let value = unsafe { cbor_value(sign1, "sign1") }?;
            let sign1 = cose_sign1(value).map_err(TavError::cbor)?;
            let payload = borrowed_bytes(
                sign1_field(sign1, crate::COSE_SIGN1_PAYLOAD, "payload")?,
                "payload",
            )?;
            verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_verify_cose_sign1_detached(
        sign1: *const TavCborValue,
        payload: *const u8,
        payload_len: usize,
        spki_der: *const u8,
        spki_der_len: usize,
        cose_alg: i32,
    ) -> *mut TavError {
        into_result((|| {
            let value = unsafe { cbor_value(sign1, "sign1") }?;
            let sign1 = cose_sign1(value).map_err(TavError::cbor)?;
            require_detached_payload(sign1)?;
            let payload = unsafe { input_bytes(payload, payload_len, "payload", true) }?;
            verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
        })())
    }

    fn verify_sign1(
        sign1: &NativeCborValue,
        payload: &[u8],
        spki_der: *const u8,
        spki_der_len: usize,
        cose_alg: i32,
    ) -> Result<(), TavError> {
        let protected = borrowed_bytes(
            sign1_field(sign1, crate::COSE_SIGN1_PROTECTED, "protected")?,
            "protected",
        )?;
        let signature = borrowed_bytes(
            sign1_field(sign1, crate::COSE_SIGN1_SIGNATURE, "signature")?,
            "signature",
        )?;
        let spki_der = unsafe { input_bytes(spki_der, spki_der_len, "SPKI DER", false) }?;
        let algorithm = signature_key_algorithm_for_cose_alg(cose_alg as i64)
            .map_err(|error| TavError::new(TavErrorCode::CoseUnsupportedAlgorithm, error))?;
        let key = <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(
            spki_der, algorithm,
        )
        .map_err(|error| TavError::new(TavErrorCode::CoseKeyImport, error.to_string()))?;
        crate::synchronous::cose_verify1(&key, algorithm, protected, payload, signature)
            .map_err(|error| TavError::new(TavErrorCode::CoseVerification, error))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const PAYLOAD: &[u8] = b"verification-only COSE vector";
        const P256_PHDR: &[u8] = &[161, 1, 38];
        const P256_SPKI: &[u8] = &[
            48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
            3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119, 177, 246, 18, 133,
            248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11, 85, 3, 249, 180, 113, 248,
            87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72, 167, 32, 114, 51, 92, 109, 60, 158,
            23, 216, 2, 11, 126, 11, 242, 186, 211, 205,
        ];
        const P256_SIG: &[u8] = &[
            90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47, 248, 221,
            245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92, 210, 184, 112, 104,
            224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93, 103, 128, 147, 144, 252, 13,
            252, 91, 233, 88, 189, 169, 103, 151,
        ];

        #[test]
        fn c_header_enums_match_rust_enums() {
            let cose_header = include_str!("../../include/tav/cose.h");

            for (name, value) in [
                ("TAV_CBOR_KIND_INT", TavCborKind::Int as i32),
                ("TAV_CBOR_KIND_SIMPLE", TavCborKind::Simple as i32),
                ("TAV_CBOR_KIND_BYTES", TavCborKind::Bytes as i32),
                ("TAV_CBOR_KIND_TEXT", TavCborKind::Text as i32),
                ("TAV_CBOR_KIND_ARRAY", TavCborKind::Array as i32),
                ("TAV_CBOR_KIND_MAP", TavCborKind::Map as i32),
                ("TAV_CBOR_KIND_TAGGED", TavCborKind::Tagged as i32),
                ("TAV_COSE_TAG_SIGN1", crate::COSE_SIGN1_TAG as i32),
                (
                    "TAV_COSE_SIGN1_PROTECTED",
                    crate::COSE_SIGN1_PROTECTED as i32,
                ),
                (
                    "TAV_COSE_SIGN1_UNPROTECTED",
                    crate::COSE_SIGN1_UNPROTECTED as i32,
                ),
                ("TAV_COSE_SIGN1_PAYLOAD", crate::COSE_SIGN1_PAYLOAD as i32),
                (
                    "TAV_COSE_SIGN1_SIGNATURE",
                    crate::COSE_SIGN1_SIGNATURE as i32,
                ),
                ("TAV_COSE_HEADER_ALG", crate::COSE_HEADER_ALG as i32),
                (
                    "TAV_COSE_HEADER_CWT_CLAIMS",
                    crate::COSE_HEADER_CWT_CLAIMS as i32,
                ),
                ("TAV_COSE_HEADER_X5CHAIN", crate::COSE_HEADER_X5CHAIN as i32),
                (
                    "TAV_COSE_HEADER_CONTENT_TYPE",
                    crate::COSE_HEADER_CONTENT_TYPE as i32,
                ),
                (
                    "TAV_COSE_HEADER_PREIMAGE_CONTENT_TYPE",
                    crate::COSE_HEADER_PREIMAGE_CONTENT_TYPE as i32,
                ),
                ("TAV_CWT_CLAIMS_ISSUER", crate::CWT_CLAIMS_ISSUER as i32),
                ("TAV_CWT_CLAIMS_SUBJECT", crate::CWT_CLAIMS_SUBJECT as i32),
                ("TAV_CWT_CLAIMS_IAT", crate::CWT_CLAIMS_IAT as i32),
            ] {
                assert_eq!(
                    c_header_enum_value(cose_header, name),
                    Some(value),
                    "{name} in include/tav/cose.h must match Rust"
                );
            }
        }

        #[test]
        fn cbor_children_are_borrowed_from_owned_root() {
            let cbor = [0x82, 0x01, 0x42, 0xaa, 0xbb];
            let mut root = ptr::null_mut();
            let err = unsafe { tav_cbor_value_from_bytes(cbor.as_ptr(), cbor.len(), &mut root) };
            assert!(err.is_null());
            assert!(!root.is_null());

            let mut child = ptr::null();
            let err = unsafe { tav_cbor_value_array_at(root, 0, &mut child) };
            assert!(err.is_null());
            assert_eq!(unsafe { tav_cbor_value_kind(child) }, TavCborKind::Int);

            let mut int = 0;
            let err = unsafe { tav_cbor_value_int(child, &mut int) };
            assert!(err.is_null());
            assert_eq!(int, 1);

            let err = unsafe { tav_cbor_value_array_at(root, 1, &mut child) };
            assert!(err.is_null());
            let mut bytes = ptr::null();
            let mut len = 0;
            let err = unsafe { tav_cbor_value_bytes(child, &mut bytes, &mut len) };
            assert!(err.is_null());
            assert_eq!(
                unsafe { std::slice::from_raw_parts(bytes, len) },
                &[0xaa, 0xbb]
            );

            unsafe { tav_cbor_value_free(root) };
        }

        #[test]
        fn cbor_map_lookup_and_presence_checks() {
            let cbor = [
                0xa3, 0x01, 0x63, b'o', b'n', b'e', 0x63, b'k', b'e', b'y', 0x18, 0x2a, 0x41, 0xaa,
                0xf5,
            ];
            let mut root = ptr::null_mut();
            let err = unsafe { tav_cbor_value_from_bytes(cbor.as_ptr(), cbor.len(), &mut root) };
            assert!(err.is_null());

            let mut key = ptr::null();
            let mut value = ptr::null();
            let err = unsafe { tav_cbor_value_map_entry_at(root, 0, &mut key, &mut value) };
            assert!(err.is_null());
            let mut text = ptr::null();
            let mut text_len = 0;
            let err = unsafe { tav_cbor_value_text(value, &mut text, &mut text_len) };
            assert!(err.is_null());
            assert_eq!(
                unsafe { std::slice::from_raw_parts(text.cast::<u8>(), text_len) },
                b"one"
            );

            let mut has_key = false;
            let err = unsafe { tav_cbor_value_map_has_key(root, key, &mut has_key) };
            assert!(err.is_null());
            assert!(has_key);

            let err = unsafe { tav_cbor_value_map_has_int_key(root, 2, &mut has_key) };
            assert!(err.is_null());
            assert!(!has_key);

            let key_text = b"key";
            let err = unsafe {
                tav_cbor_value_map_has_text_key(
                    root,
                    key_text.as_ptr().cast(),
                    key_text.len(),
                    &mut has_key,
                )
            };
            assert!(err.is_null());
            assert!(has_key);

            let mut byte_string_key = ptr::null();
            let err =
                unsafe { tav_cbor_value_map_entry_at(root, 2, &mut byte_string_key, &mut value) };
            assert!(err.is_null());
            let err = unsafe { tav_cbor_value_map_at(root, byte_string_key, &mut value) };
            assert!(err.is_null());
            assert_eq!(unsafe { tav_cbor_value_kind(value) }, TavCborKind::Simple);

            let key_cbor = [0x41, 0xaa];
            let mut owned_key = ptr::null_mut();
            let err = unsafe {
                tav_cbor_value_from_bytes(key_cbor.as_ptr(), key_cbor.len(), &mut owned_key)
            };
            assert!(err.is_null());
            let err = unsafe { tav_cbor_value_map_has_key(root, owned_key, &mut has_key) };
            assert!(err.is_null());
            assert!(has_key);

            unsafe { tav_cbor_value_free(root) };
            unsafe { tav_cbor_value_free(owned_key) };
        }

        #[test]
        fn cbor_value_round_trips_through_out_parameters() {
            let cbor = [0x81, 0x01];
            let mut root = ptr::null_mut();
            let err = unsafe { tav_cbor_value_from_bytes(cbor.as_ptr(), cbor.len(), &mut root) };
            assert!(err.is_null());
            assert!(!root.is_null());

            // Byte-buffer out-parameters are write-only: a stale, non-empty
            // buffer is reset before any fallible work.
            let mut bytes = TavByteBuffer {
                data: ptr::NonNull::<u8>::dangling().as_ptr(),
                len: usize::MAX,
            };
            let err = unsafe { tav_cbor_value_to_bytes(root, &mut bytes) };
            assert!(err.is_null());
            assert!(!bytes.data.is_null());
            assert_ne!(bytes.len, 0);

            unsafe {
                ffi_utils::tav_byte_buffer_free(&mut bytes);
                tav_cbor_value_free(root);
            }
            assert!(bytes.data.is_null());
            assert_eq!(bytes.len, 0);
        }

        #[test]
        fn owned_out_pointer_must_be_null_on_entry() {
            let cbor = [0x81, 0x01];
            // A live (non-NULL) owned out-pointer is rejected without being
            // dereferenced or overwritten, matching tav_verify_snp_attestation.
            let sentinel = ptr::NonNull::<TavCborValue>::dangling().as_ptr();
            let mut root = sentinel;
            let err = unsafe { tav_cbor_value_from_bytes(cbor.as_ptr(), cbor.len(), &mut root) };
            assert!(!err.is_null());
            assert_eq!(root, sentinel);
            unsafe {
                assert_eq!(
                    ffi_utils::tav_error_code(err),
                    TavErrorCode::InvalidArgument
                );
                ffi_utils::tav_error_free(err);
            }
        }

        #[test]
        fn byte_buffer_free_is_defensive_for_null_and_empty_buffers() {
            unsafe { ffi_utils::tav_byte_buffer_free(ptr::null_mut()) };

            let mut bytes = TavByteBuffer {
                data: ptr::null_mut(),
                len: 0,
            };
            unsafe { ffi_utils::tav_byte_buffer_free(&mut bytes) };
            assert!(bytes.data.is_null());
            assert_eq!(bytes.len, 0);
        }

        #[test]
        fn cose_sign1_embedded_verification_succeeds() {
            let envelope = NativeCborValue::Tagged {
                tag: 18,
                payload: Box::new(NativeCborValue::Array(vec![
                    NativeCborValue::ByteString(P256_PHDR.to_vec()),
                    NativeCborValue::Map(vec![]),
                    NativeCborValue::ByteString(PAYLOAD.to_vec()),
                    NativeCborValue::ByteString(P256_SIG.to_vec()),
                ])),
            }
            .to_bytes()
            .unwrap();

            let mut root = ptr::null_mut();
            let err =
                unsafe { tav_cbor_value_from_bytes(envelope.as_ptr(), envelope.len(), &mut root) };
            assert!(err.is_null());

            let mut sign1 = ptr::null();
            let err = unsafe { tav_validate_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());
            assert!(!sign1.is_null());
            assert_eq!(unsafe { tav_cbor_value_kind(sign1) }, TavCborKind::Array);

            let err = unsafe {
                tav_verify_cose_sign1_embedded(sign1, P256_SPKI.as_ptr(), P256_SPKI.len(), -7)
            };
            assert!(err.is_null());

            unsafe { tav_cbor_value_free(root) };
        }

        #[test]
        fn cose_sign1_detached_verification_requires_nil_payload() {
            let envelope = NativeCborValue::Tagged {
                tag: 18,
                payload: Box::new(NativeCborValue::Array(vec![
                    NativeCborValue::ByteString(P256_PHDR.to_vec()),
                    NativeCborValue::Map(vec![]),
                    NativeCborValue::ByteString(PAYLOAD.to_vec()),
                    NativeCborValue::ByteString(P256_SIG.to_vec()),
                ])),
            }
            .to_bytes()
            .unwrap();

            let mut root = ptr::null_mut();
            let err =
                unsafe { tav_cbor_value_from_bytes(envelope.as_ptr(), envelope.len(), &mut root) };
            assert!(err.is_null());

            let mut sign1 = ptr::null();
            let err = unsafe { tav_validate_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());

            let err = unsafe {
                tav_verify_cose_sign1_detached(
                    sign1,
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                    P256_SPKI.as_ptr(),
                    P256_SPKI.len(),
                    -7,
                )
            };
            assert_eq!(
                unsafe { ffi_utils::tav_error_code(err) },
                TavErrorCode::CoseUnexpectedType
            );
            assert!(
                unsafe { std::ffi::CStr::from_ptr(ffi_utils::tav_error_message(err)) }
                    .to_str()
                    .unwrap()
                    .contains("requires nil COSE payload")
            );

            unsafe {
                ffi_utils::tav_error_free(err);
                tav_cbor_value_free(root);
            }
        }

        #[test]
        fn cose_sign1_detached_verification_accepts_nil_payload() {
            let envelope = NativeCborValue::Tagged {
                tag: 18,
                payload: Box::new(NativeCborValue::Array(vec![
                    NativeCborValue::ByteString(P256_PHDR.to_vec()),
                    NativeCborValue::Map(vec![]),
                    NativeCborValue::Simple(crate::CBOR_SIMPLE_NULL),
                    NativeCborValue::ByteString(P256_SIG.to_vec()),
                ])),
            }
            .to_bytes()
            .unwrap();

            let mut root = ptr::null_mut();
            let err =
                unsafe { tav_cbor_value_from_bytes(envelope.as_ptr(), envelope.len(), &mut root) };
            assert!(err.is_null());

            let mut sign1 = ptr::null();
            let err = unsafe { tav_validate_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());

            let err = unsafe {
                tav_verify_cose_sign1_detached(
                    sign1,
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                    P256_SPKI.as_ptr(),
                    P256_SPKI.len(),
                    -7,
                )
            };
            assert!(err.is_null());

            unsafe { tav_cbor_value_free(root) };
        }

        #[test]
        fn null_error_accessors_are_defensive() {
            assert_eq!(
                unsafe { ffi_utils::tav_error_code(ptr::null()) },
                TavErrorCode::ErrorCodeIsNull
            );
            let message = unsafe { ffi_utils::tav_error_message(ptr::null()) };
            assert_eq!(
                unsafe { std::ffi::CStr::from_ptr(message) }
                    .to_str()
                    .unwrap(),
                "null TavError pointer"
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
