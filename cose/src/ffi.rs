// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_family = "wasm")]
pub mod wasm {
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
            required_bytes(self.inner.array_at(0)?, "protected")
        }

        pub fn unprotected(&self) -> Result<CborValue, String> {
            self.inner.array_at(1).cloned().map(CborValue::from_native)
        }

        pub fn payload(&self) -> Result<Vec<u8>, String> {
            required_bytes(self.inner.array_at(2)?, "payload")
        }

        pub fn signature(&self) -> Result<Vec<u8>, String> {
            required_bytes(self.inner.array_at(3)?, "signature")
        }

        pub fn protected_header(&self) -> Result<CborValue, String> {
            NativeCborValue::from_bytes(&self.protected()?).map(CborValue::from_native)
        }
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
        match value {
            NativeCborValue::Map(entries) => entries
                .get(index as usize)
                .map(|(key, value)| (key, value))
                .ok_or_else(|| format!("Index {index} out of bounds")),
            other => Err(format!("Expected Map, got {:?}", other)),
        }
    }
}

#[cfg(all(not(target_family = "wasm"), sync_crypto))]
pub mod c {
    //! C ABI bindings for CBOR navigation and COSE_Sign1 verification.
    //!
    //! This module exports the symbols declared in `include/tav/cose.h`.
    //!
    //! `TAVCborValue` handles returned by [`tav_cbor_value_from_bytes`] are
    //! owned and must be released with [`tav_cbor_value_free`]. Child accessors
    //! return borrowed handles into the owned root. Borrowed handles must not be
    //! freed and remain valid only while the ancestor owned handle is alive.

    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;

    use crypto::{CryptoBackend, KeyBackend};

    use crate::{cose_sign1, signature_key_algorithm_for_cose_alg, CborValue as NativeCborValue};

    const MAX_INPUT_LEN: usize = 1024 * 1024 * 1024;
    const NULL_ERROR_MESSAGE: &[u8] = b"null TAVCoseError pointer\0";

    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TavCoseErrorCode {
        Ok = 0,
        InvalidArgument = 1,
        ErrorIsNull = 2,
        Cbor = 201,
        UnexpectedType = 202,
        UnsupportedAlgorithm = 203,
        KeyImport = 204,
        Verification = 205,
    }

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

    #[repr(transparent)]
    pub struct TavCoseSign1 {
        inner: NativeCborValue,
    }

    pub struct TavCoseByteBuffer {
        bytes: Vec<u8>,
    }

    pub struct TavCoseError {
        code: TavCoseErrorCode,
        message: CString,
    }

    impl TavCoseError {
        fn new(code: TavCoseErrorCode, message: impl Into<String>) -> Self {
            Self {
                code,
                message: c_string(message.into()),
            }
        }

        fn invalid_argument(message: impl Into<String>) -> Self {
            Self::new(TavCoseErrorCode::InvalidArgument, message)
        }

        fn cbor(message: impl Into<String>) -> Self {
            Self::new(TavCoseErrorCode::Cbor, message)
        }

        fn unexpected_type(message: impl Into<String>) -> Self {
            Self::new(TavCoseErrorCode::UnexpectedType, message)
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

    impl TavCoseSign1 {
        fn as_native(&self) -> &NativeCborValue {
            &self.inner
        }

        fn borrowed(value: &NativeCborValue) -> *const Self {
            value as *const NativeCborValue as *const Self
        }
    }

    fn c_string(message: String) -> CString {
        CString::new(message.replace('\0', "\\0")).expect("NUL bytes were replaced")
    }

    fn into_error(error: TavCoseError) -> *mut TavCoseError {
        Box::into_raw(Box::new(error))
    }

    fn into_result(result: Result<(), TavCoseError>) -> *mut TavCoseError {
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
    ) -> Result<&'a [u8], TavCoseError> {
        if len == 0 {
            if allow_empty {
                return Ok(&[]);
            }
            return Err(TavCoseError::invalid_argument(format!("{name} is empty")));
        }
        if data.is_null() {
            return Err(TavCoseError::invalid_argument(format!(
                "{name} pointer is null"
            )));
        }
        if len > MAX_INPUT_LEN {
            return Err(TavCoseError::invalid_argument(format!(
                "{name} exceeds maximum input size"
            )));
        }
        Ok(unsafe { std::slice::from_raw_parts(data, len) })
    }

    unsafe fn input_text<'a>(
        data: *const c_char,
        len: usize,
        name: &str,
    ) -> Result<&'a str, TavCoseError> {
        let bytes = unsafe { input_bytes(data.cast(), len, name, true) }?;
        std::str::from_utf8(bytes).map_err(|error| {
            TavCoseError::invalid_argument(format!("{name} is not valid UTF-8: {error}"))
        })
    }

    unsafe fn out_ptr<T>(out: *mut T, name: &str) -> Result<(), TavCoseError> {
        if out.is_null() {
            return Err(TavCoseError::invalid_argument(format!(
                "{name} pointer is null"
            )));
        }
        Ok(())
    }

    unsafe fn owned_out_ptr<T>(out: *mut *mut T, name: &str) -> Result<(), TavCoseError> {
        unsafe { out_ptr(out, name) }?;
        unsafe {
            *out = ptr::null_mut();
        }
        Ok(())
    }

    unsafe fn borrowed_out_ptr<T>(out: *mut *const T, name: &str) -> Result<(), TavCoseError> {
        unsafe { out_ptr(out, name) }
    }

    unsafe fn cbor_value<'a>(
        value: *const TavCborValue,
        name: &str,
    ) -> Result<&'a NativeCborValue, TavCoseError> {
        if value.is_null() {
            return Err(TavCoseError::invalid_argument(format!("{name} is null")));
        }
        Ok(unsafe { (*value).as_native() })
    }

    unsafe fn cose_sign1_value<'a>(
        sign1: *const TavCoseSign1,
    ) -> Result<&'a NativeCborValue, TavCoseError> {
        if sign1.is_null() {
            return Err(TavCoseError::invalid_argument("sign1 is null"));
        }
        Ok(unsafe { (*sign1).as_native() })
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

    fn borrowed_bytes<'a>(
        value: &'a NativeCborValue,
        name: &str,
    ) -> Result<&'a [u8], TavCoseError> {
        match value {
            NativeCborValue::ByteString(bytes) => Ok(bytes),
            _ => Err(TavCoseError::unexpected_type(format!(
                "{name} must be a byte string"
            ))),
        }
    }

    fn protected_header(value: &NativeCborValue) -> Result<NativeCborValue, TavCoseError> {
        let protected = borrowed_bytes(value, "protected")?;
        if protected.is_empty() {
            return Ok(NativeCborValue::Map(vec![]));
        }
        NativeCborValue::from_bytes(protected).map_err(TavCoseError::cbor)
    }

    fn require_detached_payload(sign1: &NativeCborValue) -> Result<(), TavCoseError> {
        match sign1_field(sign1, 2, "payload")? {
            NativeCborValue::Simple(22) => Ok(()),
            NativeCborValue::ByteString(_) => Err(TavCoseError::unexpected_type(
                "detached payload verification requires nil COSE payload; use embedded verification for byte string payloads",
            )),
            _ => Err(TavCoseError::unexpected_type(
                "detached payload verification requires nil COSE payload",
            )),
        }
    }

    fn sign1_field<'a>(
        sign1: &'a NativeCborValue,
        index: usize,
        name: &str,
    ) -> Result<&'a NativeCborValue, TavCoseError> {
        sign1
            .array_at(index)
            .map_err(|error| TavCoseError::cbor(format!("Failed to read {name}: {error}")))
    }

    fn map_entry_at(
        value: &NativeCborValue,
        index: usize,
    ) -> Result<(&NativeCborValue, &NativeCborValue), TavCoseError> {
        match value {
            NativeCborValue::Map(entries) => entries
                .get(index)
                .map(|(key, value)| (key, value))
                .ok_or_else(|| TavCoseError::cbor(format!("Index {index} out of bounds"))),
            _ => Err(TavCoseError::unexpected_type("value must be a map")),
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_from_bytes(
        bytes: *const u8,
        len: usize,
        out_value: *mut *mut TavCborValue,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { owned_out_ptr(out_value, "out_value") }?;
            let bytes = unsafe { input_bytes(bytes, len, "CBOR bytes", false) }?;
            let value = NativeCborValue::from_bytes(bytes).map_err(TavCoseError::cbor)?;
            unsafe {
                *out_value = Box::into_raw(Box::new(TavCborValue::from_native(value)));
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_to_bytes(
        value: *const TavCborValue,
        out_bytes: *mut *mut TavCoseByteBuffer,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { owned_out_ptr(out_bytes, "out_bytes") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let bytes = value.to_bytes().map_err(TavCoseError::cbor)?;
            unsafe {
                *out_bytes = Box::into_raw(Box::new(TavCoseByteBuffer { bytes }));
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let int = match value {
                NativeCborValue::Int(value) => *value,
                _ => return Err(TavCoseError::unexpected_type("value must be an int")),
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let simple = match value {
                NativeCborValue::Simple(value) => *value,
                _ => return Err(TavCoseError::unexpected_type("value must be simple")),
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
    ) -> *mut TavCoseError {
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe {
                borrowed_out_ptr(text, "text")?;
                out_ptr(len, "len")?;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let value = match value {
                NativeCborValue::TextString(value) => value.as_bytes(),
                _ => return Err(TavCoseError::unexpected_type("value must be text")),
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let tag = match value {
                NativeCborValue::Tagged { tag, .. } => *tag,
                _ => return Err(TavCoseError::unexpected_type("value must be tagged")),
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let payload = match value {
                NativeCborValue::Tagged { payload, .. } => payload.as_ref(),
                _ => return Err(TavCoseError::unexpected_type("value must be tagged")),
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let value_len = value.len().map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let child = value.array_at(index).map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let child = value.map_at_int(key).map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let key = unsafe { input_text(key, key_len, "key") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let child = value.map_at_str(key).map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let key = unsafe { cbor_value(key, "key") }?;
            let child = value.map_at(key).map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            unsafe {
                *out = false;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let has_key = value.map_has_int_key(key).map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            unsafe {
                *out = false;
            }
            let key = unsafe { input_text(key, key_len, "key") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let has_key = value.map_has_str_key(key).map_err(TavCoseError::cbor)?;
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
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { out_ptr(out, "out") }?;
            unsafe {
                *out = false;
            }
            let value = unsafe { cbor_value(value, "value") }?;
            let key = unsafe { cbor_value(key, "key") }?;
            let has_key = value.map_has_key(key).map_err(TavCoseError::cbor)?;
            unsafe {
                *out = has_key;
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_key_at(
        value: *const TavCborValue,
        index: usize,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let (key, _) = map_entry_at(value, index)?;
            unsafe {
                *out_value = TavCborValue::borrowed(key);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_map_value_at(
        value: *const TavCborValue,
        index: usize,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let (_, child) = map_entry_at(value, index)?;
            unsafe {
                *out_value = TavCborValue::borrowed(child);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cbor_value_as_cose_sign1(
        value: *const TavCborValue,
        out_sign1: *mut *const TavCoseSign1,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_sign1, "out_sign1") }?;
            let value = unsafe { cbor_value(value, "value") }?;
            let sign1 = cose_sign1(value).map_err(TavCoseError::cbor)?;
            unsafe {
                *out_sign1 = TavCoseSign1::borrowed(sign1);
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
    pub unsafe extern "C" fn tav_cose_byte_buffer_data(
        bytes: *const TavCoseByteBuffer,
        data: *mut *const u8,
        len: *mut usize,
    ) {
        if !data.is_null() {
            unsafe {
                *data = ptr::null();
            }
        }
        if !len.is_null() {
            unsafe {
                *len = 0;
            }
        }
        if bytes.is_null() || data.is_null() || len.is_null() {
            return;
        }

        let bytes = unsafe { &*bytes };
        unsafe {
            *data = bytes.bytes.as_ptr();
            *len = bytes.bytes.len();
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_byte_buffer_free(bytes: *mut TavCoseByteBuffer) {
        if !bytes.is_null() {
            unsafe {
                drop(Box::from_raw(bytes));
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_protected(
        sign1: *const TavCoseSign1,
        data: *mut *const u8,
        len: *mut usize,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe {
                borrowed_out_ptr(data, "data")?;
                out_ptr(len, "len")?;
            }
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
            let protected = borrowed_bytes(sign1_field(sign1, 0, "protected")?, "protected")?;
            unsafe {
                *data = protected.as_ptr();
                *len = protected.len();
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_unprotected(
        sign1: *const TavCoseSign1,
        out_value: *mut *const TavCborValue,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { borrowed_out_ptr(out_value, "out_value") }?;
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
            let unprotected = sign1_field(sign1, 1, "unprotected")?;
            unsafe {
                *out_value = TavCborValue::borrowed(unprotected);
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_payload(
        sign1: *const TavCoseSign1,
        data: *mut *const u8,
        len: *mut usize,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe {
                borrowed_out_ptr(data, "data")?;
                out_ptr(len, "len")?;
            }
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
            let payload = borrowed_bytes(sign1_field(sign1, 2, "payload")?, "payload")?;
            unsafe {
                *data = payload.as_ptr();
                *len = payload.len();
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_signature(
        sign1: *const TavCoseSign1,
        data: *mut *const u8,
        len: *mut usize,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe {
                borrowed_out_ptr(data, "data")?;
                out_ptr(len, "len")?;
            }
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
            let signature = borrowed_bytes(sign1_field(sign1, 3, "signature")?, "signature")?;
            unsafe {
                *data = signature.as_ptr();
                *len = signature.len();
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_protected_header(
        sign1: *const TavCoseSign1,
        out_value: *mut *mut TavCborValue,
    ) -> *mut TavCoseError {
        into_result((|| {
            unsafe { owned_out_ptr(out_value, "out_value") }?;
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
            let protected = protected_header(sign1_field(sign1, 0, "protected")?)?;
            unsafe {
                *out_value = Box::into_raw(Box::new(TavCborValue::from_native(protected)));
            }
            Ok(())
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_verify_embedded(
        sign1: *const TavCoseSign1,
        spki_der: *const u8,
        spki_der_len: usize,
        cose_alg: i32,
    ) -> *mut TavCoseError {
        into_result((|| {
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
            let payload = borrowed_bytes(sign1_field(sign1, 2, "payload")?, "payload")?;
            verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
        })())
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_sign1_verify_detached(
        sign1: *const TavCoseSign1,
        payload: *const u8,
        payload_len: usize,
        spki_der: *const u8,
        spki_der_len: usize,
        cose_alg: i32,
    ) -> *mut TavCoseError {
        into_result((|| {
            let sign1 = unsafe { cose_sign1_value(sign1) }?;
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
    ) -> Result<(), TavCoseError> {
        let protected = borrowed_bytes(sign1_field(sign1, 0, "protected")?, "protected")?;
        let signature = borrowed_bytes(sign1_field(sign1, 3, "signature")?, "signature")?;
        let spki_der = unsafe { input_bytes(spki_der, spki_der_len, "SPKI DER", false) }?;
        let algorithm = signature_key_algorithm_for_cose_alg(cose_alg as i64)
            .map_err(|error| TavCoseError::new(TavCoseErrorCode::UnsupportedAlgorithm, error))?;
        let key = <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(
            spki_der, algorithm,
        )
        .map_err(|error| TavCoseError::new(TavCoseErrorCode::KeyImport, error.to_string()))?;
        crate::synchronous::cose_verify1(&key, algorithm, protected, payload, signature)
            .map_err(|error| TavCoseError::new(TavCoseErrorCode::Verification, error))
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_error_code(error: *const TavCoseError) -> TavCoseErrorCode {
        if error.is_null() {
            return TavCoseErrorCode::ErrorIsNull;
        }

        unsafe { (*error).code }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_error_message(error: *const TavCoseError) -> *const c_char {
        if error.is_null() {
            return NULL_ERROR_MESSAGE.as_ptr().cast();
        }

        unsafe { (*error).message.as_ptr() }
    }

    #[no_mangle]
    pub unsafe extern "C" fn tav_cose_error_free(error: *mut TavCoseError) {
        if !error.is_null() {
            unsafe {
                drop(Box::from_raw(error));
            }
        }
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
            let header = include_str!("../../include/tav/cose.h");

            for (name, value) in [
                ("TAV_COSE_ERROR_OK", TavCoseErrorCode::Ok as i32),
                (
                    "TAV_COSE_ERROR_INVALID_ARGUMENT",
                    TavCoseErrorCode::InvalidArgument as i32,
                ),
                (
                    "TAV_COSE_ERROR_ERROR_IS_NULL",
                    TavCoseErrorCode::ErrorIsNull as i32,
                ),
                ("TAV_COSE_ERROR_CBOR", TavCoseErrorCode::Cbor as i32),
                (
                    "TAV_COSE_ERROR_UNEXPECTED_TYPE",
                    TavCoseErrorCode::UnexpectedType as i32,
                ),
                (
                    "TAV_COSE_ERROR_UNSUPPORTED_ALGORITHM",
                    TavCoseErrorCode::UnsupportedAlgorithm as i32,
                ),
                (
                    "TAV_COSE_ERROR_KEY_IMPORT",
                    TavCoseErrorCode::KeyImport as i32,
                ),
                (
                    "TAV_COSE_ERROR_VERIFICATION",
                    TavCoseErrorCode::Verification as i32,
                ),
                ("TAV_CBOR_KIND_INT", TavCborKind::Int as i32),
                ("TAV_CBOR_KIND_SIMPLE", TavCborKind::Simple as i32),
                ("TAV_CBOR_KIND_BYTES", TavCborKind::Bytes as i32),
                ("TAV_CBOR_KIND_TEXT", TavCborKind::Text as i32),
                ("TAV_CBOR_KIND_ARRAY", TavCborKind::Array as i32),
                ("TAV_CBOR_KIND_MAP", TavCborKind::Map as i32),
                ("TAV_CBOR_KIND_TAGGED", TavCborKind::Tagged as i32),
            ] {
                assert_eq!(
                    c_header_enum_value(header, name),
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
                0xa2, 0x01, 0x63, b'o', b'n', b'e', 0x63, b'k', b'e', b'y', 0x18, 0x2a,
            ];
            let mut root = ptr::null_mut();
            let err = unsafe { tav_cbor_value_from_bytes(cbor.as_ptr(), cbor.len(), &mut root) };
            assert!(err.is_null());

            let mut key = ptr::null();
            let err = unsafe { tav_cbor_value_map_key_at(root, 0, &mut key) };
            assert!(err.is_null());

            let mut value = ptr::null();
            let err = unsafe { tav_cbor_value_map_at(root, key, &mut value) };
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

            unsafe { tav_cbor_value_free(root) };
        }

        #[test]
        fn owned_out_parameters_are_write_only() {
            let cbor = [0x81, 0x01];
            let mut root = ptr::NonNull::<TavCborValue>::dangling().as_ptr();
            let err = unsafe { tav_cbor_value_from_bytes(cbor.as_ptr(), cbor.len(), &mut root) };
            assert!(err.is_null());
            assert!(!root.is_null());

            let mut bytes = ptr::NonNull::<TavCoseByteBuffer>::dangling().as_ptr();
            let err = unsafe { tav_cbor_value_to_bytes(root, &mut bytes) };
            assert!(err.is_null());
            assert!(!bytes.is_null());

            unsafe {
                tav_cose_byte_buffer_free(bytes);
                tav_cbor_value_free(root);
            }
        }

        #[test]
        fn byte_buffer_data_is_defensive_for_null_pointers() {
            let mut data = ptr::NonNull::<u8>::dangling().as_ptr().cast_const();
            let mut len = 42;
            unsafe { tav_cose_byte_buffer_data(ptr::null(), &mut data, &mut len) };
            assert!(data.is_null());
            assert_eq!(len, 0);

            unsafe { tav_cose_byte_buffer_data(ptr::null(), ptr::null_mut(), &mut len) };
            assert_eq!(len, 0);
            unsafe { tav_cose_byte_buffer_data(ptr::null(), &mut data, ptr::null_mut()) };
            assert!(data.is_null());
        }

        #[test]
        fn cose_sign1_protected_header_accepts_empty_protected_bytes() {
            let envelope = NativeCborValue::Tagged {
                tag: 18,
                payload: Box::new(NativeCborValue::Array(vec![
                    NativeCborValue::ByteString(vec![]),
                    NativeCborValue::Map(vec![]),
                    NativeCborValue::ByteString(vec![]),
                    NativeCborValue::ByteString(vec![]),
                ])),
            }
            .to_bytes()
            .unwrap();

            let mut root = ptr::null_mut();
            let err =
                unsafe { tav_cbor_value_from_bytes(envelope.as_ptr(), envelope.len(), &mut root) };
            assert!(err.is_null());

            let mut sign1 = ptr::null();
            let err = unsafe { tav_cbor_value_as_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());

            let mut protected = ptr::null_mut();
            let err = unsafe { tav_cose_sign1_protected_header(sign1, &mut protected) };
            assert!(err.is_null());
            assert_eq!(unsafe { tav_cbor_value_kind(protected) }, TavCborKind::Map);

            let mut len = usize::MAX;
            let err = unsafe { tav_cbor_value_len(protected, &mut len) };
            assert!(err.is_null());
            assert_eq!(len, 0);

            unsafe {
                tav_cbor_value_free(protected);
                tav_cbor_value_free(root);
            }
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
            let err = unsafe { tav_cbor_value_as_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());
            assert!(!sign1.is_null());

            let err = unsafe {
                tav_cose_sign1_verify_embedded(sign1, P256_SPKI.as_ptr(), P256_SPKI.len(), -7)
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
            let err = unsafe { tav_cbor_value_as_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());

            let err = unsafe {
                tav_cose_sign1_verify_detached(
                    sign1,
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                    P256_SPKI.as_ptr(),
                    P256_SPKI.len(),
                    -7,
                )
            };
            assert_eq!(
                unsafe { tav_cose_error_code(err) },
                TavCoseErrorCode::UnexpectedType
            );
            assert!(
                unsafe { std::ffi::CStr::from_ptr(tav_cose_error_message(err)) }
                    .to_str()
                    .unwrap()
                    .contains("requires nil COSE payload")
            );

            unsafe {
                tav_cose_error_free(err);
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
                    NativeCborValue::Simple(22),
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
            let err = unsafe { tav_cbor_value_as_cose_sign1(root, &mut sign1) };
            assert!(err.is_null());

            let err = unsafe {
                tav_cose_sign1_verify_detached(
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
                unsafe { tav_cose_error_code(ptr::null()) },
                TavCoseErrorCode::ErrorIsNull
            );
            let message = unsafe { tav_cose_error_message(ptr::null()) };
            assert_eq!(
                unsafe { std::ffi::CStr::from_ptr(message) }
                    .to_str()
                    .unwrap(),
                "null TAVCoseError pointer"
            );
        }

        fn c_header_enum_value(header: &str, name: &str) -> Option<i32> {
            let line = header
                .lines()
                .find(|line| line.trim_start().starts_with(name))?;
            line.split('=')
                .nth(1)?
                .trim()
                .trim_end_matches(',')
                .parse()
                .ok()
        }
    }
}
