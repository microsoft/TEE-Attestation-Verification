// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI bindings for CBOR navigation and COSE_Sign1 verification.
//!
//! This module exports the symbols declared in `ffi/include/tav/cose.h`.
//!
//! `TavCborValue` handles returned by [`tav_cbor_value_from_bytes`] are
//! owned and must be released with [`tav_cbor_value_free`]. Existing child
//! accessors return borrowed handles into the owned root.
//! [`tav_cbor_value_to_owned`] converts any live handle to an independently
//! owned handle backed by the same immutable CBOR document.

use std::marker::PhantomData;
use std::os::raw::c_char;
use std::rc::Rc;
use std::sync::Mutex;

use super::utils::{input_bytes, input_text, out_ptr, owned_out_ptr, TavByteBuffer};
use crate::cbor_view::CborView;
use crate::{into_result, TavError, TavErrorCode};
use std::ptr;

use crypto::{CryptoBackend, KeyBackend};

use cose::{cose_sign1, signature_key_algorithm_for_cose_alg, CborValue as NativeCborValue};

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

enum HandleState {
    Owned(CborView),
    Borrowed {
        parent: *const TavCborValue,
        node: *const NativeCborValue,
    },
}

/// An opaque C handle with owned-or-borrowed `Cow`-style storage.
///
/// Every handle is allocated in a `Box`. An owned handle keeps the immutable
/// CBOR document alive through `CborView`; a borrowed handle points to its
/// parent handle and to a node in that same document. Borrowed children are
/// stored in their direct parent's `children` arena, so both the child and
/// parent `Box` addresses remain stable until the owned ancestor is freed.
/// Traversing the parent chain therefore reaches a live owning `CborView` for
/// every handle used within the released C lifetime contract.
///
/// The document is never exposed mutably, so node pointers cannot be
/// invalidated while the owning `Arc` lives. `children` is declared before
/// `state`, so descendants are recursively dropped before an owned view releases
/// that `Arc`. `_not_send_sync` prevents Rust auto-traits from promising
/// cross-thread use for these raw-pointer handles.
pub struct TavCborValue {
    children: Mutex<Vec<Box<TavCborValue>>>,
    state: HandleState,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl TavCborValue {
    fn from_native(value: NativeCborValue) -> *mut Self {
        Self::owned_raw(CborView::new(value))
    }

    pub(super) fn as_native(&self) -> &NativeCborValue {
        match &self.state {
            HandleState::Owned(view) => view.as_native(),
            HandleState::Borrowed { node, .. } => {
                // SAFETY: borrowed nodes come only from immutable projections
                // of the parent node. The child is owned by that parent's arena,
                // and the released C contract keeps the ancestor chain alive
                // whenever this handle is used.
                unsafe { &**node }
            }
        }
    }

    fn owned_raw(view: CborView) -> *mut Self {
        Box::into_raw(Box::new(Self {
            children: Mutex::new(Vec::new()),
            state: HandleState::Owned(view),
            _not_send_sync: PhantomData,
        }))
    }

    fn borrowed<E>(
        &self,
        project: impl for<'a> FnOnce(&'a NativeCborValue) -> Result<&'a NativeCborValue, E>,
    ) -> Result<*const Self, E> {
        project(self.as_native()).map(|node| self.store_borrowed(node))
    }

    fn store_borrowed(&self, node: &NativeCborValue) -> *const Self {
        let child = Box::new(Self {
            children: Mutex::new(Vec::new()),
            state: HandleState::Borrowed { parent: self, node },
            _not_send_sync: PhantomData,
        });
        let child_ptr = child.as_ref() as *const Self;
        self.children.lock().unwrap().push(child);
        child_ptr
    }

    fn to_owned(&self) -> *mut Self {
        // SAFETY: `node_ptr` is either the owning view's selected node or an
        // immutable projection from a live parent in the same document.
        let view = unsafe { self.owning_view().clone_at(self.node_ptr()) };
        Self::owned_raw(view)
    }

    fn is_owned(&self) -> bool {
        matches!(self.state, HandleState::Owned(_))
    }

    fn node_ptr(&self) -> *const NativeCborValue {
        match &self.state {
            HandleState::Owned(view) => view.node_ptr(),
            HandleState::Borrowed { node, .. } => *node,
        }
    }

    fn owning_view(&self) -> &CborView {
        let mut handle = self;
        loop {
            match &handle.state {
                HandleState::Owned(view) => return view,
                HandleState::Borrowed { parent, .. } => {
                    // SAFETY: each borrowed handle is stored in its parent's
                    // arena, and callers must keep the owned ancestor alive.
                    handle = unsafe { &**parent };
                }
            }
        }
    }

    #[cfg(test)]
    fn document_ptr(&self) -> *const NativeCborValue {
        self.owning_view().document_ptr()
    }

    #[cfg(test)]
    fn document_strong_count(&self) -> usize {
        self.owning_view().document_strong_count()
    }
}

unsafe fn scalar_out_ptr<T: Default>(out: *mut T, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = T::default();
    }
    Ok(())
}

unsafe fn borrowed_out_ptr<T>(out: *mut *const T, name: &str) -> Result<(), TavError> {
    unsafe { out_ptr(out, name) }?;
    unsafe {
        *out = ptr::null();
    }
    Ok(())
}

unsafe fn cbor_value<'a>(
    value: *const TavCborValue,
    name: &str,
) -> Result<&'a NativeCborValue, TavError> {
    Ok(unsafe { cbor_handle(value, name) }?.as_native())
}

unsafe fn cbor_handle<'a>(
    value: *const TavCborValue,
    name: &str,
) -> Result<&'a TavCborValue, TavError> {
    if value.is_null() {
        return Err(TavError::invalid_argument(format!("{name} is null")));
    }
    Ok(unsafe { &*value })
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
        _ => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            format!("{name} must be a byte string"),
        )),
    }
}

fn require_detached_payload(sign1: &NativeCborValue) -> Result<(), TavError> {
    match sign1_field(sign1, 2, "payload")? {
        NativeCborValue::Simple(22) => Ok(()),
        NativeCborValue::ByteString(_) => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            "detached payload verification requires nil COSE payload; use embedded verification for byte string payloads",
        )),
        _ => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            "detached payload verification requires nil COSE payload",
        )),
    }
}

fn sign1_field<'a>(
    sign1: &'a NativeCborValue,
    index: usize,
    name: &str,
) -> Result<&'a NativeCborValue, TavError> {
    sign1.array_at(index).map_err(|error| {
        TavError::new(
            TavErrorCode::CoseCbor,
            format!("Failed to read {name}: {error}"),
        )
    })
}

fn map_entry_at(
    value: &NativeCborValue,
    index: usize,
) -> Result<(&NativeCborValue, &NativeCborValue), TavError> {
    match value {
        NativeCborValue::Map(entries) => entries
            .get(index)
            .map(|(key, value)| (key, value))
            .ok_or_else(|| {
                TavError::new(
                    TavErrorCode::CoseCbor,
                    format!("Index {index} out of bounds"),
                )
            }),
        _ => Err(TavError::new(
            TavErrorCode::CoseUnexpectedType,
            "value must be a map",
        )),
    }
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_from_bytes(
    bytes: *const u8,
    len: usize,
    out_value: *mut *mut TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_value, "out_value") }?;
        let bytes = unsafe { input_bytes(bytes, len, "CBOR bytes", false) }?;
        let value = NativeCborValue::from_bytes(bytes)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_value = TavCborValue::from_native(value);
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_to_owned(
    value: *const TavCborValue,
    out_owned: *mut *mut TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_owned, "out_owned") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        unsafe {
            *out_owned = handle.to_owned();
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_to_bytes(
    value: *const TavCborValue,
    out_bytes: *mut *mut TavByteBuffer,
) -> *mut TavError {
    into_result(|| {
        unsafe { owned_out_ptr(out_bytes, "out_bytes") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let bytes = value
            .to_bytes()
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out_bytes = Box::into_raw(TavByteBuffer::from_bytes(bytes));
        }
        Ok(())
    })
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
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let int = match value {
            NativeCborValue::Int(value) => *value,
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be an int",
                ))
            }
        };
        unsafe {
            *out = int;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_simple(
    value: *const TavCborValue,
    out: *mut u8,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let simple = match value {
            NativeCborValue::Simple(value) => *value,
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be simple",
                ))
            }
        };
        unsafe {
            *out = simple;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_bytes(
    value: *const TavCborValue,
    data: *mut *const u8,
    len: *mut usize,
) -> *mut TavError {
    into_result(|| {
        unsafe {
            borrowed_out_ptr(data, "data")?;
            scalar_out_ptr(len, "len")?;
        }
        let value = unsafe { cbor_value(value, "value") }?;
        let bytes = borrowed_bytes(value, "value")?;
        unsafe {
            *data = bytes.as_ptr();
            *len = bytes.len();
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_text(
    value: *const TavCborValue,
    text: *mut *const c_char,
    len: *mut usize,
) -> *mut TavError {
    into_result(|| {
        unsafe {
            borrowed_out_ptr(text, "text")?;
            scalar_out_ptr(len, "len")?;
        }
        let value = unsafe { cbor_value(value, "value") }?;
        let value = match value {
            NativeCborValue::TextString(value) => value.as_bytes(),
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be text",
                ))
            }
        };
        unsafe {
            *text = value.as_ptr().cast();
            *len = value.len();
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_tag(
    value: *const TavCborValue,
    out: *mut u64,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let tag = match value {
            NativeCborValue::Tagged { tag, .. } => *tag,
            _ => {
                return Err(TavError::new(
                    TavErrorCode::CoseUnexpectedType,
                    "value must be tagged",
                ))
            }
        };
        unsafe {
            *out = tag;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_tagged_payload(
    value: *const TavCborValue,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let payload = handle.borrowed(|value| match value {
            NativeCborValue::Tagged { payload, .. } => Ok(payload.as_ref()),
            _ => Err(TavError::new(
                TavErrorCode::CoseUnexpectedType,
                "value must be tagged",
            )),
        })?;
        unsafe {
            *out_value = payload;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_len(
    value: *const TavCborValue,
    out: *mut usize,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let value_len = value
            .len()
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = value_len;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_array_at(
    value: *const TavCborValue,
    index: usize,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let child = handle.borrowed(|value| {
            value
                .array_at(index)
                .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))
        })?;
        unsafe {
            *out_value = child;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_at_int(
    value: *const TavCborValue,
    key: i64,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let child = handle.borrowed(|value| {
            value
                .map_at_int(key)
                .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))
        })?;
        unsafe {
            *out_value = child;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_at_text(
    value: *const TavCborValue,
    key: *const c_char,
    key_len: usize,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let key = unsafe { input_text(key, key_len, "key", true) }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let child = handle.borrowed(|value| {
            value
                .map_at_str(key)
                .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))
        })?;
        unsafe {
            *out_value = child;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_at(
    value: *const TavCborValue,
    key: *const TavCborValue,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let key = unsafe { cbor_value(key, "key") }?;
        let child = handle.borrowed(|value| {
            value
                .map_at(key)
                .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))
        })?;
        unsafe {
            *out_value = child;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_has_int_key(
    value: *const TavCborValue,
    key: i64,
    out: *mut bool,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let has_key = value
            .map_has_int_key(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = has_key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_has_text_key(
    value: *const TavCborValue,
    key: *const c_char,
    key_len: usize,
    out: *mut bool,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let key = unsafe { input_text(key, key_len, "key", true) }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let has_key = value
            .map_has_str_key(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = has_key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_has_key(
    value: *const TavCborValue,
    key: *const TavCborValue,
    out: *mut bool,
) -> *mut TavError {
    into_result(|| {
        unsafe { scalar_out_ptr(out, "out") }?;
        let value = unsafe { cbor_value(value, "value") }?;
        let key = unsafe { cbor_value(key, "key") }?;
        let has_key = value
            .map_has_key(key)
            .map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        unsafe {
            *out = has_key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_entry_at(
    value: *const TavCborValue,
    index: usize,
    out_key: *mut *const TavCborValue,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_key, "out_key") }?;
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let (key, child) = map_entry_at(handle.as_native(), index)?;
        let key = handle.store_borrowed(key);
        let child = handle.store_borrowed(child);
        unsafe {
            *out_key = key;
            *out_value = child;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_key_at(
    value: *const TavCborValue,
    index: usize,
    out_key: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_key, "out_key") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let key = handle.borrowed(|value| map_entry_at(value, index).map(|(key, _)| key))?;
        unsafe {
            *out_key = key;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_map_value_at(
    value: *const TavCborValue,
    index: usize,
    out_value: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_value, "out_value") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let child = handle.borrowed(|value| map_entry_at(value, index).map(|(_, child)| child))?;
        unsafe {
            *out_value = child;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_validate_cose_sign1(
    value: *const TavCborValue,
    out_sign1: *mut *const TavCborValue,
) -> *mut TavError {
    into_result(|| {
        unsafe { borrowed_out_ptr(out_sign1, "out_sign1") }?;
        let handle = unsafe { cbor_handle(value, "value") }?;
        let sign1 = handle.borrowed(|value| {
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))
        })?;
        unsafe {
            *out_sign1 = sign1;
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn tav_cbor_value_free(value: *mut TavCborValue) {
    if !value.is_null() && unsafe { (*value).is_owned() } {
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
    into_result(|| {
        let value = unsafe { cbor_value(sign1, "sign1") }?;
        let sign1 =
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        let payload = borrowed_bytes(sign1_field(sign1, 2, "payload")?, "payload")?;
        verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
    })
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
    into_result(|| {
        let value = unsafe { cbor_value(sign1, "sign1") }?;
        let sign1 =
            cose_sign1(value).map_err(|error| TavError::new(TavErrorCode::CoseCbor, error))?;
        require_detached_payload(sign1)?;
        let payload = unsafe { input_bytes(payload, payload_len, "payload", true) }?;
        verify_sign1(sign1, payload, spki_der, spki_der_len, cose_alg)
    })
}

fn verify_sign1(
    sign1: &NativeCborValue,
    payload: &[u8],
    spki_der: *const u8,
    spki_der_len: usize,
    cose_alg: i32,
) -> Result<(), TavError> {
    let protected = borrowed_bytes(sign1_field(sign1, 0, "protected")?, "protected")?;
    let signature = borrowed_bytes(sign1_field(sign1, 3, "signature")?, "signature")?;
    let spki_der = unsafe { input_bytes(spki_der, spki_der_len, "SPKI DER", false) }?;
    let algorithm = signature_key_algorithm_for_cose_alg(cose_alg as i64)
        .map_err(|error| TavError::new(TavErrorCode::CoseUnsupportedAlgorithm, error))?;
    let key =
        <<crypto::Crypto as CryptoBackend>::Key as KeyBackend>::from_spki_der(spki_der, algorithm)
            .map_err(|error| TavError::new(TavErrorCode::CoseKeyImport, error.to_string()))?;
    cose::synchronous::cose_verify1(&key, algorithm, protected, payload, signature)
        .map_err(|error| TavError::new(TavErrorCode::CoseVerification, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_header_enums_match_rust_enums() {
        let header = include_str!("../../include/tav/cose.h");

        for (name, value) in [
            ("TAV_CBOR_KIND_INT", TavCborKind::Int as i32),
            ("TAV_CBOR_KIND_SIMPLE", TavCborKind::Simple as i32),
            ("TAV_CBOR_KIND_BYTES", TavCborKind::Bytes as i32),
            ("TAV_CBOR_KIND_TEXT", TavCborKind::Text as i32),
            ("TAV_CBOR_KIND_ARRAY", TavCborKind::Array as i32),
            ("TAV_CBOR_KIND_MAP", TavCborKind::Map as i32),
            ("TAV_CBOR_KIND_TAGGED", TavCborKind::Tagged as i32),
            ("TAV_COSE_TAG_SIGN1", cose::COSE_SIGN1_TAG as i32),
            (
                "TAV_COSE_SIGN1_PROTECTED",
                cose::COSE_SIGN1_PROTECTED as i32,
            ),
            (
                "TAV_COSE_SIGN1_UNPROTECTED",
                cose::COSE_SIGN1_UNPROTECTED as i32,
            ),
            ("TAV_COSE_SIGN1_PAYLOAD", cose::COSE_SIGN1_PAYLOAD as i32),
            (
                "TAV_COSE_SIGN1_SIGNATURE",
                cose::COSE_SIGN1_SIGNATURE as i32,
            ),
            ("TAV_COSE_HEADER_ALG", cose::COSE_HEADER_ALG as i32),
            (
                "TAV_COSE_HEADER_CWT_CLAIMS",
                cose::COSE_HEADER_CWT_CLAIMS as i32,
            ),
            ("TAV_COSE_HEADER_X5CHAIN", cose::COSE_HEADER_X5CHAIN as i32),
            (
                "TAV_COSE_HEADER_CONTENT_TYPE",
                cose::COSE_HEADER_CONTENT_TYPE as i32,
            ),
            (
                "TAV_COSE_HEADER_PREIMAGE_CONTENT_TYPE",
                cose::COSE_HEADER_PREIMAGE_CONTENT_TYPE as i32,
            ),
            ("TAV_CWT_CLAIMS_ISSUER", cose::CWT_CLAIMS_ISSUER as i32),
            ("TAV_CWT_CLAIMS_SUBJECT", cose::CWT_CLAIMS_SUBJECT as i32),
            ("TAV_CWT_CLAIMS_IAT", cose::CWT_CLAIMS_IAT as i32),
        ] {
            assert_eq!(
                c_header_enum_value(header, name),
                Some(value),
                "{name} in ffi/include/tav/cose.h must match Rust"
            );
        }
    }

    #[test]
    fn borrowed_navigation_does_not_retain_the_document() {
        unsafe {
            let root = TavCborValue::from_native(NativeCborValue::Array(vec![
                NativeCborValue::Array(vec![NativeCborValue::Int(42)]),
                NativeCborValue::Map(vec![(
                    NativeCborValue::Int(1),
                    NativeCborValue::TextString("value".into()),
                )]),
                NativeCborValue::Tagged {
                    tag: cose::COSE_SIGN1_TAG,
                    payload: Box::new(NativeCborValue::Array(vec![
                        NativeCborValue::ByteString(vec![]),
                        NativeCborValue::Map(vec![]),
                        NativeCborValue::Simple(22),
                        NativeCborValue::ByteString(vec![]),
                    ])),
                },
            ]));
            assert_eq!((*root).document_strong_count(), 1);

            let mut array = ptr::null();
            assert!(tav_cbor_value_array_at(root, 0, &mut array).is_null());
            let mut nested = ptr::null();
            assert!(tav_cbor_value_array_at(array, 0, &mut nested).is_null());
            assert_eq!((*root).document_strong_count(), 1);

            let mut map = ptr::null();
            assert!(tav_cbor_value_array_at(root, 1, &mut map).is_null());
            let mut key = ptr::null();
            let mut value = ptr::null();
            assert!(tav_cbor_value_map_entry_at(map, 0, &mut key, &mut value).is_null());
            assert_eq!((*root).document_strong_count(), 1);

            let mut tagged = ptr::null();
            assert!(tav_cbor_value_array_at(root, 2, &mut tagged).is_null());
            let mut sign1 = ptr::null();
            assert!(tav_validate_cose_sign1(tagged, &mut sign1).is_null());
            assert_eq!((*root).document_strong_count(), 1);

            let mut int = 0;
            assert!(tav_cbor_value_int(nested, &mut int).is_null());
            assert_eq!(int, 42);
            assert!(tav_cbor_value_int(key, &mut int).is_null());
            assert_eq!(int, 1);
            let mut text = ptr::null();
            let mut text_len = 0;
            assert!(tav_cbor_value_text(value, &mut text, &mut text_len).is_null());
            assert_eq!(
                std::slice::from_raw_parts(text.cast::<u8>(), text_len),
                b"value"
            );
            assert_eq!(tav_cbor_value_kind(sign1), TavCborKind::Array);

            tav_cbor_value_free(root);
        }
    }

    #[test]
    fn to_owned_clones_one_arc_and_retains_every_handle_state() {
        unsafe {
            let root = TavCborValue::from_native(NativeCborValue::Array(vec![
                NativeCborValue::Array(vec![NativeCborValue::Int(42)]),
                NativeCborValue::Map(vec![(
                    NativeCborValue::Int(7),
                    NativeCborValue::TextString("pair".into()),
                )]),
                NativeCborValue::Tagged {
                    tag: cose::COSE_SIGN1_TAG,
                    payload: Box::new(NativeCborValue::Array(vec![
                        NativeCborValue::ByteString(vec![]),
                        NativeCborValue::Map(vec![]),
                        NativeCborValue::Simple(22),
                        NativeCborValue::ByteString(vec![]),
                    ])),
                },
            ]));
            let document = (*root).document_ptr();
            assert_eq!((*root).document_strong_count(), 1);

            let mut borrowed_array = ptr::null();
            assert!(tav_cbor_value_array_at(root, 0, &mut borrowed_array).is_null());
            let mut borrowed_nested = ptr::null();
            assert!(tav_cbor_value_array_at(borrowed_array, 0, &mut borrowed_nested).is_null());
            let mut owned_nested = ptr::null_mut();
            assert!(tav_cbor_value_to_owned(borrowed_nested, &mut owned_nested).is_null());
            assert_eq!((*root).document_strong_count(), 2);
            assert_eq!((*owned_nested).document_ptr(), document);
            assert_eq!((*owned_nested).node_ptr(), (*borrowed_nested).node_ptr());

            let mut map = ptr::null();
            assert!(tav_cbor_value_array_at(root, 1, &mut map).is_null());
            let mut pair_key = ptr::null();
            let mut pair_value = ptr::null();
            assert!(tav_cbor_value_map_entry_at(map, 0, &mut pair_key, &mut pair_value).is_null());
            let mut owned_pair = ptr::null_mut();
            assert!(tav_cbor_value_to_owned(pair_value, &mut owned_pair).is_null());
            assert_eq!((*root).document_strong_count(), 3);
            assert_eq!((*owned_pair).document_ptr(), document);
            assert_eq!((*owned_pair).node_ptr(), (*pair_value).node_ptr());

            let mut tagged = ptr::null();
            assert!(tav_cbor_value_array_at(root, 2, &mut tagged).is_null());
            let mut borrowed_sign1 = ptr::null();
            assert!(tav_validate_cose_sign1(tagged, &mut borrowed_sign1).is_null());
            let mut owned_sign1 = ptr::null_mut();
            assert!(tav_cbor_value_to_owned(borrowed_sign1, &mut owned_sign1).is_null());
            assert_eq!((*root).document_strong_count(), 4);
            assert_eq!((*owned_sign1).document_ptr(), document);
            assert_eq!((*owned_sign1).node_ptr(), (*borrowed_sign1).node_ptr());

            let mut owned_root = ptr::null_mut();
            assert!(tav_cbor_value_to_owned(root, &mut owned_root).is_null());
            assert_eq!((*root).document_strong_count(), 5);
            assert_eq!((*owned_root).document_ptr(), document);
            assert_eq!((*owned_root).node_ptr(), (*root).node_ptr());

            let mut owned_again = ptr::null_mut();
            assert!(tav_cbor_value_to_owned(owned_nested, &mut owned_again).is_null());
            assert_eq!((*root).document_strong_count(), 6);
            assert_eq!((*owned_again).document_ptr(), document);
            assert_eq!((*owned_again).node_ptr(), (*owned_nested).node_ptr());

            tav_cbor_value_free(root);

            let mut value = 0;
            assert!(tav_cbor_value_int(owned_nested, &mut value).is_null());
            assert_eq!(value, 42);
            tav_cbor_value_free(owned_nested);

            assert!(tav_cbor_value_int(owned_again, &mut value).is_null());
            assert_eq!(value, 42);

            let mut text = ptr::null();
            let mut text_len = 0;
            assert!(tav_cbor_value_text(owned_pair, &mut text, &mut text_len).is_null());
            assert_eq!(
                std::slice::from_raw_parts(text.cast::<u8>(), text_len),
                b"pair"
            );
            assert_eq!(tav_cbor_value_kind(owned_sign1), TavCborKind::Array);

            let mut root_len = 0;
            assert!(tav_cbor_value_len(owned_root, &mut root_len).is_null());
            assert_eq!(root_len, 3);

            tav_cbor_value_free(owned_pair);
            tav_cbor_value_free(owned_sign1);
            tav_cbor_value_free(owned_again);
            tav_cbor_value_free(owned_root);
            tav_cbor_value_free(ptr::null_mut());
        }
    }

    #[test]
    fn to_owned_retains_validated_borrowed_cose_sign1() {
        unsafe {
            let bytes = [0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40];
            let mut root = ptr::null_mut();
            assert!(tav_cbor_value_from_bytes(bytes.as_ptr(), bytes.len(), &mut root).is_null());

            let mut borrowed_sign1 = ptr::null();
            assert!(tav_validate_cose_sign1(root, &mut borrowed_sign1).is_null());
            let mut owned_sign1 = ptr::null_mut();
            assert!(tav_cbor_value_to_owned(borrowed_sign1, &mut owned_sign1).is_null());
            tav_cbor_value_free(root);

            assert_eq!(tav_cbor_value_kind(owned_sign1), TavCborKind::Array);
            let mut len = 0;
            assert!(tav_cbor_value_len(owned_sign1, &mut len).is_null());
            assert_eq!(len, 4);
            tav_cbor_value_free(owned_sign1);
        }
    }

    #[test]
    fn to_owned_validates_and_clears_out_parameter() {
        unsafe {
            let mut owned = ptr::dangling_mut();
            let error = tav_cbor_value_to_owned(ptr::null(), &mut owned);
            assert!(!error.is_null());
            assert_eq!((*error).code(), TavErrorCode::InvalidArgument);
            assert!(owned.is_null());
            crate::c_ffi::utils::tav_error_free(error);

            let bytes = [0x01];
            let mut root = ptr::null_mut();
            assert!(tav_cbor_value_from_bytes(bytes.as_ptr(), bytes.len(), &mut root).is_null());
            let error = tav_cbor_value_to_owned(root, ptr::null_mut());
            assert!(!error.is_null());
            assert_eq!((*error).code(), TavErrorCode::InvalidArgument);
            crate::c_ffi::utils::tav_error_free(error);
            tav_cbor_value_free(root);
        }
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
