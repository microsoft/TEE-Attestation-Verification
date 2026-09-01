// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::cbor::*;
use std::ptr;

/// Serialize a handle, returning the encoded bytes.
fn encode_nondet(handle: *const TavCborHandle) -> Result<Vec<u8>, String> {
    encode(handle, MAX_DEPTH_LIMIT, false)
}

fn encode_det(handle: *const TavCborHandle) -> Result<Vec<u8>, String> {
    encode(handle, MAX_DEPTH_LIMIT, true)
}

fn encode(handle: *const TavCborHandle, max_depth: usize, det: bool) -> Result<Vec<u8>, String> {
    let (mut out, mut out_len) = (ptr::null_mut(), 0usize);
    let (mut err, mut err_len) = (ptr::null_mut(), 0usize);
    let status = unsafe {
        if det {
            tav_cbor_det_serialize(
                handle,
                max_depth,
                &mut out,
                &mut out_len,
                &mut err,
                &mut err_len,
            )
        } else {
            tav_cbor_nondet_serialize(
                handle,
                max_depth,
                &mut out,
                &mut out_len,
                &mut err,
                &mut err_len,
            )
        }
    };
    if status == STATUS_OK {
        let bytes = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
        unsafe { tav_cbor_buffer_free(out, out_len) };
        return Ok(bytes);
    }
    let message = unsafe { std::slice::from_raw_parts(err, err_len) };
    let message = String::from_utf8_lossy(message).into_owned();
    unsafe { tav_cbor_buffer_free(err, err_len) };
    Err(message)
}

/// Parse bytes, returning an owning handle.
fn decode(bytes: &[u8], max_depth: usize, det: bool) -> Result<*mut TavCborHandle, String> {
    let mut value: *mut TavCborHandle = ptr::null_mut();
    let (mut err, mut err_len) = (ptr::null_mut(), 0usize);
    let status = unsafe {
        if det {
            tav_cbor_det_parse(
                bytes.as_ptr(),
                bytes.len(),
                max_depth,
                &mut value,
                &mut err,
                &mut err_len,
            )
        } else {
            tav_cbor_nondet_parse(
                bytes.as_ptr(),
                bytes.len(),
                max_depth,
                &mut value,
                &mut err,
                &mut err_len,
            )
        }
    };
    if status == STATUS_OK {
        return Ok(value);
    }
    let message = unsafe { std::slice::from_raw_parts(err, err_len) };
    let message = String::from_utf8_lossy(message).into_owned();
    unsafe { tav_cbor_buffer_free(err, err_len) };
    Err(message)
}

fn parse_nondet(bytes: &[u8]) -> Result<*mut TavCborHandle, String> {
    decode(bytes, MAX_DEPTH_LIMIT, false)
}

// --- Construction and round trips ---

#[test]
fn scalars_round_trip() {
    for (handle, expected) in [
        (tav_cbor_make_signed(0), vec![0x00]),
        (tav_cbor_make_signed(1), vec![0x01]),
        (tav_cbor_make_signed(-1), vec![0x20]),
        (tav_cbor_make_simple(22), vec![0xf6]),
    ] {
        assert_eq!(encode_det(handle).unwrap(), expected);
        unsafe { tav_cbor_free(handle) };
    }
}

#[test]
fn reserved_simple_values_are_rejected() {
    for value in 24..=31u8 {
        assert!(tav_cbor_make_simple(value).is_null(), "accepted {value}");
    }

    // The neighbours on both sides stay usable.
    for value in [23u8, 32u8] {
        let handle = tav_cbor_make_simple(value);
        assert!(!handle.is_null(), "rejected {value}");
        assert!(encode_det(handle).is_ok());
        unsafe { tav_cbor_free(handle) };
    }
}

#[test]
fn integer_bounds_round_trip() {
    for value in [i64::MIN, i64::MAX] {
        let handle = tav_cbor_make_signed(value);
        let encoded = encode_det(handle).unwrap();
        unsafe { tav_cbor_free(handle) };

        let parsed = parse_nondet(&encoded).unwrap();
        let mut out = 0i64;
        assert_eq!(unsafe { tav_cbor_as_signed(parsed, &mut out) }, STATUS_OK);
        assert_eq!(out, value);
        unsafe { tav_cbor_free(parsed) };
    }
}

#[test]
fn a_shallow_copy_keeps_a_borrowed_payload_borrowed() {
    // The copy points at the same caller buffer, so nothing is duplicated.
    let buffer = [0x01u8, 0x02, 0x03];
    let source = unsafe { tav_cbor_make_bytes(buffer.as_ptr(), buffer.len()) };
    let copied = unsafe { tav_cbor_shallow_copy(source) };

    let (mut out, mut out_len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(copied, &mut out, &mut out_len) },
        STATUS_OK
    );
    assert_eq!(out, buffer.as_ptr());
    unsafe { tav_cbor_free(source) };
    unsafe { tav_cbor_free(copied) };
}

#[test]
fn a_shallow_copy_keeps_an_owned_payload_owned() {
    // The copy must not point into the source, which is freed first.
    let buffer = [0x01u8, 0x02, 0x03];
    let borrowed = unsafe { tav_cbor_make_bytes(buffer.as_ptr(), buffer.len()) };
    let source = unsafe { tav_cbor_deep_copy(borrowed) };
    unsafe { tav_cbor_free(borrowed) };
    let copied = unsafe { tav_cbor_shallow_copy(source) };

    let (mut source_payload, mut len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(source, &mut source_payload, &mut len) },
        STATUS_OK
    );
    let (mut copied_payload, mut len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(copied, &mut copied_payload, &mut len) },
        STATUS_OK
    );
    assert_ne!(copied_payload, source_payload);

    // The copy owns its bytes, so it outlives the source.
    unsafe { tav_cbor_free(source) };
    assert_eq!(encode_det(copied).unwrap(), [0x43, 0x01, 0x02, 0x03]);
    unsafe { tav_cbor_free(copied) };
}

#[test]
fn a_deep_copy_owns_every_payload() {
    // Built over a buffer, the deep copy must survive that buffer's death.
    let buffer = [0x01u8, 0x02, 0x03];
    let source = unsafe { tav_cbor_make_bytes(buffer.as_ptr(), buffer.len()) };
    let deep = unsafe { tav_cbor_deep_copy(source) };

    let (mut out, mut len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(deep, &mut out, &mut len) },
        STATUS_OK
    );
    assert_ne!(out, buffer.as_ptr());
    assert_eq!(encode_det(deep).unwrap(), [0x43, 0x01, 0x02, 0x03]);

    unsafe { tav_cbor_free(source) };
    unsafe { tav_cbor_free(deep) };
}

#[test]
fn a_deep_copy_reaches_nested_payloads() {
    // The payloads sit under a tag and an array, so the walk must recurse.
    let document = [0xd2u8, 0x82, 0x43, 0x01, 0x02, 0x03, 0x63, b'a', b'b', b'c'];
    let deep = {
        let owned = document.to_vec();
        let source = decode(&owned, MAX_DEPTH_LIMIT, false).unwrap();
        let deep = unsafe { tav_cbor_deep_copy(source) };
        unsafe { tav_cbor_free(source) };
        deep
    };
    assert_eq!(encode_det(deep).unwrap(), document);
    unsafe { tav_cbor_free(deep) };

    assert!(unsafe { tav_cbor_deep_copy(ptr::null()) }.is_null());
}

#[test]
fn a_shallow_copy_reproduces_a_whole_tree() {
    let document = [0xd2u8, 0x82, 0x01, 0x63, b'a', b'b', b'c'];
    let source = decode(&document, MAX_DEPTH_LIMIT, false).unwrap();
    let copied = unsafe { tav_cbor_shallow_copy(source) };

    assert_eq!(encode_det(copied).unwrap(), encode_det(source).unwrap());
    unsafe { tav_cbor_free(source) };
    unsafe { tav_cbor_free(copied) };

    assert!(unsafe { tav_cbor_shallow_copy(ptr::null()) }.is_null());
}

#[test]
fn payloads_are_borrowed_not_copied() {
    // Reading the payload back must yield the caller's own address, which a
    // copy could not. Mutating the buffer while the handle holds a shared
    // reference to it would be undefined, so identity is the safe proof.
    let buffer = [0x01u8, 0x02, 0x03];
    let handle = unsafe { tav_cbor_make_bytes(buffer.as_ptr(), buffer.len()) };

    let (mut out, mut out_len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(handle, &mut out, &mut out_len) },
        STATUS_OK
    );
    assert_eq!(out, buffer.as_ptr());
    assert_eq!(out_len, buffer.len());
    assert_eq!(encode_det(handle).unwrap(), [0x43, 0x01, 0x02, 0x03]);
    unsafe { tav_cbor_free(handle) };

    let text = b"hi";
    let handle = unsafe { tav_cbor_make_string(text.as_ptr().cast(), text.len()) };
    let (mut out, mut out_len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_string(handle, &mut out, &mut out_len) },
        STATUS_OK
    );
    assert_eq!(out.cast::<u8>(), text.as_ptr());
    unsafe { tav_cbor_free(handle) };
}

#[test]
fn parsed_payloads_point_into_the_input() {
    let document = [0x43, 0x01, 0x02, 0x03];
    let parsed = parse_nondet(&document).unwrap();

    let (mut out, mut out_len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(parsed, &mut out, &mut out_len) },
        STATUS_OK
    );
    assert_eq!(out, document[1..].as_ptr());
    assert_eq!(out_len, 3);
    unsafe { tav_cbor_free(parsed) };
}

#[test]
fn empty_payloads_are_accepted() {
    let bytes = unsafe { tav_cbor_make_bytes(ptr::null(), 0) };
    assert_eq!(encode_det(bytes).unwrap(), [0x40]);
    unsafe { tav_cbor_free(bytes) };

    let text = unsafe { tav_cbor_make_string(ptr::null(), 0) };
    assert_eq!(encode_det(text).unwrap(), [0x60]);
    unsafe { tav_cbor_free(text) };
}

#[test]
fn invalid_utf8_is_rejected() {
    let invalid = [0xff, 0xfe];
    let handle = unsafe { tav_cbor_make_string(invalid.as_ptr().cast(), invalid.len()) };
    assert!(handle.is_null());
}

#[test]
fn null_payload_pointers_are_rejected() {
    assert!(unsafe { tav_cbor_make_bytes(ptr::null(), 4) }.is_null());
    assert!(unsafe { tav_cbor_make_string(ptr::null(), 4) }.is_null());
}

// --- The tree invariant ---

#[test]
fn container_constructors_consume_their_children() {
    let mut items = vec![tav_cbor_make_signed(1), tav_cbor_make_signed(2)];
    let array = unsafe { tav_cbor_make_array(items.as_mut_ptr(), items.len()) };

    // The caller's variables are emptied, so no value can gain a second parent.
    assert!(items[0].is_null());
    assert!(items[1].is_null());
    assert_eq!(encode_det(array).unwrap(), [0x82, 0x01, 0x02]);
    unsafe { tav_cbor_free(array) };
}

#[test]
fn a_repeated_handle_is_rejected_without_consuming_the_batch() {
    let handle = tav_cbor_make_signed(1);
    let mut items = [handle, handle];

    assert!(unsafe { tav_cbor_make_array(items.as_mut_ptr(), items.len()) }.is_null());
    assert_eq!(items, [handle, handle]);

    unsafe { tav_cbor_free(handle) };
}

#[test]
fn a_container_cannot_be_a_map_key() {
    // Every key a map holds must be one tav_cbor_map_at can compare.
    for key in [
        unsafe { tav_cbor_make_array(ptr::null_mut(), 0) },
        unsafe { tav_cbor_make_map(ptr::null_mut(), 0) },
        {
            let mut payload = tav_cbor_make_signed(1);
            unsafe { tav_cbor_make_tagged(18, &mut payload) }
        },
    ] {
        let value = tav_cbor_make_signed(7);
        let mut pairs = vec![key, value];
        let map = unsafe { tav_cbor_make_map(pairs.as_mut_ptr(), 1) };

        assert!(map.is_null());
        // Nothing was consumed, so the caller still owns both handles.
        assert_eq!(pairs[0], key);
        assert_eq!(pairs[1], value);
        unsafe { tav_cbor_free(key) };
        unsafe { tav_cbor_free(value) };
    }
}

#[test]
fn duplicate_map_keys_build_but_cannot_be_serialized() {
    let mut pairs = vec![
        tav_cbor_make_signed(1),
        tav_cbor_make_signed(10),
        tav_cbor_make_signed(1),
        tav_cbor_make_signed(20),
    ];
    let map = unsafe { tav_cbor_make_map(pairs.as_mut_ptr(), 2) };

    assert!(!map.is_null());
    assert!(pairs.iter().all(|handle| handle.is_null()));
    assert!(encode_nondet(map).is_err());
    assert!(encode_det(map).is_err());
    unsafe { tav_cbor_free(map) };
}

#[test]
fn scalars_are_accepted_as_map_keys() {
    let text = b"k";
    let bytes = [0x01u8];
    for key in [
        tav_cbor_make_signed(1),
        tav_cbor_make_simple(22),
        unsafe { tav_cbor_make_bytes(bytes.as_ptr(), bytes.len()) },
        unsafe { tav_cbor_make_string(text.as_ptr().cast(), text.len()) },
    ] {
        let mut pairs = vec![key, tav_cbor_make_signed(7)];
        let map = unsafe { tav_cbor_make_map(pairs.as_mut_ptr(), 1) };
        assert!(!map.is_null());
        unsafe { tav_cbor_free(map) };
    }
}

#[test]
fn a_failed_container_returns_the_children() {
    let mut items = vec![tav_cbor_make_signed(1), ptr::null_mut()];
    let array = unsafe { tav_cbor_make_array(items.as_mut_ptr(), items.len()) };

    assert!(array.is_null());
    // The first child is handed back rather than leaked.
    assert!(!items[0].is_null());
    assert_eq!(encode_det(items[0]).unwrap(), [0x01]);
    unsafe { tav_cbor_free(items[0]) };
}

#[test]
fn tagged_consumes_its_payload() {
    let mut payload = tav_cbor_make_signed(42);
    let tagged = unsafe { tav_cbor_make_tagged(18, &mut payload) };
    assert!(payload.is_null());
    assert_eq!(encode_det(tagged).unwrap(), [0xd2, 0x18, 0x2a]);
    unsafe { tav_cbor_free(tagged) };
}

#[test]
fn a_null_payload_fails_tagged_construction() {
    let mut payload: *mut TavCborHandle = ptr::null_mut();
    assert!(unsafe { tav_cbor_make_tagged(18, &mut payload) }.is_null());
    assert!(unsafe { tav_cbor_make_tagged(18, ptr::null_mut()) }.is_null());
}

#[test]
fn maps_pair_their_children_in_order() {
    let mut pairs = vec![
        tav_cbor_make_signed(1),
        tav_cbor_make_signed(2),
        tav_cbor_make_signed(3),
        tav_cbor_make_signed(4),
    ];
    let map = unsafe { tav_cbor_make_map(pairs.as_mut_ptr(), 2) };
    assert_eq!(encode_nondet(map).unwrap(), [0xa2, 0x01, 0x02, 0x03, 0x04]);
    unsafe { tav_cbor_free(map) };
}

#[test]
fn an_oversized_pair_count_is_rejected() {
    let mut pairs = vec![tav_cbor_make_signed(1)];
    // 2 * pair_count overflows usize.
    let map = unsafe { tav_cbor_make_map(pairs.as_mut_ptr(), usize::MAX / 2 + 1) };
    assert!(map.is_null());
    assert!(!pairs[0].is_null());
    unsafe { tav_cbor_free(pairs[0]) };
}

#[test]
fn empty_containers_are_accepted() {
    let array = unsafe { tav_cbor_make_array(ptr::null_mut(), 0) };
    assert_eq!(encode_det(array).unwrap(), [0x80]);
    unsafe { tav_cbor_free(array) };

    let map = unsafe { tav_cbor_make_map(ptr::null_mut(), 0) };
    assert_eq!(encode_det(map).unwrap(), [0xa0]);
    unsafe { tav_cbor_free(map) };
}

// --- Modes ---

#[test]
fn det_sorts_map_keys_and_nondet_preserves_order() {
    let text_b = b"b";
    let text_a = b"a";
    let mut pairs = vec![
        unsafe { tav_cbor_make_string(text_b.as_ptr().cast(), 1) },
        tav_cbor_make_signed(2),
        unsafe { tav_cbor_make_string(text_a.as_ptr().cast(), 1) },
        tav_cbor_make_signed(1),
    ];
    let map = unsafe { tav_cbor_make_map(pairs.as_mut_ptr(), 2) };

    assert_eq!(
        encode_nondet(map).unwrap(),
        [0xa2, 0x61, 0x62, 0x02, 0x61, 0x61, 0x01]
    );
    assert_eq!(
        encode_det(map).unwrap(),
        [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]
    );
    unsafe { tav_cbor_free(map) };
}

#[test]
fn det_parsing_rejects_non_preferred_encodings() {
    // 1 in a two-byte head.
    let document = [0x18, 0x01];
    let lenient = decode(&document, MAX_DEPTH_LIMIT, false).unwrap();
    unsafe { tav_cbor_free(lenient) };

    assert!(decode(&document, MAX_DEPTH_LIMIT, true).is_err());
}

#[test]
fn parsing_rejects_trailing_bytes_and_garbage() {
    assert!(parse_nondet(&[0x00, 0x00])
        .unwrap_err()
        .contains("Trailing bytes"));
    assert!(parse_nondet(&[0xff]).is_err());
    assert!(parse_nondet(&[]).is_err());
}

// --- Depth ---

#[test]
fn the_requested_depth_is_honoured_below_the_ceiling() {
    // [[[[1]]]]
    let document = [0x81, 0x81, 0x81, 0x81, 0x01];
    assert!(decode(&document, 2, false)
        .unwrap_err()
        .contains("Maximum CBOR nesting depth"));

    let deep_enough = decode(&document, 16, false).unwrap();
    unsafe { tav_cbor_free(deep_enough) };
}

#[test]
fn the_depth_ceiling_bounds_the_caller() {
    // Each 0x81 opens a one-element array, so the run gives that many levels.
    let nested = |levels: usize| {
        let mut document = vec![0x81u8; levels];
        document.push(0x01);
        document
    };

    // However large a depth the caller asks for, the ceiling still applies.
    let handle = decode(&nested(MAX_DEPTH_LIMIT), usize::MAX, false).unwrap();
    unsafe { tav_cbor_free(handle) };
    assert!(decode(&nested(MAX_DEPTH_LIMIT + 1), usize::MAX, false).is_err());
}

#[test]
fn serialization_honours_the_depth_ceiling() {
    let document = [0x81, 0x81, 0x81, 0x81, 0x01];
    let handle = parse_nondet(&document).unwrap();
    assert!(encode(handle, 2, false)
        .unwrap_err()
        .contains("Maximum CBOR nesting depth"));
    assert!(encode(handle, 16, false).is_ok());
    unsafe { tav_cbor_free(handle) };
}

// --- Inspection ---

#[test]
fn kinds_are_reported_for_every_type() {
    let text = b"a";
    let bytes = [0x01u8];
    let cases: Vec<(*mut TavCborHandle, i32)> = vec![
        (tav_cbor_make_signed(1), KIND_SIGNED),
        (tav_cbor_make_simple(22), KIND_SIMPLE),
        (
            unsafe { tav_cbor_make_bytes(bytes.as_ptr(), 1) },
            KIND_BYTES,
        ),
        (
            unsafe { tav_cbor_make_string(text.as_ptr().cast(), 1) },
            KIND_STRING,
        ),
        (
            unsafe { tav_cbor_make_array(ptr::null_mut(), 0) },
            KIND_ARRAY,
        ),
        (unsafe { tav_cbor_make_map(ptr::null_mut(), 0) }, KIND_MAP),
    ];
    for (handle, expected) in cases {
        assert_eq!(unsafe { tav_cbor_kind(handle) }, expected);
        unsafe { tav_cbor_free(handle) };
    }

    let mut payload = tav_cbor_make_signed(1);
    let tagged = unsafe { tav_cbor_make_tagged(1, &mut payload) };
    assert_eq!(unsafe { tav_cbor_kind(tagged) }, KIND_TAGGED);
    unsafe { tav_cbor_free(tagged) };

    assert_eq!(unsafe { tav_cbor_kind(ptr::null()) }, KIND_INVALID);
}

#[test]
fn accessors_reject_the_wrong_kind() {
    let handle = tav_cbor_make_signed(1);
    let mut simple = 0u8;
    let mut size = 0usize;
    let (mut ptr_out, mut len_out) = (ptr::null(), 0usize);

    assert_eq!(
        unsafe { tav_cbor_as_simple(handle, &mut simple) },
        STATUS_TYPE_MISMATCH
    );
    assert_eq!(
        unsafe { tav_cbor_as_bytes(handle, &mut ptr_out, &mut len_out) },
        STATUS_TYPE_MISMATCH
    );
    assert_eq!(
        unsafe { tav_cbor_size(handle, &mut size) },
        STATUS_TYPE_MISMATCH
    );
    unsafe { tav_cbor_free(handle) };
}

#[test]
fn size_counts_entries_not_children() {
    // {1: 2, 3: 4} has two entries and four child values.
    let document = [0xa2, 0x01, 0x02, 0x03, 0x04];
    let handle = parse_nondet(&document).unwrap();
    let mut size = 0usize;
    assert_eq!(unsafe { tav_cbor_size(handle, &mut size) }, STATUS_OK);
    assert_eq!(size, 2);
    unsafe { tav_cbor_free(handle) };
}

#[test]
fn a_tagged_value_has_no_size() {
    let mut payload = tav_cbor_make_signed(1);
    let tagged = unsafe { tav_cbor_make_tagged(1, &mut payload) };
    let mut size = 0usize;
    assert_eq!(
        unsafe { tav_cbor_size(tagged, &mut size) },
        STATUS_TYPE_MISMATCH
    );
    unsafe { tav_cbor_free(tagged) };
}

// --- Navigation ---

#[test]
fn array_indexing_reports_out_of_bounds_separately_from_type() {
    let document = [0x81, 0x01];
    let handle = parse_nondet(&document).unwrap();
    let mut out: *mut TavCborHandle = ptr::null_mut();

    assert_eq!(unsafe { tav_cbor_array_at(handle, 0, &mut out) }, STATUS_OK);
    unsafe { tav_cbor_free(out) };
    assert_eq!(
        unsafe { tav_cbor_array_at(handle, 1, &mut out) },
        STATUS_OUT_OF_BOUND
    );
    assert!(out.is_null());
    unsafe { tav_cbor_free(handle) };

    let scalar = tav_cbor_make_signed(1);
    assert_eq!(
        unsafe { tav_cbor_array_at(scalar, 0, &mut out) },
        STATUS_TYPE_MISMATCH
    );
    unsafe { tav_cbor_free(scalar) };
}

#[test]
fn map_lookup_matches_by_value() {
    // {1: 2, "a": 3}
    let document = [0xa2, 0x01, 0x02, 0x61, 0x61, 0x03];
    let handle = parse_nondet(&document).unwrap();
    let mut out: *mut TavCborHandle = ptr::null_mut();

    let int_key = tav_cbor_make_signed(1);
    assert_eq!(
        unsafe { tav_cbor_map_at(handle, int_key, &mut out) },
        STATUS_OK
    );
    let mut found = 0i64;
    assert_eq!(unsafe { tav_cbor_as_signed(out, &mut found) }, STATUS_OK);
    assert_eq!(found, 2);
    unsafe { tav_cbor_free(out) };
    unsafe { tav_cbor_free(int_key) };

    let text = b"a";
    let text_key = unsafe { tav_cbor_make_string(text.as_ptr().cast(), 1) };
    assert_eq!(
        unsafe { tav_cbor_map_at(handle, text_key, &mut out) },
        STATUS_OK
    );
    unsafe { tav_cbor_free(out) };
    unsafe { tav_cbor_free(text_key) };

    let absent = tav_cbor_make_signed(9);
    assert_eq!(
        unsafe { tav_cbor_map_at(handle, absent, &mut out) },
        STATUS_KEY_NOT_FOUND
    );
    assert!(out.is_null());
    unsafe { tav_cbor_free(absent) };

    unsafe { tav_cbor_free(handle) };
}

#[test]
fn parsing_rejects_a_container_used_as_a_map_key() {
    // {[1]: 2}, which map_at could never look up.
    let document = [0xa1, 0x81, 0x01, 0x02];
    assert!(parse_nondet(&document).is_err());
    assert!(decode(&document, MAX_DEPTH_LIMIT, true).is_err());

    // Nested below the root, so the whole tree is checked.
    let nested = [0x81, 0xa1, 0x81, 0x01, 0x02]; // [{[1]: 2}]
    assert!(parse_nondet(&nested).is_err());

    // A map key is also rejected under a tag.
    let tagged = [0xd2, 0xa1, 0x81, 0x01, 0x02]; // 18({[1]: 2})
    assert!(parse_nondet(&tagged).is_err());

    // Scalar keys of every kind still parse.
    let scalars = [0xa2, 0x01, 0x02, 0x63, 0x6b, 0x65, 0x79, 0x04];
    let handle = parse_nondet(&scalars).unwrap();
    unsafe { tav_cbor_free(handle) };
}

#[test]
fn containers_are_not_usable_as_map_keys() {
    let document = [0xa1, 0x01, 0x02];
    let handle = parse_nondet(&document).unwrap();
    let mut out: *mut TavCborHandle = ptr::null_mut();

    let container_key = unsafe { tav_cbor_make_array(ptr::null_mut(), 0) };
    assert_eq!(
        unsafe { tav_cbor_map_at(handle, container_key, &mut out) },
        STATUS_TYPE_MISMATCH
    );
    unsafe { tav_cbor_free(container_key) };
    unsafe { tav_cbor_free(handle) };
}

#[test]
fn tag_lookup_distinguishes_a_wrong_tag_from_a_wrong_kind() {
    let document = [0xd2, 0x01];
    let handle = parse_nondet(&document).unwrap();
    let mut out: *mut TavCborHandle = ptr::null_mut();

    assert_eq!(unsafe { tav_cbor_tag_at(handle, 18, &mut out) }, STATUS_OK);
    unsafe { tav_cbor_free(out) };
    assert_eq!(
        unsafe { tav_cbor_tag_at(handle, 19, &mut out) },
        STATUS_KEY_NOT_FOUND
    );
    assert!(out.is_null());
    unsafe { tav_cbor_free(handle) };

    let scalar = tav_cbor_make_signed(1);
    assert_eq!(
        unsafe { tav_cbor_tag_at(scalar, 18, &mut out) },
        STATUS_TYPE_MISMATCH
    );
    unsafe { tav_cbor_free(scalar) };
}

#[test]
fn a_tag_can_be_read_before_it_is_known() {
    // Reconstructing a value from a handle needs the tag itself, not a guess.
    let document = [0xd2, 0x01];
    let handle = parse_nondet(&document).unwrap();
    let mut tag = 0u64;
    assert_eq!(unsafe { tav_cbor_as_tag(handle, &mut tag) }, STATUS_OK);
    assert_eq!(tag, 18);
    unsafe { tav_cbor_free(handle) };

    let scalar = tav_cbor_make_signed(1);
    assert_eq!(
        unsafe { tav_cbor_as_tag(scalar, &mut tag) },
        STATUS_TYPE_MISMATCH
    );
    unsafe { tav_cbor_free(scalar) };
}

#[test]
fn map_enumeration_walks_entries_in_order() {
    let document = [0xa2, 0x01, 0x02, 0x03, 0x04];
    let handle = parse_nondet(&document).unwrap();
    let mut out: *mut TavCborHandle = ptr::null_mut();

    for (index, (key, value)) in [(1i64, 2i64), (3, 4)].iter().enumerate() {
        assert_eq!(
            unsafe { tav_cbor_map_key_at(handle, index, &mut out) },
            STATUS_OK
        );
        let mut found = 0i64;
        assert_eq!(unsafe { tav_cbor_as_signed(out, &mut found) }, STATUS_OK);
        assert_eq!(found, *key);
        unsafe { tav_cbor_free(out) };

        assert_eq!(
            unsafe { tav_cbor_map_value_at(handle, index, &mut out) },
            STATUS_OK
        );
        assert_eq!(unsafe { tav_cbor_as_signed(out, &mut found) }, STATUS_OK);
        assert_eq!(found, *value);
        unsafe { tav_cbor_free(out) };
    }

    assert_eq!(
        unsafe { tav_cbor_map_key_at(handle, 2, &mut out) },
        STATUS_OUT_OF_BOUND
    );
    assert!(out.is_null());
    unsafe { tav_cbor_free(handle) };
}

#[test]
fn an_owned_child_stays_valid_after_the_root_is_freed() {
    let document = [0x82, 0x42, 0xaa, 0xbb, 0x01];
    let handle = parse_nondet(&document).unwrap();
    let mut child: *mut TavCborHandle = ptr::null_mut();
    assert_eq!(
        unsafe { tav_cbor_array_at(handle, 0, &mut child) },
        STATUS_OK
    );
    unsafe { tav_cbor_free(handle) };

    let (mut out, mut out_len) = (ptr::null(), 0usize);
    assert_eq!(
        unsafe { tav_cbor_as_bytes(child, &mut out, &mut out_len) },
        STATUS_OK
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(out, out_len) },
        [0xaa, 0xbb]
    );
    unsafe { tav_cbor_free(child) };
}

#[test]
fn a_projected_child_can_be_consumed_by_a_builder() {
    let document = [0x81, 0x01];
    let handle = parse_nondet(&document).unwrap();
    let mut child: *mut TavCborHandle = ptr::null_mut();
    assert_eq!(
        unsafe { tav_cbor_array_at(handle, 0, &mut child) },
        STATUS_OK
    );
    unsafe { tav_cbor_free(handle) };

    let mut items = [child];
    let rebuilt = unsafe { tav_cbor_make_array(items.as_mut_ptr(), items.len()) };
    assert!(!rebuilt.is_null());
    assert!(items[0].is_null());
    assert_eq!(encode_det(rebuilt).unwrap(), document);
    unsafe { tav_cbor_free(rebuilt) };
}

#[test]
fn a_root_and_its_projection_can_be_consumed_in_either_order() {
    for root_first in [true, false] {
        let document = [0x81, 0x01];
        let root = parse_nondet(&document).unwrap();
        let mut child: *mut TavCborHandle = ptr::null_mut();
        assert_eq!(unsafe { tav_cbor_array_at(root, 0, &mut child) }, STATUS_OK);

        let mut items = if root_first {
            [root, child]
        } else {
            [child, root]
        };
        let rebuilt = unsafe { tav_cbor_make_array(items.as_mut_ptr(), items.len()) };

        assert!(!rebuilt.is_null());
        assert_eq!(items, [ptr::null_mut(), ptr::null_mut()]);
        let expected = if root_first {
            vec![0x82, 0x81, 0x01, 0x01] // [[1], 1]
        } else {
            vec![0x82, 0x01, 0x81, 0x01] // [1, [1]]
        };
        assert_eq!(encode_det(rebuilt).unwrap(), expected);
        unsafe { tav_cbor_free(rebuilt) };
    }
}

// --- The C contract ---

#[test]
fn freeing_null_is_a_no_op() {
    unsafe {
        tav_cbor_free(ptr::null_mut());
        tav_cbor_buffer_free(ptr::null_mut(), 0);
        tav_cbor_buffer_free(ptr::null_mut(), 7);
    }
}

#[test]
fn output_parameters_are_cleared_on_failure() {
    let document = [0xff];
    let sentinel = 0x1 as *mut TavCborHandle;
    let mut value = sentinel;
    let (mut err, mut err_len) = (0x1 as *mut u8, 12345usize);

    assert_eq!(
        unsafe {
            tav_cbor_nondet_parse(
                document.as_ptr(),
                document.len(),
                16,
                &mut value,
                &mut err,
                &mut err_len,
            )
        },
        STATUS_DECODE_FAILED
    );
    assert!(value.is_null());
    assert!(err_len > 0);
    unsafe { tav_cbor_buffer_free(err, err_len) };

    let handle = tav_cbor_make_signed(1);
    let mut items = vec![handle];
    let nested = unsafe { tav_cbor_make_array(items.as_mut_ptr(), 1) };
    let mut outer = vec![nested];
    let nested = unsafe { tav_cbor_make_array(outer.as_mut_ptr(), 1) };

    let mut out = 0x1 as *mut u8;
    let mut out_len = 12345usize;
    assert_eq!(
        unsafe {
            tav_cbor_det_serialize(
                nested,
                1,
                &mut out,
                &mut out_len,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        STATUS_ENCODE_FAILED
    );
    assert!(out.is_null());
    assert_eq!(out_len, 0);
    unsafe { tav_cbor_free(nested) };
}

/// A failure must not leave a stale pointer that the caller frees twice.
#[test]
fn a_reused_output_slot_is_cleared_before_the_next_failure() {
    let mut out: *mut u8 = ptr::null_mut();
    let mut out_len = 0usize;
    let value = tav_cbor_make_signed(1);

    assert_eq!(
        unsafe {
            tav_cbor_det_serialize(
                value,
                16,
                &mut out,
                &mut out_len,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        STATUS_OK
    );
    assert!(!out.is_null());
    unsafe { tav_cbor_buffer_free(out, out_len) };

    // The same slots now hold a freed pointer. A failing call must clear them,
    // so the caller cannot tell it to free that pointer again.
    let mut items = vec![value];
    let nested = unsafe { tav_cbor_make_array(items.as_mut_ptr(), 1) };
    let mut outer = vec![nested];
    let nested = unsafe { tav_cbor_make_array(outer.as_mut_ptr(), 1) };

    assert_eq!(
        unsafe {
            tav_cbor_det_serialize(
                nested,
                1,
                &mut out,
                &mut out_len,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        STATUS_ENCODE_FAILED
    );
    assert!(out.is_null());
    assert_eq!(out_len, 0);
    unsafe { tav_cbor_buffer_free(out, out_len) };
    unsafe { tav_cbor_free(nested) };
}

#[test]
fn null_error_pointers_suppress_the_message() {
    let document = [0xff];
    let mut value: *mut TavCborHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            tav_cbor_nondet_parse(
                document.as_ptr(),
                document.len(),
                16,
                &mut value,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        STATUS_DECODE_FAILED
    );
    assert!(value.is_null());
}

#[test]
fn null_handles_and_outputs_are_reported_not_dereferenced() {
    let mut signed = 0i64;
    assert_eq!(
        unsafe { tav_cbor_as_signed(ptr::null(), &mut signed) },
        STATUS_TYPE_MISMATCH
    );

    let handle = tav_cbor_make_signed(1);
    assert_eq!(
        unsafe { tav_cbor_as_signed(handle, ptr::null_mut()) },
        STATUS_TYPE_MISMATCH
    );

    let (mut out, mut out_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            tav_cbor_det_serialize(
                ptr::null(),
                16,
                &mut out,
                &mut out_len,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        STATUS_ENCODE_FAILED
    );
    unsafe { tav_cbor_free(handle) };
}

// --- C header synchronisation ---

fn header_enum_value(header: &str, name: &str) -> Option<i64> {
    header.lines().find_map(|line| {
        let line = line.trim().trim_end_matches(',');
        let (candidate, value) = line.split_once('=')?;
        if candidate.trim() != name {
            return None;
        }
        value.trim().parse().ok()
    })
}

fn header_names(header: &str, prefix: &str) -> std::collections::BTreeSet<String> {
    header
        .lines()
        .filter_map(|line| {
            let line = line.trim().trim_end_matches(',');
            let (candidate, _) = line.split_once('=')?;
            let candidate = candidate.trim();
            candidate.starts_with(prefix).then(|| candidate.to_owned())
        })
        .collect()
}

#[test]
fn c_header_status_codes_match_rust() {
    let header = include_str!("../../include/tav/internal/cbor_abi.h");
    let mapping = [
        ("TAV_CBOR_OK", STATUS_OK),
        ("TAV_CBOR_DECODE_FAILED", STATUS_DECODE_FAILED),
        ("TAV_CBOR_KEY_NOT_FOUND", STATUS_KEY_NOT_FOUND),
        ("TAV_CBOR_OUT_OF_BOUND", STATUS_OUT_OF_BOUND),
        ("TAV_CBOR_TYPE_MISMATCH", STATUS_TYPE_MISMATCH),
        ("TAV_CBOR_ENCODE_FAILED", STATUS_ENCODE_FAILED),
    ];
    for (name, value) in mapping {
        assert_eq!(
            header_enum_value(header, name),
            Some(i64::from(value)),
            "{name} must match the Rust constant"
        );
    }

    let declared = header_names(header, "TAV_CBOR_")
        .into_iter()
        .filter(|n| !n.starts_with("TAV_CBOR_HANDLE_KIND_"))
        .collect::<std::collections::BTreeSet<_>>();
    let checked = mapping
        .iter()
        .map(|(n, _)| (*n).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(declared, checked, "status codes are declared but unchecked");
}

#[test]
fn c_header_kinds_match_rust() {
    let header = include_str!("../../include/tav/internal/cbor_abi.h");
    let mapping = [
        ("TAV_CBOR_HANDLE_KIND_INVALID", KIND_INVALID),
        ("TAV_CBOR_HANDLE_KIND_SIGNED", KIND_SIGNED),
        ("TAV_CBOR_HANDLE_KIND_BYTES", KIND_BYTES),
        ("TAV_CBOR_HANDLE_KIND_STRING", KIND_STRING),
        ("TAV_CBOR_HANDLE_KIND_ARRAY", KIND_ARRAY),
        ("TAV_CBOR_HANDLE_KIND_MAP", KIND_MAP),
        ("TAV_CBOR_HANDLE_KIND_TAGGED", KIND_TAGGED),
        ("TAV_CBOR_HANDLE_KIND_SIMPLE", KIND_SIMPLE),
    ];
    for (name, value) in mapping {
        assert_eq!(
            header_enum_value(header, name),
            Some(i64::from(value)),
            "{name} must match the Rust constant"
        );
    }

    let declared = header_names(header, "TAV_CBOR_HANDLE_KIND_");
    let checked = mapping
        .iter()
        .map(|(n, _)| (*n).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(declared, checked, "kinds are declared but unchecked");
}

#[test]
fn c_header_publishes_the_depth_ceiling() {
    let header = include_str!("../../include/tav/internal/cbor_abi.h");
    let declared = header.lines().find_map(|line| {
        line.trim()
            .strip_prefix("#define TAV_CBOR_MAX_DEPTH ")
            .and_then(|v| v.trim().parse::<usize>().ok())
    });
    assert_eq!(
        declared,
        Some(MAX_DEPTH_LIMIT),
        "TAV_CBOR_MAX_DEPTH must match the Rust constant"
    );
}

#[test]
fn c_header_declares_every_exported_symbol() {
    let header = include_str!("../../include/tav/internal/cbor_abi.h");
    let source = include_str!("cbor.rs");

    let exported: std::collections::BTreeSet<&str> = source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line
                .strip_prefix("pub unsafe extern \"C\" fn ")
                .or_else(|| line.strip_prefix("pub extern \"C\" fn "))?;
            rest.split('(').next()
        })
        .collect();
    assert_eq!(exported.len(), 27, "unexpected entry point count");

    for symbol in exported {
        assert!(
            header.contains(&format!("{symbol}(")),
            "{symbol} is exported but not declared in include/tav/internal/cbor_abi.h"
        );
    }
}
