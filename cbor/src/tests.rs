// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// Serializing, reparsing, and reserializing must be a fixed point.
///
/// Deterministic serialization may reorder map keys, so this compares the
/// re-serialized bytes rather than the structural values.
fn round_trip(val: &CborValue<'_>) {
    let bytes = val.to_bytes_det().unwrap();
    let parsed = CborValue::parse_nondet(&bytes).unwrap();
    assert_eq!(bytes, parsed.to_bytes_det().unwrap());
}

// --- Int ---

#[test]
fn round_trip_uint() {
    round_trip(&CborValue::Int(42));
}

#[test]
fn round_trip_nint() {
    round_trip(&CborValue::Int(-7));
}

#[test]
fn round_trip_zero() {
    round_trip(&CborValue::Int(0));
}

#[test]
fn round_trip_i64_min() {
    round_trip(&CborValue::Int(i64::MIN));
}

#[test]
fn round_trip_i64_max() {
    round_trip(&CborValue::Int(i64::MAX));
}

// --- Simple ---

#[test]
fn round_trip_simple_true() {
    round_trip(&CborValue::Simple(21)); // CBOR true
}

#[test]
fn round_trip_simple_null() {
    round_trip(&CborValue::Simple(22)); // CBOR null
}

// --- ByteString ---

#[test]
fn round_trip_bstr() {
    round_trip(&CborValue::bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn round_trip_bstr_empty() {
    round_trip(&CborValue::bytes(vec![]));
}

// --- TextString ---

#[test]
fn round_trip_tstr() {
    round_trip(&CborValue::text("hello world"));
}

#[test]
fn round_trip_tstr_empty() {
    round_trip(&CborValue::text(String::new()));
}

// --- Array ---

#[test]
fn round_trip_flat_array() {
    round_trip(&CborValue::Array(vec![
        CborValue::Int(1),
        CborValue::Int(2),
        CborValue::Int(3),
    ]));
}

#[test]
fn round_trip_nested_array() {
    round_trip(&CborValue::Array(vec![
        CborValue::Int(1),
        CborValue::Array(vec![
            CborValue::Int(-1),
            CborValue::Array(vec![CborValue::Int(99)]),
        ]),
        CborValue::Int(3),
    ]));
}

#[test]
fn round_trip_empty_array() {
    round_trip(&CborValue::Array(vec![]));
}

// --- Map ---

#[test]
fn round_trip_map_int_keys() {
    round_trip(&CborValue::Map(vec![
        (CborValue::Int(1), CborValue::text("one")),
        (CborValue::Int(2), CborValue::text("two")),
    ]));
}

#[test]
fn round_trip_map_str_keys() {
    round_trip(&CborValue::Map(vec![
        (CborValue::text("name"), CborValue::text("alice")),
        (CborValue::text("age"), CborValue::Int(30)),
    ]));
}

#[test]
fn round_trip_map_nested_value() {
    round_trip(&CborValue::Map(vec![(
        CborValue::Int(1),
        CborValue::Array(vec![CborValue::bytes(vec![1, 2]), CborValue::Simple(22)]),
    )]));
}

#[test]
fn round_trip_empty_map() {
    round_trip(&CborValue::Map(vec![]));
}

// --- Tagged ---

#[test]
fn round_trip_tagged() {
    round_trip(&CborValue::Tagged {
        tag: 18,
        payload: Box::new(CborValue::bytes(b"payload".to_vec())),
    });
}

#[test]
fn round_trip_tagged_nested() {
    round_trip(&CborValue::Tagged {
        tag: 1,
        payload: Box::new(CborValue::Array(vec![
            CborValue::Int(42),
            CborValue::text("inside tag"),
        ])),
    });
}

// --- Mixed nesting ---

#[test]
fn round_trip_complex() {
    round_trip(&CborValue::Array(vec![
        CborValue::bytes(vec![0xFF]),
        CborValue::Map(vec![
            (
                CborValue::Int(1),
                CborValue::Tagged {
                    tag: 99,
                    payload: Box::new(CborValue::text("nested")),
                },
            ),
            (
                CborValue::Int(2),
                CborValue::Array(vec![CborValue::Simple(22)]),
            ),
        ]),
        CborValue::Int(-100),
    ]));
}

// --- Nesting limits ---

#[test]
fn parse_rejects_excessive_array_nesting() {
    let mut value = CborValue::Int(42);
    for _ in 0..=MAX_CBOR_NESTING_DEPTH {
        value = CborValue::Array(vec![value]);
    }
    let err = value.to_bytes_det().expect_err("serialization should fail");
    assert!(err.contains("Maximum CBOR nesting depth"));

    let mut bytes = vec![0];
    for _ in 0..=MAX_CBOR_NESTING_DEPTH {
        let mut nested = vec![0x81];
        nested.extend_from_slice(&bytes);
        bytes = nested;
    }
    let err = CborValue::parse_nondet(&bytes).expect_err("parse should fail");
    assert!(err.contains("Maximum CBOR nesting depth"));
    let err = CborValue::parse_det(&bytes).expect_err("parse should fail");
    assert!(err.contains("Maximum CBOR nesting depth"));
}

#[test]
fn to_bytes_rejects_excessive_map_nesting() {
    let mut value = CborValue::Int(42);
    for _ in 0..=MAX_CBOR_NESTING_DEPTH {
        value = CborValue::Map(vec![(CborValue::Int(1), value)]);
    }
    for err in [
        value.to_bytes_det().expect_err("det should fail"),
        value.to_bytes_nondet().expect_err("nondet should fail"),
    ] {
        assert!(err.contains("Maximum CBOR nesting depth"));
    }
}

#[test]
fn to_bytes_rejects_excessive_tag_nesting() {
    let mut value = CborValue::Int(42);
    for _ in 0..=MAX_CBOR_NESTING_DEPTH {
        value = CborValue::Tagged {
            tag: 1,
            payload: Box::new(value),
        };
    }
    let err = value.to_bytes_det().expect_err("serialization should fail");
    assert!(err.contains("Maximum CBOR nesting depth"));
}

/// An empty container has no children to descend into, so it costs no depth.
#[test]
fn empty_containers_do_not_spend_depth() {
    for document in [&[0x80u8][..], &[0xa0][..]] {
        assert!(
            CborValue::parse_with_depth::<Nondet>(document, 0).is_ok(),
            "empty container should fit depth 0: {document:02x?}"
        );
    }
    for value in [CborValue::Array(vec![]), CborValue::Map(vec![])] {
        assert!(value.to_bytes_with_depth::<Det>(0).is_ok());
    }

    // A single child needs one level of budget.
    let one_item: &[u8] = &[0x81, 0x01];
    assert!(CborValue::parse_with_depth::<Nondet>(one_item, 0).is_err());
    assert!(CborValue::parse_with_depth::<Nondet>(one_item, 1).is_ok());

    // A tag always has a payload, so it always spends a level.
    let tagged: &[u8] = &[0xc1, 0x01];
    assert!(CborValue::parse_with_depth::<Nondet>(tagged, 0).is_err());
    assert!(CborValue::parse_with_depth::<Nondet>(tagged, 1).is_ok());
}

/// Scalars sit at depth 0, matching the documented root-at-zero semantics.
#[test]
fn scalars_fit_the_smallest_depth() {
    for document in [&[0x01u8][..], &[0x40][..], &[0x60][..], &[0xf5][..]] {
        assert!(CborValue::parse_with_depth::<Nondet>(document, 0).is_ok());
    }
}

/// Well-formed integers outside `i64` are rejected, in both modes.
#[test]
fn integers_outside_i64_are_rejected_in_both_modes() {
    let documents: [&[u8]; 2] = [
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // 2^64 - 1
        &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // -2^64
    ];
    for document in documents {
        for error in [
            CborValue::parse_nondet(document).expect_err("nondet should reject"),
            CborValue::parse_det(document).expect_err("det should reject"),
        ] {
            assert!(error.contains("exceeds i64 range"), "{error}");
        }
    }

    // The largest and smallest values that do fit are still accepted.
    let max: &[u8] = &[0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let min: &[u8] = &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(CborValue::parse_det(max).unwrap(), CborValue::Int(i64::MAX));
    assert_eq!(CborValue::parse_det(min).unwrap(), CborValue::Int(i64::MIN));
}

/// A container header can declare a length far larger than the input supplies.
#[test]
fn oversized_declared_lengths_are_rejected_not_reserved() {
    // Array header claiming 2^64 - 1 items, with none following.
    let document: &[u8] = &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(CborValue::parse_nondet(document).is_err());

    // Byte string header claiming 2^64 - 1 bytes, with none following.
    let document: &[u8] = &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(CborValue::parse_nondet(document).is_err());
}

#[test]
fn explicit_depth_limit_is_honoured() {
    // [[42]] needs a budget of 2: one for each array.
    let bytes = [0x81, 0x81, 0x18, 0x2a];
    assert!(CborValue::parse_with_depth::<Nondet>(&bytes, 2).is_ok());
    assert!(CborValue::parse_with_depth::<Nondet>(&bytes, 1).is_err());

    let value = CborValue::parse_nondet(&bytes).unwrap();
    assert!(value.to_bytes_with_depth::<Det>(2).is_ok());
    assert!(value.to_bytes_with_depth::<Det>(1).is_err());
}

// --- Accessor: array index ---

#[test]
fn array_at_item() {
    let arr = CborValue::Array(vec![CborValue::Int(10), CborValue::Int(20)]);
    assert_eq!(arr.array_at(0).unwrap(), &CborValue::Int(10));
    assert_eq!(arr.array_at(1).unwrap(), &CborValue::Int(20));
    assert!(arr.array_at(2).is_err());
}

#[test]
fn array_at_on_non_array_is_err() {
    assert!(CborValue::Int(1).array_at(0).is_err());
    assert!(CborValue::text("hi").array_at(0).is_err());
    assert!(CborValue::Map(vec![]).array_at(0).is_err());
}

// --- Accessor: map lookup ---

#[test]
fn map_at_int_key() {
    let map = CborValue::Map(vec![
        (CborValue::Int(1), CborValue::text("one")),
        (CborValue::Int(2), CborValue::text("two")),
    ]);
    assert_eq!(map.map_at_int(1).unwrap(), &CborValue::text("one"));
    assert_eq!(map.map_at_int(2).unwrap(), &CborValue::text("two"));
    assert!(map.map_at_int(3).is_err());
}

#[test]
fn map_at_str_key() {
    let map = CborValue::Map(vec![(CborValue::text("key"), CborValue::Int(42))]);
    assert_eq!(map.map_at_str("key").unwrap(), &CborValue::Int(42));
    assert!(map.map_at_str("missing").is_err());
}

#[test]
fn map_has_key() {
    let map = CborValue::Map(vec![
        (CborValue::Int(1), CborValue::text("one")),
        (CborValue::text("key"), CborValue::Int(42)),
        (CborValue::bytes(vec![0xaa]), CborValue::Simple(21)),
    ]);

    assert!(map.map_has_int_key(1).unwrap());
    assert!(!map.map_has_int_key(2).unwrap());
    assert!(map.map_has_str_key("key").unwrap());
    assert!(!map.map_has_str_key("missing").unwrap());
    assert!(map.map_has_key(&CborValue::Int(1)).unwrap());
    assert!(map.map_has_key(&CborValue::text("key")).unwrap());
    assert!(map.map_has_key(&CborValue::bytes(vec![0xaa])).unwrap());
    assert!(!map.map_has_key(&CborValue::Array(vec![])).unwrap());
}

#[test]
fn map_at_cbor_key() {
    let map = CborValue::Map(vec![(CborValue::bytes(vec![0xaa]), CborValue::Simple(21))]);
    assert_eq!(
        map.map_at(&CborValue::bytes(vec![0xaa])).unwrap(),
        &CborValue::Simple(21)
    );
    assert!(map.map_at(&CborValue::Array(vec![])).is_err());
}

#[test]
fn map_at_on_non_map_is_err() {
    assert!(CborValue::Int(1).map_at_int(0).is_err());
    assert!(CborValue::Array(vec![]).map_at_str("x").is_err());
    assert!(CborValue::Int(1).map_has_int_key(0).is_err());
    assert!(CborValue::Array(vec![]).map_has_str_key("x").is_err());
}

/// Lookups must not care whether a key or the stored entry is borrowed.
#[test]
fn map_lookup_ignores_ownership() {
    let document = [0xa1, 0x63, 0x6b, 0x65, 0x79, 0x18, 0x2a]; // {"key": 42}
    let borrowed = CborValue::parse_nondet(&document).unwrap();
    let CborValue::Map(entries) = &borrowed else {
        panic!("expected a map")
    };
    assert!(matches!(
        entries[0].0,
        CborValue::TextString(Cow::Borrowed(_))
    ));

    assert_eq!(borrowed.map_at_str("key").unwrap(), &CborValue::Int(42));
    assert_eq!(
        borrowed
            .map_at(&CborValue::text(String::from("key")))
            .unwrap(),
        &CborValue::Int(42)
    );
    assert_eq!(borrowed, borrowed.clone().into_owned());
}

// --- Iterators ---

#[test]
fn iter_array_elements() {
    let arr = CborValue::Array(vec![
        CborValue::Int(1),
        CborValue::Int(2),
        CborValue::Int(3),
    ]);
    let collected: Vec<_> = arr.iter_array().unwrap().collect();
    assert_eq!(collected.len(), 3);
    assert_eq!(collected[0], &CborValue::Int(1));
}

#[test]
fn iter_array_on_non_array_is_err() {
    assert!(CborValue::Int(1).iter_array().is_err());
}

#[test]
fn iter_map_entries() {
    let map = CborValue::Map(vec![
        (CborValue::Int(1), CborValue::text("a")),
        (CborValue::Int(2), CborValue::text("b")),
    ]);
    let collected: Vec<_> = map.iter_map().unwrap().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].0, &CborValue::Int(1));
}

#[test]
fn iter_map_on_non_map_is_err() {
    assert!(CborValue::Array(vec![]).iter_map().is_err());
}

// --- len ---

#[test]
fn len_array() {
    let arr = CborValue::Array(vec![CborValue::Int(1)]);
    assert_eq!(arr.len().unwrap(), 1);
    assert!(!arr.is_empty().unwrap());
    assert!(CborValue::Array(vec![]).is_empty().unwrap());
}

#[test]
fn len_map() {
    let map = CborValue::Map(vec![(CborValue::Int(1), CborValue::Int(2))]);
    assert_eq!(map.len().unwrap(), 1);
}

#[test]
fn len_on_other_types_is_err() {
    assert!(CborValue::Int(0).len().is_err());
    assert!(CborValue::text("x").len().is_err());
}

// --- Debug ---

#[test]
fn debug_format() {
    let val = CborValue::Array(vec![CborValue::Int(42), CborValue::Int(-7)]);
    let s = format!("{val:?}");
    assert!(s.contains("Int(42)"));
    assert!(s.contains("Int(-7)"));
}

// --- Borrowing ---

/// Returns whether `needle` points inside `haystack`'s allocation.
fn points_into(haystack: &[u8], needle: &[u8]) -> bool {
    let (start, at) = (haystack.as_ptr() as usize, needle.as_ptr() as usize);
    at >= start && at + needle.len() <= start + haystack.len()
}

#[test]
fn parse_borrows_from_the_input_in_both_modes() {
    // {1: h'DEADBEEF', "k": "vvvv"}
    let document = [
        0xa2, 0x01, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x61, 0x6b, 0x64, 0x76, 0x76, 0x76, 0x76,
    ];
    for value in [
        CborValue::parse_nondet(&document).unwrap(),
        CborValue::parse_det(&document).unwrap(),
    ] {
        let CborValue::Map(entries) = &value else {
            panic!("expected a map")
        };
        let CborValue::ByteString(payload) = &entries[0].1 else {
            panic!("expected a byte string")
        };
        assert!(matches!(payload, Cow::Borrowed(_)));
        assert!(points_into(&document, payload));

        let CborValue::TextString(text) = &entries[1].1 else {
            panic!("expected a text string")
        };
        assert!(matches!(text, Cow::Borrowed(_)));
        assert!(points_into(&document, text.as_bytes()));
    }
}

#[test]
fn into_owned_outlives_the_input() {
    let detached = {
        let document = vec![0x43, 0xaa, 0xbb, 0xcc];
        CborValue::parse_nondet(&document).unwrap().into_owned()
    };
    assert_eq!(detached, CborValue::bytes(vec![0xaa, 0xbb, 0xcc]));
    let CborValue::ByteString(payload) = &detached else {
        panic!("expected a byte string")
    };
    assert!(matches!(payload, Cow::Owned(_)));
}

#[test]
fn values_built_from_owned_data_serialize() {
    let generated = format!("{}.{}", 2, 42);
    let value = CborValue::Map(vec![
        (CborValue::text("txid"), CborValue::text(generated)),
        (CborValue::text("kid"), CborValue::bytes(vec![1, 2, 3])),
    ]);
    // Deterministic serialization sorts the keys, so compare re-serialized
    // bytes rather than the structure.
    let bytes = value.to_bytes_det().unwrap();
    let parsed = CborValue::parse_det(&bytes).unwrap();
    assert_eq!(parsed.to_bytes_det().unwrap(), bytes);
    assert_eq!(parsed.map_at_str("txid").unwrap(), &CborValue::text("2.42"));
    assert_eq!(
        parsed.map_at_str("kid").unwrap(),
        &CborValue::bytes(vec![1, 2, 3])
    );
}

// --- Modes ---

#[test]
fn det_sorts_map_keys_and_nondet_preserves_order() {
    let value = CborValue::Map(vec![
        (CborValue::Int(2), CborValue::Int(20)),
        (CborValue::Int(1), CborValue::Int(10)),
    ]);
    assert_eq!(
        value.to_bytes_nondet().unwrap(),
        [0xa2, 0x02, 0x14, 0x01, 0x0a]
    );
    assert_eq!(
        value.to_bytes_det().unwrap(),
        [0xa2, 0x01, 0x0a, 0x02, 0x14]
    );
}

#[test]
fn det_parse_rejects_what_nondet_accepts() {
    // {2: 20, 1: 10} is well formed but not in canonical key order.
    let document = [0xa2, 0x02, 0x14, 0x01, 0x0a];
    assert!(CborValue::parse_nondet(&document).is_ok());
    assert!(CborValue::parse_det(&document).is_err());

    // -2 encoded in a non-preferred 8-byte head.
    let document = [0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert_eq!(
        CborValue::parse_nondet(&document).unwrap(),
        CborValue::Int(-2)
    );
    assert!(CborValue::parse_det(&document).is_err());
}

#[test]
fn round_trips_are_not_byte_preserving() {
    // -2 in a non-preferred 8-byte head re-serializes in preferred form.
    let document = [0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let value = CborValue::parse_nondet(&document).unwrap();
    assert_eq!(value.to_bytes_nondet().unwrap(), [0x21]);
    assert_eq!(value.to_bytes_det().unwrap(), [0x21]);
}

#[test]
fn both_modes_reject_duplicate_map_keys() {
    let value = CborValue::Map(vec![
        (CborValue::Int(1), CborValue::Int(10)),
        (CborValue::Int(1), CborValue::Int(20)),
    ]);
    assert!(value.to_bytes_det().is_err());
    assert!(value.to_bytes_nondet().is_err());
}

/// Map entry order is the only thing the two modes serialize differently.
#[test]
fn modes_serialize_identically_apart_from_map_order() {
    let values = [
        CborValue::Int(0),
        CborValue::Int(23),
        CborValue::Int(24),
        CborValue::Int(i64::MAX),
        CborValue::Int(-1),
        CborValue::Int(i64::MIN),
        CborValue::Simple(21),
        CborValue::bytes(vec![]),
        CborValue::bytes(vec![7; 24]),
        CborValue::bytes(vec![7; 300]),
        CborValue::text("hello"),
        CborValue::Array(vec![]),
        CborValue::Array((0..30).map(CborValue::Int).collect()),
        CborValue::Tagged {
            tag: 18,
            payload: Box::new(CborValue::Int(1)),
        },
        CborValue::Tagged {
            tag: 1_000_000,
            payload: Box::new(CborValue::Int(1)),
        },
        CborValue::Map(vec![]),
        CborValue::Map(vec![(CborValue::Int(1), CborValue::Int(0))]),
        // Already in canonical order, so sorting is a no-op.
        CborValue::Map(vec![
            (CborValue::Int(1), CborValue::Int(0)),
            (CborValue::Int(2), CborValue::Int(0)),
        ]),
    ];
    for value in values {
        assert_eq!(
            value.to_bytes_det().unwrap(),
            value.to_bytes_nondet().unwrap(),
            "modes disagreed on {value:?}"
        );
    }
}

/// Deterministic parsing rejects more than just unsorted map keys: every head
/// must use the shortest width that fits its argument.
#[test]
fn det_parse_rejects_non_preferred_head_widths() {
    let documents: [&[u8]; 10] = [
        &[0x18, 0x00],                            // uint 0, 2 byte head
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0x01],       // uint 1, 9 byte head
        &[0x1b, 0, 0, 0, 0, 0, 0x0f, 0x42, 0x40], // uint 1000000, 9 byte head
        &[0x38, 0x00],                            // nint -1, 2 byte head
        &[0x3b, 0, 0, 0, 0, 0, 0, 0, 0x00],       // nint -1, 9 byte head
        &[0x58, 0x01, 0xaa],                      // byte string length
        &[0x78, 0x01, 0x61],                      // text string length
        &[0x98, 0x01, 0x01],                      // array length
        &[0xb8, 0x01, 0x01, 0x00],                // map length
        &[0xd8, 0x01, 0x01],                      // tag
    ];
    for document in documents {
        assert!(
            CborValue::parse_nondet(document).is_ok(),
            "nondet should accept {document:02x?}"
        );
        assert!(
            CborValue::parse_det(document).is_err(),
            "det should reject {document:02x?}"
        );
    }
}

/// Serialization always writes the shortest head that fits, in both modes.
#[test]
fn serialization_writes_preferred_head_widths() {
    let cases: [(CborValue<'_>, &[u8]); 12] = [
        (CborValue::Int(0), &[0x00]),
        (CborValue::Int(23), &[0x17]),
        (CborValue::Int(24), &[0x18, 0x18]),
        (CborValue::Int(255), &[0x18, 0xff]),
        (CborValue::Int(256), &[0x19, 0x01, 0x00]),
        (CborValue::Int(-1), &[0x20]),
        (CborValue::Int(-25), &[0x38, 0x18]),
        (CborValue::Simple(20), &[0xf4]),
        (CborValue::bytes(vec![0xaa]), &[0x41, 0xaa]),
        (CborValue::text("a"), &[0x61, 0x61]),
        (CborValue::Array(vec![CborValue::Int(1)]), &[0x81, 0x01]),
        (
            CborValue::Map(vec![(CborValue::Int(1), CborValue::Int(0))]),
            &[0xa1, 0x01, 0x00],
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(value.to_bytes_det().unwrap(), expected, "det {value:?}");
        assert_eq!(
            value.to_bytes_nondet().unwrap(),
            expected,
            "nondet {value:?}"
        );
    }
}

/// Rejected by both modes, so neither is a deterministic-only restriction.
#[test]
fn both_modes_reject_unsupported_encodings() {
    let documents: [&[u8]; 5] = [
        &[0xf9, 0x3c, 0x00],             // half-precision float
        &[0x9f, 0x01, 0xff],             // indefinite-length array
        &[0x62, 0xff, 0xfe],             // invalid UTF-8 text
        &[0xa2, 0x01, 0x00, 0x01, 0x09], // duplicate map keys
        &[0xf8, 0x14],                   // simple value 20 in a 2 byte head
    ];
    for document in documents {
        assert!(
            CborValue::parse_nondet(document).is_err(),
            "nondet should reject {document:02x?}"
        );
        assert!(
            CborValue::parse_det(document).is_err(),
            "det should reject {document:02x?}"
        );
    }
}

#[test]
fn parse_rejects_trailing_bytes() {
    let err = CborValue::parse_nondet(&[0x01, 0x02]).expect_err("should reject");
    assert!(err.contains("Trailing bytes"));
}

#[test]
fn parse_rejects_malformed_input() {
    assert!(CborValue::parse_nondet(&[]).is_err());
    assert!(CborValue::parse_nondet(&[0x81]).is_err()); // array header, no item
    assert!(CborValue::parse_nondet(&[0xf9, 0x3c, 0x00]).is_err()); // float
    assert!(CborValue::parse_nondet(&[0x62, 0xff, 0xfe]).is_err()); // invalid UTF-8
}

#[test]
fn integers_outside_i64_are_rejected() {
    // 2^63, one past i64::MAX.
    let document = [0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = CborValue::parse_nondet(&document).expect_err("should reject");
    assert!(err.contains("exceeds i64 range"));

    // -1 - 2^63, one past i64::MIN.
    let document = [0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let err = CborValue::parse_nondet(&document).expect_err("should reject");
    assert!(err.contains("exceeds i64 range"));
}

#[test]
#[allow(deprecated)]
fn deprecated_from_bytes_outlives_its_input() {
    let value: CborValue<'static> = {
        let buffer = vec![0x43, 0x01, 0x02, 0x03];
        CborValue::from_bytes(&buffer).unwrap()
    };
    assert_eq!(value, CborValue::bytes(vec![1u8, 2, 3]));
}

#[test]
#[allow(deprecated)]
fn deprecated_from_bytes_parses_in_nondet_mode() {
    // 1 in a one-byte head, which is not the preferred encoding.
    let document = [0x18, 0x01];
    assert_eq!(CborValue::from_bytes(&document).unwrap(), CborValue::Int(1));
    assert!(CborValue::parse_det(&document).is_err());
}

#[test]
#[allow(deprecated)]
fn deprecated_to_bytes_serializes_in_det_mode() {
    let value = CborValue::Map(vec![
        (CborValue::text("b"), CborValue::Int(2)),
        (CborValue::text("a"), CborValue::Int(1)),
    ]);
    assert_eq!(value.to_bytes().unwrap(), value.to_bytes_det().unwrap());
    assert_ne!(value.to_bytes().unwrap(), value.to_bytes_nondet().unwrap());
}

#[test]
fn compound_key_equivalence_and_duplicate_detection() {
    let first = CborValue::Map(vec![
        (CborValue::Int(1), CborValue::Int(2)),
        (CborValue::Int(3), CborValue::Int(4)),
    ]);
    let reordered = CborValue::Map(vec![
        (CborValue::Int(3), CborValue::Int(4)),
        (CborValue::Int(1), CborValue::Int(2)),
    ]);
    for (key, equivalent) in [
        (first.clone(), reordered.clone()),
        (
            CborValue::Array(vec![first.clone()]),
            CborValue::Array(vec![reordered.clone()]),
        ),
        (
            CborValue::Tagged {
                tag: 42,
                payload: Box::new(first),
            },
            CborValue::Tagged {
                tag: 42,
                payload: Box::new(reordered),
            },
        ),
    ] {
        let map = CborValue::Map(vec![(key.clone(), CborValue::Int(7))]);
        assert_eq!(map.map_at(&equivalent).unwrap(), &CborValue::Int(7));
        assert!(map.map_has_key(&equivalent).unwrap());
        for encoded in [map.to_bytes_det().unwrap(), map.to_bytes_nondet().unwrap()] {
            assert_eq!(
                CborValue::parse_nondet(&encoded)
                    .unwrap()
                    .map_at(&equivalent)
                    .unwrap(),
                &CborValue::Int(7)
            );
        }
        let duplicate = CborValue::Map(vec![
            (key, CborValue::Int(1)),
            (equivalent, CborValue::Int(2)),
        ]);
        assert!(duplicate.to_bytes_det().is_err());
        assert!(duplicate.to_bytes_nondet().is_err());
    }
    // Equivalent map keys with different entry order in non-deterministic input.
    let duplicate = [0xa2, 0xa2, 1, 2, 3, 4, 0, 0xa2, 3, 4, 1, 2, 1];
    assert!(CborValue::parse_nondet(&duplicate).is_err());
    assert!(CborValue::parse_det(&duplicate).is_err());
    assert!(
        !CborValue::Array(vec![CborValue::Int(1), CborValue::Int(2)]).key_equivalent(
            &CborValue::Array(vec![CborValue::Int(2), CborValue::Int(1)])
        )
    );
}
