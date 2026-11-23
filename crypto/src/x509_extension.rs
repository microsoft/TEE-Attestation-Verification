// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decoders for the X.509 extension values returned by
//! `CertificateBackend::get_extension_value_by_oid`.

use super::Result;

const SEQUENCE: u8 = 0x30;
const OBJECT_IDENTIFIER: u8 = 0x06;

/// RFC 5280 section 4.2.1.12: id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }.
pub(crate) const EXTENDED_KEY_USAGE_OID: &str = "2.5.29.37";

/// Decodes `ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId` into dotted-decimal OIDs.
pub(crate) fn extended_key_usage(value: &[u8]) -> Result<Vec<String>> {
    let (mut key_purposes, trailing) = read_tlv(value, SEQUENCE)?;
    if !trailing.is_empty() {
        return Err("Trailing data after extended key usage".into());
    }

    let mut oids = Vec::new();
    while !key_purposes.is_empty() {
        let (oid, rest) = read_tlv(key_purposes, OBJECT_IDENTIFIER)?;
        oids.push(oid_to_dotted_decimal(oid)?);
        key_purposes = rest;
    }
    Ok(oids)
}

/// Reads one DER value with the expected tag, returning its contents and the
/// input that follows it.
fn read_tlv(input: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let [actual_tag, first_length, rest @ ..] = input else {
        return Err("Truncated DER value".into());
    };
    if *actual_tag != tag {
        return Err("Unexpected DER tag".into());
    }

    let (length, rest) = if *first_length < 0x80 {
        (usize::from(*first_length), rest)
    } else {
        // Long form: the low seven bits count the big-endian length octets.
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > 4 || count > rest.len() {
            return Err("Unsupported DER length".into());
        }
        let (length_octets, rest) = rest.split_at(count);
        let length = length_octets
            .iter()
            .fold(0, |length, &octet| length << 8 | usize::from(octet));
        if length < 0x80 || length_octets[0] == 0 {
            return Err("Non-minimal DER length".into());
        }
        (length, rest)
    };
    if length > rest.len() {
        return Err("Truncated DER value".into());
    }
    Ok(rest.split_at(length))
}

/// Decodes the contents of a DER OBJECT IDENTIFIER (X.690 section 8.19).
fn oid_to_dotted_decimal(contents: &[u8]) -> Result<String> {
    let mut arcs = Vec::new();
    let mut subidentifier = 0u128;
    let mut complete = true;
    for &octet in contents {
        if complete && octet == 0x80 {
            return Err("Non-minimal OID subidentifier".into());
        }
        if subidentifier > u128::MAX >> 7 {
            return Err("OID subidentifier is too large".into());
        }
        subidentifier = subidentifier << 7 | u128::from(octet & 0x7f);
        complete = octet & 0x80 == 0;
        if complete {
            if arcs.is_empty() {
                // The first subidentifier packs the first two arcs as 40 * first + second.
                let first = (subidentifier / 40).min(2);
                arcs.push(first);
                subidentifier -= first * 40;
            }
            arcs.push(subidentifier);
            subidentifier = 0;
        }
    }
    if !complete || arcs.is_empty() {
        return Err("Truncated OID".into());
    }

    let arcs = arcs.iter().map(u128::to_string).collect::<Vec<_>>();
    Ok(arcs.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn oid_contents_decode_to_dotted_decimal() {
        for (contents, expected) in [
            (&[0x00][..], "0.0"),
            (&[0x4f], "1.39"),
            (&[0x50], "2.0"),
            // X.690 section 8.19.5 example.
            (&[0x81, 0x34, 0x03], "2.100.3"),
            (
                &[
                    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x4c, 0x3b, 0x01, 0x02,
                ],
                "1.3.6.1.4.1.311.76.59.1.2",
            ),
        ] {
            assert_eq!(oid_to_dotted_decimal(contents).unwrap(), expected);
        }

        let too_large = [&[0x2a, 0x84][..], &[0x80; 18], &[0x00]].concat();
        for contents in [&[][..], &[0x2a, 0x81], &[0x2a, 0x80, 0x01], &too_large] {
            assert!(oid_to_dotted_decimal(contents).is_err(), "{contents:x?}");
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn extended_key_usage_decodes_each_key_purpose() {
        let value = [0x30, 7, 0x06, 2, 0x2a, 0x03, 0x06, 1, 0x2b];
        assert_eq!(extended_key_usage(&value).unwrap(), ["1.2.3", "1.3"]);

        // A long-form length, as needed for 128 bytes or more.
        let long = [&[0x30, 0x81, 129][..], &[0x06, 1, 0x2b].repeat(43)].concat();
        assert_eq!(extended_key_usage(&long).unwrap(), vec!["1.3"; 43]);

        let malformed: [&[u8]; 8] = [
            &[],
            // Not a SEQUENCE.
            &[0x31, 3, 0x06, 1, 0x2a],
            // Element is not an OBJECT IDENTIFIER.
            &[0x30, 3, 0x04, 1, 0x2a],
            // Trailing data.
            &[0x30, 3, 0x06, 1, 0x2a, 0x00],
            // SEQUENCE longer than the input.
            &[0x30, 4, 0x06, 1, 0x2a],
            // OID longer than the SEQUENCE.
            &[0x30, 3, 0x06, 2, 0x2a],
            // Indefinite length.
            &[0x30, 0x80, 0x06, 1, 0x2a, 0x00, 0x00],
            // Long-form length where the short form fits.
            &[0x30, 0x81, 3, 0x06, 1, 0x2a],
        ];
        for value in malformed {
            assert!(extended_key_usage(value).is_err(), "{value:x?}");
        }
    }
}
