// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use x509_cert::der::{asn1::UintRef, Reader, SliceReader};

use super::{EcSignatureKeyAlgorithm, Result};

pub(crate) fn fixed_from_components(
    r: &[u8],
    s: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    let expected_len = algorithm.scalar_byte_len();
    if r.len() != expected_len || s.len() != expected_len {
        return Err(format!(
            "Invalid ECDSA {} component length: expected {}, got r={} s={}",
            algorithm.name(),
            expected_len,
            r.len(),
            s.len()
        )
        .into());
    }

    let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
    fixed.extend_from_slice(r);
    fixed.extend_from_slice(s);
    Ok(fixed)
}

pub(crate) fn ecdsa_der_to_fixed(
    signature: &[u8],
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<Vec<u8>> {
    let mut reader = SliceReader::new(signature)?;
    let components = reader.sequence(|reader| {
        Ok((
            reader.decode::<UintRef<'_>>()?,
            reader.decode::<UintRef<'_>>()?,
        ))
    });
    let (r, s) = reader
        .finish(components?)
        .map_err(|e| format!("Failed to parse DER ECDSA signature: {e:?}"))?;

    let mut fixed = Vec::with_capacity(algorithm.fixed_signature_byte_len());
    append_fixed_width_integer(&mut fixed, r.as_bytes(), "r", algorithm)?;
    append_fixed_width_integer(&mut fixed, s.as_bytes(), "s", algorithm)?;
    Ok(fixed)
}

fn append_fixed_width_integer(
    output: &mut Vec<u8>,
    integer: &[u8],
    name: &str,
    algorithm: EcSignatureKeyAlgorithm,
) -> Result<()> {
    let expected_len = algorithm.scalar_byte_len();
    if integer.len() > expected_len {
        return Err(format!(
            "Invalid ECDSA {} {name} component length: expected <= {}, got {}",
            algorithm.name(),
            expected_len,
            integer.len()
        )
        .into());
    }

    output.resize(output.len() + expected_len - integer.len(), 0);
    output.extend_from_slice(integer);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_fixed_width_components() {
        let r = [1; 32];
        let s = [2; 32];

        let fixed = fixed_from_components(&r, &s, EcSignatureKeyAlgorithm::P256).unwrap();
        assert_eq!(&fixed[..32], &r);
        assert_eq!(&fixed[32..], &s);
    }

    #[test]
    fn rejects_wrong_component_lengths() {
        assert!(fixed_from_components(&[1; 31], &[2; 32], EcSignatureKeyAlgorithm::P256).is_err());
    }

    #[test]
    fn converts_short_scalars_and_required_sign_padding() {
        let signature = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];

        let fixed = ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P256).unwrap();
        assert_eq!(fixed.len(), 64);
        assert_eq!(fixed[31], 1);
        assert_eq!(fixed[63], 0x80);
        assert!(fixed[..31].iter().all(|byte| *byte == 0));
        assert!(fixed[32..63].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn accepts_canonical_long_form_length() {
        let mut signature = vec![0x30, 0x81, 0x88, 0x02, 66];
        signature.extend_from_slice(&[1; 66]);
        signature.extend_from_slice(&[0x02, 66]);
        signature.extend_from_slice(&[1; 66]);

        let fixed = ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P521).unwrap();
        assert_eq!(fixed, vec![1; 132]);
    }

    #[test]
    fn rejects_malformed_structure() {
        for signature in [
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01][..],
            &[0x30, 0x80][..],
            &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01][..],
            &[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01][..],
            &[0x30, 0x03, 0x02, 0x01, 0x01][..],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00][..],
        ] {
            assert!(ecdsa_der_to_fixed(signature, EcSignatureKeyAlgorithm::P256).is_err());
        }
    }

    #[test]
    fn rejects_redundant_integer_sign_padding() {
        let signature = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];

        assert!(ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P256).is_err());
    }

    #[test]
    fn rejects_non_minimal_long_form_length() {
        let signature = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

        assert!(ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P256).is_err());
    }

    #[test]
    fn rejects_long_form_length_with_leading_zero() {
        let mut signature = vec![0x30, 0x82, 0x00, 0x80, 0x02, 61];
        signature.extend_from_slice(&[1; 61]);
        signature.extend_from_slice(&[0x02, 63]);
        signature.extend_from_slice(&[1; 63]);

        assert!(ecdsa_der_to_fixed(&signature, EcSignatureKeyAlgorithm::P521).is_err());
    }
}
